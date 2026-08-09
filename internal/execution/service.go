package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const (
	nodeServiceSignalScript   = `const fs=require("node:fs");const signalName=process.argv[1],graceMs=Number(process.argv[2]),quiescentNoopArg=process.argv[3],allowQuiescentNoop=quiescentNoopArg==="true";const allowed={term:"SIGTERM",kill:"SIGKILL",int:"SIGINT",hup:"SIGHUP"};if(!allowed[signalName]||!Number.isSafeInteger(graceMs)||graceMs<1||graceMs>10000||!["true","false"].includes(quiescentNoopArg))throw new Error("invalid signal request");const sleep=new Int32Array(new SharedArrayBuffer(4));function targets(){const result=[];for(const name of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(name))continue;try{const status=fs.readFileSync("/proc/"+name+"/status","utf8"),uid=/^Uid:\s+(\d+)\s+(\d+)/m.exec(status),state=/^State:\s+([A-Z])/m.exec(status);if(uid&&(uid[1]==="65532"||uid[2]==="65532")&&(!state||!/^[ZX]$/.test(state[1])))result.push(Number(name));}catch(error){if(error.code!=="ENOENT")throw error;}}return result;}function send(pids,signal){let count=0;for(const pid of pids){try{process.kill(pid,signal);count++;}catch(error){if(error.code!=="ESRCH")throw error;}}return count;}const initial=targets(),started=Date.now(),sent=send(initial,allowed[signalName]);while(targets().length&&Date.now()-started<graceMs)Atomics.wait(sleep,0,0,10);let escalated=false;if(targets().length){escalated=true;send(targets(),"SIGKILL");for(let pass=0;pass<50&&targets().length;pass++)Atomics.wait(sleep,0,0,10);}const remaining=targets().length,delivered=initial.length>0&&sent>0&&sent<=initial.length&&remaining===0,quiescentNoop=allowQuiescentNoop&&initial.length>=0&&sent===0&&remaining===0&&!escalated,ok=delivered||quiescentNoop;process.stdout.write(JSON.stringify({ok,escalated,remaining,initialTargets:initial.length,sent})+"\n");if(!ok)process.exitCode=1;`
	pythonServiceSignalScript = `import json,os,re,signal,sys,time
signal_name=sys.argv[1]
grace_ms=int(sys.argv[2])
quiescent_noop_arg=sys.argv[3]
allow_quiescent_noop=quiescent_noop_arg=="true"
allowed={"term":signal.SIGTERM,"kill":signal.SIGKILL,"int":signal.SIGINT,"hup":signal.SIGHUP}
if signal_name not in allowed or grace_ms<1 or grace_ms>10000 or quiescent_noop_arg not in {"true","false"}:
    raise RuntimeError("invalid signal request")
def targets():
    result=[]
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/"+name+"/status",encoding="ascii") as source:
                status=source.read()
        except FileNotFoundError:
            continue
        uid=re.search(r"^Uid:\s+(\d+)\s+(\d+)",status,re.MULTILINE)
        state=re.search(r"^State:\s+([A-Z])",status,re.MULTILINE)
        if uid and 65532 in (int(uid.group(1)),int(uid.group(2))) and (not state or state.group(1) not in "ZX"):
            result.append(int(name))
    return result
def send(pids,value):
    count=0
    for pid in pids:
        try:
            os.kill(pid,value)
            count+=1
        except ProcessLookupError:
            pass
    return count
initial=targets()
started=time.monotonic()
sent=send(initial,allowed[signal_name])
while targets() and (time.monotonic()-started)*1000<grace_ms:
    time.sleep(0.01)
escalated=False
if targets():
    escalated=True
    send(targets(),signal.SIGKILL)
    for _ in range(50):
        if not targets():
            break
        time.sleep(0.01)
remaining=len(targets())
delivered=len(initial)>0 and sent>0 and sent<=len(initial) and remaining==0
quiescent_noop=allow_quiescent_noop and len(initial)>=0 and sent==0 and remaining==0 and not escalated
ok=delivered or quiescent_noop
print(json.dumps({"ok":ok,"escalated":escalated,"remaining":remaining,"initialTargets":len(initial),"sent":sent},separators=(",",":")))
raise SystemExit(0 if ok else 1)`
)

type runningService struct {
	command domain.PlanCommand
	cancel  context.CancelFunc
	done    chan stepExecution
	mu      sync.Mutex
	result  *stepExecution
}

type signalHelperResult struct {
	OK             bool `json:"ok"`
	Escalated      bool `json:"escalated"`
	Remaining      int  `json:"remaining"`
	InitialTargets int  `json:"initialTargets"`
	Sent           int  `json:"sent"`
	AlreadyExited  bool `json:"-"`
}

const maxHTTPReadinessAttempts = 128

func (r *Runner) startService(
	ctx context.Context,
	prepared *PreparedRun,
	step preparedStep,
	containerName string,
) *runningService {
	serviceCtx, cancel := context.WithTimeout(ctx, step.timeout)
	service := &runningService{
		command: clonePlanCommand(step.command),
		cancel:  cancel,
		done:    make(chan stepExecution, 1),
	}
	go func() {
		service.done <- r.runAttachedService(
			serviceCtx,
			prepared,
			step,
			containerName,
		)
	}()
	return service
}

func (r *Runner) runAttachedService(
	ctx context.Context,
	prepared *PreparedRun,
	step preparedStep,
	containerName string,
) stepExecution {
	execution := stepExecution{
		result: StepResult{
			ID:            step.command.ID,
			Phase:         domain.PhaseRun,
			Role:          "service",
			ExitCode:      -1,
			ContainerName: containerName,
		},
		exportSafe: true,
	}
	capture := newLogCapture(r.config.MaxLogBytes)
	args := []string{
		"exec",
		"--user", containerUser,
		"--workdir", containerWorkspace,
		containerName,
	}
	args = append(args, step.command.Argv...)
	startedAt := r.now()
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		args,
		capture.stdout,
		capture.stderr,
	)
	execution.result.ExitCode = exitCode
	execution.result.Stdout = capture.stdout.Bytes()
	execution.result.Stderr = capture.stderr.Bytes()
	execution.result.Duration = r.now().Sub(startedAt)
	execution.result.LogBytes = capture.budget.Total()
	execution.result.LogTruncated = capture.budget.Truncated()
	execution.result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		execution.exportSafe = false
		execution.primaryError = domain.WrapError(
			domain.CodeTimeout,
			domain.SeverityHigh,
			"Attached service exceeded its resolved wall timeout.",
			ctx.Err(),
		)
		execution.primaryError.Phase = domain.PhaseRun
	case errors.Is(ctx.Err(), context.Canceled):
		execution.exportSafe = false
		execution.primaryError = domain.WrapError(
			domain.CodeCancelled,
			domain.SeverityWarning,
			"Attached service execution was cancelled.",
			ctx.Err(),
		)
		execution.primaryError.Phase = domain.PhaseRun
	case exitCode < 0 || exitCode >= 125 && exitCode <= 127:
		execution.exportSafe = false
		execution.primaryError = domain.WrapError(
			domain.CodeServiceStartFailed,
			domain.SeverityHigh,
			"Attached service exec failed before a trustworthy workload exit was observed.",
			runErr,
		)
		execution.primaryError.Phase = domain.PhaseRun
		execution.primaryError.Details = map[string]any{
			"backend":       prepared.Backend,
			"containerName": containerName,
			"exitCode":      exitCode,
		}
	}
	if execution.primaryError != nil {
		execution.result.ErrorCode = execution.primaryError.Code
	}
	return execution
}

func pollServiceResult(
	service *runningService,
) (stepExecution, bool) {
	if service == nil {
		return stepExecution{}, false
	}
	service.mu.Lock()
	if service.result != nil {
		result := *service.result
		service.mu.Unlock()
		return result, true
	}
	service.mu.Unlock()
	select {
	case result := <-service.done:
		service.mu.Lock()
		service.result = &result
		service.mu.Unlock()
		return result, true
	default:
		return stepExecution{}, false
	}
}

func waitServiceResult(
	ctx context.Context,
	service *runningService,
) (stepExecution, error) {
	if service == nil {
		return stepExecution{}, errors.New("service was not started")
	}
	if result, done := pollServiceResult(service); done {
		service.cancel()
		return result, nil
	}
	select {
	case result := <-service.done:
		service.mu.Lock()
		service.result = &result
		service.mu.Unlock()
		service.cancel()
		return result, nil
	case <-ctx.Done():
		service.cancel()
		return stepExecution{}, ctx.Err()
	}
}

func (r *Runner) waitForReadiness(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	service *runningService,
) (domain.ObservationEvent, *domain.Error) {
	readiness := service.command.Readiness
	resource, queryPresent := sanitizedHTTPResource(readiness.URL)
	observation := lifecycleObservation(
		r.now().UTC(),
		prepared,
		domain.PhaseRun,
		"service.readiness",
		service.command.ID,
		"failed",
		map[string]any{
			"url":            resource,
			"queryPresent":   queryPresent,
			"expectedStatus": readiness.Status,
		},
	)
	timeout, _ := time.ParseDuration(readiness.Timeout)
	readinessCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	attempts := 0
	var lastStatus int
	for {
		if result, exited := pollServiceResult(service); exited {
			if result.primaryError != nil {
				observation.Details["attempts"] = attempts
				observation.Details["exitCode"] = result.result.ExitCode
				return observation, result.primaryError
			}
			err := domain.NewError(
				domain.CodeServiceStartFailed,
				domain.SeverityHigh,
				"HTTP service exited before readiness was established.",
			)
			err.Phase = domain.PhaseRun
			err.Details = map[string]any{
				"service":  service.command.ID,
				"exitCode": result.result.ExitCode,
			}
			observation.Details["attempts"] = attempts
			observation.Details["exitCode"] = result.result.ExitCode
			return observation, err
		}
		remaining := timeout
		if deadline, ok := readinessCtx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		if remaining <= 0 {
			observation.Details["attempts"] = attempts
			observation.Details["lastStatus"] = lastStatus
			return observation, readinessTerminalError(
				ctx,
				service.command.ID,
				attempts,
				lastStatus,
			)
		}
		attemptTimeout := remaining
		if attemptTimeout > time.Second {
			attemptTimeout = time.Second
		}
		attemptTimeout = attemptTimeout.Truncate(time.Millisecond)
		if attemptTimeout < domain.AlphaHTTPMinimumDuration {
			<-readinessCtx.Done()
			observation.Details["attempts"] = attempts
			observation.Details["lastStatus"] = lastStatus
			return observation, readinessTerminalError(
				ctx,
				service.command.ID,
				attempts,
				lastStatus,
			)
		}
		attempts++
		request := trustedHTTPRequest{
			ID: "readiness", Method: "GET", URL: readiness.URL,
			Headers: []httpHeader{}, Timeout: attemptTimeout,
		}
		attemptCtx, cancelAttempt := context.WithTimeout(
			readinessCtx,
			attemptTimeout+250*time.Millisecond,
		)
		response, requestErr := r.runTrustedHTTPRequest(
			attemptCtx,
			prepared,
			containerName,
			request,
		)
		cancelAttempt()
		if errors.Is(requestErr, errHTTPDriverResidue) {
			err := domain.WrapError(
				domain.CodeProcessLeak,
				domain.SeverityCritical,
				"Trusted HTTP readiness driver residue could not be excluded.",
				requestErr,
			)
			err.Phase = domain.PhaseRun
			err.Details = map[string]any{
				"service":  service.command.ID,
				"attempts": attempts,
			}
			observation.Details["attempts"] = attempts
			observation.Details["driverResidue"] = "inconclusive"
			return observation, err
		}
		if readinessCtx.Err() != nil {
			observation.Details["attempts"] = attempts
			observation.Details["lastStatus"] = lastStatus
			return observation, readinessTerminalError(
				ctx,
				service.command.ID,
				attempts,
				lastStatus,
			)
		}
		if requestErr == nil {
			lastStatus = response.Status
			if response.Status == readiness.Status {
				observation.Result = "succeeded"
				observation.Details["attempts"] = attempts
				observation.Details["actualStatus"] = response.Status
				observation.Details["durationMillis"] =
					response.DurationMillis
				return observation, nil
			}
		}
		if attempts >= maxHTTPReadinessAttempts {
			observation.Details["attempts"] = attempts
			observation.Details["lastStatus"] = lastStatus
			observation.Details["attemptLimit"] =
				maxHTTPReadinessAttempts
			return observation, readinessAttemptLimitError(
				service.command.ID,
				attempts,
				lastStatus,
			)
		}
		timer := time.NewTimer(readinessRetryBackoff(attempts))
		select {
		case <-readinessCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if readinessCtx.Err() != nil {
			observation.Details["attempts"] = attempts
			observation.Details["lastStatus"] = lastStatus
			return observation, readinessTerminalError(
				ctx,
				service.command.ID,
				attempts,
				lastStatus,
			)
		}
	}
}

func readinessRetryBackoff(attempts int) time.Duration {
	delay := 100 * time.Millisecond
	for current := 1; current < attempts && delay < time.Second; current++ {
		delay *= 2
		if delay > time.Second {
			return time.Second
		}
	}
	return delay
}

func readinessAttemptLimitError(
	serviceID string,
	attempts int,
	lastStatus int,
) *domain.Error {
	err := domain.NewError(
		domain.CodeReadinessFailed,
		domain.SeverityHigh,
		"HTTP service did not satisfy readiness within the bounded attempt limit.",
	)
	err.Phase = domain.PhaseRun
	err.Details = map[string]any{
		"service":      serviceID,
		"attempts":     attempts,
		"lastStatus":   lastStatus,
		"attemptLimit": maxHTTPReadinessAttempts,
	}
	return err
}

func readinessTerminalError(
	parent context.Context,
	serviceID string,
	attempts int,
	lastStatus int,
) *domain.Error {
	code := domain.CodeReadinessFailed
	severity := domain.SeverityHigh
	message := "HTTP service did not satisfy readiness before its deadline."
	cause := error(nil)
	switch {
	case errors.Is(parent.Err(), context.Canceled):
		code = domain.CodeCancelled
		severity = domain.SeverityWarning
		message = "HTTP service readiness was cancelled."
		cause = parent.Err()
	case errors.Is(parent.Err(), context.DeadlineExceeded):
		code = domain.CodeTimeout
		message = "HTTP service readiness exceeded the run deadline."
		cause = parent.Err()
	}
	var err *domain.Error
	if cause == nil {
		err = domain.NewError(code, severity, message)
	} else {
		err = domain.WrapError(code, severity, message, cause)
	}
	err.Phase = domain.PhaseRun
	err.Details = map[string]any{
		"service":    serviceID,
		"attempts":   attempts,
		"lastStatus": lastStatus,
	}
	return err
}

func (r *Runner) signalService(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	command domain.PlanCommand,
	allowQuiescentNoop bool,
) (signalHelperResult, StepResult, error) {
	result := StepResult{
		ID: command.ID, Phase: domain.PhaseCleanup, Role: "signal",
		ExitCode: -1, ContainerName: containerName,
	}
	signal := command.Signal
	if signal == nil {
		return signalHelperResult{}, result, errors.New("signal action is absent")
	}
	if signal.GracePeriod == "" {
		return signalHelperResult{}, result, errors.New(
			"signal action has no grace period",
		)
	}
	grace, err := domain.ParseAlphaHTTPDuration(
		signal.GracePeriod,
		domain.AlphaHTTPMaxSignalGrace,
	)
	if err != nil {
		return signalHelperResult{}, result, errors.New(
			"signal action has an invalid grace period",
		)
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return signalHelperResult{}, result, errors.New("runtime adapter has no trusted signal helper")
	}
	script := nodeServiceSignalScript
	scriptArgs := []string{"-e", script}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		script = pythonServiceSignalScript
		scriptArgs = []string{"-I", "-S", "-c", script}
	}
	args := []string{
		"exec",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(args, scriptArgs...)
	args = append(
		args,
		signal.Type,
		strconv.FormatInt(grace.Milliseconds(), 10),
		strconv.FormatBool(allowQuiescentNoop),
	)
	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	startedAt := r.now()
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	result.Duration = r.now().Sub(startedAt)
	result.ExitCode = exitCode
	result.LogBytes = stdout.total + stderr.total
	result.LogTruncated = stdout.truncated || stderr.truncated
	result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated || len(stderr.Bytes()) != 0 {
		return signalHelperResult{}, result, fmt.Errorf(
			"trusted signal helper failed with exit %d: %w",
			exitCode,
			runErr,
		)
	}
	response, err := decodeSignalHelperResult(stdout.Bytes())
	if err != nil {
		return signalHelperResult{}, result, err
	}
	delivered, alreadyExited := classifySignalHelperResult(
		response,
		allowQuiescentNoop,
	)
	if !delivered && !alreadyExited {
		return response, result, errors.New(
			"service signal did not target and terminate the observed workload process set",
		)
	}
	response.AlreadyExited = alreadyExited
	return response, result, nil
}

func decodeSignalHelperResult(raw []byte) (signalHelperResult, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return signalHelperResult{}, errors.New(
			"signal helper response must be one object",
		)
	}

	response := signalHelperResult{}
	seen := make(map[string]struct{}, 5)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return signalHelperResult{}, errors.New(
				"signal helper response has an invalid key",
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return signalHelperResult{}, errors.New(
				"signal helper response has a duplicate key",
			)
		}
		seen[key] = struct{}{}

		var destination any
		switch key {
		case "ok":
			destination = &response.OK
		case "escalated":
			destination = &response.Escalated
		case "remaining":
			destination = &response.Remaining
		case "initialTargets":
			destination = &response.InitialTargets
		case "sent":
			destination = &response.Sent
		default:
			return signalHelperResult{}, errors.New(
				"signal helper response has an unknown key",
			)
		}
		if err := decodeRequiredSignalValue(decoder, destination); err != nil {
			return signalHelperResult{}, err
		}
	}

	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return signalHelperResult{}, errors.New(
			"signal helper response is truncated",
		)
	}
	if len(seen) != 5 {
		return signalHelperResult{}, errors.New(
			"signal helper response is missing a required key",
		)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return signalHelperResult{}, errors.New(
			"signal helper returned trailing data",
		)
	}
	return response, nil
}

func decodeRequiredSignalValue(decoder *json.Decoder, destination any) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("signal helper response has a null value")
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return err
	}
	return nil
}

func classifySignalHelperResult(
	response signalHelperResult,
	allowQuiescentNoop bool,
) (delivered bool, quiescentNoop bool) {
	delivered = response.OK &&
		response.Remaining == 0 &&
		response.InitialTargets >= 1 &&
		response.Sent >= 1 &&
		response.Sent <= response.InitialTargets
	quiescentNoop = response.OK &&
		allowQuiescentNoop &&
		!response.Escalated &&
		response.Remaining == 0 &&
		response.InitialTargets >= 0 &&
		response.Sent == 0
	return delivered, quiescentNoop
}

func serviceExitObservation(
	now time.Time,
	prepared *PreparedRun,
	service *runningService,
	execution stepExecution,
	expected bool,
	exitedBeforeSignal bool,
) domain.ObservationEvent {
	result := "failed"
	if expected {
		result = "succeeded"
	}
	return lifecycleObservation(
		now,
		prepared,
		domain.PhaseCleanup,
		"service.exit",
		service.command.ID,
		result,
		map[string]any{
			"exitCode":           execution.result.ExitCode,
			"timedOut":           execution.result.TimedOut,
			"logBytes":           execution.result.LogBytes,
			"logTruncated":       execution.result.LogTruncated,
			"exitedBeforeSignal": exitedBeforeSignal,
		},
	)
}

func signalObservation(
	now time.Time,
	prepared *PreparedRun,
	command domain.PlanCommand,
	helper signalHelperResult,
	err error,
) domain.ObservationEvent {
	result := "succeeded"
	if err != nil {
		result = "failed"
	}
	return lifecycleObservation(
		now,
		prepared,
		domain.PhaseCleanup,
		"service.signal",
		command.Signal.Target,
		result,
		map[string]any{
			"signal":         strings.ToUpper(command.Signal.Type),
			"escalated":      helper.Escalated,
			"remaining":      helper.Remaining,
			"initialTargets": helper.InitialTargets,
			"sent":           helper.Sent,
			"alreadyExited":  helper.AlreadyExited,
		},
	)
}

func boundedSignalFinalizationTimeout(
	resolved time.Duration,
	cleanup time.Duration,
) time.Duration {
	if cleanup > 0 && cleanup < resolved {
		return cleanup
	}
	return resolved
}
