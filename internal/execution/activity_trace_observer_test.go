package execution

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestActivityTraceFrameDecoderRejectsUntrustedTransport(t *testing.T) {
	token := strings.Repeat("a", 64)
	sessionDigest := activityTraceSessionDigest(token)
	ready := `{"type":"ready","schemaVersion":"1","sessionDigest":"` +
		sessionDigest +
		`","observerAdapter":"node-fs-watch-linux"}`
	decodedReady, err := decodeActivityTraceReadyFrame([]byte(ready))
	if err != nil ||
		decodedReady.ObserverAdapter != "node-fs-watch-linux" {
		t.Fatalf("valid ready frame rejected: %#v, %v", decodedReady, err)
	}

	for name, raw := range map[string][]byte{
		"duplicate": []byte(`{"type":"ready","type":"ready","schemaVersion":"1","sessionDigest":"` +
			sessionDigest +
			`","observerAdapter":"node-fs-watch-linux"}`),
		"unknown": []byte(`{"type":"ready","schemaVersion":"1","sessionDigest":"` +
			sessionDigest +
			`","observerAdapter":"node-fs-watch-linux","extra":true}`),
		"cross-adapter": []byte(`{"type":"ready","schemaVersion":"1","sessionDigest":"` +
			sessionDigest +
			`","observerAdapter":"untrusted-watch"}`),
		"trailing": append([]byte(ready), []byte(`{}`)...),
		"invalid-utf8": {
			'{', '"', 'x', '"', ':', '"', 0xff, '"', '}',
		},
		"oversize": []byte(`{"` +
			strings.Repeat("x", activityTraceFrameLimit) +
			`":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeActivityTraceReadyFrame(raw); err == nil {
				t.Fatal("untrusted ready frame was accepted")
			}
		})
	}

	validFinal := validActivityTraceFinalJSON(
		sessionDigest,
		"node-fs-watch-linux",
	)
	result, err := decodeActivityTraceFinalFrame(
		validFinal,
		sessionDigest,
		"node-fs-watch-linux",
	)
	if err != nil || result.NotificationCount != 1 ||
		result.ExerciseCount != 1 {
		t.Fatalf("valid final frame rejected: %#v, %v", result, err)
	}
	validFailed := validActivityTraceFailedJSON(
		sessionDigest,
		activityTraceFailureOverflow,
	)
	failed, err := decodeActivityTraceFinalFrame(
		validFailed,
		sessionDigest,
		"python-inotify-linux",
	)
	if err != nil || failed.Failure != activityTraceFailureOverflow ||
		failed.ObserverAdapter != "python-inotify-linux" ||
		failed.OperationNotification != nil {
		t.Fatalf("valid failed frame rejected: %#v, %v", failed, err)
	}
	if _, err := decodeActivityTraceFinalFrame(
		validFailed,
		sessionDigest,
		"node-fs-watch-linux",
	); err == nil {
		t.Fatal("Python failed frame crossed into the Node union")
	}

	var valid map[string]any
	if err := json.Unmarshal(validFinal, &valid); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"session-swap": func(value map[string]any) {
			value["sessionDigest"] = "sha256:" + strings.Repeat("b", 64)
		},
		"adapter-swap": func(value map[string]any) {
			value["observerAdapter"] = "python-inotify-linux"
		},
		"overflow": func(value map[string]any) {
			value["overflowDetected"] = true
		},
		"gap": func(value map[string]any) {
			value["gapDetected"] = true
		},
		"count-mismatch": func(value map[string]any) {
			value["exerciseCount"] = 0
		},
		"classification-mismatch": func(value map[string]any) {
			value["renameHintCount"] = 0
		},
		"negative-phase-offset": func(value map[string]any) {
			value["setupCount"] = -1
			value["exerciseCount"] = 2
		},
		"negative-classification-offset": func(value map[string]any) {
			value["renameHintCount"] = -1
			value["changeHintCount"] = 2
		},
		"too-many-events": func(value map[string]any) {
			value["notificationCount"] =
				activityTraceNotificationLimit + 1
			value["renameHintCount"] =
				activityTraceNotificationLimit + 1
			value["exerciseCount"] =
				activityTraceNotificationLimit + 1
		},
		"oversize-canonical": func(value map[string]any) {
			value["canonicalByteCount"] =
				activityTraceRawDigestLimit + 1
		},
		"bad-digest": func(value map[string]any) {
			value["canonicalTranscriptDigest"] = "sha256:bad"
		},
		"not-ok": func(value map[string]any) {
			value["ok"] = false
		},
		"unknown-key": func(value map[string]any) {
			value["rawPath"] = "/outputs/secret"
		},
	}
	for name, mutate := range mutations {
		t.Run("final-"+name, func(t *testing.T) {
			copied := make(map[string]any, len(valid))
			for key, value := range valid {
				copied[key] = value
			}
			mutate(copied)
			raw, err := json.Marshal(copied)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeActivityTraceFinalFrame(
				raw,
				sessionDigest,
				"node-fs-watch-linux",
			); err == nil {
				t.Fatal("untrusted final frame was accepted")
			}
		})
	}

	var failedBase map[string]any
	if err := json.Unmarshal(validFailed, &failedBase); err != nil {
		t.Fatal(err)
	}
	failedMutations := map[string]func(map[string]any){
		"extra": func(value map[string]any) {
			value["notificationCount"] = 1
		},
		"wrong-union": func(value map[string]any) {
			value["type"] = "final"
		},
		"wrong-schema": func(value map[string]any) {
			value["schemaVersion"] = "2"
		},
		"wrong-session": func(value map[string]any) {
			value["sessionDigest"] = "sha256:" + strings.Repeat("b", 64)
		},
		"wrong-ok": func(value map[string]any) {
			value["ok"] = true
		},
		"wrong-adapter": func(value map[string]any) {
			value["observerAdapter"] = "node-fs-watch-linux"
		},
		"unknown-failure": func(value map[string]any) {
			value["failure"] = "unknown"
		},
		"missing-failure": func(value map[string]any) {
			delete(value, "failure")
		},
	}
	for name, mutate := range failedMutations {
		t.Run("failed-"+name, func(t *testing.T) {
			copied := make(map[string]any, len(failedBase))
			for key, value := range failedBase {
				copied[key] = value
			}
			mutate(copied)
			raw, err := json.Marshal(copied)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeActivityTraceFinalFrame(
				raw,
				sessionDigest,
				"python-inotify-linux",
			); err == nil {
				t.Fatal("invalid failed frame was accepted")
			}
		})
	}
	duplicateFailed := []byte(`{"type":"failed","schemaVersion":"1","sessionDigest":"` +
		sessionDigest +
		`","ok":false,"observerAdapter":"python-inotify-linux","failure":"notification-gap","failure":"notification-gap"}`)
	if _, err := decodeActivityTraceFinalFrame(
		duplicateFailed,
		sessionDigest,
		"python-inotify-linux",
	); err == nil {
		t.Fatal("failed frame with duplicate failure was accepted")
	}
}

func TestActivityTraceFrameStreamRequiresExactlyReadyAndFinal(t *testing.T) {
	stream := newActivityTraceFrameStream()
	if _, err := stream.Write([]byte(`{"type":"ready"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte(`{"type":"final"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if !stream.complete() {
		t.Fatal("exactly two complete frames were not accepted")
	}
	if _, err := stream.Write([]byte(`{"type":"extra"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if stream.complete() {
		t.Fatal("third stdout frame did not invalidate transport")
	}

	oversize := newActivityTraceFrameStream()
	if _, err := oversize.Write(
		[]byte(strings.Repeat("x", activityTraceFrameLimit+1)),
	); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := oversize.next(ctx); err == nil {
		t.Fatal("oversize partial frame did not fail closed")
	}

	trailing := newActivityTraceFrameStream()
	_, _ = trailing.Write([]byte(`{"type":"ready"}` + "\n"))
	_, _ = trailing.Write([]byte(`{"type":"final"}` + "\n" + "x"))
	if trailing.complete() {
		t.Fatal("trailing stdout bytes were accepted")
	}
}

func TestActivityTraceControlWriteTimeoutClosesAndJoins(t *testing.T) {
	writer := newBlockingActivityTraceWriter()
	cancelled := make(chan struct{})
	session := &activityTraceSession{
		stdin: writer,
		cancel: func() {
			select {
			case <-cancelled:
			default:
				close(cancelled)
			}
		},
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	started := time.Now()
	err := session.writeControl(ctx, map[string]string{
		"command": "start",
		"token":   strings.Repeat("a", 64),
	})
	if err == nil {
		t.Fatal("blocked control writer was accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("blocked control writer exceeded its context bound")
	}
	select {
	case <-writer.returned:
	default:
		t.Fatal("blocked writer goroutine was not joined")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("blocked writer did not cancel the helper")
	}
}

func TestActivityTraceControlWriteRemainsBoundedWhenCloseDoesNotUnblock(
	t *testing.T,
) {
	writer := &stubbornActivityTraceWriter{
		block: make(chan struct{}),
	}
	session := &activityTraceSession{
		stdin:  writer,
		cancel: func() {},
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	started := time.Now()
	err := session.writeControl(ctx, map[string]string{
		"command": "start",
		"token":   strings.Repeat("a", 64),
	})
	if err == nil {
		t.Fatal("stubborn control writer was accepted")
	}
	if time.Since(started) >
		activityTraceWriteJoinTimeout+500*time.Millisecond {
		t.Fatal("stubborn writer escaped the bounded drain window")
	}
	close(writer.block)
}

func TestActivityTraceUsesExactAsyncArgvAndOpaqueSession(t *testing.T) {
	executor := &scriptedActivityTraceExecutor{}
	runner := NewRunner(executor, DefaultConfig())
	containerID := strings.Repeat("c", 64)
	prepared := &PreparedRun{
		Backend: "docker",
		executionPlan: domain.ResolvedPlan{
			RuntimeAdapter: "node",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := runner.startOutputsActivityTrace(
		ctx,
		prepared,
		containerID,
	)
	if err != nil {
		t.Fatalf("startOutputsActivityTrace: %v", err)
	}
	if err := session.setPhase(ctx, domain.PhaseExercise); err != nil {
		t.Fatalf("setPhase: %v", err)
	}
	result, err := session.finish(ctx)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	if result.ObserverAdapter != "node-fs-watch-linux" ||
		result.NotificationCount != 1 ||
		result.ExerciseCount != 1 {
		t.Fatalf("activity result = %#v", result)
	}
	call := executor.startCall()
	wantPrefix := []string{
		"exec", "--interactive",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerID, "node", "-e", nodeActivityTraceScript,
	}
	if call.name != "docker" ||
		len(call.args) != len(wantPrefix) {
		t.Fatalf("async call = %#v, want exact Docker argv", call)
	}
	for index := range wantPrefix {
		if call.args[index] != wantPrefix[index] {
			t.Fatalf(
				"async argv[%d] = %q, want %q",
				index,
				call.args[index],
				wantPrefix[index],
			)
		}
	}
	joinedArgs := strings.Join(call.args, "\x00")
	if strings.Contains(joinedArgs, session.token) ||
		strings.Contains(joinedArgs, session.sessionDigest) ||
		containsArgument(call.args, "sh") ||
		containsArgument(call.args, "bash") ||
		containsArgument(call.args, "powershell") {
		t.Fatal("session material or shell leaked into async argv")
	}
	if executor.seenToken() != session.token {
		t.Fatal("session token was not transported only through stdin")
	}
}

func TestActivityTraceFinishAcceptsExactTypedFailedExitOne(t *testing.T) {
	token := strings.Repeat("a", 64)
	digest := activityTraceSessionDigest(token)
	stream := newOperationNotificationFrameStream()
	ready, err := json.Marshal(map[string]any{
		"type":            "ready",
		"schemaVersion":   "1",
		"sessionDigest":   digest,
		"observerAdapter": "python-inotify-linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(append(ready, '\n')); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := stream.next(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(append(
		validActivityTraceFailedJSON(
			digest,
			activityTraceFailureNewDirectoryGap,
		),
		'\n',
	)); err != nil {
		t.Fatal(err)
	}
	wait := make(chan activityTraceProcessResult, 1)
	wait <- activityTraceProcessResult{
		exitCode: 1,
		err:      errors.New("exit status 1"),
	}
	session := &activityTraceSession{
		token:           token,
		sessionDigest:   digest,
		expectedAdapter: "python-inotify-linux",
		stdin:           &operationNotificationTestWriter{},
		stream:          stream,
		stderr:          &activityTraceLockedBuffer{limit: activityTraceStderrLimit},
		cancel:          func() {},
		wait:            wait,
		abortDone:       make(chan struct{}),
	}
	result, err := session.finish(ctx)
	if err != nil {
		t.Fatalf("typed fail-closed finish: %v", err)
	}
	if result.Failure != activityTraceFailureNewDirectoryGap ||
		result.ObserverAdapter != "python-inotify-linux" ||
		result.OperationNotification != nil {
		t.Fatalf("typed fail-closed result = %#v", result)
	}
}

func TestActivityTraceStartRejectsNilAsyncProcessAndStdin(t *testing.T) {
	containerID := strings.Repeat("c", 64)
	prepared := &PreparedRun{
		Backend: "docker",
		executionPlan: domain.ResolvedPlan{
			RuntimeAdapter: "node",
		},
	}
	t.Run("nil process", func(t *testing.T) {
		runner := NewRunner(
			&invalidActivityTraceExecutor{},
			DefaultConfig(),
		)
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		if _, err := runner.startOutputsActivityTrace(
			ctx,
			prepared,
			containerID,
		); err == nil {
			t.Fatal("nil async process was accepted")
		}
	})
	t.Run("nil stdin", func(t *testing.T) {
		waited := make(chan struct{})
		runner := NewRunner(
			&invalidActivityTraceExecutor{
				process: &nilStdinActivityTraceProcess{
					waited: waited,
				},
			},
			DefaultConfig(),
		)
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		if _, err := runner.startOutputsActivityTrace(
			ctx,
			prepared,
			containerID,
		); err == nil {
			t.Fatal("nil activity-trace stdin was accepted")
		}
		select {
		case <-waited:
		default:
			t.Fatal("nil-stdin process was not reaped")
		}
	})
}

func TestActivityTraceHelperScriptsFreezeBoundedManualWatchContracts(
	t *testing.T,
) {
	if strings.Contains(nodeActivityTraceScript, "recursive:true") {
		t.Fatal("Node helper must use bounded manual per-directory watchers")
	}
	for adapter, script := range map[string]string{
		"node":   nodeActivityTraceScript,
		"python": pythonActivityTraceScript,
	} {
		if !strings.Contains(script, "MAX_WATCHES=2048") {
			t.Fatalf("%s helper does not freeze the 2048 watch limit", adapter)
		}
	}
	if !strings.Contains(
		nodeActivityTraceScript,
		"if(watchers.size>=MAX_WATCHES){overflow=true;final(false);return;}",
	) {
		t.Fatal("Node watch-limit fail-close marker is absent")
	}
	if !strings.Contains(
		pythonActivityTraceScript,
		"if len(watches)>=MAX_WATCHES:overflow=True;return",
	) ||
		!strings.Contains(
			pythonActivityTraceScript,
			"if gap or overflow:break",
		) {
		t.Fatal("Python watch-limit traversal fail-close marker is absent")
	}
	if !strings.Contains(
		pythonActivityTraceScript,
		"if gap or overflow:final(False);sys.exit(1)",
	) {
		t.Fatal("Python startup watch-limit failure is not fail closed")
	}
	for _, marker := range []string{
		"def record(wd,mask,name):",
		`if wd not in watches:latch("notification-gap");return`,
		"directory=watches[wd];path_bytes=len(directory)+1+len(name)",
		`directory+b"\0"+name`,
		`if path_bytes>MAX_PATH:latch("notification-gap");return`,
		"record(wd,mask,name)",
		"def latch(reason):",
		"if failure:return",
		"if watching:sources.insert(0,fd)",
		"if failure:failed()",
	} {
		if !strings.Contains(pythonActivityTraceScript, marker) {
			t.Fatalf(
				"Python full-path keyed commitment marker %q is absent",
				marker,
			)
		}
	}
	overflowIndex := strings.Index(
		pythonActivityTraceScript,
		`if mask&IN_Q_OVERFLOW:latch("notification-overflow");return`,
	)
	watchIdentityIndex := strings.Index(
		pythonActivityTraceScript,
		`if wd not in watches:latch("notification-gap");return`,
	)
	if overflowIndex < 0 || watchIdentityIndex < 0 ||
		overflowIndex > watchIdentityIndex {
		t.Fatal("Python queue overflow is not handled before watch identity")
	}
}

func TestActivityTraceSummaryFailsClosed(t *testing.T) {
	complete := activityTraceObservationState{
		required:                   true,
		backendEligible:            true,
		startIdentityVerified:      true,
		readyIdentityVerified:      true,
		stopIdentityVerified:       true,
		finalIdentityVerified:      true,
		workloadQuiescenceVerified: true,
		ready:                      true,
		finalReady:                 true,
		phaseSignalsComplete:       true,
		result: activityTraceResult{
			ObserverAdapter:           "node-fs-watch-linux",
			NotificationCount:         2,
			RenameHintCount:           1,
			ChangeHintCount:           1,
			ExerciseCount:             2,
			CanonicalTranscriptDigest: "sha256:" + strings.Repeat("d", 64),
			CanonicalByteCount:        128,
		},
	}
	event, coverage := summarizeOutputsActivityTrace(
		complete,
		time.Unix(1, 0),
	)
	if coverage != coverageBestEffort ||
		event.Coverage != coverageBestEffort ||
		event.Result != "observed" ||
		event.Operation != "filesystem.activity-trace.summary" ||
		event.Observer != "docker-outputs-activity-trace" {
		t.Fatalf("complete summary = %#v", event)
	}
	if event.Details["operationHistoryCoverage"] != coverageUnavailable ||
		event.Details["kernelOverflowDetection"] != coverageUnavailable ||
		event.Details["actorAttribution"] != "unavailable" ||
		event.Details["watchLimit"] != activityTraceWatchLimit ||
		event.Details["observerPlacement"] !=
			"in-sandbox-trusted-helper" ||
		event.Details["sharesSandboxResourceBudget"] != true {
		t.Fatalf("summary overclaims semantics: %#v", event.Details)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"/outputs/transient-secret",
		`"path"`,
		`"content"`,
		"sessionDigest",
		"token",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("public summary leaked %q: %s", forbidden, raw)
		}
	}

	mutations := map[string]func(*activityTraceObservationState){
		"podman": func(state *activityTraceObservationState) {
			state.backendEligible = false
		},
		"start-identity": func(state *activityTraceObservationState) {
			state.startIdentityVerified = false
		},
		"ready-identity": func(state *activityTraceObservationState) {
			state.readyIdentityVerified = false
		},
		"stop-identity": func(state *activityTraceObservationState) {
			state.stopIdentityVerified = false
		},
		"final-identity": func(state *activityTraceObservationState) {
			state.finalIdentityVerified = false
		},
		"quiescence": func(state *activityTraceObservationState) {
			state.workloadQuiescenceVerified = false
		},
		"phase-control": func(state *activityTraceObservationState) {
			state.phaseSignalsComplete = false
		},
		"overflow": func(state *activityTraceObservationState) {
			state.result.OverflowDetected = true
		},
		"gap": func(state *activityTraceObservationState) {
			state.result.GapDetected = true
		},
		"typed-failure": func(state *activityTraceObservationState) {
			state.result.Failure = activityTraceFailureOverflow
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			state := complete
			mutate(&state)
			event, coverage := summarizeOutputsActivityTrace(
				state,
				time.Unix(1, 0),
			)
			if coverage != coverageUnavailable ||
				event.Coverage != coverageUnavailable ||
				event.Result != "unavailable" {
				t.Fatalf("incomplete summary = %#v", event)
			}
			if _, present := event.Details["notificationCount"]; present {
				t.Fatal("incomplete summary exposed partial counts")
			}
			if _, present := event.Details["canonicalTranscriptDigest"]; present {
				t.Fatal("incomplete summary exposed partial commitment")
			}
			if name == "typed-failure" &&
				event.Details["failure"] != activityTraceFailureOverflow {
				t.Fatalf("typed failure was not published safely: %#v", event)
			}
		})
	}
}

func TestExecutePublishesActivityTraceWithoutCompletingRequiredFilesystemObserver(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(
		t,
		sourceRoot+"/app.js",
		[]byte("console.log('ok')\n"),
	)
	plan := testPlan(t, sourceRoot)
	plan.ObserverSet = []string{"filesystem-write"}
	plan.ObserverVersions = map[string]string{
		"filesystem-write": "0.4.0",
	}
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"observer:filesystem-write",
	)
	workloadRan := false
	executor := &scriptedActivityTraceExecutor{
		runHandler: successfulNodeSandbox(func(
			_ context.Context,
			_ string,
			_ []string,
			_ io.Writer,
			_ io.Writer,
		) (int, error) {
			workloadRan = true
			return 0, nil
		}),
	}
	outcome, err := testRunner(executor).Execute(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !workloadRan {
		t.Fatal("workload did not run after activity trace ready")
	}
	if outcome.Runner.FilesystemWriteObservation != coverageBestEffort {
		t.Fatalf(
			"filesystem coverage = %q, want best-effort",
			outcome.Runner.FilesystemWriteObservation,
		)
	}
	if !containsString(
		outcome.IncompleteFeatures,
		"observer:filesystem-write",
	) {
		t.Fatalf(
			"required filesystem observer was incorrectly completed: %#v",
			outcome.IncompleteFeatures,
		)
	}
	var summary *domain.ObservationEvent
	for index := range outcome.Observations {
		if outcome.Observations[index].Operation ==
			"filesystem.activity-trace.summary" {
			summary = &outcome.Observations[index]
			break
		}
	}
	if summary == nil ||
		summary.Coverage != coverageBestEffort ||
		summary.Result != "observed" ||
		summary.Details["operationHistoryCoverage"] !=
			coverageUnavailable {
		t.Fatalf("activity summary = %#v", summary)
	}
}

func validActivityTraceFinalJSON(
	sessionDigest string,
	adapter string,
) []byte {
	value := map[string]any{
		"type":                      "final",
		"schemaVersion":             "1",
		"sessionDigest":             sessionDigest,
		"ok":                        true,
		"observerAdapter":           adapter,
		"notificationCount":         1,
		"renameHintCount":           1,
		"changeHintCount":           0,
		"setupCount":                0,
		"buildCount":                0,
		"runCount":                  0,
		"exerciseCount":             1,
		"cleanupCount":              0,
		"unknownCount":              0,
		"overflowDetected":          false,
		"gapDetected":               false,
		"canonicalTranscriptDigest": "sha256:" + strings.Repeat("c", 64),
		"canonicalByteCount":        64,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func validActivityTraceFailedJSON(
	sessionDigest string,
	failure string,
) []byte {
	value := map[string]any{
		"type":            "failed",
		"schemaVersion":   "1",
		"sessionDigest":   sessionDigest,
		"ok":              false,
		"observerAdapter": "python-inotify-linux",
		"failure":         failure,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

type blockingActivityTraceWriter struct {
	once     sync.Once
	closed   chan struct{}
	returned chan struct{}
}

type stubbornActivityTraceWriter struct {
	block chan struct{}
}

func (w *stubbornActivityTraceWriter) Write(
	_ []byte,
) (int, error) {
	<-w.block
	return 0, errors.New("released")
}

func (*stubbornActivityTraceWriter) Close() error {
	return nil
}

func newBlockingActivityTraceWriter() *blockingActivityTraceWriter {
	return &blockingActivityTraceWriter{
		closed:   make(chan struct{}),
		returned: make(chan struct{}),
	}
}

func (w *blockingActivityTraceWriter) Write(
	_ []byte,
) (int, error) {
	<-w.closed
	close(w.returned)
	return 0, errors.New("closed")
}

func (w *blockingActivityTraceWriter) Close() error {
	w.once.Do(func() {
		close(w.closed)
	})
	return nil
}

type scriptedActivityTraceExecutor struct {
	mu         sync.Mutex
	call       commandCall
	token      string
	runHandler func(
		context.Context,
		string,
		[]string,
		io.Writer,
		io.Writer,
	) (int, error)
}

type invalidActivityTraceExecutor struct {
	process RunningCommand
}

func (*invalidActivityTraceExecutor) Run(
	_ context.Context,
	_ string,
	_ []string,
	_ io.Writer,
	_ io.Writer,
) (int, error) {
	return 0, nil
}

func (e *invalidActivityTraceExecutor) Start(
	_ context.Context,
	_ string,
	_ []string,
	_ io.Writer,
	_ io.Writer,
) (RunningCommand, error) {
	return e.process, nil
}

type nilStdinActivityTraceProcess struct {
	waited chan struct{}
}

func (*nilStdinActivityTraceProcess) Stdin() io.WriteCloser {
	return nil
}

func (p *nilStdinActivityTraceProcess) Wait() (int, error) {
	close(p.waited)
	return 0, nil
}

func (e *scriptedActivityTraceExecutor) Run(
	ctx context.Context,
	name string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	if e.runHandler == nil {
		return 0, nil
	}
	return e.runHandler(ctx, name, args, stdout, stderr)
}

func (e *scriptedActivityTraceExecutor) Start(
	ctx context.Context,
	name string,
	args []string,
	stdout io.Writer,
	_ io.Writer,
) (RunningCommand, error) {
	e.mu.Lock()
	e.call = commandCall{name: name, args: cloneStrings(args)}
	e.mu.Unlock()
	reader, writer := io.Pipe()
	wait := make(chan activityTraceProcessResult, 1)
	process := &scriptedActivityTraceProcess{
		stdin: writer,
		wait:  wait,
	}
	adapter := "node-fs-watch-linux"
	if containsArgument(args, pythonActivityTraceScript) {
		adapter = "python-inotify-linux"
	}
	go func() {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 512), 1024)
		phaseCounts := map[string]int{
			"setup": 0, "build": 0, "run": 0,
			"exercise": 0, "cleanup": 0, "unknown": 0,
		}
		finish := func(exitCode int, err error) {
			_ = reader.Close()
			wait <- activityTraceProcessResult{
				exitCode: exitCode,
				err:      err,
			}
		}
		if !scanner.Scan() {
			finish(-1, errors.New("missing start"))
			return
		}
		var start map[string]string
		if json.Unmarshal(scanner.Bytes(), &start) != nil ||
			start["command"] != "start" ||
			len(start["token"]) != 64 {
			finish(-1, errors.New("bad start"))
			return
		}
		token := start["token"]
		e.mu.Lock()
		e.token = token
		e.mu.Unlock()
		sessionDigest := activityTraceSessionDigest(token)
		ready, _ := json.Marshal(map[string]any{
			"type":            "ready",
			"schemaVersion":   "1",
			"sessionDigest":   sessionDigest,
			"observerAdapter": adapter,
		})
		_, _ = stdout.Write(append(ready, '\n'))
		for scanner.Scan() {
			var control map[string]string
			if json.Unmarshal(scanner.Bytes(), &control) != nil ||
				control["token"] != token {
				finish(-1, errors.New("bad control"))
				return
			}
			switch control["command"] {
			case "phase":
				phaseCounts[control["phase"]]++
			case "stop":
				notifications := 0
				for _, count := range phaseCounts {
					notifications += count
				}
				digest := sha256.Sum256(
					[]byte("canonical-test-transcript"),
				)
				final, _ := json.Marshal(map[string]any{
					"type":              "final",
					"schemaVersion":     "1",
					"sessionDigest":     sessionDigest,
					"ok":                true,
					"observerAdapter":   adapter,
					"notificationCount": notifications,
					"renameHintCount":   notifications,
					"changeHintCount":   0,
					"setupCount":        phaseCounts["setup"],
					"buildCount":        phaseCounts["build"],
					"runCount":          phaseCounts["run"],
					"exerciseCount":     phaseCounts["exercise"],
					"cleanupCount":      phaseCounts["cleanup"],
					"unknownCount":      phaseCounts["unknown"],
					"overflowDetected":  false,
					"gapDetected":       false,
					"canonicalTranscriptDigest": "sha256:" +
						hexLower(digest[:]),
					"canonicalByteCount": 32,
				})
				_, _ = stdout.Write(append(final, '\n'))
				finish(0, nil)
				return
			default:
				finish(-1, errors.New("unknown control"))
				return
			}
		}
		select {
		case <-ctx.Done():
			finish(-1, ctx.Err())
		default:
			finish(-1, errors.New("missing stop"))
		}
	}()
	return process, nil
}

func (e *scriptedActivityTraceExecutor) startCall() commandCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return commandCall{
		name: e.call.name,
		args: cloneStrings(e.call.args),
	}
}

func (e *scriptedActivityTraceExecutor) seenToken() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.token
}

type scriptedActivityTraceProcess struct {
	stdin io.WriteCloser
	wait  <-chan activityTraceProcessResult
}

func (p *scriptedActivityTraceProcess) Stdin() io.WriteCloser {
	return p.stdin
}

func (p *scriptedActivityTraceProcess) Wait() (int, error) {
	result := <-p.wait
	return result.exitCode, result.err
}

func hexLower(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&0x0f]
	}
	return string(result)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

var _ AsyncCommandExecutor = (*scriptedActivityTraceExecutor)(nil)
var _ RunningCommand = (*scriptedActivityTraceProcess)(nil)
var _ AsyncCommandExecutor = (*invalidActivityTraceExecutor)(nil)
var _ RunningCommand = (*nilStdinActivityTraceProcess)(nil)
