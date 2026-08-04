package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	nodeHTTPDriverQuiesceScript   = `const fs=require("node:fs");const sleep=new Int32Array(new SharedArrayBuffer(4));function targets(){const result=[];for(const name of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(name))continue;try{const status=fs.readFileSync("/proc/"+name+"/status","utf8"),uid=/^Uid:\s+(\d+)\s+(\d+)/m.exec(status),state=/^State:\s+([A-Z])/m.exec(status);if(uid&&(uid[1]==="65533"||uid[2]==="65533")&&(!state||!/^[ZX]$/.test(state[1])))result.push(Number(name));}catch(error){if(error.code!=="ENOENT")throw error;}}return result;}let killed=0;for(let pass=0;pass<50&&targets().length;pass++){for(const pid of targets()){try{process.kill(pid,"SIGKILL");killed++;}catch(error){if(error.code!=="ESRCH")throw error;}}Atomics.wait(sleep,0,0,10);}const remaining=targets().length,ok=remaining===0;process.stdout.write(JSON.stringify({ok,remaining,killed})+"\n");if(!ok)process.exitCode=1;`
	pythonHTTPDriverQuiesceScript = `import json,os,re,signal,time
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
        if uid and 65533 in (int(uid.group(1)),int(uid.group(2))) and (not state or state.group(1) not in "ZX"):
            result.append(int(name))
    return result
killed=0
for _ in range(50):
    current=targets()
    if not current:
        break
    for pid in current:
        try:
            os.kill(pid,signal.SIGKILL)
            killed+=1
        except ProcessLookupError:
            pass
    time.sleep(0.01)
remaining=len(targets())
ok=remaining==0
print(json.dumps({"ok":ok,"remaining":remaining,"killed":killed},separators=(",",":")))
raise SystemExit(0 if ok else 1)`
)

var errHTTPDriverResidue = errors.New(
	"trusted HTTP driver residue could not be quiesced",
)

type httpDriverQuiesceResponse struct {
	OK        bool `json:"ok"`
	Remaining int  `json:"remaining"`
	Killed    int  `json:"killed"`
}

func (r *Runner) quiesceHTTPDriverProcesses(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) error {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return errors.New(
			"runtime adapter has no trusted HTTP driver quiescence helper",
		)
	}
	scriptArgs := []string{"-e", nodeHTTPDriverQuiesceScript}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		scriptArgs = []string{
			"-I", "-S", "-c",
			pythonHTTPDriverQuiesceScript,
		}
	}
	args := []string{
		"exec",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(args, scriptArgs...)
	stdout := &cappedBuffer{limit: 4096}
	stderr := &cappedBuffer{limit: 4096}
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated {
		return fmt.Errorf(
			"trusted HTTP driver quiescence helper failed with exit %d: %w",
			exitCode,
			runErr,
		)
	}
	var response httpDriverQuiesceResponse
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New(
			"trusted HTTP driver quiescence helper returned trailing data",
		)
	}
	if !response.OK ||
		response.Remaining != 0 ||
		response.Killed < 0 {
		return errors.New(
			"trusted HTTP driver processes remain after quiescence",
		)
	}
	return nil
}

func (r *Runner) cleanupHTTPDriverAfterFailure(
	prepared *PreparedRun,
	containerName string,
	cause error,
) error {
	timeout := r.config.CleanupTimeout
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := r.quiesceHTTPDriverProcesses(
		ctx,
		prepared,
		containerName,
	); err != nil {
		residue := fmt.Errorf("%w: %v", errHTTPDriverResidue, err)
		return errors.Join(cause, residue)
	}
	return cause
}
