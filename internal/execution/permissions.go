package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const (
	nodeIdleScript                 = `setInterval(()=>{},2147483647)`
	quiescentWorkloadProcessStates = "ZX"
	trustedHelperWorkdir           = "/"
	pythonIdleScript               = `import time
time.sleep(2147483647)`
	nodeOutputInitScript   = `const fs=require("node:fs");for(const p of ["/outputs/.home","/outputs/.tmp"]){fs.mkdirSync(p,{recursive:false,mode:0o700});fs.chmodSync(p,0o700);}`
	pythonOutputInitScript = `import os
for path in ("/outputs/.home","/outputs/.tmp"):
    os.mkdir(path,0o700)
    os.chmod(path,0o700)`
	nodeWorkloadIdentityScript   = `const fs=require("node:fs"),status=fs.readFileSync("/proc/self/status","utf8");const field=name=>{const match=new RegExp("^"+name+":\\s*([0-9a-f]+)$","mi").exec(status);if(!match)throw new Error("missing "+name);return match[1].toLowerCase();};const result={uid:process.getuid(),euid:process.geteuid(),gid:process.getgid(),egid:process.getegid(),capInh:field("CapInh"),capPrm:field("CapPrm"),capEff:field("CapEff"),capAmb:field("CapAmb"),noNewPrivs:Number(field("NoNewPrivs"))};if(result.uid!==65532||result.euid!==65532||result.gid!==65532||result.egid!==65532||![result.capInh,result.capPrm,result.capEff,result.capAmb].every(value=>/^0+$/.test(value))||result.noNewPrivs!==1)throw new Error("unsafe workload identity");process.stdout.write(JSON.stringify(result)+"\n");`
	pythonWorkloadIdentityScript = `import json,os,re
with open("/proc/self/status",encoding="ascii") as source:
    status=source.read()
def field(name):
    match=re.search(r"^"+name+r":\s*([0-9a-f]+)$",status,re.MULTILINE|re.IGNORECASE)
    if not match:
        raise RuntimeError("missing "+name)
    return match.group(1).lower()
result={"uid":os.getuid(),"euid":os.geteuid(),"gid":os.getgid(),"egid":os.getegid(),"capInh":field("CapInh"),"capPrm":field("CapPrm"),"capEff":field("CapEff"),"capAmb":field("CapAmb"),"noNewPrivs":int(field("NoNewPrivs"))}
if any(result[name]!=65532 for name in ("uid","euid","gid","egid")) or any(set(result[name])!={"0"} for name in ("capInh","capPrm","capEff","capAmb")) or result["noNewPrivs"]!=1:
    raise RuntimeError("unsafe workload identity")
print(json.dumps(result,separators=(",",":")))`
	nodeOutputRepairScript = `const fs=require("node:fs"),C=fs.constants,ROOT="/outputs",MAX_ENTRIES=2048,MAX_DEPTH=64;let count=0;
function same(left,right){return left.dev===right.dev&&left.ino===right.ino&&left.mode===right.mode&&left.ctimeNs===right.ctimeNs&&left.mtimeNs===right.mtimeNs;}
function rooted(fd,name){return Buffer.concat([Buffer.from("/proc/self/fd/"+fd+"/"),name]);}
function repair(fd,depth){
  if(depth>MAX_DEPTH)throw new Error("depth");
  fs.fchmodSync(fd,0o777);
  const before=fs.fstatSync(fd,{bigint:true}),directory=fs.opendirSync("/proc/self/fd/"+fd,{encoding:"buffer"});
  try{
    for(let item=directory.readSync();item!==null;item=directory.readSync()){
      if(++count>MAX_ENTRIES)throw new Error("entries");
      const name=item.name,target=rooted(fd,name),initial=fs.lstatSync(target,{bigint:true});
      if(initial.isDirectory()&&!initial.isSymbolicLink()){
        const child=fs.openSync(target,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),opened=fs.fstatSync(child,{bigint:true});
        if(!same(initial,opened))throw new Error("changed");
        let final;
        try{final=repair(child,depth+1);}finally{fs.closeSync(child);}
        if(!same(final,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
      }else if(initial.isFile()&&!initial.isSymbolicLink()){
        const child=fs.openSync(target,C.O_RDONLY|C.O_NOFOLLOW),opened=fs.fstatSync(child,{bigint:true});
        try{if(!same(initial,opened))throw new Error("changed");}finally{fs.closeSync(child);}
        if(!same(initial,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
      }else{throw new Error("unsafe");}
    }
  }finally{directory.closeSync();}
  const after=fs.fstatSync(fd,{bigint:true});
  if(!same(before,after))throw new Error("changed");
  return after;
}
const root=fs.openSync(ROOT,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);try{repair(root,0);}finally{fs.closeSync(root);}`
	pythonOutputRepairScript = `import os,stat
ROOT=b"/outputs"
MAX_ENTRIES=2048
MAX_DEPTH=64
count=0
def same(left,right):
    return (left.st_dev,left.st_ino,left.st_mode,left.st_ctime_ns,left.st_mtime_ns)==(right.st_dev,right.st_ino,right.st_mode,right.st_ctime_ns,right.st_mtime_ns)
def repair(fd,depth):
    global count
    if depth>MAX_DEPTH:
        raise RuntimeError("depth")
    os.fchmod(fd,0o777)
    before=os.fstat(fd)
    with os.scandir(fd) as entries:
        for entry in entries:
            count+=1
            if count>MAX_ENTRIES:
                raise RuntimeError("entries")
            name=os.fsencode(entry.name)
            initial=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(initial.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                opened=os.fstat(child)
                if not same(initial,opened):
                    raise RuntimeError("changed")
                try:
                    final=repair(child,depth+1)
                finally:
                    os.close(child)
                if not same(final,os.stat(name,dir_fd=fd,follow_symlinks=False)):
                    raise RuntimeError("changed")
            elif stat.S_ISREG(initial.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
                opened=os.fstat(child)
                try:
                    if not same(initial,opened):
                        raise RuntimeError("changed")
                finally:
                    os.close(child)
                if not same(initial,os.stat(name,dir_fd=fd,follow_symlinks=False)):
                    raise RuntimeError("changed")
            else:
                raise RuntimeError("unsafe")
    after=os.fstat(fd)
    if not same(before,after):
        raise RuntimeError("changed")
    return after
root=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    repair(root,0)
finally:
    os.close(root)`
)

var (
	nodeWorkloadQuiesceScript   = `const fs=require("node:fs");const sleep=new Int32Array(new SharedArrayBuffer(4));function workloadPids(){const result=[];for(const name of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(name))continue;try{const status=fs.readFileSync("/proc/"+name+"/status","utf8"),uid=/^Uid:\s+(\d+)\s+(\d+)/m.exec(status),state=/^State:\s+([A-Z])/m.exec(status);if(uid&&(["65532","65533"].includes(uid[1])||["65532","65533"].includes(uid[2]))&&(!state||!/^[` + quiescentWorkloadProcessStates + `]$/.test(state[1])))result.push(Number(name));}catch(error){if(error.code!=="ENOENT")throw error;}}return result;}for(let pass=0;pass<50;pass++){const targets=workloadPids();if(!targets.length)process.exit(0);for(const pid of targets){try{process.kill(pid,"SIGKILL");}catch(error){if(error.code!=="ESRCH")throw error;}}Atomics.wait(sleep,0,0,10);}throw new Error("non-root workload or trusted driver processes remain");`
	pythonWorkloadQuiesceScript = `import os,re,signal,time
def workload_pids():
    result=[]
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/"+name+"/status",encoding="ascii") as source:
                status=source.read()
                uid=re.search(r"^Uid:\s+(\d+)\s+(\d+)",status,re.MULTILINE)
                state=re.search(r"^State:\s+([A-Z])",status,re.MULTILINE)
        except FileNotFoundError:
            continue
        if uid and any(value in (65532,65533) for value in (int(uid.group(1)),int(uid.group(2)))) and (not state or state.group(1) not in "` + quiescentWorkloadProcessStates + `"):
            result.append(int(name))
    return result
for _ in range(50):
    targets=workload_pids()
    if not targets:
        raise SystemExit(0)
    for pid in targets:
        try:
            os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
    time.sleep(0.01)
raise RuntimeError("non-root workload or trusted driver processes remain")`
	pythonWorkloadQuiescenceCheckScript = `import os,re,time
TARGET_UIDS={65532,65533}
PASSES=2
SEPARATION_SECONDS=0.02
def snapshot():
    try:
        names=tuple(sorted((name for name in os.listdir("/proc") if name.isdigit()),key=int))
    except Exception as error:
        raise RuntimeError("process snapshot unavailable") from error
    identities=[]
    active=[]
    for name in names:
        try:
            with open("/proc/"+name+"/status",encoding="ascii") as source:
                status=source.read()
        except Exception as error:
            raise RuntimeError("process snapshot changed while reading") from error
        uid=re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",status,re.MULTILINE)
        state=re.search(r"^State:\s+([A-Z])(?:\s|$)",status,re.MULTILINE)
        if uid is None or state is None:
            raise RuntimeError("process identity is malformed")
        real_uid=int(uid.group(1));effective_uid=int(uid.group(2))
        identities.append((int(name),real_uid,effective_uid))
        if (real_uid in TARGET_UIDS or effective_uid in TARGET_UIDS) and state.group(1) not in "` + quiescentWorkloadProcessStates + `":
            active.append(int(name))
    if active:
        raise RuntimeError("non-root workload or trusted driver processes are active")
    return tuple(identities)
previous=snapshot()
for _ in range(1,PASSES):
    time.sleep(SEPARATION_SECONDS)
    current=snapshot()
    if current!=previous:
        raise RuntimeError("process snapshot changed between quiescence checks")
    previous=current`
)

func workloadProcessStateIsQuiescent(state string) bool {
	state = strings.TrimSpace(state)
	return len(state) == 1 && strings.Contains(quiescentWorkloadProcessStates, state)
}

func runtimeExecutable(adapter string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return "node", true
	case "python":
		return "python", true
	default:
		return "", false
	}
}

func idleRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeIdleScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonIdleScript}
	default:
		return nil
	}
}

func outputInitRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeOutputInitScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonOutputInitScript}
	default:
		return nil
	}
}

func outputRepairRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeOutputRepairScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonOutputRepairScript}
	default:
		return nil
	}
}

func workloadQuiesceRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeWorkloadQuiesceScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonWorkloadQuiesceScript}
	default:
		return nil
	}
}

func workloadQuiescenceCheckRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "python":
		return []string{
			"-I", "-S", "-c", pythonWorkloadQuiescenceCheckScript,
		}
	default:
		return nil
	}
}

func workloadIdentityRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeWorkloadIdentityScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonWorkloadIdentityScript}
	default:
		return nil
	}
}

func (r *Runner) initializeOutputDirectories(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) error {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return fmt.Errorf(
			"runtime adapter %q has no trusted initialization command",
			prepared.executionPlan.RuntimeAdapter,
		)
	}
	args := []string{
		"exec",
		"--user", containerUser,
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(
		args,
		outputInitRuntimeArgs(prepared.executionPlan.RuntimeAdapter)...,
	)
	return r.runBackendOperation(
		ctx,
		prepared.Backend,
		args,
		"initialize bounded output controller directories",
	)
}

func (r *Runner) repairOutputPermissions(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) error {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return fmt.Errorf(
			"runtime adapter %q has no trusted output repair command",
			prepared.executionPlan.RuntimeAdapter,
		)
	}
	args := []string{
		"exec",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(
		args,
		outputRepairRuntimeArgs(prepared.executionPlan.RuntimeAdapter)...,
	)
	return r.runBackendOperation(
		ctx,
		prepared.Backend,
		args,
		"repair bounded output directory permissions",
	)
}

func (r *Runner) quiesceWorkloadProcesses(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) error {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return fmt.Errorf(
			"runtime adapter %q has no trusted process quiescence command",
			prepared.executionPlan.RuntimeAdapter,
		)
	}
	args := []string{
		"exec",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(
		args,
		workloadQuiesceRuntimeArgs(prepared.executionPlan.RuntimeAdapter)...,
	)
	return r.runBackendOperation(
		ctx,
		prepared.Backend,
		args,
		"quiesce non-root workload processes",
	)
}

// verifyWorkloadProcessesQuiescent is an observe-only guard for a bounded
// foreground-command notification window. Unlike quiesceWorkloadProcesses it
// never sends a signal or changes process state.
func (r *Runner) verifyWorkloadProcessesQuiescent(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) error {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	args := workloadQuiescenceCheckRuntimeArgs(
		prepared.executionPlan.RuntimeAdapter,
	)
	if !ok || len(args) == 0 {
		return fmt.Errorf(
			"runtime adapter %q has no observe-only process quiescence check",
			prepared.executionPlan.RuntimeAdapter,
		)
	}
	command := []string{
		"exec",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	command = append(command, args...)
	return r.runBackendOperation(
		ctx,
		prepared.Backend,
		command,
		"verify non-root workload process quiescence",
	)
}

func (r *Runner) verifyRuntimeVersion(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) (domain.ObservationEvent, *domain.Error) {
	observation := lifecycleObservation(
		r.now().UTC(),
		prepared,
		domain.PhasePrepare,
		"runtime.version.verify",
		prepared.executionPlan.RuntimeAdapter,
		"failed",
		map[string]any{"expected": prepared.executionPlan.RuntimeVersion},
	)
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Resolved runtime adapter has no trusted version probe.",
		)
		err.Phase = domain.PhasePrepare
		err.Details = map[string]any{
			"runtimeAdapter": prepared.executionPlan.RuntimeAdapter,
			"expected":       prepared.executionPlan.RuntimeVersion,
		}
		return observation, err
	}

	probeCtx, cancelProbe := context.WithTimeout(ctx, r.config.CreateTimeout)
	defer cancelProbe()
	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	exitCode, runErr := r.executor.Run(
		probeCtx,
		prepared.Backend,
		[]string{
			"exec",
			"--user", containerUser,
			"--workdir", trustedHelperWorkdir,
			containerName,
			executable,
			"--version",
		},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 {
		err := domain.WrapError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Pinned image runtime version probe did not execute successfully.",
			runErr,
		)
		err.Phase = domain.PhasePrepare
		err.Details = map[string]any{
			"runtimeAdapter": prepared.executionPlan.RuntimeAdapter,
			"expected":       prepared.executionPlan.RuntimeVersion,
			"exitCode":       exitCode,
		}
		observation.Details["exitCode"] = exitCode
		return observation, err
	}

	actual, parseErr := normalizeRuntimeVersion(
		prepared.executionPlan.RuntimeAdapter,
		stdout.Bytes(),
		stderr.Bytes(),
	)
	if parseErr != nil || actual != prepared.executionPlan.RuntimeVersion {
		err := domain.WrapError(
			domain.CodeRuntimeVersionUnresolved,
			domain.SeverityCritical,
			"Pinned image runtime version does not exactly match the resolved plan.",
			parseErr,
		)
		err.Phase = domain.PhasePrepare
		err.Details = map[string]any{
			"runtimeAdapter": prepared.executionPlan.RuntimeAdapter,
			"expected":       prepared.executionPlan.RuntimeVersion,
			"actual":         actual,
		}
		observation.Details["actual"] = actual
		return observation, err
	}

	observation.Result = "succeeded"
	observation.Details["actual"] = actual
	return observation, nil
}

func (r *Runner) verifyWorkloadIdentity(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) (domain.ObservationEvent, *domain.Error) {
	observation := lifecycleObservation(
		r.now().UTC(),
		prepared,
		domain.PhasePrepare,
		"sandbox.workload.identity.verify",
		containerName,
		"failed",
		map[string]any{
			"expectedIdentity":   "uid/euid/gid/egid=65532",
			"expectedCapability": "CapInh/CapPrm/CapEff/CapAmb=0",
			"expectedNoNewPrivs": 1,
		},
	)
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityCritical,
			"Resolved runtime adapter has no trusted workload identity probe.",
		)
		err.Phase = domain.PhasePrepare
		return observation, err
	}

	probeCtx, cancelProbe := context.WithTimeout(ctx, r.config.CreateTimeout)
	defer cancelProbe()
	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	args := []string{
		"exec",
		"--user", containerUser,
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(
		args,
		workloadIdentityRuntimeArgs(prepared.executionPlan.RuntimeAdapter)...,
	)
	exitCode, runErr := r.executor.Run(
		probeCtx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	type workloadIdentity struct {
		UID        int    `json:"uid"`
		EUID       int    `json:"euid"`
		GID        int    `json:"gid"`
		EGID       int    `json:"egid"`
		CapInh     string `json:"capInh"`
		CapPrm     string `json:"capPrm"`
		CapEff     string `json:"capEff"`
		CapAmb     string `json:"capAmb"`
		NoNewPrivs int    `json:"noNewPrivs"`
	}
	var identity workloadIdentity
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&identity)
	trailingErr := decoder.Decode(&struct{}{})
	allZero := func(value string) bool {
		return value != "" && strings.Trim(value, "0") == ""
	}
	identityValid := decodeErr == nil &&
		trailingErr == io.EOF &&
		identity.UID == 65532 &&
		identity.EUID == 65532 &&
		identity.GID == 65532 &&
		identity.EGID == 65532 &&
		allZero(identity.CapInh) &&
		allZero(identity.CapPrm) &&
		allZero(identity.CapEff) &&
		allZero(identity.CapAmb) &&
		identity.NoNewPrivs == 1
	if runErr != nil || exitCode != 0 || !identityValid {
		if runErr == nil && decodeErr != nil {
			runErr = decodeErr
		}
		err := domain.WrapError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityCritical,
			"Container engine did not provide an unprivileged capability-free workload exec identity.",
			runErr,
		)
		err.Phase = domain.PhasePrepare
		err.Details = map[string]any{
			"backend":       prepared.Backend,
			"containerName": containerName,
			"exitCode":      exitCode,
		}
		observation.Details["exitCode"] = exitCode
		return observation, err
	}
	observation.Result = "succeeded"
	observation.Details["actualIdentity"] = "uid/euid/gid/egid=65532"
	observation.Details["actualCapInh"] = identity.CapInh
	observation.Details["actualCapPrm"] = identity.CapPrm
	observation.Details["actualCapEff"] = identity.CapEff
	observation.Details["actualCapAmb"] = identity.CapAmb
	observation.Details["actualNoNewPrivs"] = identity.NoNewPrivs
	return observation, nil
}

func (r *Runner) verifyArchiveHelper(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) (domain.ObservationEvent, *domain.Error) {
	observation := lifecycleObservation(
		r.now().UTC(),
		prepared,
		domain.PhasePrepare,
		"sandbox.archive-helper.verify",
		"/bin/tar",
		"failed",
		map[string]any{"runtimePolicy": "baseline-v1"},
	)
	probeCtx, cancelProbe := context.WithTimeout(ctx, r.config.CreateTimeout)
	defer cancelProbe()
	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	exitCode, runErr := r.executor.Run(
		probeCtx,
		prepared.Backend,
		[]string{
			"exec",
			"--user", "0:0",
			"--workdir", containerOutputs,
			containerName,
			"/bin/tar",
			"--version",
		},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 ||
		!bytes.Contains(stdout.Bytes(), []byte("GNU tar")) {
		err := domain.WrapError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityCritical,
			"Approved runtime image does not provide the required trusted /bin/tar export helper.",
			runErr,
		)
		err.Phase = domain.PhasePrepare
		err.Details = map[string]any{
			"backend":       prepared.Backend,
			"containerName": containerName,
			"exitCode":      exitCode,
			"helper":        "/bin/tar",
		}
		observation.Details["exitCode"] = exitCode
		return observation, err
	}
	observation.Result = "succeeded"
	return observation, nil
}

func normalizeRuntimeVersion(
	adapter string,
	stdout []byte,
	stderr []byte,
) (string, error) {
	raw := bytes.TrimSpace(stdout)
	if len(raw) == 0 {
		raw = bytes.TrimSpace(stderr)
	}
	if len(raw) == 0 || len(raw) > 128 ||
		bytes.ContainsAny(raw, "\r\n") {
		return "", errors.New("runtime version probe output is absent or not a single bounded line")
	}
	value := string(raw)
	var prefix string
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		prefix = "v"
	case "python":
		prefix = "Python "
	default:
		return "", fmt.Errorf("unsupported runtime adapter %q", adapter)
	}
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("runtime version probe output has an unexpected prefix")
	}
	version := strings.TrimPrefix(value, prefix)
	if !exactRuntimeVersionPattern.MatchString(version) {
		return "", errors.New("runtime version probe output is not an exact semantic version")
	}
	return version, nil
}

func (r *Runner) containerRunning(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) (bool, error) {
	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		[]string{
			"inspect",
			"--format", "{{.State.Running}}",
			containerName,
		},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 {
		return false, backendOperationFailure(
			"inspect long-lived sandbox state",
			exitCode,
			runErr,
		)
	}
	switch strings.TrimSpace(string(stdout.Bytes())) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("container state inspection returned an unreadable running state")
	}
}

func (r *Runner) runBackendOperation(
	ctx context.Context,
	backend string,
	args []string,
	operation string,
) error {
	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	exitCode, runErr := r.executor.Run(
		ctx,
		backend,
		args,
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 {
		return backendOperationFailure(operation, exitCode, runErr)
	}
	return nil
}

func backendOperationFailure(operation string, exitCode int, err error) error {
	if err != nil {
		return fmt.Errorf(
			"%s failed with exit code %d: %w",
			operation,
			exitCode,
			err,
		)
	}
	return fmt.Errorf("%s failed with exit code %d", operation, exitCode)
}

func lifecycleObservation(
	timestamp time.Time,
	prepared *PreparedRun,
	phase domain.Phase,
	operation string,
	resource string,
	result string,
	details map[string]any,
) domain.ObservationEvent {
	return domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp,
		Phase:         phase,
		Actor:         "trusted-runner",
		Operation:     operation,
		Resource:      resource,
		Result:        result,
		Observer:      prepared.Backend + "-cli",
		Coverage:      coverageFull,
		Confidence:    "high",
		Details:       details,
	}
}
