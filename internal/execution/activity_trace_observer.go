package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const (
	activityTraceFrameLimit              = 8 << 10
	activityTraceTransportLimit          = 16 << 10
	activityTraceStderrLimit             = 8 << 10
	activityTraceNotificationLimit       = 4096
	activityTraceRawDigestLimit          = 1 << 20
	activityTraceWatchLimit              = 2048
	activityTraceOperationRuleLimit      = 256
	activityTraceOperationWindowLimit    = 128
	activityTraceOperationControlLimit   = 512 << 10
	activityTraceOperationTransportLimit = 64 << 10
	activityTraceControlTimeout          = 2 * time.Second
	activityTraceWriteJoinTimeout        = 100 * time.Millisecond
	activityTraceFailureOverflow         = "notification-overflow"
	activityTraceFailureNewDirectoryGap  = "new-directory-watch-gap"
	activityTraceFailureGap              = "notification-gap"
)

var activityTraceSessionDigestPattern = regexp.MustCompile(
	`^sha256:[a-f0-9]{64}$`,
)

const nodeActivityTraceScript = `const fs=require("node:fs"),crypto=require("node:crypto");
const ROOT=Buffer.from("/outputs"),MAX_INPUT=1024,MAX_EVENTS=4096,MAX_RAW=1048576,MAX_PATH=1024,MAX_WATCHES=2048,PHASES=new Set(["setup","build","run","exercise","cleanup"]);
let input=Buffer.alloc(0),started=false,finished=false,token="",sessionDigest="",adapter="node-fs-watch-linux",phase="unknown",count=0,renameCount=0,changeCount=0,overflow=false,gap=false,rawBytes=0,raw=crypto.createHash("sha256"),startNs=0n;
const watchers=new Map();
const phases={setup:0,build:0,run:0,exercise:0,cleanup:0,unknown:0};
function emit(value){process.stdout.write(JSON.stringify(value)+"\n");}
function exact(value,keys){return value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.prototype.hasOwnProperty.call(value,key));}
function digest(value){return "sha256:"+crypto.createHash("sha256").update(value).digest("hex");}
function watchKey(directory){return directory.toString("base64");}
function record(kind,name,directory){count++;phases[phase]=(phases[phase]||0)+1;if(kind==="rename")renameCount++;else if(kind==="change")changeCount++;else gap=true;if(count>MAX_EVENTS){overflow=true;final(false);return;}let bytes;if(name===null||name===undefined){gap=true;bytes=Buffer.alloc(0);}else bytes=Buffer.isBuffer(name)?name:Buffer.from(String(name));const pathBytes=directory.length+1+bytes.length;if(pathBytes>MAX_PATH)gap=true;if(gap){final(false);return;}const keyed=crypto.createHmac("sha256",token).update(directory).update(Buffer.from([0])).update(bytes).digest("hex"),elapsed=Number((process.hrtime.bigint()-startNs)/1000n),line=Buffer.from(JSON.stringify([count,kind,phase,elapsed,pathBytes,keyed])+"\n");if(rawBytes+line.length>MAX_RAW){overflow=true;final(false);return;}raw.update(line);rawBytes+=line.length;}
function addTree(root){const pending=[root];while(pending.length&&!finished){const directory=pending.pop(),key=watchKey(directory);if(watchers.has(key))continue;if(watchers.size>=MAX_WATCHES){overflow=true;final(false);return;}let entries;try{entries=fs.readdirSync(directory,{withFileTypes:true,encoding:"buffer"});}catch(error){if(error.code==="ENOENT")return;gap=true;final(false);return;}let watcher;try{watcher=fs.watch(directory,{encoding:"buffer"},(kind,name)=>{record(kind,name,directory);if(finished||kind!=="rename"||name===null||name===undefined)return;const bytes=Buffer.isBuffer(name)?name:Buffer.from(String(name)),child=Buffer.concat([directory,Buffer.from("/"),bytes]),childKey=watchKey(child);try{if(fs.lstatSync(child).isDirectory())addTree(child);}catch(error){if(error.code!=="ENOENT"){gap=true;final(false);}else if(watchers.has(childKey)){gap=true;final(false);}}});watcher.on("error",()=>{gap=true;final(false);});}catch(_){gap=true;final(false);return;}watchers.set(key,watcher);for(const entry of entries){if(entry.isDirectory()){const name=Buffer.isBuffer(entry.name)?entry.name:Buffer.from(String(entry.name)),child=Buffer.concat([directory,Buffer.from("/"),name]);if(child.length>MAX_PATH){gap=true;final(false);return;}pending.push(child);}}}}
function final(ok){if(finished)return;finished=true;for(const watcher of watchers.values()){try{watcher.close();}catch(_){gap=true;}}watchers.clear();emit({type:"final",schemaVersion:"1",sessionDigest,ok:Boolean(ok&&!overflow&&!gap),observerAdapter:adapter,notificationCount:Math.min(count,MAX_EVENTS),renameHintCount:renameCount,changeHintCount:changeCount,setupCount:phases.setup,buildCount:phases.build,runCount:phases.run,exerciseCount:phases.exercise,cleanupCount:phases.cleanup,unknownCount:phases.unknown,overflowDetected:overflow,gapDetected:gap,canonicalTranscriptDigest:"sha256:"+raw.digest("hex"),canonicalByteCount:rawBytes});process.exitCode=ok&&!overflow&&!gap?0:1;process.stdin.pause();}
function begin(command){if(started||!exact(command,["command","token"])||command.command!=="start"||typeof command.token!=="string"||!/^[a-f0-9]{64}$/.test(command.token)){gap=true;final(false);return;}started=true;token=command.token;sessionDigest=digest(Buffer.from(token,"ascii"));startNs=process.hrtime.bigint();addTree(ROOT);if(finished)return;emit({type:"ready",schemaVersion:"1",sessionDigest,observerAdapter:adapter});}
function command(value){if(!started){begin(value);return;}if(!value||typeof value!=="object"||Array.isArray(value)||value.token!==token){gap=true;final(false);return;}if(value.command==="phase"&&exact(value,["command","token","phase"])&&PHASES.has(value.phase)){phase=value.phase;return;}if(value.command==="stop"&&exact(value,["command","token"])){final(true);return;}gap=true;final(false);}
function consume(){for(;;){const newline=input.indexOf(10);if(newline<0)break;const line=input.subarray(0,newline);input=input.subarray(newline+1);if(!line.length||line.length>512){gap=true;final(false);return;}let value;try{value=JSON.parse(line.toString("utf8"));}catch(_){gap=true;final(false);return;}command(value);if(finished)return;}}
process.stdin.on("data",chunk=>{if(finished)return;if(input.length+chunk.length>MAX_INPUT){gap=true;final(false);return;}input=Buffer.concat([input,chunk]);consume();});
process.stdin.on("end",()=>{if(!finished){gap=true;final(false);}});
process.stdin.on("error",()=>{if(!finished){gap=true;final(false);}});`

const pythonActivityTraceScript = `import ctypes,hashlib,hmac,json,os,select,struct,sys,time
ROOT=b"/outputs";ROOT_TEXT="/outputs";MAX_INPUT=524288;MAX_EVENTS=4096;MAX_RAW=1048576;MAX_PATH=1024;MAX_WATCHES=2048;MAX_RULES=256;MAX_WINDOWS=128
PHASES={"setup","build","run","exercise","cleanup"};KINDS={"exact","child","tree"}
IN_MODIFY=0x2;IN_ATTRIB=0x4;IN_CLOSE_WRITE=0x8;IN_MOVED_FROM=0x40;IN_MOVED_TO=0x80;IN_CREATE=0x100;IN_DELETE=0x200;IN_DELETE_SELF=0x400;IN_MOVE_SELF=0x800;IN_Q_OVERFLOW=0x4000;IN_IGNORED=0x8000;IN_ISDIR=0x40000000
MUTATION=IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE;FAIL_MASK=IN_DELETE_SELF|IN_MOVE_SELF|IN_Q_OVERFLOW|IN_IGNORED;MASK=MUTATION|FAIL_MASK
adapter="python-inotify-linux";token="";session_digest="";phase="unknown";rules=[];counts={name:0 for name in (*PHASES,"unknown")};categories={name:0 for name in ("create","delete","write","rename","metadata")};count=rename_count=change_count=raw_bytes=windows=declared=allowed=undeclared=0;overflow=gap=finished=watching=False;failure="";raw=hashlib.sha256();start_ns=0;watches={}
def emit(value):
    sys.stdout.write(json.dumps(value,separators=(",",":"),sort_keys=True)+"\n");sys.stdout.flush()
def exact(value,keys):
    return isinstance(value,dict) and set(value)==set(keys)
def stop_watching():
    global watching
    if not watching:return True
    watching=False
    try:os.close(fd);clean=True
    except Exception:clean=False
    watches.clear();return clean
def latch(reason):
    global failure,overflow,gap
    if failure:return
    failure=reason;overflow=reason=="notification-overflow";gap=not overflow;stop_watching()
def failed():
    global finished
    if finished:return
    finished=True;stop_watching()
    emit({"type":"failed","schemaVersion":"1","sessionDigest":session_digest,"ok":False,"observerAdapter":adapter,"failure":failure})
def final(ok):
    global finished,gap
    if finished:return
    finished=True
    if not stop_watching():gap=True
    result="nonconforming-notifications" if undeclared else "no-undeclared-observed"
    emit({"type":"final","schemaVersion":"1","sessionDigest":session_digest,"ok":bool(ok and not overflow and not gap),"observerAdapter":adapter,"notificationCount":min(count,MAX_EVENTS),"renameHintCount":rename_count,"changeHintCount":change_count,"setupCount":counts["setup"],"buildCount":counts["build"],"runCount":counts["run"],"exerciseCount":counts["exercise"],"cleanupCount":counts["cleanup"],"unknownCount":counts["unknown"],"overflowDetected":overflow,"gapDetected":gap,"canonicalTranscriptDigest":"sha256:"+raw.hexdigest(),"canonicalByteCount":raw_bytes,"windowCount":windows,"declaredPatternCount":declared,"comparedNotificationCount":count,"allowedNotificationCount":allowed,"undeclaredNotificationCount":undeclared,"createNotificationCount":categories["create"],"deleteNotificationCount":categories["delete"],"writeNotificationCount":categories["write"],"renameNotificationCount":categories["rename"],"metadataNotificationCount":categories["metadata"],"comparisonResult":result})
def add_watch(directory):
    global gap,overflow
    if len(directory)>MAX_PATH:gap=True;return
    if len(watches)>=MAX_WATCHES:overflow=True;return
    wd=libc.inotify_add_watch(fd,ctypes.c_char_p(directory),ctypes.c_uint32(MASK))
    if wd<0 or wd in watches:gap=True;return
    watches[wd]=directory
def add_tree(root):
    global gap
    add_watch(root)
    if gap or overflow:return
    try:
        for current,dirs,_ in os.walk(root):
            if gap or overflow:break
            dirs[:]=sorted(dirs)
            for name in dirs:
                add_watch(current+b"/"+name)
                if gap or overflow:break
    except Exception:gap=True
def valid_text(value):
    return isinstance(value,str) and len(value.encode("utf-8"))<=MAX_PATH and all(ord(ch)>=32 and ord(ch)!=127 for ch in value)
def valid_base(value):
    if not valid_text(value) or "\\" in value or not (value==ROOT_TEXT or value.startswith(ROOT_TEXT+"/")):return False
    return os.path.normpath(value)==value
def decode_rules(value):
    if not isinstance(value,list) or len(value)>MAX_RULES:return None
    result=[]
    for rule in value:
        if not exact(rule,("kind","base")) or rule.get("kind") not in KINDS or not valid_base(rule.get("base")):return None
        result.append((rule["kind"],rule["base"]))
    return result
def matches(path_text):
    for kind,base in rules:
        if kind=="exact" and path_text==base:return True
        if kind=="tree" and (path_text==base or path_text.startswith(base+"/")):return True
        if kind=="child" and path_text.startswith(base+"/") and "/" not in path_text[len(base)+1:]:return True
    return False
def record(wd,mask,name):
    global count,rename_count,change_count,raw_bytes,allowed,undeclared
    known=MUTATION|FAIL_MASK|IN_ISDIR
    if mask&IN_Q_OVERFLOW:latch("notification-overflow");return
    if mask&~known:latch("notification-gap");return
    if wd not in watches:latch("notification-gap");return
    if mask&(IN_DELETE_SELF|IN_MOVE_SELF|IN_IGNORED):latch("notification-gap");return
    if phase=="unknown" or not name or b"/" in name or b"\0" in name:latch("notification-gap");return
    try:name_text=name.decode("utf-8","strict")
    except UnicodeDecodeError:latch("notification-gap");return
    if not valid_text(name_text):latch("notification-gap");return
    directory=watches[wd];path_bytes=len(directory)+1+len(name)
    if path_bytes>MAX_PATH:latch("notification-gap");return
    try:path_text=(directory+b"/"+name).decode("utf-8","strict")
    except UnicodeDecodeError:latch("notification-gap");return
    if not valid_base(path_text):latch("notification-gap");return
    if mask&IN_ISDIR and mask&(IN_CREATE|IN_MOVED_TO):latch("new-directory-watch-gap");return
    mutation=mask&MUTATION
    if mutation==0:latch("notification-gap");return
    if mutation&(IN_MOVED_FROM|IN_MOVED_TO):kind="rename"
    elif mutation&IN_CREATE:kind="create"
    elif mutation&IN_DELETE:kind="delete"
    elif mutation&IN_ATTRIB:kind="metadata"
    elif mutation&(IN_MODIFY|IN_CLOSE_WRITE):kind="write"
    else:latch("notification-gap");return
    count+=1;counts[phase]+=1;categories[kind]+=1
    if kind in ("rename","create","delete"):rename_count+=1
    else:change_count+=1
    if count>MAX_EVENTS:latch("notification-overflow");return
    matched=matches(path_text)
    if matched:allowed+=1
    else:undeclared+=1
    path_digest=hmac.new(token.encode("ascii"),directory+b"\0"+name,hashlib.sha256).hexdigest()
    elapsed=(time.monotonic_ns()-start_ns)//1000
    line=json.dumps([count,kind,phase,elapsed,path_bytes,path_digest,matched],separators=(",",":")).encode()+b"\n"
    if raw_bytes+len(line)>MAX_RAW:latch("notification-overflow");return
    raw.update(line);raw_bytes+=len(line)
def pending_notifications():
    if not watching:return False
    try:return bool(select.select([fd],[],[],0)[0])
    except Exception:return True
line=sys.stdin.buffer.readline(513)
try:start=json.loads(line)
except Exception:start=None
if len(line)>512 or not exact(start,("command","token")) or start.get("command")!="start" or not isinstance(start.get("token"),str) or len(start["token"])!=64 or any(ch not in "0123456789abcdef" for ch in start["token"]):sys.exit(1)
token=start["token"];session_digest="sha256:"+hashlib.sha256(token.encode("ascii")).hexdigest()
libc=ctypes.CDLL(None,use_errno=True);libc.inotify_init1.argtypes=[ctypes.c_int];libc.inotify_init1.restype=ctypes.c_int;libc.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32];libc.inotify_add_watch.restype=ctypes.c_int
fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
if fd<0:sys.exit(1)
watching=True;start_ns=time.monotonic_ns();add_tree(ROOT)
if gap or overflow:final(False);sys.exit(1)
emit({"type":"ready","schemaVersion":"1","sessionDigest":session_digest,"observerAdapter":adapter});control=b""
while not finished:
    sources=[sys.stdin.buffer]
    if watching:sources.insert(0,fd)
    readable,_,_=select.select(sources,[],[],0.1)
    if watching and fd in readable:
        try:data=os.read(fd,65536)
        except BlockingIOError:data=b""
        except Exception:latch("notification-gap");data=b""
        offset=0
        while not failure and offset+16<=len(data):
            wd,mask,cookie,length=struct.unpack_from("iIII",data,offset);offset+=16
            if length>MAX_PATH+1 or offset+length>len(data):latch("notification-gap");break
            name=data[offset:offset+length].split(b"\0",1)[0];offset+=length;record(wd,mask,name)
        if not failure and offset!=len(data):latch("notification-gap")
    if sys.stdin.buffer in readable:
        chunk=os.read(0,65536)
        if not chunk or len(control)+len(chunk)>MAX_INPUT:latch("notification-gap");failed();break
        control+=chunk
        while b"\n" in control and not finished:
            raw_line,control=control.split(b"\n",1)
            try:value=json.loads(raw_line)
            except Exception:value=None
            if not isinstance(value,dict) or value.get("token")!=token:latch("notification-gap");failed();break
            if exact(value,("command","token","phase","rules")) and value.get("command")=="phase" and value.get("phase") in PHASES:
                decoded=decode_rules(value.get("rules"))
                if decoded is None or windows>=MAX_WINDOWS:latch("notification-gap");failed();break
                if not failure and pending_notifications():latch("notification-gap")
                phase=value["phase"];rules=decoded;windows+=1;declared+=len(rules)
                emit({"type":"phase-ack","schemaVersion":"1","sessionDigest":session_digest,"observerAdapter":adapter,"phase":phase,"ruleCount":len(rules),"windowSequence":windows})
            elif exact(value,("command","token")) and value.get("command")=="stop":
                if not failure and pending_notifications():latch("notification-gap")
                if failure:failed()
                else:final(True)
            else:latch("notification-gap");failed()
sys.exit(0 if finished and not failure and not gap and not overflow else 1)`

type activityTraceReadyFrame struct {
	Type            string
	SchemaVersion   string
	SessionDigest   string
	ObserverAdapter string
}

type activityTraceResult struct {
	ObserverAdapter           string
	Failure                   string
	NotificationCount         int
	RenameHintCount           int
	ChangeHintCount           int
	SetupCount                int
	BuildCount                int
	RunCount                  int
	ExerciseCount             int
	CleanupCount              int
	UnknownCount              int
	CanonicalTranscriptDigest string
	CanonicalByteCount        int
	OverflowDetected          bool
	GapDetected               bool
	OperationNotification     *operationNotificationResult
}

type activityTraceObservationState struct {
	required                   bool
	backendEligible            bool
	containerID                string
	session                    *activityTraceSession
	startIdentityVerified      bool
	readyIdentityVerified      bool
	stopIdentityVerified       bool
	finalIdentityVerified      bool
	workloadQuiescenceVerified bool
	ready                      bool
	finalReady                 bool
	phaseSignalsComplete       bool
	result                     activityTraceResult
	failure                    string
	observedAt                 time.Time
}

type activityTraceSession struct {
	token                   string
	sessionDigest           string
	expectedAdapter         string
	process                 RunningCommand
	stdin                   io.WriteCloser
	stream                  *activityTraceFrameStream
	stderr                  *activityTraceLockedBuffer
	cancel                  context.CancelFunc
	wait                    <-chan activityTraceProcessResult
	controlMu               sync.Mutex
	operationWindowSequence int
	abortOnce               sync.Once
	abortDone               chan struct{}
}

type activityTraceProcessResult struct {
	exitCode int
	err      error
}

type activityTraceStreamEvent struct {
	frame []byte
	err   error
}

type activityTraceFrameStream struct {
	mu              sync.Mutex
	pending         []byte
	total           int
	frameCount      int
	frameLimit      int
	transportLimit  int
	frameCountLimit int
	consumed        int
	requireConsumed bool
	minimumFrames   int
	invalid         bool
	events          chan activityTraceStreamEvent
}

func newActivityTraceFrameStream() *activityTraceFrameStream {
	return newBoundedActivityTraceFrameStream(
		activityTraceFrameLimit,
		activityTraceTransportLimit,
		2,
	)
}

func newOperationNotificationFrameStream() *activityTraceFrameStream {
	stream := newBoundedActivityTraceFrameStream(
		activityTraceFrameLimit,
		activityTraceOperationTransportLimit,
		activityTraceOperationWindowLimit+2,
	)
	stream.requireConsumed = true
	stream.minimumFrames = 2
	return stream
}

func newBoundedActivityTraceFrameStream(
	frameLimit int,
	transportLimit int,
	frameCountLimit int,
) *activityTraceFrameStream {
	return &activityTraceFrameStream{
		frameLimit:      frameLimit,
		transportLimit:  transportLimit,
		frameCountLimit: frameCountLimit,
		events:          make(chan activityTraceStreamEvent, 4),
	}
}

func (s *activityTraceFrameStream) Write(value []byte) (int, error) {
	originalLength := len(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalid {
		return originalLength, nil
	}
	s.total += originalLength
	if s.total > s.transportLimit {
		s.invalidateLocked()
		return originalLength, nil
	}
	s.pending = append(s.pending, value...)
	for {
		newline := bytes.IndexByte(s.pending, '\n')
		if newline < 0 {
			if len(s.pending) > s.frameLimit {
				s.invalidateLocked()
			}
			return originalLength, nil
		}
		if newline == 0 || newline > s.frameLimit {
			s.invalidateLocked()
			return originalLength, nil
		}
		frame := bytes.Clone(s.pending[:newline])
		s.pending = append([]byte(nil), s.pending[newline+1:]...)
		s.frameCount++
		if s.frameCount > s.frameCountLimit {
			s.invalidateLocked()
			return originalLength, nil
		}
		s.events <- activityTraceStreamEvent{frame: frame}
	}
}

func (s *activityTraceFrameStream) invalidateLocked() {
	if s.invalid {
		return
	}
	s.invalid = true
	select {
	case s.events <- activityTraceStreamEvent{
		err: errors.New("activity trace transport is invalid"),
	}:
	default:
	}
}

func (s *activityTraceFrameStream) next(
	ctx context.Context,
) ([]byte, error) {
	select {
	case event := <-s.events:
		if event.err != nil {
			return nil, event.err
		}
		s.mu.Lock()
		s.consumed++
		s.mu.Unlock()
		return event.frame, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *activityTraceFrameStream) complete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requireConsumed {
		return !s.invalid && s.frameCount >= s.minimumFrames &&
			s.frameCount == s.consumed && len(s.pending) == 0
	}
	return !s.invalid &&
		s.frameCount == s.frameCountLimit &&
		len(s.pending) == 0
}

type activityTraceLockedBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *activityTraceLockedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		if originalLength > 0 {
			b.truncated = true
		}
		return originalLength, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(value)
	return originalLength, nil
}

func (b *activityTraceLockedBuffer) clean() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.truncated && b.buffer.Len() == 0
}

func secureActivityTraceToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func activityTraceSessionDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("sha256:%x", digest)
}

func (r *Runner) startOutputsActivityTrace(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) (*activityTraceSession, error) {
	if prepared == nil || prepared.Backend != "docker" {
		return nil, errors.New("activity trace backend is unavailable")
	}
	if !fullContainerIDPattern.MatchString(containerID) {
		return nil, errors.New("activity trace identity is unavailable")
	}
	asyncExecutor, ok := r.executor.(AsyncCommandExecutor)
	if !ok {
		return nil, errors.New("activity trace transport is unavailable")
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return nil, errors.New("activity trace runtime helper is unavailable")
	}
	token, err := secureActivityTraceToken()
	if err != nil {
		return nil, errors.New("activity trace session could not be created")
	}
	script := nodeActivityTraceScript
	scriptArgs := []string{"-e", script}
	expectedAdapter := "node-fs-watch-linux"
	if prepared.executionPlan.RuntimeAdapter == "python" {
		script = pythonActivityTraceScript
		scriptArgs = []string{"-I", "-S", "-c", script}
		expectedAdapter = "python-inotify-linux"
	}
	args := []string{
		"exec", "--interactive",
		"--user", "0:0",
		"--workdir", trustedHelperWorkdir,
		containerID,
		executable,
	}
	args = append(args, scriptArgs...)
	stream := newActivityTraceFrameStream()
	if expectedAdapter == "python-inotify-linux" {
		stream = newOperationNotificationFrameStream()
	}
	stderr := &activityTraceLockedBuffer{limit: activityTraceStderrLimit}
	lifetimeCtx, cancel := context.WithCancel(context.Background())
	process, err := asyncExecutor.Start(
		lifetimeCtx,
		"docker",
		args,
		stream,
		stderr,
	)
	if err != nil || process == nil {
		cancel()
		return nil, errors.New("activity trace process did not start")
	}
	stdin := process.Stdin()
	if stdin == nil {
		cancel()
		reapUnusableActivityTraceProcess(process)
		return nil, errors.New("activity trace stdin is unavailable")
	}
	wait := make(chan activityTraceProcessResult, 1)
	go func() {
		exitCode, waitErr := process.Wait()
		wait <- activityTraceProcessResult{
			exitCode: exitCode,
			err:      waitErr,
		}
	}()
	session := &activityTraceSession{
		token:           token,
		sessionDigest:   activityTraceSessionDigest(token),
		expectedAdapter: expectedAdapter,
		process:         process,
		stdin:           stdin,
		stream:          stream,
		stderr:          stderr,
		cancel:          cancel,
		wait:            wait,
		abortDone:       make(chan struct{}),
	}
	if err := session.writeControl(ctx, map[string]string{
		"command": "start",
		"token":   token,
	}); err != nil {
		session.abort()
		return nil, errors.New("activity trace start frame failed")
	}
	frame, err := stream.next(ctx)
	if err != nil {
		session.abort()
		return nil, errors.New("activity trace ready frame is unavailable")
	}
	ready, err := decodeActivityTraceReadyFrame(frame)
	if err != nil ||
		ready.SessionDigest != session.sessionDigest ||
		ready.ObserverAdapter != session.expectedAdapter {
		session.abort()
		return nil, errors.New("activity trace ready frame is invalid")
	}
	return session, nil
}

func reapUnusableActivityTraceProcess(process RunningCommand) {
	if process == nil {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = process.Wait()
		close(done)
	}()
	timer := time.NewTimer(activityTraceWriteJoinTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

func (s *activityTraceSession) writeControl(
	ctx context.Context,
	value any,
) error {
	return s.writeBoundedControl(ctx, value, 512)
}

func (s *activityTraceSession) writeBoundedControl(
	ctx context.Context,
	value any,
	limit int,
) error {
	if s == nil || s.stdin == nil {
		return errors.New("activity trace control is unavailable")
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > limit {
		return errors.New("activity trace control is invalid")
	}
	raw = append(raw, '\n')
	written := make(chan error, 1)
	go func() {
		count, writeErr := s.stdin.Write(raw)
		if writeErr == nil && count != len(raw) {
			writeErr = io.ErrShortWrite
		}
		written <- writeErr
	}()
	select {
	case writeErr := <-written:
		if writeErr != nil {
			return errors.New("activity trace control write failed")
		}
		return nil
	case <-ctx.Done():
		_ = s.stdin.Close()
		if s.cancel != nil {
			s.cancel()
		}
		timer := time.NewTimer(activityTraceWriteJoinTimeout)
		select {
		case <-written:
			timer.Stop()
		case <-timer.C:
		}
		return errors.New("activity trace control write failed")
	}
}

func (s *activityTraceSession) setPhase(
	ctx context.Context,
	phase domain.Phase,
) error {
	switch phase {
	case domain.PhaseSetup, domain.PhaseBuild, domain.PhaseRun,
		domain.PhaseExercise, domain.PhaseCleanup:
	default:
		return errors.New("activity trace phase is invalid")
	}
	return s.writeControl(ctx, map[string]string{
		"command": "phase",
		"token":   s.token,
		"phase":   string(phase),
	})
}

func markActivityTracePhase(
	state *activityTraceObservationState,
	phase domain.Phase,
) {
	if state == nil || state.session == nil ||
		!state.ready || !state.readyIdentityVerified {
		return
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		activityTraceControlTimeout,
	)
	err := state.session.setPhase(ctx, phase)
	cancel()
	if err != nil {
		state.phaseSignalsComplete = false
		if state.failure == "" {
			state.failure = "phase-control-failed"
		}
		state.session.abort()
		state.session = nil
	}
}

func (s *activityTraceSession) finish(
	ctx context.Context,
) (activityTraceResult, error) {
	if s == nil {
		return activityTraceResult{}, errors.New(
			"activity trace session is unavailable",
		)
	}
	if err := s.writeControl(ctx, map[string]string{
		"command": "stop",
		"token":   s.token,
	}); err != nil {
		s.abort()
		return activityTraceResult{}, err
	}
	if err := s.stdin.Close(); err != nil {
		s.abort()
		return activityTraceResult{}, errors.New(
			"activity trace input did not close",
		)
	}
	frame, err := s.stream.next(ctx)
	if err != nil {
		s.abort()
		return activityTraceResult{}, errors.New(
			"activity trace final frame is unavailable",
		)
	}
	result, err := decodeActivityTraceFinalFrame(
		frame,
		s.sessionDigest,
		s.expectedAdapter,
	)
	if err != nil {
		s.abort()
		return activityTraceResult{}, err
	}
	select {
	case waited := <-s.wait:
		s.cancel()
		cleanExit := result.Failure == "" &&
			waited.err == nil && waited.exitCode == 0
		failedExit := result.Failure != "" && waited.exitCode == 1
		if (!cleanExit && !failedExit) || !s.stderr.clean() ||
			!s.stream.complete() {
			return activityTraceResult{}, errors.New(
				"activity trace process did not complete cleanly",
			)
		}
	case <-ctx.Done():
		s.abort()
		return activityTraceResult{}, errors.New(
			"activity trace process completion timed out",
		)
	}
	return result, nil
}

func (s *activityTraceSession) abort() {
	if s == nil {
		return
	}
	done := s.abortDone
	s.abortOnce.Do(func() {
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
		timer := time.NewTimer(activityTraceControlTimeout)
		defer timer.Stop()
		select {
		case <-s.wait:
		case <-timer.C:
		}
		if done != nil {
			close(done)
		}
	})
	if done != nil {
		<-done
	}
}

func decodeActivityTraceReadyFrame(
	raw []byte,
) (activityTraceReadyFrame, error) {
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"type", "schemaVersion", "sessionDigest", "observerAdapter",
	}) {
		return activityTraceReadyFrame{}, errors.New(
			"activity trace ready frame is invalid",
		)
	}
	var frame activityTraceReadyFrame
	if decodeActivityTraceValue(fields["type"], &frame.Type) != nil ||
		decodeActivityTraceValue(
			fields["schemaVersion"],
			&frame.SchemaVersion,
		) != nil ||
		decodeActivityTraceValue(
			fields["sessionDigest"],
			&frame.SessionDigest,
		) != nil ||
		decodeActivityTraceValue(
			fields["observerAdapter"],
			&frame.ObserverAdapter,
		) != nil ||
		frame.Type != "ready" || frame.SchemaVersion != "1" ||
		!activityTraceSessionDigestPattern.MatchString(frame.SessionDigest) ||
		!validActivityTraceAdapter(frame.ObserverAdapter) {
		return activityTraceReadyFrame{}, errors.New(
			"activity trace ready frame is invalid",
		)
	}
	return frame, nil
}

func decodeActivityTraceFinalFrame(
	raw []byte,
	expectedSessionDigest string,
	expectedAdapter string,
) (activityTraceResult, error) {
	fields, err := decodeActivityTraceObject(raw)
	if err == nil && expectedAdapter == "python-inotify-linux" &&
		exactActivityTraceKeys(fields, []string{
			"type", "schemaVersion", "sessionDigest", "ok",
			"observerAdapter", "failure",
		}) {
		return decodeActivityTraceFailedFrame(
			fields,
			expectedSessionDigest,
			expectedAdapter,
		)
	}
	keys := []string{
		"type", "schemaVersion", "sessionDigest", "ok",
		"observerAdapter", "notificationCount", "renameHintCount",
		"changeHintCount", "setupCount", "buildCount", "runCount",
		"exerciseCount", "cleanupCount", "unknownCount",
		"overflowDetected", "gapDetected",
		"canonicalTranscriptDigest", "canonicalByteCount",
	}
	if expectedAdapter == "python-inotify-linux" {
		keys = append(keys,
			"windowCount", "declaredPatternCount",
			"comparedNotificationCount", "allowedNotificationCount",
			"undeclaredNotificationCount", "createNotificationCount",
			"deleteNotificationCount", "writeNotificationCount",
			"renameNotificationCount", "metadataNotificationCount",
			"comparisonResult",
		)
	}
	if err != nil || !exactActivityTraceKeys(fields, keys) {
		return activityTraceResult{}, errors.New(
			"activity trace final frame is invalid",
		)
	}
	var frameType, schemaVersion, sessionDigest string
	var ok bool
	result := activityTraceResult{}
	values := []struct {
		key    string
		target any
	}{
		{"type", &frameType},
		{"schemaVersion", &schemaVersion},
		{"sessionDigest", &sessionDigest},
		{"ok", &ok},
		{"observerAdapter", &result.ObserverAdapter},
		{"notificationCount", &result.NotificationCount},
		{"renameHintCount", &result.RenameHintCount},
		{"changeHintCount", &result.ChangeHintCount},
		{"setupCount", &result.SetupCount},
		{"buildCount", &result.BuildCount},
		{"runCount", &result.RunCount},
		{"exerciseCount", &result.ExerciseCount},
		{"cleanupCount", &result.CleanupCount},
		{"unknownCount", &result.UnknownCount},
		{"overflowDetected", &result.OverflowDetected},
		{"gapDetected", &result.GapDetected},
		{"canonicalTranscriptDigest", &result.CanonicalTranscriptDigest},
		{"canonicalByteCount", &result.CanonicalByteCount},
	}
	if expectedAdapter == "python-inotify-linux" {
		result.OperationNotification = &operationNotificationResult{}
		aggregate := result.OperationNotification
		values = append(values,
			struct {
				key    string
				target any
			}{"windowCount", &aggregate.WindowCount},
			struct {
				key    string
				target any
			}{"declaredPatternCount", &aggregate.DeclaredPatternCount},
			struct {
				key    string
				target any
			}{"comparedNotificationCount", &aggregate.ComparedNotificationCount},
			struct {
				key    string
				target any
			}{"allowedNotificationCount", &aggregate.AllowedNotificationCount},
			struct {
				key    string
				target any
			}{"undeclaredNotificationCount", &aggregate.UndeclaredNotificationCount},
			struct {
				key    string
				target any
			}{"createNotificationCount", &aggregate.CreateNotificationCount},
			struct {
				key    string
				target any
			}{"deleteNotificationCount", &aggregate.DeleteNotificationCount},
			struct {
				key    string
				target any
			}{"writeNotificationCount", &aggregate.WriteNotificationCount},
			struct {
				key    string
				target any
			}{"renameNotificationCount", &aggregate.RenameNotificationCount},
			struct {
				key    string
				target any
			}{"metadataNotificationCount", &aggregate.MetadataNotificationCount},
			struct {
				key    string
				target any
			}{"comparisonResult", &aggregate.ComparisonResult},
		)
	}
	for _, value := range values {
		if err := decodeActivityTraceValue(
			fields[value.key],
			value.target,
		); err != nil {
			return activityTraceResult{}, errors.New(
				"activity trace final frame is invalid",
			)
		}
	}
	phaseCounts := []int{
		result.SetupCount,
		result.BuildCount,
		result.RunCount,
		result.ExerciseCount,
		result.CleanupCount,
		result.UnknownCount,
	}
	var totalPhases int64
	for _, count := range phaseCounts {
		if count < 0 || count > activityTraceNotificationLimit {
			return activityTraceResult{}, errors.New(
				"activity trace final frame is incomplete",
			)
		}
		totalPhases += int64(count)
	}
	if frameType != "final" || schemaVersion != "1" ||
		sessionDigest != expectedSessionDigest ||
		result.ObserverAdapter != expectedAdapter ||
		!validActivityTraceAdapter(result.ObserverAdapter) ||
		!filesystemDigestPattern.MatchString(
			result.CanonicalTranscriptDigest,
		) ||
		result.NotificationCount < 0 ||
		result.NotificationCount > activityTraceNotificationLimit ||
		result.RenameHintCount < 0 ||
		result.RenameHintCount > activityTraceNotificationLimit ||
		result.ChangeHintCount < 0 ||
		result.ChangeHintCount > activityTraceNotificationLimit ||
		int64(result.RenameHintCount)+int64(result.ChangeHintCount) !=
			int64(result.NotificationCount) ||
		totalPhases != int64(result.NotificationCount) ||
		result.CanonicalByteCount < 0 ||
		result.CanonicalByteCount > activityTraceRawDigestLimit ||
		!ok || result.OverflowDetected || result.GapDetected {
		return activityTraceResult{}, errors.New(
			"activity trace final frame is incomplete",
		)
	}
	if result.OperationNotification != nil &&
		!validOperationNotificationResult(
			*result.OperationNotification,
			result.NotificationCount,
			result.RenameHintCount,
			result.ChangeHintCount,
		) {
		return activityTraceResult{}, errors.New(
			"activity trace final frame is incomplete",
		)
	}
	return result, nil
}

func decodeActivityTraceFailedFrame(
	fields map[string]json.RawMessage,
	expectedSessionDigest string,
	expectedAdapter string,
) (activityTraceResult, error) {
	var frameType, schemaVersion, sessionDigest string
	var ok bool
	result := activityTraceResult{}
	values := []struct {
		key    string
		target any
	}{
		{"type", &frameType},
		{"schemaVersion", &schemaVersion},
		{"sessionDigest", &sessionDigest},
		{"ok", &ok},
		{"observerAdapter", &result.ObserverAdapter},
		{"failure", &result.Failure},
	}
	for _, value := range values {
		if err := decodeActivityTraceValue(
			fields[value.key],
			value.target,
		); err != nil {
			return activityTraceResult{}, errors.New(
				"activity trace failed frame is invalid",
			)
		}
	}
	if frameType != "failed" || schemaVersion != "1" || ok ||
		sessionDigest != expectedSessionDigest ||
		expectedAdapter != "python-inotify-linux" ||
		result.ObserverAdapter != expectedAdapter ||
		!validActivityTraceFailure(result.Failure) {
		return activityTraceResult{}, errors.New(
			"activity trace failed frame is invalid",
		)
	}
	return result, nil
}

func validActivityTraceFailure(value string) bool {
	switch value {
	case activityTraceFailureOverflow,
		activityTraceFailureNewDirectoryGap,
		activityTraceFailureGap:
		return true
	default:
		return false
	}
}

func decodeActivityTraceObject(
	raw []byte,
) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > activityTraceFrameLimit ||
		!utf8.Valid(raw) {
		return nil, errors.New("activity trace frame is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("activity trace frame is not an object")
	}
	result := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		key, valid := token.(string)
		if err != nil || !valid {
			return nil, errors.New("activity trace frame key is invalid")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("activity trace frame key is duplicated")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("activity trace frame value is invalid")
		}
		result[key] = bytes.Clone(value)
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, errors.New("activity trace frame is not closed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("activity trace frame has trailing data")
	}
	return result, nil
}

func decodeActivityTraceValue(raw json.RawMessage, target any) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("activity trace frame value is absent")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return errors.New("activity trace frame value has the wrong type")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("activity trace frame value has trailing data")
	}
	return nil
}

func exactActivityTraceKeys(
	fields map[string]json.RawMessage,
	keys []string,
) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := fields[key]; !present {
			return false
		}
	}
	return true
}

func validActivityTraceAdapter(value string) bool {
	return value == "node-fs-watch-linux" ||
		value == "python-inotify-linux"
}

func summarizeOutputsActivityTrace(
	state activityTraceObservationState,
	completedAt time.Time,
) (domain.ObservationEvent, string) {
	coverage := coverageUnavailable
	result := "unavailable"
	confidence := "unknown"
	if state.required && state.backendEligible &&
		state.failure == "" &&
		state.result.Failure == "" &&
		state.startIdentityVerified && state.readyIdentityVerified &&
		state.stopIdentityVerified && state.finalIdentityVerified &&
		state.workloadQuiescenceVerified &&
		state.ready && state.finalReady &&
		state.phaseSignalsComplete &&
		!state.result.OverflowDetected && !state.result.GapDetected {
		coverage = coverageBestEffort
		result = "observed"
		confidence = "high"
	}
	timestamp := state.observedAt
	if timestamp.IsZero() {
		timestamp = completedAt
	}
	details := map[string]any{
		"scope":                       "outputs-activity-notification-trace",
		"traceBoundary":               "post-preflight-pre-workload-to-post-quiesce-pre-retained-final",
		"notificationSemantics":       "runtime-filesystem-notification-hints",
		"rawPathIncluded":             false,
		"contentIncluded":             false,
		"publicEvidence":              "aggregate-only",
		"actorAttribution":            "unavailable",
		"phaseAttribution":            "controller-window-hint",
		"operationClassification":     "hint-only",
		"operationHistoryCoverage":    coverageUnavailable,
		"observerPlacement":           "in-sandbox-trusted-helper",
		"sharesSandboxResourceBudget": true,
		"startIdentityVerified":       state.startIdentityVerified,
		"readyIdentityVerified":       state.readyIdentityVerified,
		"stopIdentityVerified":        state.stopIdentityVerified,
		"finalIdentityVerified":       state.finalIdentityVerified,
		"workloadQuiescenceVerified":  state.workloadQuiescenceVerified,
		"transport":                   "controller-stdin-stdout-jsonl",
		"transportBoundBytes":         activityTraceTransportLimit,
		"notificationLimit":           activityTraceNotificationLimit,
		"watchLimit":                  activityTraceWatchLimit,
		"activityTraceCoverage":       coverage,
		"blindSpots": []string{
			"outside-outputs",
			"exact-process-and-actor",
			"syscall-and-operation-history",
			"kernel-or-runtime-notification-coalescing",
			"node-kernel-queue-overflow-unobservable",
			"new-directory-watch-install-race",
			"watched-directory-delete-recreate",
			"phase-boundary-race",
			"rename-pairing",
			"read-activity",
		},
	}
	if coverage == coverageBestEffort {
		details["observerAdapter"] = state.result.ObserverAdapter
		details["notificationCount"] = state.result.NotificationCount
		details["renameHintCount"] = state.result.RenameHintCount
		details["changeHintCount"] = state.result.ChangeHintCount
		details["phaseCounts"] = []string{
			fmt.Sprintf("setup=%d", state.result.SetupCount),
			fmt.Sprintf("build=%d", state.result.BuildCount),
			fmt.Sprintf("run=%d", state.result.RunCount),
			fmt.Sprintf("exercise=%d", state.result.ExerciseCount),
			fmt.Sprintf("cleanup=%d", state.result.CleanupCount),
			fmt.Sprintf("unknown=%d", state.result.UnknownCount),
		}
		details["canonicalTranscriptDigest"] =
			state.result.CanonicalTranscriptDigest
		details["canonicalByteCount"] =
			state.result.CanonicalByteCount
		if state.result.ObserverAdapter == "python-inotify-linux" {
			details["kernelOverflowDetection"] =
				"inotify-queue-overflow-fail-closed"
		} else {
			details["kernelOverflowDetection"] = coverageUnavailable
		}
	}
	failure := state.failure
	if failure == "" {
		failure = state.result.Failure
	}
	if failure != "" {
		details["failure"] = failure
	}
	return domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "filesystem.activity-trace.summary",
		Resource:      containerOutputs,
		Result:        result,
		Observer:      "docker-outputs-activity-trace",
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       details,
	}, coverage
}
