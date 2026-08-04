package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

const (
	httpJSONFileMaxBytes        int64 = 1 << 20
	httpJSONFileMaxBase64Bytes        = ((httpJSONFileMaxBytes + 2) / 3) * 4
	httpJSONFileMaxControlBytes       = httpJSONFileMaxBase64Bytes + 4096

	nodeHTTPFileLstatScript   = `const fs=require("node:fs"),path=require("node:path"),c=fs.constants;(()=>{const target=process.argv[1],emit=status=>process.stdout.write(JSON.stringify({status})+"\n");if(typeof target!=="string"||target.includes("\0")||path.posix.normalize(target)!==target||(target!=="/outputs"&&!target.startsWith("/outputs/"))){emit("error");return;}const parts=target==="/outputs"?[]:target.slice(9).split("/"),fds=[];let status="error";try{let parent=fs.openSync("/outputs",c.O_RDONLY|c.O_DIRECTORY|c.O_NOFOLLOW);fds.push(parent);if(!parts.length){status="exists";}else{for(const part of parts.slice(0,-1)){parent=fs.openSync("/proc/self/fd/"+parent+"/"+part,c.O_RDONLY|c.O_DIRECTORY|c.O_NOFOLLOW);fds.push(parent);}const info=fs.lstatSync("/proc/self/fd/"+parent+"/"+parts[parts.length-1]);status=info.isSymbolicLink()?"symlink":"exists";}}catch(error){status=error&&error.code==="ELOOP"?"symlink":error&&(["ENOENT","ENOTDIR"].includes(error.code))?"missing":"error";}finally{for(const fd of fds.reverse()){try{fs.closeSync(fd);}catch(_){}}}emit(status);})();`
	pythonHTTPFileLstatScript = `import errno,json,os,stat,sys
target=sys.argv[1]
def emit(value):
    print(json.dumps({"status":value},separators=(",",":")))
if "\0" in target or os.path.normpath(target)!=target or (target!="/outputs" and not target.startswith("/outputs/")):
    emit("error")
    raise SystemExit(0)
parts=[] if target=="/outputs" else target[9:].split("/")
fds=[]
status_value="error"
try:
    parent=os.open("/outputs",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fds.append(parent)
    if not parts:
        status_value="exists"
    else:
        for part in parts[:-1]:
            parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            fds.append(parent)
        info=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        status_value="symlink" if stat.S_ISLNK(info.st_mode) else "exists"
except OSError as error:
    if error.errno==errno.ELOOP:
        status_value="symlink"
    elif error.errno in (errno.ENOENT,errno.ENOTDIR):
        status_value="missing"
    else:
        status_value="error"
finally:
    for fd in reversed(fds):
        try:
            os.close(fd)
        except OSError:
            pass
emit(status_value)`
	nodeHTTPJSONFileReadScript   = `const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),c=fs.constants;(()=>{const target=process.argv[1],limit=1048576,emit=value=>process.stdout.write(JSON.stringify(value)+"\n"),fds=[];let response={status:"error"};const stop=status=>{const error=new Error("controlled");error.controlled=true;error.status=status;throw error;},sameNode=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode,sameSnapshot=(a,b)=>sameNode(a,b)&&a.size===b.size&&a.mtimeNs===b.mtimeNs&&a.ctimeNs===b.ctimeNs;try{if(typeof target!=="string"||target.includes("\0")||path.posix.normalize(target)!==target||(target!=="/outputs"&&!target.startsWith("/outputs/")))stop("error");const parts=target==="/outputs"?[]:target.slice(9).split("/");if(!parts.length)stop("directory");let parent=fs.openSync("/outputs",c.O_RDONLY|c.O_DIRECTORY|c.O_NOFOLLOW);fds.push(parent);if(!fs.fstatSync(parent,{bigint:true}).isDirectory())stop("special");for(const part of parts.slice(0,-1)){const candidate="/proc/self/fd/"+parent+"/"+part,before=fs.lstatSync(candidate,{bigint:true});if(before.isSymbolicLink())stop("symlink");if(!before.isDirectory())stop("special");const next=fs.openSync(candidate,c.O_RDONLY|c.O_DIRECTORY|c.O_NOFOLLOW);fds.push(next);const opened=fs.fstatSync(next,{bigint:true});if(!opened.isDirectory()||!sameNode(before,opened))stop("changed");parent=next;}const candidate="/proc/self/fd/"+parent+"/"+parts[parts.length-1],before=fs.lstatSync(candidate,{bigint:true});if(before.isSymbolicLink())stop("symlink");if(before.isDirectory())stop("directory");if(!before.isFile())stop("special");const file=fs.openSync(candidate,c.O_RDONLY|c.O_NOFOLLOW|c.O_NONBLOCK);fds.push(file);const opened=fs.fstatSync(file,{bigint:true});if(!opened.isFile()||!sameNode(before,opened))stop("changed");const buffer=Buffer.allocUnsafe(limit+1);let size=0;while(size<buffer.length){const count=fs.readSync(file,buffer,size,buffer.length-size,null);if(count===0)break;size+=count;}if(size>limit)stop("too-large");const after=fs.fstatSync(file,{bigint:true});if(!sameSnapshot(opened,after))stop("changed");const content=buffer.subarray(0,size);response={status:"ok",size,contentBase64:content.toString("base64"),sha256:"sha256:"+crypto.createHash("sha256").update(content).digest("hex")};}catch(error){if(error&&error.controlled){response={status:error.status};}else if(error&&error.code==="ENOENT"){response={status:"missing"};}else if(error&&error.code==="ELOOP"){response={status:"symlink"};}else if(error&&error.code==="EISDIR"){response={status:"directory"};}else if(error&&error.code==="ENOTDIR"){response={status:"changed"};}else{response={status:"error"};}}finally{for(const fd of fds.reverse()){try{fs.closeSync(fd);}catch(_){}}}emit(response);})();`
	pythonHTTPJSONFileReadScript = `import base64,errno,hashlib,json,os,stat,sys
LIMIT=1048576
target=sys.argv[1]
fds=[]
class Controlled(Exception):
    def __init__(self,status_value):
        self.status_value=status_value
def stop(status_value):
    raise Controlled(status_value)
def same_node(left,right):
    return left.st_dev==right.st_dev and left.st_ino==right.st_ino and left.st_mode==right.st_mode
def same_snapshot(left,right):
    return same_node(left,right) and left.st_size==right.st_size and left.st_mtime_ns==right.st_mtime_ns and left.st_ctime_ns==right.st_ctime_ns
response={"status":"error"}
try:
    if "\0" in target or os.path.normpath(target)!=target or (target!="/outputs" and not target.startswith("/outputs/")):
        stop("error")
    parts=[] if target=="/outputs" else target[9:].split("/")
    if not parts:
        stop("directory")
    parent=os.open("/outputs",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fds.append(parent)
    if not stat.S_ISDIR(os.fstat(parent).st_mode):
        stop("special")
    for part in parts[:-1]:
        before=os.stat(part,dir_fd=parent,follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            stop("symlink")
        if not stat.S_ISDIR(before.st_mode):
            stop("special")
        next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        fds.append(next_fd)
        opened=os.fstat(next_fd)
        if not stat.S_ISDIR(opened.st_mode) or not same_node(before,opened):
            stop("changed")
        parent=next_fd
    before=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        stop("symlink")
    if stat.S_ISDIR(before.st_mode):
        stop("directory")
    if not stat.S_ISREG(before.st_mode):
        stop("special")
    file_fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    fds.append(file_fd)
    opened=os.fstat(file_fd)
    if not stat.S_ISREG(opened.st_mode) or not same_node(before,opened):
        stop("changed")
    content=bytearray()
    while len(content)<LIMIT+1:
        chunk=os.read(file_fd,min(65536,LIMIT+1-len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if len(content)>LIMIT:
        stop("too-large")
    after=os.fstat(file_fd)
    if not same_snapshot(opened,after):
        stop("changed")
    value=bytes(content)
    response={"status":"ok","size":len(value),"contentBase64":base64.b64encode(value).decode("ascii"),"sha256":"sha256:"+hashlib.sha256(value).hexdigest()}
except Controlled as error:
    response={"status":error.status_value}
except FileNotFoundError:
    response={"status":"missing"}
except OSError as error:
    if error.errno==errno.ELOOP:
        response={"status":"symlink"}
    elif error.errno==errno.EISDIR:
        response={"status":"directory"}
    elif error.errno==errno.ENOTDIR:
        response={"status":"changed"}
    else:
        response={"status":"error"}
finally:
    for fd in reversed(fds):
        try:
            os.close(fd)
        except OSError:
            pass
sys.stdout.write(json.dumps(response,separators=(",",":"))+"\n")`
)

type httpFileLstatResponse struct {
	Status string `json:"status"`
}

type httpJSONFileReadFailure string

const (
	httpJSONFileInvalidPath        httpJSONFileReadFailure = "invalid-path"
	httpJSONFileUnsupportedRuntime httpJSONFileReadFailure = "unsupported-runtime"
	httpJSONFileMissing            httpJSONFileReadFailure = "missing"
	httpJSONFileSymlink            httpJSONFileReadFailure = "symlink"
	httpJSONFileDirectory          httpJSONFileReadFailure = "directory"
	httpJSONFileSpecial            httpJSONFileReadFailure = "special"
	httpJSONFileTooLarge           httpJSONFileReadFailure = "too-large"
	httpJSONFileChanged            httpJSONFileReadFailure = "changed"
	httpJSONFileHelperTimeout      httpJSONFileReadFailure = "helper-timeout"
	httpJSONFileHelperExecution    httpJSONFileReadFailure = "helper-execution"
	httpJSONFileControlLimit       httpJSONFileReadFailure = "control-limit"
	httpJSONFileInvalidControl     httpJSONFileReadFailure = "invalid-control"
	httpJSONFileIntegrity          httpJSONFileReadFailure = "integrity"
)

type httpJSONFileReadError struct {
	failure httpJSONFileReadFailure
	cause   error
}

func (e *httpJSONFileReadError) Error() string {
	return "trusted ordered HTTP JSON file read failed (" +
		string(e.failure) + ")"
}

func (e *httpJSONFileReadError) Unwrap() error {
	return e.cause
}

func httpJSONFileReadFailureOf(err error) httpJSONFileReadFailure {
	var target *httpJSONFileReadError
	if errors.As(err, &target) {
		return target.failure
	}
	return httpJSONFileHelperExecution
}

func newHTTPJSONFileReadError(
	failure httpJSONFileReadFailure,
	cause error,
) error {
	return &httpJSONFileReadError{failure: failure, cause: cause}
}

// httpJSONFileSnapshot is intentionally not JSON-serializable. A later
// ordered assertion driver may inspect content, size, and digest in memory,
// but raw repository-controlled file bytes must not enter evidence by
// accidentally marshaling this value.
type httpJSONFileSnapshot struct {
	content []byte
	size    int64
	sha256  string
}

type httpJSONFileReadResponse struct {
	Status        string  `json:"status"`
	Size          *int64  `json:"size,omitempty"`
	ContentBase64 *string `json:"contentBase64,omitempty"`
	SHA256        *string `json:"sha256,omitempty"`
}

func validateHTTPOutputAssertionPath(value string) error {
	if err := domain.ValidateAlphaHTTPOutputPath(value); err != nil {
		return errors.New(
			"HTTP file assertion must be a normalized /outputs path",
		)
	}
	return nil
}

// readHTTPOutputJSONFile takes an ordered, point-in-time snapshot of one
// regular file below /outputs. The trusted helper owns the path walk and
// bounded read; the controller independently validates the transport size and
// SHA-256 before returning bytes to a later in-process assertion driver.
func (r *Runner) readHTTPOutputJSONFile(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	targetPath string,
) (httpJSONFileSnapshot, error) {
	return r.readHTTPOutputJSONFileWithStart(
		ctx,
		prepared,
		containerName,
		targetPath,
		nil,
	)
}

func (r *Runner) readHTTPOutputJSONFileWithStart(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	targetPath string,
	onStart func(),
) (httpJSONFileSnapshot, error) {
	if prepared == nil {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileHelperExecution,
			errors.New("prepared run is required"),
		)
	}
	if err := validateHTTPOutputAssertionPath(targetPath); err != nil {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileInvalidPath,
			err,
		)
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileUnsupportedRuntime,
			nil,
		)
	}
	scriptArgs := []string{
		"-e", nodeHTTPJSONFileReadScript, targetPath,
	}
	if executable == "python" {
		scriptArgs = []string{
			"-I", "-S", "-c",
			pythonHTTPJSONFileReadScript,
			targetPath,
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
	stdout := &cappedBuffer{limit: httpJSONFileMaxControlBytes}
	stderr := &cappedBuffer{limit: 4096}
	helperTimeout := r.config.CreateTimeout
	if helperTimeout > 5*time.Second {
		helperTimeout = 5 * time.Second
	}
	helperCtx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	if onStart != nil {
		onStart()
	}
	exitCode, runErr := r.executor.Run(
		helperCtx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	if errors.Is(runErr, context.DeadlineExceeded) ||
		errors.Is(helperCtx.Err(), context.DeadlineExceeded) {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileHelperTimeout,
			runErr,
		)
	}
	if stdout.truncated || stderr.truncated {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileControlLimit,
			nil,
		)
	}
	if runErr != nil || exitCode != 0 || len(stderr.Bytes()) != 0 {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileHelperExecution,
			runErr,
		)
	}
	return decodeHTTPJSONFileReadResponse(stdout.Bytes())
}

func decodeHTTPJSONFileReadResponse(
	raw []byte,
) (httpJSONFileSnapshot, error) {
	if int64(len(raw)) > httpJSONFileMaxControlBytes {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileControlLimit,
			nil,
		)
	}
	response, err := decodeHTTPJSONFileReadControl(raw)
	if err != nil {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileInvalidControl,
			err,
		)
	}

	if response.Status != "ok" {
		if response.Size != nil ||
			response.ContentBase64 != nil ||
			response.SHA256 != nil {
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileInvalidControl,
				nil,
			)
		}
		switch response.Status {
		case "missing":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileMissing,
				nil,
			)
		case "symlink":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileSymlink,
				nil,
			)
		case "directory":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileDirectory,
				nil,
			)
		case "special":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileSpecial,
				nil,
			)
		case "too-large":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileTooLarge,
				nil,
			)
		case "changed":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileChanged,
				nil,
			)
		case "error":
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileHelperExecution,
				nil,
			)
		default:
			return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
				httpJSONFileInvalidControl,
				nil,
			)
		}
	}

	if response.Size == nil ||
		response.ContentBase64 == nil ||
		response.SHA256 == nil ||
		*response.Size < 0 ||
		*response.Size > httpJSONFileMaxBytes ||
		int64(len(*response.ContentBase64)) > httpJSONFileMaxBase64Bytes ||
		len(*response.ContentBase64) !=
			base64.StdEncoding.EncodedLen(int(*response.Size)) {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileInvalidControl,
			nil,
		)
	}
	content, err := base64.StdEncoding.DecodeString(
		*response.ContentBase64,
	)
	if err != nil ||
		int64(len(content)) != *response.Size ||
		int64(len(content)) > httpJSONFileMaxBytes {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileInvalidControl,
			err,
		)
	}
	sum := sha256.Sum256(content)
	actualDigest := "sha256:" + hex.EncodeToString(sum[:])
	if *response.SHA256 != actualDigest {
		return httpJSONFileSnapshot{}, newHTTPJSONFileReadError(
			httpJSONFileIntegrity,
			nil,
		)
	}
	return httpJSONFileSnapshot{
		content: bytes.Clone(content),
		size:    int64(len(content)),
		sha256:  actualDigest,
	}, nil
}

func decodeHTTPJSONFileReadControl(
	raw []byte,
) (httpJSONFileReadResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return httpJSONFileReadResponse{}, errors.New(
			"helper control must be one JSON object",
		)
	}

	var response httpJSONFileReadResponse
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return httpJSONFileReadResponse{}, errors.New(
				"helper control contains an invalid object key",
			)
		}
		key, ok := token.(string)
		if !ok {
			return httpJSONFileReadResponse{}, errors.New(
				"helper control contains a non-string object key",
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return httpJSONFileReadResponse{}, errors.New(
				"helper control contains a duplicate object key",
			)
		}
		seen[key] = struct{}{}

		switch key {
		case "status":
			var value *string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpJSONFileReadResponse{}, errors.New(
					"helper control status is invalid",
				)
			}
			response.Status = *value
		case "size":
			var value *int64
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpJSONFileReadResponse{}, errors.New(
					"helper control size is invalid",
				)
			}
			response.Size = value
		case "contentBase64":
			var value *string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpJSONFileReadResponse{}, errors.New(
					"helper control payload is invalid",
				)
			}
			response.ContentBase64 = value
		case "sha256":
			var value *string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpJSONFileReadResponse{}, errors.New(
					"helper control digest is invalid",
				)
			}
			response.SHA256 = value
		default:
			return httpJSONFileReadResponse{}, errors.New(
				"helper control contains an unknown object key",
			)
		}
	}

	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return httpJSONFileReadResponse{}, errors.New(
			"helper control object is not closed",
		)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return httpJSONFileReadResponse{}, errors.New(
			"helper control must contain exactly one JSON object",
		)
	}
	return response, nil
}

func (r *Runner) inspectHTTPFileAssertion(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	assertion domain.PlanAssertion,
) domain.AssertionResult {
	return r.inspectHTTPFileAssertionWithStart(
		ctx,
		prepared,
		containerName,
		assertion,
		nil,
	)
}

func (r *Runner) inspectHTTPFileAssertionWithStart(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	assertion domain.PlanAssertion,
	onStart func(),
) domain.AssertionResult {
	result := domain.AssertionResult{
		SchemaVersion: "1",
		ID:            assertion.ID,
		Type:          "file-exists",
		Required:      true,
		Expected:      true,
		Actual:        false,
		Status:        "inconclusive",
		EvidenceRefs: []string{
			"http-assertion:" + assertion.ID + ":lstat",
		},
		Message: "Trusted in-container lstat could not inspect the declared output entry.",
	}
	if err := validateHTTPOutputAssertionPath(assertion.FileExists); err != nil {
		result.Status = "blocked"
		result.Message = "Resolved HTTP file assertion path is unsafe."
		return result
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		result.Status = "blocked"
		result.Message = "Runtime adapter has no trusted file assertion helper."
		return result
	}
	scriptArgs := []string{
		"-e", nodeHTTPFileLstatScript, assertion.FileExists,
	}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		scriptArgs = []string{
			"-I", "-S", "-c",
			pythonHTTPFileLstatScript,
			assertion.FileExists,
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
	startedAt := r.now()
	helperTimeout := r.config.CreateTimeout
	if helperTimeout > 5*time.Second {
		helperTimeout = 5 * time.Second
	}
	helperCtx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	if onStart != nil {
		onStart()
	}
	exitCode, runErr := r.executor.Run(
		helperCtx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	result.DurationMillis = r.now().Sub(startedAt).Milliseconds()
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated {
		return result
	}
	var response httpFileLstatResponse
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return result
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return result
	}
	switch response.Status {
	case "exists":
		result.Actual = true
		result.Status = "passed"
		result.Message = "Trusted in-container lstat observed the declared output entry at this journey step."
	case "missing":
		result.Status = "failed"
		result.Message = "The declared output entry did not exist at this journey step."
	case "symlink":
		result.Status = "failed"
		result.Message = "A symbolic link cannot satisfy the ordered file-exists assertion."
	case "error":
	default:
		return result
	}
	return result
}
