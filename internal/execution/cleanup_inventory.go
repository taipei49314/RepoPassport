package execution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

const (
	cleanupClassifierVersion      = "0.1.0"
	cleanupInventoryMaxEntries    = 2048
	cleanupInventoryMaxPathBytes  = 1024
	cleanupInventoryMaxDepth      = 64
	cleanupInventoryControlBytes  = 512 << 10
	cleanupInventoryStderrBytes   = 4096
	cleanupInventoryTokenKeyBytes = 32
	cleanupInventoryBoundary      = "post-quiescence-post-final-observers-post-disposable-pre-repair-pre-export-pre-destroy"
)

const nodeCleanupDisposableScript = `const fs=require("node:fs"),C=fs.constants,ROOT="/outputs",LIMIT=2048;
let count=0;
function same(a,b){return a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode;}
function rooted(fd,name){return Buffer.concat([Buffer.from("/proc/self/fd/"+fd+"/"),name]);}
function removeTree(fd){
  const before=fs.fstatSync(fd,{bigint:true}),directory=fs.opendirSync("/proc/self/fd/"+fd,{encoding:"buffer"});
  try{
    for(let entry=directory.readSync();entry!==null;entry=directory.readSync()){
      if(++count>LIMIT)throw new Error("limit");
      const name=entry.name,target=rooted(fd,name),initial=fs.lstatSync(target,{bigint:true});
      if(initial.isDirectory()&&!initial.isSymbolicLink()){
        const child=fs.openSync(target,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),opened=fs.fstatSync(child,{bigint:true});
        if(!same(initial,opened))throw new Error("changed");
        try{removeTree(child);if(!same(opened,fs.fstatSync(child,{bigint:true})))throw new Error("changed");}
        finally{fs.closeSync(child);}
        if(!same(opened,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
        fs.rmdirSync(target);
      }else{
        if(!same(initial,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
        fs.unlinkSync(target);
      }
    }
  }finally{directory.closeSync();}
  if(!same(before,fs.fstatSync(fd,{bigint:true})))throw new Error("changed");
}
try{
  const root=fs.openSync(ROOT,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),rootBefore=fs.fstatSync(root,{bigint:true});
  try{
    for(const name of [Buffer.from(".home"),Buffer.from(".tmp")]){
      const target=rooted(root,name);
      let initial;
      try{initial=fs.lstatSync(target,{bigint:true});}catch(error){if(error.code==="ENOENT")continue;throw error;}
      if(initial.isDirectory()&&!initial.isSymbolicLink()){
        const child=fs.openSync(target,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),opened=fs.fstatSync(child,{bigint:true});
        if(!same(initial,opened))throw new Error("changed");
        try{removeTree(child);if(!same(opened,fs.fstatSync(child,{bigint:true})))throw new Error("changed");}
        finally{fs.closeSync(child);}
        if(!same(opened,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
        fs.rmdirSync(target);
      }else{
        if(!same(initial,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
        fs.unlinkSync(target);
      }
      try{fs.lstatSync(target);throw new Error("retained");}catch(error){if(error.code!=="ENOENT")throw error;}
    }
    if(!same(rootBefore,fs.fstatSync(root,{bigint:true})))throw new Error("changed");
  }finally{fs.closeSync(root);}
}catch(_){process.exitCode=1;}`

const pythonCleanupDisposableScript = `import os,stat
LIMIT=2048
count=0
def same(left,right):
    return (left.st_dev,left.st_ino,left.st_mode)==(right.st_dev,right.st_ino,right.st_mode)
def remove_tree(fd):
    global count
    before=os.fstat(fd)
    with os.scandir(fd) as values:
        for entry in values:
            count+=1
            if count>LIMIT:
                raise RuntimeError("limit")
            name=os.fsencode(entry.name)
            initial=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(initial.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                opened=os.fstat(child)
                if not same(initial,opened):
                    raise RuntimeError("changed")
                try:
                    remove_tree(child)
                    if not same(opened,os.fstat(child)):
                        raise RuntimeError("changed")
                finally:
                    os.close(child)
                if not same(opened,os.stat(name,dir_fd=fd,follow_symlinks=False)):
                    raise RuntimeError("changed")
                os.rmdir(name,dir_fd=fd)
            else:
                if not same(initial,os.stat(name,dir_fd=fd,follow_symlinks=False)):
                    raise RuntimeError("changed")
                os.unlink(name,dir_fd=fd)
    if not same(before,os.fstat(fd)):
        raise RuntimeError("changed")
try:
    root=os.open(b"/outputs",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    root_before=os.fstat(root)
    try:
        for name in (b".home",b".tmp"):
            try:
                initial=os.stat(name,dir_fd=root,follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(initial.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
                opened=os.fstat(child)
                if not same(initial,opened):
                    raise RuntimeError("changed")
                try:
                    remove_tree(child)
                    if not same(opened,os.fstat(child)):
                        raise RuntimeError("changed")
                finally:
                    os.close(child)
                if not same(opened,os.stat(name,dir_fd=root,follow_symlinks=False)):
                    raise RuntimeError("changed")
                os.rmdir(name,dir_fd=root)
            else:
                if not same(initial,os.stat(name,dir_fd=root,follow_symlinks=False)):
                    raise RuntimeError("changed")
                os.unlink(name,dir_fd=root)
            try:
                os.stat(name,dir_fd=root,follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RuntimeError("retained")
        if not same(root_before,os.fstat(root)):
            raise RuntimeError("changed")
    finally:
        os.close(root)
except Exception:
    raise SystemExit(1)`

const nodeCleanupInventoryScript = `const fs=require("node:fs"),C=fs.constants,ROOT="/outputs",MAX_ENTRIES=2048,MAX_PATH=1024,MAX_DEPTH=64;
function kind(mode){const value=mode&0o170000n;if(value===0o100000n)return"file";if(value===0o040000n)return"directory";if(value===0o120000n)return"symlink";if(value===0o010000n)return"fifo";if(value===0o140000n)return"socket";if(value===0o020000n)return"char-device";if(value===0o060000n)return"block-device";return"unknown";}
function text(value){const result=value.toString("utf8");if(!Buffer.from(result,"utf8").equals(value)||Buffer.byteLength(result,"utf8")<1)throw new Error("encoding");for(const item of result){const code=item.codePointAt(0);if(code<32||code===127)throw new Error("control");}return result;}
function same(left,right){return left.dev===right.dev&&left.ino===right.ino&&left.mode===right.mode&&left.ctimeNs===right.ctimeNs&&left.mtimeNs===right.mtimeNs;}
function identity(value){return{device:String(value.dev),inode:String(value.ino),mode:Number(value.mode&0o7777n),ctimeNs:String(value.ctimeNs),mtimeNs:String(value.mtimeNs)};}
function rooted(fd,name){return Buffer.concat([Buffer.from("/proc/self/fd/"+fd+"/"),name]);}
const entries=[];
function scan(fd,relative,depth){
  if(depth>MAX_DEPTH)throw new Error("depth");
  const before=fs.fstatSync(fd,{bigint:true}),directory=fs.opendirSync("/proc/self/fd/"+fd,{encoding:"buffer"});
  try{
    for(let item=directory.readSync();item!==null;item=directory.readSync()){
      if(entries.length>=MAX_ENTRIES)throw new Error("entries");
      const name=item.name,value=text(name),childRelative=relative?relative+"/"+value:value;
      if(Buffer.byteLength(childRelative,"utf8")>MAX_PATH)throw new Error("path");
      const target=rooted(fd,name),initial=fs.lstatSync(target,{bigint:true}),entry={path:childRelative,type:kind(initial.mode),mode:Number(initial.mode&0o7777n)};
      entries.push(entry);
      if(entry.type==="directory"){
        const child=fs.openSync(target,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),opened=fs.fstatSync(child,{bigint:true});
        if(!same(initial,opened))throw new Error("changed");
        try{scan(child,childRelative,depth+1);if(!same(opened,fs.fstatSync(child,{bigint:true})))throw new Error("changed");}
        finally{fs.closeSync(child);}
      }else if(entry.type==="file"){
        const child=fs.openSync(target,C.O_RDONLY|C.O_NOFOLLOW),opened=fs.fstatSync(child,{bigint:true});
        try{if(!same(initial,opened))throw new Error("changed");}finally{fs.closeSync(child);}
      }
      if(!same(initial,fs.lstatSync(target,{bigint:true})))throw new Error("changed");
    }
  }finally{directory.closeSync();}
  if(!same(before,fs.fstatSync(fd,{bigint:true})))throw new Error("changed");
}
try{
  const root=fs.openSync(ROOT,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),before=fs.fstatSync(root,{bigint:true});
  let after;
  try{scan(root,"",0);after=fs.fstatSync(root,{bigint:true});if(!same(before,after))throw new Error("changed");}
  finally{fs.closeSync(root);}
  entries.sort((left,right)=>Buffer.compare(Buffer.from(left.path,"utf8"),Buffer.from(right.path,"utf8")));
  let disposableAbsent=true;
  for(const value of ["/outputs/.home","/outputs/.tmp"]){try{fs.lstatSync(value);disposableAbsent=false;}catch(error){if(error.code!=="ENOENT")throw error;}}
  process.stdout.write(JSON.stringify({schemaVersion:"1",ok:true,scope:"/outputs",count:entries.length,rootBefore:identity(before),rootAfter:identity(after),disposableAbsent,entries})+"\n");
}catch(_){process.exitCode=1;}`

const pythonCleanupInventoryScript = `import json,os,stat
ROOT=b"/outputs"
MAX_ENTRIES=2048
MAX_PATH=1024
MAX_DEPTH=64
entries=[]
def kind(mode):
    if stat.S_ISREG(mode): return "file"
    if stat.S_ISDIR(mode): return "directory"
    if stat.S_ISLNK(mode): return "symlink"
    if stat.S_ISFIFO(mode): return "fifo"
    if stat.S_ISSOCK(mode): return "socket"
    if stat.S_ISCHR(mode): return "char-device"
    if stat.S_ISBLK(mode): return "block-device"
    return "unknown"
def text(value):
    result=value.decode("utf-8","strict")
    if not result or any(ord(item)<32 or ord(item)==127 for item in result):
        raise RuntimeError("encoding")
    return result
def same(left,right):
    return (left.st_dev,left.st_ino,left.st_mode,left.st_ctime_ns,left.st_mtime_ns)==(right.st_dev,right.st_ino,right.st_mode,right.st_ctime_ns,right.st_mtime_ns)
def identity(value):
    return {"device":str(value.st_dev),"inode":str(value.st_ino),"mode":stat.S_IMODE(value.st_mode),"ctimeNs":str(value.st_ctime_ns),"mtimeNs":str(value.st_mtime_ns)}
def scan(fd,relative,depth):
    if depth>MAX_DEPTH: raise RuntimeError("depth")
    before=os.fstat(fd)
    with os.scandir(fd) as values:
        for item in values:
            if len(entries)>=MAX_ENTRIES: raise RuntimeError("entries")
            name=os.fsencode(item.name)
            value=text(name)
            child_relative=relative+b"/"+name if relative else name
            if len(child_relative)>MAX_PATH: raise RuntimeError("path")
            initial=os.stat(name,dir_fd=fd,follow_symlinks=False)
            entry={"path":text(child_relative),"type":kind(initial.st_mode),"mode":stat.S_IMODE(initial.st_mode)}
            entries.append(entry)
            if entry["type"]=="directory":
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                opened=os.fstat(child)
                if not same(initial,opened): raise RuntimeError("changed")
                try:
                    scan(child,child_relative,depth+1)
                    if not same(opened,os.fstat(child)): raise RuntimeError("changed")
                finally:
                    os.close(child)
            elif entry["type"]=="file":
                child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
                try:
                    if not same(initial,os.fstat(child)): raise RuntimeError("changed")
                finally:
                    os.close(child)
            if not same(initial,os.stat(name,dir_fd=fd,follow_symlinks=False)): raise RuntimeError("changed")
    if not same(before,os.fstat(fd)): raise RuntimeError("changed")
try:
    root=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    before=os.fstat(root)
    try:
        scan(root,b"",0)
        after=os.fstat(root)
        if not same(before,after): raise RuntimeError("changed")
    finally:
        os.close(root)
    entries.sort(key=lambda item:item["path"].encode("utf-8"))
    disposable_absent=True
    for value in (b"/outputs/.home",b"/outputs/.tmp"):
        try:
            os.stat(value,follow_symlinks=False)
            disposable_absent=False
        except FileNotFoundError:
            pass
    print(json.dumps({"schemaVersion":"1","ok":True,"scope":"/outputs","count":len(entries),"rootBefore":identity(before),"rootAfter":identity(after),"disposableAbsent":disposable_absent,"entries":entries},separators=(",",":"),ensure_ascii=False))
except Exception:
    raise SystemExit(1)`

type cleanupInventoryEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Mode int64  `json:"mode"`
}

type cleanupInventoryIdentity struct {
	Device  string `json:"device"`
	Inode   string `json:"inode"`
	Mode    int64  `json:"mode"`
	CtimeNS string `json:"ctimeNs"`
	MtimeNS string `json:"mtimeNs"`
}

type cleanupInventory struct {
	Entries []cleanupInventoryEntry
}

type cleanupResidueSummary struct {
	Verdict                   domain.CleanupVerdict
	EntryCount                int
	RegularFileCount          int
	DirectoryCount            int
	SymlinkCount              int
	SpecialCount              int
	UnmatchedCount            int
	OpaqueToken               string
	Failure                   string
	QuiescenceConfirmed       bool
	DisposableCleanupVerified bool
	IdentityVerified          bool
	InventoryComplete         bool
	AllowedProfile            string
	AllowedPatternCount       int
}

type cleanupInventoryFailure struct {
	class string
}

func (e *cleanupInventoryFailure) Error() string {
	return "cleanup inventory failed: " + e.class
}

func cleanupInventoryFail(class string) error {
	return &cleanupInventoryFailure{class: class}
}

func cleanupInventoryFailureClass(err error) string {
	var failure *cleanupInventoryFailure
	if errors.As(err, &failure) && failure.class != "" {
		return failure.class
	}
	return "inventory-unavailable"
}

func cleanupDisposableRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeCleanupDisposableScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonCleanupDisposableScript}
	default:
		return nil
	}
}

func cleanupInventoryRuntimeArgs(adapter string) []string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "node":
		return []string{"-e", nodeCleanupInventoryScript}
	case "python":
		return []string{"-I", "-S", "-c", pythonCleanupInventoryScript}
	default:
		return nil
	}
}

func (r *Runner) removeCleanupDisposableDirectories(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) error {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok || !fullContainerIDPattern.MatchString(containerID) {
		return cleanupInventoryFail("disposable-removal-unavailable")
	}
	args := []string{
		"exec", "--user", "0:0", "--workdir", trustedHelperWorkdir,
		containerID, executable,
	}
	args = append(
		args,
		cleanupDisposableRuntimeArgs(prepared.executionPlan.RuntimeAdapter)...,
	)
	stdout := &cappedBuffer{limit: cleanupInventoryStderrBytes}
	stderr := &cappedBuffer{limit: cleanupInventoryStderrBytes}
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 || stdout.truncated ||
		stderr.truncated || len(stdout.Bytes()) != 0 ||
		len(stderr.Bytes()) != 0 {
		return cleanupInventoryFail("disposable-removal-failed")
	}
	return nil
}

func (r *Runner) collectCleanupInventory(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) (cleanupInventory, error) {
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok || !fullContainerIDPattern.MatchString(containerID) {
		return cleanupInventory{}, cleanupInventoryFail(
			"inventory-helper-unavailable",
		)
	}
	args := []string{
		"exec", "--user", "0:0", "--workdir", trustedHelperWorkdir,
		containerID, executable,
	}
	args = append(
		args,
		cleanupInventoryRuntimeArgs(prepared.executionPlan.RuntimeAdapter)...,
	)
	stdout := &cappedBuffer{limit: cleanupInventoryControlBytes}
	stderr := &cappedBuffer{limit: cleanupInventoryStderrBytes}
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	switch {
	case stdout.truncated:
		return cleanupInventory{}, cleanupInventoryFail("control-limit")
	case stderr.truncated || len(stderr.Bytes()) != 0:
		return cleanupInventory{}, cleanupInventoryFail("dirty-stderr")
	case runErr != nil || exitCode != 0:
		return cleanupInventory{}, cleanupInventoryFail("helper-failed")
	}
	return decodeCleanupInventory(stdout.Bytes())
}

func decodeCleanupInventory(raw []byte) (cleanupInventory, error) {
	value, err := structuredjson.Decode(
		raw,
		structuredjson.DecodeLimits{
			MaxBytes: cleanupInventoryControlBytes,
			MaxDepth: 8,
			MaxNodes: cleanupInventoryMaxEntries*5 + 32,
		},
	)
	if err != nil {
		return cleanupInventory{}, cleanupInventoryFail("invalid-control")
	}
	root, ok := value.(map[string]any)
	if !ok || !exactCleanupKeys(root, []string{
		"count",
		"disposableAbsent",
		"entries",
		"ok",
		"rootAfter",
		"rootBefore",
		"schemaVersion",
		"scope",
	}) {
		return cleanupInventory{}, cleanupInventoryFail("invalid-control")
	}
	schemaVersion, schemaOK := root["schemaVersion"].(string)
	scope, scopeOK := root["scope"].(string)
	okValue, okOK := root["ok"].(bool)
	disposableAbsent, disposableOK := root["disposableAbsent"].(bool)
	count, countOK := cleanupJSONInteger(root["count"])
	before, beforeOK := cleanupInventoryIdentityValue(root["rootBefore"])
	after, afterOK := cleanupInventoryIdentityValue(root["rootAfter"])
	rawEntries, entriesOK := root["entries"].([]any)
	if !schemaOK || schemaVersion != "1" ||
		!scopeOK || scope != containerOutputs ||
		!okOK || !okValue ||
		!disposableOK || !disposableAbsent ||
		!countOK || count < 0 ||
		!beforeOK || !afterOK || before != after ||
		!entriesOK {
		return cleanupInventory{}, cleanupInventoryFail("invalid-control")
	}
	if count != len(rawEntries) {
		return cleanupInventory{}, cleanupInventoryFail("count-mismatch")
	}
	if count > cleanupInventoryMaxEntries {
		return cleanupInventory{}, cleanupInventoryFail("entry-limit")
	}

	entries := make([]cleanupInventoryEntry, 0, count)
	previous := ""
	for _, rawEntry := range rawEntries {
		object, objectOK := rawEntry.(map[string]any)
		if !objectOK || !exactCleanupKeys(
			object,
			[]string{"mode", "path", "type"},
		) {
			return cleanupInventory{}, cleanupInventoryFail("invalid-control")
		}
		entryPath, pathOK := object["path"].(string)
		entryType, typeOK := object["type"].(string)
		mode, modeOK := cleanupJSONInteger(object["mode"])
		if !pathOK || !validCleanupInventoryPath(entryPath) ||
			!typeOK || !validCleanupInventoryType(entryType) ||
			!modeOK || mode < 0 || mode > 0o7777 {
			return cleanupInventory{}, cleanupInventoryFail("invalid-entry")
		}
		if previous != "" && previous >= entryPath {
			return cleanupInventory{}, cleanupInventoryFail(
				"unsorted-or-duplicate",
			)
		}
		if entryPath == ".home" ||
			entryPath == ".tmp" ||
			strings.HasPrefix(entryPath, ".home/") ||
			strings.HasPrefix(entryPath, ".tmp/") {
			return cleanupInventory{}, cleanupInventoryFail(
				"disposable-removal-failed",
			)
		}
		previous = entryPath
		entries = append(entries, cleanupInventoryEntry{
			Path: entryPath,
			Type: entryType,
			Mode: int64(mode),
		})
	}
	return cleanupInventory{Entries: entries}, nil
}

func cleanupInventoryIdentityValue(
	value any,
) (cleanupInventoryIdentity, bool) {
	object, ok := value.(map[string]any)
	if !ok || !exactCleanupKeys(
		object,
		[]string{"ctimeNs", "device", "inode", "mode", "mtimeNs"},
	) {
		return cleanupInventoryIdentity{}, false
	}
	device, deviceOK := object["device"].(string)
	inode, inodeOK := object["inode"].(string)
	ctimeNS, ctimeOK := object["ctimeNs"].(string)
	mtimeNS, mtimeOK := object["mtimeNs"].(string)
	mode, modeOK := cleanupJSONInteger(object["mode"])
	if !deviceOK || !decimalCleanupIdentity(device) ||
		!inodeOK || !decimalCleanupIdentity(inode) ||
		!ctimeOK || !decimalCleanupIdentity(ctimeNS) ||
		!mtimeOK || !decimalCleanupIdentity(mtimeNS) ||
		!modeOK || mode < 0 || mode > 0o7777 {
		return cleanupInventoryIdentity{}, false
	}
	return cleanupInventoryIdentity{
		Device:  device,
		Inode:   inode,
		Mode:    int64(mode),
		CtimeNS: ctimeNS,
		MtimeNS: mtimeNS,
	}, true
}

func exactCleanupKeys(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := value[key]; !exists || value[key] == nil {
			return false
		}
	}
	return true
}

func cleanupJSONInteger(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 32)
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func decimalCleanupIdentity(value string) bool {
	if value == "" || len(value) > 32 ||
		(value != "0" && value[0] == '0') {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validCleanupInventoryPath(value string) bool {
	if value == "" ||
		!utf8.ValidString(value) ||
		len([]byte(value)) > cleanupInventoryMaxPathBytes ||
		path.IsAbs(value) ||
		path.Clean(value) != value ||
		value == "." ||
		value == ".." ||
		strings.HasPrefix(value, "../") ||
		strings.Contains(value, "//") {
		return false
	}
	depth := 1
	for _, character := range value {
		if character == '/' {
			depth++
		}
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return depth <= cleanupInventoryMaxDepth
}

func validCleanupInventoryType(value string) bool {
	switch value {
	case "file", "directory", "symlink", "fifo", "socket",
		"char-device", "block-device", "unknown":
		return true
	default:
		return false
	}
}

func classifyCleanupInventory(
	inventory cleanupInventory,
	allowedResidue []string,
	keyReader io.Reader,
) cleanupResidueSummary {
	summary := newCleanupResidueSummary(allowedResidue)
	summary.Verdict = domain.CleanupClean
	summary.EntryCount = len(inventory.Entries)
	summary.InventoryComplete = true
	if len(allowedResidue) > 1 ||
		len(allowedResidue) == 1 &&
			allowedResidue[0] != containerOutputs+"/**" {
		summary.Verdict = domain.CleanupNotTested
		summary.Failure = "invalid-plan-contract"
		return summary
	}

	for _, entry := range inventory.Entries {
		switch entry.Type {
		case "file":
			summary.RegularFileCount++
		case "directory":
			summary.DirectoryCount++
		case "symlink":
			summary.SymlinkCount++
		default:
			summary.SpecialCount++
		}
		if len(allowedResidue) == 0 ||
			entry.Type != "file" && entry.Type != "directory" {
			summary.UnmatchedCount++
		}
	}
	switch {
	case summary.EntryCount == 0:
		summary.Verdict = domain.CleanupClean
	case summary.UnmatchedCount > 0:
		summary.Verdict = domain.CleanupUndeclaredResidue
	default:
		summary.Verdict = domain.CleanupAllowedResidue
	}

	key := make([]byte, cleanupInventoryTokenKeyBytes)
	if keyReader == nil {
		keyReader = bytes.NewReader(nil)
	}
	if _, err := io.ReadFull(keyReader, key); err != nil {
		summary.Verdict = domain.CleanupNotTested
		summary.Failure = "random-unavailable"
		return summary
	}
	canonical, err := canonicaljson.Marshal(inventory.Entries)
	if err != nil {
		summary.Verdict = domain.CleanupNotTested
		summary.Failure = "token-unavailable"
		return summary
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	summary.OpaqueToken = "hmac-sha256:" +
		hex.EncodeToString(mac.Sum(nil))
	return summary
}

func newCleanupResidueSummary(
	allowedResidue []string,
) cleanupResidueSummary {
	profile := "none"
	if len(allowedResidue) == 1 &&
		allowedResidue[0] == containerOutputs+"/**" {
		profile = "outputs-descendants"
	}
	return cleanupResidueSummary{
		Verdict:             domain.CleanupNotTested,
		AllowedProfile:      profile,
		AllowedPatternCount: len(allowedResidue),
	}
}

func cleanupResidueObservation(
	prepared *PreparedRun,
	summary cleanupResidueSummary,
	timestamp time.Time,
) domain.ObservationEvent {
	result := "succeeded"
	coverage := coverageEnforcementOnly
	confidence := "high"
	if summary.Verdict == domain.CleanupNotTested {
		result = "failed"
		coverage = coverageUnavailable
		confidence = "unknown"
	}
	return domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "cleanup.residue.summary",
		Resource:      containerOutputs,
		Result:        result,
		Observer:      "controller-cleanup-residue-classifier",
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       cleanupResidueDetails(summary),
	}
}

func cleanupResidueDetails(
	summary cleanupResidueSummary,
) map[string]any {
	details := map[string]any{
		"allowedPatternCount":       summary.AllowedPatternCount,
		"allowedProfile":            summary.AllowedProfile,
		"boundary":                  cleanupInventoryBoundary,
		"classifierVersion":         cleanupClassifierVersion,
		"directoryCount":            summary.DirectoryCount,
		"disposableCleanupVerified": summary.DisposableCleanupVerified,
		"entryCount":                summary.EntryCount,
		"identityVerified":          summary.IdentityVerified,
		"inventoryComplete":         summary.InventoryComplete,
		"maxControlBytes":           cleanupInventoryControlBytes,
		"maxDepth":                  cleanupInventoryMaxDepth,
		"maxEntries":                cleanupInventoryMaxEntries,
		"maxPathBytes":              cleanupInventoryMaxPathBytes,
		"quiescenceConfirmed":       summary.QuiescenceConfirmed,
		"regularFileCount":          summary.RegularFileCount,
		"scope":                     containerOutputs,
		"specialCount":              summary.SpecialCount,
		"symlinkCount":              summary.SymlinkCount,
		"unmatchedCount":            summary.UnmatchedCount,
		"verdict":                   string(summary.Verdict),
	}
	if summary.OpaqueToken != "" {
		details["opaqueInventoryToken"] = summary.OpaqueToken
		details["tokenScheme"] = "ephemeral-keyed-hmac-sha256"
	}
	if summary.Failure != "" {
		details["failure"] = summary.Failure
	}
	return details
}

func cleanupResidueFinding(
	summary cleanupResidueSummary,
) *domain.Error {
	if summary.Verdict != domain.CleanupUndeclaredResidue {
		return nil
	}
	err := domain.NewError(
		domain.CodeCleanupResidue,
		domain.SeverityHigh,
		"Controller inventory confirmed undeclared cleanup residue.",
	)
	err.Phase = domain.PhaseCleanup
	err.Details = map[string]any{
		"scope":          containerOutputs,
		"entryCount":     summary.EntryCount,
		"unmatchedCount": summary.UnmatchedCount,
		"symlinkCount":   summary.SymlinkCount,
		"specialCount":   summary.SpecialCount,
	}
	return err
}

func cleanupTechnicalError(
	message string,
	class string,
	cause error,
) *domain.Error {
	err := domain.WrapError(
		domain.CodeCleanupFailed,
		domain.SeverityHigh,
		message,
		cause,
	)
	err.Phase = domain.PhaseCleanup
	err.Details = map[string]any{
		"scope":   containerOutputs,
		"failure": class,
	}
	return err
}

func validateCleanupClassifierVersion(version string) error {
	if version != cleanupClassifierVersion {
		return fmt.Errorf("unsupported cleanup classifier version")
	}
	return nil
}
