package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
)

const (
	filesystemControlLimit = 4 << 20
	filesystemEntryLimit   = 2048
	filesystemChangeLimit  = 256
	filesystemPathLimit    = 1024
	filesystemSafeInteger  = int64(1<<53 - 1)

	filesystemDeclarationPatternLimit = 256
	filesystemDeclarationVersion      = "0.1.0"
	filesystemDeclarationScope        = "executed-phase-filesystem-write-union"

	nodeFilesystemSnapshotScript = `const fs=require("node:fs"),crypto=require("node:crypto"),{isUtf8}=require("node:buffer"),c=fs.constants;const ROOT="/outputs",MAX_ENTRIES=2048,MAX_PATH_BYTES=1024,MAX_SAFE=BigInt(Number.MAX_SAFE_INTEGER);function emit(value){process.stdout.write(JSON.stringify(value)+"\n");}function validName(value){if(!value.length||value.equals(Buffer.from("."))||value.equals(Buffer.from(".."))||!isUtf8(value))throw new Error("name");const text=value.toString("utf8");if(Buffer.byteLength(text)>MAX_PATH_BYTES||/[\u0000-\u001f\u007f]/u.test(text))throw new Error("name");return text;}function stable(before,after){return before.dev===after.dev&&before.ino===after.ino&&before.mode===after.mode&&before.size===after.size&&before.mtimeNs===after.mtimeNs&&before.ctimeNs===after.ctimeNs;}function digestBytes(value){return "sha256:"+crypto.createHash("sha256").update(value).digest("hex");}function fileDigest(name,expected){const fd=fs.openSync(name,c.O_RDONLY|c.O_NOFOLLOW|c.O_NONBLOCK);try{const before=fs.fstatSync(fd,{bigint:true});if(!before.isFile()||!stable(expected,before)||before.size>MAX_SAFE)throw new Error("changed");const hash=crypto.createHash("sha256"),buffer=Buffer.allocUnsafe(65536);let total=0n;for(;;){const count=fs.readSync(fd,buffer,0,buffer.length,null);if(count===0)break;hash.update(buffer.subarray(0,count));total+=BigInt(count);if(total>before.size)throw new Error("changed");}const after=fs.fstatSync(fd,{bigint:true});if(total!==before.size||!stable(before,after))throw new Error("changed");return "sha256:"+hash.digest("hex");}finally{fs.closeSync(fd);}}function sameNode(before,after){return before.dev===after.dev&&before.ino===after.ino&&before.mode===after.mode&&before.size===after.size&&before.mtimeNs===after.mtimeNs&&before.ctimeNs===after.ctimeNs;}try{const entries=[],pending=[{absolute:ROOT,relative:""}];while(pending.length){const current=pending.pop(),names=fs.readdirSync(current.absolute,{encoding:"buffer"}).sort((a,b)=>Buffer.compare(a,b));for(const raw of names){const name=validName(raw),relative=current.relative?current.relative+"/"+name:name,publicPath=ROOT+"/"+relative;if(Buffer.byteLength(publicPath)>MAX_PATH_BYTES)throw new Error("path");const absolute=current.absolute+"/"+name,before=fs.lstatSync(absolute,{bigint:true});if(before.size<0n||before.size>MAX_SAFE)throw new Error("size");let type="other",digest="";if(before.isDirectory()){type="directory";pending.push({absolute,relative});}else if(before.isFile()){type="file";digest=fileDigest(absolute,before);}else if(before.isSymbolicLink()){type="symlink";const target=fs.readlinkSync(absolute,{encoding:"buffer"}),after=fs.lstatSync(absolute,{bigint:true});if(!sameNode(before,after))throw new Error("changed");digest=digestBytes(target);}entries.push({path:publicPath,type,mode:Number(before.mode&4095n),size:Number(before.size),digest});if(entries.length>MAX_ENTRIES)throw new Error("entries");}}entries.sort((a,b)=>Buffer.compare(Buffer.from(a.path),Buffer.from(b.path)));emit({ok:true,entries});}catch(_){emit({ok:false,error:"snapshot-unavailable"});}`

	pythonFilesystemSnapshotScript = `import hashlib,json,os,stat
ROOT=b"/outputs"
MAX_ENTRIES=2048
MAX_PATH_BYTES=1024
MAX_SAFE=9007199254740991
def emit(value):
    print(json.dumps(value,separators=(",",":"),ensure_ascii=False))
def text_name(value):
    if value in (b"",b".",b".."):
        raise ValueError()
    text=value.decode("utf-8","strict")
    if len(value)>MAX_PATH_BYTES or any(ord(ch)<32 or ord(ch)==127 for ch in text):
        raise ValueError()
    return text
def stable(before,after):
    return (before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
def file_digest(name,expected):
    descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not stable(expected,before) or before.st_size>MAX_SAFE:
            raise ValueError()
        digest=hashlib.sha256()
        total=0
        while True:
            data=os.read(descriptor,65536)
            if not data:
                break
            digest.update(data)
            total+=len(data)
            if total>before.st_size:
                raise ValueError()
        after=os.fstat(descriptor)
        if total!=before.st_size or not stable(before,after):
            raise ValueError()
        return "sha256:"+digest.hexdigest()
    finally:
        os.close(descriptor)
try:
    entries=[]
    pending=[(ROOT,"")]
    while pending:
        current,relative=pending.pop()
        for raw in sorted(os.listdir(current)):
            name=text_name(raw)
            child_relative=relative+"/"+name if relative else name
            public_path="/outputs/"+child_relative
            if len(public_path.encode("utf-8"))>MAX_PATH_BYTES:
                raise ValueError()
            absolute=current+b"/"+raw
            before=os.lstat(absolute)
            if before.st_size<0 or before.st_size>MAX_SAFE:
                raise ValueError()
            kind="other"
            digest=""
            if stat.S_ISDIR(before.st_mode):
                kind="directory"
                pending.append((absolute,child_relative))
            elif stat.S_ISREG(before.st_mode):
                kind="file"
                digest=file_digest(absolute,before)
            elif stat.S_ISLNK(before.st_mode):
                kind="symlink"
                target=os.readlink(absolute)
                after=os.lstat(absolute)
                if not stable(before,after):
                    raise ValueError()
                digest="sha256:"+hashlib.sha256(target).hexdigest()
            entries.append({"path":public_path,"type":kind,"mode":stat.S_IMODE(before.st_mode),"size":before.st_size,"digest":digest})
            if len(entries)>MAX_ENTRIES:
                raise ValueError()
    entries.sort(key=lambda entry:entry["path"].encode("utf-8"))
    emit({"ok":True,"entries":entries})
except Exception:
    emit({"ok":False,"error":"snapshot-unavailable"})`
)

var filesystemDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type filesystemSnapshotEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   int64  `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type filesystemSnapshot struct {
	Entries []filesystemSnapshotEntry
	Digest  string
}

type filesystemChange struct {
	Path   string
	Kind   string
	Before *filesystemSnapshotEntry
	After  *filesystemSnapshotEntry
}

type filesystemObservationState struct {
	required                   bool
	containerID                string
	baseline                   filesystemSnapshot
	baselineReady              bool
	baselineIdentityVerified   bool
	final                      filesystemSnapshot
	finalReady                 bool
	finalIdentityVerified      bool
	workloadQuiescenceVerified bool
	failure                    string
	observedAt                 time.Time
	declarationPatterns        map[string]struct{}
	declarationScopeAmbiguous  bool
	declarationScopeFailure    string
}

type filesystemDeclarationComparison struct {
	Result                string
	Failure               string
	DeclaredPatternCount  int
	ComparedChangeCount   int
	AllowedChangeCount    int
	UndeclaredChangeCount int
	CreateChangeCount     int
	DeleteChangeCount     int
	ModifyChangeCount     int
	TypeChangeCount       int
}

func (r *Runner) collectFilesystemSnapshot(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) (filesystemSnapshot, error) {
	if !fullContainerIDPattern.MatchString(containerID) {
		return filesystemSnapshot{}, errors.New(
			"filesystem observer has no immutable container ID",
		)
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return filesystemSnapshot{}, errors.New(
			"filesystem observer has no trusted runtime helper",
		)
	}
	scriptArgs := []string{"-e", nodeFilesystemSnapshotScript}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		scriptArgs = []string{
			"-I", "-S", "-c", pythonFilesystemSnapshotScript,
		}
	}
	args := []string{
		"exec", "--user", "0:0", "--workdir", trustedHelperWorkdir,
		containerID, executable,
	}
	args = append(args, scriptArgs...)
	stdout := &cappedBuffer{limit: filesystemControlLimit}
	stderr := &cappedBuffer{limit: filesystemControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		args,
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 || stdout.truncated ||
		stderr.truncated || len(stderr.Bytes()) != 0 {
		return filesystemSnapshot{}, errors.New(
			"trusted filesystem helper did not complete cleanly",
		)
	}
	return decodeFilesystemControl(stdout.Bytes())
}

func decodeFilesystemControl(raw []byte) (filesystemSnapshot, error) {
	if len(raw) == 0 || len(raw) > filesystemControlLimit {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper control exceeds its exact size bound",
		)
	}
	if !utf8.Valid(raw) {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper control is not valid UTF-8",
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper control must be one object",
		)
	}
	seen := make(map[string]struct{}, 3)
	ok := false
	failure := ""
	var entries []filesystemSnapshotEntry
	for decoder.More() {
		token, err = decoder.Token()
		key, valid := token.(string)
		if err != nil || !valid {
			return filesystemSnapshot{}, errors.New(
				"filesystem helper control has an invalid key",
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return filesystemSnapshot{}, errors.New(
				"filesystem helper control has a duplicate key",
			)
		}
		seen[key] = struct{}{}
		switch key {
		case "ok":
			if err := decodeRequiredFilesystemValue(decoder, &ok); err != nil {
				return filesystemSnapshot{}, err
			}
		case "error":
			if err := decodeRequiredFilesystemValue(
				decoder,
				&failure,
			); err != nil {
				return filesystemSnapshot{}, err
			}
		case "entries":
			entries, err = decodeFilesystemEntries(decoder)
			if err != nil {
				return filesystemSnapshot{}, err
			}
		default:
			return filesystemSnapshot{}, errors.New(
				"filesystem helper control has an unknown key",
			)
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper control object is not closed",
		)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper control has trailing data",
		)
	}
	if _, present := seen["ok"]; !present {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper control is missing ok",
		)
	}
	if !ok {
		if len(seen) != 2 || failure != "snapshot-unavailable" {
			return filesystemSnapshot{}, errors.New(
				"filesystem helper failure envelope is invalid",
			)
		}
		return filesystemSnapshot{}, errors.New(
			"filesystem retained-state snapshot is unavailable",
		)
	}
	if len(seen) != 2 {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper success envelope is invalid",
		)
	}
	if _, present := seen["entries"]; !present {
		return filesystemSnapshot{}, errors.New(
			"filesystem helper success envelope is missing entries",
		)
	}
	digest, err := canonicaljson.Digest(entries)
	if err != nil {
		return filesystemSnapshot{}, fmt.Errorf(
			"filesystem snapshot could not be canonicalized: %w",
			err,
		)
	}
	return filesystemSnapshot{
		Entries: entries,
		Digest:  digest,
	}, nil
}

func decodeFilesystemEntries(
	decoder *json.Decoder,
) ([]filesystemSnapshotEntry, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errors.New(
			"filesystem helper entries must be one array",
		)
	}
	entries := make([]filesystemSnapshotEntry, 0)
	previousPath := ""
	for decoder.More() {
		if len(entries) >= filesystemEntryLimit {
			return nil, errors.New(
				"filesystem helper returned too many entries",
			)
		}
		entry, err := decodeFilesystemEntry(decoder)
		if err != nil {
			return nil, err
		}
		if len(entries) > 0 && entry.Path <= previousPath {
			return nil, errors.New(
				"filesystem helper entries are not unique and sorted",
			)
		}
		previousPath = entry.Path
		entries = append(entries, entry)
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim(']') {
		return nil, errors.New(
			"filesystem helper entries array is not closed",
		)
	}
	return entries, nil
}

func decodeFilesystemEntry(
	decoder *json.Decoder,
) (filesystemSnapshotEntry, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return filesystemSnapshotEntry{}, errors.New(
			"filesystem helper entry must be one object",
		)
	}
	entry := filesystemSnapshotEntry{}
	seen := make(map[string]struct{}, 5)
	for decoder.More() {
		token, err = decoder.Token()
		key, valid := token.(string)
		if err != nil || !valid {
			return filesystemSnapshotEntry{}, errors.New(
				"filesystem helper entry has an invalid key",
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return filesystemSnapshotEntry{}, errors.New(
				"filesystem helper entry has a duplicate key",
			)
		}
		seen[key] = struct{}{}
		switch key {
		case "path":
			err = decodeRequiredFilesystemValue(decoder, &entry.Path)
		case "type":
			err = decodeRequiredFilesystemValue(decoder, &entry.Type)
		case "mode":
			err = decodeRequiredFilesystemValue(decoder, &entry.Mode)
		case "size":
			err = decodeRequiredFilesystemValue(decoder, &entry.Size)
		case "digest":
			err = decodeRequiredFilesystemValue(decoder, &entry.Digest)
		default:
			return filesystemSnapshotEntry{}, errors.New(
				"filesystem helper entry has an unknown key",
			)
		}
		if err != nil {
			return filesystemSnapshotEntry{}, err
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return filesystemSnapshotEntry{}, errors.New(
			"filesystem helper entry object is not closed",
		)
	}
	if len(seen) != 5 || !validFilesystemSnapshotEntry(entry) {
		return filesystemSnapshotEntry{}, errors.New(
			"filesystem helper entry is incomplete or invalid",
		)
	}
	return entry, nil
}

func decodeRequiredFilesystemValue(
	decoder *json.Decoder,
	target any,
) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil ||
		bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New(
			"filesystem helper control has an invalid field type",
		)
	}
	valueDecoder := json.NewDecoder(bytes.NewReader(raw))
	if err := valueDecoder.Decode(target); err != nil {
		return errors.New(
			"filesystem helper control has an invalid field type",
		)
	}
	if err := valueDecoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New(
			"filesystem helper control has an invalid field value",
		)
	}
	return nil
}

func validFilesystemSnapshotEntry(entry filesystemSnapshotEntry) bool {
	if !validObservedFilesystemPath(entry.Path) ||
		entry.Mode < 0 || entry.Mode > 0o7777 ||
		entry.Size < 0 || entry.Size > filesystemSafeInteger {
		return false
	}
	switch entry.Type {
	case "file", "symlink":
		return filesystemDigestPattern.MatchString(entry.Digest)
	case "directory", "other":
		return entry.Digest == ""
	default:
		return false
	}
}

func validObservedFilesystemPath(value string) bool {
	if value == "" || len(value) > filesystemPathLimit ||
		!utf8.ValidString(value) ||
		!strings.HasPrefix(value, containerOutputs+"/") ||
		path.Clean(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func diffFilesystemSnapshots(
	baseline filesystemSnapshot,
	final filesystemSnapshot,
) []filesystemChange {
	before := make(
		map[string]filesystemSnapshotEntry,
		len(baseline.Entries),
	)
	after := make(
		map[string]filesystemSnapshotEntry,
		len(final.Entries),
	)
	paths := make(map[string]struct{}, len(baseline.Entries)+len(final.Entries))
	for _, entry := range baseline.Entries {
		before[entry.Path] = entry
		paths[entry.Path] = struct{}{}
	}
	for _, entry := range final.Entries {
		after[entry.Path] = entry
		paths[entry.Path] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for item := range paths {
		ordered = append(ordered, item)
	}
	sort.Strings(ordered)

	changes := make([]filesystemChange, 0)
	for _, item := range ordered {
		beforeEntry, hadBefore := before[item]
		afterEntry, hasAfter := after[item]
		switch {
		case !hadBefore:
			copied := afterEntry
			changes = append(changes, filesystemChange{
				Path: item, Kind: "create", After: &copied,
			})
		case !hasAfter:
			copied := beforeEntry
			changes = append(changes, filesystemChange{
				Path: item, Kind: "delete", Before: &copied,
			})
		case beforeEntry != afterEntry:
			beforeCopy := beforeEntry
			afterCopy := afterEntry
			kind := "modify"
			if beforeEntry.Type != afterEntry.Type {
				kind = "type-change"
			}
			changes = append(changes, filesystemChange{
				Path: item, Kind: kind,
				Before: &beforeCopy, After: &afterCopy,
			})
		}
	}
	return changes
}

func validateFilesystemChangeBound(
	baseline filesystemSnapshot,
	final filesystemSnapshot,
) error {
	if len(diffFilesystemSnapshots(baseline, final)) >
		filesystemChangeLimit {
		return errors.New(
			"filesystem retained-state diff exceeds the public evidence bound",
		)
	}
	return nil
}

func recordFilesystemPhaseDispatch(
	state *filesystemObservationState,
	plan domain.ResolvedPlan,
	phase domain.Phase,
) {
	if state == nil || !state.required || state.declarationScopeAmbiguous {
		return
	}
	capability, present := plan.Capabilities[phase]
	if !present {
		return
	}
	if state.declarationPatterns == nil {
		state.declarationPatterns = make(map[string]struct{})
	}
	for _, pattern := range capability.Filesystem.Write {
		if !validFilesystemDeclarationPattern(pattern) {
			markFilesystemDeclarationAmbiguous(
				state,
				"invalid-declared-write-scope",
			)
			return
		}
		state.declarationPatterns[pattern] = struct{}{}
		if len(state.declarationPatterns) >
			filesystemDeclarationPatternLimit {
			markFilesystemDeclarationAmbiguous(
				state,
				"declared-write-scope-bound-exceeded",
			)
			return
		}
	}
}

func recordFilesystemSignalGrant(
	state *filesystemObservationState,
	plan domain.ResolvedPlan,
	helper signalHelperResult,
	signalErr error,
) {
	if state == nil || !state.required {
		return
	}
	if signalErr != nil {
		markFilesystemDeclarationAmbiguous(
			state,
			"cleanup-signal-delivery-ambiguous",
		)
		return
	}
	if helper.AlreadyExited {
		return
	}
	if !helper.OK || helper.InitialTargets < 1 || helper.Sent < 1 ||
		helper.Sent > helper.InitialTargets || helper.Remaining != 0 {
		markFilesystemDeclarationAmbiguous(
			state,
			"cleanup-signal-delivery-ambiguous",
		)
		return
	}
	recordFilesystemPhaseDispatch(state, plan, domain.PhaseCleanup)
}

func markFilesystemDeclarationAmbiguous(
	state *filesystemObservationState,
	failure string,
) {
	if state == nil {
		return
	}
	state.declarationScopeAmbiguous = true
	state.declarationScopeFailure = failure
	state.declarationPatterns = nil
}

func validFilesystemDeclarationPattern(value string) bool {
	if value == "" || len([]byte(value)) > filesystemPathLimit ||
		!utf8.ValidString(value) || strings.Contains(value, "\\") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	base := value
	if strings.HasSuffix(base, "/**") {
		base = strings.TrimSuffix(base, "/**")
	} else if strings.HasSuffix(base, "/*") {
		base = strings.TrimSuffix(base, "/*")
	}
	return base != "" && path.Clean(base) == base &&
		(base == containerOutputs ||
			strings.HasPrefix(base, containerOutputs+"/"))
}

func filesystemDeclarationPatternMatches(pattern string, observed string) bool {
	if !validFilesystemDeclarationPattern(pattern) ||
		!validObservedFilesystemPath(observed) {
		return false
	}
	if strings.HasSuffix(pattern, "/**") {
		base := strings.TrimSuffix(pattern, "/**")
		return observed == base || strings.HasPrefix(observed, base+"/")
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(observed, base+"/") {
			return false
		}
		remainder := strings.TrimPrefix(observed, base+"/")
		return remainder != "" && !strings.Contains(remainder, "/")
	}
	return observed == pattern
}

func compareFilesystemRetainedState(
	state filesystemObservationState,
) filesystemDeclarationComparison {
	comparison := filesystemDeclarationComparison{Result: "not-tested"}
	if !state.required {
		comparison.Failure = "observer-not-required"
		return comparison
	}
	if state.declarationScopeAmbiguous {
		comparison.Failure = state.declarationScopeFailure
		if comparison.Failure == "" {
			comparison.Failure = "runtime-phase-scope-ambiguous"
		}
		return comparison
	}
	if state.failure != "" || !state.baselineReady || !state.finalReady ||
		!state.baselineIdentityVerified ||
		!state.finalIdentityVerified ||
		!state.workloadQuiescenceVerified {
		comparison.Failure = "retained-state-prerequisite-unavailable"
		return comparison
	}
	if err := validateFilesystemChangeBound(
		state.baseline,
		state.final,
	); err != nil {
		comparison.Failure = "retained-state-change-bound-exceeded"
		return comparison
	}
	patterns := make([]string, 0, len(state.declarationPatterns))
	for pattern := range state.declarationPatterns {
		if !validFilesystemDeclarationPattern(pattern) {
			comparison.Failure = "invalid-declared-write-scope"
			return comparison
		}
		patterns = append(patterns, pattern)
	}
	if len(patterns) > filesystemDeclarationPatternLimit {
		comparison.Failure = "declared-write-scope-bound-exceeded"
		return comparison
	}
	sort.Strings(patterns)
	comparison.DeclaredPatternCount = len(patterns)
	changes := diffFilesystemSnapshots(state.baseline, state.final)
	comparison.ComparedChangeCount = len(changes)
	for _, change := range changes {
		if !validObservedFilesystemPath(change.Path) {
			comparison.Result = "not-tested"
			comparison.Failure = "retained-state-path-invalid"
			return comparison
		}
		switch change.Kind {
		case "create":
			comparison.CreateChangeCount++
		case "delete":
			comparison.DeleteChangeCount++
		case "modify":
			comparison.ModifyChangeCount++
		case "type-change":
			comparison.TypeChangeCount++
		default:
			comparison.Result = "not-tested"
			comparison.Failure = "retained-state-change-kind-invalid"
			return comparison
		}
		allowed := false
		for _, pattern := range patterns {
			if filesystemDeclarationPatternMatches(pattern, change.Path) {
				allowed = true
				break
			}
		}
		if allowed {
			comparison.AllowedChangeCount++
		} else {
			comparison.UndeclaredChangeCount++
		}
	}
	comparison.Result = "conforming-retained-state"
	if comparison.UndeclaredChangeCount > 0 {
		comparison.Result = "nonconforming-retained-state"
	}
	return comparison
}

func filesystemDeclarationFinding(
	comparison filesystemDeclarationComparison,
) *domain.Error {
	if comparison.Result != "nonconforming-retained-state" ||
		comparison.UndeclaredChangeCount < 1 {
		return nil
	}
	err := domain.NewError(
		domain.CodeUndeclaredFilesystemWrite,
		domain.SeverityHigh,
		"Bounded retained output state contains changes outside every filesystem.write declaration granted during this run.",
	)
	err.Details = map[string]any{
		"comparisonScope":          filesystemDeclarationScope,
		"comparisonVersion":        filesystemDeclarationVersion,
		"declaredPatternCount":     comparison.DeclaredPatternCount,
		"comparedChangeCount":      comparison.ComparedChangeCount,
		"allowedChangeCount":       comparison.AllowedChangeCount,
		"undeclaredChangeCount":    comparison.UndeclaredChangeCount,
		"evidenceBasis":            "bounded-retained-state-delta",
		"operationHistoryCoverage": coverageUnavailable,
		"actorAttribution":         coverageUnavailable,
		"phaseAttribution":         coverageUnavailable,
	}
	return err
}

func summarizeFilesystemRetainedState(
	state filesystemObservationState,
	backend string,
	containerName string,
	completedAt time.Time,
) ([]domain.ObservationEvent, string, string) {
	if !state.required {
		return nil, coverageUnavailable, coverageUnavailable
	}
	writeCoverage := coverageUnavailable
	retainedCoverage := coverageUnavailable
	result := "unavailable"
	confidence := "unknown"
	changes := []filesystemChange{}
	if state.failure == "" &&
		state.baselineReady && state.finalReady &&
		state.baselineIdentityVerified &&
		state.finalIdentityVerified &&
		state.workloadQuiescenceVerified {
		writeCoverage = coverageBestEffort
		retainedCoverage = "high"
		result = "observed"
		confidence = "high"
		changes = diffFilesystemSnapshots(state.baseline, state.final)
	}
	timestamp := state.observedAt
	if timestamp.IsZero() {
		timestamp = completedAt
	}
	comparison := compareFilesystemRetainedState(state)
	details := map[string]any{
		"scope":                            "outputs-retained-state",
		"snapshotBoundary":                 "post-init-pre-workload-to-post-quiesce-pre-repair",
		"includesTrustedHelpers":           true,
		"includesRunnerManagedDirectories": true,
		"contentIncluded":                  false,
		"publicEvidence":                   "aggregate-only",
		"actorAttribution":                 "unavailable",
		"baselineIdentityVerified":         state.baselineIdentityVerified,
		"finalIdentityVerified":            state.finalIdentityVerified,
		"workloadQuiescenceVerified":       state.workloadQuiescenceVerified,
		"baselineReady":                    state.baselineReady,
		"finalReady":                       state.finalReady,
		"retainedStateCoverage":            retainedCoverage,
		"declarationComparisonScope":       filesystemDeclarationScope,
		"declarationComparisonVersion":     filesystemDeclarationVersion,
		"declarationComparisonResult":      comparison.Result,
		"blindSpots": []string{
			"outside-outputs",
			"transient-create-delete",
			"write-then-restore",
			"operation-time",
			"process-phase-attribution",
			"exact-actor-and-operation-kind",
			"unexecuted-phase-declarations",
			"rename-vs-delete-create",
			"ownership",
			"timestamps",
			"xattr-acl",
			"inode-device",
		},
	}
	if retainedCoverage == "high" {
		details["baselineDigest"] = state.baseline.Digest
		details["baselineEntryCount"] = len(state.baseline.Entries)
		details["finalDigest"] = state.final.Digest
		details["finalEntryCount"] = len(state.final.Entries)
		details["changeCount"] = len(changes)
	}
	if comparison.Result == "conforming-retained-state" ||
		comparison.Result == "nonconforming-retained-state" {
		details["declaredPatternCount"] =
			comparison.DeclaredPatternCount
		details["comparedChangeCount"] =
			comparison.ComparedChangeCount
		details["allowedChangeCount"] =
			comparison.AllowedChangeCount
		details["undeclaredChangeCount"] =
			comparison.UndeclaredChangeCount
		details["createChangeCount"] = comparison.CreateChangeCount
		details["deleteChangeCount"] = comparison.DeleteChangeCount
		details["modifyChangeCount"] = comparison.ModifyChangeCount
		details["typeChangeCount"] = comparison.TypeChangeCount
	} else if comparison.Failure != "" {
		details["declarationComparisonFailure"] = comparison.Failure
	}
	if state.failure != "" {
		details["failure"] = state.failure
	}
	observations := []domain.ObservationEvent{{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "filesystem.retained-state.summary",
		Resource:      containerName,
		Result:        result,
		Observer:      backend + "-filesystem-retained-state",
		Coverage:      retainedCoverage,
		Confidence:    confidence,
		Details:       details,
	}}
	return observations, writeCoverage, retainedCoverage
}

func planRequiresFilesystemWriteObservation(
	plan domain.ResolvedPlan,
) bool {
	for _, observer := range plan.ObserverSet {
		if observer == "filesystem-write" {
			return true
		}
	}
	if _, ok := plan.ObserverVersions["filesystem-write"]; ok {
		return true
	}
	for _, feature := range plan.RequiredRunnerFeatures {
		switch feature {
		case "filesystem-write-observation", "observer:filesystem-write":
			return true
		}
	}
	return false
}
