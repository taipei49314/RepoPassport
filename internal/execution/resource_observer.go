package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const (
	linuxResourceControlLimit       = 4096
	resourceContainerIdentityFormat = `{{printf "{\"id\":%q,\"runLabel\":%q}" .Id (index .Config.Labels "dev.repopass.run")}}`
	nodeLinuxResourceScript         = `const fs=require("node:fs"),path=require("node:path");const emit=value=>process.stdout.write(JSON.stringify(value)+"\n"),max=BigInt(Number.MAX_SAFE_INTEGER);function decimal(value){if(!/^(0|[1-9][0-9]*)$/.test(value))throw new Error("invalid");const parsed=BigInt(value);if(parsed>max)throw new Error("large");return Number(parsed);}function file(name){return fs.readFileSync(name,"ascii").trim();}function named(name,key){const matches=file(name).split("\n").filter(line=>line.startsWith(key+" "));if(matches.length!==1)throw new Error("missing");return decimal(matches[0].slice(key.length+1));}function flat(name){return decimal(file(name));}try{const control=file("/proc/self/cgroup");if(control!=="0::/")throw new Error("private-cgroup");const root="/sys/fs/cgroup";file(path.join(root,"cgroup.controllers"));const cpuMax=file(path.join(root,"cpu.max")).split(" ");if(cpuMax.length!==2)throw new Error("cpu");const stat=fs.statfsSync("/outputs",{bigint:true}),limit=stat.blocks*stat.bsize,used=(stat.blocks-stat.bfree)*stat.bsize;if(limit<0n||used<0n||limit>max||used>max||stat.bsize<=0n||stat.bsize>max)throw new Error("statfs");emit({ok:true,cgroupVersion:2,cpuUsageUsec:named(path.join(root,"cpu.stat"),"usage_usec"),sandboxPeakMemoryBytes:flat(path.join(root,"memory.peak")),maxTasks:flat(path.join(root,"pids.peak")),pidsLimitEvents:named(path.join(root,"pids.events"),"max"),memoryOOMEvents:named(path.join(root,"memory.events"),"oom"),memoryOOMKillEvents:named(path.join(root,"memory.events"),"oom_kill"),memoryMaxBytes:flat(path.join(root,"memory.max")),memorySwapMaxBytes:flat(path.join(root,"memory.swap.max")),pidsMax:flat(path.join(root,"pids.max")),cpuQuotaMicros:decimal(cpuMax[0]),cpuPeriodMicros:decimal(cpuMax[1]),writableBytes:Number(used),writableLimitBytes:Number(limit),writableBlockSize:Number(stat.bsize)});}catch(_){emit({ok:false,error:"measurement-unavailable"});}`
	pythonLinuxResourceScript       = `import json,os,posixpath,re
MAX_SAFE=9007199254740991
def emit(value):
    print(json.dumps(value,separators=(",",":")))
def decimal(value):
    if not re.fullmatch(r"0|[1-9][0-9]*",value):
        raise ValueError()
    parsed=int(value)
    if parsed>MAX_SAFE:
        raise ValueError()
    return parsed
def file(name):
    with open(name,encoding="ascii") as source:
        return source.read().strip()
def named(name,key):
    matches=[line for line in file(name).splitlines() if line.startswith(key+" ")]
    if len(matches)!=1:
        raise ValueError()
    return decimal(matches[0][len(key)+1:])
def flat(name):
    return decimal(file(name))
try:
    control=file("/proc/self/cgroup")
    if control!="0::/":
        raise ValueError()
    root="/sys/fs/cgroup"
    file(posixpath.join(root,"cgroup.controllers"))
    cpu_max=file(posixpath.join(root,"cpu.max")).split(" ")
    if len(cpu_max)!=2:
        raise ValueError()
    stat=os.statvfs("/outputs")
    limit=stat.f_blocks*stat.f_frsize
    used=(stat.f_blocks-stat.f_bfree)*stat.f_frsize
    if min(limit,used,stat.f_frsize)<0 or max(limit,used,stat.f_frsize)>MAX_SAFE or stat.f_frsize==0:
        raise ValueError()
    emit({"ok":True,"cgroupVersion":2,"cpuUsageUsec":named(posixpath.join(root,"cpu.stat"),"usage_usec"),"sandboxPeakMemoryBytes":flat(posixpath.join(root,"memory.peak")),"maxTasks":flat(posixpath.join(root,"pids.peak")),"pidsLimitEvents":named(posixpath.join(root,"pids.events"),"max"),"memoryOOMEvents":named(posixpath.join(root,"memory.events"),"oom"),"memoryOOMKillEvents":named(posixpath.join(root,"memory.events"),"oom_kill"),"memoryMaxBytes":flat(posixpath.join(root,"memory.max")),"memorySwapMaxBytes":flat(posixpath.join(root,"memory.swap.max")),"pidsMax":flat(posixpath.join(root,"pids.max")),"cpuQuotaMicros":decimal(cpu_max[0]),"cpuPeriodMicros":decimal(cpu_max[1]),"writableBytes":used,"writableLimitBytes":limit,"writableBlockSize":stat.f_frsize})
except Exception:
    emit({"ok":False,"error":"measurement-unavailable"})`
)

var fullContainerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type linuxResourceSnapshot struct {
	CPUUsageUsec           int64
	SandboxPeakMemoryBytes int64
	MaxTasks               int
	PIDsLimitEvents        int64
	MemoryOOMEvents        int64
	MemoryOOMKillEvents    int64
	MemoryMaxBytes         int64
	MemorySwapMaxBytes     int64
	PIDsMax                int
	CPUQuotaMicros         int64
	CPUPeriodMicros        int64
	WritableBytes          int64
	WritableLimitBytes     int64
	WritableBlockSize      int64
}

type resourceControlResponse struct {
	OK                     bool
	Error                  string
	CgroupVersion          int
	CPUUsageUsec           int64
	SandboxPeakMemoryBytes int64
	MaxTasks               int64
	PIDsLimitEvents        int64
	MemoryOOMEvents        int64
	MemoryOOMKillEvents    int64
	MemoryMaxBytes         int64
	MemorySwapMaxBytes     int64
	PIDsMax                int64
	CPUQuotaMicros         int64
	CPUPeriodMicros        int64
	WritableBytes          int64
	WritableLimitBytes     int64
	WritableBlockSize      int64
}

func parseCreatedContainerID(raw []byte) (string, error) {
	value := string(raw)
	if strings.HasSuffix(value, "\r\n") {
		value = strings.TrimSuffix(value, "\r\n")
	} else {
		value = strings.TrimSuffix(value, "\n")
	}
	if !fullContainerIDPattern.MatchString(value) {
		return "", errors.New("container create did not return one full immutable ID")
	}
	return value, nil
}

func decodeLinuxResourceControl(raw []byte) (linuxResourceSnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return linuxResourceSnapshot{}, errors.New("resource helper control must be one object")
	}
	response := resourceControlResponse{}
	seen := make(map[string]struct{}, 16)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return linuxResourceSnapshot{}, errors.New("resource helper control has an invalid key")
		}
		if _, duplicate := seen[key]; duplicate {
			return linuxResourceSnapshot{}, errors.New("resource helper control has a duplicate key")
		}
		seen[key] = struct{}{}
		switch key {
		case "ok":
			if err := decodeRequiredResourceValue(decoder, &response.OK); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "error":
			if err := decodeRequiredResourceValue(decoder, &response.Error); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "cgroupVersion":
			if err := decodeRequiredResourceValue(decoder, &response.CgroupVersion); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "cpuUsageUsec":
			if err := decodeRequiredResourceValue(decoder, &response.CPUUsageUsec); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "sandboxPeakMemoryBytes":
			if err := decodeRequiredResourceValue(decoder, &response.SandboxPeakMemoryBytes); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "maxTasks":
			if err := decodeRequiredResourceValue(decoder, &response.MaxTasks); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "pidsLimitEvents":
			if err := decodeRequiredResourceValue(decoder, &response.PIDsLimitEvents); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "memoryOOMEvents":
			if err := decodeRequiredResourceValue(decoder, &response.MemoryOOMEvents); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "memoryOOMKillEvents":
			if err := decodeRequiredResourceValue(decoder, &response.MemoryOOMKillEvents); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "memoryMaxBytes":
			if err := decodeRequiredResourceValue(decoder, &response.MemoryMaxBytes); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "memorySwapMaxBytes":
			if err := decodeRequiredResourceValue(decoder, &response.MemorySwapMaxBytes); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "pidsMax":
			if err := decodeRequiredResourceValue(decoder, &response.PIDsMax); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "cpuQuotaMicros":
			if err := decodeRequiredResourceValue(decoder, &response.CPUQuotaMicros); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "cpuPeriodMicros":
			if err := decodeRequiredResourceValue(decoder, &response.CPUPeriodMicros); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "writableBytes":
			if err := decodeRequiredResourceValue(decoder, &response.WritableBytes); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "writableLimitBytes":
			if err := decodeRequiredResourceValue(decoder, &response.WritableLimitBytes); err != nil {
				return linuxResourceSnapshot{}, err
			}
		case "writableBlockSize":
			if err := decodeRequiredResourceValue(decoder, &response.WritableBlockSize); err != nil {
				return linuxResourceSnapshot{}, err
			}
		default:
			return linuxResourceSnapshot{}, errors.New("resource helper control has an unknown key")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return linuxResourceSnapshot{}, errors.New("resource helper control object is not closed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return linuxResourceSnapshot{}, errors.New("resource helper control has trailing data")
	}
	if _, ok := seen["ok"]; !ok {
		return linuxResourceSnapshot{}, errors.New("resource helper control is missing ok")
	}
	if !response.OK {
		if len(seen) != 2 || response.Error != "measurement-unavailable" {
			return linuxResourceSnapshot{}, errors.New("resource helper failure envelope is invalid")
		}
		return linuxResourceSnapshot{}, errors.New("linux cgroup v2 measurement is unavailable")
	}
	required := []string{
		"ok", "cgroupVersion", "cpuUsageUsec", "sandboxPeakMemoryBytes",
		"maxTasks", "pidsLimitEvents", "memoryOOMEvents",
		"memoryOOMKillEvents", "memoryMaxBytes", "memorySwapMaxBytes",
		"pidsMax", "cpuQuotaMicros", "cpuPeriodMicros", "writableBytes",
		"writableLimitBytes", "writableBlockSize",
	}
	if len(seen) != len(required) || !containsAllResourceFields(seen, required) ||
		response.CgroupVersion != 2 ||
		!nonnegativeResourceValues(response) ||
		response.MaxTasks > int64(math.MaxInt) ||
		response.PIDsMax > int64(math.MaxInt) {
		return linuxResourceSnapshot{}, errors.New("resource helper success envelope is invalid")
	}
	return linuxResourceSnapshot{
		CPUUsageUsec:           response.CPUUsageUsec,
		SandboxPeakMemoryBytes: response.SandboxPeakMemoryBytes,
		MaxTasks:               int(response.MaxTasks),
		PIDsLimitEvents:        response.PIDsLimitEvents,
		MemoryOOMEvents:        response.MemoryOOMEvents,
		MemoryOOMKillEvents:    response.MemoryOOMKillEvents,
		MemoryMaxBytes:         response.MemoryMaxBytes,
		MemorySwapMaxBytes:     response.MemorySwapMaxBytes,
		PIDsMax:                int(response.PIDsMax),
		CPUQuotaMicros:         response.CPUQuotaMicros,
		CPUPeriodMicros:        response.CPUPeriodMicros,
		WritableBytes:          response.WritableBytes,
		WritableLimitBytes:     response.WritableLimitBytes,
		WritableBlockSize:      response.WritableBlockSize,
	}, nil
}

func decodeRequiredResourceValue(decoder *json.Decoder, target any) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil ||
		bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("resource helper control has an invalid field type")
	}
	valueDecoder := json.NewDecoder(bytes.NewReader(raw))
	if err := valueDecoder.Decode(target); err != nil {
		return errors.New("resource helper control has an invalid field type")
	}
	if err := valueDecoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("resource helper control has an invalid field value")
	}
	return nil
}

func containsAllResourceFields(seen map[string]struct{}, required []string) bool {
	for _, field := range required {
		if _, ok := seen[field]; !ok {
			return false
		}
	}
	return true
}

func nonnegativeResourceValues(value resourceControlResponse) bool {
	return value.CPUUsageUsec >= 0 &&
		value.SandboxPeakMemoryBytes >= 0 &&
		value.MaxTasks >= 0 &&
		value.PIDsLimitEvents >= 0 &&
		value.MemoryOOMEvents >= 0 &&
		value.MemoryOOMKillEvents >= 0 &&
		value.MemoryMaxBytes >= 0 &&
		value.MemorySwapMaxBytes >= 0 &&
		value.PIDsMax >= 0 &&
		value.CPUQuotaMicros > 0 &&
		value.CPUPeriodMicros > 0 &&
		value.WritableBytes >= 0 &&
		value.WritableLimitBytes > 0 &&
		value.WritableBytes <= value.WritableLimitBytes &&
		value.WritableBlockSize > 0
}

func (r *Runner) collectLinuxResourceSnapshot(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) (linuxResourceSnapshot, error) {
	if !fullContainerIDPattern.MatchString(containerID) {
		return linuxResourceSnapshot{}, errors.New("resource observer has no immutable container ID")
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return linuxResourceSnapshot{}, errors.New("resource observer has no trusted runtime helper")
	}
	scriptArgs := []string{"-e", nodeLinuxResourceScript}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		scriptArgs = []string{"-I", "-S", "-c", pythonLinuxResourceScript}
	}
	args := []string{
		"exec", "--user", "0:0", "--workdir", trustedHelperWorkdir,
		containerID, executable,
	}
	args = append(args, scriptArgs...)
	stdout := &cappedBuffer{limit: linuxResourceControlLimit}
	stderr := &cappedBuffer{limit: linuxResourceControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx, prepared.Backend, args, stdout, stderr,
	)
	if runErr != nil || exitCode != 0 || stdout.truncated ||
		stderr.truncated || len(stderr.Bytes()) != 0 {
		return linuxResourceSnapshot{}, errors.New("trusted resource helper did not complete cleanly")
	}
	return decodeLinuxResourceControl(stdout.Bytes())
}

func validateLinuxResourcePreflight(
	snapshot linuxResourceSnapshot,
	limits domain.ResourceLimits,
) error {
	if err := validateLinuxResourceBinding(snapshot, limits); err != nil {
		return err
	}
	if snapshot.PIDsLimitEvents != 0 ||
		snapshot.MemoryOOMEvents != 0 ||
		snapshot.MemoryOOMKillEvents != 0 {
		return errors.New("sandbox reported resource-limit events before workload dispatch")
	}
	return nil
}

func validateLinuxResourceBinding(
	snapshot linuxResourceSnapshot,
	limits domain.ResourceLimits,
) error {
	if snapshot.MemoryMaxBytes != limits.MemoryBytes ||
		snapshot.MemorySwapMaxBytes != 0 ||
		snapshot.PIDsMax != limits.PIDs {
		return errors.New("sandbox resource limits do not match the resolved plan")
	}
	if snapshot.CPUQuotaMicros > math.MaxInt64/1000 ||
		limits.CPUMillis > math.MaxInt64/snapshot.CPUPeriodMicros ||
		snapshot.CPUQuotaMicros*1000 !=
			limits.CPUMillis*snapshot.CPUPeriodMicros {
		return errors.New("sandbox CPU limit does not match the resolved plan")
	}
	if limits.DiskBytes > math.MaxInt64-snapshot.WritableBlockSize+1 {
		return errors.New("sandbox writable limit cannot be rounded safely")
	}
	roundedDisk := ((limits.DiskBytes + snapshot.WritableBlockSize - 1) /
		snapshot.WritableBlockSize) * snapshot.WritableBlockSize
	if snapshot.WritableLimitBytes != roundedDisk {
		return errors.New("sandbox writable limit does not match the resolved plan")
	}
	return nil
}

func validateLinuxResourceMonotonic(
	active linuxResourceSnapshot,
	final linuxResourceSnapshot,
) error {
	if final.CPUUsageUsec < active.CPUUsageUsec ||
		final.SandboxPeakMemoryBytes <
			active.SandboxPeakMemoryBytes ||
		final.MaxTasks < active.MaxTasks ||
		final.PIDsLimitEvents < active.PIDsLimitEvents ||
		final.MemoryOOMEvents < active.MemoryOOMEvents ||
		final.MemoryOOMKillEvents < active.MemoryOOMKillEvents {
		return errors.New(
			"sandbox cgroup cumulative resource counters moved backwards",
		)
	}
	return nil
}

type resourceContainerIdentity struct {
	ID       string
	RunLabel string
}

func (r *Runner) inspectResourceContainerIdentity(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) error {
	if prepared == nil || !fullContainerIDPattern.MatchString(containerID) ||
		!safeRunID(prepared.RunID) {
		return errors.New(
			"resource observer has no trusted immutable container binding",
		)
	}
	stdout := &cappedBuffer{limit: linuxResourceControlLimit}
	stderr := &cappedBuffer{limit: linuxResourceControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		prepared.Backend,
		[]string{
			"inspect", "--format", resourceContainerIdentityFormat,
			containerID,
		},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 || stdout.truncated ||
		stderr.truncated || len(stderr.Bytes()) != 0 {
		return errors.New("resource observer could not inspect the immutable container")
	}
	identity, err := decodeResourceContainerIdentity(stdout.Bytes())
	if err != nil {
		return err
	}
	if identity.ID != containerID || identity.RunLabel != prepared.RunID {
		return errors.New("resource observer container identity or run label changed")
	}
	return nil
}

func decodeResourceContainerIdentity(raw []byte) (resourceContainerIdentity, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return resourceContainerIdentity{}, errors.New("container identity control must be one object")
	}
	identity := resourceContainerIdentity{}
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return resourceContainerIdentity{}, errors.New("container identity control has an invalid key")
		}
		if _, duplicate := seen[key]; duplicate {
			return resourceContainerIdentity{}, errors.New("container identity control has a duplicate key")
		}
		seen[key] = struct{}{}
		switch key {
		case "id":
			if err := decoder.Decode(&identity.ID); err != nil {
				return resourceContainerIdentity{}, errors.New("container identity ID is invalid")
			}
		case "runLabel":
			if err := decoder.Decode(&identity.RunLabel); err != nil {
				return resourceContainerIdentity{}, errors.New("container identity run label is invalid")
			}
		default:
			return resourceContainerIdentity{}, errors.New("container identity control has an unknown key")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return resourceContainerIdentity{}, errors.New("container identity control is not closed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return resourceContainerIdentity{}, errors.New("container identity control has trailing data")
	}
	if len(seen) != 2 || !fullContainerIDPattern.MatchString(identity.ID) ||
		!safeRunID(identity.RunLabel) {
		return resourceContainerIdentity{}, errors.New("container identity control is incomplete")
	}
	return identity, nil
}

func resourceLimitEventError(
	active linuxResourceSnapshot,
	final linuxResourceSnapshot,
) *domain.Error {
	pidsEvents := final.PIDsLimitEvents - active.PIDsLimitEvents
	oomEvents := final.MemoryOOMEvents - active.MemoryOOMEvents
	oomKillEvents := final.MemoryOOMKillEvents - active.MemoryOOMKillEvents
	if pidsEvents <= 0 && oomEvents <= 0 && oomKillEvents <= 0 {
		return nil
	}
	err := domain.NewError(
		domain.CodeResourceLimitExceeded,
		domain.SeverityHigh,
		"Sandbox cgroup reported one or more workload resource-limit events.",
	)
	err.Phase = domain.PhaseRun
	err.Details = map[string]any{
		"pidsMaxEvents":       pidsEvents,
		"memoryOOMEvents":     oomEvents,
		"memoryOOMKillEvents": oomKillEvents,
	}
	return err
}

func resourceObserverError(message string, cause error) *domain.Error {
	err := domain.WrapError(
		domain.CodeObserverStartFailed,
		domain.SeverityCritical,
		message,
		cause,
	)
	err.Phase = domain.PhasePrepare
	return err
}

func resourceObserverIncomplete(
	message string,
	cause error,
) *domain.Error {
	err := domain.WrapError(
		domain.CodeObserverIncomplete,
		domain.SeverityHigh,
		message,
		cause,
	)
	err.Phase = domain.PhaseCleanup
	return err
}

type resourceObservationState struct {
	required         bool
	containerID      string
	active           linuxResourceSnapshot
	activeReady      bool
	final            linuxResourceSnapshot
	finalReady       bool
	identityVerified bool
	outputBytes      *int64
	failure          string
	observedAt       time.Time
}

func summarizeResourceUsage(
	state resourceObservationState,
	startedAt time.Time,
	completedAt time.Time,
	steps []StepResult,
	backend string,
	containerName string,
) (
	domain.ResourceSummary,
	domain.ObservationEvent,
	string,
) {
	durationMillis := completedAt.Sub(startedAt).Milliseconds()
	if durationMillis < 0 {
		durationMillis = 0
	}
	summary := domain.ResourceSummary{DurationMillis: durationMillis}
	for _, step := range steps {
		if step.LogBytes > 0 && summary.LogBytes <= math.MaxInt64-step.LogBytes {
			summary.LogBytes += step.LogBytes
		}
	}
	if !state.required {
		return summary, domain.ObservationEvent{}, coverageUnavailable
	}
	details := map[string]any{
		"scope":                  "sandbox-cgroup",
		"durationMillis":         summary.DurationMillis,
		"logBytes":               summary.LogBytes,
		"includesTrustedHelpers": true,
		"memoryMetric":           "cgroup-total-not-rss",
		"taskMetric":             "tasks-tids-not-processes",
		"snapshotBoundary":       "post-quiesce-pre-export",
		"writableMeasurement":    "current-at-frozen-gate-not-peak",
		"activeProbe":            state.activeReady,
		"identityVerified":       state.identityVerified,
	}
	metrics := []string{"durationMillis", "logBytes"}
	if state.activeReady {
		details["cgroupVersion"] = 2
		details["memoryMaxBytes"] = state.active.MemoryMaxBytes
		details["memorySwapMaxBytes"] =
			state.active.MemorySwapMaxBytes
		details["pidsMax"] = state.active.PIDsMax
		details["cpuQuotaMicros"] =
			state.active.CPUQuotaMicros
		details["cpuPeriodMicros"] =
			state.active.CPUPeriodMicros
		details["writableLimitBytes"] =
			state.active.WritableLimitBytes
		details["writableBlockSize"] =
			state.active.WritableBlockSize
	}
	if state.finalReady {
		summary.SandboxCPUTimeMillis = state.final.CPUUsageUsec / 1000
		summary.SandboxPeakMemoryBytes =
			state.final.SandboxPeakMemoryBytes
		summary.MaxTasks = state.final.MaxTasks
		summary.WritableBytes = state.final.WritableBytes
		summary.ObservedFields = append(
			summary.ObservedFields,
			domain.ResourceObservedMaxTasks,
			domain.ResourceObservedSandboxCPUTimeMillis,
			domain.ResourceObservedSandboxPeakMemoryBytes,
			domain.ResourceObservedWritableBytes,
		)
		details["cpuUsageUsec"] = state.final.CPUUsageUsec
		details["sandboxCPUTimeMillis"] =
			summary.SandboxCPUTimeMillis
		details["sandboxPeakMemoryBytes"] =
			summary.SandboxPeakMemoryBytes
		details["maxTasks"] = summary.MaxTasks
		details["writableBytes"] = summary.WritableBytes
		details["pidsLimitEvents"] = state.final.PIDsLimitEvents
		details["memoryOOMEvents"] = state.final.MemoryOOMEvents
		details["memoryOOMKillEvents"] =
			state.final.MemoryOOMKillEvents
		metrics = append(
			metrics,
			"maxTasks",
			"memoryOOMEvents",
			"memoryOOMKillEvents",
			"pidsLimitEvents",
			"sandboxCPUTimeMillis",
			"sandboxPeakMemoryBytes",
			"writableBytes",
		)
	}
	if state.outputBytes != nil {
		summary.OutputBytes = *state.outputBytes
		summary.ObservedFields = append(
			summary.ObservedFields,
			domain.ResourceObservedOutputBytes,
		)
		details["outputBytes"] = summary.OutputBytes
		details["outputMeasurement"] =
			"controller-validated-export-logical-bytes"
		metrics = append(metrics, "outputBytes")
	}
	sort.Slice(summary.ObservedFields, func(i, j int) bool {
		return summary.ObservedFields[i] < summary.ObservedFields[j]
	})
	sort.Strings(metrics)
	details["metrics"] = metrics
	if state.failure != "" {
		details["failure"] = state.failure
	}

	coverage := coverageUnavailable
	result := "unavailable"
	confidence := "unknown"
	if state.activeReady && state.finalReady &&
		state.identityVerified {
		coverage = coverageBestEffort
		result = "observed"
		confidence = "high"
	}
	if state.activeReady && state.finalReady &&
		state.identityVerified && state.outputBytes != nil {
		coverage = "high"
	}
	// Public evidence uses a stable logical resource. The immutable container
	// ID remains controller-private verification state.
	resource := "sandbox"
	timestamp := state.observedAt
	if timestamp.IsZero() {
		timestamp = completedAt
	}
	return summary, domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "resource.usage",
		Resource:      resource,
		Result:        result,
		Observer:      backend + "-cgroup-v2",
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       details,
	}, coverage
}

func planRequiresResourceObservation(plan domain.ResolvedPlan) bool {
	for _, observer := range plan.ObserverSet {
		if observer == "resource-usage" {
			return true
		}
	}
	if _, ok := plan.ObserverVersions["resource-usage"]; ok {
		return true
	}
	for _, feature := range plan.RequiredRunnerFeatures {
		switch feature {
		case "resource-usage-observation", "observer:resource-usage":
			return true
		}
	}
	return false
}

func removeCompletedResourceFeatures(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		switch value {
		case "resource-usage-observation", "observer:resource-usage":
			continue
		default:
			result = append(result, value)
		}
	}
	return result
}
