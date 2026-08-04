package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"

	"github.com/repopass/repopass/internal/domain"
)

const (
	coverageFull            = "full"
	coverageBestEffort      = "best-effort"
	coverageEnforcementOnly = "enforcement-only"
	coverageUnavailable     = "unavailable"
)

// CommandExecutor is deliberately argv-based. Implementations must never
// interpolate these arguments through a shell.
type CommandExecutor interface {
	Run(ctx context.Context, name string, args []string, stdout, stderr io.Writer) (exitCode int, err error)
}

// InputCommandExecutor is the narrow extension used by trusted in-container
// helpers. Request specifications are passed on stdin so untrusted data is not
// exposed through argv, environment variables, or a workload-writable file.
type InputCommandExecutor interface {
	CommandExecutor
	RunInput(
		ctx context.Context,
		name string,
		args []string,
		stdin io.Reader,
		stdout, stderr io.Writer,
	) (exitCode int, err error)
}

// RunningCommand is the narrow lifecycle exposed to controller-owned
// long-running helpers. Stdin remains an explicit framed control channel and
// Wait reports the exact child exit; callers never receive an os.Process.
type RunningCommand interface {
	Stdin() io.WriteCloser
	Wait() (exitCode int, err error)
}

// AsyncCommandExecutor starts one argv-only subprocess without a shell. It is
// intentionally separate from CommandExecutor so test doubles and backends
// that cannot provide a trustworthy streaming transport fail closed.
type AsyncCommandExecutor interface {
	CommandExecutor
	Start(
		ctx context.Context,
		name string,
		args []string,
		stdout, stderr io.Writer,
	) (RunningCommand, error)
}

// OSCommandExecutor invokes a locally installed Docker or Podman CLI without a
// shell. Container commands remain distinct argv elements.
type OSCommandExecutor struct{}

type osRunningCommand struct {
	command *exec.Cmd
	ctx     context.Context
	stdin   io.WriteCloser
}

func (c *osRunningCommand) Stdin() io.WriteCloser {
	return c.stdin
}

func (c *osRunningCommand) Wait() (int, error) {
	err := c.command.Wait()
	if err == nil {
		return 0, nil
	}
	if ctxErr := c.ctx.Err(); ctxErr != nil {
		return -1, ctxErr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return -1, err
}

func (OSCommandExecutor) Start(
	ctx context.Context,
	name string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (RunningCommand, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	return &osRunningCommand{
		command: cmd,
		ctx:     ctx,
		stdin:   stdin,
	}, nil
}

func (OSCommandExecutor) Run(
	ctx context.Context,
	name string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return -1, ctxErr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return -1, err
}

func (OSCommandExecutor) RunInput(
	ctx context.Context,
	name string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return -1, ctxErr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return -1, err
}

type backendSpec struct {
	name     string
	infoArgs []string
}

func lookupBackend(name string) (backendSpec, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "docker":
		return backendSpec{
			name:     "docker",
			infoArgs: []string{"info", "--format", "{{json .}}"},
		}, true
	case "podman":
		return backendSpec{
			name:     "podman",
			infoArgs: []string{"info", "--format", "json"},
		}, true
	default:
		return backendSpec{}, false
	}
}

// DetectBackends reports both supported local CLI backends. An unavailable
// backend is represented as Available=false rather than aborting detection of
// the other backend.
func DetectBackends(ctx context.Context) []domain.RunnerFeatures {
	return NewRunner(OSCommandExecutor{}, DefaultConfig()).DetectBackends(ctx)
}

// Doctor verifies that backendName is reachable and serves Linux containers.
// On Windows and macOS, the controller OS is recorded separately from the
// Linux engine VM.
func Doctor(ctx context.Context, backendName string) (domain.RunnerFeatures, error) {
	return NewRunner(OSCommandExecutor{}, DefaultConfig()).Doctor(ctx, backendName)
}

func (r *Runner) DetectBackends(ctx context.Context) []domain.RunnerFeatures {
	results := make([]domain.RunnerFeatures, 0, 2)
	for _, name := range []string{"docker", "podman"} {
		features, err := r.Doctor(ctx, name)
		if err != nil {
			features = unavailableRunnerFeatures(name, "unknown", safeErrorMessage(err))
		}
		results = append(results, features)
	}
	return results
}

func (r *Runner) Doctor(ctx context.Context, backendName string) (domain.RunnerFeatures, error) {
	spec, ok := lookupBackend(backendName)
	if !ok {
		err := domain.NewError(
			domain.CodeRunnerUnavailable,
			domain.SeverityHigh,
			"Runner backend must be docker or podman.",
		)
		err.Details = map[string]any{"backend": backendName}
		return unavailableRunnerFeatures(backendName, "unknown", err.Message), err
	}

	doctorCtx, cancel := context.WithTimeout(ctx, r.config.DoctorTimeout)
	defer cancel()

	stdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	exitCode, runErr := r.executor.Run(doctorCtx, spec.name, cloneStrings(spec.infoArgs), stdout, stderr)
	if runErr != nil || exitCode != 0 {
		err := domain.WrapError(
			domain.CodeRunnerUnavailable,
			domain.SeverityHigh,
			fmt.Sprintf("%s CLI or engine is unavailable.", spec.name),
			runErr,
		)
		err.Details = map[string]any{
			"backend":  spec.name,
			"exitCode": exitCode,
		}
		return unavailableRunnerFeatures(spec.name, "unknown", err.Message), err
	}

	info, err := parseBackendInfo(spec.name, stdout.Bytes())
	if err != nil {
		wrapped := domain.WrapError(
			domain.CodeRunnerUnavailable,
			domain.SeverityHigh,
			"Runner returned an unreadable engine information document.",
			err,
		)
		wrapped.Details = map[string]any{"backend": spec.name}
		return unavailableRunnerFeatures(spec.name, "unknown", wrapped.Message), wrapped
	}

	features := domain.RunnerFeatures{
		Backend:                    spec.name,
		Available:                  true,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 strings.ToLower(info.workloadOS),
		Rootless:                   info.rootless,
		NetworkDeny:                true,
		NetworkAttemptObservation:  coverageUnavailable,
		ProcessExecObservation:     coverageBestEffort,
		FilesystemWriteObservation: coverageUnavailable,
		FilesystemReadObservation:  coverageUnavailable,
		PortObservation:            coverageUnavailable,
		ResourceUsage:              coverageUnavailable,
		EngineVersion:              info.engineVersion,
		Reason:                     "Controller and workload platforms are reported separately.",
	}
	if features.WorkloadOS != "linux" {
		features = unavailableRunnerFeatures(
			spec.name,
			features.WorkloadOS,
			"The selected engine does not serve Linux containers.",
		)
		features.EngineVersion = info.engineVersion
		features.Rootless = info.rootless
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"RepoPassport v0.1 requires a Linux container engine.",
		)
		err.Details = map[string]any{
			"backend":      spec.name,
			"controllerOS": runtime.GOOS,
			"workloadOS":   features.WorkloadOS,
		}
		return features, err
	}
	return features, nil
}

func unavailableRunnerFeatures(backend, workloadOS, reason string) domain.RunnerFeatures {
	return domain.RunnerFeatures{
		Backend:                    backend,
		Available:                  false,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 workloadOS,
		Rootless:                   "unknown",
		NetworkDeny:                false,
		NetworkAttemptObservation:  coverageUnavailable,
		ProcessExecObservation:     coverageUnavailable,
		FilesystemWriteObservation: coverageUnavailable,
		FilesystemReadObservation:  coverageUnavailable,
		PortObservation:            coverageUnavailable,
		ResourceUsage:              coverageUnavailable,
		Reason:                     reason,
	}
}

type parsedBackendInfo struct {
	workloadOS    string
	engineVersion string
	rootless      string
}

func parseBackendInfo(backend string, raw []byte) (parsedBackendInfo, error) {
	document, err := decodeJSONObject(raw)
	if err != nil {
		return parsedBackendInfo{}, err
	}

	info := parsedBackendInfo{rootless: "unknown"}
	switch backend {
	case "docker":
		info.workloadOS = mapString(document, "OSType")
		info.engineVersion = mapString(document, "ServerVersion")
		info.rootless = dockerRootlessStatus(document)
	case "podman":
		host := mapObject(document, "host")
		info.workloadOS = mapString(host, "os")
		security := mapObject(host, "security")
		if rootless, ok := mapBool(security, "rootless"); ok {
			if rootless {
				info.rootless = "yes"
			} else {
				info.rootless = "no"
			}
		}
		version := mapObject(document, "version")
		info.engineVersion = firstNonEmpty(
			mapString(version, "Version"),
			mapString(version, "version"),
		)
	}

	if info.workloadOS == "" {
		info.workloadOS = recursiveString(document, "ostype", "os")
	}
	if info.engineVersion == "" {
		info.engineVersion = recursiveString(document, "serverversion")
	}
	if backend != "docker" && info.rootless == "unknown" {
		if value, ok := recursiveBool(document, "rootless"); ok {
			if value {
				info.rootless = "yes"
			} else {
				info.rootless = "no"
			}
		}
	}
	if info.workloadOS == "" {
		return parsedBackendInfo{}, errors.New("engine operating system is absent")
	}
	return info, nil
}

func dockerRootlessStatus(document map[string]any) string {
	security, ok := document["SecurityOptions"].([]any)
	if !ok {
		return "unknown"
	}
	rootless := false
	for _, option := range security {
		value, ok := option.(string)
		if !ok {
			return "unknown"
		}
		if strings.EqualFold(strings.TrimSpace(value), "name=rootless") {
			rootless = true
		}
	}
	if rootless {
		return "yes"
	}
	return "no"
}

func decodeJSONObject(raw []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	start := bytes.IndexByte(trimmed, '{')
	end := bytes.LastIndexByte(trimmed, '}')
	if start < 0 || end < start {
		return nil, errors.New("engine info is not a JSON object")
	}
	trimmed = trimmed[start : end+1]
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

func mapObject(document map[string]any, key string) map[string]any {
	if document == nil {
		return nil
	}
	value, ok := document[key]
	if !ok {
		for candidate, item := range document {
			if strings.EqualFold(candidate, key) {
				value = item
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil
	}
	result, _ := value.(map[string]any)
	return result
}

func mapString(document map[string]any, key string) string {
	if document == nil {
		return ""
	}
	for candidate, value := range document {
		if strings.EqualFold(candidate, key) {
			result, _ := value.(string)
			return result
		}
	}
	return ""
}

func mapBool(document map[string]any, key string) (bool, bool) {
	if document == nil {
		return false, false
	}
	for candidate, value := range document {
		if strings.EqualFold(candidate, key) {
			result, ok := value.(bool)
			return result, ok
		}
	}
	return false, false
}

func recursiveString(value any, keys ...string) string {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			for _, wanted := range keys {
				if strings.EqualFold(key, wanted) {
					if result, ok := item.(string); ok && result != "" {
						return result
					}
				}
			}
		}
		for _, item := range typed {
			if result := recursiveString(item, keys...); result != "" {
				return result
			}
		}
	case []any:
		for _, item := range typed {
			if result := recursiveString(item, keys...); result != "" {
				return result
			}
		}
	}
	return ""
}

func recursiveBool(value any, key string) (bool, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for candidate, item := range typed {
			if strings.EqualFold(candidate, key) {
				result, ok := item.(bool)
				if ok {
					return result, true
				}
			}
		}
		for _, item := range typed {
			if result, ok := recursiveBool(item, key); ok {
				return result, true
			}
		}
	case []any:
		for _, item := range typed {
			if result, ok := recursiveBool(item, key); ok {
				return result, true
			}
		}
	}
	return false, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type cappedBuffer struct {
	buffer    bytes.Buffer
	limit     int64
	total     int64
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	originalLength := len(p)
	b.total += int64(originalLength)
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		if originalLength > 0 {
			b.truncated = true
		}
		return originalLength, nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	return originalLength, nil
}

func (b *cappedBuffer) Bytes() []byte {
	return bytes.Clone(b.buffer.Bytes())
}

func safeErrorMessage(err error) string {
	var structured *domain.Error
	if errors.As(err, &structured) {
		return structured.Message
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Runner doctor timed out."
	}
	if errors.Is(err, context.Canceled) {
		return "Runner doctor was cancelled."
	}
	return "Runner is unavailable."
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

var _ CommandExecutor = OSCommandExecutor{}
var _ InputCommandExecutor = OSCommandExecutor{}
var _ AsyncCommandExecutor = OSCommandExecutor{}
var _ RunningCommand = (*osRunningCommand)(nil)
