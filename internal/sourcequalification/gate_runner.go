package sourcequalification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const maximumGateOutputBytes int64 = 4 << 20

var (
	errGateInvalidInput  = errors.New("SOURCE_QUAL_INVALID_INPUT")
	errGateFailed        = errors.New("SOURCE_QUAL_GATE_FAILED")
	errGateBlocked       = errors.New("SOURCE_QUAL_GATE_BLOCKED")
	errGateNotRun        = errors.New("SOURCE_QUAL_GATE_NOT_RUN")
	errGateOutputLimit   = errors.New("SOURCE_QUAL_OUTPUT_LIMIT")
	errGateCleanupFailed = errors.New("SOURCE_QUAL_CLEANUP_FAILED")
)

type gateRunRequest struct {
	Lane           Lane
	TestedRevision string
	RepositoryRoot string
	GOOS           string
	GOARCH         string
	Applications   map[string]string
	Environment    gateRunEnvironment
}

type gateRunEnvironment struct {
	ToolPath                 string
	HomeDir                  string
	GoCacheDir               string
	GoModCacheDir            string
	TempDir                  string
	GoProxy                  string
	GoSumDB                  string
	VulnerabilityDatabaseURL string
	SystemRoot               string
}

// gateProcessRequest is the complete private process boundary. An OS-specific
// executor must invoke Application directly with Args; the logical public argv
// remains in the receipt record.
type gateProcessRequest struct {
	Application string
	Args        []string
	Dir         string
	Env         []string
	Timeout     time.Duration
	StdoutLimit int64
	StderrLimit int64
}

type gateProcessResult struct {
	ExitCode       *int64
	Stdout         []byte
	Stderr         []byte
	Blocked        bool
	TimedOut       bool
	Cancelled      bool
	StdoutOverflow bool
	StderrOverflow bool
	CleanupFailed  bool
	SourceChanged  bool
}

type gateExecutor interface {
	Execute(context.Context, gateProcessRequest) (gateProcessResult, error)
}

type gatePrivateLogSink interface {
	WriteGateLog(id string, stdout, stderr []byte) error
}

func runRequiredGates(
	ctx context.Context,
	request gateRunRequest,
	executor gateExecutor,
	logs gatePrivateLogSink,
) ([]receiptGate, error) {
	registry, applications, valid := validateGateRunRequest(request, executor, logs)
	if !valid {
		return nil, errGateInvalidInput
	}

	records := make([]receiptGate, len(registry))
	for index, specification := range registry {
		records[index] = receiptGate{
			Argv:           substituteGateArgv(specification.Argv, request.TestedRevision),
			Attempt:        1,
			ID:             specification.ID,
			Network:        specification.Network,
			Status:         StatusNotRun,
			TimeoutSeconds: int64(specification.TimeoutSeconds),
		}
	}

	for index, specification := range registry {
		if ctx.Err() != nil {
			return records, errGateNotRun
		}

		started := time.Now().UTC().Truncate(time.Second)
		processRequest := gateProcessRequest{
			Application: applications[specification.Argv[0]],
			Args:        append([]string(nil), records[index].Argv[1:]...),
			Dir:         request.RepositoryRoot,
			Env:         gateEnvironment(request.Environment, specification.Network),
			Timeout:     time.Duration(specification.TimeoutSeconds) * time.Second,
			StdoutLimit: maximumGateOutputBytes,
			StderrLimit: maximumGateOutputBytes,
		}

		result, executionErr := executor.Execute(ctx, processRequest)
		if ctx.Err() != nil {
			result.Cancelled = true
		}
		finished := time.Now().UTC().Truncate(time.Second)
		if finished.Before(started) {
			finished = started
		}
		records[index].StartedAt = gateTimestamp(started)
		records[index].FinishedAt = gateTimestamp(finished)

		stdout, stdoutTooLarge := boundedGateLog(result.Stdout)
		stderr, stderrTooLarge := boundedGateLog(result.Stderr)
		outputOverflow := stdoutTooLarge || stderrTooLarge || result.StdoutOverflow || result.StderrOverflow
		if err := logs.WriteGateLog(
			specification.ID,
			append([]byte(nil), stdout...),
			append([]byte(nil), stderr...),
		); err != nil {
			records[index].Status = StatusFail
			records[index].ExitCode = validGateExitCode(result.ExitCode)
			return records, errGateFailed
		}

		status, exitCode, runErr := evaluateGateResult(
			specification,
			request,
			result,
			executionErr,
			stdout,
			outputOverflow,
		)
		records[index].Status = status
		records[index].ExitCode = exitCode
		if runErr != nil {
			return records, runErr
		}
	}

	return records, nil
}

func validateGateRunRequest(
	request gateRunRequest,
	executor gateExecutor,
	logs gatePrivateLogSink,
) ([]GateSpec, map[string]string, bool) {
	if executor == nil || logs == nil || nilGateDependency(executor) || nilGateDependency(logs) ||
		!validRepositoryOID(request.TestedRevision) ||
		!validGateLanePlatform(request.Lane, request.GOOS, request.GOARCH) ||
		!validGateDirectory(request.RepositoryRoot) {
		return nil, nil, false
	}
	registry := RequiredGates(request.Lane)
	if len(registry) == 0 || !validGateRunEnvironment(request.RepositoryRoot, request.Environment) {
		return nil, nil, false
	}

	requiredApplications := make(map[string]struct{})
	for _, specification := range registry {
		if len(specification.Argv) == 0 || specification.TimeoutSeconds <= 0 {
			return nil, nil, false
		}
		requiredApplications[specification.Argv[0]] = struct{}{}
	}
	if len(request.Applications) != len(requiredApplications) {
		return nil, nil, false
	}

	toolDirectories := filepath.SplitList(request.Environment.ToolPath)
	applications := make(map[string]string, len(requiredApplications))
	for logicalName := range requiredApplications {
		application, ok := request.Applications[logicalName]
		if !ok || !validGateApplication(request.RepositoryRoot, application, toolDirectories) {
			return nil, nil, false
		}
		applications[logicalName] = application
	}
	for logicalName := range request.Applications {
		if _, ok := requiredApplications[logicalName]; !ok {
			return nil, nil, false
		}
	}
	return registry, applications, true
}

func validGateLanePlatform(lane Lane, goos, goarch string) bool {
	if goarch != "amd64" {
		return false
	}
	switch lane {
	case LaneLinuxAMD64:
		return goos == "linux"
	case LaneWindowsAMD64:
		return goos == "windows"
	default:
		return false
	}
}

func validGateRunEnvironment(repositoryRoot string, environment gateRunEnvironment) bool {
	if environment.GoProxy != "https://proxy.golang.org" ||
		environment.GoSumDB != "sum.golang.org" ||
		environment.VulnerabilityDatabaseURL != "https://vuln.go.dev" {
		return false
	}

	toolDirectories := filepath.SplitList(environment.ToolPath)
	if len(toolDirectories) == 0 {
		return false
	}
	for _, directory := range toolDirectories {
		if !validGatePrivateDirectory(repositoryRoot, directory) {
			return false
		}
	}
	for _, directory := range []string{
		environment.HomeDir,
		environment.GoCacheDir,
		environment.GoModCacheDir,
		environment.TempDir,
	} {
		if !validGatePrivateDirectory(repositoryRoot, directory) {
			return false
		}
	}
	return environment.SystemRoot == "" || validGateDirectory(environment.SystemRoot)
}

func validGateDirectory(path string) bool {
	if !cleanAbsoluteGatePath(path) {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(resolved) && sameCanonicalPath(path, resolved)
}

func validGatePrivateDirectory(repositoryRoot, path string) bool {
	return validGateDirectory(path) && !pathWithinRepository(repositoryRoot, path)
}

func validGateApplication(repositoryRoot, application string, toolDirectories []string) bool {
	if !cleanAbsoluteGatePath(application) || pathWithinRepository(repositoryRoot, application) {
		return false
	}
	info, err := os.Lstat(application)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(application)
	if err != nil || !filepath.IsAbs(resolved) || !sameCanonicalPath(application, resolved) ||
		pathWithinRepository(repositoryRoot, resolved) {
		return false
	}
	for _, directory := range toolDirectories {
		if pathWithinRepository(directory, resolved) {
			return true
		}
	}
	return false
}

func cleanAbsoluteGatePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\x00\r\n")
}

func nilGateDependency(value any) bool {
	current := reflect.ValueOf(value)
	switch current.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return current.IsNil()
	default:
		return false
	}
}

func substituteGateArgv(argv []string, testedRevision string) []string {
	result := append([]string(nil), argv...)
	for index, token := range result {
		if token == "{testedRevision}" {
			result[index] = testedRevision
		}
	}
	return result
}

func gateEnvironment(configuration gateRunEnvironment, network NetworkMode) []string {
	environment := []string{
		"PATH=" + configuration.ToolPath,
		"HOME=" + configuration.HomeDir,
		"USERPROFILE=" + configuration.HomeDir,
		"XDG_CONFIG_HOME=" + configuration.HomeDir,
		"TMPDIR=" + configuration.TempDir,
		"TMP=" + configuration.TempDir,
		"TEMP=" + configuration.TempDir,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"GOWORK=off",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOFLAGS=",
		"GOCACHEPROG=",
		"GOTELEMETRY=off",
		"GOCACHE=" + configuration.GoCacheDir,
		"GOMODCACHE=" + configuration.GoModCacheDir,
		"GOTMPDIR=" + configuration.TempDir,
		"GOAUTH=off",
		"GONOPROXY=none",
		"GOPRIVATE=",
		"GONOSUMDB=",
		"GOINSECURE=",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=" + os.DevNull,
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_LITERAL_PATHSPECS=1",
		"GIT_PAGER=",
		"PAGER=",
		"GCM_INTERACTIVE=Never",
	}
	if configuration.SystemRoot != "" {
		environment = append(environment,
			"SYSTEMROOT="+configuration.SystemRoot,
			"WINDIR="+configuration.SystemRoot,
		)
	}

	switch network {
	case NetworkNone:
		environment = append(environment, "GOPROXY=off", "GOSUMDB=off", "GOVULNDB=off")
	case NetworkGoModules:
		environment = append(environment,
			"GOPROXY="+configuration.GoProxy,
			"GOSUMDB="+configuration.GoSumDB,
			"GOVULNDB=off",
		)
	case NetworkVulnerabilityDatabase:
		environment = append(environment,
			"GOPROXY=off",
			"GOSUMDB=off",
			"GOVULNDB="+configuration.VulnerabilityDatabaseURL,
		)
	case NetworkGoModulesAndVulnerabilityDatabase:
		environment = append(environment,
			"GOPROXY="+configuration.GoProxy,
			"GOSUMDB="+configuration.GoSumDB,
			"GOVULNDB="+configuration.VulnerabilityDatabaseURL,
		)
	}
	return environment
}

func evaluateGateResult(
	specification GateSpec,
	request gateRunRequest,
	result gateProcessResult,
	executionErr error,
	stdout []byte,
	outputOverflow bool,
) (QualificationStatus, *int64, error) {
	if result.CleanupFailed {
		return StatusFail, nil, errGateCleanupFailed
	}
	if outputOverflow {
		return StatusFail, nil, errGateOutputLimit
	}
	if result.TimedOut || result.Cancelled {
		return StatusFail, nil, errGateFailed
	}
	if result.Blocked {
		if result.ExitCode != nil {
			return StatusFail, nil, errGateFailed
		}
		return StatusBlocked, nil, errGateBlocked
	}

	exitCode := validGateExitCode(result.ExitCode)
	if result.ExitCode == nil || exitCode == nil {
		return StatusFail, nil, errGateFailed
	}
	if executionErr != nil || *exitCode != 0 {
		return StatusFail, exitCode, errGateFailed
	}
	if result.SourceChanged || !gateSemanticPredicate(specification.ID, request, stdout) {
		return StatusFail, exitCode, errGateFailed
	}
	return StatusPass, exitCode, nil
}

func gateSemanticPredicate(id string, request gateRunRequest, stdout []byte) bool {
	switch id {
	case "RP-M0-QUAL-GO-VERSION":
		want := "go version go1.26.5 " + request.GOOS + "/" + request.GOARCH + "\n"
		return string(stdout) == want
	case "RP-M0-QUAL-TIDY-DIFF", "RP-M0-QUAL-FORMAT":
		return len(stdout) == 0
	default:
		return true
	}
}

func validGateExitCode(value *int64) *int64 {
	if value == nil || *value < receiptMinInt32 || *value > receiptMaxInt32 {
		return nil
	}
	result := *value
	return &result
}

func boundedGateLog(value []byte) ([]byte, bool) {
	if int64(len(value)) > maximumGateOutputBytes {
		return append([]byte(nil), value[:maximumGateOutputBytes]...), true
	}
	return append([]byte(nil), value...), false
}

func gateTimestamp(value time.Time) *string {
	formatted := value.UTC().Truncate(time.Second).Format(time.RFC3339)
	return &formatted
}
