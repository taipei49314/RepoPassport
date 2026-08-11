package sourcequalification

// Production contract under test. The runner stays package-private because it
// executes source bytes and is only used by the private RFC-0002 controller.
//
//	type gateRunRequest struct {
//		Lane Lane
//		TestedRevision string
//		RepositoryRoot string
//		GOOS string
//		GOARCH string
//		Applications map[string]string // logical name -> trusted absolute path
//		Environment gateRunEnvironment
//	}
//	type gateRunEnvironment struct {
//		ToolPath string
//		HomeDir string
//		GoCacheDir string
//		GoModCacheDir string
//		TempDir string
//		GoProxy string
//		GoSumDB string
//		VulnerabilityDatabaseURL string
//		SystemRoot string
//	}
//	type gateProcessRequest struct {
//		Application string
//		Args []string
//		Dir string
//		Env []string
//		Timeout time.Duration
//		StdoutLimit int64
//		StderrLimit int64
//	}
//	type gateProcessResult struct {
//		ExitCode *int64
//		Stdout []byte
//		Stderr []byte
//		Blocked bool
//		TimedOut bool
//		Cancelled bool
//		StdoutOverflow bool
//		StderrOverflow bool
//		CleanupFailed bool
//		SourceChanged bool
//	}
//	type gateExecutor interface {
//		BindApplications(context.Context, map[string]string) (gateApplicationBinding, error)
//		Execute(context.Context, gateProcessRequest) (gateProcessResult, error)
//	}
//	type gateApplicationBinding interface {
//		Verify(context.Context) error
//		Release() error
//	}
//	type gatePrivateLogSink interface {
//		WriteGateLog(id string, stdout, stderr []byte) error
//	}
//	func runRequiredGates(context.Context, gateRunRequest, gateExecutor, gatePrivateLogSink) ([]receiptGate, error)

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const gateTestOutputLimit int64 = 4 << 20

func TestRunRequiredGatesUsesExactArgvEnvironmentAndPrivateApplications(t *testing.T) {
	fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
	for _, name := range []string{
		"GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0",
		"GIT_CONFIG_VALUE_0", "GIT_ASKPASS", "GIT_SSH_COMMAND", "SSH_AUTH_SOCK",
		"GOFLAGS", "GOWORK", "GOENV", "GOTOOLCHAIN", "GOCACHEPROG", "GOPROXY",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	} {
		t.Setenv(name, "ambient-secret-"+name)
	}

	executor := &gateTestExecutor{steps: passingGateSteps(fixture.request)}
	logs := &gateTestLogSink{}
	records, err := runRequiredGates(context.Background(), fixture.request, executor, logs)
	if err != nil {
		t.Fatalf("runRequiredGates: %v", err)
	}

	registry := RequiredGates(fixture.request.Lane)
	if len(records) != len(registry) || len(executor.requests) != len(registry) {
		t.Fatalf("records/requests = %d/%d, want %d/%d", len(records), len(executor.requests), len(registry), len(registry))
	}
	for index, specification := range registry {
		wantArgv := gateTestArgv(specification, fixture.request.TestedRevision)
		requireGateRecord(t, records[index], specification, wantArgv, StatusPass, gateTestInt64(0))

		request := executor.requests[index]
		if request.Application != fixture.request.Applications[specification.Argv[0]] {
			t.Fatalf("gate %s application = %q, want trusted absolute application", specification.ID, request.Application)
		}
		if !reflect.DeepEqual(request.Args, wantArgv[1:]) {
			t.Fatalf("gate %s args = %#v, want %#v", specification.ID, request.Args, wantArgv[1:])
		}
		if request.Dir != fixture.request.RepositoryRoot {
			t.Fatalf("gate %s dir = %q, want exact repository root", specification.ID, request.Dir)
		}
		if request.Timeout != time.Duration(specification.TimeoutSeconds)*time.Second {
			t.Fatalf("gate %s timeout = %s, want %ds", specification.ID, request.Timeout, specification.TimeoutSeconds)
		}
		if request.StdoutLimit != gateTestOutputLimit || request.StderrLimit != gateTestOutputLimit {
			t.Fatalf("gate %s output limits = %d/%d, want independent 4 MiB limits", specification.ID, request.StdoutLimit, request.StderrLimit)
		}
		requireGateEnvironment(t, request.Env, fixture.request.Environment, specification.Network)
	}

	if got := RequiredGates(LaneWindowsAMD64)[9].Argv[len(RequiredGates(LaneWindowsAMD64)[9].Argv)-1]; got != "{testedRevision}" {
		t.Fatalf("registry token was mutated to %q", got)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal gate records: %v", err)
	}
	for _, private := range []string{fixture.privateRoot, fixture.request.Applications["go"], fixture.request.Environment.GoProxy} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatalf("public gate record disclosed private value %q", private)
		}
	}
}

func TestRunRequiredGatesRequiresLaneLifetimeApplicationBinding(t *testing.T) {
	const privateFailure = "private immutable-tool failure C:\\runner\\tool.exe"
	tests := []struct {
		name       string
		binding    *gateTestApplicationBinding
		bindErr    error
		wantStatus QualificationStatus
		wantCode   string
		wantCalls  int
	}{
		{
			name:       "binding unavailable blocks before execution",
			bindErr:    errors.New(privateFailure),
			wantStatus: StatusBlocked,
			wantCode:   "SOURCE_QUAL_GATE_BLOCKED",
		},
		{
			name: "application mutation fails before replacement can execute",
			binding: &gateTestApplicationBinding{verifyErrors: []error{
				nil,
				errors.New(privateFailure),
			}},
			wantStatus: StatusFail,
			wantCode:   "SOURCE_QUAL_GATE_FAILED",
			wantCalls:  1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
			executor := &gateTestExecutor{
				steps:   passingGateSteps(fixture.request),
				binding: test.binding,
				bindErr: test.bindErr,
			}
			records, err := runRequiredGates(
				context.Background(),
				fixture.request,
				executor,
				&gateTestLogSink{},
			)
			requireGateRunError(t, err, test.wantCode)
			if len(records) == 0 || records[0].Status != test.wantStatus || records[0].ExitCode != nil {
				t.Fatalf("binding failure first record = %#v, want %s with null exit", records, test.wantStatus)
			}
			requireLaterNotRun(t, records, 0)
			if len(executor.requests) != test.wantCalls {
				t.Fatalf("binding failure invoked %d applications, want %d", len(executor.requests), test.wantCalls)
			}
			if len(executor.boundApplications) != 1 || !reflect.DeepEqual(executor.boundApplications[0], fixture.request.Applications) {
				t.Fatalf("bound applications = %#v, want exact private map", executor.boundApplications)
			}
			if strings.Contains(err.Error(), privateFailure) {
				t.Fatalf("binding failure disclosed private diagnostic: %v", err)
			}
		})
	}
}

func TestRunRequiredGatesTreatsApplicationBindingReleaseFailureAsCleanupFailure(t *testing.T) {
	fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
	executor := &gateTestExecutor{
		steps: passingGateSteps(fixture.request),
		binding: &gateTestApplicationBinding{
			releaseErr: errors.New("private release failure C:\\runner\\tool.exe"),
		},
	}
	records, err := runRequiredGates(context.Background(), fixture.request, executor, &gateTestLogSink{})
	requireGateRunError(t, err, "SOURCE_QUAL_CLEANUP_FAILED")
	last := len(records) - 1
	if last < 0 || records[last].Status != StatusFail || records[last].ExitCode != nil {
		t.Fatalf("release failure final record = %#v, want FAIL with null exit", records)
	}
	if executor.binding.releaseCalls != 1 || strings.Contains(err.Error(), "private release failure") {
		t.Fatalf("release failure calls/error = %d/%v", executor.binding.releaseCalls, err)
	}
}

func TestRunRequiredGatesEnforcesSemanticStdoutPredicates(t *testing.T) {
	tests := []struct {
		name   string
		gateID string
		mutate func(*gateProcessResult)
	}{
		{"Go version requires LF", "RP-M0-QUAL-GO-VERSION", func(result *gateProcessResult) { result.Stdout = []byte("go version go1.26.5 windows/amd64\r\n") }},
		{"Go version rejects extra line", "RP-M0-QUAL-GO-VERSION", func(result *gateProcessResult) { result.Stdout = []byte("go version go1.26.5 windows/amd64\nextra\n") }},
		{"Go version binds OS arch", "RP-M0-QUAL-GO-VERSION", func(result *gateProcessResult) { result.Stdout = []byte("go version go1.26.5 linux/amd64\n") }},
		{"Tidy requires empty output", "RP-M0-QUAL-TIDY-DIFF", func(result *gateProcessResult) { result.Stdout = []byte("diff --git a/go.mod b/go.mod\n") }},
		{"Tidy rejects source change", "RP-M0-QUAL-TIDY-DIFF", func(result *gateProcessResult) { result.SourceChanged = true }},
		{"Format requires empty stdout", "RP-M0-QUAL-FORMAT", func(result *gateProcessResult) { result.Stdout = []byte("internal/sourcequalification/gate.go\n") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
			steps := passingGateSteps(fixture.request)
			index := gateTestIndex(fixture.request.Lane, test.gateID)
			test.mutate(&steps[index].result)
			executor := &gateTestExecutor{steps: steps}
			records, err := runRequiredGates(context.Background(), fixture.request, executor, &gateTestLogSink{})
			requireGateRunError(t, err, "SOURCE_QUAL_GATE_FAILED")
			if records[index].Status != StatusFail || records[index].ExitCode == nil || *records[index].ExitCode != 0 {
				t.Fatalf("semantic mismatch record = %#v, want FAIL with exit 0", records[index])
			}
			requireLaterNotRun(t, records, index)
			if len(executor.requests) != index+1 {
				t.Fatalf("executed %d gates after semantic failure at %d", len(executor.requests), index)
			}
		})
	}
}

func TestRunRequiredGatesStopsAfterFirstFailOrBlocked(t *testing.T) {
	tests := []struct {
		name       string
		result     gateProcessResult
		runError   error
		wantStatus QualificationStatus
		wantCode   string
		wantExit   *int64
	}{
		{"FAIL", gateProcessResult{ExitCode: gateTestInt64(23)}, nil, StatusFail, "SOURCE_QUAL_GATE_FAILED", gateTestInt64(23)},
		{"BLOCKED", gateProcessResult{Blocked: true}, errors.New("private prerequisite path C:\\secret\\tool"), StatusBlocked, "SOURCE_QUAL_GATE_BLOCKED", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
			steps := passingGateSteps(fixture.request)
			const failingIndex = 1
			steps[failingIndex] = gateTestStep{result: test.result, err: test.runError}
			executor := &gateTestExecutor{steps: steps}
			records, err := runRequiredGates(context.Background(), fixture.request, executor, &gateTestLogSink{})
			requireGateRunError(t, err, test.wantCode)
			if records[failingIndex].Status != test.wantStatus || !gateTestEqualInt64(records[failingIndex].ExitCode, test.wantExit) {
				t.Fatalf("terminal record = %#v, want status %s exit %#v", records[failingIndex], test.wantStatus, test.wantExit)
			}
			requireLaterNotRun(t, records, failingIndex)
			if len(executor.requests) != failingIndex+1 {
				t.Fatalf("executor received %d requests, want %d", len(executor.requests), failingIndex+1)
			}
		})
	}
}

func TestRunRequiredGatesBoundsOutputAndHandlesCancellation(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*gateProcessResult)
		wantCode   string
		wantStatus QualificationStatus
	}{
		{"stdout over 4 MiB", func(result *gateProcessResult) { result.Stdout = bytes.Repeat([]byte{'x'}, int(gateTestOutputLimit)+1) }, "SOURCE_QUAL_OUTPUT_LIMIT", StatusFail},
		{"reported stderr overflow", func(result *gateProcessResult) { result.StderrOverflow = true }, "SOURCE_QUAL_OUTPUT_LIMIT", StatusFail},
		{"timeout", func(result *gateProcessResult) { result.ExitCode = nil; result.TimedOut = true }, "SOURCE_QUAL_GATE_FAILED", StatusFail},
		{"cancellation after invocation", func(result *gateProcessResult) { result.ExitCode = nil; result.Cancelled = true }, "SOURCE_QUAL_GATE_FAILED", StatusFail},
		{"process tree cleanup", func(result *gateProcessResult) { result.ExitCode = nil; result.CleanupFailed = true }, "SOURCE_QUAL_CLEANUP_FAILED", StatusFail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
			steps := passingGateSteps(fixture.request)
			const failingIndex = 3
			test.mutate(&steps[failingIndex].result)
			records, err := runRequiredGates(context.Background(), fixture.request, &gateTestExecutor{steps: steps}, &gateTestLogSink{})
			requireGateRunError(t, err, test.wantCode)
			if records[failingIndex].Status != test.wantStatus || records[failingIndex].ExitCode != nil {
				t.Fatalf("bounded/cancelled record = %#v, want %s with null exit", records[failingIndex], test.wantStatus)
			}
			requireLaterNotRun(t, records, failingIndex)
		})
	}

	fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
	steps := passingGateSteps(fixture.request)
	steps[3].result.Stdout = bytes.Repeat([]byte{'x'}, int(gateTestOutputLimit))
	steps[3].result.Stderr = bytes.Repeat([]byte{'y'}, int(gateTestOutputLimit))
	records, err := runRequiredGates(context.Background(), fixture.request, &gateTestExecutor{steps: steps}, gateTestDiscardLogSink{})
	if err != nil || records[3].Status != StatusPass {
		t.Fatalf("independent exact 4 MiB bounds rejected: record=%#v err=%v", records[3], err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	executor := &gateTestExecutor{steps: passingGateSteps(fixture.request)}
	records, err = runRequiredGates(cancelled, fixture.request, executor, &gateTestLogSink{})
	requireGateRunError(t, err, "SOURCE_QUAL_GATE_NOT_RUN")
	if len(executor.requests) != 0 {
		t.Fatalf("pre-cancelled run invoked %d gates", len(executor.requests))
	}
	for index, record := range records {
		if record.Status != StatusNotRun || record.ExitCode != nil || record.StartedAt != nil || record.FinishedAt != nil {
			t.Fatalf("pre-cancelled gate %d = %#v, want pristine NOT_RUN", index, record)
		}
	}
}

func TestRunRequiredGatesKeepsRawDiagnosticsPrivate(t *testing.T) {
	fixture := newGateRunnerFixture(t, LaneWindowsAMD64)
	steps := passingGateSteps(fixture.request)
	const (
		privateStdout = "private-stdout-token-39d7"
		privateStderr = "private-stderr-token-a428"
		privateError  = "private executor error C:\\runner\\_temp\\credential.txt"
	)
	steps[1] = gateTestStep{
		result: gateProcessResult{ExitCode: gateTestInt64(7), Stdout: []byte(privateStdout), Stderr: []byte(privateStderr)},
		err:    errors.New(privateError),
	}
	logs := &gateTestLogSink{}
	records, err := runRequiredGates(context.Background(), fixture.request, &gateTestExecutor{steps: steps}, logs)
	requireGateRunError(t, err, "SOURCE_QUAL_GATE_FAILED")
	if !logs.contains(privateStdout) || !logs.contains(privateStderr) {
		t.Fatalf("private log sink did not receive both raw streams: %#v", logs.entries)
	}
	public, marshalErr := json.Marshal(records)
	if marshalErr != nil {
		t.Fatalf("marshal records: %v", marshalErr)
	}
	for _, forbidden := range []string{privateStdout, privateStderr, privateError, fixture.privateRoot} {
		if strings.Contains(err.Error(), forbidden) || bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("public result disclosed private diagnostic %q: err=%q JSON=%s", forbidden, err, public)
		}
	}
}

type gateRunnerFixture struct {
	request     gateRunRequest
	privateRoot string
}

func newGateRunnerFixture(t *testing.T, lane Lane) gateRunnerFixture {
	t.Helper()
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	privateRoot := filepath.Join(root, "private")
	tools := filepath.Join(privateRoot, "tools")
	home := filepath.Join(privateRoot, "home")
	cache := filepath.Join(privateRoot, "cache")
	moduleCache := filepath.Join(privateRoot, "modules")
	temporary := filepath.Join(privateRoot, "temporary")
	for _, directory := range []string{repository, tools, home, cache, moduleCache, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create gate fixture directory: %v", err)
		}
	}
	applications := make(map[string]string)
	for _, name := range []string{"go", "gofmt", "pwsh", "repopass-source-qualify"} {
		path := filepath.Join(tools, name+".fixed")
		if err := os.WriteFile(path, []byte("test application\n"), 0o700); err != nil {
			t.Fatalf("create application fixture: %v", err)
		}
		applications[name] = path
	}
	goos := "windows"
	if lane == LaneLinuxAMD64 {
		goos = "linux"
	}
	return gateRunnerFixture{
		privateRoot: privateRoot,
		request: gateRunRequest{
			Lane:           lane,
			TestedRevision: strings.Repeat("a", 40),
			RepositoryRoot: repository,
			GOOS:           goos,
			GOARCH:         "amd64",
			Applications:   applications,
			Environment: gateRunEnvironment{
				ToolPath:                 tools,
				HomeDir:                  home,
				GoCacheDir:               cache,
				GoModCacheDir:            moduleCache,
				TempDir:                  temporary,
				GoProxy:                  "https://proxy.golang.org",
				GoSumDB:                  "sum.golang.org",
				VulnerabilityDatabaseURL: "https://vuln.go.dev",
			},
		},
	}
}

type gateTestStep struct {
	result gateProcessResult
	err    error
}

type gateTestExecutor struct {
	steps             []gateTestStep
	requests          []gateProcessRequest
	binding           *gateTestApplicationBinding
	bindErr           error
	boundApplications []map[string]string
}

func (executor *gateTestExecutor) BindApplications(
	_ context.Context,
	applications map[string]string,
) (gateApplicationBinding, error) {
	cloned := make(map[string]string, len(applications))
	for name, path := range applications {
		cloned[name] = path
	}
	executor.boundApplications = append(executor.boundApplications, cloned)
	if executor.bindErr != nil {
		return nil, executor.bindErr
	}
	if executor.binding == nil {
		executor.binding = &gateTestApplicationBinding{}
	}
	return executor.binding, nil
}

func (executor *gateTestExecutor) Execute(ctx context.Context, request gateProcessRequest) (gateProcessResult, error) {
	request.Args = append([]string(nil), request.Args...)
	request.Env = append([]string(nil), request.Env...)
	executor.requests = append(executor.requests, request)
	index := len(executor.requests) - 1
	if index >= len(executor.steps) {
		return gateProcessResult{}, errors.New("fake executor received an unexpected request")
	}
	step := executor.steps[index]
	step.result.Stdout = append([]byte(nil), step.result.Stdout...)
	step.result.Stderr = append([]byte(nil), step.result.Stderr...)
	return step.result, step.err
}

type gateTestApplicationBinding struct {
	verifyErrors []error
	verifyCalls  int
	releaseErr   error
	releaseCalls int
}

func (binding *gateTestApplicationBinding) Verify(context.Context) error {
	index := binding.verifyCalls
	binding.verifyCalls++
	if index < len(binding.verifyErrors) {
		return binding.verifyErrors[index]
	}
	return nil
}

func (binding *gateTestApplicationBinding) Release() error {
	binding.releaseCalls++
	return binding.releaseErr
}

type gateTestLogEntry struct {
	id     string
	stdout []byte
	stderr []byte
}

type gateTestLogSink struct{ entries []gateTestLogEntry }

func (sink *gateTestLogSink) WriteGateLog(id string, stdout, stderr []byte) error {
	sink.entries = append(sink.entries, gateTestLogEntry{id: id, stdout: append([]byte(nil), stdout...), stderr: append([]byte(nil), stderr...)})
	return nil
}

func (sink *gateTestLogSink) contains(value string) bool {
	for _, entry := range sink.entries {
		if bytes.Contains(entry.stdout, []byte(value)) || bytes.Contains(entry.stderr, []byte(value)) {
			return true
		}
	}
	return false
}

type gateTestDiscardLogSink struct{}

func (gateTestDiscardLogSink) WriteGateLog(string, []byte, []byte) error { return nil }

func passingGateSteps(request gateRunRequest) []gateTestStep {
	registry := RequiredGates(request.Lane)
	steps := make([]gateTestStep, len(registry))
	for index, specification := range registry {
		steps[index].result.ExitCode = gateTestInt64(0)
		if specification.ID == "RP-M0-QUAL-GO-VERSION" {
			steps[index].result.Stdout = []byte("go version go1.26.5 " + request.GOOS + "/" + request.GOARCH + "\n")
		}
	}
	return steps
}

func gateTestArgv(specification GateSpec, testedRevision string) []string {
	result := append([]string(nil), specification.Argv...)
	for index, token := range result {
		if token == "{testedRevision}" {
			result[index] = testedRevision
		}
	}
	return result
}

func gateTestIndex(lane Lane, id string) int {
	for index, specification := range RequiredGates(lane) {
		if specification.ID == id {
			return index
		}
	}
	panic("gate test refers to an unknown gate: " + id)
}

func requireGateRecord(t *testing.T, record receiptGate, specification GateSpec, argv []string, status QualificationStatus, exitCode *int64) {
	t.Helper()
	if record.ID != specification.ID || !reflect.DeepEqual(record.Argv, argv) || record.Attempt != 1 ||
		record.Network != specification.Network || record.TimeoutSeconds != int64(specification.TimeoutSeconds) ||
		record.Status != status || !gateTestEqualInt64(record.ExitCode, exitCode) {
		t.Fatalf("gate record = %#v, want exact registry record for %#v with %s", record, specification, status)
	}
	if status == StatusNotRun {
		if record.StartedAt != nil || record.FinishedAt != nil {
			t.Fatalf("NOT_RUN record has timestamps: %#v", record)
		}
		return
	}
	if record.StartedAt == nil || record.FinishedAt == nil {
		t.Fatalf("evaluated record lacks timestamps: %#v", record)
	}
	for _, value := range []string{*record.StartedAt, *record.FinishedAt} {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || parsed.Format(time.RFC3339) != value || parsed.Location() != time.UTC {
			t.Fatalf("gate timestamp %q is not whole-second UTC RFC3339", value)
		}
	}
}

func requireLaterNotRun(t *testing.T, records []receiptGate, terminalIndex int) {
	t.Helper()
	registry := RequiredGates(LaneWindowsAMD64)
	for index := terminalIndex + 1; index < len(records); index++ {
		requireGateRecord(t, records[index], registry[index], gateTestArgv(registry[index], strings.Repeat("a", 40)), StatusNotRun, nil)
	}
}

func requireGateRunError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("run error = %v, want fixed redacted code %q", err, want)
	}
}

func requireGateEnvironment(t *testing.T, environment []string, configuration gateRunEnvironment, network NetworkMode) {
	t.Helper()
	got := make(map[string]string, len(environment))
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		name = strings.ToUpper(name)
		if !ok || name == "" {
			t.Fatalf("invalid environment entry %q", item)
		}
		if _, duplicate := got[name]; duplicate {
			t.Fatalf("duplicate environment name %q", name)
		}
		got[name] = value
	}
	want := map[string]string{
		"PATH": configuration.ToolPath, "HOME": configuration.HomeDir, "USERPROFILE": configuration.HomeDir,
		"XDG_CONFIG_HOME": configuration.HomeDir, "TMPDIR": configuration.TempDir, "TMP": configuration.TempDir, "TEMP": configuration.TempDir,
		"LANG": "C", "LC_ALL": "C", "TZ": "UTC",
		"GOWORK": "off", "GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOCACHEPROG": "", "GOTELEMETRY": "off",
		"GOCACHE": configuration.GoCacheDir, "GOMODCACHE": configuration.GoModCacheDir, "GOTMPDIR": configuration.TempDir,
		"GOAUTH": "off", "GONOPROXY": "none", "GOPRIVATE": "", "GONOSUMDB": "", "GOINSECURE": "",
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.DevNull, "GIT_CONFIG_GLOBAL": os.DevNull, "GIT_ATTR_NOSYSTEM": "1",
		"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_LITERAL_PATHSPECS": "1",
		"GIT_PAGER": "", "PAGER": "", "GCM_INTERACTIVE": "Never",
	}
	switch network {
	case NetworkNone:
		want["GOPROXY"], want["GOSUMDB"], want["GOVULNDB"] = "off", "off", "off"
	case NetworkGoModules:
		want["GOPROXY"], want["GOSUMDB"], want["GOVULNDB"] = configuration.GoProxy, configuration.GoSumDB, "off"
	case NetworkVulnerabilityDatabase:
		want["GOPROXY"], want["GOSUMDB"], want["GOVULNDB"] = "off", "off", configuration.VulnerabilityDatabaseURL
	case NetworkGoModulesAndVulnerabilityDatabase:
		want["GOPROXY"], want["GOSUMDB"], want["GOVULNDB"] = configuration.GoProxy, configuration.GoSumDB, configuration.VulnerabilityDatabaseURL
	default:
		t.Fatalf("unknown network mode %q", network)
	}
	if configuration.SystemRoot != "" {
		want["SYSTEMROOT"] = configuration.SystemRoot
		want["WINDIR"] = configuration.SystemRoot
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gate environment = %#v, want exact allowlist %#v", got, want)
	}
}

func gateTestInt64(value int64) *int64 { return &value }

func gateTestEqualInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
