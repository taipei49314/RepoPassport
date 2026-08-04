package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/storage"
)

type testEnvelope struct {
	SchemaVersion string          `json:"schemaVersion"`
	Command       string          `json:"command"`
	Status        string          `json:"status"`
	Data          json.RawMessage `json:"data"`
	Error         *domain.Error   `json:"error"`
}

type verifyEnvelopeData struct {
	Verification      domain.VerificationResult `json:"verification"`
	ArtifactDirectory string                    `json:"artifactDirectory"`
}

func TestDoctorUsesInjectedProbeAll(t *testing.T) {
	t.Parallel()

	want := domain.RunnerFeatures{
		Backend:                    "test-runner",
		Available:                  true,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 "linux",
		Rootless:                   "yes",
		NetworkDeny:                true,
		NetworkAttemptObservation:  "best-effort",
		ProcessExecObservation:     "full",
		FilesystemWriteObservation: "full",
		FilesystemReadObservation:  "unavailable",
		PortObservation:            "full",
		ResourceUsage:              "full",
		EngineVersion:              "test-1.0",
	}
	probeCalls := 0
	var stdout, stderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				probeCalls++
				return []domain.RunnerFeatures{want}, nil
			},
		},
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if exitCode := app.Run(context.Background(), []string{"--json", "doctor"}); exitCode != 0 {
		t.Fatalf("doctor exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if probeCalls != 1 {
		t.Fatalf("ProbeAll calls = %d, want 1", probeCalls)
	}

	response := decodeEnvelope(t, stdout.Bytes())
	if response.Command != "doctor" || response.Status != "ok" {
		t.Fatalf("doctor envelope = command %q status %q", response.Command, response.Status)
	}
	var data struct {
		Runners []domain.RunnerFeatures `json:"runners"`
	}
	decodeJSON(t, response.Data, &data)
	if len(data.Runners) != 1 {
		t.Fatalf("doctor runners = %d, want 1", len(data.Runners))
	}
	if got := data.Runners[0]; got != want {
		t.Fatalf("doctor runner = %#v, want %#v", got, want)
	}
}

func TestDoctorWithoutProbeReportsUnavailableCoverage(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	app := App{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if exitCode := app.Run(context.Background(), []string{"--json", "doctor"}); exitCode != 0 {
		t.Fatalf("doctor exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	response := decodeEnvelope(t, stdout.Bytes())
	var data struct {
		Runners []domain.RunnerFeatures `json:"runners"`
	}
	decodeJSON(t, response.Data, &data)
	if len(data.Runners) != 1 {
		t.Fatalf("doctor runners = %d, want 1", len(data.Runners))
	}
	got := data.Runners[0]
	for field, value := range map[string]string{
		"networkAttemptObservation":  got.NetworkAttemptObservation,
		"processExecObservation":     got.ProcessExecObservation,
		"filesystemWriteObservation": got.FilesystemWriteObservation,
		"filesystemReadObservation":  got.FilesystemReadObservation,
		"portObservation":            got.PortObservation,
		"resourceUsage":              got.ResourceUsage,
	} {
		if value != "unavailable" {
			t.Errorf("%s = %q, want unavailable", field, value)
		}
	}
}

func TestVerifyWithoutRunnerWritesAuthoritativeBlockedArtifact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		failOn   string
		wantExit int
	}{
		{name: "default exit remains zero", wantExit: 0},
		{name: "fail on blocked exits three", failOn: "blocked", wantExit: 3},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dataRoot := t.TempDir()
			executeCalled := false
			var stdout, stderr bytes.Buffer
			app := App{
				Deps: Dependencies{
					ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
						return []domain.RunnerFeatures{{
							Backend:      "docker",
							Available:    false,
							ControllerOS: runtime.GOOS,
							WorkloadOS:   "linux",
							Rootless:     "unknown",
							Reason:       "fake runner is unavailable",
						}}, nil
					},
					Execute: func(context.Context, domain.ResolvedPlan, string, string, string) (RunnerOutcome, error) {
						executeCalled = true
						return RunnerOutcome{}, errors.New("Execute must not run without an available runner")
					},
				},
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			}
			args := []string{
				"--json",
				"--data-dir", dataRoot,
				"verify",
				"--manifest", healthyNodeManifest(t),
			}
			if test.failOn != "" {
				args = append(args, "--fail-on", test.failOn)
			}

			if exitCode := app.Run(context.Background(), args); exitCode != test.wantExit {
				t.Fatalf("verify exit code = %d, want %d; stderr: %s", exitCode, test.wantExit, stderr.String())
			}
			if executeCalled {
				t.Fatal("Execute was called despite an unavailable runner")
			}

			response := decodeEnvelope(t, stdout.Bytes())
			if response.Command != "verify" || response.Status != "ok" {
				t.Fatalf("verify envelope = command %q status %q", response.Command, response.Status)
			}
			var data verifyEnvelopeData
			decodeJSON(t, response.Data, &data)
			assertBlockedResult(t, data.Verification)

			if data.Verification.RunID == data.Verification.VerificationID {
				t.Fatalf("runId and verificationId must be distinct: %q", data.Verification.RunID)
			}
			if !strings.HasPrefix(data.Verification.RunID, "run_") {
				t.Fatalf("runId = %q, want run_ prefix", data.Verification.RunID)
			}
			if !strings.HasPrefix(data.Verification.VerificationID, "vrf_") {
				t.Fatalf("verificationId = %q, want vrf_ prefix", data.Verification.VerificationID)
			}

			wantDirectory := filepath.Join(dataRoot, "runs", data.Verification.RunID)
			if got, err := filepath.Abs(data.ArtifactDirectory); err != nil {
				t.Fatalf("resolve artifact directory: %v", err)
			} else if want, err := filepath.Abs(wantDirectory); err != nil {
				t.Fatalf("resolve expected artifact directory: %v", err)
			} else if filepath.Clean(got) != filepath.Clean(want) {
				t.Fatalf("artifact directory = %q, want %q", got, want)
			}
			if _, err := os.Stat(filepath.Join(data.ArtifactDirectory, "verification.json")); err != nil {
				t.Fatalf("authoritative verification artifact: %v", err)
			}

			stored, err := (storage.RunStore{Root: filepath.Join(dataRoot, "runs")}).Read(data.Verification.RunID)
			if err != nil {
				t.Fatalf("read authoritative verification artifact: %v", err)
			}
			assertBlockedResult(t, stored)
			if stored.VerificationID != data.Verification.VerificationID {
				t.Fatalf("stored verificationId = %q, response verificationId = %q", stored.VerificationID, data.Verification.VerificationID)
			}
		})
	}
}

func TestVerifyPreservesPartialExecuteOutcomeOnError(t *testing.T) {
	t.Parallel()

	dataRoot := t.TempDir()
	executeCalls := 0
	observedAt := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	var stdout, stderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				return []domain.RunnerFeatures{fullyObservedRunner()}, nil
			},
			Execute: func(context.Context, domain.ResolvedPlan, string, string, string) (RunnerOutcome, error) {
				executeCalls++
				return RunnerOutcome{
					Runner: fullyObservedRunner(),
					Assertions: []domain.AssertionResult{{
						ID:           "partial-assertion",
						Type:         "exit-code",
						Required:     true,
						Expected:     0,
						Actual:       0,
						Status:       "pass",
						EvidenceRefs: []string{"obs-partial"},
					}},
					Observations: []domain.ObservationEvent{{
						SchemaVersion: "1",
						Timestamp:     observedAt,
						Phase:         domain.PhaseExercise,
						Actor:         "fake-runner",
						Operation:     "process-exec",
						Resource:      "node",
						Result:        "observed",
						Observer:      "process-exec",
						Coverage:      "full",
						Confidence:    "high",
					}},
				}, errors.New("fake attach failed after partial evidence")
			},
		},
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	exitCode := app.Run(context.Background(), []string{
		"--json",
		"--data-dir", dataRoot,
		"verify",
		"--manifest", healthyNodeManifest(t),
	})
	if exitCode != 0 {
		t.Fatalf("verify exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if executeCalls != 1 {
		t.Fatalf("Execute calls = %d, want 1", executeCalls)
	}

	response := decodeEnvelope(t, stdout.Bytes())
	var data verifyEnvelopeData
	decodeJSON(t, response.Data, &data)
	if len(data.Verification.Assertions) != 1 {
		t.Fatalf("response assertions = %d, want 1", len(data.Verification.Assertions))
	}
	if len(data.Verification.Observations) != 1 {
		t.Fatalf("response observations = %d, want 1", len(data.Verification.Observations))
	}
	assertPartialEvidence(t, data.Verification)

	stored, err := (storage.RunStore{Root: filepath.Join(dataRoot, "runs")}).Read(data.Verification.RunID)
	if err != nil {
		t.Fatalf("read authoritative verification artifact: %v", err)
	}
	assertPartialEvidence(t, stored)
	if !hasErrorCode(stored.Errors, domain.CodeSandboxStartFailed) {
		t.Fatalf("stored errors do not include %s: %v", domain.CodeSandboxStartFailed, stored.Errors)
	}
}

func TestVerifyRejectsUnknownFailOnWithUsageExit(t *testing.T) {
	t.Parallel()

	probeCalled := false
	var stdout, stderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				probeCalled = true
				return nil, nil
			},
		},
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if exitCode := app.Run(context.Background(), []string{
		"--json", "verify", "--fail-on", "definitely-unknown",
	}); exitCode != 2 {
		t.Fatalf("verify exit code = %d, want 2; stderr: %s", exitCode, stderr.String())
	}
	if probeCalled {
		t.Fatal("ProbeAll was called before invalid --fail-on was rejected")
	}

	response := decodeEnvelope(t, stdout.Bytes())
	if response.Command != "verify" || response.Status != "error" {
		t.Fatalf("verify envelope = command %q status %q", response.Command, response.Status)
	}
	if response.Error == nil {
		t.Fatal("verify error envelope has no structured error")
	}
	if response.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("verify error code = %q, want %q", response.Error.Code, domain.CodeManifestInvalid)
	}
	if got := response.Error.Details["value"]; got != "definitely-unknown" {
		t.Fatalf("unknown fail-on detail = %#v, want %q", got, "definitely-unknown")
	}
}

func TestReportRejectsRepositoryLocalAuthoritativeRoot(t *testing.T) {
	t.Parallel()

	manifestPath := healthyNodeManifest(t)
	dataRoot := filepath.Join(filepath.Dir(manifestPath), ".repopass")
	var stdout, stderr bytes.Buffer
	app := App{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), []string{
		"--json",
		"--data-dir", dataRoot,
		"report",
		"--run", "run_untrusted",
		"--format", "json",
	})
	if exitCode != 7 {
		t.Fatalf("report exit code = %d, want 7; stdout: %s; stderr: %s", exitCode, stdout.String(), stderr.String())
	}
	response := decodeEnvelope(t, stdout.Bytes())
	if response.Error == nil || response.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("report error = %#v, want %s", response.Error, domain.CodeEvidenceDigestMismatch)
	}
}

func TestVerifyRejectsSymlinkedControllerDataRoot(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	realRoot := filepath.Join(base, "real-data")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatalf("create real data root: %v", err)
	}
	linkedRoot := filepath.Join(base, "linked-data")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	var stdout, stderr bytes.Buffer
	app := App{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), []string{
		"--json",
		"--data-dir", linkedRoot,
		"verify",
		"--manifest", healthyNodeManifest(t),
	})
	if exitCode != 7 {
		t.Fatalf("verify exit code = %d, want 7; stdout: %s; stderr: %s", exitCode, stdout.String(), stderr.String())
	}
	response := decodeEnvelope(t, stdout.Bytes())
	if response.Error == nil || response.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("verify error = %#v, want %s", response.Error, domain.CodeEvidenceDigestMismatch)
	}
}

func TestAssertionFingerprintIgnoresPerRunMetadata(t *testing.T) {
	first := []domain.AssertionResult{{
		ID:             "process-exited",
		Type:           "exit-code",
		Required:       true,
		Expected:       0,
		Actual:         0,
		Status:         "pass",
		EvidenceRefs:   []string{"step:001"},
		Message:        "first run",
		Repeat:         1,
		DurationMillis: 17,
	}}
	second := []domain.AssertionResult{{
		ID:             "process-exited",
		Type:           "exit-code",
		Required:       true,
		Expected:       0,
		Actual:         0,
		Status:         "passed",
		EvidenceRefs:   []string{"step:999"},
		Message:        "second run",
		Repeat:         2,
		DurationMillis: 983,
	}}
	firstDigest, err := assertionFingerprint(first, domain.CleanupClean)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	secondDigest, err := assertionFingerprint(second, domain.CleanupClean)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("per-run metadata changed semantic fingerprint: %q != %q", firstDigest, secondDigest)
	}

	second[0].Actual = 1
	changedDigest, err := assertionFingerprint(second, domain.CleanupClean)
	if err != nil {
		t.Fatalf("changed fingerprint: %v", err)
	}
	if changedDigest == firstDigest {
		t.Fatal("semantic assertion result did not change fingerprint")
	}
}

func TestAggregateCleanupVerdictIsOrderIndependent(t *testing.T) {
	tests := []struct {
		name  string
		left  domain.CleanupVerdict
		right domain.CleanupVerdict
		want  domain.CleanupVerdict
	}{
		{
			name:  "clean and allowed",
			left:  domain.CleanupClean,
			right: domain.CleanupAllowedResidue,
			want:  domain.CleanupAllowedResidue,
		},
		{
			name:  "allowed and not tested",
			left:  domain.CleanupAllowedResidue,
			right: domain.CleanupNotTested,
			want:  domain.CleanupNotTested,
		},
		{
			name:  "clean and undeclared",
			left:  domain.CleanupClean,
			right: domain.CleanupUndeclaredResidue,
			want:  domain.CleanupUndeclaredResidue,
		},
		{
			name:  "undeclared and not tested",
			left:  domain.CleanupUndeclaredResidue,
			right: domain.CleanupNotTested,
			want:  domain.CleanupUndeclaredResidue,
		},
		{
			name:  "unknown is not tested",
			left:  domain.CleanupClean,
			right: domain.CleanupVerdict("future-value"),
			want:  domain.CleanupNotTested,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := aggregateCleanupVerdict(
				test.left,
				test.right,
			); got != test.want {
				t.Fatalf("forward aggregate = %q, want %q", got, test.want)
			}
			if got := aggregateCleanupVerdict(
				test.right,
				test.left,
			); got != test.want {
				t.Fatalf("reverse aggregate = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAssertionFingerprintBindsCleanupVerdict(t *testing.T) {
	assertions := []domain.AssertionResult{{
		ID:       "process-exited",
		Type:     "exit-code",
		Required: true,
		Expected: 0,
		Actual:   0,
		Status:   "passed",
	}}
	clean, err := assertionFingerprint(assertions, domain.CleanupClean)
	if err != nil {
		t.Fatalf("clean fingerprint: %v", err)
	}
	undeclared, err := assertionFingerprint(
		assertions,
		domain.CleanupUndeclaredResidue,
	)
	if err != nil {
		t.Fatalf("undeclared fingerprint: %v", err)
	}
	if clean == undeclared {
		t.Fatal("cleanup verdict did not change semantic fingerprint")
	}
}

func TestAssertionFingerprintStableAcrossSchemaValidPrivateStdoutValues(
	t *testing.T,
) {
	const (
		firstPrivateStdout  = `{"nonce":"first-private-value"}`
		secondPrivateStdout = `{"nonce":"second-private-value"}`
		schemaDigest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	if firstPrivateStdout == secondPrivateStdout {
		t.Fatal("test requires distinct schema-valid stdout instances")
	}
	resultFor := func(privateStdout string) []domain.AssertionResult {
		if privateStdout == "" {
			t.Fatal("test requires a complete private stdout instance")
		}
		return []domain.AssertionResult{{
			ID:       "stdout-schema-valid",
			Type:     "stdout-json-schema",
			Required: true,
			Expected: map[string]any{
				"path":             ".repopass/schemas/cli-stdout.schema.json",
				"digest":           schemaDigest,
				"dialect":          domain.AlphaJSONSchemaDialect,
				"validatorVersion": domain.AlphaJSONValidatorVersion,
			},
			Actual: map[string]any{
				"stdoutComplete":    true,
				"strictJSON":        true,
				"jsonSchemaMatched": true,
			},
			Status: "passed",
		}}
	}

	firstDigest, err := assertionFingerprint(
		resultFor(firstPrivateStdout),
		domain.CleanupClean,
	)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	secondDigest, err := assertionFingerprint(
		resultFor(secondPrivateStdout),
		domain.CleanupClean,
	)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf(
			"private schema-valid stdout changed semantic fingerprint: %q != %q",
			firstDigest,
			secondDigest,
		)
	}
}

func healthyNodeManifest(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(
		"..", "..", "testdata", "fixtures", "healthy", "healthy-node-cli", "repo-passport.yml",
	))
	if err != nil {
		t.Fatalf("resolve healthy-node-cli manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("healthy-node-cli manifest: %v", err)
	}
	return path
}

func fullyObservedRunner() domain.RunnerFeatures {
	return domain.RunnerFeatures{
		Backend:                    "fake",
		Available:                  true,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 "linux",
		Rootless:                   "yes",
		NetworkDeny:                true,
		NetworkAttemptObservation:  "full",
		ProcessExecObservation:     "full",
		FilesystemWriteObservation: "full",
		FilesystemReadObservation:  "full",
		PortObservation:            "full",
		ResourceUsage:              "full",
		EngineVersion:              "fake-1.0",
	}
}

func assertBlockedResult(t *testing.T, result domain.VerificationResult) {
	t.Helper()
	if result.Results.Functional != domain.FunctionalBlocked {
		t.Fatalf("functional verdict = %q, want %q", result.Results.Functional, domain.FunctionalBlocked)
	}
	if result.Results.Overall != domain.OverallBlocked {
		t.Fatalf("overall verdict = %q, want %q", result.Results.Overall, domain.OverallBlocked)
	}
	if result.Results.Reproducibility != domain.ReproducibilityNotTested {
		t.Fatalf("reproducibility verdict = %q, want %q", result.Results.Reproducibility, domain.ReproducibilityNotTested)
	}
	if !hasErrorCode(result.Errors, domain.CodeRunnerUnavailable) {
		t.Fatalf("errors do not include %s: %v", domain.CodeRunnerUnavailable, result.Errors)
	}
}

func TestRemoveWorkRootRestoresReadOnlyTree(t *testing.T) {
	dataRoot := t.TempDir()
	runID := "run_cleanup"
	workRoot := filepath.Join(dataRoot, "work", runID)
	nested := filepath.Join(workRoot, "repeat-01", "run-test", "source-snapshot")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(nested, "fixture.txt")
	if err := os.WriteFile(fixture, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture, 0o400); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		nested,
		filepath.Dir(nested),
		filepath.Dir(filepath.Dir(nested)),
		workRoot,
	} {
		if err := os.Chmod(directory, 0o500); err != nil {
			t.Fatal(err)
		}
	}

	if err := removeWorkRoot(dataRoot, workRoot, runID); err != nil {
		t.Fatalf("removeWorkRoot returned error: %v", err)
	}
	if _, err := os.Lstat(workRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("controller work root still exists: %v", err)
	}
}

func assertPartialEvidence(t *testing.T, result domain.VerificationResult) {
	t.Helper()
	if len(result.Assertions) != 1 {
		t.Fatalf("assertions = %d, want 1", len(result.Assertions))
	}
	assertion := result.Assertions[0]
	if assertion.ID != "partial-assertion" {
		t.Fatalf("assertion ID = %q, want partial-assertion", assertion.ID)
	}
	if assertion.Repeat != 1 {
		t.Fatalf("assertion repeat = %d, want 1", assertion.Repeat)
	}
	if assertion.Status != "passed" {
		t.Fatalf("assertion status = %q, want passed", assertion.Status)
	}
	if len(result.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(result.Observations))
	}
	observation := result.Observations[0]
	if observation.Sequence != 1 {
		t.Fatalf("observation sequence = %d, want 1", observation.Sequence)
	}
	if observation.Operation != "process-exec" || observation.Observer != "process-exec" {
		t.Fatalf("observation was not retained: %#v", observation)
	}
}

func TestMergeResourcesRequiresEveryRepeatToObserveMetric(t *testing.T) {
	left := domain.ResourceSummary{
		DurationMillis:         10,
		LogBytes:               20,
		SandboxPeakMemoryBytes: 100,
		SandboxCPUTimeMillis:   30,
		MaxTasks:               5,
		WritableBytes:          40,
		OutputBytes:            50,
		ObservedFields: []domain.ResourceObservedField{
			domain.ResourceObservedMaxTasks,
			domain.ResourceObservedOutputBytes,
			domain.ResourceObservedSandboxCPUTimeMillis,
			domain.ResourceObservedSandboxPeakMemoryBytes,
			domain.ResourceObservedWritableBytes,
		},
	}
	right := domain.ResourceSummary{
		DurationMillis:         11,
		LogBytes:               21,
		SandboxPeakMemoryBytes: 101,
		SandboxCPUTimeMillis:   31,
		MaxTasks:               6,
		OutputBytes:            51,
		ObservedFields: []domain.ResourceObservedField{
			domain.ResourceObservedMaxTasks,
			domain.ResourceObservedOutputBytes,
			domain.ResourceObservedSandboxCPUTimeMillis,
			domain.ResourceObservedSandboxPeakMemoryBytes,
		},
	}

	merged := mergeResources(left, right)
	if merged.DurationMillis != 21 ||
		merged.LogBytes != 41 ||
		merged.SandboxPeakMemoryBytes != 101 ||
		merged.SandboxCPUTimeMillis != 61 ||
		merged.MaxTasks != 6 ||
		merged.OutputBytes != 101 {
		t.Fatalf("unexpected aggregate: %#v", merged)
	}
	if merged.WritableBytes != 0 {
		t.Fatalf(
			"partially observed writable bytes = %d, want unavailable zero",
			merged.WritableBytes,
		)
	}
	for _, field := range merged.ObservedFields {
		if field == domain.ResourceObservedWritableBytes {
			t.Fatalf(
				"partial field remained observed: %#v",
				merged.ObservedFields,
			)
		}
	}
}

func TestMergeRunnerFeaturesDowngradesPartialRepeatCoverage(t *testing.T) {
	base := domain.RunnerFeatures{
		Backend:                  "docker",
		Available:                true,
		ControllerOS:             "windows",
		WorkloadOS:               "linux",
		Rootless:                 "no",
		NetworkDeny:              true,
		ResourceUsage:            "high",
		ResourceLimitEnforcement: true,
		EngineVersion:            "29.1.3",
	}
	partial := base
	partial.ResourceUsage = "unavailable"
	partial.ResourceLimitEnforcement = false

	merged := mergeRunnerFeatures(base, partial)
	if merged.ResourceUsage != "unavailable" {
		t.Fatalf(
			"partial repeat resource coverage = %q, want unavailable",
			merged.ResourceUsage,
		)
	}
	if merged.ResourceLimitEnforcement {
		t.Fatal("partial repeat retained resource-limit enforcement")
	}
}

func TestMergeRunnerFeaturesRejectsRepeatIdentityDrift(t *testing.T) {
	left := domain.RunnerFeatures{
		Backend:       "docker",
		Available:     true,
		ControllerOS:  "windows",
		WorkloadOS:    "linux",
		Rootless:      "no",
		EngineVersion: "29.1.3",
		ResourceUsage: "high",
	}
	right := left
	right.EngineVersion = "29.1.4"

	merged := mergeRunnerFeatures(left, right)
	if merged.Available || merged.ResourceUsage != "unavailable" {
		t.Fatalf("runner identity drift did not fail closed: %#v", merged)
	}
}

func hasErrorCode(errors []*domain.Error, code domain.ErrorCode) bool {
	for _, item := range errors {
		if item != nil && item.Code == code {
			return true
		}
	}
	return false
}

func decodeEnvelope(t *testing.T, data []byte) testEnvelope {
	t.Helper()
	var response testEnvelope
	decodeJSON(t, data, &response)
	return response
}

func decodeJSON(t *testing.T, data []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(data, destination); err != nil {
		t.Fatalf("decode JSON %q: %v", data, err)
	}
}
