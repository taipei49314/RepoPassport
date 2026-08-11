//go:build integration

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/execution"
	"github.com/taipei49314/RepoPassport/internal/manifest"
	"github.com/taipei49314/RepoPassport/internal/planner"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/rendering"
	"github.com/taipei49314/RepoPassport/internal/runtimepolicy"
	"github.com/taipei49314/RepoPassport/internal/storage"
	"github.com/taipei49314/RepoPassport/internal/verification"
)

func TestContainerAlpha25UndeclaredPortFixtureContract(t *testing.T) {
	cases := []struct {
		name          string
		adapter       string
		healthySchema string
		expectedFiles []string
	}{
		{
			name:          "alpha25-undeclared-port-node",
			adapter:       "node",
			healthySchema: filepath.Join("healthy", "healthy-node-http"),
			expectedFiles: []string{
				".repopass/schemas/echo-response.schema.json",
				"fixture.json",
				"package.json",
				"repo-passport.yml",
				"server.mjs",
			},
		},
		{
			name:          "alpha25-undeclared-port-python",
			adapter:       "python",
			healthySchema: filepath.Join("healthy", "healthy-python-http"),
			expectedFiles: []string{
				".repopass/schemas/echo-response.schema.json",
				"fixture.json",
				"repo-passport.yml",
				"server.py",
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixtureRoot, err := filepath.Abs(filepath.Join(
				"..", "..", "testdata", "fixtures", "malicious", test.name,
			))
			if err != nil {
				t.Fatalf("resolve fixture root: %v", err)
			}
			var files []string
			err = filepath.WalkDir(fixtureRoot, func(
				path string,
				entry fs.DirEntry,
				walkErr error,
			) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return nil
				}
				relative, err := filepath.Rel(fixtureRoot, path)
				if err != nil {
					return err
				}
				files = append(files, filepath.ToSlash(relative))
				return nil
			})
			if err != nil {
				t.Fatalf("walk fixture tree: %v", err)
			}
			if strings.Join(files, "\x00") !=
				strings.Join(test.expectedFiles, "\x00") {
				t.Fatalf("fixture tree = %#v, want %#v", files, test.expectedFiles)
			}
			document, err := manifest.Load(
				filepath.Join(fixtureRoot, "repo-passport.yml"),
			)
			if err != nil {
				t.Fatalf("load fixture manifest: %v", err)
			}
			snapshot, err := acquisition.NewLocalProvider().Fetch(
				context.Background(),
				domain.ResolvedSource{Kind: "local", LocalPath: fixtureRoot},
			)
			if err != nil {
				t.Fatalf("snapshot fixture: %v", err)
			}
			plan, err := planner.Resolve(document, snapshot, "quickstart")
			if err != nil {
				t.Fatalf("resolve fixture plan: %v", err)
			}
			if plan.RuntimeAdapter != test.adapter ||
				plan.ObserverVersions["port-listen"] != "0.3.0" {
				t.Fatalf("Alpha.25 fixture plan = %#v", plan)
			}
			healthyRoot, err := filepath.Abs(filepath.Join(
				"..", "..", "testdata", "fixtures", test.healthySchema,
			))
			if err != nil {
				t.Fatalf("resolve healthy schema root: %v", err)
			}
			fixtureSchema, err := os.ReadFile(filepath.Join(
				fixtureRoot, ".repopass", "schemas", "echo-response.schema.json",
			))
			if err != nil {
				t.Fatalf("read fixture schema: %v", err)
			}
			healthySchema, err := os.ReadFile(filepath.Join(
				healthyRoot, ".repopass", "schemas", "echo-response.schema.json",
			))
			if err != nil {
				t.Fatalf("read healthy schema: %v", err)
			}
			if !bytes.Equal(fixtureSchema, healthySchema) {
				t.Fatal("fixture schema must exactly match its healthy HTTP control")
			}
		})
	}
}

func TestContainerHealthyJourneys(t *testing.T) {
	backend := requiredContainerIntegrationBackend(t)
	runner, err := execution.Doctor(context.Background(), backend)
	if err != nil {
		t.Fatalf("%s doctor failed: %v", backend, err)
	}
	if !runner.Available || runner.ControllerOS != "linux" ||
		runner.WorkloadOS != "linux" || strings.TrimSpace(runner.EngineVersion) == "" {
		t.Fatalf("integration runner is not an available Linux engine: %#v", runner)
	}

	tests := []struct {
		name           string
		fixture        string
		adapter        string
		imageReference string
		imageDigest    string
		wantAssertions int
		wantRepeats    int
		httpProfile    bool
	}{
		{
			name:           "node cli",
			fixture:        filepath.Join("healthy", "healthy-node-cli"),
			adapter:        "node",
			imageReference: runtimepolicy.NodeReference,
			imageDigest:    runtimepolicy.NodeDigest,
			wantAssertions: 12,
			wantRepeats:    3,
		},
		{
			name:           "python cli",
			fixture:        filepath.Join("healthy", "healthy-python-cli"),
			adapter:        "python",
			imageReference: runtimepolicy.PythonReference,
			imageDigest:    runtimepolicy.PythonDigest,
			wantAssertions: 6,
			wantRepeats:    2,
		},
		{
			name:           "node http",
			fixture:        filepath.Join("healthy", "healthy-node-http"),
			adapter:        "node",
			imageReference: runtimepolicy.NodeReference,
			imageDigest:    runtimepolicy.NodeDigest,
			wantAssertions: 21,
			wantRepeats:    3,
			httpProfile:    true,
		},
		{
			name:           "python http",
			fixture:        filepath.Join("healthy", "healthy-python-http"),
			adapter:        "python",
			imageReference: runtimepolicy.PythonReference,
			imageDigest:    runtimepolicy.PythonDigest,
			wantAssertions: 15,
			wantRepeats:    3,
			httpProfile:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataRoot := t.TempDir()
			manifestPath, err := filepath.Abs(filepath.Join(
				"..", "..", "testdata", "fixtures", test.fixture, "repo-passport.yml",
			))
			if err != nil {
				t.Fatalf("resolve fixture manifest: %v", err)
			}
			document, err := manifest.Load(manifestPath)
			if err != nil {
				t.Fatalf("load fixture manifest: %v", err)
			}
			fixtureRoot := filepath.Dir(manifestPath)
			snapshot, err := acquisition.NewLocalProvider().Fetch(
				context.Background(),
				domain.ResolvedSource{Kind: "local", LocalPath: fixtureRoot},
			)
			if err != nil {
				t.Fatalf("snapshot fixture: %v", err)
			}
			resolvedPlan, err := planner.Resolve(document, snapshot, "quickstart")
			if err != nil {
				t.Fatalf("resolve fixture plan: %v", err)
			}
			if resolvedPlan.RuntimeAdapter != test.adapter ||
				resolvedPlan.BaseImageReference != test.imageReference ||
				resolvedPlan.BaseImageDigest != test.imageDigest {
				t.Fatalf("resolved runtime tuple = %#v", resolvedPlan)
			}
			if !containsExactString(
				resolvedPlan.RequiredRunnerFeatures,
				"platform:linux/amd64",
			) {
				t.Fatalf(
					"resolved runner features omit exact linux/amd64 platform: %#v",
					resolvedPlan.RequiredRunnerFeatures,
				)
			}

			var stdout, stderr bytes.Buffer
			app := App{
				Deps: Dependencies{
					ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
						return []domain.RunnerFeatures{runner}, nil
					},
					Execute: containerIntegrationExecute,
				},
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			}
			exitCode := app.Run(context.Background(), []string{
				"--json",
				"--data-dir", dataRoot,
				"verify",
				"--runner", backend,
				"--manifest", manifestPath,
				"--scenario", "quickstart",
			})
			if exitCode != 0 {
				t.Fatalf(
					"verify exit code = %d; stdout: %s; stderr: %s",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}

			response := decodeEnvelope(t, stdout.Bytes())
			var data verifyEnvelopeData
			decodeJSON(t, response.Data, &data)
			result := data.Verification
			if result.Plan.PlanDigest != resolvedPlan.PlanDigest ||
				result.Plan.PolicyBundleDigest != resolvedPlan.PolicyBundleDigest ||
				result.Plan.RepeatCount != resolvedPlan.RepeatCount ||
				result.Plan.SuccessThreshold != resolvedPlan.SuccessThreshold ||
				result.Subject != resolvedPlan.Source {
				t.Fatalf(
					"executed plan drifted from the independently resolved tuple: got %#v want %#v",
					result.Plan,
					resolvedPlan,
				)
			}
			if result.Runner.Backend != backend ||
				result.Runner.WorkloadOS != "linux" {
				t.Fatalf("executed runner tuple = %#v", result.Runner)
			}
			if result.Results.Functional != domain.FunctionalPass ||
				result.Results.Reproducibility != domain.ReproducibilityStable ||
				result.Results.Cleanup != domain.CleanupAllowedResidue ||
				result.Results.Capability != domain.CapabilityIncomplete ||
				result.Results.Overall != domain.OverallInconclusive {
				t.Fatalf(
					"healthy %s/%s verdicts = %#v, want pass/stable/allowed-residue/incomplete/inconclusive",
					backend,
					test.name,
					result.Results,
				)
			}
			if result.Repeats.Requested != test.wantRepeats ||
				result.Repeats.Completed != test.wantRepeats ||
				result.Repeats.Matching != test.wantRepeats {
				t.Fatalf(
					"healthy repeat receipt = %#v, want exact %d/%d/%d",
					result.Repeats,
					test.wantRepeats,
					test.wantRepeats,
					test.wantRepeats,
				)
			}
			if len(result.Assertions) != test.wantAssertions {
				t.Fatalf("assertions = %d, want %d", len(result.Assertions), test.wantAssertions)
			}
			for _, assertion := range result.Assertions {
				if assertion.Status != "passed" {
					t.Fatalf("assertion %q status = %q, want passed", assertion.ID, assertion.Status)
				}
			}
			assertFilesystemRetainedStateObservations(t, result, "")
			if test.httpProfile {
				wantPortCoverage := "best-effort"
				if backend == "podman" {
					wantPortCoverage = "unavailable"
				}
				if result.Runner.PortObservation != wantPortCoverage {
					t.Fatalf(
						"%s HTTP port coverage = %q, want honest backend-specific %q",
						backend,
						result.Runner.PortObservation,
						wantPortCoverage,
					)
				}
			}

			annotation, err := json.Marshal(map[string]any{
				"backend":         backend,
				"capability":      result.Results.Capability,
				"cleanup":         result.Results.Cleanup,
				"fixture":         filepath.Base(test.fixture),
				"functional":      result.Results.Functional,
				"imageDigest":     resolvedPlan.BaseImageDigest,
				"imageReference":  resolvedPlan.BaseImageReference,
				"kind":            "container-healthy-journey-result-annotation",
				"overall":         result.Results.Overall,
				"planDigest":      result.Plan.PlanDigest,
				"platform":        "linux/amd64",
				"reproducibility": result.Results.Reproducibility,
				"trustBoundary":   "non-versioned-ci-check-not-trusted-evidence",
			})
			if err != nil {
				t.Fatalf("marshal healthy journey annotation: %v", err)
			}
			t.Logf("REPOPASS_M1_JOURNEY_RESULT %s", annotation)

			stored, err := (storage.RunStore{Root: filepath.Join(dataRoot, "runs")}).Read(result.RunID)
			if err != nil {
				t.Fatalf("read authoritative result: %v", err)
			}
			if stored.VerificationID != result.VerificationID ||
				stored.Digests.Verification != result.Digests.Verification {
				t.Fatal("stored artifact differs from the controller result")
			}
			assertContainersRemoved(t, backend, result.Observations)
		})
	}
}

func TestContainerCLIJourneys(t *testing.T) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("REPOPASS_INTEGRATION_BACKEND")))
	if backend == "" {
		t.Skip("set REPOPASS_INTEGRATION_BACKEND=docker or podman to run live container tests")
	}
	if backend != "docker" && backend != "podman" {
		t.Fatalf("REPOPASS_INTEGRATION_BACKEND = %q, want docker or podman", backend)
	}

	runner, err := execution.Doctor(context.Background(), backend)
	if err != nil {
		t.Fatalf("%s doctor failed: %v", backend, err)
	}
	if !runner.Available || runner.WorkloadOS != "linux" {
		t.Fatalf("integration runner is not an available Linux engine: %#v", runner)
	}

	tests := []struct {
		name                string
		fixture             string
		wantAssertions      int
		wantRepeatVerdict   domain.ReproducibilityVerdict
		wantCleanup         domain.CleanupVerdict
		wantOverall         domain.OverallVerdict
		wantCapability      domain.CapabilityVerdict
		wantResidueError    bool
		wantUndeclaredWrite bool
		wantUndeclaredPort  bool
		wantOperationWrite  bool
		wantOperationResult string
		wantActivityFailure string
		wantQuiescence      bool
		wantEscalation      bool
	}{
		{
			name:              "healthy node cli",
			fixture:           filepath.Join("healthy", "healthy-node-cli"),
			wantAssertions:    12,
			wantRepeatVerdict: domain.ReproducibilityStable,
			wantCleanup:       domain.CleanupAllowedResidue,
			wantOverall:       domain.OverallInconclusive,
		},
		{
			name:              "healthy node cli with SPDX-selected evidence",
			fixture:           filepath.Join("healthy", "minimal-public-spdx"),
			wantAssertions:    12,
			wantRepeatVerdict: domain.ReproducibilityStable,
			wantCleanup:       domain.CleanupAllowedResidue,
			wantOverall:       domain.OverallInconclusive,
		},
		{
			name:              "cleanup undeclared residue",
			fixture:           filepath.Join("malicious", "cleanup-undeclared-residue"),
			wantAssertions:    6,
			wantRepeatVerdict: domain.ReproducibilityStable,
			wantCleanup:       domain.CleanupUndeclaredResidue,
			wantOverall:       domain.OverallNonconforming,
			wantResidueError:  true,
		},
		{
			name:                "undeclared retained write",
			fixture:             filepath.Join("malicious", "undeclared-retained-write"),
			wantAssertions:      6,
			wantRepeatVerdict:   domain.ReproducibilityStable,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallNonconforming,
			wantCapability:      domain.CapabilityNonconforming,
			wantUndeclaredWrite: true,
		},
		{
			name:                "healthy python cli with persisted setup output",
			fixture:             filepath.Join("healthy", "healthy-python-cli"),
			wantAssertions:      6,
			wantRepeatVerdict:   domain.ReproducibilityStable,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallInconclusive,
			wantOperationResult: "no-undeclared-observed",
		},
		{
			name:                "alpha24 transient create delete",
			fixture:             filepath.Join("malicious", "alpha24-transient-create-delete"),
			wantAssertions:      6,
			wantRepeatVerdict:   domain.ReproducibilityStable,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallNonconforming,
			wantCapability:      domain.CapabilityNonconforming,
			wantUndeclaredWrite: true,
			wantOperationWrite:  true,
			wantOperationResult: "nonconforming-notifications",
		},
		{
			name:                "alpha24 write restore",
			fixture:             filepath.Join("malicious", "alpha24-write-restore"),
			wantAssertions:      6,
			wantRepeatVerdict:   domain.ReproducibilityStable,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallNonconforming,
			wantCapability:      domain.CapabilityNonconforming,
			wantUndeclaredWrite: true,
			wantOperationWrite:  true,
			wantOperationResult: "nonconforming-notifications",
		},
		{
			name:                "alpha24 wrong phase write",
			fixture:             filepath.Join("malicious", "alpha24-wrong-phase"),
			wantAssertions:      4,
			wantRepeatVerdict:   domain.ReproducibilityStable,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallNonconforming,
			wantCapability:      domain.CapabilityNonconforming,
			wantUndeclaredWrite: true,
			wantOperationWrite:  true,
			wantOperationResult: "nonconforming-notifications",
		},
		{
			name:                "alpha24 notification overflow fails closed",
			fixture:             filepath.Join("malicious", "alpha24-notification-overflow"),
			wantAssertions:      3,
			wantRepeatVerdict:   domain.ReproducibilityNotTested,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallInconclusive,
			wantOperationResult: "not-tested",
			wantActivityFailure: "notification-overflow",
		},
		{
			name:                "alpha24 new directory gap fails closed",
			fixture:             filepath.Join("malicious", "alpha24-new-directory-gap"),
			wantAssertions:      3,
			wantRepeatVerdict:   domain.ReproducibilityNotTested,
			wantCleanup:         domain.CleanupAllowedResidue,
			wantOverall:         domain.OverallInconclusive,
			wantOperationResult: "not-tested",
			wantActivityFailure: "new-directory-watch-gap",
		},
		{
			name:              "healthy python http",
			fixture:           filepath.Join("healthy", "healthy-python-http"),
			wantAssertions:    15,
			wantRepeatVerdict: domain.ReproducibilityStable,
			wantCleanup:       domain.CleanupAllowedResidue,
			wantOverall:       domain.OverallInconclusive,
		},
		{
			name:              "healthy node http",
			fixture:           filepath.Join("healthy", "healthy-node-http"),
			wantAssertions:    21,
			wantRepeatVerdict: domain.ReproducibilityStable,
			wantCleanup:       domain.CleanupAllowedResidue,
			wantOverall:       domain.OverallInconclusive,
		},
		{
			name:               "alpha25 undeclared node tcp listener",
			fixture:            filepath.Join("malicious", "alpha25-undeclared-port-node"),
			wantAssertions:     21,
			wantRepeatVerdict:  domain.ReproducibilityStable,
			wantCleanup:        domain.CleanupAllowedResidue,
			wantOverall:        domain.OverallNonconforming,
			wantCapability:     domain.CapabilityNonconforming,
			wantUndeclaredPort: true,
		},
		{
			name:               "alpha25 undeclared python tcp listener",
			fixture:            filepath.Join("malicious", "alpha25-undeclared-port-python"),
			wantAssertions:     15,
			wantRepeatVerdict:  domain.ReproducibilityStable,
			wantCleanup:        domain.CleanupAllowedResidue,
			wantOverall:        domain.OverallNonconforming,
			wantCapability:     domain.CapabilityNonconforming,
			wantUndeclaredPort: true,
		},
		{
			name:              "workload forged verification is ignored",
			fixture:           filepath.Join("malicious", "fake-verification-json"),
			wantAssertions:    3,
			wantRepeatVerdict: domain.ReproducibilityNotTested,
			wantCleanup:       domain.CleanupAllowedResidue,
			wantOverall:       domain.OverallInconclusive,
			wantQuiescence:    true,
		},
		{
			name:              "term resistant http child is removed",
			fixture:           filepath.Join("malicious", "http-term-resistant-child"),
			wantAssertions:    2,
			wantRepeatVerdict: domain.ReproducibilityNotTested,
			wantCleanup:       domain.CleanupAllowedResidue,
			wantOverall:       domain.OverallInconclusive,
			wantQuiescence:    true,
			wantEscalation:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataRoot := t.TempDir()
			manifestPath, err := filepath.Abs(filepath.Join(
				"..", "..", "testdata", "fixtures", test.fixture, "repo-passport.yml",
			))
			if err != nil {
				t.Fatalf("resolve fixture manifest: %v", err)
			}

			var stdout, stderr bytes.Buffer
			app := App{
				Deps: Dependencies{
					ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
						return []domain.RunnerFeatures{runner}, nil
					},
					Execute: containerIntegrationExecute,
				},
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			}
			exitCode := app.Run(context.Background(), []string{
				"--json",
				"--data-dir", dataRoot,
				"verify",
				"--runner", backend,
				"--manifest", manifestPath,
				"--scenario", "quickstart",
			})
			if exitCode != 0 {
				t.Fatalf("verify exit code = %d; stdout: %s; stderr: %s", exitCode, stdout.String(), stderr.String())
			}

			response := decodeEnvelope(t, stdout.Bytes())
			var data verifyEnvelopeData
			decodeJSON(t, response.Data, &data)
			result := data.Verification
			if result.Results.Functional != domain.FunctionalPass {
				t.Fatalf("functional verdict = %q, want pass; findings: %v", result.Results.Functional, result.Errors)
			}
			if result.Results.Reproducibility != test.wantRepeatVerdict {
				t.Fatalf("reproducibility = %q, want %q", result.Results.Reproducibility, test.wantRepeatVerdict)
			}
			wantCapability := test.wantCapability
			if wantCapability == "" {
				wantCapability = domain.CapabilityIncomplete
			}
			if result.Results.Capability != wantCapability {
				t.Fatalf(
					"capability verdict = %q, want %q",
					result.Results.Capability,
					wantCapability,
				)
			}
			if result.Results.Cleanup != test.wantCleanup {
				t.Fatalf(
					"cleanup verdict = %q, want %q; findings: %v",
					result.Results.Cleanup,
					test.wantCleanup,
					result.Errors,
				)
			}
			if result.Results.Overall != test.wantOverall {
				t.Fatalf(
					"overall verdict = %q, want %q",
					result.Results.Overall,
					test.wantOverall,
				)
			}
			if filepath.Base(test.fixture) == "minimal-public-spdx" {
				wantInclude := []string{"normalized-observations", "sbom", "verification-summary"}
				if strings.Join(result.Plan.Evidence.Include, "\x00") != strings.Join(wantInclude, "\x00") ||
					result.Plan.ResolvedPlanSchemaVersion != "4" {
					t.Fatalf("SPDX-selected live plan evidence = %#v", result.Plan)
				}
			}
			assertFilesystemRetainedStateObservations(
				t,
				result,
				test.wantActivityFailure,
			)
			if len(result.Assertions) != test.wantAssertions {
				t.Fatalf("assertions = %d, want %d: %#v", len(result.Assertions), test.wantAssertions, result.Assertions)
			}
			for _, assertion := range result.Assertions {
				if assertion.Status != "passed" {
					t.Fatalf("assertion %q status = %q, want passed", assertion.ID, assertion.Status)
				}
			}
			residueError := false
			for _, finding := range result.Errors {
				if finding != nil &&
					finding.Code == domain.CodeCleanupResidue {
					residueError = true
					break
				}
			}
			if residueError != test.wantResidueError {
				t.Fatalf(
					"cleanup residue finding = %t, want %t",
					residueError,
					test.wantResidueError,
				)
			}
			undeclaredWriteError := containsErrorCode(
				result.Errors,
				domain.CodeUndeclaredFilesystemWrite,
			)
			if undeclaredWriteError != test.wantUndeclaredWrite {
				t.Fatalf(
					"undeclared retained write finding = %t, want %t",
					undeclaredWriteError,
					test.wantUndeclaredWrite,
				)
			}
			if test.wantUndeclaredWrite {
				if test.wantOperationWrite {
					assertUndeclaredOperationNotification(t, result)
				} else {
					assertUndeclaredRetainedWrite(t, result)
				}
			}
			undeclaredPortError := containsErrorCode(
				result.Errors,
				domain.CodeUndeclaredPortListen,
			)
			if undeclaredPortError != test.wantUndeclaredPort {
				t.Fatalf(
					"undeclared TCP listener finding = %t, want %t",
					undeclaredPortError,
					test.wantUndeclaredPort,
				)
			}
			if test.wantUndeclaredPort {
				assertUndeclaredPeerPortListener(t, result)
			}
			assertOperationNotificationObservations(
				t,
				result,
				test.wantOperationResult,
				test.wantActivityFailure,
			)
			if filepath.Base(test.fixture) ==
				"cleanup-undeclared-residue" {
				var cleanupObservation *domain.ObservationEvent
				for index := range result.Observations {
					if result.Observations[index].Operation ==
						"cleanup.residue.summary" {
						cleanupObservation =
							&result.Observations[index]
						break
					}
				}
				if cleanupObservation == nil {
					t.Fatal("cleanup residue observation is absent")
				}
				symlinkCount, symlinkCountOK := observationInteger(
					cleanupObservation.Details["symlinkCount"],
				)
				if !symlinkCountOK || symlinkCount < 1 {
					t.Fatalf(
						"cleanup symlinkCount = %#v, want >= 1",
						cleanupObservation.Details["symlinkCount"],
					)
				}
				var residueFinding *domain.Error
				for _, finding := range result.Errors {
					if finding != nil &&
						finding.Code == domain.CodeCleanupResidue {
						residueFinding = finding
						break
					}
				}
				if residueFinding == nil {
					t.Fatal("cleanup residue finding is absent")
				}
				publicValues := []any{
					result,
					*cleanupObservation,
					residueFinding,
				}
				for index, value := range publicValues {
					encoded, encodeErr := json.Marshal(value)
					if encodeErr != nil {
						t.Fatalf(
							"marshal cleanup public value %d: %v",
							index,
							encodeErr,
						)
					}
					assertNoCleanupPrivatePath(t, string(encoded))
				}
				assertNoCleanupPrivatePath(
					t,
					rendering.Text(result),
				)
			}
			if backend == "docker" &&
				(filepath.Base(test.fixture) == "healthy-node-cli" ||
					filepath.Base(test.fixture) ==
						"cleanup-undeclared-residue") {
				liveEvidence := map[string]any{
					"backend":             "docker",
					"cleanup":             result.Results.Cleanup,
					"cleanupResidueError": residueError,
					"fixture":             filepath.Base(test.fixture),
					"functional":          result.Results.Functional,
					"kind":                "cleanup-residue-live-evidence",
					"overall":             result.Results.Overall,
					"platform":            "linux/amd64",
					"repeatCompleted":     result.Repeats.Completed,
					"repeatMatching":      result.Repeats.Matching,
					"repeatRequested":     result.Repeats.Requested,
					"reproducibility":     result.Results.Reproducibility,
					"runtimeAdapter":      "node",
					"schemaVersion":       "1",
				}
				payload, marshalErr := json.Marshal(liveEvidence)
				if marshalErr != nil {
					t.Fatalf("marshal cleanup live evidence: %v", marshalErr)
				}
				t.Logf("REPOPASS_CLEANUP_EVIDENCE %s", payload)
			}
			if result.VerificationID == "workload-controlled" {
				t.Fatal("workload-controlled verification ID became authoritative")
			}
			if test.wantQuiescence {
				observed := false
				for _, observation := range result.Observations {
					if observation.Operation == "sandbox.processes.quiesce" &&
						observation.Result == "succeeded" {
						observed = true
						break
					}
				}
				if !observed {
					t.Fatalf("successful process quiescence observation is absent: %#v", result.Observations)
				}
			}
			if test.wantEscalation {
				assertTermSignalEscalated(t, result.Observations)
			}

			stored, err := (storage.RunStore{Root: filepath.Join(dataRoot, "runs")}).Read(result.RunID)
			if err != nil {
				t.Fatalf("read authoritative result: %v", err)
			}
			if stored.VerificationID != result.VerificationID ||
				stored.Digests.Verification != result.Digests.Verification {
				t.Fatalf("stored artifact differs from the controller result")
			}
			assertContainersRemoved(t, backend, result.Observations)
		})
	}
}

func TestPodmanEngineDiffUnavailableContract(t *testing.T) {
	result := domain.VerificationResult{
		Runner: domain.RunnerFeatures{
			Backend:                    "podman",
			FilesystemWriteObservation: "best-effort",
		},
		ObserverCoverage: []domain.ObserverCoverage{
			{
				Observer: "podman-filesystem-retained-state",
				Feature:  "filesystem-write",
				Coverage: "best-effort",
				Required: true,
				Reason:   "operation-history observer remains unavailable",
			},
		},
		Repeats: domain.RepeatSummary{
			Requested: 1,
			Completed: 1,
			Matching:  1,
		},
		Observations: []domain.ObservationEvent{
			{
				Actor:      "trusted-runner",
				Operation:  "filesystem.engine-diff.summary",
				Result:     "unavailable",
				Observer:   "docker-container-diff",
				Coverage:   "unavailable",
				Confidence: "unknown",
				Details: map[string]any{
					"scope": "docker-engine-filesystem-diff",
					"snapshotBoundary": "image-to-" +
						"post-quiesce-pre-repair",
					"engineSemantics": "changes-since-" +
						"container-create",
					"opaqueTranscript":            true,
					"transcriptParsed":            false,
					"baselineDiagnosticOnly":      true,
					"includesPreWorkloadChanges":  true,
					"includesTrustedObserverWork": true,
					"contentIncluded":             false,
					"pathsIncluded":               false,
					"publicEvidence":              "aggregate-only",
					"actorAttribution":            "unavailable",
					"baselineIdentityVerified":    true,
					"finalIdentityVerified":       true,
					"workloadQuiescenceVerified":  true,
					"baselineReady":               false,
					"finalReady":                  false,
					"engineDiffCoverage":          "unavailable",
					"mountedFilesystemCoverage":   "unavailable",
					"operationHistoryCoverage":    "unavailable",
					"pathClassificationAvailable": false,
					"baselineFailure": "baseline-" +
						"engine-diff-failed",
					"failure": "final-engine-diff-failed",
				},
			},
			{
				Actor:      "trusted-runner",
				Operation:  "filesystem.retained-state.summary",
				Result:     "observed",
				Observer:   "podman-filesystem-retained-state",
				Coverage:   "high",
				Confidence: "high",
				Details: map[string]any{
					"scope": "outputs-retained-state",
					"snapshotBoundary": "post-init-pre-workload-" +
						"to-post-quiesce-pre-repair",
					"includesTrustedHelpers":           true,
					"includesRunnerManagedDirectories": true,
					"contentIncluded":                  false,
					"publicEvidence":                   "aggregate-only",
					"actorAttribution":                 "unavailable",
					"baselineIdentityVerified":         true,
					"finalIdentityVerified":            true,
					"workloadQuiescenceVerified":       true,
					"baselineReady":                    true,
					"finalReady":                       true,
					"retainedStateCoverage":            "high",
					"changeCount":                      0,
					"baselineDigest": "sha256:" +
						strings.Repeat("a", 64),
					"finalDigest": "sha256:" +
						strings.Repeat("a", 64),
				},
			},
			{
				SchemaVersion: "1",
				Phase:         domain.PhaseCleanup,
				Actor:         "trusted-runner",
				Operation:     "filesystem.activity-trace.summary",
				Resource:      "/outputs",
				Result:        "unavailable",
				Observer:      "docker-outputs-activity-trace",
				Coverage:      "unavailable",
				Confidence:    "unknown",
				Details: map[string]any{
					"scope": "outputs-activity-notification-trace",
					"traceBoundary": "post-preflight-pre-workload-to-" +
						"post-quiesce-pre-retained-final",
					"notificationSemantics": "runtime-filesystem-" +
						"notification-hints",
					"rawPathIncluded":             false,
					"contentIncluded":             false,
					"publicEvidence":              "aggregate-only",
					"actorAttribution":            "unavailable",
					"phaseAttribution":            "controller-window-hint",
					"operationClassification":     "hint-only",
					"operationHistoryCoverage":    "unavailable",
					"observerPlacement":           "in-sandbox-trusted-helper",
					"sharesSandboxResourceBudget": true,
					"startIdentityVerified":       false,
					"readyIdentityVerified":       false,
					"stopIdentityVerified":        false,
					"finalIdentityVerified":       false,
					"workloadQuiescenceVerified":  true,
					"transport":                   "controller-stdin-stdout-jsonl",
					"transportBoundBytes":         16384,
					"notificationLimit":           4096,
					"watchLimit":                  2048,
					"activityTraceCoverage":       "unavailable",
					"blindSpots": []string{
						"outside-outputs",
						"syscall-and-operation-history",
					},
					"failure": "backend-not-live-qualified",
				},
			},
		},
	}

	assertFilesystemRetainedStateObservations(t, result, "")
}

func assertFilesystemRetainedStateObservations(
	t *testing.T,
	result domain.VerificationResult,
	wantActivityFailure string,
) {
	t.Helper()
	if result.Runner.FilesystemWriteObservation != "best-effort" {
		t.Fatalf(
			"composite filesystem-write coverage = %q, want best-effort",
			result.Runner.FilesystemWriteObservation,
		)
	}
	requiredCoverageFound := false
	for _, coverage := range result.ObserverCoverage {
		if coverage.Feature != "filesystem-write" {
			continue
		}
		requiredCoverageFound = true
		if !coverage.Required ||
			coverage.Coverage != "best-effort" ||
			coverage.Reason == "" {
			t.Fatalf(
				"required filesystem-write coverage was overstated: %#v",
				coverage,
			)
		}
	}
	if !requiredCoverageFound {
		t.Fatal("required filesystem-write coverage row is absent")
	}

	summaryCount := 0
	engineDiffSummaryCount := 0
	activityTraceSummaryCount := 0
	for _, observation := range result.Observations {
		if strings.HasPrefix(
			observation.Operation,
			"filesystem.retained-state.",
		) && observation.Operation != "filesystem.retained-state.summary" {
			t.Fatalf(
				"retained-state evidence is not aggregate-only: %#v",
				observation,
			)
		}
		if observation.Operation == "filesystem.activity-trace.summary" {
			activityTraceSummaryCount++
			assertActivityTraceObservation(
				t,
				result,
				observation,
				wantActivityFailure,
			)
			continue
		}
		if observation.Operation == "filesystem.engine-diff.summary" {
			engineDiffSummaryCount++
			if result.Runner.Backend == "podman" {
				if observation.Result != "unavailable" ||
					observation.Coverage != "unavailable" ||
					observation.Confidence != "unknown" ||
					observation.Actor != "trusted-runner" ||
					observation.Observer != "docker-container-diff" {
					t.Fatalf(
						"Podman engine diff availability was overstated: %#v",
						observation,
					)
				}
				for key, want := range map[string]any{
					"scope": "docker-engine-filesystem-diff",
					"snapshotBoundary": "image-to-" +
						"post-quiesce-pre-repair",
					"engineSemantics": "changes-since-" +
						"container-create",
					"opaqueTranscript":            true,
					"transcriptParsed":            false,
					"baselineDiagnosticOnly":      true,
					"includesPreWorkloadChanges":  true,
					"includesTrustedObserverWork": true,
					"contentIncluded":             false,
					"pathsIncluded":               false,
					"publicEvidence":              "aggregate-only",
					"actorAttribution":            "unavailable",
					"baselineIdentityVerified":    true,
					"finalIdentityVerified":       true,
					"workloadQuiescenceVerified":  true,
					"baselineReady":               false,
					"finalReady":                  false,
					"engineDiffCoverage":          "unavailable",
					"mountedFilesystemCoverage":   "unavailable",
					"operationHistoryCoverage":    "unavailable",
					"pathClassificationAvailable": false,
					"baselineFailure": "baseline-" +
						"engine-diff-failed",
					"failure": "final-engine-diff-failed",
				} {
					if observation.Details[key] != want {
						t.Fatalf(
							"Podman engine diff details[%q] = %#v, want %#v",
							key,
							observation.Details[key],
							want,
						)
					}
				}
				for _, forbiddenKey := range []string{
					"baselineDigest",
					"baselineByteCount",
					"baselineNonEmpty",
					"finalDigest",
					"finalByteCount",
					"finalNonEmpty",
					"transcriptChangedFromBaseline",
					"path",
					"entries",
					"rawTranscript",
				} {
					if _, present :=
						observation.Details[forbiddenKey]; present {
						t.Fatalf(
							"unavailable Podman engine diff exposed %q: %#v",
							forbiddenKey,
							observation,
						)
					}
				}
				continue
			}
			if result.Runner.Backend != "docker" {
				t.Fatalf(
					"unexpected backend for engine diff summary: %q",
					result.Runner.Backend,
				)
			}
			if observation.Result != "observed" ||
				observation.Coverage != "best-effort" ||
				observation.Confidence != "high" ||
				observation.Actor != "trusted-runner" ||
				observation.Observer != "docker-container-diff" {
				t.Fatalf(
					"engine diff summary trust envelope = %#v",
					observation,
				)
			}
			for key, want := range map[string]any{
				"scope": "docker-engine-filesystem-diff",
				"snapshotBoundary": "image-to-" +
					"post-quiesce-pre-repair",
				"engineSemantics": "changes-since-" +
					"container-create",
				"opaqueTranscript":            true,
				"transcriptParsed":            false,
				"baselineDiagnosticOnly":      true,
				"includesPreWorkloadChanges":  true,
				"includesTrustedObserverWork": true,
				"contentIncluded":             false,
				"pathsIncluded":               false,
				"publicEvidence":              "aggregate-only",
				"actorAttribution":            "unavailable",
				"baselineIdentityVerified":    true,
				"finalIdentityVerified":       true,
				"workloadQuiescenceVerified":  true,
				"baselineReady":               true,
				"finalReady":                  true,
				"engineDiffCoverage":          "best-effort",
				"mountedFilesystemCoverage":   "unavailable",
				"operationHistoryCoverage":    "unavailable",
				"pathClassificationAvailable": false,
			} {
				if observation.Details[key] != want {
					t.Fatalf(
						"engine diff details[%q] = %#v, want %#v",
						key,
						observation.Details[key],
						want,
					)
				}
			}
			for _, key := range []string{
				"baselineByteCount",
				"finalByteCount",
			} {
				count, ok := observationInteger(
					observation.Details[key],
				)
				if !ok || count < 0 || count > 4<<20 {
					t.Fatalf(
						"engine diff %s is not bounded: %#v",
						key,
						observation.Details[key],
					)
				}
			}
			finalBytes, _ := observationInteger(
				observation.Details["finalByteCount"],
			)
			finalNonEmpty, ok := observation.Details["finalNonEmpty"].(bool)
			if !ok || finalNonEmpty != (finalBytes != 0) {
				t.Fatalf(
					"engine diff final nonempty state is inconsistent: %#v",
					observation.Details,
				)
			}
			for _, key := range []string{
				"baselineDigest",
				"finalDigest",
			} {
				digest, ok := observation.Details[key].(string)
				if !ok || len(digest) != 71 ||
					!strings.HasPrefix(digest, "sha256:") {
					t.Fatalf(
						"engine diff %s is not an exact SHA-256: %#v",
						key,
						observation.Details[key],
					)
				}
			}
			for _, forbiddenKey := range []string{
				"path",
				"entries",
				"rawTranscript",
			} {
				if _, present := observation.Details[forbiddenKey]; present {
					t.Fatalf(
						"engine diff exposed %q: %#v",
						forbiddenKey,
						observation,
					)
				}
			}
			wire, err := json.Marshal(observation)
			if err != nil {
				t.Fatalf("marshal engine diff summary: %v", err)
			}
			for _, rawRecord := range [][]byte{
				[]byte("A /"),
				[]byte("C /"),
				[]byte("D /"),
			} {
				if bytes.Contains(wire, rawRecord) {
					t.Fatalf(
						"raw Docker diff record entered public evidence: %s",
						wire,
					)
				}
			}
			continue
		}
		if observation.Operation != "filesystem.retained-state.summary" {
			continue
		}
		summaryCount++
		if observation.Result != "observed" ||
			observation.Coverage != "high" ||
			observation.Confidence != "high" ||
			observation.Actor != "trusted-runner" ||
			observation.Observer !=
				result.Runner.Backend+"-filesystem-retained-state" {
			t.Fatalf(
				"retained-state summary trust envelope = %#v",
				observation,
			)
		}
		for key, want := range map[string]any{
			"scope":                            "outputs-retained-state",
			"snapshotBoundary":                 "post-init-pre-workload-to-post-quiesce-pre-repair",
			"includesTrustedHelpers":           true,
			"includesRunnerManagedDirectories": true,
			"contentIncluded":                  false,
			"publicEvidence":                   "aggregate-only",
			"actorAttribution":                 "unavailable",
			"baselineIdentityVerified":         true,
			"finalIdentityVerified":            true,
			"workloadQuiescenceVerified":       true,
			"baselineReady":                    true,
			"finalReady":                       true,
			"retainedStateCoverage":            "high",
		} {
			if observation.Details[key] != want {
				t.Fatalf(
					"retained-state details[%q] = %#v, want %#v",
					key,
					observation.Details[key],
					want,
				)
			}
		}
		changeCount, ok := observationInteger(
			observation.Details["changeCount"],
		)
		if !ok || changeCount < 0 || changeCount > 256 {
			t.Fatalf(
				"retained-state change count is not bounded: %#v",
				observation.Details["changeCount"],
			)
		}
		for _, key := range []string{"baselineDigest", "finalDigest"} {
			digest, ok := observation.Details[key].(string)
			if !ok || len(digest) != 71 ||
				!strings.HasPrefix(digest, "sha256:") {
				t.Fatalf(
					"retained-state %s is not an exact SHA-256: %#v",
					key,
					observation.Details[key],
				)
			}
		}
		wire, err := json.Marshal(observation)
		if err != nil {
			t.Fatalf("marshal retained-state summary: %v", err)
		}
		if bytes.Contains(wire, []byte("/outputs/")) {
			t.Fatalf(
				"raw workload-controlled output path entered public evidence: %s",
				wire,
			)
		}
	}
	if summaryCount != result.Repeats.Completed {
		t.Fatalf(
			"retained-state summaries = %d, want one per completed repeat (%d)",
			summaryCount,
			result.Repeats.Completed,
		)
	}
	if engineDiffSummaryCount != result.Repeats.Completed {
		t.Fatalf(
			"engine diff summaries = %d, want one per completed repeat (%d)",
			engineDiffSummaryCount,
			result.Repeats.Completed,
		)
	}
	if activityTraceSummaryCount != result.Repeats.Completed {
		t.Fatalf(
			"activity trace summaries = %d, want one per completed repeat (%d)",
			activityTraceSummaryCount,
			result.Repeats.Completed,
		)
	}
}

func assertUndeclaredRetainedWrite(
	t *testing.T,
	result domain.VerificationResult,
) {
	t.Helper()
	const rawMarker = "RAW-ALPHA23-UNDECLARED-PATH-MARKER"
	if len(result.Errors) != 1 || result.Errors[0] == nil ||
		result.Errors[0].Code != domain.CodeUndeclaredFilesystemWrite {
		t.Fatalf(
			"undeclared retained write must have exactly one sole-cause finding: %#v",
			result.Errors,
		)
	}

	summaryCount := 0
	for _, observation := range result.Observations {
		if observation.Operation != "filesystem.retained-state.summary" {
			continue
		}
		summaryCount++
		for key, want := range map[string]string{
			"declarationComparisonScope":   "executed-phase-filesystem-write-union",
			"declarationComparisonVersion": "0.1.0",
			"declarationComparisonResult":  "nonconforming-retained-state",
		} {
			if got, ok := observation.Details[key].(string); !ok || got != want {
				t.Fatalf(
					"undeclared write summary %s = %#v, want %q",
					key,
					observation.Details[key],
					want,
				)
			}
		}
		for key, want := range map[string]int{
			"declaredPatternCount":  1,
			"comparedChangeCount":   2,
			"allowedChangeCount":    1,
			"undeclaredChangeCount": 1,
			"createChangeCount":     2,
			"deleteChangeCount":     0,
			"modifyChangeCount":     0,
			"typeChangeCount":       0,
		} {
			got, ok := observationInteger(observation.Details[key])
			if !ok || got != want {
				t.Fatalf(
					"undeclared write summary %s = %#v, want %d",
					key,
					observation.Details[key],
					want,
				)
			}
		}
	}
	if summaryCount != result.Repeats.Completed {
		t.Fatalf(
			"undeclared write summaries = %d, want %d",
			summaryCount,
			result.Repeats.Completed,
		)
	}

	findingCount := 0
	var undeclaredFinding *domain.Error
	for _, finding := range result.Errors {
		if finding == nil ||
			finding.Code != domain.CodeUndeclaredFilesystemWrite {
			continue
		}
		findingCount++
		undeclaredFinding = finding
		if finding.Severity != domain.SeverityHigh {
			t.Fatalf("undeclared write finding severity = %q", finding.Severity)
		}
		if finding.Phase != "" || finding.Cause != nil ||
			len(finding.EvidenceRefs) != 0 || finding.Suggestion != "" ||
			finding.Retryable {
			t.Fatalf(
				"undeclared write finding overstated operation semantics: %#v",
				finding,
			)
		}
		if strings.Contains(finding.Error(), rawMarker) {
			t.Fatal("undeclared workload path entered finding error string")
		}
		for key, want := range map[string]int{
			"declaredPatternCount":  1,
			"comparedChangeCount":   2,
			"allowedChangeCount":    1,
			"undeclaredChangeCount": 1,
		} {
			got, ok := observationInteger(finding.Details[key])
			if !ok || got != want {
				t.Fatalf(
					"undeclared write finding %s = %#v, want %d",
					key,
					finding.Details[key],
					want,
				)
			}
		}
	}
	if findingCount != 1 {
		t.Fatalf("undeclared write findings = %d, want one deduplicated finding", findingCount)
	}
	findingWire, err := json.Marshal(undeclaredFinding)
	if err != nil {
		t.Fatalf("marshal undeclared write finding: %v", err)
	}

	publicJSON, err := rendering.JSON(result)
	if err != nil {
		t.Fatalf("render undeclared write JSON: %v", err)
	}
	publicHTML, err := rendering.HTML(result)
	if err != nil {
		t.Fatalf("render undeclared write HTML: %v", err)
	}
	resultWire, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal undeclared write result: %v", err)
	}
	publicValues := [][]byte{
		publicJSON,
		publicHTML,
		[]byte(rendering.Text(result)),
		resultWire,
		findingWire,
		[]byte(undeclaredFinding.Error()),
	}
	for index, value := range publicValues {
		for _, fragment := range []string{
			rawMarker,
			"RAW-ALPHA23",
			"UNDECLARED-PATH-MARKER",
		} {
			if bytes.Contains(value, []byte(fragment)) {
				t.Fatalf(
					"undeclared workload path fragment entered public surface %d",
					index,
				)
			}
		}
	}
	if _, err := privacy.Evaluate(publicJSON); err != nil {
		t.Fatalf("undeclared write public JSON failed privacy gate: %v", err)
	}
}

func assertOperationNotificationObservations(
	t *testing.T,
	result domain.VerificationResult,
	wantComparison string,
	wantFailure string,
) {
	t.Helper()
	if wantComparison == "" {
		wantComparison = "not-tested"
	}
	summaryCount := 0
	for _, observation := range result.Observations {
		if observation.Operation !=
			"filesystem.operation-notification.summary" {
			continue
		}
		summaryCount++
		if observation.SchemaVersion != "1" ||
			observation.Phase != domain.PhaseCleanup ||
			observation.Actor != "trusted-runner" ||
			observation.Resource != "/outputs" ||
			observation.Observer !=
				"docker-python-outputs-inotify-comparison" ||
			observation.Details["scope"] !=
				"outputs-operation-notification-comparison" ||
			observation.Details["publicEvidence"] != "aggregate-only" ||
			observation.Details["evidenceBasis"] != "aggregate-only" ||
			observation.Details["rawPathIncluded"] != false ||
			observation.Details["ruleTextIncluded"] != false ||
			observation.Details["contentIncluded"] != false ||
			observation.Details["actorAttribution"] != "unavailable" ||
			observation.Details["renamePairing"] != "unavailable" ||
			observation.Details["comparisonResult"] != wantComparison {
			t.Fatalf(
				"operation notification trust envelope = %#v",
				observation,
			)
		}
		wire, err := json.Marshal(observation)
		if err != nil {
			t.Fatalf("marshal operation notification summary: %v", err)
		}
		for _, forbidden := range [][]byte{
			[]byte("RAW-ALPHA24"),
			[]byte(`"token"`),
			[]byte(`"rawPath"`),
			[]byte(`"rules"`),
			[]byte("/outputs/RAW"),
		} {
			if bytes.Contains(wire, forbidden) {
				t.Fatalf(
					"operation notification public evidence leaked %q: %s",
					forbidden,
					wire,
				)
			}
		}
		if wantComparison == "not-tested" {
			if observation.Result != "unavailable" ||
				observation.Coverage != "unavailable" ||
				observation.Confidence != "unknown" {
				t.Fatalf(
					"not-tested operation comparison was overstated: %#v",
					observation,
				)
			}
			for _, key := range []string{
				"windowCount",
				"quiescenceWindowCount",
				"declaredPatternCount",
				"comparedNotificationCount",
				"allowedNotificationCount",
				"undeclaredNotificationCount",
				"mutationCounts",
			} {
				if _, present := observation.Details[key]; present {
					t.Fatalf(
						"not-tested comparison exposed partial %q: %#v",
						key,
						observation,
					)
				}
			}
			if wantFailure != "" &&
				observation.Details["failure"] != wantFailure {
				t.Fatalf(
					"not-tested operation failure = %#v, want %q",
					observation.Details["failure"],
					wantFailure,
				)
			}
			continue
		}
		if observation.Result != "observed" ||
			observation.Coverage != "best-effort" ||
			observation.Confidence != "high" ||
			observation.Details["preDispatchQuiescenceVerified"] != true ||
			observation.Details["postDispatchQuiescenceVerified"] != true ||
			observation.Details["phaseAcknowledgementsComplete"] != true {
			t.Fatalf(
				"complete operation comparison trust gates = %#v",
				observation,
			)
		}
		windowCount, windowOK := observationInteger(
			observation.Details["windowCount"],
		)
		quiescenceCount, quiescenceOK := observationInteger(
			observation.Details["quiescenceWindowCount"],
		)
		compared, comparedOK := observationInteger(
			observation.Details["comparedNotificationCount"],
		)
		allowed, allowedOK := observationInteger(
			observation.Details["allowedNotificationCount"],
		)
		undeclared, undeclaredOK := observationInteger(
			observation.Details["undeclaredNotificationCount"],
		)
		if !windowOK || !quiescenceOK || windowCount < 1 ||
			windowCount != quiescenceCount || !comparedOK || !allowedOK ||
			!undeclaredOK || compared < 0 || compared > 4096 ||
			allowed+undeclared != compared {
			t.Fatalf(
				"operation notification aggregate algebra is invalid: %#v",
				observation.Details,
			)
		}
		if wantComparison == "nonconforming-notifications" &&
			undeclared < 1 ||
			wantComparison == "no-undeclared-observed" && undeclared != 0 {
			t.Fatalf(
				"operation comparison/count mismatch: %#v",
				observation.Details,
			)
		}
	}
	if summaryCount != result.Repeats.Completed {
		t.Fatalf(
			"operation notification summaries = %d, want %d",
			summaryCount,
			result.Repeats.Completed,
		)
	}
}

func assertUndeclaredOperationNotification(
	t *testing.T,
	result domain.VerificationResult,
) {
	t.Helper()
	if len(result.Errors) != 1 || result.Errors[0] == nil ||
		result.Errors[0].Code != domain.CodeUndeclaredFilesystemWrite {
		t.Fatalf(
			"operation-positive run must have one aggregate finding: %#v",
			result.Errors,
		)
	}
	finding := result.Errors[0]
	undeclared, ok := observationInteger(
		finding.Details["undeclaredNotificationCount"],
	)
	if finding.Phase != "" || finding.Severity != domain.SeverityHigh ||
		finding.Details["observer"] !=
			"docker-python-outputs-inotify-comparison" ||
		finding.Details["evidenceBasis"] != "aggregate-only" ||
		!ok || undeclared < 1 {
		t.Fatalf("operation-positive finding = %#v", finding)
	}
	for _, observation := range result.Observations {
		if observation.Operation == "filesystem.retained-state.summary" &&
			observation.Details["declarationComparisonResult"] ==
				"nonconforming-retained-state" {
			t.Fatalf(
				"fixture unexpectedly relied on retained-state finding: %#v",
				observation,
			)
		}
	}
	publicJSON, err := rendering.JSON(result)
	if err != nil {
		t.Fatalf("render operation-positive JSON: %v", err)
	}
	publicHTML, err := rendering.HTML(result)
	if err != nil {
		t.Fatalf("render operation-positive HTML: %v", err)
	}
	for index, value := range [][]byte{
		publicJSON,
		publicHTML,
		[]byte(rendering.Text(result)),
	} {
		for _, fragment := range []string{
			"RAW-ALPHA24",
			"TRANSIENT-PATH-MARKER",
			"RESTORE-CONTENT-MARKER",
			"WRONG-PHASE-PATH-MARKER",
		} {
			if bytes.Contains(value, []byte(fragment)) {
				t.Fatalf(
					"operation marker entered public surface %d: %s",
					index,
					value,
				)
			}
		}
	}
	if _, err := privacy.Evaluate(publicJSON); err != nil {
		t.Fatalf("operation-positive JSON failed privacy gate: %v", err)
	}
}

func assertUndeclaredPeerPortListener(
	t *testing.T,
	result domain.VerificationResult,
) {
	t.Helper()
	const syntheticEndpoint = "127.0.0.1:18081/tcp"
	if result.Repeats.Requested != 3 || result.Repeats.Completed != 3 ||
		result.Repeats.Matching != 3 {
		t.Fatalf("Alpha.25 repeats = %#v, want three exact completed matches", result.Repeats)
	}
	if len(result.Errors) != 1 || result.Errors[0] == nil ||
		result.Errors[0].Code != domain.CodeUndeclaredPortListen {
		t.Fatalf("Alpha.25 must have one aggregate undeclared-listener finding: %#v", result.Errors)
	}
	finding := result.Errors[0]
	if finding.Phase != "" || finding.Severity != domain.SeverityHigh ||
		finding.Cause != nil || len(finding.EvidenceRefs) != 0 ||
		finding.Suggestion != "" || finding.Retryable ||
		len(finding.Details) != 3 {
		t.Fatalf("Alpha.25 listener finding overstates private observation: %#v", finding)
	}
	for key, want := range map[string]string{
		"observer":      "docker-peer-port-listener-trace",
		"evidenceBasis": "aggregate-only",
	} {
		if finding.Details[key] != want {
			t.Fatalf("Alpha.25 listener finding[%q] = %#v, want %#v", key, finding.Details[key], want)
		}
	}
	undeclaredCount, ok := observationInteger(
		finding.Details["undeclaredEndpointCount"],
	)
	if !ok || undeclaredCount != 1 {
		t.Fatalf(
			"Alpha.25 listener finding[%q] = %#v, want exact integer 1",
			"undeclaredEndpointCount",
			finding.Details["undeclaredEndpointCount"],
		)
	}

	summaryCount := 0
	for _, observation := range result.Observations {
		if observation.Operation != "port.listener-trace.summary" {
			continue
		}
		summaryCount++
		if observation.Resource != "tcp-listeners" ||
			observation.Observer != "docker-peer-port-listener-trace" ||
			observation.Result != "observed" ||
			observation.Coverage != "best-effort" ||
			observation.Confidence != "high" ||
			observation.Details["comparisonResult"] != "nonconforming-listeners" ||
			observation.Details["evidenceBasis"] != "aggregate-only" {
			t.Fatalf("Alpha.25 listener summary trust contract = %#v", observation)
		}
		for key, want := range map[string]int{
			"baselineEndpointCount":   0,
			"declaredEndpointCount":   1,
			"sampledEndpointCount":    2,
			"undeclaredEndpointCount": 1,
		} {
			got, ok := observationInteger(observation.Details[key])
			if !ok || got != want {
				t.Fatalf("Alpha.25 listener summary %s = %#v, want %d", key, observation.Details[key], want)
			}
		}
		for _, forbidden := range []string{
			"declaredEndpoints",
			"declaredObservedEndpoints",
			"declaredClosedEndpoints",
			"observedEndpoints",
			"initialEndpoints",
			"finalEndpoints",
		} {
			if _, present := observation.Details[forbidden]; present {
				t.Fatalf("Alpha.25 public summary exposed %q: %#v", forbidden, observation)
			}
		}
		wire, err := json.Marshal(observation)
		if err != nil {
			t.Fatalf("marshal Alpha.25 listener summary: %v", err)
		}
		if bytes.Contains(wire, []byte(syntheticEndpoint)) ||
			bytes.Contains(wire, []byte("18081")) {
			t.Fatalf("Alpha.25 listener summary leaked synthetic endpoint: %s", wire)
		}
	}
	if summaryCount != result.Repeats.Completed {
		t.Fatalf("Alpha.25 listener summaries = %d, want one per completed repeat (%d)", summaryCount, result.Repeats.Completed)
	}

	publicJSON, err := rendering.JSON(result)
	if err != nil {
		t.Fatalf("render Alpha.25 listener JSON: %v", err)
	}
	publicHTML, err := rendering.HTML(result)
	if err != nil {
		t.Fatalf("render Alpha.25 listener HTML: %v", err)
	}
	for index, value := range [][]byte{
		publicJSON,
		publicHTML,
		[]byte(rendering.Text(result)),
	} {
		if bytes.Contains(value, []byte(syntheticEndpoint)) ||
			bytes.Contains(value, []byte("18081")) {
			t.Fatalf("Alpha.25 public surface %d leaked synthetic endpoint", index)
		}
	}
	if _, err := privacy.Evaluate(publicJSON); err != nil {
		if blocked, ok := err.(*domain.Error); ok {
			t.Fatalf(
				"Alpha.25 listener JSON failed privacy gate: rules=%v surfaces=%v findings=%v",
				blocked.Details["ruleIds"],
				blocked.Details["surfaces"],
				blocked.Details["findingCount"],
			)
		}
		t.Fatalf("Alpha.25 listener JSON failed privacy gate: %v", err)
	}
}

func assertActivityTraceObservation(
	t *testing.T,
	result domain.VerificationResult,
	observation domain.ObservationEvent,
	wantFailure string,
) {
	t.Helper()
	if observation.SchemaVersion != "1" ||
		observation.Phase != domain.PhaseCleanup ||
		observation.Actor != "trusted-runner" ||
		observation.Resource != "/outputs" ||
		observation.Observer != "docker-outputs-activity-trace" {
		t.Fatalf("activity trace metadata = %#v", observation)
	}
	for key, want := range map[string]any{
		"scope": "outputs-activity-notification-trace",
		"traceBoundary": "post-preflight-pre-workload-to-" +
			"post-quiesce-pre-retained-final",
		"notificationSemantics": "runtime-filesystem-" +
			"notification-hints",
		"rawPathIncluded":             false,
		"contentIncluded":             false,
		"publicEvidence":              "aggregate-only",
		"actorAttribution":            "unavailable",
		"phaseAttribution":            "controller-window-hint",
		"operationClassification":     "hint-only",
		"operationHistoryCoverage":    "unavailable",
		"observerPlacement":           "in-sandbox-trusted-helper",
		"sharesSandboxResourceBudget": true,
		"transport":                   "controller-stdin-stdout-jsonl",
	} {
		if observation.Details[key] != want {
			t.Fatalf(
				"activity trace details[%q] = %#v, want %#v",
				key,
				observation.Details[key],
				want,
			)
		}
	}
	for key, want := range map[string]int{
		"transportBoundBytes": 16384,
		"notificationLimit":   4096,
		"watchLimit":          2048,
	} {
		got, ok := observationInteger(observation.Details[key])
		if !ok || got != want {
			t.Fatalf(
				"activity trace details[%q] = %#v, want %d",
				key,
				observation.Details[key],
				want,
			)
		}
	}
	if result.Runner.Backend == "podman" {
		if wantFailure != "" {
			t.Fatalf("Podman cannot satisfy Docker activity failure %q", wantFailure)
		}
		if observation.Result != "unavailable" ||
			observation.Coverage != "unavailable" ||
			observation.Confidence != "unknown" ||
			observation.Details["activityTraceCoverage"] !=
				"unavailable" ||
			observation.Details["failure"] !=
				"backend-not-live-qualified" {
			t.Fatalf(
				"Podman activity trace availability was overstated: %#v",
				observation,
			)
		}
		for _, key := range []string{
			"observerAdapter",
			"notificationCount",
			"renameHintCount",
			"changeHintCount",
			"phaseCounts",
			"canonicalTranscriptDigest",
			"canonicalByteCount",
			"kernelOverflowDetection",
		} {
			if _, present := observation.Details[key]; present {
				t.Fatalf(
					"unavailable Podman activity trace exposed %q: %#v",
					key,
					observation,
				)
			}
		}
		return
	}
	if wantFailure != "" {
		if result.Runner.Backend != "docker" ||
			observation.Result != "unavailable" ||
			observation.Coverage != "unavailable" ||
			observation.Confidence != "unknown" ||
			observation.Details["activityTraceCoverage"] != "unavailable" ||
			observation.Details["failure"] != wantFailure {
			t.Fatalf(
				"Docker fail-closed activity trace = %#v, want failure %q",
				observation,
				wantFailure,
			)
		}
		for _, key := range []string{
			"startIdentityVerified",
			"readyIdentityVerified",
			"stopIdentityVerified",
			"finalIdentityVerified",
			"workloadQuiescenceVerified",
		} {
			if observation.Details[key] != true {
				t.Fatalf(
					"fail-closed activity identity gate %q = %#v",
					key,
					observation.Details[key],
				)
			}
		}
		for _, key := range []string{
			"observerAdapter",
			"notificationCount",
			"renameHintCount",
			"changeHintCount",
			"phaseCounts",
			"canonicalTranscriptDigest",
			"canonicalByteCount",
			"kernelOverflowDetection",
		} {
			if _, present := observation.Details[key]; present {
				t.Fatalf(
					"fail-closed activity trace exposed partial %q: %#v",
					key,
					observation,
				)
			}
		}
		return
	}
	if result.Runner.Backend != "docker" ||
		observation.Result != "observed" ||
		observation.Coverage != "best-effort" ||
		observation.Confidence != "high" ||
		observation.Details["activityTraceCoverage"] != "best-effort" {
		t.Fatalf("Docker activity trace trust envelope = %#v", observation)
	}
	for _, key := range []string{
		"startIdentityVerified",
		"readyIdentityVerified",
		"stopIdentityVerified",
		"finalIdentityVerified",
		"workloadQuiescenceVerified",
	} {
		if observation.Details[key] != true {
			t.Fatalf(
				"activity trace identity gate %q = %#v",
				key,
				observation.Details[key],
			)
		}
	}
	adapter, ok := observation.Details["observerAdapter"].(string)
	if !ok {
		t.Fatalf("activity trace adapter = %#v", observation.Details)
	}
	switch adapter {
	case "node-fs-watch-linux":
		if observation.Details["kernelOverflowDetection"] != "unavailable" {
			t.Fatalf("Node overflow semantics = %#v", observation.Details)
		}
	case "python-inotify-linux":
		if observation.Details["kernelOverflowDetection"] !=
			"inotify-queue-overflow-fail-closed" {
			t.Fatalf("Python overflow semantics = %#v", observation.Details)
		}
	default:
		t.Fatalf("unexpected activity trace adapter %q", adapter)
	}
	notificationCount, notificationOK := observationInteger(
		observation.Details["notificationCount"],
	)
	renameCount, renameOK := observationInteger(
		observation.Details["renameHintCount"],
	)
	changeCount, changeOK := observationInteger(
		observation.Details["changeHintCount"],
	)
	if !notificationOK || !renameOK || !changeOK ||
		notificationCount < 0 || notificationCount > 4096 ||
		renameCount < 0 || changeCount < 0 ||
		renameCount+changeCount != notificationCount {
		t.Fatalf("activity trace counts are invalid: %#v", observation.Details)
	}
	phaseTotal, phaseOK := activityTracePhaseTotal(
		observation.Details["phaseCounts"],
	)
	if !phaseOK || phaseTotal != notificationCount {
		t.Fatalf(
			"activity trace phase counts are invalid: %#v",
			observation.Details,
		)
	}
	canonicalBytes, bytesOK := observationInteger(
		observation.Details["canonicalByteCount"],
	)
	digest, digestOK :=
		observation.Details["canonicalTranscriptDigest"].(string)
	if !bytesOK || canonicalBytes < 0 || canonicalBytes > 1<<20 ||
		!digestOK || !exactLowerSHA256(digest) {
		t.Fatalf(
			"activity trace commitment is invalid: %#v",
			observation.Details,
		)
	}
	wire, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("marshal activity trace summary: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"sessionDigest"`),
		[]byte(`"token"`),
		[]byte(`"rawPath"`),
		[]byte(`"path":`),
	} {
		if bytes.Contains(wire, forbidden) {
			t.Fatalf(
				"activity trace public evidence leaked %s: %s",
				forbidden,
				wire,
			)
		}
	}
}

func activityTracePhaseTotal(value any) (int, bool) {
	var values []string
	switch typed := value.(type) {
	case []string:
		values = typed
	case []any:
		values = make([]string, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return 0, false
			}
			values[index] = text
		}
	default:
		return 0, false
	}
	names := [...]string{
		"setup",
		"build",
		"run",
		"exercise",
		"cleanup",
		"unknown",
	}
	if len(values) != len(names) {
		return 0, false
	}
	total := 0
	for index, name := range names {
		raw, found := strings.CutPrefix(values[index], name+"=")
		if !found || raw == "" {
			return 0, false
		}
		count, err := strconv.Atoi(raw)
		if err != nil || count < 0 || count > 4096 ||
			total > 4096-count {
			return 0, false
		}
		total += count
	}
	return total, true
}

func exactLowerSHA256(value string) bool {
	if len(value) != len("sha256:")+64 ||
		!strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func assertTermSignalEscalated(
	t *testing.T,
	observations []domain.ObservationEvent,
) {
	t.Helper()
	for _, observation := range observations {
		if observation.Operation != "service.signal" ||
			observation.Result != "succeeded" {
			continue
		}
		signalName, _ := observation.Details["signal"].(string)
		escalated, _ := observation.Details["escalated"].(bool)
		initialTargets, initialOK := observationInteger(
			observation.Details["initialTargets"],
		)
		sent, sentOK := observationInteger(observation.Details["sent"])
		remaining, remainingOK := observationInteger(
			observation.Details["remaining"],
		)
		if signalName == "TERM" &&
			escalated &&
			initialOK &&
			initialTargets >= 2 &&
			sentOK &&
			sent >= 1 &&
			sent <= initialTargets &&
			remainingOK &&
			remaining == 0 {
			return
		}
		t.Fatalf(
			"TERM-resistant case has an invalid signal envelope: %#v",
			observation,
		)
	}
	t.Fatal("TERM-resistant case has no successful service.signal observation")
}

func observationInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case float64:
		integer := int(typed)
		return integer, typed == float64(integer)
	default:
		return 0, false
	}
}

func assertNoCleanupPrivatePath(t *testing.T, value string) {
	t.Helper()
	for _, privateValue := range []string{
		"escape-link",
		"/etc/shadow",
		"leak.json",
	} {
		if strings.Contains(value, privateValue) {
			t.Fatalf(
				"public cleanup evidence leaked private value %q: %s",
				privateValue,
				value,
			)
		}
	}
}

func TestContainerHTTPServiceFailures(t *testing.T) {
	backend := integrationBackend(t)
	runner, err := execution.Doctor(context.Background(), backend)
	if err != nil {
		t.Fatalf("%s doctor failed: %v", backend, err)
	}
	if !runner.Available || runner.WorkloadOS != "linux" {
		t.Fatalf("integration runner is not an available Linux engine: %#v", runner)
	}

	tests := []struct {
		name     string
		fixture  string
		wantCode domain.ErrorCode
	}{
		{
			name:     "service exits before readiness",
			fixture:  filepath.Join("malicious", "http-service-early-exit"),
			wantCode: domain.CodeServiceStartFailed,
		},
		{
			name:     "service never becomes ready",
			fixture:  filepath.Join("malicious", "http-never-ready"),
			wantCode: domain.CodeReadinessFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataRoot := t.TempDir()
			manifestPath, err := filepath.Abs(filepath.Join(
				"..", "..", "testdata", "fixtures", test.fixture, "repo-passport.yml",
			))
			if err != nil {
				t.Fatalf("resolve fixture manifest: %v", err)
			}

			var stdout, stderr bytes.Buffer
			app := App{
				Deps: Dependencies{
					ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
						return []domain.RunnerFeatures{runner}, nil
					},
					Execute: containerIntegrationExecute,
				},
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			}
			exitCode := app.Run(context.Background(), []string{
				"--json",
				"--data-dir", dataRoot,
				"verify",
				"--runner", backend,
				"--manifest", manifestPath,
				"--scenario", "quickstart",
			})
			if exitCode != 0 {
				t.Fatalf(
					"verify exit code = %d; stdout: %s; stderr: %s",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}

			response := decodeEnvelope(t, stdout.Bytes())
			var data verifyEnvelopeData
			decodeJSON(t, response.Data, &data)
			result := data.Verification
			if result.Results.Functional != domain.FunctionalFail {
				t.Fatalf(
					"functional verdict = %q, want fail; findings: %v",
					result.Results.Functional,
					result.Errors,
				)
			}
			if result.Results.Capability != domain.CapabilityIncomplete {
				t.Fatalf(
					"capability verdict = %q, want incomplete",
					result.Results.Capability,
				)
			}
			if result.Results.Cleanup != domain.CleanupClean {
				t.Fatalf(
					"cleanup verdict = %q, want clean; findings: %v",
					result.Results.Cleanup,
					result.Errors,
				)
			}
			if result.Results.Overall != domain.OverallFailed {
				t.Fatalf(
					"overall verdict = %q, want failed",
					result.Results.Overall,
				)
			}
			if !containsErrorCode(result.Errors, test.wantCode) {
				t.Fatalf(
					"findings do not contain %s: %#v",
					test.wantCode,
					result.Errors,
				)
			}
			assertContainersRemoved(t, backend, result.Observations)
		})
	}
}

func TestContainerDiskQuotaExpectedDenial(t *testing.T) {
	backend := strings.ToLower(strings.TrimSpace(
		os.Getenv("REPOPASS_INTEGRATION_BACKEND"),
	))
	if backend == "" {
		t.Skip("set REPOPASS_INTEGRATION_BACKEND=docker or podman to run live container tests")
	}
	if backend != "docker" && backend != "podman" {
		t.Fatalf("REPOPASS_INTEGRATION_BACKEND = %q, want docker or podman", backend)
	}

	sourceRoot := t.TempDir()
	script := `const fs=require("node:fs");` +
		`const target="/outputs/overflow.bin",chunk=Buffer.alloc(65536,0x61);` +
		`let fd,written=0;` +
		`try{fd=fs.openSync(target,"w");while(written<2097152){written+=fs.writeSync(fd,chunk);}` +
		`console.error("quota-missing:wrote-"+written);process.exitCode=0;}` +
		`catch(error){if(error.code!=="ENOSPC")throw error;` +
		`console.error("quota-enforced:ENOSPC");process.exitCode=23;}` +
		`finally{if(fd!==undefined)fs.closeSync(fd);}`
	if err := os.WriteFile(
		filepath.Join(sourceRoot, "overflow.cjs"),
		[]byte(script),
		0o644,
	); err != nil {
		t.Fatalf("write overflow fixture: %v", err)
	}
	snapshot, err := acquisition.NewLocalProvider().Fetch(
		context.Background(),
		domain.ResolvedSource{Kind: "local", LocalPath: sourceRoot},
	)
	if err != nil {
		t.Fatalf("inventory overflow fixture: %v", err)
	}
	expectedExit := 23
	diskLimit := int64(1 << 20)
	plan := currentDirectCLIPlan(domain.ResolvedPlan{
		Source: domain.PlanSource{
			Identity:   snapshot.Identity,
			TreeDigest: snapshot.TreeDigest,
		},
		PlanDigest:         "sha256:" + strings.Repeat("b", 64),
		RuntimeAdapter:     "node",
		RuntimeVersion:     runtimepolicy.NodeVersion,
		BaseImageReference: runtimepolicy.NodeReference,
		BaseImageDigest:    runtimepolicy.NodeDigest,
		Resources: domain.ResourceLimits{
			CPUMillis:   1000,
			MemoryBytes: 256 << 20,
			DiskBytes:   diskLimit,
			PIDs:        64,
		},
		Commands: []domain.PlanCommand{{
			Phase:   domain.PhaseExercise,
			ID:      "overflow",
			Argv:    []string{"node", "/workspace/overflow.cjs"},
			Timeout: "30s",
			Role:    "journey",
		}},
		JourneyAssertions: []domain.PlanAssertion{
			{ID: "quota-exit", ExitCode: &expectedExit},
			{ID: "quota-stderr", StderrContains: "quota-enforced:ENOSPC"},
		},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {
				Network: domain.NetworkCapability{Deny: true},
				Filesystem: domain.FilesystemCapability{
					Read:  []string{"/workspace/**"},
					Write: []string{"/outputs/**"},
				},
			},
		},
		RequiredRunnerFeatures: []string{
			"linux-container",
			"platform:linux/amd64",
			"read-only-source",
			"isolated-workspace",
			"network-deny",
			"bounded-logs",
			"process-cleanup",
		},
	})

	outcome, err := execution.Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		backend,
	)
	if err != nil {
		t.Fatalf("expected quota denial did not pass its declarations: %v; outcome %#v", err, outcome)
	}
	if len(outcome.Steps) != 1 ||
		outcome.Steps[0].ExitCode != expectedExit ||
		outcome.Cleanup != domain.CleanupAllowedResidue {
		t.Fatalf(
			"quota denial outcome = %#v, want exit=%d cleanup=allowed-residue",
			outcome,
			expectedExit,
		)
	}
	for _, assertion := range outcome.Assertions {
		if assertion.Status != "passed" {
			t.Fatalf("quota assertion = %#v", assertion)
		}
	}
	outputInfo, statErr := os.Stat(filepath.Join(outcome.OutputsDir, "overflow.bin"))
	if statErr != nil {
		t.Fatalf("stat bounded partial output: %v", statErr)
	}
	if outputInfo.Size() <= 0 || outputInfo.Size() > diskLimit {
		t.Fatalf(
			"bounded partial output size = %d, want 1..%d",
			outputInfo.Size(),
			diskLimit,
		)
	}
	if _, statErr := os.Stat(filepath.Join(sourceRoot, "overflow.bin")); !os.IsNotExist(statErr) {
		t.Fatalf("overflow escaped into source tree: %v", statErr)
	}
}

func TestContainerResourceUsageObservation(t *testing.T) {
	backend := integrationBackend(t)
	if backend != "docker" {
		t.Skip("the alpha.4 resource-usage live gate is qualified for Docker")
	}

	const (
		allocationBytes = int64(16 << 20)
		outputBytes     = int64(64 << 10)
		memoryLimit     = int64(128 << 20)
		diskLimit       = int64(4 << 20)
		pidsLimit       = 32
	)
	sourceRoot := t.TempDir()
	script := `const fs=require("node:fs");` +
		`const allocation=Buffer.alloc(16777216,0x5a);` +
		`const deadline=process.hrtime.bigint()+350000000n;let checksum=0;` +
		`while(process.hrtime.bigint()<deadline){` +
		`for(let offset=0;offset<allocation.length;offset+=4096){` +
		`checksum=(checksum+allocation[offset])>>>0;}}` +
		`const output=Buffer.alloc(65536,checksum&0xff);` +
		`fs.writeFileSync("/outputs/resource.bin",output);` +
		`if(fs.statSync("/outputs/resource.bin").size!==output.length)throw new Error("size");` +
		`console.log("resource-observer-workload-ok:"+checksum);`
	if err := os.WriteFile(
		filepath.Join(sourceRoot, "resource-observer.cjs"),
		[]byte(script),
		0o644,
	); err != nil {
		t.Fatalf("write resource observer fixture: %v", err)
	}
	snapshot, err := acquisition.NewLocalProvider().Fetch(
		context.Background(),
		domain.ResolvedSource{Kind: "local", LocalPath: sourceRoot},
	)
	if err != nil {
		t.Fatalf("inventory resource observer fixture: %v", err)
	}
	expectedExit := 0
	plan := currentDirectCLIPlan(domain.ResolvedPlan{
		Source: domain.PlanSource{
			Identity:   snapshot.Identity,
			TreeDigest: snapshot.TreeDigest,
		},
		PlanDigest:         "sha256:" + strings.Repeat("c", 64),
		RuntimeAdapter:     "node",
		RuntimeVersion:     runtimepolicy.NodeVersion,
		BaseImageReference: runtimepolicy.NodeReference,
		BaseImageDigest:    runtimepolicy.NodeDigest,
		Resources: domain.ResourceLimits{
			CPUMillis:   500,
			MemoryBytes: memoryLimit,
			DiskBytes:   diskLimit,
			PIDs:        pidsLimit,
		},
		Commands: []domain.PlanCommand{{
			Phase:   domain.PhaseExercise,
			ID:      "resource-workload",
			Argv:    []string{"node", "/workspace/resource-observer.cjs"},
			Timeout: "30s",
			Role:    "journey",
		}},
		JourneyAssertions: []domain.PlanAssertion{
			{ID: "resource-exit", ExitCode: &expectedExit},
			{
				ID:             "resource-stdout",
				StdoutContains: "resource-observer-workload-ok:",
			},
			{
				ID:         "resource-output",
				FileExists: "/outputs/resource.bin",
			},
		},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {
				Network: domain.NetworkCapability{Deny: true},
				Filesystem: domain.FilesystemCapability{
					Read:  []string{"/workspace/**"},
					Write: []string{"/outputs/**"},
				},
			},
		},
		RequiredRunnerFeatures: []string{
			"linux-container",
			"platform:linux/amd64",
			"read-only-source",
			"isolated-workspace",
			"network-deny",
			"bounded-logs",
			"process-cleanup",
			"observer:resource-usage",
		},
		ObserverSet:      []string{"resource-usage"},
		ObserverVersions: map[string]string{"resource-usage": "0.2.0"},
	})

	outcome, err := execution.Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		backend,
	)
	if err != nil {
		t.Fatalf("resource-usage observation failed: %v; outcome %#v", err, outcome)
	}
	if outcome.Runner.ResourceUsage != "high" {
		t.Fatalf(
			"resource usage coverage = %q, want high",
			outcome.Runner.ResourceUsage,
		)
	}
	if !outcome.Runner.ResourceLimitEnforcement {
		t.Fatal("resource limit enforcement was not actively verified")
	}
	if len(outcome.IncompleteFeatures) != 0 {
		t.Fatalf(
			"completed resource observer remains incomplete: %#v",
			outcome.IncompleteFeatures,
		)
	}
	if outcome.Cleanup != domain.CleanupAllowedResidue {
		t.Fatalf(
			"resource workload cleanup = %q, want allowed-residue; errors: %#v",
			outcome.Cleanup,
			outcome.Errors,
		)
	}
	if len(outcome.Errors) != 0 {
		t.Fatalf("resource workload findings = %#v, want none", outcome.Errors)
	}
	if len(outcome.Steps) != 1 || outcome.Steps[0].ExitCode != expectedExit {
		t.Fatalf("resource workload steps = %#v", outcome.Steps)
	}
	for _, assertion := range outcome.Assertions {
		if assertion.Status != "passed" {
			t.Fatalf("resource workload assertion = %#v", assertion)
		}
	}

	wantObservedFields := []domain.ResourceObservedField{
		domain.ResourceObservedMaxTasks,
		domain.ResourceObservedOutputBytes,
		domain.ResourceObservedSandboxCPUTimeMillis,
		domain.ResourceObservedSandboxPeakMemoryBytes,
		domain.ResourceObservedWritableBytes,
	}
	if len(outcome.Resources.ObservedFields) != len(wantObservedFields) {
		t.Fatalf(
			"observed resource fields = %#v, want %#v",
			outcome.Resources.ObservedFields,
			wantObservedFields,
		)
	}
	for index, want := range wantObservedFields {
		if outcome.Resources.ObservedFields[index] != want {
			t.Fatalf(
				"observed resource field %d = %q, want %q",
				index,
				outcome.Resources.ObservedFields[index],
				want,
			)
		}
	}
	if outcome.Resources.OutputBytes != outputBytes {
		t.Fatalf(
			"observed output bytes = %d, want exactly %d",
			outcome.Resources.OutputBytes,
			outputBytes,
		)
	}
	if outcome.Resources.WritableBytes < outputBytes ||
		outcome.Resources.WritableBytes > diskLimit {
		t.Fatalf(
			"writable snapshot bytes = %d, want %d..%d",
			outcome.Resources.WritableBytes,
			outputBytes,
			diskLimit,
		)
	}
	if outcome.Resources.SandboxPeakMemoryBytes < allocationBytes ||
		outcome.Resources.SandboxPeakMemoryBytes > memoryLimit {
		t.Fatalf(
			"sandbox peak memory bytes = %d, want %d..%d",
			outcome.Resources.SandboxPeakMemoryBytes,
			allocationBytes,
			memoryLimit,
		)
	}
	if outcome.Resources.SandboxCPUTimeMillis < 25 ||
		outcome.Resources.DurationMillis <= 0 {
		t.Fatalf(
			"resource timing is implausible: cpu=%dms duration=%dms",
			outcome.Resources.SandboxCPUTimeMillis,
			outcome.Resources.DurationMillis,
		)
	}
	if outcome.Resources.MaxTasks < 1 ||
		outcome.Resources.MaxTasks > pidsLimit {
		t.Fatalf(
			"max tasks = %d, want 1..%d",
			outcome.Resources.MaxTasks,
			pidsLimit,
		)
	}
	outputInfo, statErr := os.Stat(
		filepath.Join(outcome.OutputsDir, "resource.bin"),
	)
	if statErr != nil {
		t.Fatalf("stat exported resource output: %v", statErr)
	}
	if outputInfo.Size() != outputBytes {
		t.Fatalf(
			"exported resource output size = %d, want %d",
			outputInfo.Size(),
			outputBytes,
		)
	}
	assertResourceUsageObservations(t, outcome.Observations)
	assertContainersRemoved(t, backend, outcome.Observations)
}

func TestContainerOutputsActivityTraceObservation(t *testing.T) {
	backend := integrationBackend(t)
	if backend != "docker" {
		t.Skip("the alpha.7 activity-trace live gate is qualified for Docker")
	}

	const (
		transientDirectory = "activity-dynamic-b8447953"
		transientFile      = "transient-child-01d7c3f9.tmp"
	)
	sourceRoot := t.TempDir()
	script := `const fs=require("node:fs");` +
		`const pause=ms=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,ms);` +
		`const root="/outputs/` + transientDirectory + `";` +
		`const child=root+"/` + transientFile + `";` +
		`fs.mkdirSync(root);pause(250);` +
		`fs.writeFileSync(child,"first");fs.appendFileSync(child,"-second");` +
		`pause(100);fs.unlinkSync(child);pause(100);` +
		`if(fs.existsSync(child))throw new Error("transient-child-retained");` +
		`console.log("activity-trace-dynamic-watch-ok");`
	if err := os.WriteFile(
		filepath.Join(sourceRoot, "activity-trace.cjs"),
		[]byte(script),
		0o644,
	); err != nil {
		t.Fatalf("write activity trace fixture: %v", err)
	}
	snapshot, err := acquisition.NewLocalProvider().Fetch(
		context.Background(),
		domain.ResolvedSource{Kind: "local", LocalPath: sourceRoot},
	)
	if err != nil {
		t.Fatalf("inventory activity trace fixture: %v", err)
	}
	expectedExit := 0
	plan := currentDirectCLIPlan(domain.ResolvedPlan{
		Source: domain.PlanSource{
			Identity:   snapshot.Identity,
			TreeDigest: snapshot.TreeDigest,
		},
		PlanDigest:         "sha256:" + strings.Repeat("d", 64),
		RuntimeAdapter:     "node",
		RuntimeVersion:     runtimepolicy.NodeVersion,
		BaseImageReference: runtimepolicy.NodeReference,
		BaseImageDigest:    runtimepolicy.NodeDigest,
		Resources: domain.ResourceLimits{
			CPUMillis:   1000,
			MemoryBytes: 256 << 20,
			DiskBytes:   4 << 20,
			PIDs:        64,
		},
		Commands: []domain.PlanCommand{{
			Phase:   domain.PhaseExercise,
			ID:      "activity-trace-workload",
			Argv:    []string{"node", "/workspace/activity-trace.cjs"},
			Timeout: "30s",
			Role:    "journey",
		}},
		JourneyAssertions: []domain.PlanAssertion{
			{ID: "activity-trace-exit", ExitCode: &expectedExit},
			{
				ID:             "activity-trace-stdout",
				StdoutContains: "activity-trace-dynamic-watch-ok",
			},
		},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {
				Network: domain.NetworkCapability{Deny: true},
				Filesystem: domain.FilesystemCapability{
					Read:  []string{"/workspace/**"},
					Write: []string{"/outputs/**"},
				},
			},
		},
		RequiredRunnerFeatures: []string{
			"linux-container",
			"platform:linux/amd64",
			"read-only-source",
			"isolated-workspace",
			"network-deny",
			"bounded-logs",
			"process-cleanup",
			"observer:filesystem-write",
		},
		ObserverSet: []string{"filesystem-write"},
		ObserverVersions: map[string]string{
			"filesystem-write": "0.4.0",
		},
	})

	outcome, err := execution.Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		backend,
	)
	if err != nil {
		t.Fatalf(
			"activity trace observation failed: %v; outcome %#v",
			err,
			outcome,
		)
	}
	if outcome.Cleanup != domain.CleanupAllowedResidue {
		t.Fatalf(
			"activity workload cleanup = %q, want allowed-residue; errors: %#v",
			outcome.Cleanup,
			outcome.Errors,
		)
	}
	if outcome.Runner.FilesystemWriteObservation != "best-effort" {
		t.Fatalf(
			"composite filesystem coverage = %q, want best-effort",
			outcome.Runner.FilesystemWriteObservation,
		)
	}
	if !containsExactString(
		outcome.IncompleteFeatures,
		"observer:filesystem-write",
	) {
		t.Fatalf(
			"required filesystem observer was incorrectly completed: %#v",
			outcome.IncompleteFeatures,
		)
	}
	if len(outcome.Steps) != 1 ||
		outcome.Steps[0].ExitCode != expectedExit {
		t.Fatalf("activity workload steps = %#v", outcome.Steps)
	}
	for _, assertion := range outcome.Assertions {
		if assertion.Status != "passed" {
			t.Fatalf("activity workload assertion = %#v", assertion)
		}
	}

	summaryCount := 0
	for _, observation := range outcome.Observations {
		if observation.Operation !=
			"filesystem.activity-trace.summary" {
			continue
		}
		summaryCount++
		assertActivityTraceObservation(
			t,
			domain.VerificationResult{Runner: outcome.Runner},
			observation,
			"",
		)
		notificationCount, ok := observationInteger(
			observation.Details["notificationCount"],
		)
		if !ok || notificationCount < 2 {
			t.Fatalf(
				"dynamic-directory activity was not observed: %#v",
				observation.Details,
			)
		}
		if observation.Details["operationHistoryCoverage"] !=
			"unavailable" {
			t.Fatalf(
				"activity hints were overstated as operation history: %#v",
				observation.Details,
			)
		}
	}
	if summaryCount != 1 {
		t.Fatalf("activity summaries = %d, want 1", summaryCount)
	}

	transientPath := filepath.Join(
		outcome.OutputsDir,
		transientDirectory,
		transientFile,
	)
	if _, statErr := os.Stat(transientPath); !os.IsNotExist(statErr) {
		t.Fatalf("transient child was exported: %v", statErr)
	}
	renderResult := domain.VerificationResult{
		Runner: outcome.Runner,
		Repeats: domain.RepeatSummary{
			Requested: 1,
			Completed: 1,
			Matching:  1,
		},
		Observations: outcome.Observations,
	}
	publicJSON, err := rendering.JSON(renderResult)
	if err != nil {
		t.Fatalf("render activity JSON: %v", err)
	}
	publicHTML, err := rendering.HTML(renderResult)
	if err != nil {
		t.Fatalf("render activity HTML: %v", err)
	}
	publicValues := [][]byte{
		publicJSON,
		publicHTML,
		[]byte(rendering.Text(renderResult)),
	}
	executionWire, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("marshal execution output: %v", err)
	}
	publicValues = append(publicValues, executionWire)
	for index, publicValue := range publicValues {
		for _, forbidden := range []string{
			transientDirectory,
			transientFile,
			`"sessionDigest"`,
			`"token"`,
			`"rawPath"`,
		} {
			if bytes.Contains(publicValue, []byte(forbidden)) {
				t.Fatalf(
					"public output %d leaked %q: %s",
					index,
					forbidden,
					publicValue,
				)
			}
		}
	}
	if !strings.Contains(
		rendering.Text(renderResult),
		"/outputs activity trace (optional):     BEST-EFFORT",
	) {
		t.Fatalf(
			"rendered report did not preserve best-effort activity coverage",
		)
	}
	assertContainersRemoved(t, backend, outcome.Observations)
}

func TestContainerPeerPortObservation(t *testing.T) {
	backend := integrationBackend(t)
	if backend != "docker" {
		t.Skip("the alpha.8 peer port observer live gate is qualified for Docker")
	}
	runner, err := execution.Doctor(context.Background(), backend)
	if err != nil {
		t.Fatalf("%s doctor failed: %v", backend, err)
	}
	if !runner.Available || runner.WorkloadOS != "linux" {
		t.Fatalf("integration runner is not an available Linux engine: %#v", runner)
	}

	fixtures := []struct {
		path     string
		positive bool
	}{
		{path: filepath.Join("healthy", "healthy-node-http")},
		{path: filepath.Join("healthy", "healthy-python-http")},
		{
			path:     filepath.Join("malicious", "alpha25-undeclared-port-node"),
			positive: true,
		},
		{
			path:     filepath.Join("malicious", "alpha25-undeclared-port-python"),
			positive: true,
		},
	}
	for _, fixtureCase := range fixtures {
		fixture := fixtureCase.path
		fixtureRoot, err := filepath.Abs(filepath.Join(
			"..", "..", "testdata", "fixtures", fixture,
		))
		if err != nil {
			t.Fatalf("%s: resolve fixture root: %v", fixture, err)
		}
		document, err := manifest.Load(
			filepath.Join(fixtureRoot, "repo-passport.yml"),
		)
		if err != nil {
			t.Fatalf("%s: load manifest: %v", fixture, err)
		}
		snapshot, err := acquisition.NewLocalProvider().Fetch(
			context.Background(),
			domain.ResolvedSource{
				Kind:      "local",
				LocalPath: fixtureRoot,
			},
		)
		if err != nil {
			t.Fatalf("%s: inventory fixture: %v", fixture, err)
		}
		plan, err := planner.Resolve(document, snapshot, "quickstart")
		if err != nil {
			t.Fatalf("%s: resolve fixture plan: %v", fixture, err)
		}
		outcome, err := execution.Execute(
			context.Background(),
			plan,
			fixtureRoot,
			t.TempDir(),
			backend,
		)
		if err != nil {
			t.Fatalf(
				"%s: peer port observation failed: %v; outcome %#v",
				fixture,
				err,
				outcome,
			)
		}
		if outcome.Cleanup != domain.CleanupAllowedResidue {
			t.Fatalf(
				"%s: cleanup = %q, want allowed-residue; errors: %#v",
				fixture,
				outcome.Cleanup,
				outcome.Errors,
			)
		}
		if outcome.Runner.PortObservation != "best-effort" {
			failure := "summary-missing"
			identityVerified := false
			namespaceIsolationVerified := false
			workloadQuiescenceVerified := false
			peerRemoveVerified := false
			for _, observation := range outcome.Observations {
				if observation.Operation !=
					"port.listener-trace.summary" {
					continue
				}
				if value, ok := observation.Details["failure"].(string); ok {
					failure = value
				}
				identityVerified, _ =
					observation.Details["identityVerified"].(bool)
				namespaceIsolationVerified, _ =
					observation.Details["namespaceIsolationVerified"].(bool)
				workloadQuiescenceVerified, _ =
					observation.Details["workloadQuiescenceVerified"].(bool)
				peerRemoveVerified, _ =
					observation.Details["peerRemoveVerified"].(bool)
			}
			t.Fatalf(
				"%s: port observation = %q, want best-effort; "+
					"failure=%q identity=%t namespace=%t "+
					"quiescence=%t peerRemove=%t",
				fixture,
				outcome.Runner.PortObservation,
				failure,
				identityVerified,
				namespaceIsolationVerified,
				workloadQuiescenceVerified,
				peerRemoveVerified,
			)
		}
		if !containsExactString(
			outcome.IncompleteFeatures,
			"observer:port-listen",
		) {
			t.Fatalf(
				"%s: required port observer was incorrectly completed: %#v",
				fixture,
				outcome.IncompleteFeatures,
			)
		}
		for _, assertion := range outcome.Assertions {
			if assertion.Status != "passed" {
				t.Fatalf("%s: assertion = %#v", fixture, assertion)
			}
		}

		summaryCount := 0
		peerRemoveIndex := -1
		targetRemoveIndex := -1
		var portSummary domain.ObservationEvent
		for index, observation := range outcome.Observations {
			switch observation.Operation {
			case "observer.container.remove":
				if observation.Resource != "tcp-listener-observer" ||
					observation.Result != "succeeded" {
					t.Fatalf(
						"%s: peer removal observation = %#v",
						fixture,
						observation,
					)
				}
				peerRemoveIndex = index
			case "container.remove":
				targetRemoveIndex = index
			case "port.listener-trace.summary":
				summaryCount++
				portSummary = observation
				if observation.Result != "observed" ||
					observation.Coverage != "best-effort" ||
					observation.Confidence != "high" {
					t.Fatalf(
						"%s: port summary trust envelope = %#v",
						fixture,
						observation,
					)
				}
				for key, want := range map[string]any{
					"observerPlacement": "peer-container-" +
						"shared-network-namespace",
					"sharesTargetPIDNamespace":   false,
					"sharesTargetMountNamespace": false,
					"sharesTargetIPCNamespace":   false,
					"sharesTargetCgroup":         false,
					"identityVerified":           true,
					"namespaceIsolationVerified": true,
					"workloadQuiescenceVerified": true,
					"peerRemoveVerified":         true,
					"canonicalDigestSemantics": "helper-commitment-" +
						"not-controller-recomputed",
				} {
					if observation.Details[key] != want {
						t.Fatalf(
							"%s: port summary[%q] = %#v, want %#v",
							fixture,
							key,
							observation.Details[key],
							want,
						)
					}
				}
				wantComparison := "no-undeclared-observed"
				wantSampled := 1
				wantUndeclared := 0
				if fixtureCase.positive {
					wantComparison = "nonconforming-listeners"
					wantSampled = 2
					wantUndeclared = 1
				}
				if observation.Details["comparisonResult"] != wantComparison ||
					observation.Details["evidenceBasis"] != "aggregate-only" {
					t.Fatalf("%s: Alpha.25 comparison details = %#v", fixture, observation.Details)
				}
				for key, want := range map[string]int{
					"baselineEndpointCount":   0,
					"declaredEndpointCount":   1,
					"sampledEndpointCount":    wantSampled,
					"undeclaredEndpointCount": wantUndeclared,
				} {
					got, ok := observationInteger(observation.Details[key])
					if !ok || got != want {
						t.Fatalf("%s: port summary[%q] = %#v, want %d", fixture, key, observation.Details[key], want)
					}
				}
				for _, key := range []string{
					"declaredEndpoints",
					"declaredObservedEndpoints",
					"declaredClosedEndpoints",
					"observedEndpoints",
					"initialEndpoints",
					"finalEndpoints",
				} {
					if _, present := observation.Details[key]; present {
						t.Fatalf("%s: Alpha.25 port summary exposed %q", fixture, key)
					}
				}
			}
		}
		if summaryCount != 1 {
			t.Fatalf("%s: port summaries = %d, want 1", fixture, summaryCount)
		}
		if peerRemoveIndex < 0 || targetRemoveIndex < 0 ||
			peerRemoveIndex >= targetRemoveIndex {
			t.Fatalf(
				"%s: peer removal index %d must precede target removal %d",
				fixture,
				peerRemoveIndex,
				targetRemoveIndex,
			)
		}
		verificationResult, err := verification.Build(verification.Input{
			RunID:            outcome.RunID,
			Plan:             plan,
			Runner:           outcome.Runner,
			StartedAt:        outcome.StartedAt,
			CompletedAt:      outcome.CompletedAt,
			Observations:     outcome.Observations,
			Assertions:       outcome.Assertions,
			Errors:           outcome.Errors,
			Requested:        1,
			Completed:        1,
			Matching:         1,
			SuccessThreshold: 1,
			Cleanup:          outcome.Cleanup,
			Resources:        outcome.Resources,
		})
		if err != nil {
			t.Fatalf("%s: build verification result: %v", fixture, err)
		}
		wantCapability := domain.CapabilityIncomplete
		wantOverall := domain.OverallInconclusive
		if fixtureCase.positive {
			wantCapability = domain.CapabilityNonconforming
			wantOverall = domain.OverallNonconforming
			if len(verificationResult.Errors) != 1 ||
				verificationResult.Errors[0] == nil ||
				verificationResult.Errors[0].Code !=
					domain.CodeUndeclaredPortListen ||
				len(verificationResult.Errors[0].Details) != 3 {
				t.Fatalf(
					"%s: Alpha.25 finding = %#v",
					fixture,
					verificationResult.Errors,
				)
			}
			for key, want := range map[string]any{
				"observer":                "docker-peer-port-listener-trace",
				"evidenceBasis":           "aggregate-only",
				"undeclaredEndpointCount": 1,
			} {
				if verificationResult.Errors[0].Details[key] != want {
					t.Fatalf(
						"%s: Alpha.25 finding[%q] = %#v, want %#v",
						fixture,
						key,
						verificationResult.Errors[0].Details[key],
						want,
					)
				}
			}
		}
		if verificationResult.Results.Functional != domain.FunctionalPass ||
			verificationResult.Results.Capability != wantCapability ||
			verificationResult.Results.Overall != wantOverall {
			t.Fatalf(
				"%s: peer observer verdicts = %#v",
				fixture,
				verificationResult.Results,
			)
		}
		requiredObserverDecision := ""
		for _, decision := range verificationResult.PolicyDecisions {
			if decision.PolicyID == "core.required-observer-coverage" {
				requiredObserverDecision = decision.Decision
			}
		}
		if requiredObserverDecision != "deny" {
			t.Fatalf(
				"%s: required observer policy decision = %q, want deny",
				fixture,
				requiredObserverDecision,
			)
		}
		sampleCount, sampleCountOK :=
			portSummary.Details["sampleCount"].(int)
		maxGapMillis, maxGapOK :=
			portSummary.Details["maxSampleGapMillis"].(int)
		transitionCount, transitionCountOK :=
			portSummary.Details["transitionCount"].(int)
		sampledEndpointCount, sampledCountOK :=
			portSummary.Details["sampledEndpointCount"].(int)
		canonicalDigest, digestOK :=
			portSummary.Details["canonicalSampleDigest"].(string)
		if !sampleCountOK || sampleCount < 2 ||
			!maxGapOK || maxGapMillis < 0 || maxGapMillis > 1000 ||
			!transitionCountOK || transitionCount < 2 ||
			!sampledCountOK || sampledEndpointCount < 1 ||
			!digestOK ||
			!strings.HasPrefix(canonicalDigest, "sha256:") ||
			len(canonicalDigest) != len("sha256:")+64 {
			t.Fatalf(
				"%s: bounded port summary metrics = %#v",
				fixture,
				portSummary.Details,
			)
		}
		comparisonResult := "no-undeclared-observed"
		undeclaredEndpointCount := 0
		if fixtureCase.positive {
			comparisonResult = "nonconforming-listeners"
			undeclaredEndpointCount = 1
		}
		liveEvidence, err := json.Marshal(map[string]any{
			"schemaVersion":                "1",
			"kind":                         "peer-port-live-evidence",
			"fixture":                      filepath.Base(fixture),
			"runtimeAdapter":               plan.RuntimeAdapter,
			"backend":                      "docker",
			"platform":                     "linux/amd64",
			"listenerLifecycleVerified":    true,
			"identityVerified":             true,
			"namespaceIsolationVerified":   true,
			"workloadQuiescenceVerified":   true,
			"peerRemoveVerified":           true,
			"peerSecurityIdentityVerified": true,
			"sampleCount":                  sampleCount,
			"maxSampleGapMillis":           maxGapMillis,
			"transitionCount":              transitionCount,
			"sampledEndpointCount":         sampledEndpointCount,
			"baselineEndpointCount":        0,
			"declaredEndpointCount":        1,
			"undeclaredEndpointCount":      undeclaredEndpointCount,
			"comparisonResult":             comparisonResult,
			"evidenceBasis":                "aggregate-only",
			"canonicalSampleDigest":        canonicalDigest,
			"coverage":                     "best-effort",
			"requiredCapability":           wantCapability,
			"overallVerdict":               wantOverall,
			"requiredObserverDecision":     requiredObserverDecision,
		})
		if err != nil {
			t.Fatalf("%s: marshal live port evidence: %v", fixture, err)
		}
		t.Logf("REPOPASS_PORT_EVIDENCE %s", liveEvidence)

		publicWire, err := json.Marshal(outcome)
		if err != nil {
			t.Fatalf("%s: marshal execution output: %v", fixture, err)
		}
		for _, forbidden := range []string{
			`"sessionDigest"`,
			`"token"`,
			`"/proc/net/"`,
			`"inode"`,
			"127.0.0.1:18081/tcp",
			"18081",
		} {
			if bytes.Contains(publicWire, []byte(forbidden)) {
				t.Fatalf(
					"%s: public output leaked %q: %s",
					fixture,
					forbidden,
					publicWire,
				)
			}
		}
		assertContainersRemoved(t, backend, outcome.Observations)

		residueCtx, cancelResidue := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		var residueStdout, residueStderr bytes.Buffer
		residueExit, residueErr := (execution.OSCommandExecutor{}).Run(
			residueCtx,
			"docker",
			[]string{
				"ps", "--all", "--quiet",
				"--filter", "label=dev.repopass.run=" + outcome.RunID,
				"--filter", "label=dev.repopass.observer=" +
					"peer-port-listener-trace",
			},
			&residueStdout,
			&residueStderr,
		)
		residueContextErr := residueCtx.Err()
		cancelResidue()
		if residueContextErr != nil || residueErr != nil ||
			residueExit != 0 ||
			strings.TrimSpace(residueStdout.String()) != "" ||
			strings.TrimSpace(residueStderr.String()) != "" {
			t.Fatalf(
				"%s: peer observer residue: exit=%d err=%v context=%v stdout=%q stderr=%q",
				fixture,
				residueExit,
				residueErr,
				residueContextErr,
				residueStdout.String(),
				residueStderr.String(),
			)
		}
	}
}

func containerIntegrationExecute(
	ctx context.Context,
	plan domain.ResolvedPlan,
	sourceRoot string,
	runRoot string,
	backend string,
) (RunnerOutcome, error) {
	outcome, err := execution.Execute(ctx, plan, sourceRoot, runRoot, backend)
	return RunnerOutcome{
		Runner:       outcome.Runner,
		Observations: outcome.Observations,
		Assertions:   outcome.Assertions,
		Errors:       outcome.Errors,
		Resources:    outcome.Resources,
		Completed:    !outcome.CompletedAt.IsZero(),
		Cleanup:      outcome.Cleanup,
	}, err
}

func integrationBackend(t *testing.T) string {
	t.Helper()
	backend := strings.ToLower(strings.TrimSpace(
		os.Getenv("REPOPASS_INTEGRATION_BACKEND"),
	))
	if backend == "" {
		t.Skip("set REPOPASS_INTEGRATION_BACKEND=docker or podman to run live container tests")
	}
	if backend != "docker" && backend != "podman" {
		t.Fatalf(
			"REPOPASS_INTEGRATION_BACKEND = %q, want docker or podman",
			backend,
		)
	}
	return backend
}

func requiredContainerIntegrationBackend(t *testing.T) string {
	t.Helper()
	backend := strings.ToLower(strings.TrimSpace(
		os.Getenv("REPOPASS_INTEGRATION_BACKEND"),
	))
	if backend == "" {
		t.Fatal("required healthy journey gate must set REPOPASS_INTEGRATION_BACKEND=docker or podman")
	}
	if backend != "docker" && backend != "podman" {
		t.Fatalf(
			"REPOPASS_INTEGRATION_BACKEND = %q, want docker or podman",
			backend,
		)
	}
	return backend
}

func containsExactString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsErrorCode(findings []*domain.Error, code domain.ErrorCode) bool {
	for _, finding := range findings {
		if finding != nil && finding.Code == code {
			return true
		}
	}
	return false
}

func assertResourceUsageObservations(
	t *testing.T,
	observations []domain.ObservationEvent,
) {
	t.Helper()
	diskLimitObserved := false
	resourceUsageObserved := false
	for _, observation := range observations {
		switch observation.Operation {
		case "resource.disk.limit":
			if observation.Result != "succeeded" ||
				observation.Coverage != "enforcement-only" {
				t.Fatalf(
					"disk resource-limit observation = %#v",
					observation,
				)
			}
			diskLimitObserved = true
		case "resource.usage":
			if observation.Result != "observed" ||
				observation.Coverage != "high" ||
				observation.Confidence != "high" {
				t.Fatalf("resource-usage observation = %#v", observation)
			}
			activeProbe, activeOK := observation.Details["activeProbe"].(bool)
			identityVerified, identityOK :=
				observation.Details["identityVerified"].(bool)
			includesHelpers, helpersOK :=
				observation.Details["includesTrustedHelpers"].(bool)
			if !activeOK || !activeProbe ||
				!identityOK || !identityVerified ||
				!helpersOK || !includesHelpers {
				t.Fatalf(
					"resource-usage trust details = %#v",
					observation.Details,
				)
			}
			if observation.Details["memoryMetric"] != "cgroup-total-not-rss" ||
				observation.Details["taskMetric"] != "tasks-tids-not-processes" ||
				observation.Details["writableMeasurement"] !=
					"current-at-frozen-gate-not-peak" ||
				observation.Details["snapshotBoundary"] !=
					"post-quiesce-pre-export" {
				t.Fatalf(
					"resource-usage metric scopes = %#v",
					observation.Details,
				)
			}
			if observation.Details["cgroupVersion"] != 2 ||
				observation.Details["memoryMaxBytes"] != int64(128<<20) ||
				observation.Details["memorySwapMaxBytes"] != int64(0) ||
				observation.Details["pidsMax"] != 32 ||
				observation.Details["cpuQuotaMicros"] != int64(50_000) ||
				observation.Details["cpuPeriodMicros"] != int64(100_000) ||
				observation.Details["writableLimitBytes"] != int64(4<<20) ||
				observation.Details["writableBlockSize"] != int64(4096) {
				t.Fatalf(
					"resource-limit readback details = %#v",
					observation.Details,
				)
			}
			resourceUsageObserved = true
		}
	}
	if !diskLimitObserved || !resourceUsageObserved {
		t.Fatalf(
			"resource observations are incomplete: diskLimit=%t usage=%t; %#v",
			diskLimitObserved,
			resourceUsageObserved,
			observations,
		)
	}
}

func assertContainersRemoved(
	t *testing.T,
	backend string,
	observations []domain.ObservationEvent,
) {
	t.Helper()
	created := map[string]bool{}
	removed := map[string]bool{}
	for _, observation := range observations {
		switch observation.Operation {
		case "container.create":
			if observation.Result == "succeeded" {
				created[observation.Resource] = true
			}
		case "container.remove":
			if observation.Result == "succeeded" {
				removed[observation.Resource] = true
			}
		}
	}
	if len(created) == 0 {
		t.Fatalf("no successful container creation observation: %#v", observations)
	}

	for containerName := range created {
		if !removed[containerName] {
			t.Fatalf(
				"container %q has no successful removal observation",
				containerName,
			)
		}
		inspectCtx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		var stdout, stderr bytes.Buffer
		exitCode, _ := (execution.OSCommandExecutor{}).Run(
			inspectCtx,
			backend,
			[]string{"inspect", containerName},
			&stdout,
			&stderr,
		)
		inspectErr := inspectCtx.Err()
		cancel()
		if inspectErr != nil {
			t.Fatalf(
				"container %q residue inspection did not complete: %v",
				containerName,
				inspectErr,
			)
		}
		if exitCode == 0 {
			t.Fatalf(
				"container %q remains after verification: stdout=%q stderr=%q",
				containerName,
				stdout.String(),
				stderr.String(),
			)
		}
	}
}
