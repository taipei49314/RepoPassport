package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/spdx"
	"github.com/repopass/repopass/internal/storage"
	"github.com/repopass/repopass/internal/verification"
)

func TestAttestSPDXSyntaxFailuresAreFixedPreAccessAndNonEchoing(t *testing.T) {
	marker := "synthetic-spdx-value-never-echo.invalid"
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "missing value", args: []string{"--spdx"}},
		{name: "flag-like missing value", args: []string{"--spdx", "--key"}},
		{name: "empty value", args: []string{"--spdx="}},
		{name: "single dash", args: []string{"-spdx=" + marker}},
		{name: "extra dash", args: []string{"---spdx=" + marker}},
		{name: "suffix", args: []string{"--spdx-file=" + marker}},
		{name: "case variant", args: []string{"--SpDx=" + marker}},
		{name: "duplicate", args: []string{"--spdx", marker, "--spdx=" + marker + "-second"}},
		{name: "positional", args: []string{
			"--run", "run_syntax", "--key", "missing-key.pem", "--out", "must-not-exist.tar", marker,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--json", "--data-dir", filepath.Join(t.TempDir(), "missing-data"), "attest"}, test.args...)
			envelope, stdout, stderr, exitCode := runAttestationCLI(t, args...)
			if exitCode != 2 || envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("syntax exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
			}
			if strings.Contains(stdout+stderr, marker) {
				t.Fatalf("syntax error echoed SPDX value: stdout=%s stderr=%s", stdout, stderr)
			}
		})
	}
}

func TestVerifyAttestationFreshnessSyntaxIsFixedPreAccessAndNonEchoing(t *testing.T) {
	marker := "synthetic-freshness-value-never-echo.invalid"
	canonicalDigest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing current value", args: []string{"--current-manifest"}},
		{name: "current followed by freshness flag", args: []string{
			"--current-manifest", "--trust-key", marker,
			"--expect-bundle-digest", canonicalDigest,
		}},
		{name: "empty current value", args: []string{"--current-manifest="}},
		{name: "duplicate current", args: []string{
			"--current-manifest", marker, "--current-manifest=" + marker + "-two",
			"--trust-key", marker, "--expect-bundle-digest", canonicalDigest,
		}},
		{name: "missing trust", args: []string{
			"--current-manifest", marker, "--expect-bundle-digest", canonicalDigest,
		}},
		{name: "trust followed by freshness flag", args: []string{
			"--current-manifest", marker, "--trust-key",
			"--expect-bundle-digest", canonicalDigest,
		}},
		{name: "empty trust", args: []string{
			"--current-manifest", marker, "--trust-key=", "--expect-bundle-digest", canonicalDigest,
		}},
		{name: "duplicate trust", args: []string{
			"--current-manifest", marker, "--trust-key", marker, "--trust-key=" + marker + "-two",
			"--expect-bundle-digest", canonicalDigest,
		}},
		{name: "missing digest", args: []string{
			"--current-manifest", marker, "--trust-key", marker,
		}},
		{name: "malformed digest", args: []string{
			"--current-manifest", marker, "--trust-key", marker,
			"--expect-bundle-digest", "sha256:" + strings.Repeat("A", 64),
		}},
		{name: "duplicate digest", args: []string{
			"--current-manifest", marker, "--trust-key", marker,
			"--expect-bundle-digest", canonicalDigest,
			"--expect-bundle-digest=" + canonicalDigest,
		}},
		{name: "malformed current flag", args: []string{
			"--Current-manifest=" + marker, "--trust-key", marker,
			"--expect-bundle-digest", canonicalDigest,
		}},
		{name: "malformed trust flag", args: []string{
			"--current-manifest", marker, "--trust-key-file=" + marker,
			"--expect-bundle-digest", canonicalDigest,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probeCalls := 0
			var stdout, stderr bytes.Buffer
			app := App{
				Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
					probeCalls++
					return nil, nil
				}},
				Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
			}
			args := append([]string{"--json", "verify-attestation", marker}, test.args...)
			exitCode := app.Run(context.Background(), args)
			if exitCode != 2 || probeCalls != 0 {
				t.Fatalf("exit=%d probeCalls=%d stdout=%s stderr=%s", exitCode, probeCalls, stdout.String(), stderr.String())
			}
			envelope := decodeEnvelope(t, stdout.Bytes())
			if envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("syntax envelope=%#v", envelope)
			}
			if strings.Contains(stdout.String()+stderr.String(), marker) {
				t.Fatalf("syntax error echoed freshness value: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestVerifyAttestationHelpListsCurrentManifest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	if exitCode := app.Run(context.Background(), []string{"verify-attestation", "-h"}); exitCode != 0 {
		t.Fatalf("help exit=%d stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String()+stderr.String(), "-current-manifest") {
		t.Fatalf("freshness flag missing from help: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestEvaluateCurrentFreshnessPlanUnavailablePreventsRunnerProbe(t *testing.T) {
	manifestPath := copyFreshnessFixture(t)
	plan, _, _, err := loadPlan(context.Background(), manifestPath, "quickstart")
	if err != nil {
		t.Fatalf("load current fixture plan: %v", err)
	}
	runner := domain.RunnerFeatures{
		Backend: "docker", Available: true, ControllerOS: runtime.GOOS,
		WorkloadOS: "linux", Rootless: "no", EngineVersion: "24.0.7",
	}
	historical := attestation.AcceptedClaims{
		Source: plan.Source,
		Plan: attestation.PredicatePlan{
			Scenario:    "signed-scenario-does-not-exist",
			Environment: plan.Environment, PlanDigest: plan.PlanDigest,
			PolicyBundleDigest: plan.PolicyBundleDigest,
		},
		Runner: runner,
	}
	probeCalls := 0
	app := App{Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
		probeCalls++
		return []domain.RunnerFeatures{runner}, nil
	}}}
	evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(
		context.Background(), manifestPath, historical,
	)
	if evaluation != attestation.FreshnessUnknown ||
		freshness.Reason != attestation.FreshnessReasonPlanUnavailable ||
		domain.ErrorCodeOf(evaluationErr) != domain.CodePlanUnresolved || probeCalls != 0 {
		t.Fatalf("evaluation=%q freshness=%#v error=%v probes=%d", evaluation, freshness, evaluationErr, probeCalls)
	}
	if freshness.Checks[0].Status != attestation.FreshnessStatusMatch ||
		freshness.Checks[1].Status != attestation.FreshnessStatusUnknown ||
		freshness.Checks[2].Status != attestation.FreshnessStatusUnknown ||
		freshness.Checks[3].Status != attestation.FreshnessStatusNotEvaluated {
		t.Fatalf("plan unavailable checks=%#v", freshness.Checks)
	}
}

func TestEvaluateCurrentFreshnessHistoricalSourcePreflightHasZeroObservation(t *testing.T) {
	runner := freshnessStableRunner()
	commit := strings.Repeat("a", 40)
	historical := attestation.AcceptedClaims{
		Source: domain.PlanSource{
			Identity: "git:" + commit, Commit: commit, TreeDigest: cliSHA256Digest([]byte("historical-tree")),
		},
		Plan: attestation.PredicatePlan{
			Scenario: "quickstart", Environment: "linux-node",
			PlanDigest: cliSHA256Digest([]byte("plan")), PolicyBundleDigest: cliSHA256Digest([]byte("policy")),
		},
		Runner: runner,
	}
	probeCalls := 0
	app := App{Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
		probeCalls++
		return []domain.RunnerFeatures{runner}, nil
	}}}
	missingCurrent := filepath.Join(t.TempDir(), "must-not-be-observed", "repo-passport.yml")
	evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(
		context.Background(), missingCurrent, historical,
	)
	if evaluation != attestation.FreshnessUnknown ||
		freshness.Reason != attestation.FreshnessReasonSourceIdentityUnavailable ||
		domain.ErrorCodeOf(evaluationErr) != domain.CodeSourceDigestMismatch || probeCalls != 0 {
		t.Fatalf("evaluation=%q freshness=%#v error=%v probes=%d", evaluation, freshness, evaluationErr, probeCalls)
	}
	if freshness.Checks[0].Status != attestation.FreshnessStatusUnknown ||
		freshness.Checks[1].Status != attestation.FreshnessStatusNotEvaluated {
		t.Fatalf("historical source preflight checks=%#v", freshness.Checks)
	}
}

func TestEvaluateCurrentFreshnessCancellationAndStableDriftPrecedence(t *testing.T) {
	manifestPath := copyFreshnessFixture(t)
	plan, _, snapshot, err := loadPlan(context.Background(), manifestPath, "quickstart")
	if err != nil {
		t.Fatalf("load current fixture plan: %v", err)
	}
	runner := freshnessStableRunner()
	base := attestation.AcceptedClaims{
		Source: plan.Source,
		Plan: attestation.PredicatePlan{
			Scenario: "quickstart", Environment: plan.Environment,
			PlanDigest: plan.PlanDigest, PolicyBundleDigest: plan.PolicyBundleDigest,
		},
		Runner: runner,
	}

	t.Run("cancel before source prevents runner", func(t *testing.T) {
		probeCalls := 0
		app := App{Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			probeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(ctx, manifestPath, base)
		if evaluation != attestation.FreshnessUnknown ||
			freshness.Reason != attestation.FreshnessReasonSourceUnavailable ||
			domain.ErrorCodeOf(evaluationErr) != domain.CodeCancelled || probeCalls != 0 {
			t.Fatalf("evaluation=%q freshness=%#v error=%v probes=%d", evaluation, freshness, evaluationErr, probeCalls)
		}
	})

	t.Run("third snapshot instability prevents runner", func(t *testing.T) {
		snapshotCalls := 0
		probeCalls := 0
		app := App{Deps: Dependencies{
			FreshnessSnapshot: func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error) {
				snapshotCalls++
				observed := snapshot
				if snapshotCalls == 3 {
					observed.Identity = cliSHA256Digest([]byte("third-snapshot-changed"))
					observed.TreeDigest = observed.Identity
				}
				return observed, nil
			},
			ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
				probeCalls++
				return []domain.RunnerFeatures{runner}, nil
			},
		}}
		evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(
			context.Background(), manifestPath, base,
		)
		if evaluation != attestation.FreshnessUnknown ||
			freshness.Reason != attestation.FreshnessReasonSourceUnstable ||
			domain.ErrorCodeOf(evaluationErr) != domain.CodeSourceDigestMismatch ||
			snapshotCalls != 3 || probeCalls != 0 {
			t.Fatalf("evaluation=%q freshness=%#v error=%v snapshots=%d probes=%d", evaluation, freshness, evaluationErr, snapshotCalls, probeCalls)
		}
		if freshness.Checks[0].Status != attestation.FreshnessStatusUnknown ||
			freshness.Checks[0].CurrentDigest != "" ||
			freshness.Checks[1].Status != attestation.FreshnessStatusNotEvaluated {
			t.Fatalf("unstable source checks=%#v", freshness.Checks)
		}
	})

	t.Run("policy stale prevents runner", func(t *testing.T) {
		historical := base
		historical.Plan.PolicyBundleDigest = cliSHA256Digest([]byte("historical-policy"))
		probeCalls := 0
		app := App{Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			probeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}}}
		evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(
			context.Background(), manifestPath, historical,
		)
		if evaluation != attestation.FreshnessStale ||
			freshness.Reason != attestation.FreshnessReasonPolicyChanged ||
			domain.ErrorCodeOf(evaluationErr) != domain.CodeEvidenceStale || probeCalls != 0 {
			t.Fatalf("evaluation=%q freshness=%#v error=%v probes=%d", evaluation, freshness, evaluationErr, probeCalls)
		}
		if freshness.Checks[1].Status != attestation.FreshnessStatusMismatch ||
			freshness.Checks[2].Status != attestation.FreshnessStatusNotEvaluated {
			t.Fatalf("policy drift checks=%#v", freshness.Checks)
		}
	})

	t.Run("plan stale prevents runner", func(t *testing.T) {
		historical := base
		historical.Plan.PlanDigest = cliSHA256Digest([]byte("historical-plan"))
		probeCalls := 0
		app := App{Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			probeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}}}
		evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(
			context.Background(), manifestPath, historical,
		)
		if evaluation != attestation.FreshnessStale ||
			freshness.Reason != attestation.FreshnessReasonPlanChanged ||
			domain.ErrorCodeOf(evaluationErr) != domain.CodeEvidenceStale || probeCalls != 0 {
			t.Fatalf("evaluation=%q freshness=%#v error=%v probes=%d", evaluation, freshness, evaluationErr, probeCalls)
		}
		if freshness.Checks[1].Status != attestation.FreshnessStatusMatch ||
			freshness.Checks[2].Status != attestation.FreshnessStatusMismatch {
			t.Fatalf("plan drift checks=%#v", freshness.Checks)
		}
	})

	t.Run("runner stale probes exact backend", func(t *testing.T) {
		currentRunner := runner
		currentRunner.EngineVersion = "25.0.1"
		probeCalls := 0
		app := App{Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				t.Fatal("freshness called ProbeAll")
				return nil, nil
			},
			ProbeBackend: func(_ context.Context, backend string) ([]domain.RunnerFeatures, error) {
				probeCalls++
				if backend != runner.Backend {
					t.Fatalf("backend=%q, want %q", backend, runner.Backend)
				}
				return []domain.RunnerFeatures{currentRunner}, nil
			},
		}}
		evaluation, freshness, evaluationErr := app.evaluateCurrentFreshness(
			context.Background(), manifestPath, base,
		)
		if evaluation != attestation.FreshnessStale ||
			freshness.Reason != attestation.FreshnessReasonRunnerChanged ||
			domain.ErrorCodeOf(evaluationErr) != domain.CodeEvidenceStale || probeCalls != 1 {
			t.Fatalf("evaluation=%q freshness=%#v error=%v probes=%d", evaluation, freshness, evaluationErr, probeCalls)
		}
		if freshness.Checks[3].Status != attestation.FreshnessStatusMismatch {
			t.Fatalf("runner drift checks=%#v", freshness.Checks)
		}
	})
}

func freshnessStableRunner() domain.RunnerFeatures {
	return domain.RunnerFeatures{
		Backend: "docker", Available: true, ControllerOS: runtime.GOOS,
		WorkloadOS: "linux", Rootless: "no", EngineVersion: "24.0.7",
	}
}

func TestVerifyAttestationFreshnessCurrentThenSourceChanged(t *testing.T) {
	manifestPath := copyFreshnessFixture(t)
	dataRoot := t.TempDir()
	runner := domain.RunnerFeatures{
		Backend: "docker", Available: true, ControllerOS: runtime.GOOS,
		WorkloadOS: "linux", Rootless: "no", EngineVersion: "24.0.7",
		NetworkDeny: true, NetworkAttemptObservation: "full",
		ProcessExecObservation: "full", FilesystemWriteObservation: "full",
		FilesystemReadObservation: "full", PortObservation: "full",
		ResourceUsage: "full", ResourceLimitEnforcement: true,
	}
	var verifyStdout, verifyStderr bytes.Buffer
	verifyApp := App{
		Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				return []domain.RunnerFeatures{runner}, nil
			},
			Execute: func(context.Context, domain.ResolvedPlan, string, string, string) (RunnerOutcome, error) {
				return RunnerOutcome{Runner: runner, Completed: false, Cleanup: domain.CleanupNotTested}, nil
			},
		},
		Stdin: strings.NewReader(""), Stdout: &verifyStdout, Stderr: &verifyStderr,
	}
	if exitCode := verifyApp.Run(context.Background(), []string{
		"--json", "--data-dir", dataRoot, "verify", "--manifest", manifestPath,
	}); exitCode != 0 {
		t.Fatalf("prepare verification exit=%d stdout=%s stderr=%s", exitCode, verifyStdout.String(), verifyStderr.String())
	}
	verifyEnvelope := decodeEnvelope(t, verifyStdout.Bytes())
	var verifyData verifyEnvelopeData
	decodeJSON(t, verifyEnvelope.Data, &verifyData)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	built, err := attestation.Build(verifyData.Verification, privateKey)
	if err != nil {
		t.Fatalf("build freshness bundle: %v", err)
	}
	artifactRoot := t.TempDir()
	bundlePath := filepath.Join(artifactRoot, "freshness-bundle.tar")
	trustPath := filepath.Join(artifactRoot, "freshness-trust.pem")
	if err := os.WriteFile(bundlePath, built.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, built.PublicKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyProbeCalls := 0
	var legacyStdout, legacyStderr bytes.Buffer
	legacyApp := App{
		Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			legacyProbeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}},
		Stdin: strings.NewReader(""), Stdout: &legacyStdout, Stderr: &legacyStderr,
	}
	if exitCode := legacyApp.Run(context.Background(), []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key", trustPath, "--expect-bundle-digest", built.BundleDigest,
	}); exitCode != 0 || legacyProbeCalls != 0 {
		t.Fatalf("legacy exit=%d probes=%d stdout=%s stderr=%s", exitCode, legacyProbeCalls, legacyStdout.String(), legacyStderr.String())
	}
	legacyEnvelope := decodeEnvelope(t, legacyStdout.Bytes())
	var legacyReport attestation.VerificationReport
	decodeJSON(t, legacyEnvelope.Data, &legacyReport)
	if legacyReport.FreshnessEvaluation != attestation.FreshnessNotEvaluated || legacyReport.Freshness != nil {
		t.Fatalf("legacy report=%#v", legacyReport)
	}
	var legacyRaw map[string]any
	decodeJSON(t, legacyEnvelope.Data, &legacyRaw)
	if _, exists := legacyRaw["freshness"]; exists {
		t.Fatalf("legacy JSON unexpectedly contains freshness object: %#v", legacyRaw)
	}

	wrongPrivate, wrongPrivatePEM, _ := writeCLIKeyPair(t, artifactRoot, "wrong-freshness")
	defer clear(wrongPrivate)
	defer clear(wrongPrivatePEM)
	wrongTrustPath := filepath.Join(artifactRoot, "wrong-freshness-public.pem")
	wrongProbeCalls := 0
	var wrongStdout, wrongStderr bytes.Buffer
	wrongApp := App{
		Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			wrongProbeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}},
		Stdin: strings.NewReader(""), Stdout: &wrongStdout, Stderr: &wrongStderr,
	}
	missingCurrentPath := filepath.Join(t.TempDir(), "must-not-be-opened", "repo-passport.yml")
	wrongExit := wrongApp.Run(context.Background(), []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key", wrongTrustPath,
		"--expect-bundle-digest", built.BundleDigest,
		"--current-manifest", missingCurrentPath,
	})
	wrongEnvelope := decodeEnvelope(t, wrongStdout.Bytes())
	var wrongReport attestation.VerificationReport
	decodeJSON(t, wrongEnvelope.Data, &wrongReport)
	if wrongExit != 7 || wrongEnvelope.Error == nil || wrongEnvelope.Error.Code != domain.CodeAttestationUntrusted ||
		wrongReport.TrustDecision != "rejected" || wrongReport.FreshnessEvaluation != attestation.FreshnessNotEvaluated ||
		wrongReport.Freshness != nil || wrongProbeCalls != 0 {
		t.Fatalf("wrong trust exit=%d probes=%d envelope=%#v report=%#v stderr=%s", wrongExit, wrongProbeCalls, wrongEnvelope, wrongReport, wrongStderr.String())
	}
	for _, forbidden := range []string{missingCurrentPath, wrongTrustPath, bundlePath} {
		if strings.Contains(wrongStdout.String()+wrongStderr.String(), forbidden) {
			t.Fatalf("wrong-trust output echoed private path %q", forbidden)
		}
	}

	runDashRouting := func(arguments []string) (string, string, int, int) {
		var stdout, stderr bytes.Buffer
		probeCalls := 0
		app := App{
			Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
				probeCalls++
				return []domain.RunnerFeatures{runner}, nil
			}},
			Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		}
		exitCode := app.Run(context.Background(), arguments)
		return stdout.String(), stderr.String(), exitCode, probeCalls
	}
	dashTrust := "-synthetic-dash-trust-never-echo.pem"
	dashTrustSeparated := []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key", dashTrust,
		"--expect-bundle-digest", built.BundleDigest,
		"--current-manifest", missingCurrentPath,
	}
	dashTrustEqual := []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key=" + dashTrust,
		"--expect-bundle-digest=" + built.BundleDigest,
		"--current-manifest=" + missingCurrentPath,
	}
	separatedOut, separatedErr, separatedExit, separatedProbes := runDashRouting(dashTrustSeparated)
	equalOut, equalErr, equalExit, equalProbes := runDashRouting(dashTrustEqual)
	if separatedExit != 7 || equalExit != 7 || separatedProbes != 0 || equalProbes != 0 ||
		separatedOut != equalOut || separatedErr != equalErr {
		t.Fatalf("dash trust routing differs: split=%d/%d %q %q equal=%d/%d %q %q", separatedExit, separatedProbes, separatedOut, separatedErr, equalExit, equalProbes, equalOut, equalErr)
	}
	if strings.Contains(separatedOut+separatedErr+equalOut+equalErr, dashTrust) {
		t.Fatal("dash-leading trust path was echoed")
	}

	dashCurrent := "-synthetic-dash-current-never-echo/repo-passport.yml"
	dashCurrentSeparated := []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key", trustPath,
		"--expect-bundle-digest", built.BundleDigest,
		"--current-manifest", dashCurrent,
	}
	dashCurrentEqual := []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key=" + trustPath,
		"--expect-bundle-digest=" + built.BundleDigest,
		"--current-manifest=" + dashCurrent,
	}
	separatedOut, separatedErr, separatedExit, separatedProbes = runDashRouting(dashCurrentSeparated)
	equalOut, equalErr, equalExit, equalProbes = runDashRouting(dashCurrentEqual)
	if separatedExit != 1 || equalExit != 1 || separatedProbes != 0 || equalProbes != 0 ||
		separatedOut != equalOut || separatedErr != equalErr {
		t.Fatalf("dash current routing differs: split=%d/%d %q %q equal=%d/%d %q %q", separatedExit, separatedProbes, separatedOut, separatedErr, equalExit, equalProbes, equalOut, equalErr)
	}
	if strings.Contains(separatedOut+separatedErr+equalOut+equalErr, dashCurrent) {
		t.Fatal("dash-leading current-manifest path was echoed")
	}

	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	if wrongDigest == built.BundleDigest {
		wrongDigest = "sha256:" + strings.Repeat("1", 64)
	}
	digestProbeCalls := 0
	var digestStdout, digestStderr bytes.Buffer
	digestApp := App{
		Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			digestProbeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}},
		Stdin: strings.NewReader(""), Stdout: &digestStdout, Stderr: &digestStderr,
	}
	missingPinTrust := filepath.Join(t.TempDir(), "must-not-be-read-trust.pem")
	digestExit := digestApp.Run(context.Background(), []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key", missingPinTrust,
		"--expect-bundle-digest", wrongDigest,
		"--current-manifest", missingCurrentPath,
	})
	digestEnvelope := decodeEnvelope(t, digestStdout.Bytes())
	if digestExit != 7 || digestEnvelope.Error == nil ||
		digestEnvelope.Error.Code != domain.CodeEvidenceDigestMismatch || digestProbeCalls != 0 {
		t.Fatalf("wrong digest exit=%d probes=%d envelope=%#v stderr=%s", digestExit, digestProbeCalls, digestEnvelope, digestStderr.String())
	}
	for _, forbidden := range []string{missingCurrentPath, missingPinTrust} {
		if strings.Contains(digestStdout.String()+digestStderr.String(), forbidden) {
			t.Fatalf("wrong-digest output echoed private value %q", forbidden)
		}
	}

	tampered := append([]byte(nil), built.Bundle...)
	tampered[len(tampered)-1] ^= 1
	tamperedPath := filepath.Join(artifactRoot, "tampered-freshness-bundle.tar")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	tamperTrust := filepath.Join(t.TempDir(), "tamper-trust-must-not-be-read.pem")
	tamperProbeCalls := 0
	var tamperStdout, tamperStderr bytes.Buffer
	tamperApp := App{
		Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			tamperProbeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}},
		Stdin: strings.NewReader(""), Stdout: &tamperStdout, Stderr: &tamperStderr,
	}
	tamperExit := tamperApp.Run(context.Background(), []string{
		"--json", "verify-attestation", tamperedPath,
		"--trust-key", tamperTrust,
		"--expect-bundle-digest", cliSHA256Digest(tampered),
		"--current-manifest", missingCurrentPath,
	})
	tamperEnvelope := decodeEnvelope(t, tamperStdout.Bytes())
	if tamperExit != 7 || tamperEnvelope.Error == nil ||
		tamperEnvelope.Error.Code != domain.CodeAttestationInvalid || tamperProbeCalls != 0 {
		t.Fatalf("tamper exit=%d probes=%d envelope=%#v stderr=%s", tamperExit, tamperProbeCalls, tamperEnvelope, tamperStderr.String())
	}
	for _, forbidden := range []string{tamperedPath, tamperTrust, missingCurrentPath} {
		if strings.Contains(tamperStdout.String()+tamperStderr.String(), forbidden) {
			t.Fatalf("tamper output echoed private path %q", forbidden)
		}
	}

	missingProbeCalls := 0
	missingEnvelope, _, missingStderr, missingExit := runFreshnessCLI(
		t,
		func(context.Context) ([]domain.RunnerFeatures, error) {
			missingProbeCalls++
			return []domain.RunnerFeatures{runner}, nil
		},
		bundlePath,
		trustPath,
		built.BundleDigest,
		missingCurrentPath,
	)
	if missingExit != 1 || missingEnvelope.Error == nil ||
		missingEnvelope.Error.Code != domain.CodeSourceDigestMismatch || missingProbeCalls != 0 {
		t.Fatalf("missing source exit=%d probes=%d envelope=%#v stderr=%s", missingExit, missingProbeCalls, missingEnvelope, missingStderr)
	}
	var missingReport attestation.VerificationReport
	decodeJSON(t, missingEnvelope.Data, &missingReport)
	if missingReport.FreshnessEvaluation != attestation.FreshnessUnknown || missingReport.Freshness == nil ||
		missingReport.Freshness.Reason != attestation.FreshnessReasonSourceUnavailable ||
		missingReport.Freshness.Checks[0].Status != attestation.FreshnessStatusUnknown {
		t.Fatalf("missing source report=%#v", missingReport)
	}

	probeCalls := 0
	currentEnvelope, currentStdout, currentStderr, currentExit := runFreshnessCLI(
		t,
		func(context.Context) ([]domain.RunnerFeatures, error) {
			probeCalls++
			return []domain.RunnerFeatures{runner}, nil
		},
		bundlePath,
		trustPath,
		built.BundleDigest,
		manifestPath,
	)
	if currentExit != 0 || currentEnvelope.Status != "ok" || currentEnvelope.Error != nil || probeCalls != 1 {
		t.Fatalf("current exit=%d probes=%d envelope=%#v stderr=%s", currentExit, probeCalls, currentEnvelope, currentStderr)
	}
	var currentReport attestation.VerificationReport
	decodeJSON(t, currentEnvelope.Data, &currentReport)
	if currentReport.FreshnessEvaluation != attestation.FreshnessCurrent || currentReport.Freshness == nil ||
		currentReport.Freshness.Reason != attestation.FreshnessReasonNone || len(currentReport.Freshness.Checks) != 4 ||
		currentReport.OriginalResults != verifyData.Verification.Results {
		t.Fatalf("current freshness report=%#v", currentReport)
	}
	for _, check := range currentReport.Freshness.Checks {
		if check.Status != attestation.FreshnessStatusMatch || check.HistoricalDigest == "" || check.CurrentDigest == "" {
			t.Fatalf("current freshness check=%#v", check)
		}
	}
	for _, forbidden := range []string{manifestPath, bundlePath, trustPath} {
		if strings.Contains(currentStdout+currentStderr, forbidden) {
			t.Fatalf("current output echoed private path %q: %s%s", forbidden, currentStdout, currentStderr)
		}
	}

	policyPath, policyDigest := writeCLIOfflineTrustPolicy(t, artifactRoot, "freshness-policy.json", map[string]string{
		built.SignerKeyID: "trusted",
	})
	policyProbeCalls := 0
	var policyStdout, policyStderr bytes.Buffer
	policyApp := App{
		Deps: Dependencies{ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
			policyProbeCalls++
			return []domain.RunnerFeatures{runner}, nil
		}},
		Stdin: strings.NewReader(""), Stdout: &policyStdout, Stderr: &policyStderr,
	}
	policyExit := policyApp.Run(context.Background(), []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-policy", policyPath,
		"--expect-trust-policy-digest", policyDigest,
		"--expect-bundle-digest", built.BundleDigest,
		"--current-manifest", manifestPath,
	})
	policyEnvelope := decodeEnvelope(t, policyStdout.Bytes())
	var policyReport attestation.VerificationReport
	decodeJSON(t, policyEnvelope.Data, &policyReport)
	if policyExit != 0 || policyEnvelope.Error != nil || policyProbeCalls != 1 ||
		policyReport.TrustDecision != "accepted" || policyReport.TrustBasis != "offline-policy-v1" ||
		policyReport.TrustPolicyDigest != policyDigest || policyReport.TrustReason != "trusted" ||
		policyReport.FreshnessEvaluation != attestation.FreshnessCurrent || policyReport.Freshness == nil {
		t.Fatalf("accepted policy freshness exit=%d probes=%d report=%#v envelope=%#v stderr=%s", policyExit, policyProbeCalls, policyReport, policyEnvelope, policyStderr.String())
	}

	for _, runnerTest := range []struct {
		name   string
		result []domain.RunnerFeatures
	}{
		{name: "duplicate", result: []domain.RunnerFeatures{runner, runner}},
		{name: "unavailable", result: []domain.RunnerFeatures{{
			Backend: "docker", Available: false, ControllerOS: runtime.GOOS,
			WorkloadOS: "linux", Rootless: "unknown",
		}}},
	} {
		t.Run("runner "+runnerTest.name, func(t *testing.T) {
			calls := 0
			unknownEnvelope, _, unknownStderr, unknownExit := runFreshnessCLI(
				t,
				func(context.Context) ([]domain.RunnerFeatures, error) {
					calls++
					return runnerTest.result, nil
				},
				bundlePath,
				trustPath,
				built.BundleDigest,
				manifestPath,
			)
			if unknownExit != 3 || unknownEnvelope.Error == nil ||
				unknownEnvelope.Error.Code != domain.CodeRunnerUnavailable || calls != 1 {
				t.Fatalf("unknown runner exit=%d calls=%d envelope=%#v stderr=%s", unknownExit, calls, unknownEnvelope, unknownStderr)
			}
			var unknownReport attestation.VerificationReport
			decodeJSON(t, unknownEnvelope.Data, &unknownReport)
			if unknownReport.FreshnessEvaluation != attestation.FreshnessUnknown || unknownReport.Freshness == nil ||
				unknownReport.Freshness.Reason != attestation.FreshnessReasonRunnerUnavailable ||
				unknownReport.Freshness.Checks[0].Status != attestation.FreshnessStatusMatch ||
				unknownReport.Freshness.Checks[1].Status != attestation.FreshnessStatusMatch ||
				unknownReport.Freshness.Checks[2].Status != attestation.FreshnessStatusMatch ||
				unknownReport.Freshness.Checks[3].Status != attestation.FreshnessStatusUnknown {
				t.Fatalf("unknown runner report=%#v", unknownReport)
			}
		})
	}

	driftMarker := "synthetic-source-drift-never-echo"
	if err := os.WriteFile(filepath.Join(filepath.Dir(manifestPath), "freshness-drift.txt"), []byte(driftMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	probeCalls = 0
	staleEnvelope, staleStdout, staleStderr, staleExit := runFreshnessCLI(
		t,
		func(context.Context) ([]domain.RunnerFeatures, error) {
			probeCalls++
			return []domain.RunnerFeatures{runner}, nil
		},
		bundlePath,
		trustPath,
		built.BundleDigest,
		manifestPath,
	)
	if staleExit != 7 || staleEnvelope.Error == nil || staleEnvelope.Error.Code != domain.CodeEvidenceStale || probeCalls != 0 {
		t.Fatalf("stale exit=%d probes=%d envelope=%#v stderr=%s", staleExit, probeCalls, staleEnvelope, staleStderr)
	}
	var staleReport attestation.VerificationReport
	decodeJSON(t, staleEnvelope.Data, &staleReport)
	if staleReport.FreshnessEvaluation != attestation.FreshnessStale || staleReport.Freshness == nil ||
		staleReport.Freshness.Reason != attestation.FreshnessReasonSourceChanged ||
		staleReport.Freshness.Checks[0].Status != attestation.FreshnessStatusMismatch ||
		staleReport.Freshness.Checks[1].Status != attestation.FreshnessStatusNotEvaluated ||
		staleReport.OriginalResults != verifyData.Verification.Results {
		t.Fatalf("stale freshness report=%#v", staleReport)
	}
	if staleEnvelope.Error.Details["profile"] != attestation.FreshnessProfileLocalReobserveV1 ||
		staleEnvelope.Error.Details["reason"] != attestation.FreshnessReasonSourceChanged {
		t.Fatalf("stale fixed details=%#v", staleEnvelope.Error.Details)
	}
	for _, forbidden := range []string{manifestPath, bundlePath, trustPath, driftMarker} {
		if strings.Contains(staleStdout+staleStderr, forbidden) {
			t.Fatalf("stale output echoed private value %q: %s%s", forbidden, staleStdout, staleStderr)
		}
	}
}

func runFreshnessCLI(
	t *testing.T,
	probe func(context.Context) ([]domain.RunnerFeatures, error),
	bundlePath, trustPath, bundleDigest, manifestPath string,
) (testEnvelope, string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				t.Fatal("freshness must never use multi-backend ProbeAll")
				return nil, nil
			},
			ProbeBackend: func(ctx context.Context, backend string) ([]domain.RunnerFeatures, error) {
				if backend != "docker" {
					t.Fatalf("freshness probed backend %q, want docker", backend)
				}
				return probe(ctx)
			},
		},
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), []string{
		"--json", "verify-attestation", bundlePath,
		"--trust-key", trustPath,
		"--expect-bundle-digest", bundleDigest,
		"--current-manifest", manifestPath,
	})
	return decodeEnvelope(t, stdout.Bytes()), stdout.String(), stderr.String(), exitCode
}

func copyFreshnessFixture(t *testing.T) string {
	t.Helper()
	sourceRoot := filepath.Dir(healthyNodeManifest(t))
	targetRoot := filepath.Join(t.TempDir(), "freshness-source")
	if err := filepath.Walk(sourceRoot, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(sourceRoot, sourcePath)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(targetRoot, relative)
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}
		raw, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		return os.WriteFile(targetPath, raw, info.Mode().Perm())
	}); err != nil {
		t.Fatalf("copy freshness fixture: %v", err)
	}
	return filepath.Join(targetRoot, "repo-passport.yml")
}

func TestAttestAndVerifyCLISelectedSPDXMetadataPrecedenceAndNonEcho(t *testing.T) {
	dataRoot := t.TempDir()
	baseRunID := createBlockedAuthoritativeRun(t, dataRoot)
	store := storage.RunStore{Root: filepath.Join(dataRoot, "runs")}
	base, err := store.Read(baseRunID)
	if err != nil {
		t.Fatal(err)
	}
	selected := rebuildCLISBOMRun(t, base)
	if _, err := store.Write(selected); err != nil {
		t.Fatalf("write SBOM-selected run: %v", err)
	}

	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	_, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "spdx-signer")
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "spdx-signer-private.pem")
	trustPath := filepath.Join(keyRoot, "spdx-signer-public.pem")
	spdxPath := filepath.Join(outputRoot, "synthetic-spdx-source-never-echo.json")
	if err := os.WriteFile(spdxPath, cliValidSPDXBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(outputRoot, "selected.tar")

	envelope, stdout, stderr, exitCode := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "attest", "--run", selected.RunID,
		"--spdx", spdxPath, "--key", keyPath, "--out", bundlePath)
	if exitCode != 0 || envelope.Status != "ok" || envelope.Error != nil {
		t.Fatalf("selected SPDX attest exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	if strings.Contains(stdout+stderr, spdxPath) || bytes.Contains([]byte(stdout+stderr), cliValidSPDXBytes()) {
		t.Fatalf("attest output echoed SPDX source path/content: stdout=%s stderr=%s", stdout, stderr)
	}
	var attestData struct {
		SBOMPresent bool   `json:"sbomPresent"`
		SBOMFormat  string `json:"sbomFormat"`
		SBOMDigest  string `json:"sbomDigest"`
	}
	decodeJSON(t, envelope.Data, &attestData)
	if !attestData.SBOMPresent || attestData.SBOMFormat != spdx.Format || attestData.SBOMDigest == "" {
		t.Fatalf("selected SPDX attest metadata = %#v", attestData)
	}
	var rawData map[string]any
	decodeJSON(t, envelope.Data, &rawData)
	for _, key := range []string{"sbomPresent", "sbomFormat", "sbomDigest"} {
		if _, exists := rawData[key]; !exists {
			t.Fatalf("attest data lacks required %q metadata: %#v", key, rawData)
		}
	}

	unknown, _, unknownStderr, exitCode := runAttestationCLI(t,
		"--json", "verify-attestation", bundlePath)
	if exitCode != 7 || unknown.Error == nil || unknown.Error.Code != domain.CodeAttestationUntrusted {
		t.Fatalf("unknown SPDX trust exit=%d envelope=%#v stderr=%s", exitCode, unknown, unknownStderr)
	}
	var report attestation.VerificationReport
	decodeJSON(t, unknown.Data, &report)
	if !report.SBOMPresent || report.SBOMFormat != spdx.Format || report.SBOMDigest != attestData.SBOMDigest ||
		report.SignatureValidity != "valid" || report.TrustDecision != "unknown" {
		t.Fatalf("unknown SPDX report = %#v", report)
	}

	_, textStdout, textStderr, exitCode := runAttestationCLI(t,
		"verify-attestation", bundlePath, "--trust-key", trustPath)
	if exitCode != 0 || textStderr != "" {
		t.Fatalf("trusted text SPDX verify exit=%d stderr=%s", exitCode, textStderr)
	}
	for _, wanted := range []string{
		"SPDX attachment:      PRESENT",
		"SPDX format:          " + spdx.Format,
		"SPDX digest:          " + attestData.SBOMDigest,
	} {
		if !strings.Contains(textStdout, wanted) {
			t.Fatalf("trusted text report lacks %q:\n%s", wanted, textStdout)
		}
	}

	missingSelectedOutput := filepath.Join(outputRoot, "missing-selected.tar")
	missingSelected, missingStdout, missingStderr, exitCode := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "attest", "--run", selected.RunID,
		"--key", filepath.Join(keyRoot, "missing-private.pem"), "--out", missingSelectedOutput)
	if exitCode != 1 || missingSelected.Error == nil || missingSelected.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("missing selected SPDX exit=%d envelope=%#v stderr=%s", exitCode, missingSelected, missingStderr)
	}
	if _, err := os.Lstat(missingSelectedOutput); !os.IsNotExist(err) {
		t.Fatalf("selection mismatch published output: %v", err)
	}
	if strings.Contains(missingStdout+missingStderr, spdxPath) {
		t.Fatal("missing selection error echoed prior SPDX path")
	}

	unselectedOutput := filepath.Join(outputRoot, "unselected.tar")
	unselected, unselectedStdout, unselectedStderr, exitCode := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "attest", "--run", base.RunID,
		"--spdx="+spdxPath, "--key", filepath.Join(keyRoot, "missing-private.pem"), "--out", unselectedOutput)
	if exitCode != 1 || unselected.Error == nil || unselected.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("unselected SPDX exit=%d envelope=%#v stderr=%s", exitCode, unselected, unselectedStderr)
	}
	if strings.Contains(unselectedStdout+unselectedStderr, spdxPath) {
		t.Fatal("selection mismatch echoed SPDX path")
	}
	if _, err := os.Lstat(unselectedOutput); !os.IsNotExist(err) {
		t.Fatalf("unselected mismatch published output: %v", err)
	}

	unsafePath := filepath.Join(outputRoot, "privacy-unsafe-source-never-echo.json")
	unsafeRaw := bytes.Replace(cliValidSPDXBytes(), []byte("demo-sbom"), []byte("synthetic.user@example.invalid"), 1)
	if err := os.WriteFile(unsafePath, unsafeRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	privacyOutput := filepath.Join(outputRoot, "privacy-blocked.tar")
	privacyEnvelope, privacyStdout, privacyStderr, exitCode := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "attest", "--run", selected.RunID,
		"--spdx", unsafePath, "--key", filepath.Join(keyRoot, "missing-private.pem"), "--out", privacyOutput)
	if exitCode != 7 || privacyEnvelope.Error == nil || privacyEnvelope.Error.Code != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("privacy SPDX exit=%d envelope=%#v stderr=%s", exitCode, privacyEnvelope, privacyStderr)
	}
	for _, forbidden := range []string{unsafePath, "synthetic.user@example.invalid"} {
		if strings.Contains(privacyStdout+privacyStderr, forbidden) {
			t.Fatalf("privacy SPDX error echoed forbidden value: %s", privacyStdout+privacyStderr)
		}
	}
	if _, err := os.Lstat(privacyOutput); !os.IsNotExist(err) {
		t.Fatalf("privacy rejection published output: %v", err)
	}
}

func TestAttestCLISelectedSPDXReadAndProfileFailuresPrecedeKeyAndDoNotEcho(t *testing.T) {
	dataRoot := t.TempDir()
	baseRunID := createBlockedAuthoritativeRun(t, dataRoot)
	store := storage.RunStore{Root: filepath.Join(dataRoot, "runs")}
	base, err := store.Read(baseRunID)
	if err != nil {
		t.Fatal(err)
	}
	selected := rebuildCLISBOMRun(t, base)
	if _, err := store.Write(selected); err != nil {
		t.Fatalf("write SBOM-selected run: %v", err)
	}

	inputRoot := t.TempDir()
	validPath := filepath.Join(inputRoot, "valid-source.json")
	if err := os.WriteFile(validPath, cliValidSPDXBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	missingPath := filepath.Join(inputRoot, "missing-source-never-echo.json")
	directoryPath := filepath.Join(inputRoot, "directory-source-never-echo")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	oversizePath := filepath.Join(inputRoot, "oversize-source-never-echo.json")
	if err := os.WriteFile(oversizePath, bytes.Repeat([]byte{'x'}, spdx.MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(inputRoot, "profile-source-never-echo.json")
	profileRaw := []byte(`{"SPDXID":"synthetic-private-profile-value"}`)
	if err := os.WriteFile(profilePath, profileRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
	}{
		{name: "missing", path: missingPath},
		{name: "directory", path: directoryPath},
		{name: "oversized", path: oversizePath},
		{name: "invalid profile", path: profilePath},
	}
	linkPath := filepath.Join(inputRoot, "linked-source-never-echo.json")
	if err := os.Symlink(validPath, linkPath); err == nil {
		tests = append(tests, struct {
			name string
			path string
		}{name: "linked", path: linkPath})
	} else {
		t.Run("linked", func(t *testing.T) {
			t.Skipf("symlink creation unavailable: %v", err)
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputRoot := t.TempDir()
			bundlePath := filepath.Join(outputRoot, "must-not-exist-bundle.tar")
			publicPath := filepath.Join(outputRoot, "must-not-exist-public.pem")
			missingKey := filepath.Join(outputRoot, "missing-private-key.pem")
			envelope, stdout, stderr, exitCode := runAttestationCLI(t,
				"--json", "--data-dir", dataRoot, "attest", "--run", selected.RunID,
				"--spdx", test.path, "--key", missingKey, "--out", bundlePath,
				"--public-key-out", publicPath)
			if exitCode != 1 || envelope.Error == nil || envelope.Error.Code != domain.CodeEvidenceBuildFailed {
				t.Fatalf("selected SPDX failure exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
			}
			serialized := stdout + stderr
			for _, forbidden := range []string{test.path, missingKey, "synthetic-private-profile-value"} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("selected SPDX failure echoed forbidden value: %s", serialized)
				}
			}
			for _, output := range []string{bundlePath, publicPath} {
				if _, err := os.Lstat(output); !os.IsNotExist(err) {
					t.Fatalf("selected SPDX failure published %s: %v", filepath.Base(output), err)
				}
			}
		})
	}
}

func TestAttestCLIPrivacyGatePrecedesMissingKeyAndPublishesNeitherOutput(t *testing.T) {
	dataRoot := t.TempDir()
	baseRunID := createBlockedAuthoritativeRun(t, dataRoot)
	store := storage.RunStore{Root: filepath.Join(dataRoot, "runs")}
	base, err := store.Read(baseRunID)
	if err != nil {
		t.Fatal(err)
	}
	privacyRun := rebuildCLIPrivacyRun(t, base, "synthetic.unique@example.invalid")
	if _, err := store.Write(privacyRun); err != nil {
		t.Fatalf("write privacy run: %v", err)
	}

	outputRoot := t.TempDir()
	bundlePath := filepath.Join(outputRoot, "existing-bundle.tar")
	publicPath := filepath.Join(outputRoot, "existing-public.pem")
	wantBundle := []byte("existing bundle sentinel")
	wantPublic := []byte("existing public sentinel")
	if err := os.WriteFile(bundlePath, wantBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, wantPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	missingKey := filepath.Join(t.TempDir(), "synthetic-missing-private.pem")

	envelope, stdout, stderr, exitCode := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "attest", "--run", privacyRun.RunID,
		"--key", missingKey, "--out", bundlePath, "--public-key-out", publicPath)
	if exitCode != 7 || envelope.Error == nil || envelope.Error.Code != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("privacy attest exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	serialized := stdout + stderr
	for _, forbidden := range []string{"synthetic.unique@example.invalid", missingKey} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("privacy error echoed forbidden value: %s", serialized)
		}
	}
	if got := mustReadFile(t, bundlePath); !bytes.Equal(got, wantBundle) {
		t.Fatalf("bundle target changed: %q", got)
	}
	if got := mustReadFile(t, publicPath); !bytes.Equal(got, wantPublic) {
		t.Fatalf("public target changed: %q", got)
	}
}

func rebuildCLIPrivacyRun(t *testing.T, base domain.VerificationResult, marker string) domain.VerificationResult {
	t.Helper()
	errorsList := append([]*domain.Error(nil), base.Errors...)
	errorsList = append(errorsList, domain.NewError(domain.CodeInternal, domain.SeverityHigh, marker))
	observerSet := make([]string, 0, len(base.ObserverCoverage))
	for _, coverage := range base.ObserverCoverage {
		observerSet = append(observerSet, coverage.Observer)
	}
	result, err := verification.Build(verification.Input{
		RunID: "run_privacycli", VerificationID: "vrf_privacycli",
		Plan: domain.ResolvedPlan{SchemaVersion: base.Plan.ResolvedPlanSchemaVersion,
			Evidence: base.Plan.Evidence, Source: base.Subject, Scenario: base.Plan.Scenario,
			Environment: base.Plan.Environment, PlanDigest: base.Plan.PlanDigest,
			PolicyBundleDigest: base.Plan.PolicyBundleDigest, ObserverSet: observerSet,
			RepeatCount: base.Plan.RepeatCount, SuccessThreshold: base.Plan.SuccessThreshold},
		Runner: base.Runner, StartedAt: base.StartedAt, CompletedAt: base.CompletedAt,
		Observations: base.Observations, Assertions: base.Assertions, Errors: errorsList,
		Requested: base.Repeats.Requested, Completed: base.Repeats.Completed,
		Matching: base.Repeats.Matching, SuccessThreshold: base.Plan.SuccessThreshold,
		Cleanup: base.Results.Cleanup, Resources: base.Resources,
	})
	if err != nil {
		t.Fatalf("rebuild privacy run: %v", err)
	}
	return result
}

func rebuildCLISBOMRun(t *testing.T, base domain.VerificationResult) domain.VerificationResult {
	t.Helper()
	observerSet := make([]string, 0, len(base.ObserverCoverage))
	for _, coverage := range base.ObserverCoverage {
		observerSet = append(observerSet, coverage.Observer)
	}
	result, err := verification.Build(verification.Input{
		RunID: "run_spdxcli", VerificationID: "vrf_spdxcli",
		Plan: domain.ResolvedPlan{
			SchemaVersion: base.Plan.ResolvedPlanSchemaVersion,
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "sbom", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
			Source: base.Subject, Scenario: base.Plan.Scenario, Environment: base.Plan.Environment,
			PlanDigest:         cliSHA256Digest([]byte("synthetic schema-4 SPDX-selected plan")),
			PolicyBundleDigest: base.Plan.PolicyBundleDigest, ObserverSet: observerSet,
			RepeatCount: base.Plan.RepeatCount, SuccessThreshold: base.Plan.SuccessThreshold,
		},
		Runner: base.Runner, StartedAt: base.StartedAt, CompletedAt: base.CompletedAt,
		Observations: base.Observations, Assertions: base.Assertions, Errors: base.Errors,
		Requested: base.Repeats.Requested, Completed: base.Repeats.Completed,
		Matching: base.Repeats.Matching, SuccessThreshold: base.Plan.SuccessThreshold,
		Cleanup: base.Results.Cleanup, Resources: base.Resources,
	})
	if err != nil {
		t.Fatalf("rebuild SBOM-selected CLI run: %v", err)
	}
	return result
}

func cliValidSPDXBytes() []byte {
	return []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"demo","licenseDeclared":"NOASSERTION","licenseConcluded":"NOASSERTION","filesAnalyzed":false,"downloadLocation":"NOASSERTION","copyrightText":"NOASSERTION","SPDXID":"SPDXRef-demo"}],"name":"demo-sbom","documentNamespace":"https://example.invalid/spdx/demo","documentDescribes":["SPDXRef-demo"],"dataLicense":"CC0-1.0","creationInfo":{"creators":["Tool: RepoPassport synthetic fixture"],"created":"2026-08-01T00:00:00Z"},"SPDXID":"SPDXRef-DOCUMENT"}`)
}

func TestAttestAndVerifyAttestationCLITrustDeterminismAndOutputs(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	privateKey, privatePEM, publicPEM := writeCLIKeyPair(t, keyRoot, "signer")
	defer clear(privateKey)
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "signer-private.pem")
	trustPath := filepath.Join(keyRoot, "signer-public.pem")
	firstBundle := filepath.Join(outputRoot, "first.tar")
	secondBundle := filepath.Join(outputRoot, "second.tar")

	firstEnvelope, firstStdout, firstStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath, "--out", firstBundle,
	)
	if exitCode != 0 || firstEnvelope.Status != "ok" || firstEnvelope.Error != nil {
		t.Fatalf("attest result exit=%d envelope=%#v stderr=%s", exitCode, firstEnvelope, firstStderr)
	}
	var attestData struct {
		RunID                string          `json:"runId"`
		VerificationID       string          `json:"verificationId"`
		SignerKeyID          string          `json:"signerKeyId"`
		ManifestDigest       string          `json:"manifestDigest"`
		BundleDigest         string          `json:"bundleDigest"`
		BundlePath           string          `json:"bundlePath"`
		OriginalResults      domain.Verdicts `json:"originalResults"`
		PrivacyProfile       string          `json:"privacyProfile"`
		PrivacyPolicy        string          `json:"privacyPolicy"`
		PrivacyRulesetDigest string          `json:"privacyRulesetDigest"`
		PrivacyEvaluation    string          `json:"privacyEvaluation"`
		SBOMPresent          bool            `json:"sbomPresent"`
		SBOMFormat           string          `json:"sbomFormat"`
		SBOMDigest           string          `json:"sbomDigest"`
	}
	decodeJSON(t, firstEnvelope.Data, &attestData)
	if attestData.RunID != runID || attestData.OriginalResults.Evidence != domain.EvidenceUnsigned ||
		attestData.SignerKeyID == "" || attestData.ManifestDigest == "" || attestData.BundleDigest == "" ||
		attestData.PrivacyProfile != "minimal-public" || attestData.PrivacyPolicy != "minimal-public-v1alpha2" ||
		attestData.PrivacyRulesetDigest == "" || attestData.PrivacyEvaluation != "passed" ||
		attestData.SBOMPresent || attestData.SBOMFormat != "" || attestData.SBOMDigest != "" {
		t.Fatalf("attest data = %#v", attestData)
	}
	var noSBOMAttestRaw map[string]any
	decodeJSON(t, firstEnvelope.Data, &noSBOMAttestRaw)
	if noSBOMAttestRaw["sbomPresent"] != false || noSBOMAttestRaw["sbomFormat"] != "" ||
		noSBOMAttestRaw["sbomDigest"] != "" {
		t.Fatalf("no-SBOM attest flattened metadata = %#v", noSBOMAttestRaw)
	}
	if strings.Contains(firstStdout+firstStderr, keyPath) || bytes.Contains([]byte(firstStdout+firstStderr), privatePEM) {
		t.Fatal("attest output leaked private key material or path")
	}

	secondEnvelope, _, secondStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath, "--out", secondBundle,
	)
	if exitCode != 0 || secondEnvelope.Status != "ok" {
		t.Fatalf("second attest exit=%d envelope=%#v stderr=%s", exitCode, secondEnvelope, secondStderr)
	}
	firstBytes, err := os.ReadFile(firstBundle)
	if err != nil {
		t.Fatalf("read first bundle: %v", err)
	}
	secondBytes, err := os.ReadFile(secondBundle)
	if err != nil {
		t.Fatalf("read second bundle: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same run and key produced different CLI bundle bytes")
	}
	authoritative, err := (storage.RunStore{Root: filepath.Join(dataRoot, "runs")}).Read(runID)
	if err != nil {
		t.Fatalf("read authoritative run for API/CLI byte comparison: %v", err)
	}
	apiBundle, err := attestation.BuildWithSPDX(authoritative, nil, privateKey)
	if err != nil {
		t.Fatalf("build no-SBOM API bundle for CLI comparison: %v", err)
	}
	if !bytes.Equal(firstBytes, apiBundle.Bundle) {
		t.Fatal("no-SBOM CLI bytes differ from BuildWithSPDX nil for the same schema-4 result and key")
	}
	seed := privateKey.Seed()
	defer clear(seed)
	if bytes.Contains(firstBytes, seed) || bytes.Contains(firstBytes, privatePEM) ||
		bytes.Contains(firstBytes, []byte(keyPath)) {
		t.Fatal("bundle leaked private material or path")
	}

	unknownEnvelope, _, unknownStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", firstBundle,
	)
	if exitCode != 7 || unknownEnvelope.Error == nil ||
		unknownEnvelope.Error.Code != domain.CodeAttestationUntrusted {
		t.Fatalf("unknown trust exit=%d envelope=%#v stderr=%s", exitCode, unknownEnvelope, unknownStderr)
	}
	var unknownReport attestation.VerificationReport
	decodeJSON(t, unknownEnvelope.Data, &unknownReport)
	if unknownReport.SignatureValidity != "valid" || unknownReport.TrustDecision != "unknown" ||
		unknownReport.FreshnessEvaluation != "not-evaluated" ||
		unknownReport.OriginalResults.Evidence != domain.EvidenceUnsigned ||
		unknownReport.SBOMPresent || unknownReport.SBOMFormat != "" || unknownReport.SBOMDigest != "" {
		t.Fatalf("unknown trust report = %#v", unknownReport)
	}
	var noSBOMReportRaw map[string]any
	decodeJSON(t, unknownEnvelope.Data, &noSBOMReportRaw)
	if noSBOMReportRaw["sbomPresent"] != false || noSBOMReportRaw["sbomFormat"] != "" ||
		noSBOMReportRaw["sbomDigest"] != "" {
		t.Fatalf("no-SBOM report flattened metadata = %#v", noSBOMReportRaw)
	}
	assertCLIUntrustedDetails(t, unknownEnvelope.Error, "unknown")

	otherPrivateKey, otherPrivatePEM, otherPublicPEM := writeCLIKeyPair(t, keyRoot, "other")
	defer clear(otherPrivateKey)
	defer clear(otherPrivatePEM)
	otherTrustPath := filepath.Join(keyRoot, "other-public.pem")
	rejectedEnvelope, _, rejectedStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", firstBundle, "--trust-key", otherTrustPath,
	)
	if exitCode != 7 || rejectedEnvelope.Error == nil ||
		rejectedEnvelope.Error.Code != domain.CodeAttestationUntrusted {
		t.Fatalf("rejected trust exit=%d envelope=%#v stderr=%s", exitCode, rejectedEnvelope, rejectedStderr)
	}
	var rejectedReport attestation.VerificationReport
	decodeJSON(t, rejectedEnvelope.Data, &rejectedReport)
	if rejectedReport.SignatureValidity != "valid" || rejectedReport.TrustDecision != "rejected" {
		t.Fatalf("rejected trust report = %#v", rejectedReport)
	}
	assertCLIUntrustedDetails(t, rejectedEnvelope.Error, "rejected")
	clear(otherPublicPEM)

	acceptedEnvelope, _, acceptedStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", firstBundle, "--trust-key", trustPath,
	)
	if exitCode != 0 || acceptedEnvelope.Status != "ok" || acceptedEnvelope.Error != nil {
		t.Fatalf("accepted trust exit=%d envelope=%#v stderr=%s", exitCode, acceptedEnvelope, acceptedStderr)
	}
	var acceptedReport attestation.VerificationReport
	decodeJSON(t, acceptedEnvelope.Data, &acceptedReport)
	if acceptedReport.TrustDecision != "accepted" || acceptedReport.OriginalResults != attestData.OriginalResults {
		t.Fatalf("accepted report = %#v", acceptedReport)
	}

	_, textStdout, textStderr, exitCode := runAttestationCLI(
		t,
		"verify-attestation", firstBundle, "--trust-key", trustPath,
	)
	if exitCode != 0 || textStderr != "" {
		t.Fatalf("text verify exit=%d stderr=%s", exitCode, textStderr)
	}
	for _, wanted := range []string{
		"Artifact integrity:   VALID",
		"Signature validity:   VALID",
		"Trust decision:       ACCEPTED",
		"Freshness evaluation: NOT-EVALUATED",
		"Privacy profile:      minimal-public",
		"Privacy policy:       minimal-public-v1alpha2",
		"Privacy evaluation:   PASSED",
		"SPDX attachment:      ABSENT",
		"Evidence:         UNSIGNED",
	} {
		if !strings.Contains(textStdout, wanted) {
			t.Fatalf("text verify output lacks %q:\n%s", wanted, textStdout)
		}
	}
	if strings.Contains(textStdout, "SPDX format:") || strings.Contains(textStdout, "SPDX digest:") {
		t.Fatalf("no-SBOM text report exposed present-only metadata:\n%s", textStdout)
	}
	if !bytes.Equal(publicPEM, mustReadFile(t, trustPath)) {
		t.Fatal("written public key changed")
	}
}

func TestAttestCLIExportsCanonicalPublicKeyAndReportsExactDigests(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	privateKey, privatePEM, publicPEM := writeCLIKeyPair(t, keyRoot, "portable")
	defer clear(privateKey)
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "portable-private.pem")
	bundlePath := filepath.Join(outputRoot, "portable.tar")
	publicPath := filepath.Join(outputRoot, "portable-public.pem")

	envelope, stdout, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest",
		"--out="+bundlePath,
		"--public-key-out", publicPath,
		"--key="+keyPath,
		"--run", runID,
	)
	if exitCode != 0 || envelope.Status != "ok" || envelope.Error != nil {
		t.Fatalf("attest exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	var data struct {
		BundleDigest    string `json:"bundleDigest"`
		PublicKeyDigest string `json:"publicKeyDigest"`
		SignerKeyID     string `json:"signerKeyId"`
		BundlePath      string `json:"bundlePath"`
		PublicKeyPath   string `json:"publicKeyPath"`
	}
	decodeJSON(t, envelope.Data, &data)
	bundle := mustReadFile(t, bundlePath)
	companion := mustReadFile(t, publicPath)
	if !bytes.Equal(companion, publicPEM) {
		t.Fatal("published companion is not the canonical SPKI PEM for the signing key")
	}
	if data.BundleDigest != cliSHA256Digest(bundle) ||
		data.PublicKeyDigest != cliSHA256Digest(companion) ||
		data.BundlePath != bundlePath || data.PublicKeyPath != publicPath {
		t.Fatalf("attest digest/path data = %#v", data)
	}
	publicBlock, rest := pem.Decode(companion)
	if publicBlock == nil || len(rest) != 0 || data.SignerKeyID != cliSHA256Digest(publicBlock.Bytes) {
		t.Fatalf("signer key ID does not bind canonical SPKI DER: block=%#v rest=%q data=%#v", publicBlock, rest, data)
	}
	if data.SignerKeyID == data.PublicKeyDigest {
		t.Fatal("DER signer key ID unexpectedly equals PEM companion digest")
	}
	if strings.Contains(stdout+stderr, keyPath) || bytes.Contains([]byte(stdout+stderr), privatePEM) {
		t.Fatal("portable attest output leaked private path or bytes")
	}

	unknown, _, unknownStderr, unknownExit := runAttestationCLI(
		t,
		"--json", "verify-attestation", bundlePath,
		"--expect-bundle-digest", data.BundleDigest,
	)
	if unknownExit != 7 || unknown.Error == nil || unknown.Error.Code != domain.CodeAttestationUntrusted {
		t.Fatalf("matching digest without trust exit=%d envelope=%#v stderr=%s", unknownExit, unknown, unknownStderr)
	}
	var unknownReport attestation.VerificationReport
	decodeJSON(t, unknown.Data, &unknownReport)
	if unknownReport.BundleDigest != data.BundleDigest ||
		unknownReport.PublicKeyDigest != data.PublicKeyDigest ||
		unknownReport.SignerKeyID != data.SignerKeyID ||
		unknownReport.TrustDecision != "unknown" {
		t.Fatalf("matching digest report = %#v", unknownReport)
	}

	accepted, _, acceptedStderr, acceptedExit := runAttestationCLI(
		t,
		"--json", "verify-attestation",
		"--trust-key="+publicPath,
		"--expect-bundle-digest="+data.BundleDigest,
		"--", bundlePath,
	)
	if acceptedExit != 0 || accepted.Status != "ok" || accepted.Error != nil {
		t.Fatalf("trusted portable verify exit=%d envelope=%#v stderr=%s", acceptedExit, accepted, acceptedStderr)
	}
	var acceptedReport attestation.VerificationReport
	decodeJSON(t, accepted.Data, &acceptedReport)
	if acceptedReport.TrustDecision != "accepted" || acceptedReport.BundleDigest != data.BundleDigest {
		t.Fatalf("trusted portable report = %#v", acceptedReport)
	}
}

func TestVerifyAttestationCLIExpectedDigestPrecedenceAndTamper(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	_, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "precedence")
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "precedence-private.pem")
	bundlePath := filepath.Join(outputRoot, "bundle.tar")
	publicPath := filepath.Join(outputRoot, "public.pem")
	attestEnvelope, _, attestStderr, attestExit := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath,
		"--out", bundlePath, "--public-key-out", publicPath,
	)
	if attestExit != 0 || attestEnvelope.Status != "ok" {
		t.Fatalf("attest exit=%d envelope=%#v stderr=%s", attestExit, attestEnvelope, attestStderr)
	}
	bundle := mustReadFile(t, bundlePath)
	wantDigest := cliSHA256Digest(bundle)
	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	if wrongDigest == wantDigest {
		wrongDigest = "sha256:" + strings.Repeat("1", 64)
	}
	missingTrust := filepath.Join(keyRoot, "must-not-be-read.pem")
	wrongEnvelope, _, wrongStderr, wrongExit := runAttestationCLI(
		t,
		"--json", "verify-attestation", bundlePath,
		"--trust-key", missingTrust,
		"--expect-bundle-digest", wrongDigest,
	)
	if wrongExit != 7 || wrongEnvelope.Error == nil ||
		wrongEnvelope.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("wrong digest precedence exit=%d envelope=%#v stderr=%s", wrongExit, wrongEnvelope, wrongStderr)
	}

	malformedTrust := filepath.Join(keyRoot, "malformed-public.pem")
	if err := os.WriteFile(malformedTrust, []byte("not a public key\n"), 0o600); err != nil {
		t.Fatalf("write malformed trust fixture: %v", err)
	}
	wrongEnvelope, _, wrongStderr, wrongExit = runAttestationCLI(
		t,
		"--json", "verify-attestation",
		"--expect-bundle-digest="+wrongDigest,
		bundlePath,
		"--trust-key="+malformedTrust,
	)
	if wrongExit != 7 || wrongEnvelope.Error == nil ||
		wrongEnvelope.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("wrong digest before malformed trust exit=%d envelope=%#v stderr=%s", wrongExit, wrongEnvelope, wrongStderr)
	}

	malformedDigest, _, malformedStderr, malformedExit := runAttestationCLI(
		t,
		"--json", "verify-attestation", bundlePath,
		"--expect-bundle-digest", "SHA256:"+strings.Repeat("a", 64),
		"--trust-key", missingTrust,
	)
	if malformedExit != 2 || malformedDigest.Error == nil ||
		malformedDigest.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("malformed digest exit=%d envelope=%#v stderr=%s", malformedExit, malformedDigest, malformedStderr)
	}
	emptyDigest, _, emptyDigestStderr, emptyDigestExit := runAttestationCLI(
		t,
		"--json", "verify-attestation", bundlePath,
		"--expect-bundle-digest=",
	)
	if emptyDigestExit != 2 || emptyDigest.Error == nil ||
		emptyDigest.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("empty digest exit=%d envelope=%#v stderr=%s", emptyDigestExit, emptyDigest, emptyDigestStderr)
	}

	tampered := append([]byte(nil), bundle...)
	tampered[len(tampered)-1] ^= 1
	tamperedPath := filepath.Join(outputRoot, "tampered.tar")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}
	tamperedEnvelope, _, tamperedStderr, tamperedExit := runAttestationCLI(
		t,
		"--json", "verify-attestation", tamperedPath,
		"--trust-key", missingTrust,
		"--expect-bundle-digest", cliSHA256Digest(tampered),
	)
	if tamperedExit != 7 || tamperedEnvelope.Error == nil ||
		tamperedEnvelope.Error.Code != domain.CodeAttestationInvalid {
		t.Fatalf("tamper with recomputed digest exit=%d envelope=%#v stderr=%s", tamperedExit, tamperedEnvelope, tamperedStderr)
	}
}

func TestAttestationArgumentNormalizationPreservesFlagValuesAndDoubleDash(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name string
		got  []string
		want []string
	}{
		{
			name: "verify separated flags after bundle",
			got: normalizeVerifyAttestationArgs([]string{
				"bundle.tar", "--trust-key", "trusted.pem", "--expect-bundle-digest", digest,
			}),
			want: []string{
				"--trust-key", "trusted.pem", "--expect-bundle-digest", digest, "--", "bundle.tar",
			},
		},
		{
			name: "verify equals flags and explicit separator",
			got: normalizeVerifyAttestationArgs([]string{
				"--expect-bundle-digest=" + digest, "--trust-key=trusted.pem", "--", "-bundle.tar",
			}),
			want: []string{
				"--expect-bundle-digest=" + digest, "--trust-key=trusted.pem", "--", "-bundle.tar",
			},
		},
		{
			name: "attest separated values stay paired",
			got: normalizeAttestArgs([]string{
				"--public-key-out", "public.pem", "--out=bundle.tar", "--key", "private.pem", "--run=run_1",
			}),
			want: []string{
				"--public-key-out", "public.pem", "--out=bundle.tar", "--key", "private.pem", "--run=run_1",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if strings.Join(test.got, "\x00") != strings.Join(test.want, "\x00") {
				t.Fatalf("normalized args = %#v, want %#v", test.got, test.want)
			}
		})
	}
}

func TestAttestationHelpListsPortableReplayFlags(t *testing.T) {
	for _, test := range []struct {
		command string
		flag    string
	}{
		{command: "attest", flag: "-public-key-out"},
		{command: "verify-attestation", flag: "-expect-bundle-digest"},
	} {
		t.Run(test.command, func(t *testing.T) {
			_, stdout, stderr, exitCode := runAttestationCLI(t, test.command, "-h")
			if exitCode != 0 || !strings.Contains(stdout+stderr, test.flag) {
				t.Fatalf("help exit=%d lacks %q: stdout=%s stderr=%s", exitCode, test.flag, stdout, stderr)
			}
		})
	}
}

func TestVerifyAttestationCLITamperAndMalformedTrustPrecedence(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	_, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "signer")
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "signer-private.pem")
	bundlePath := filepath.Join(outputRoot, "bundle.tar")
	envelope, _, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath, "--out", bundlePath,
	)
	if exitCode != 0 || envelope.Status != "ok" {
		t.Fatalf("attest exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	raw := mustReadFile(t, bundlePath)
	raw[len(raw)-1] ^= 1
	tamperedPath := filepath.Join(outputRoot, "tampered.tar")
	if err := os.WriteFile(tamperedPath, raw, 0o600); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}
	invalidEnvelope, _, invalidStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", tamperedPath,
	)
	if exitCode != 7 || invalidEnvelope.Error == nil ||
		invalidEnvelope.Error.Code != domain.CodeAttestationInvalid {
		t.Fatalf("tampered verify exit=%d envelope=%#v stderr=%s", exitCode, invalidEnvelope, invalidStderr)
	}

	malformedTrustPath := filepath.Join(keyRoot, "malformed-public.pem")
	if err := os.WriteFile(malformedTrustPath, []byte("not a public key\n"), 0o600); err != nil {
		t.Fatalf("write malformed trust key: %v", err)
	}
	precedenceEnvelope, _, precedenceStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", tamperedPath, "--trust-key", malformedTrustPath,
	)
	if exitCode != 7 || precedenceEnvelope.Error == nil ||
		precedenceEnvelope.Error.Code != domain.CodeAttestationInvalid {
		t.Fatalf("invalid bundle precedence exit=%d envelope=%#v stderr=%s", exitCode, precedenceEnvelope, precedenceStderr)
	}

	missingTrustPath := filepath.Join(keyRoot, "missing-public.pem")
	nonregularTrustPath := filepath.Join(keyRoot, "public-key-directory")
	if err := os.Mkdir(nonregularTrustPath, 0o700); err != nil {
		t.Fatalf("create nonregular trust fixture: %v", err)
	}
	unreadableTrustPath := filepath.Join(keyRoot, "unreadable-public.pem")
	makeCLITrustKeyUnreadableForTest(t, unreadableTrustPath)
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "missing", path: missingTrustPath},
		{name: "nonregular", path: nonregularTrustPath},
		{name: "unreadable", path: unreadableTrustPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalidWithTrust, _, invalidWithTrustStderr, invalidExit := runAttestationCLI(
				t,
				"--json", "verify-attestation", tamperedPath, "--trust-key", test.path,
			)
			if invalidExit != 7 || invalidWithTrust.Error == nil ||
				invalidWithTrust.Error.Code != domain.CodeAttestationInvalid {
				t.Fatalf("invalid bundle + trust read failure exit=%d envelope=%#v stderr=%s", invalidExit, invalidWithTrust, invalidWithTrustStderr)
			}

			validWithTrust, _, validWithTrustStderr, validExit := runAttestationCLI(
				t,
				"--json", "verify-attestation", bundlePath, "--trust-key", test.path,
			)
			if validExit != 7 || validWithTrust.Error == nil ||
				validWithTrust.Error.Code != domain.CodeAttestationUntrusted {
				t.Fatalf("valid bundle + trust read failure exit=%d envelope=%#v stderr=%s", validExit, validWithTrust, validWithTrustStderr)
			}
			var report attestation.VerificationReport
			decodeJSON(t, validWithTrust.Data, &report)
			if report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
				t.Fatalf("valid bundle + trust read failure report = %#v", report)
			}
			assertCLIUntrustedDetails(t, validWithTrust.Error, "rejected")
		})
	}
}

func TestAttestCLIRejectsTamperedAuthoritativeRunBeforeSigning(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	_, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "secret-name")
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "secret-name-private.pem")
	outputPath := filepath.Join(outputRoot, "must-not-exist.tar")
	publicOutputPath := filepath.Join(outputRoot, "must-not-exist-public.pem")
	verificationPath := filepath.Join(dataRoot, "runs", runID, "verification.json")
	var result domain.VerificationResult
	decodeJSON(t, mustReadFile(t, verificationPath), &result)
	result.Subject.TreeDigest = "sha256:" + strings.Repeat("f", 64)
	tamperedJSON, err := canonicaljson.Indent(result)
	if err != nil {
		t.Fatalf("encode tampered verification: %v", err)
	}
	if err := os.WriteFile(verificationPath, tamperedJSON, 0o600); err != nil {
		t.Fatalf("write tampered verification: %v", err)
	}

	envelope, stdout, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath, "--out", outputPath,
		"--public-key-out", publicOutputPath,
	)
	if exitCode != 7 || envelope.Error == nil ||
		envelope.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("tampered run attest exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("tampered run created output: %v", err)
	}
	if _, err := os.Lstat(publicOutputPath); !os.IsNotExist(err) {
		t.Fatalf("tampered run created public companion: %v", err)
	}
	if strings.Contains(stdout+stderr, keyPath) || bytes.Contains([]byte(stdout+stderr), privatePEM) {
		t.Fatal("tampered-run failure leaked private path or material")
	}
}

func TestAttestCLIRejectsMalformedKeyAndExistingOutputWithoutLeaks(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	secretPath := filepath.Join(keyRoot, "do-not-print-private-path.pem")
	secretBytes := []byte("malformed secret private material\n")
	if err := os.WriteFile(secretPath, secretBytes, 0o600); err != nil {
		t.Fatalf("write malformed key: %v", err)
	}
	secureCLIPrivateKeyForTest(t, secretPath)
	outputPath := filepath.Join(outputRoot, "bundle.tar")
	envelope, stdout, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", secretPath, "--out", outputPath,
	)
	if exitCode != 1 || envelope.Error == nil || envelope.Error.Code != domain.CodeSigningFailed {
		t.Fatalf("malformed key exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	if strings.Contains(stdout+stderr, secretPath) || strings.Contains(stdout+stderr, filepath.Base(secretPath)) ||
		bytes.Contains([]byte(stdout+stderr), secretBytes) {
		t.Fatal("malformed-key output leaked private path or bytes")
	}

	validPrivateKey, validPrivatePEM, _ := writeCLIKeyPair(t, keyRoot, "valid")
	defer clear(validPrivateKey)
	defer clear(validPrivatePEM)
	validKeyPath := filepath.Join(keyRoot, "valid-private.pem")
	existing := []byte("preserve me")
	if err := os.WriteFile(outputPath, existing, 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	envelope, _, stderr, exitCode = runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", validKeyPath, "--out", outputPath,
	)
	if exitCode != 1 || envelope.Error == nil || envelope.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("existing output exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	if got := mustReadFile(t, outputPath); !bytes.Equal(got, existing) {
		t.Fatalf("existing output was modified: %q", got)
	}
}

func TestAttestCLIArtifactPathValidationPublishesNeitherOutput(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	_, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "path-validation")
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "path-validation-private.pem")

	sharedPath := filepath.Join(outputRoot, "shared-output")
	collision, stdout, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath,
		"--out", sharedPath, "--public-key-out", sharedPath,
	)
	if exitCode != 1 || collision.Error == nil || collision.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("collision exit=%d envelope=%#v stderr=%s", exitCode, collision, stderr)
	}
	if _, err := os.Lstat(sharedPath); !os.IsNotExist(err) {
		t.Fatalf("collision created output: %v", err)
	}
	if strings.Contains(stdout+stderr, keyPath) || bytes.Contains([]byte(stdout+stderr), privatePEM) {
		t.Fatal("collision failure leaked private path or material")
	}

	emptyCompanionBundle := filepath.Join(outputRoot, "empty-companion-bundle.tar")
	emptyCompanion, _, emptyCompanionStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath,
		"--out", emptyCompanionBundle, "--public-key-out=",
	)
	if exitCode != 2 || emptyCompanion.Error == nil || emptyCompanion.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("empty companion exit=%d envelope=%#v stderr=%s", exitCode, emptyCompanion, emptyCompanionStderr)
	}
	if _, err := os.Lstat(emptyCompanionBundle); !os.IsNotExist(err) {
		t.Fatalf("empty companion flag created bundle: %v", err)
	}

	bundlePath := filepath.Join(outputRoot, "must-not-exist.tar")
	publicPath := filepath.Join(outputRoot, "existing-public.pem")
	want := []byte("preserve-public-destination")
	if err := os.WriteFile(publicPath, want, 0o600); err != nil {
		t.Fatalf("write existing public destination: %v", err)
	}
	existing, _, existingStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath,
		"--out", bundlePath, "--public-key-out", publicPath,
	)
	if exitCode != 1 || existing.Error == nil || existing.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("existing public exit=%d envelope=%#v stderr=%s", exitCode, existing, existingStderr)
	}
	if got := mustReadFile(t, publicPath); !bytes.Equal(got, want) {
		t.Fatalf("existing public destination changed: %q", got)
	}
	if _, err := os.Lstat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("existing public validation created bundle: %v", err)
	}

	dataPublicPath := filepath.Join(dataRoot, "must-not-exist-public.pem")
	isolation, _, isolationStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath,
		"--out", bundlePath, "--public-key-out", dataPublicPath,
	)
	if exitCode != 1 || isolation.Error == nil || isolation.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("data-root public exit=%d envelope=%#v stderr=%s", exitCode, isolation, isolationStderr)
	}
	for _, path := range []string{bundlePath, dataPublicPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("isolation validation created %s: %v", filepath.Base(path), err)
		}
	}
}

func createBlockedAuthoritativeRun(t *testing.T, dataRoot string) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				return []domain.RunnerFeatures{{
					Backend:      "docker",
					Available:    false,
					ControllerOS: runtime.GOOS,
					WorkloadOS:   "linux",
					Rootless:     "unknown",
					Reason:       "attestation CLI test runner is unavailable",
				}}, nil
			},
		},
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), []string{
		"--json", "--data-dir", dataRoot,
		"verify", "--manifest", healthyNodeManifest(t),
	})
	if exitCode != 0 {
		t.Fatalf("create authoritative run exit=%d stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	envelope := decodeEnvelope(t, stdout.Bytes())
	var data verifyEnvelopeData
	decodeJSON(t, envelope.Data, &data)
	if data.Verification.RunID == "" {
		t.Fatal("created verification has no run ID")
	}
	return data.Verification.RunID
}

func writeCLIKeyPair(t *testing.T, directory, prefix string) (ed25519.PrivateKey, []byte, []byte) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := os.WriteFile(filepath.Join(directory, prefix+"-private.pem"), privatePEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.Chmod(filepath.Join(directory, prefix+"-private.pem"), 0o600); err != nil {
		t.Fatalf("chmod private key: %v", err)
	}
	secureCLIPrivateKeyForTest(t, filepath.Join(directory, prefix+"-private.pem"))
	if err := os.WriteFile(filepath.Join(directory, prefix+"-public.pem"), publicPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privateKey, privatePEM, publicPEM
}

func runAttestationCLI(t *testing.T, args ...string) (testEnvelope, string, string, int) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := App{
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), args)
	var envelope testEnvelope
	if json.Valid(stdout.Bytes()) {
		envelope = decodeEnvelope(t, stdout.Bytes())
	}
	return envelope, stdout.String(), stderr.String(), exitCode
}

func assertCLIUntrustedDetails(t *testing.T, err *domain.Error, decision string) {
	t.Helper()
	if err.Details["signatureValid"] != true || err.Details["trustDecision"] != decision {
		t.Fatalf("untrusted error details = %#v", err.Details)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	return raw
}

func cliSHA256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
