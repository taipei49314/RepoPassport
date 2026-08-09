package attestation

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/spdx"
)

func TestEvaluateFreshnessFourDimensionMatrixAndPrecedence(t *testing.T) {
	historical := freshnessClaims()
	base := freshnessObservation(historical)
	tests := []struct {
		name       string
		mutate     func(*CurrentFreshnessObservation)
		want       string
		wantReason string
		statuses   []string
	}{
		{
			name: "current", want: FreshnessCurrent, wantReason: FreshnessReasonNone,
			statuses: []string{FreshnessStatusMatch, FreshnessStatusMatch, FreshnessStatusMatch, FreshnessStatusMatch},
		},
		{
			name: "source changed", mutate: func(value *CurrentFreshnessObservation) {
				changed := *value.Source
				changed.Identity = digestOfByte('5')
				changed.TreeDigest = changed.Identity
				value.Source = &changed
			},
			want: FreshnessStale, wantReason: FreshnessReasonSourceChanged,
			statuses: []string{FreshnessStatusMismatch, FreshnessStatusNotEvaluated, FreshnessStatusNotEvaluated, FreshnessStatusNotEvaluated},
		},
		{
			name: "policy changed before plan", mutate: func(value *CurrentFreshnessObservation) {
				policy := digestOfByte('6')
				plan := digestOfByte('7')
				value.PolicyBundleDigest = &policy
				value.PlanDigest = &plan
			},
			want: FreshnessStale, wantReason: FreshnessReasonPolicyChanged,
			statuses: []string{FreshnessStatusMatch, FreshnessStatusMismatch, FreshnessStatusNotEvaluated, FreshnessStatusNotEvaluated},
		},
		{
			name: "plan changed", mutate: func(value *CurrentFreshnessObservation) {
				plan := digestOfByte('7')
				value.PlanDigest = &plan
			},
			want: FreshnessStale, wantReason: FreshnessReasonPlanChanged,
			statuses: []string{FreshnessStatusMatch, FreshnessStatusMatch, FreshnessStatusMismatch, FreshnessStatusNotEvaluated},
		},
		{
			name: "runner changed", mutate: func(value *CurrentFreshnessObservation) {
				changed := *value.Runner
				changed.EngineVersion = "25.0.1"
				value.Runner = &changed
			},
			want: FreshnessStale, wantReason: FreshnessReasonRunnerChanged,
			statuses: []string{FreshnessStatusMatch, FreshnessStatusMatch, FreshnessStatusMatch, FreshnessStatusMismatch},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := base
			if test.mutate != nil {
				test.mutate(&current)
			}
			got, report := EvaluateFreshness(historical, current)
			if got != test.want || report.Reason != test.wantReason {
				t.Fatalf("evaluation=%q reason=%q, want %q/%q", got, report.Reason, test.want, test.wantReason)
			}
			wantDimensions := []string{"source", "policy", "plan", "runner"}
			if len(report.Checks) != len(wantDimensions) {
				t.Fatalf("checks=%d, want 4", len(report.Checks))
			}
			for index, check := range report.Checks {
				if check.Dimension != wantDimensions[index] || check.Status != test.statuses[index] {
					t.Fatalf("check[%d]=%#v, want dimension=%q status=%q", index, check, wantDimensions[index], test.statuses[index])
				}
			}
		})
	}
}

func TestEvaluateFreshnessUnknownProfilesAndDigestPresence(t *testing.T) {
	historical := freshnessClaims()
	current := freshnessObservation(historical)

	unsupported := historical
	unsupported.Source.Commit = "0123456789012345678901234567890123456789"
	unsupported.Source.Identity = "git:" + unsupported.Source.Commit
	evaluation, report := EvaluateFreshness(unsupported, current)
	if evaluation != FreshnessUnknown || report.Reason != FreshnessReasonSourceIdentityUnavailable ||
		report.Checks[0].Status != FreshnessStatusUnknown {
		t.Fatalf("unsupported source report=%#v evaluation=%q", report, evaluation)
	}

	invalidHistoricalRunner := historical
	invalidHistoricalRunner.Runner.Available = false
	evaluation, report = EvaluateFreshness(invalidHistoricalRunner, current)
	if evaluation != FreshnessUnknown || report.Reason != FreshnessReasonRunnerUnavailable ||
		report.Checks[3].HistoricalDigest != "" || report.Checks[3].CurrentDigest == "" {
		t.Fatalf("invalid historical runner report=%#v evaluation=%q", report, evaluation)
	}

	invalidCurrentRunner := *current.Runner
	invalidCurrentRunner.Rootless = "unknown"
	current.Runner = &invalidCurrentRunner
	evaluation, report = EvaluateFreshness(historical, current)
	if evaluation != FreshnessUnknown || report.Reason != FreshnessReasonRunnerUnavailable ||
		report.Checks[3].HistoricalDigest == "" || report.Checks[3].CurrentDigest != "" {
		t.Fatalf("invalid current runner report=%#v evaluation=%q", report, evaluation)
	}
}

func TestEvaluateFreshnessUnknownStageCheckStates(t *testing.T) {
	historical := freshnessClaims()
	base := freshnessObservation(historical)
	tests := []struct {
		name     string
		current  CurrentFreshnessObservation
		reason   string
		statuses []string
	}{
		{
			name: "source unavailable",
			current: CurrentFreshnessObservation{
				UnavailableReason: FreshnessReasonSourceUnavailable,
			},
			reason: FreshnessReasonSourceUnavailable,
			statuses: []string{
				FreshnessStatusUnknown, FreshnessStatusNotEvaluated,
				FreshnessStatusNotEvaluated, FreshnessStatusNotEvaluated,
			},
		},
		{
			name: "source unstable",
			current: CurrentFreshnessObservation{
				UnavailableReason: FreshnessReasonSourceUnstable,
			},
			reason: FreshnessReasonSourceUnstable,
			statuses: []string{
				FreshnessStatusUnknown, FreshnessStatusNotEvaluated,
				FreshnessStatusNotEvaluated, FreshnessStatusNotEvaluated,
			},
		},
		{
			name: "plan unavailable",
			current: CurrentFreshnessObservation{
				Source:            base.Source,
				UnavailableReason: FreshnessReasonPlanUnavailable,
			},
			reason: FreshnessReasonPlanUnavailable,
			statuses: []string{
				FreshnessStatusMatch, FreshnessStatusUnknown,
				FreshnessStatusUnknown, FreshnessStatusNotEvaluated,
			},
		},
		{
			name: "runner unavailable",
			current: CurrentFreshnessObservation{
				Source:             base.Source,
				PolicyBundleDigest: base.PolicyBundleDigest,
				PlanDigest:         base.PlanDigest,
				UnavailableReason:  FreshnessReasonRunnerUnavailable,
			},
			reason: FreshnessReasonRunnerUnavailable,
			statuses: []string{
				FreshnessStatusMatch, FreshnessStatusMatch,
				FreshnessStatusMatch, FreshnessStatusUnknown,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluation, report := EvaluateFreshness(historical, test.current)
			if evaluation != FreshnessUnknown || report.Reason != test.reason {
				t.Fatalf("evaluation=%q report=%#v", evaluation, report)
			}
			for index, want := range test.statuses {
				if report.Checks[index].Status != want {
					t.Fatalf("check[%d]=%#v, want status %q", index, report.Checks[index], want)
				}
			}
		})
	}
}

func TestRunnerStableDigestGoldenAndExcludedFields(t *testing.T) {
	runner := freshnessClaims().Runner
	want := "sha256:897be7f8375fe7688ca14a5651348d4730a9345ee7016d1562a508fa72b2d6ff"
	got, ok := RunnerStableDigest(runner)
	if !ok || got != want {
		t.Fatalf("runner digest=%q ok=%v, want %q/true", got, ok, want)
	}
	mutated := runner
	mutated.Reason = "dynamic reason"
	mutated.NetworkDeny = !mutated.NetworkDeny
	mutated.FilesystemWriteObservation = "complete"
	mutated.ResourceLimitEnforcement = true
	second, ok := RunnerStableDigest(mutated)
	if !ok || second != got {
		t.Fatalf("excluded fields changed digest: first=%q second=%q ok=%v", got, second, ok)
	}
	for name, invalid := range map[string]domain.RunnerFeatures{
		"unavailable":         withRunnerAvailable(runner, false),
		"unsupported backend": withRunnerBackend(runner, "test"),
		"empty controller":    withRunnerController(runner, ""),
		"non-linux workload":  withRunnerWorkload(runner, "windows"),
		"unknown rootless":    withRunnerRootless(runner, "unknown"),
		"empty engine":        withRunnerEngine(runner, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if digest, valid := RunnerStableDigest(invalid); valid || digest != "" {
				t.Fatalf("invalid profile digest=%q valid=%v", digest, valid)
			}
		})
	}
}

func TestEvaluateFreshnessIsDeterministicAndDoesNotMutateInputs(t *testing.T) {
	historical := freshnessClaims()
	current := freshnessObservation(historical)
	historicalBefore := historical
	currentBefore := current
	firstEvaluation, first := EvaluateFreshness(historical, current)
	secondEvaluation, second := EvaluateFreshness(historical, current)
	if firstEvaluation != secondEvaluation || !reflect.DeepEqual(first, second) {
		t.Fatalf("nondeterministic results: %q/%#v vs %q/%#v", firstEvaluation, first, secondEvaluation, second)
	}
	if !reflect.DeepEqual(historical, historicalBefore) || !reflect.DeepEqual(current, currentBefore) {
		t.Fatal("freshness evaluator mutated its inputs")
	}
}

func FuzzEvaluateFreshnessDeterministic(f *testing.F) {
	f.Add("docker", "linux", "linux", "no", "24.0.7", true)
	f.Add("podman", "windows", "linux", "yes", "5.1.0", true)
	f.Add("invalid", "", "windows", "unknown", "", false)
	f.Fuzz(func(
		t *testing.T,
		backend, controllerOS, workloadOS, rootless, engineVersion string,
		available bool,
	) {
		if len(backend)+len(controllerOS)+len(workloadOS)+len(rootless)+len(engineVersion) > 4096 {
			t.Skip()
		}
		historical := freshnessClaims()
		historical.Runner.Backend = backend
		historical.Runner.ControllerOS = controllerOS
		historical.Runner.WorkloadOS = workloadOS
		historical.Runner.Rootless = rootless
		historical.Runner.EngineVersion = engineVersion
		historical.Runner.Available = available
		current := freshnessObservation(historical)
		firstEvaluation, first := EvaluateFreshness(historical, current)
		secondEvaluation, second := EvaluateFreshness(historical, current)
		if firstEvaluation != secondEvaluation || !reflect.DeepEqual(first, second) {
			t.Fatalf("nondeterministic evaluation: %q/%#v vs %q/%#v", firstEvaluation, first, secondEvaluation, second)
		}
		wantDimensions := []string{"source", "policy", "plan", "runner"}
		if len(first.Checks) != len(wantDimensions) {
			t.Fatalf("check count=%d", len(first.Checks))
		}
		for index, dimension := range wantDimensions {
			if first.Checks[index].Dimension != dimension {
				t.Fatalf("check[%d]=%q, want %q", index, first.Checks[index].Dimension, dimension)
			}
		}
		firstDigest, firstOK := RunnerStableDigest(historical.Runner)
		secondDigest, secondOK := RunnerStableDigest(historical.Runner)
		if firstDigest != secondDigest || firstOK != secondOK {
			t.Fatalf("nondeterministic runner projection: %q/%v vs %q/%v", firstDigest, firstOK, secondDigest, secondOK)
		}
	})
}

func TestVerifyAcceptedReleasesClaimsOnlyAfterExactTrust(t *testing.T) {
	_, privateKey := generateKey(t)
	result := validResult(t, "inconclusive")
	built, err := Build(result, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublic, _ := generateKey(t)
	wrongDER, _, err := marshalPublicKey(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	_, claims, verifyErr := VerifyAccepted(built.Bundle, wrongDER)
	if domain.ErrorCodeOf(verifyErr) != domain.CodeAttestationUntrusted || !reflect.DeepEqual(claims, AcceptedClaims{}) {
		t.Fatalf("untrusted claims=%#v error=%v", claims, verifyErr)
	}
	trusted := publicKeyPEMForTest(t, privateKey)
	report, claims, verifyErr := VerifyAccepted(built.Bundle, trusted)
	if verifyErr != nil || report.TrustDecision != "accepted" ||
		claims.Source != result.Subject || claims.Plan.PlanDigest != result.Plan.PlanDigest ||
		claims.Runner != result.Runner {
		t.Fatalf("accepted report=%#v claims=%#v error=%v", report, claims, verifyErr)
	}
}

func TestVerifyAcceptedPrivacyRejectionReleasesNoClaims(t *testing.T) {
	_, privateKey := generateKey(t)
	unsafeRaw := bytes.Replace(
		validSPDXBytes(),
		[]byte("demo-sbom"),
		[]byte("synthetic.user@example.invalid"),
		1,
	)
	_, unsafeCanonical, err := spdx.Canonicalize(unsafeRaw)
	if err != nil {
		t.Fatalf("canonicalize privacy attack fixture: %v", err)
	}
	attack := buildSPDXPrivacyAttackBundle(t, validSBOMResult(t), unsafeCanonical, privateKey)
	report, claims, verifyErr := VerifyAccepted(
		attack,
		publicKeyPEMForTest(t, privateKey),
	)
	if domain.ErrorCodeOf(verifyErr) != domain.CodeEvidencePrivacyBlocked ||
		!reflect.DeepEqual(claims, AcceptedClaims{}) || report.TrustDecision != "" {
		t.Fatalf("privacy rejection report=%#v claims=%#v error=%v", report, claims, verifyErr)
	}
}

func freshnessClaims() AcceptedClaims {
	sourceDigest := digestOfByte('1')
	return AcceptedClaims{
		Source: domain.PlanSource{Identity: sourceDigest, TreeDigest: sourceDigest},
		Plan: PredicatePlan{
			Scenario: "quickstart", Environment: "linux-node",
			PolicyBundleDigest: digestOfByte('2'), PlanDigest: digestOfByte('3'),
		},
		Runner: domain.RunnerFeatures{
			Backend: "docker", Available: true, ControllerOS: "linux",
			WorkloadOS: "linux", Rootless: "no", EngineVersion: "24.0.7",
		},
	}
}

func freshnessObservation(historical AcceptedClaims) CurrentFreshnessObservation {
	source := historical.Source
	policy := historical.Plan.PolicyBundleDigest
	plan := historical.Plan.PlanDigest
	runner := historical.Runner
	return CurrentFreshnessObservation{
		Source: &source, PolicyBundleDigest: &policy, PlanDigest: &plan, Runner: &runner,
	}
}

func digestOfByte(value byte) string { return "sha256:" + string(makeDigestRunes(value)) }

func makeDigestRunes(value byte) []byte {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return result
}

func withRunnerAvailable(value domain.RunnerFeatures, available bool) domain.RunnerFeatures {
	value.Available = available
	return value
}

func withRunnerBackend(value domain.RunnerFeatures, backend string) domain.RunnerFeatures {
	value.Backend = backend
	return value
}

func withRunnerController(value domain.RunnerFeatures, controller string) domain.RunnerFeatures {
	value.ControllerOS = controller
	return value
}

func withRunnerWorkload(value domain.RunnerFeatures, workload string) domain.RunnerFeatures {
	value.WorkloadOS = workload
	return value
}

func withRunnerRootless(value domain.RunnerFeatures, rootless string) domain.RunnerFeatures {
	value.Rootless = rootless
	return value
}

func withRunnerEngine(value domain.RunnerFeatures, engine string) domain.RunnerFeatures {
	value.EngineVersion = engine
	return value
}
