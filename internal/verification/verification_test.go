package verification

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestAggregateVerdictPrecedence(t *testing.T) {
	base := domain.Verdicts{
		Functional:      domain.FunctionalPass,
		Capability:      domain.CapabilityConforming,
		Reproducibility: domain.ReproducibilityStable,
		Cleanup:         domain.CleanupClean,
		Evidence:        domain.EvidenceUnsigned,
		Freshness:       domain.FreshnessCurrent,
	}
	tests := []struct {
		name string
		edit func(*domain.Verdicts)
		want domain.OverallVerdict
	}{
		{
			name: "functional failure is reported before capability nonconformance",
			edit: func(value *domain.Verdicts) {
				value.Functional = domain.FunctionalFail
				value.Capability = domain.CapabilityNonconforming
			},
			want: domain.OverallFailed,
		},
		{
			name: "cleanup residue is nonconforming",
			edit: func(value *domain.Verdicts) {
				value.Cleanup = domain.CleanupResidue
			},
			want: domain.OverallNonconforming,
		},
		{
			name: "blocked outranks cleanup not tested",
			edit: func(value *domain.Verdicts) {
				value.Functional = domain.FunctionalBlocked
				value.Cleanup = domain.CleanupNotTested
			},
			want: domain.OverallBlocked,
		},
		{
			name: "observer incompleteness is inconclusive",
			edit: func(value *domain.Verdicts) {
				value.Capability = domain.CapabilityIncomplete
			},
			want: domain.OverallInconclusive,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.edit(&input)
			if got := aggregate(input); got != test.want {
				t.Fatalf("aggregate() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildMarksInsufficientObserverCoverageIncomplete(t *testing.T) {
	started := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	result, err := Build(Input{
		RunID:          "run_observer_incomplete",
		VerificationID: "vrf_observer_incomplete",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Evidence:           testNoSBOMEvidence(),
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"filesystem-write"},
		},
		Runner: domain.RunnerFeatures{
			Backend:                    "test",
			NetworkDeny:                true,
			FilesystemWriteObservation: "best-effort",
		},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
		},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
		Requested:  1,
		Completed:  1,
		Matching:   1,
		Cleanup:    domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Results.Functional != domain.FunctionalPass {
		t.Fatalf("functional = %q, want %q", result.Results.Functional, domain.FunctionalPass)
	}
	if result.Results.Capability != domain.CapabilityIncomplete {
		t.Fatalf("capability = %q, want %q", result.Results.Capability, domain.CapabilityIncomplete)
	}
	if result.Results.Overall != domain.OverallInconclusive {
		t.Fatalf("overall = %q, want %q", result.Results.Overall, domain.OverallInconclusive)
	}
	if len(result.ObserverCoverage) != 1 || result.ObserverCoverage[0].Coverage != "best-effort" ||
		result.ObserverCoverage[0].Reason == "" {
		t.Fatalf("unexpected observer coverage: %#v", result.ObserverCoverage)
	}
	if decision := policyDecision(result.PolicyDecisions, "core.required-observer-coverage"); decision != "deny" {
		t.Fatalf("observer coverage policy decision = %q, want deny", decision)
	}
}

func TestBuildUndeclaredRetainedFilesystemWriteSeparatesVerdicts(
	t *testing.T,
) {
	input := retainedFilesystemVerdictInput()
	finding := domain.NewError(
		domain.CodeUndeclaredFilesystemWrite,
		domain.SeverityHigh,
		"Bounded retained output state contains an undeclared change.",
	)
	finding.Details = map[string]any{
		"comparisonScope":       "executed-phase-filesystem-write-union",
		"comparisonVersion":     "0.1.0",
		"declaredPatternCount":  1,
		"comparedChangeCount":   2,
		"allowedChangeCount":    1,
		"undeclaredChangeCount": 1,
	}
	input.Errors = []*domain.Error{finding}

	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Results.Functional != domain.FunctionalPass ||
		result.Results.Capability != domain.CapabilityNonconforming ||
		result.Results.Cleanup != domain.CleanupAllowedResidue ||
		result.Results.Overall != domain.OverallNonconforming {
		t.Fatalf("undeclared retained write verdict separation = %#v", result.Results)
	}
	if result.Runner.FilesystemWriteObservation != "best-effort" ||
		len(result.ObserverCoverage) != 1 ||
		result.ObserverCoverage[0].Feature != "filesystem-write" ||
		result.ObserverCoverage[0].Coverage != "best-effort" ||
		len(result.Errors) != 1 || result.Errors[0] != finding {
		t.Fatalf("undeclared retained write evidence contract = %#v", result)
	}
}

func TestBuildMatchedRetainedFilesystemWriteRemainsIncomplete(
	t *testing.T,
) {
	result, err := Build(retainedFilesystemVerdictInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Results.Functional != domain.FunctionalPass ||
		result.Results.Capability != domain.CapabilityIncomplete ||
		result.Results.Cleanup != domain.CleanupAllowedResidue ||
		result.Results.Overall != domain.OverallInconclusive {
		t.Fatalf("matched retained write verdicts were overstated: %#v", result.Results)
	}
	if result.Runner.FilesystemWriteObservation != "best-effort" ||
		len(result.ObserverCoverage) != 1 ||
		result.ObserverCoverage[0].Feature != "filesystem-write" ||
		result.ObserverCoverage[0].Coverage != "best-effort" ||
		len(result.Errors) != 0 {
		t.Fatalf("matched retained write evidence contract = %#v", result)
	}
}

func TestBuildKeepsBestEffortPortObserverIncomplete(t *testing.T) {
	started := time.Date(2026, time.July, 31, 1, 2, 3, 0, time.UTC)
	result, err := Build(Input{
		RunID:          "run_port_observer_incomplete",
		VerificationID: "vrf_port_observer_incomplete",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Evidence:           testNoSBOMEvidence(),
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"port-listen"},
		},
		Runner: domain.RunnerFeatures{
			Backend:         "docker",
			PortObservation: "best-effort",
		},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
			portListenerObservationForTest(
				started,
				"no-undeclared-observed",
				0,
			),
		},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
		Requested:  1,
		Completed:  1,
		Matching:   1,
		Cleanup:    domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Results.Functional != domain.FunctionalPass ||
		result.Results.Capability != domain.CapabilityIncomplete ||
		result.Results.Overall != domain.OverallInconclusive {
		t.Fatalf(
			"best-effort port verdicts were overstated: %#v",
			result.Results,
		)
	}
	if len(result.ObserverCoverage) != 1 ||
		result.ObserverCoverage[0].Feature != "port-listen" ||
		result.ObserverCoverage[0].Coverage != "best-effort" ||
		result.ObserverCoverage[0].Reason == "" {
		t.Fatalf(
			"unexpected port observer coverage: %#v",
			result.ObserverCoverage,
		)
	}
	if decision := policyDecision(
		result.PolicyDecisions,
		"core.required-observer-coverage",
	); decision != "deny" {
		t.Fatalf(
			"port observer coverage policy decision = %q, want deny",
			decision,
		)
	}
}

func TestBuildUndeclaredPortListenerSeparatesVerdicts(t *testing.T) {
	started := time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC)
	finding := domain.NewError(
		domain.CodeUndeclaredPortListen,
		domain.SeverityHigh,
		"Bounded peer TCP samples observed one or more listeners outside the declared service endpoint.",
	)
	finding.Details = map[string]any{
		"observer":                "docker-peer-port-listener-trace",
		"evidenceBasis":           "aggregate-only",
		"undeclaredEndpointCount": 2,
	}
	result, err := Build(Input{
		RunID:          "run_port_observer_positive",
		VerificationID: "vrf_port_observer_positive",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Evidence:           testNoSBOMEvidence(),
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"port-listen"},
		},
		Runner: domain.RunnerFeatures{
			Backend:         "docker",
			PortObservation: "best-effort",
		},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
			portListenerObservationForTest(
				started,
				"nonconforming-listeners",
				2,
			),
		},
		Assertions: []domain.AssertionResult{{
			ID: "journey", Type: "exit-code", Status: "pass",
		}},
		Errors:    []*domain.Error{finding},
		Requested: 1,
		Completed: 1,
		Matching:  1,
		Cleanup:   domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Results.Functional != domain.FunctionalPass ||
		result.Results.Capability != domain.CapabilityNonconforming ||
		result.Results.Overall != domain.OverallNonconforming {
		t.Fatalf(
			"undeclared port listener verdict separation = %#v",
			result.Results,
		)
	}
	if result.Runner.PortObservation != "best-effort" ||
		len(result.ObserverCoverage) != 1 ||
		result.ObserverCoverage[0].Feature != "port-listen" ||
		result.ObserverCoverage[0].Coverage != "best-effort" ||
		len(result.Errors) != 1 || result.Errors[0] != finding {
		t.Fatalf("undeclared port listener evidence contract = %#v", result)
	}
	for _, decision := range result.PolicyDecisions {
		if decision.PolicyID != "core.required-observer-coverage" {
			continue
		}
		if decision.Decision != "deny" ||
			decision.Message != "Required observer coverage is incomplete." {
			t.Fatalf("port observer coverage policy = %#v, want deny/incomplete", decision)
		}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var roundTripped domain.VerificationResult
		if err := json.Unmarshal(data, &roundTripped); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := VerifyIntegrity(roundTripped); err != nil {
			t.Fatalf("round-trip integrity: %v", err)
		}
		return
	}
	t.Fatal("required observer coverage policy is absent")
}

func TestBuildAggregatesConsistentPositivePortListenerRepeats(t *testing.T) {
	started := time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC)
	result, err := Build(Input{
		RunID: "run_port_repeats", VerificationID: "vrf_port_repeats",
		Plan: domain.ResolvedPlan{
			SchemaVersion: "4", Evidence: testNoSBOMEvidence(),
			Scenario: "quickstart", Environment: "linux-node",
			PlanDigest: "sha256:plan", PolicyBundleDigest: "sha256:policy",
			ObserverSet: []string{"port-listen"}, RepeatCount: 2,
		},
		Runner:    domain.RunnerFeatures{Backend: "docker", PortObservation: "best-effort"},
		StartedAt: started, CompletedAt: started.Add(2 * time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
			cleanupObservationForTest(
				started.Add(time.Second), domain.CleanupClean,
			),
			portListenerObservationForTest(started, "nonconforming-listeners", 1),
			portListenerObservationForTest(
				started.Add(time.Second), "nonconforming-listeners", 1,
			),
		},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
		Errors:     []*domain.Error{portListenerFindingForTest(1)},
		Requested:  2, Completed: 2, Matching: 2, Cleanup: domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Repeats.Completed != 2 || len(result.Errors) != 1 ||
		result.Errors[0].Code != domain.CodeUndeclaredPortListen {
		t.Fatalf("consistent repeated port aggregate = %#v", result)
	}
}

func TestPortListenerEvidenceRejectsForgedPublicContract(t *testing.T) {
	started := time.Date(2026, time.August, 3, 2, 3, 4, 0, time.UTC)
	base := func(comparison string, undeclared int) Input {
		input := Input{
			RunID:          "run_port_contract",
			VerificationID: "vrf_port_contract",
			Plan: domain.ResolvedPlan{
				SchemaVersion: "4", Evidence: testNoSBOMEvidence(),
				Scenario: "quickstart", Environment: "linux-node",
				PlanDigest: "sha256:plan", PolicyBundleDigest: "sha256:policy",
				ObserverSet: []string{"port-listen"},
			},
			Runner: domain.RunnerFeatures{
				Backend: "docker", PortObservation: "best-effort",
			},
			StartedAt: started, CompletedAt: started.Add(time.Second),
			Observations: []domain.ObservationEvent{
				cleanupObservationForTest(started, domain.CleanupClean),
				portListenerObservationForTest(started, comparison, undeclared),
			},
			Assertions: []domain.AssertionResult{{
				ID: "journey", Type: "exit-code", Status: "pass",
			}},
			Requested: 1, Completed: 1, Matching: 1, Cleanup: domain.CleanupClean,
		}
		if comparison == "nonconforming-listeners" {
			input.Errors = []*domain.Error{portListenerFindingForTest(undeclared)}
		}
		return input
	}

	for _, test := range []struct {
		name   string
		input  Input
		mutate func(*Input)
	}{
		{
			name:  "raw endpoint detail",
			input: base("no-undeclared-observed", 0),
			mutate: func(input *Input) {
				input.Observations[1].Details["endpoint"] = "127.0.0.1:18081/tcp"
			},
		},
		{
			name:  "wrong count type",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Observations[1].Details["undeclaredEndpointCount"] = "1"
			},
		},
		{
			name:  "inconsistent sampled count",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Observations[1].Details["sampledEndpointCount"] = 1
			},
		},
		{
			name:  "positive repeats disagree on aggregate count",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Observations = append(input.Observations,
					cleanupObservationForTest(started.Add(time.Second), domain.CleanupClean),
					portListenerObservationForTest(started, "nonconforming-listeners", 2),
				)
				input.Requested = 2
				input.Completed = 2
				input.Matching = 2
			},
		},
		{
			name:  "not-tested exposes complete count",
			input: base("no-undeclared-observed", 0),
			mutate: func(input *Input) {
				input.Observations[1] = portListenerNotTestedObservationForTest(started, "")
				input.Observations[1].Details["sampleCount"] = 3
			},
		},
		{
			name:  "not-tested exposes raw endpoint detail",
			input: base("no-undeclared-observed", 0),
			mutate: func(input *Input) {
				input.Observations[1] = portListenerNotTestedObservationForTest(started, "")
				input.Observations[1].Details["endpoint"] = "127.0.0.1:18081/tcp"
			},
		},
		{
			name:  "not-tested uses non-allowlisted failure",
			input: base("no-undeclared-observed", 0),
			mutate: func(input *Input) {
				input.Observations[1] = portListenerNotTestedObservationForTest(
					started, "observer-panicked",
				)
			},
		},
		{
			name:  "positive without finding",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Errors = nil
			},
		},
		{
			name:  "duplicate positive finding",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Errors = append(input.Errors, portListenerFindingForTest(1))
			},
		},
		{
			name:  "finding exposes raw endpoint detail",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Errors[0].Details["endpoint"] = "127.0.0.1:18081/tcp"
			},
		},
		{
			name:  "finding has wrong severity",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Errors[0].Severity = domain.SeverityMedium
			},
		},
		{
			name:  "finding has wrong message",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Errors[0].Message = "listener findings are available"
			},
		},
		{
			name:  "finding has wrong count type",
			input: base("nonconforming-listeners", 1),
			mutate: func(input *Input) {
				input.Errors[0].Details["undeclaredEndpointCount"] = "1"
			},
		},
		{
			name:  "finding without positive summary",
			input: base("no-undeclared-observed", 0),
			mutate: func(input *Input) {
				input.Errors = []*domain.Error{portListenerFindingForTest(1)}
			},
		},
		{
			name:  "non-required forged summary",
			input: base("no-undeclared-observed", 0),
			mutate: func(input *Input) {
				input.Plan.ObserverSet = []string{"network-enforcement"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate(&test.input)
			_, err := Build(test.input)
			if domain.ErrorCodeOf(err) != domain.CodeObservationSchemaInvalid {
				t.Fatalf("Build error code = %q, want observation schema invalid: %v", domain.ErrorCodeOf(err), err)
			}
			if err != nil && strings.Contains(err.Error(), "18081") {
				t.Fatalf("Build error echoed raw endpoint: %v", err)
			}
		})
	}
}

func TestPortListenerEvidenceIntegritySurvivesJSONRoundTripAndRejectsRewrappedRawDetail(t *testing.T) {
	started := time.Date(2026, time.August, 3, 2, 3, 4, 0, time.UTC)
	result, err := Build(Input{
		RunID: "run_port_roundtrip", VerificationID: "vrf_port_roundtrip",
		Plan: domain.ResolvedPlan{
			SchemaVersion: "4", Evidence: testNoSBOMEvidence(),
			Scenario: "quickstart", Environment: "linux-node",
			PlanDigest: "sha256:plan", PolicyBundleDigest: "sha256:policy",
			ObserverSet: []string{"port-listen"},
		},
		Runner:    domain.RunnerFeatures{Backend: "docker", PortObservation: "best-effort"},
		StartedAt: started, CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
			portListenerObservationForTest(started, "nonconforming-listeners", 1),
		},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
		Errors:     []*domain.Error{portListenerFindingForTest(1)},
		Requested:  1, Completed: 1, Matching: 1, Cleanup: domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTripped domain.VerificationResult
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyIntegrity(roundTripped); err != nil {
		t.Fatalf("round-trip integrity: %v", err)
	}
	roundTripped.Observations[1].Details["endpoint"] = "127.0.0.1:18081/tcp"
	roundTripped.Digests.Observations, err = canonicaljson.Digest(roundTripped.Observations)
	if err != nil {
		t.Fatalf("re-digest observations: %v", err)
	}
	roundTripped.Digests.Verification, err = verificationDigest(roundTripped)
	if err != nil {
		t.Fatalf("re-digest verification: %v", err)
	}
	if err := VerifyIntegrity(roundTripped); domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("rewrapped raw endpoint error code = %q, want digest mismatch: %v", domain.ErrorCodeOf(err), err)
	} else if strings.Contains(err.Error(), "18081") {
		t.Fatalf("integrity error echoed raw endpoint: %v", err)
	}
}

func TestPortListenerNotTestedIntegrityRejectsRewrappedInvalidDetails(t *testing.T) {
	started := time.Date(2026, time.August, 3, 2, 3, 4, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*domain.VerificationResult)
	}{
		{
			name: "complete count",
			mutate: func(result *domain.VerificationResult) {
				result.Observations[1].Details["sampleCount"] = 3
			},
		},
		{
			name: "raw endpoint",
			mutate: func(result *domain.VerificationResult) {
				result.Observations[1].Details["endpoint"] = "127.0.0.1:18081/tcp"
			},
		},
		{
			name: "non-allowlisted failure",
			mutate: func(result *domain.VerificationResult) {
				result.Observations[1].Details["failure"] = "observer-panicked"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := Build(Input{
				RunID: "run_port_not_tested", VerificationID: "vrf_port_not_tested",
				Plan: domain.ResolvedPlan{
					SchemaVersion: "4", Evidence: testNoSBOMEvidence(),
					Scenario: "quickstart", Environment: "linux-node",
					PlanDigest: "sha256:plan", PolicyBundleDigest: "sha256:policy",
					ObserverSet: []string{"port-listen"},
				},
				Runner:    domain.RunnerFeatures{Backend: "docker", PortObservation: "best-effort"},
				StartedAt: started, CompletedAt: started.Add(time.Second),
				Observations: []domain.ObservationEvent{
					cleanupObservationForTest(started, domain.CleanupClean),
					portListenerNotTestedObservationForTest(started, "observer-not-started"),
				},
				Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
				Requested:  1, Completed: 1, Matching: 1, Cleanup: domain.CleanupClean,
			})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			test.mutate(&result)
			result.Digests.Observations, err = canonicaljson.Digest(result.Observations)
			if err != nil {
				t.Fatalf("re-digest observations: %v", err)
			}
			result.Digests.Verification, err = verificationDigest(result)
			if err != nil {
				t.Fatalf("re-digest verification: %v", err)
			}
			if err := VerifyIntegrity(result); domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
				t.Fatalf("rewrapped not-tested error code = %q, want digest mismatch: %v", domain.ErrorCodeOf(err), err)
			} else if strings.Contains(err.Error(), "18081") {
				t.Fatalf("integrity error echoed raw endpoint: %v", err)
			}
		})
	}
}

func TestPortListenerFindingIntegrityRejectsRewrappedInvalidDetails(t *testing.T) {
	started := time.Date(2026, time.August, 3, 2, 3, 4, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*domain.VerificationResult)
	}{
		{
			name: "raw endpoint",
			mutate: func(result *domain.VerificationResult) {
				result.Errors[0].Details["endpoint"] = "127.0.0.1:18081/tcp"
			},
		},
		{
			name: "wrong severity",
			mutate: func(result *domain.VerificationResult) {
				result.Errors[0].Severity = domain.SeverityMedium
			},
		},
		{
			name: "wrong message",
			mutate: func(result *domain.VerificationResult) {
				result.Errors[0].Message = "listener findings are available"
			},
		},
		{
			name: "wrong count type",
			mutate: func(result *domain.VerificationResult) {
				result.Errors[0].Details["undeclaredEndpointCount"] = "1"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := Build(Input{
				RunID: "run_port_finding", VerificationID: "vrf_port_finding",
				Plan: domain.ResolvedPlan{
					SchemaVersion: "4", Evidence: testNoSBOMEvidence(),
					Scenario: "quickstart", Environment: "linux-node",
					PlanDigest: "sha256:plan", PolicyBundleDigest: "sha256:policy",
					ObserverSet: []string{"port-listen"},
				},
				Runner:    domain.RunnerFeatures{Backend: "docker", PortObservation: "best-effort"},
				StartedAt: started, CompletedAt: started.Add(time.Second),
				Observations: []domain.ObservationEvent{
					cleanupObservationForTest(started, domain.CleanupClean),
					portListenerObservationForTest(started, "nonconforming-listeners", 1),
				},
				Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
				Errors:     []*domain.Error{portListenerFindingForTest(1)},
				Requested:  1, Completed: 1, Matching: 1, Cleanup: domain.CleanupClean,
			})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			test.mutate(&result)
			result.Digests.Verification, err = verificationDigest(result)
			if err != nil {
				t.Fatalf("re-digest verification: %v", err)
			}
			if err := VerifyIntegrity(result); domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
				t.Fatalf("rewrapped finding error code = %q, want digest mismatch: %v", domain.ErrorCodeOf(err), err)
			} else if strings.Contains(err.Error(), "18081") {
				t.Fatalf("integrity error echoed raw endpoint: %v", err)
			}
		})
	}
}

func portListenerFindingForTest(undeclared int) *domain.Error {
	finding := domain.NewError(
		domain.CodeUndeclaredPortListen,
		domain.SeverityHigh,
		"Bounded peer TCP samples observed one or more listeners outside the declared service endpoint.",
	)
	finding.Details = map[string]any{
		"observer":                "docker-peer-port-listener-trace",
		"evidenceBasis":           "aggregate-only",
		"undeclaredEndpointCount": undeclared,
	}
	return finding
}

func TestBuildPreservesNonconformanceWhenJourneyAlsoFails(t *testing.T) {
	started := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	result, err := Build(Input{
		RunID:          "run_precedence",
		VerificationID: "vrf_precedence",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Evidence:           testNoSBOMEvidence(),
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"network-enforcement"},
		},
		Runner:      domain.RunnerFeatures{Backend: "test", NetworkDeny: true},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
		},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "fail"}},
		Errors:     []*domain.Error{domain.NewError(domain.CodeUndeclaredNetwork, domain.SeverityHigh, "undeclared network")},
		Requested:  1,
		Completed:  1,
		Matching:   0,
		Cleanup:    domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Results.Functional != domain.FunctionalFail {
		t.Fatalf("functional = %q, want %q", result.Results.Functional, domain.FunctionalFail)
	}
	if result.Results.Capability != domain.CapabilityNonconforming {
		t.Fatalf("capability = %q, want %q", result.Results.Capability, domain.CapabilityNonconforming)
	}
	if result.Results.Overall != domain.OverallFailed {
		t.Fatalf("overall = %q, want %q", result.Results.Overall, domain.OverallFailed)
	}
}

func TestBuildPreservesBoundedResourceUsageEvidence(t *testing.T) {
	input := resourceEvidenceInput()
	input.Resources = domain.ResourceSummary{
		SandboxPeakMemoryBytes: 4096,
		SandboxCPUTimeMillis:   17,
		DurationMillis:         23,
		MaxTasks:               3,
		LogBytes:               512,
		WritableBytes:          2048,
		OutputBytes:            1024,
		ObservedFields: []domain.ResourceObservedField{
			domain.ResourceObservedMaxTasks,
			domain.ResourceObservedOutputBytes,
			domain.ResourceObservedSandboxCPUTimeMillis,
			domain.ResourceObservedSandboxPeakMemoryBytes,
			domain.ResourceObservedWritableBytes,
		},
	}
	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !reflect.DeepEqual(result.Resources, input.Resources) {
		t.Fatalf(
			"resources = %#v, want %#v",
			result.Resources,
			input.Resources,
		)
	}
}

func TestBuildRejectsNegativeResourceUsageEvidence(t *testing.T) {
	tests := map[string]func(*domain.ResourceSummary){
		"peakMemoryBytes": func(value *domain.ResourceSummary) {
			value.PeakMemoryBytes = -1
		},
		"cpuTimeMillis": func(value *domain.ResourceSummary) {
			value.CPUTimeMillis = -1
		},
		"durationMillis": func(value *domain.ResourceSummary) {
			value.DurationMillis = -1
		},
		"maxProcesses": func(value *domain.ResourceSummary) {
			value.MaxProcesses = -1
		},
		"logBytes": func(value *domain.ResourceSummary) {
			value.LogBytes = -1
		},
		"sandboxPeakMemoryBytes": func(value *domain.ResourceSummary) {
			value.SandboxPeakMemoryBytes = -1
		},
		"sandboxCPUTimeMillis": func(value *domain.ResourceSummary) {
			value.SandboxCPUTimeMillis = -1
		},
		"maxTasks": func(value *domain.ResourceSummary) {
			value.MaxTasks = -1
		},
		"writableBytes": func(value *domain.ResourceSummary) {
			value.WritableBytes = -1
		},
		"outputBytes": func(value *domain.ResourceSummary) {
			value.OutputBytes = -1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := resourceEvidenceInput()
			mutate(&input.Resources)
			if _, err := Build(input); err == nil ||
				domain.ErrorCodeOf(err) !=
					domain.CodeObservationSchemaInvalid {
				t.Fatalf("Build error = %v", err)
			}
		})
	}
}

func TestBuildRequiresCanonicalObservedResourceFields(t *testing.T) {
	tests := map[string]func(*domain.ResourceSummary){
		"missing field marker": func(value *domain.ResourceSummary) {
			value.WritableBytes = 1
		},
		"duplicate marker": func(value *domain.ResourceSummary) {
			value.ObservedFields = []domain.ResourceObservedField{
				domain.ResourceObservedMaxTasks,
				domain.ResourceObservedMaxTasks,
			}
		},
		"out of order markers": func(value *domain.ResourceSummary) {
			value.ObservedFields = []domain.ResourceObservedField{
				domain.ResourceObservedWritableBytes,
				domain.ResourceObservedMaxTasks,
			}
		},
		"unknown marker": func(value *domain.ResourceSummary) {
			value.ObservedFields = []domain.ResourceObservedField{"unknown"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := resourceEvidenceInput()
			mutate(&input.Resources)
			if _, err := Build(input); err == nil ||
				domain.ErrorCodeOf(err) !=
					domain.CodeObservationSchemaInvalid {
				t.Fatalf("Build error = %v", err)
			}
		})
	}

	input := resourceEvidenceInput()
	input.Resources.ObservedFields = []domain.ResourceObservedField{
		domain.ResourceObservedWritableBytes,
	}
	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build observed zero: %v", err)
	}
	if len(result.Resources.ObservedFields) != 1 ||
		result.Resources.WritableBytes != 0 {
		t.Fatalf("observed zero was not preserved: %#v", result.Resources)
	}
}

func TestResourceEnforcementAndObservationCoverageStaySeparate(t *testing.T) {
	input := resourceEvidenceInput()
	input.Plan.ObserverSet = []string{"resource-usage"}
	input.Runner.ResourceUsage = "enforcement-only"
	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Runner.ResourceUsage != "unavailable" ||
		len(result.ObserverCoverage) != 1 ||
		result.ObserverCoverage[0].Coverage != "unavailable" ||
		result.Results.Capability != domain.CapabilityIncomplete {
		t.Fatalf("enforcement was treated as observation: %#v", result)
	}
	if decision := policyDecision(
		result.PolicyDecisions,
		"core.resource-limit-enforcement",
	); decision != "allow" {
		t.Fatalf("resource enforcement policy = %q, want allow", decision)
	}

	input = resourceEvidenceInput()
	input.Plan.ObserverSet = []string{"resource-usage"}
	input.Runner.ResourceLimitEnforcement = false
	result, err = Build(input)
	if err != nil {
		t.Fatalf("Build without enforcement: %v", err)
	}
	if result.Runner.ResourceUsage != "high" ||
		result.Results.Capability != domain.CapabilityConforming {
		t.Fatalf("observation coverage was lost: %#v", result)
	}
	if decision := policyDecision(
		result.PolicyDecisions,
		"core.resource-limit-enforcement",
	); decision != "deny" {
		t.Fatalf("resource enforcement policy = %q, want deny", decision)
	}
}

func TestFunctionalSetupFailureOverridesBlockedJourney(t *testing.T) {
	got := functionalVerdict(Input{
		Assertions: []domain.AssertionResult{{
			ID:       "journey",
			Required: true,
			Status:   "blocked",
		}},
		Errors: []*domain.Error{
			domain.NewError(domain.CodeSetupFailed, domain.SeverityHigh, "setup failed"),
		},
		Completed: 1,
	})
	if got != domain.FunctionalFail {
		t.Fatalf("functional verdict = %q, want %q", got, domain.FunctionalFail)
	}
}

func TestReproducibilityHonorsSuccessThreshold(t *testing.T) {
	if got := reproducibilityVerdict(3, 0, 0, 3); got != domain.ReproducibilityNotTested {
		t.Fatalf("unattempted repetition = %q, want %q", got, domain.ReproducibilityNotTested)
	}
	if got := reproducibilityVerdict(3, 3, 2, 2); got != domain.ReproducibilityFlaky {
		t.Fatalf("threshold-met disagreement = %q, want %q", got, domain.ReproducibilityFlaky)
	}
	if got := reproducibilityVerdict(3, 3, 1, 2); got != domain.ReproducibilityNotReproducible {
		t.Fatalf("below-threshold disagreement = %q, want %q", got, domain.ReproducibilityNotReproducible)
	}
	if got := reproducibilityVerdict(3, 3, 3, 2); got != domain.ReproducibilityStable {
		t.Fatalf("all-matching result = %q, want %q", got, domain.ReproducibilityStable)
	}
}

func TestBuildPreservesTypedCleanupVerdicts(t *testing.T) {
	destroy := domain.NewError(
		domain.CodeSandboxDestroyFailed,
		domain.SeverityHigh,
		"destroy failed",
	)
	residue := domain.NewError(
		domain.CodeCleanupResidue,
		domain.SeverityHigh,
		"residue observed",
	)
	cleanupFailed := domain.NewError(
		domain.CodeCleanupFailed,
		domain.SeverityHigh,
		"cleanup failed",
	)
	for _, errs := range [][]*domain.Error{
		{destroy, residue, cleanupFailed},
		{cleanupFailed, residue, destroy},
		{residue, destroy, cleanupFailed},
	} {
		if got := cleanupVerdict(
			domain.CleanupUndeclaredResidue,
			1,
			errs,
		); got != domain.CleanupUndeclaredResidue {
			t.Fatalf(
				"undeclared residue was lost for errors %#v: %q",
				errs,
				got,
			)
		}
	}
	if got := cleanupVerdict(
		domain.CleanupAllowedResidue,
		1,
		[]*domain.Error{destroy},
	); got != domain.CleanupNotTested {
		t.Fatalf("allowed plus destroy failure = %q, want not-tested", got)
	}
	if got := cleanupVerdict(
		domain.CleanupClean,
		1,
		[]*domain.Error{residue},
	); got != domain.CleanupUndeclaredResidue {
		t.Fatalf("residue finding plus clean = %q, want undeclared", got)
	}
	if got := cleanupVerdict(
		domain.CleanupUndeclaredResidue,
		0,
		[]*domain.Error{residue},
	); got != domain.CleanupNotTested {
		t.Fatalf("zero completed repeats = %q, want not-tested", got)
	}
}

func TestVerifyIntegrityRejectsRewrappedComponentTamper(t *testing.T) {
	result := integrityFixture(t)
	result.Assertions[0].Status = "failed"
	var err error
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		t.Fatalf("verificationDigest: %v", err)
	}
	if err := VerifyIntegrity(result); err == nil {
		t.Fatal("VerifyIntegrity accepted a changed assertion with only the outer digest recomputed")
	}
}

func TestBuildDeepCopiesPlanEvidenceSlices(t *testing.T) {
	input := resourceEvidenceInput()
	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	input.Plan.Evidence.Include[0] = "mutated-input"
	input.Plan.Evidence.Exclude[0] = "mutated-input"
	if result.Plan.Evidence.Include[0] != "normalized-observations" ||
		result.Plan.Evidence.Exclude[0] != "raw-stderr" {
		t.Fatalf("verification retained aliased plan evidence: %#v", result.Plan.Evidence)
	}
}

func TestVerifyIntegrityRejectsSelfDigestedInvalidSchema4Evidence(t *testing.T) {
	tests := map[string]func(*domain.VerificationResult){
		"resolved plan schema": func(result *domain.VerificationResult) {
			result.Plan.ResolvedPlanSchemaVersion = "3"
		},
		"profile": func(result *domain.VerificationResult) {
			result.Plan.Evidence.Profile = "local-full"
		},
		"include": func(result *domain.VerificationResult) {
			result.Plan.Evidence.Include = []string{"normalized-observations", "other", "verification-summary"}
		},
		"exclude": func(result *domain.VerificationResult) {
			result.Plan.Evidence.Exclude = []string{"raw-stderr", "raw-stdout"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := integrityFixture(t)
			mutate(&result)
			var err error
			result.Digests.Verification, err = verificationDigest(result)
			if err != nil {
				t.Fatalf("recompute outer verification digest: %v", err)
			}
			if err := VerifyIntegrity(result); err == nil {
				t.Fatalf("VerifyIntegrity accepted self-digested invalid schema-4 %s", name)
			}
		})
	}
}

func TestBuildRejectsCleanupObservationVerdictMismatch(t *testing.T) {
	input := resourceEvidenceInput()
	input.Cleanup = domain.CleanupAllowedResidue
	if _, err := Build(input); err == nil ||
		domain.ErrorCodeOf(err) != domain.CodeObservationSchemaInvalid {
		t.Fatalf("Build mismatch error = %v", err)
	}
}

func TestVerifyIntegrityRejectsRewrappedCleanupResultTamper(t *testing.T) {
	result := integrityFixture(t)
	result.Results.Cleanup = domain.CleanupAllowedResidue
	result.Results.Overall = aggregate(result.Results)
	var err error
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		t.Fatalf("verificationDigest: %v", err)
	}
	if err := VerifyIntegrity(result); err == nil {
		t.Fatal("VerifyIntegrity accepted cleanup result tamper backed only by its outer digest")
	}
}

func TestVerifyIntegrityRejectsRewrappedCleanupObservationMismatch(
	t *testing.T,
) {
	result := integrityFixture(t)
	result.Observations[0].Details["verdict"] =
		string(domain.CleanupAllowedResidue)
	result.Results.Cleanup = domain.CleanupAllowedResidue
	result.Results.Overall = aggregate(result.Results)
	var err error
	result.Digests.Observations, err = canonicaljson.Digest(
		result.Observations,
	)
	if err != nil {
		t.Fatalf("observations digest: %v", err)
	}
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		t.Fatalf("verificationDigest: %v", err)
	}
	if err := VerifyIntegrity(result); err == nil {
		t.Fatal("VerifyIntegrity accepted an internally impossible cleanup observation")
	}
}

func TestVerifyIntegrityRejectsNullFindingWithoutPanic(t *testing.T) {
	result := integrityFixture(t)
	result.Errors = []*domain.Error{nil}
	var err error
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		t.Fatalf("verificationDigest: %v", err)
	}
	if err := VerifyIntegrity(result); err == nil ||
		domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("VerifyIntegrity null finding error = %v", err)
	}
}

func TestCleanupObservationExtractorRejectsImpossibleStates(t *testing.T) {
	tests := map[string]func(*domain.ObservationEvent){
		"allowed residue contains a symlink": func(value *domain.ObservationEvent) {
			value.Details["entryCount"] = 1
			value.Details["symlinkCount"] = 1
			value.Details["unmatchedCount"] = 1
			value.Details["verdict"] =
				string(domain.CleanupAllowedResidue)
		},
		"not tested flags are not monotonic": func(value *domain.ObservationEvent) {
			value.Details["identityVerified"] = true
		},
		"not tested failure is unbounded": func(value *domain.ObservationEvent) {
			value.Details["failure"] = "attacker-controlled"
		},
		"classification failure lacks complete inventory": func(value *domain.ObservationEvent) {
			value.Details["failure"] = "random-unavailable"
		},
		"incomplete inventory publishes counts": func(value *domain.ObservationEvent) {
			value.Details["entryCount"] = 1
			value.Details["regularFileCount"] = 1
		},
		"entry count exceeds classifier bound": func(value *domain.ObservationEvent) {
			value.Details["entryCount"] = 2049
			value.Details["regularFileCount"] = 2049
		},
		"profile understates unmatched entries": func(value *domain.ObservationEvent) {
			value.Details["allowedPatternCount"] = 0
			value.Details["allowedProfile"] = "none"
			value.Details["entryCount"] = 1
			value.Details["regularFileCount"] = 1
			value.Details["unmatchedCount"] = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := cleanupObservationForTest(
				time.Date(2026, time.July, 31, 0, 0, 0, 0, time.UTC),
				domain.CleanupNotTested,
			)
			if name == "allowed residue contains a symlink" ||
				name == "entry count exceeds classifier bound" ||
				name == "profile understates unmatched entries" {
				value = cleanupObservationForTest(
					value.Timestamp,
					domain.CleanupClean,
				)
			}
			mutate(&value)
			if _, err := cleanupVerdictFromObservation(value); err == nil {
				t.Fatal("impossible cleanup observation was accepted")
			}
		})
	}
}

func TestCleanupObservationAggregationIsOrderIndependent(t *testing.T) {
	tests := []struct {
		name     string
		verdicts []domain.CleanupVerdict
		want     domain.CleanupVerdict
	}{
		{
			name: "clean then allowed",
			verdicts: []domain.CleanupVerdict{
				domain.CleanupClean,
				domain.CleanupAllowedResidue,
			},
			want: domain.CleanupAllowedResidue,
		},
		{
			name: "allowed then clean",
			verdicts: []domain.CleanupVerdict{
				domain.CleanupAllowedResidue,
				domain.CleanupClean,
			},
			want: domain.CleanupAllowedResidue,
		},
		{
			name: "allowed then not tested",
			verdicts: []domain.CleanupVerdict{
				domain.CleanupAllowedResidue,
				domain.CleanupNotTested,
			},
			want: domain.CleanupNotTested,
		},
		{
			name: "not tested then allowed",
			verdicts: []domain.CleanupVerdict{
				domain.CleanupNotTested,
				domain.CleanupAllowedResidue,
			},
			want: domain.CleanupNotTested,
		},
		{
			name: "not tested then undeclared",
			verdicts: []domain.CleanupVerdict{
				domain.CleanupNotTested,
				domain.CleanupUndeclaredResidue,
			},
			want: domain.CleanupUndeclaredResidue,
		},
		{
			name: "undeclared then not tested",
			verdicts: []domain.CleanupVerdict{
				domain.CleanupUndeclaredResidue,
				domain.CleanupNotTested,
			},
			want: domain.CleanupUndeclaredResidue,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observations := make(
				[]domain.ObservationEvent,
				0,
				len(test.verdicts),
			)
			for index, verdict := range test.verdicts {
				observations = append(
					observations,
					cleanupObservationForTest(
						time.Date(
							2026,
							time.July,
							31,
							0,
							0,
							index,
							0,
							time.UTC,
						),
						verdict,
					),
				)
			}
			got, err := cleanupVerdictFromObservations(
				observations,
				len(observations),
			)
			if err != nil {
				t.Fatalf("cleanupVerdictFromObservations: %v", err)
			}
			if got != test.want {
				t.Fatalf("cleanup aggregate = %q, want %q", got, test.want)
			}
		})
	}
}

func TestVerifyIntegrityRejectsUnsupportedSignedClaim(t *testing.T) {
	result := integrityFixture(t)
	result.Results.Evidence = domain.EvidenceEnterpriseSigned
	result.Results.Overall = aggregate(result.Results)
	var err error
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		t.Fatalf("verificationDigest: %v", err)
	}
	if err := VerifyIntegrity(result); err == nil {
		t.Fatal("VerifyIntegrity accepted a self-digested enterprise-signed claim")
	}
}

func TestVerifyIntegrityRejectsSelfDigestedInvalidResourceEvidence(
	t *testing.T,
) {
	result := integrityFixture(t)
	result.Resources.WritableBytes = -1
	var err error
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		t.Fatalf("verificationDigest: %v", err)
	}
	if err := VerifyIntegrity(result); err == nil {
		t.Fatal("VerifyIntegrity accepted a negative resource measurement")
	}
}

func TestVerificationIntegritySurvivesJSONRoundTrip(t *testing.T) {
	result := integrityFixture(t)
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal verification result: %v", err)
	}
	var decoded domain.VerificationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal verification result: %v", err)
	}

	checks := []struct {
		name     string
		value    any
		expected string
	}{
		{name: "observations", value: decoded.Observations, expected: decoded.Digests.Observations},
		{name: "assertions", value: decoded.Assertions, expected: decoded.Digests.Assertions},
		{name: "policyDecisions", value: decoded.PolicyDecisions, expected: decoded.Digests.PolicyDecisions},
	}
	for _, check := range checks {
		actual, err := canonicaljson.Digest(check.value)
		if err != nil {
			t.Fatalf("digest %s: %v", check.name, err)
		}
		if actual != check.expected {
			t.Errorf("%s digest after round trip = %q, want %q", check.name, actual, check.expected)
		}
	}
	if err := VerifyIntegrity(decoded); err != nil {
		t.Fatalf("VerifyIntegrity after JSON round trip: %v", err)
	}
}

func resourceEvidenceInput() Input {
	started := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	return Input{
		RunID:          "run_resource_evidence",
		VerificationID: "vrf_resource_evidence",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"network-enforcement"},
			RepeatCount:        1,
			SuccessThreshold:   1,
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
		},
		Runner: domain.RunnerFeatures{
			Backend:                  "test",
			NetworkDeny:              true,
			ResourceUsage:            "high",
			ResourceLimitEnforcement: true,
		},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
		},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "passed"}},
		Requested:  1,
		Completed:  1,
		Matching:   1,
		Cleanup:    domain.CleanupClean,
	}
}

func retainedFilesystemVerdictInput() Input {
	started := time.Date(2026, time.August, 2, 1, 2, 3, 0, time.UTC)
	return Input{
		RunID:          "run_retained_filesystem_verdict",
		VerificationID: "vrf_retained_filesystem_verdict",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"filesystem-write"},
			RepeatCount:        1,
			SuccessThreshold:   1,
			Evidence:           testNoSBOMEvidence(),
		},
		Runner: domain.RunnerFeatures{
			Backend:                    "test",
			FilesystemWriteObservation: "best-effort",
		},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(
				started,
				domain.CleanupAllowedResidue,
			),
		},
		Assertions: []domain.AssertionResult{{
			ID:           "journey",
			Type:         "exit-code",
			Required:     true,
			Expected:     0,
			Actual:       0,
			Status:       "passed",
			EvidenceRefs: []string{},
		}},
		Requested:        1,
		Completed:        1,
		Matching:         1,
		SuccessThreshold: 1,
		Cleanup:          domain.CleanupAllowedResidue,
	}
}

func testNoSBOMEvidence() domain.PlanEvidence {
	return domain.PlanEvidence{
		Profile: "minimal-public",
		Include: []string{"normalized-observations", "verification-summary"},
		Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
	}
}

func portListenerObservationForTest(
	timestamp time.Time,
	comparison string,
	undeclared int,
) domain.ObservationEvent {
	details := map[string]any{
		"observerPlacement":          "peer-container-shared-network-namespace",
		"sharesTargetPIDNamespace":   false,
		"sharesTargetMountNamespace": false,
		"sharesTargetIPCNamespace":   false,
		"sharesTargetCgroup":         false,
		"processAttribution":         "unavailable",
		"lifetimeSemantics":          "sample-window-only",
		"kernelEventCoverage":        "unavailable",
		"shortLivedListenerGap":      true,
		"udpUnavailable":             true,
		"publicEvidence":             "aggregate-only",
		"evidenceBasis":              "aggregate-only",
		"comparisonResult":           comparison,
		"sampleLimit":                1200,
		"intervalMillis":             100,
		"maxAllowedGapMillis":        1000,
		"identityVerified":           true,
		"namespaceIsolationVerified": true,
		"workloadQuiescenceVerified": true,
		"peerRemoveVerified":         true,
		"canonicalDigestSemantics":   "helper-commitment-not-controller-recomputed",
		"observerAdapter":            "node-proc-net-tcp-linux",
		"declaredEndpointCount":      1,
		"baselineEndpointCount":      0,
		"sampledEndpointCount":       1 + undeclared,
		"undeclaredEndpointCount":    undeclared,
		"sampleCount":                3,
		"maxSampleGapMillis":         100,
		"transitionCount":            2,
		"canonicalSampleDigest": "sha256:" +
			strings.Repeat("d", 64),
	}
	return domain.ObservationEvent{
		SchemaVersion: "1", Timestamp: timestamp, Phase: domain.PhaseCleanup,
		Actor: "trusted-runner", Operation: "port.listener-trace.summary",
		Resource: "tcp-listeners", Result: "observed",
		Observer: "docker-peer-port-listener-trace",
		Coverage: "best-effort", Confidence: "high", Details: details,
	}
}

func portListenerNotTestedObservationForTest(
	timestamp time.Time,
	failure string,
) domain.ObservationEvent {
	observation := portListenerObservationForTest(
		timestamp, "no-undeclared-observed", 0,
	)
	for _, key := range []string{
		"observerAdapter", "declaredEndpointCount", "baselineEndpointCount",
		"sampledEndpointCount", "undeclaredEndpointCount", "sampleCount",
		"maxSampleGapMillis", "transitionCount", "canonicalSampleDigest",
	} {
		delete(observation.Details, key)
	}
	observation.Details["comparisonResult"] = "not-tested"
	if failure != "" {
		observation.Details["failure"] = failure
	}
	observation.Result = "unavailable"
	observation.Coverage = "unavailable"
	observation.Confidence = "unknown"
	return observation
}

func integrityFixture(t *testing.T) domain.VerificationResult {
	t.Helper()
	started := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	result, err := Build(Input{
		RunID:          "run_integrity",
		VerificationID: "vrf_integrity",
		Plan: domain.ResolvedPlan{
			SchemaVersion:      "4",
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"network-enforcement"},
			RepeatCount:        1,
			SuccessThreshold:   1,
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
		},
		Runner:      domain.RunnerFeatures{Backend: "test", NetworkDeny: true},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservationForTest(started, domain.CleanupClean),
		},
		Assertions:       []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "passed", Required: true, Expected: 0, Actual: 0, EvidenceRefs: []string{}}},
		Requested:        1,
		Completed:        1,
		Matching:         1,
		SuccessThreshold: 1,
		Cleanup:          domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return result
}

func cleanupObservationForTest(
	timestamp time.Time,
	verdict domain.CleanupVerdict,
) domain.ObservationEvent {
	entryCount := 0
	regularFileCount := 0
	symlinkCount := 0
	unmatchedCount := 0
	if verdict == domain.CleanupAllowedResidue {
		entryCount = 1
		regularFileCount = 1
	}
	if verdict == domain.CleanupUndeclaredResidue {
		entryCount = 1
		symlinkCount = 1
		unmatchedCount = 1
	}
	result := "succeeded"
	coverage := "enforcement-only"
	confidence := "high"
	failure := ""
	if verdict == domain.CleanupNotTested {
		result = "failed"
		coverage = "unavailable"
		confidence = "unknown"
		failure = "sandbox-boundary-unavailable"
	}
	details := map[string]any{
		"allowedPatternCount":       1,
		"allowedProfile":            "outputs-descendants",
		"boundary":                  cleanupObservationBoundary,
		"classifierVersion":         cleanupObservationClassifier,
		"directoryCount":            0,
		"disposableCleanupVerified": verdict != domain.CleanupNotTested,
		"entryCount":                entryCount,
		"identityVerified":          verdict != domain.CleanupNotTested,
		"inventoryComplete":         verdict != domain.CleanupNotTested,
		"maxControlBytes":           512 << 10,
		"maxDepth":                  64,
		"maxEntries":                2048,
		"maxPathBytes":              1024,
		"quiescenceConfirmed":       verdict != domain.CleanupNotTested,
		"regularFileCount":          regularFileCount,
		"scope":                     cleanupObservationResource,
		"specialCount":              0,
		"symlinkCount":              symlinkCount,
		"unmatchedCount":            unmatchedCount,
		"verdict":                   string(verdict),
	}
	if verdict == domain.CleanupNotTested {
		details["failure"] = failure
	} else {
		details["opaqueInventoryToken"] = "hmac-sha256:" +
			"abababababababababababababababababababababababababababababababab"
		details["tokenScheme"] = "ephemeral-keyed-hmac-sha256"
	}
	return domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp,
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     cleanupObservationOperation,
		Resource:      cleanupObservationResource,
		Result:        result,
		Observer:      cleanupObservationObserver,
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       details,
	}
}

func policyDecision(values []domain.PolicyDecision, id string) string {
	for _, value := range values {
		if value.PolicyID == id {
			return value.Decision
		}
	}
	return ""
}
