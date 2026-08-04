package rendering

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func alpha25PortSummaryDetails(comparison string) map[string]any {
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
	}
	if comparison != "not-tested" {
		details["observerAdapter"] = "node-proc-net-tcp-linux"
		details["sampleCount"] = 3
		details["maxSampleGapMillis"] = 100
		details["transitionCount"] = 2
		details["canonicalSampleDigest"] = "sha256:" + strings.Repeat("d", 64)
	}
	return details
}

func TestHTMLEscapesUntrustedContentAndSetsCSP(t *testing.T) {
	scriptPayload := `<script>alert("x")</script>`
	imagePayload := `<img src=x onerror=alert(1)>`
	result := domain.VerificationResult{
		VerificationID: scriptPayload,
		Subject:        domain.PlanSource{TreeDigest: imagePayload},
		Plan: domain.VerificationPlanRef{
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
		},
		Runner: domain.RunnerFeatures{Backend: imagePayload},
		Results: domain.Verdicts{
			Functional:      domain.FunctionalPass,
			Capability:      domain.CapabilityConforming,
			Reproducibility: domain.ReproducibilityNotTested,
			Cleanup:         domain.CleanupClean,
			Evidence:        domain.EvidenceUnsigned,
			Freshness:       domain.FreshnessCurrent,
			Overall:         domain.OverallVerifiedWithWarnings,
		},
		Assertions: []domain.AssertionResult{
			{ID: "assertion", Type: "text", Status: "pass", Message: scriptPayload},
		},
		Errors: []*domain.Error{
			{
				Code: domain.ErrorCode(imagePayload), Severity: domain.SeverityHigh,
				Message: scriptPayload,
			},
		},
	}

	data, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	page := string(data)
	if strings.Contains(page, scriptPayload) || strings.Contains(page, imagePayload) {
		t.Fatalf("HTML contains raw untrusted payload:\n%s", page)
	}
	if !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "&lt;img") {
		t.Fatalf("HTML does not contain escaped payloads:\n%s", page)
	}
	const csp = `Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"`
	if !strings.Contains(page, csp) {
		t.Fatalf("HTML is missing the restrictive CSP: %s", page)
	}
	if strings.Contains(strings.ToLower(page), "<script") {
		t.Fatalf("HTML unexpectedly contains a script element: %s", page)
	}
}

func TestRenderersHandleNullFindingDefensively(t *testing.T) {
	result := domain.VerificationResult{
		VerificationID: "vrf_null_finding",
		Errors: []*domain.Error{
			nil,
			domain.NewError(
				domain.CodeCleanupFailed,
				domain.SeverityHigh,
				"bounded finding",
			),
		},
	}
	if text := Text(result); !strings.Contains(text, "bounded finding") {
		t.Fatalf("text report lost the non-null finding: %s", text)
	}
	page, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML with null finding: %v", err)
	}
	if !strings.Contains(string(page), "bounded finding") {
		t.Fatalf("HTML report lost the non-null finding: %s", page)
	}

	_, err = DecodeVerification([]byte(`{"errors":[null]}`))
	if err == nil ||
		domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("DecodeVerification null finding error = %v", err)
	}
}

func TestReportsRenderResourceUsageEvidenceWithoutOverclaiming(t *testing.T) {
	result := domain.VerificationResult{
		VerificationID: "vrf_resources",
		Runner: domain.RunnerFeatures{
			Backend:                  "docker",
			ResourceUsage:            "high",
			ResourceLimitEnforcement: true,
		},
		Resources: domain.ResourceSummary{
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
		},
	}

	text := Text(result)
	for _, wanted := range []string{
		"Resource usage:",
		"Observation coverage:          HIGH",
		"Limit enforcement:             ACTIVE",
		"Sandbox peak memory:           4096 bytes",
		"Maximum tasks (TIDs):          3",
		"Writable bytes (snapshot):     2048 bytes",
		"Verified output bytes:         1024 bytes",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("text report omitted %q:\n%s", wanted, text)
		}
	}

	pageBytes, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	page := string(pageBytes)
	for _, wanted := range []string{
		"<h2>Resource usage</h2>",
		"<td>HIGH</td>",
		"<th>Limit enforcement</th><td>ACTIVE</td>",
		"<th>Maximum tasks (TIDs)</th><td>3</td>",
		"<th>Writable bytes (snapshot)</th><td>2048 bytes</td>",
		"<th>Verified output bytes</th><td>1024 bytes</td>",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("HTML report omitted %q:\n%s", wanted, page)
		}
	}

	result.Runner.ResourceUsage = "unexpected"
	result.Runner.ResourceLimitEnforcement = false
	result.Resources.WritableBytes = 0
	result.Resources.ObservedFields = nil
	text = Text(result)
	if !strings.Contains(text, "Observation coverage:          UNAVAILABLE") ||
		!strings.Contains(text, "Limit enforcement:             not reported") ||
		!strings.Contains(text, "Writable bytes (snapshot):     not reported") {
		t.Fatalf("text report overstated unavailable measurements:\n%s", text)
	}
}

func TestReportsSeparateCompositeFilesystemFromRetainedState(t *testing.T) {
	result := domain.VerificationResult{
		VerificationID: "vrf_filesystem",
		Runner: domain.RunnerFeatures{
			FilesystemWriteObservation: "best-effort",
		},
		Repeats: domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
		Observations: []domain.ObservationEvent{
			{
				Operation: "filesystem.retained-state.change",
				Details:   map[string]any{"changeCount": 99},
			},
			{
				Operation: "filesystem.retained-state.summary",
				Coverage:  "high",
				Details: map[string]any{
					"changeCount": json.Number("12"),
				},
			},
			{
				Operation: "filesystem.engine-diff.summary",
				Result:    "observed",
				Observer:  "docker-container-diff",
				Coverage:  "best-effort",
				Details: map[string]any{
					"finalByteCount": json.Number("7"),
					"finalNonEmpty":  true,
				},
			},
			{
				SchemaVersion: "1",
				Phase:         domain.PhaseCleanup,
				Actor:         "trusted-runner",
				Operation:     "filesystem.activity-trace.summary",
				Resource:      "/outputs",
				Result:        "observed",
				Observer:      "docker-outputs-activity-trace",
				Coverage:      "best-effort",
				Confidence:    "high",
				Details: map[string]any{
					"scope": "outputs-activity-notification-trace",
					"traceBoundary": "post-preflight-pre-workload-to-" +
						"post-quiesce-pre-retained-final",
					"notificationSemantics": "runtime-filesystem-" +
						"notification-hints",
					"activityTraceCoverage":       "best-effort",
					"operationHistoryCoverage":    "unavailable",
					"actorAttribution":            "unavailable",
					"phaseAttribution":            "controller-window-hint",
					"operationClassification":     "hint-only",
					"rawPathIncluded":             false,
					"contentIncluded":             false,
					"publicEvidence":              "aggregate-only",
					"observerPlacement":           "in-sandbox-trusted-helper",
					"sharesSandboxResourceBudget": true,
					"startIdentityVerified":       true,
					"readyIdentityVerified":       true,
					"stopIdentityVerified":        true,
					"finalIdentityVerified":       true,
					"workloadQuiescenceVerified":  true,
					"transport":                   "controller-stdin-stdout-jsonl",
					"transportBoundBytes":         16 << 10,
					"notificationLimit":           4096,
					"watchLimit":                  2048,
					"observerAdapter":             "node-fs-watch-linux",
					"kernelOverflowDetection":     "unavailable",
					"blindSpots": []string{
						"outside-outputs",
						"exact-process-and-actor",
						"syscall-and-operation-history",
						"kernel-or-runtime-notification-coalescing",
						"node-kernel-queue-overflow-unobservable",
						"new-directory-watch-install-race",
						"watched-directory-delete-recreate",
						"phase-boundary-race",
						"rename-pairing",
						"read-activity",
					},
					"notificationCount": json.Number("3"),
					"renameHintCount":   2,
					"changeHintCount":   1,
					"phaseCounts": []string{
						"setup=0",
						"build=0",
						"run=0",
						"exercise=3",
						"cleanup=0",
						"unknown=0",
					},
					"canonicalTranscriptDigest": "sha256:" +
						strings.Repeat("c", 64),
					"canonicalByteCount": 192,
				},
			},
		},
	}

	text := Text(result)
	for _, wanted := range []string{
		"Filesystem observation:",
		"Composite write observation (required): BEST-EFFORT",
		"Retained state observation (optional):  HIGH",
		"Retained-state change count:            12",
		"Docker engine diff (optional):          BEST-EFFORT",
		"Opaque final transcript bytes:          7 total across 1 summary (1 non-empty)",
		"/outputs activity trace (optional):     BEST-EFFORT",
		"Activity notification hints:            3 total across 1 summary",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("text report omitted %q:\n%s", wanted, text)
		}
	}

	pageBytes, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	page := string(pageBytes)
	for _, wanted := range []string{
		"<h2>Filesystem observation</h2>",
		"<th>Composite write observation (required)</th><td>BEST-EFFORT</td>",
		"<th>Retained state observation (optional)</th><td>HIGH</td>",
		"<th>Retained-state change count</th><td>12</td>",
		"<th>Docker engine diff (optional)</th><td>BEST-EFFORT</td>",
		"<th>Opaque final transcript bytes</th><td>7 total across 1 summary (1 non-empty)</td>",
		"<th>/outputs activity trace (optional)</th><td>BEST-EFFORT</td>",
		"<th>Activity notification hints</th><td>3 total across 1 summary</td>",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("HTML report omitted %q:\n%s", wanted, page)
		}
	}
}

func TestReportsRetainedFilesystemComparisonWithoutPaths(t *testing.T) {
	const rawMarker = "RAW-ALPHA23-UNDECLARED-PATH-MARKER"
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
	result := domain.VerificationResult{
		VerificationID: "vrf_retained_comparison",
		Subject: domain.PlanSource{
			TreeDigest: "sha256:" + strings.Repeat("a", 64),
		},
		Plan: domain.VerificationPlanRef{
			PlanDigest:         "sha256:" + strings.Repeat("b", 64),
			PolicyBundleDigest: "sha256:" + strings.Repeat("c", 64),
		},
		Runner: domain.RunnerFeatures{
			Backend:                    "docker",
			FilesystemWriteObservation: "best-effort",
		},
		Results: domain.Verdicts{
			Functional:      domain.FunctionalPass,
			Capability:      domain.CapabilityNonconforming,
			Reproducibility: domain.ReproducibilityStable,
			Cleanup:         domain.CleanupAllowedResidue,
			Evidence:        domain.EvidenceUnsigned,
			Freshness:       domain.FreshnessCurrent,
			Overall:         domain.OverallNonconforming,
		},
		Repeats: domain.RepeatSummary{
			Requested: 1,
			Completed: 1,
			Matching:  1,
		},
		Observations: []domain.ObservationEvent{{
			SchemaVersion: "1",
			Sequence:      1,
			Operation:     "filesystem.retained-state.summary",
			Coverage:      "high",
			Details: map[string]any{
				"changeCount":                  2,
				"declarationComparisonScope":   "executed-phase-filesystem-write-union",
				"declarationComparisonVersion": "0.1.0",
				"declarationComparisonResult":  "nonconforming-retained-state",
				"declaredPatternCount":         1,
				"comparedChangeCount":          2,
				"allowedChangeCount":           1,
				"undeclaredChangeCount":        1,
			},
		}},
		Errors: []*domain.Error{finding},
	}

	jsonBytes, err := JSON(result)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	jsonReport := string(jsonBytes)
	for _, wanted := range []string{
		`"declarationComparisonResult": "nonconforming-retained-state"`,
		`"declaredPatternCount": 1`,
		`"comparedChangeCount": 2`,
		`"allowedChangeCount": 1`,
		`"undeclaredChangeCount": 1`,
		`"code": "UNDECLARED_FILESYSTEM_WRITE"`,
	} {
		if !strings.Contains(jsonReport, wanted) {
			t.Errorf("JSON report omitted %q:\n%s", wanted, jsonReport)
		}
	}

	textReport := Text(result)
	for _, wanted := range []string{
		"Capability:      NONCONFORMING",
		"Overall:         NONCONFORMING",
		"Retained declaration comparison:       NONCONFORMING",
		"Retained declaration counts:           declared-pattern total 1; compared 2; allowed 1; undeclared 1",
		"UNDECLARED_FILESYSTEM_WRITE",
	} {
		if !strings.Contains(textReport, wanted) {
			t.Errorf("text report omitted %q:\n%s", wanted, textReport)
		}
	}

	htmlBytes, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	htmlReport := string(htmlBytes)
	for _, wanted := range []string{
		`<div>Capability</div><div class="status">NONCONFORMING</div>`,
		`<div>Overall</div><div class="status">NONCONFORMING</div>`,
		`<th>Retained declaration comparison</th><td>NONCONFORMING</td>`,
		`<th>Retained declaration counts</th><td>declared-pattern total 1; compared 2; allowed 1; undeclared 1</td>`,
		"UNDECLARED_FILESYSTEM_WRITE",
	} {
		if !strings.Contains(htmlReport, wanted) {
			t.Errorf("HTML report omitted %q:\n%s", wanted, htmlReport)
		}
	}

	for index, report := range []string{jsonReport, textReport, htmlReport} {
		upper := strings.ToUpper(report)
		if strings.Contains(report, rawMarker) ||
			strings.Contains(report, "RAW-ALPHA23") ||
			strings.Contains(report, "UNDECLARED-PATH-MARKER") ||
			strings.Contains(upper, `"OVERALL": "VERIFIED`) ||
			strings.Contains(upper, "OVERALL:         VERIFIED") ||
			strings.Contains(upper, `>VERIFIED</DIV>`) {
			t.Fatalf("report %d leaked a raw path or verified verdict", index)
		}
	}
}

func TestPortListenerSummaryViewIsAggregateOnlyAndConservative(t *testing.T) {
	summary := func(comparison string) domain.ObservationEvent {
		details := alpha25PortSummaryDetails(comparison)
		if comparison == "not-tested" {
			return domain.ObservationEvent{
				SchemaVersion: "1", Phase: domain.PhaseCleanup,
				Actor: "trusted-runner", Operation: "port.listener-trace.summary",
				Resource: "tcp-listeners", Result: "unavailable",
				Observer: "docker-peer-port-listener-trace",
				Coverage: "unavailable", Confidence: "unknown", Details: details,
			}
		}
		undeclared := 0
		if comparison == "nonconforming-listeners" {
			undeclared = 1
		}
		details["baselineEndpointCount"] = 0
		details["declaredEndpointCount"] = 1
		details["sampledEndpointCount"] = 1 + undeclared
		details["undeclaredEndpointCount"] = undeclared
		return domain.ObservationEvent{
			SchemaVersion: "1", Phase: domain.PhaseCleanup,
			Actor: "trusted-runner", Operation: "port.listener-trace.summary",
			Resource: "tcp-listeners", Result: "observed",
			Observer: "docker-peer-port-listener-trace",
			Coverage: "best-effort", Confidence: "high", Details: details,
		}
	}
	conforming := summary("no-undeclared-observed")
	nonconforming := summary("nonconforming-listeners")
	notTested := summary("not-tested")

	for _, test := range []struct {
		name         string
		observations []domain.ObservationEvent
		comparison   string
		coverage     string
		counts       string
	}{
		{
			name:         "clean observed listener set",
			observations: []domain.ObservationEvent{conforming},
			comparison:   "NO-UNDECLARED-OBSERVED", coverage: "BEST-EFFORT",
			counts: "baseline total 0; declared total 1; sampled total 1; undeclared total 0 across 1 summary",
		},
		{
			name:         "undeclared listener is nonconforming",
			observations: []domain.ObservationEvent{nonconforming},
			comparison:   "NONCONFORMING", coverage: "BEST-EFFORT",
			counts: "baseline total 0; declared total 1; sampled total 2; undeclared total 1 across 1 summary",
		},
		{
			name:         "not tested suppresses counts",
			observations: []domain.ObservationEvent{notTested},
			comparison:   "NOT-TESTED", coverage: "UNAVAILABLE", counts: "not reported",
		},
		{
			name:         "positive outranks not tested but counts stay suppressed",
			observations: []domain.ObservationEvent{nonconforming, notTested},
			comparison:   "NONCONFORMING", coverage: "UNAVAILABLE", counts: "not reported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := portListenerSummaryView(domain.VerificationResult{
				Repeats: domain.RepeatSummary{
					Requested: len(test.observations), Completed: len(test.observations),
					Matching: len(test.observations),
				},
				Observations: test.observations,
			})
			if view.Comparison != test.comparison || view.Coverage != test.coverage ||
				view.Counts != test.counts {
				t.Fatalf("port listener view = %#v", view)
			}
		})
	}

	unsafe := summary("nonconforming-listeners")
	unsafe.Details["endpoint"] = "127.0.0.1:43123/tcp"
	unsafeView := portListenerSummaryView(domain.VerificationResult{
		Repeats:      domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
		Observations: []domain.ObservationEvent{unsafe},
	})
	if unsafeView.Coverage != "UNAVAILABLE" ||
		unsafeView.Comparison != "NOT REPORTED" ||
		unsafeView.Counts != "not reported" {
		t.Fatalf("unsafe port listener detail was rendered: %#v", unsafeView)
	}
}

func TestReportsPortListenerComparisonWithoutEndpoints(t *testing.T) {
	const rawMarker = "127.0.0.1:43123/tcp"
	finding := domain.NewError(
		domain.CodeUndeclaredPortListen,
		domain.SeverityHigh,
		"Bounded peer TCP samples observed one or more listeners outside the declared service endpoint.",
	)
	finding.Details = map[string]any{
		"observer":                "docker-peer-port-listener-trace",
		"evidenceBasis":           "aggregate-only",
		"undeclaredEndpointCount": 1,
	}
	result := domain.VerificationResult{
		VerificationID: "vrf_port_comparison",
		Subject:        domain.PlanSource{TreeDigest: "sha256:" + strings.Repeat("a", 64)},
		Plan: domain.VerificationPlanRef{
			PlanDigest:         "sha256:" + strings.Repeat("b", 64),
			PolicyBundleDigest: "sha256:" + strings.Repeat("c", 64),
		},
		Results: domain.Verdicts{
			Functional: domain.FunctionalPass, Capability: domain.CapabilityNonconforming,
			Reproducibility: domain.ReproducibilityStable, Cleanup: domain.CleanupClean,
			Evidence: domain.EvidenceUnsigned, Freshness: domain.FreshnessCurrent,
			Overall: domain.OverallNonconforming,
		},
		Repeats: domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
		Observations: []domain.ObservationEvent{{
			SchemaVersion: "1", Sequence: 1, Phase: domain.PhaseCleanup,
			Actor: "trusted-runner", Operation: "port.listener-trace.summary",
			Resource: "tcp-listeners", Result: "observed",
			Observer: "docker-peer-port-listener-trace",
			Coverage: "best-effort", Confidence: "high",
			Details: func() map[string]any {
				details := alpha25PortSummaryDetails("nonconforming-listeners")
				details["baselineEndpointCount"] = 0
				details["declaredEndpointCount"] = 1
				details["sampledEndpointCount"] = 2
				details["undeclaredEndpointCount"] = 1
				return details
			}(),
		}},
		Errors: []*domain.Error{finding},
	}

	jsonBytes, err := JSON(result)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	jsonReport := string(jsonBytes)
	for _, wanted := range []string{
		`"comparisonResult": "nonconforming-listeners"`,
		`"baselineEndpointCount": 0`, `"declaredEndpointCount": 1`,
		`"sampledEndpointCount": 2`, `"undeclaredEndpointCount": 1`,
		`"code": "UNDECLARED_PORT_LISTEN"`,
	} {
		if !strings.Contains(jsonReport, wanted) {
			t.Errorf("JSON report omitted %q:\n%s", wanted, jsonReport)
		}
	}
	roundTripped, err := DecodeVerification(jsonBytes)
	if err != nil {
		t.Fatalf("DecodeVerification: %v", err)
	}
	if view := portListenerSummaryView(roundTripped); view.Comparison != "NONCONFORMING" ||
		view.Coverage != "BEST-EFFORT" ||
		view.Counts != "baseline total 0; declared total 1; sampled total 2; undeclared total 1 across 1 summary" {
		t.Fatalf("round-tripped port listener view = %#v", view)
	}
	textReport := Text(result)
	htmlBytes, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	htmlReport := string(htmlBytes)
	for _, wanted := range []string{
		"Capability:      NONCONFORMING", "Overall:         NONCONFORMING",
		"Peer listener result:                   NONCONFORMING",
		"Peer listener counts:                   baseline total 0; declared total 1; sampled total 2; undeclared total 1 across 1 summary",
		"UNDECLARED_PORT_LISTEN",
	} {
		if !strings.Contains(textReport, wanted) {
			t.Errorf("text report omitted %q:\n%s", wanted, textReport)
		}
	}
	for _, wanted := range []string{
		`<th>Peer listener result</th><td>NONCONFORMING</td>`,
		`<th>Peer listener counts</th><td>baseline total 0; declared total 1; sampled total 2; undeclared total 1 across 1 summary</td>`,
		"UNDECLARED_PORT_LISTEN",
	} {
		if !strings.Contains(htmlReport, wanted) {
			t.Errorf("HTML report omitted %q:\n%s", wanted, htmlReport)
		}
	}
	for index, report := range []string{jsonReport, textReport, htmlReport} {
		upper := strings.ToUpper(report)
		if strings.Contains(report, rawMarker) ||
			strings.Contains(upper, `"OVERALL": "VERIFIED`) ||
			strings.Contains(upper, "OVERALL:         VERIFIED") ||
			strings.Contains(upper, `>VERIFIED</DIV>`) {
			t.Fatalf("report %d leaked a raw endpoint or verified verdict", index)
		}
	}
}

func TestRetainedDeclarationComparisonViewUsesConservativeMixedRepeatPrecedence(
	t *testing.T,
) {
	summary := func(
		result string,
		declared any,
		compared any,
		allowed any,
		undeclared any,
	) domain.ObservationEvent {
		details := map[string]any{
			"changeCount":                  1,
			"declarationComparisonScope":   "executed-phase-filesystem-write-union",
			"declarationComparisonVersion": "0.1.0",
			"declarationComparisonResult":  result,
		}
		if result != "not-tested" {
			details["declaredPatternCount"] = declared
			details["comparedChangeCount"] = compared
			details["allowedChangeCount"] = allowed
			details["undeclaredChangeCount"] = undeclared
		} else {
			details["declarationComparisonFailure"] =
				"retained-state-prerequisite-unavailable"
		}
		return domain.ObservationEvent{
			Operation: "filesystem.retained-state.summary",
			Result:    "observed",
			Coverage:  "high",
			Details:   details,
		}
	}
	conforming := summary(
		"conforming-retained-state",
		1,
		1,
		1,
		0,
	)
	nonconforming := summary(
		"nonconforming-retained-state",
		1,
		1,
		0,
		1,
	)
	notTested := summary("not-tested", nil, nil, nil, nil)

	for _, test := range []struct {
		name         string
		observations []domain.ObservationEvent
		wantResult   string
		wantCounts   string
	}{
		{
			name:         "conforming and nonconforming",
			observations: []domain.ObservationEvent{conforming, nonconforming},
			wantResult:   "NONCONFORMING",
			wantCounts:   "declared-pattern total 2; compared 2; allowed 1; undeclared 1 across 2 summaries",
		},
		{
			name:         "conforming and not-tested",
			observations: []domain.ObservationEvent{conforming, notTested},
			wantResult:   "NOT-TESTED",
			wantCounts:   "not reported",
		},
		{
			name:         "nonconforming and not-tested",
			observations: []domain.ObservationEvent{nonconforming, notTested},
			wantResult:   "NONCONFORMING",
			wantCounts:   "not reported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := filesystemSummaryView(domain.VerificationResult{
				Repeats: domain.RepeatSummary{
					Requested: 2,
					Completed: 2,
					Matching:  2,
				},
				Observations: test.observations,
			})
			if view.DeclarationComparison != test.wantResult ||
				view.DeclarationCounts != test.wantCounts {
				t.Fatalf(
					"mixed retained declaration view = %#v",
					view,
				)
			}
		})
	}
}

func TestOperationNotificationSummaryViewIsAggregateOnlyAndConservative(
	t *testing.T,
) {
	summary := func(comparison string) domain.ObservationEvent {
		details := map[string]any{
			"scope":                          "outputs-operation-notification-comparison",
			"publicEvidence":                 "aggregate-only",
			"rawPathIncluded":                false,
			"ruleTextIncluded":               false,
			"contentIncluded":                false,
			"actorAttribution":               "unavailable",
			"renamePairing":                  "unavailable",
			"preDispatchQuiescenceVerified":  true,
			"postDispatchQuiescenceVerified": true,
			"phaseAcknowledgementsComplete":  true,
			"notificationLimit":              4096,
			"ruleLimitPerWindow":             256,
			"windowLimit":                    128,
			"evidenceBasis":                  "aggregate-only",
			"comparisonResult":               comparison,
			"blindSpots": []string{
				"outside-outputs", "read-and-syscall-history",
				"actor-and-process-attribution", "rename-pairing",
				"inotify-coalescing", "new-directory-watch-race",
			},
		}
		if comparison == "not-tested" {
			details["failure"] = "unsupported-runtime-adapter"
			return domain.ObservationEvent{
				SchemaVersion: "1", Phase: domain.PhaseCleanup,
				Actor:     "trusted-runner",
				Operation: "filesystem.operation-notification.summary",
				Resource:  "/outputs", Result: "unavailable",
				Observer: "docker-python-outputs-inotify-comparison",
				Coverage: "unavailable", Confidence: "unknown", Details: details,
			}
		}
		undeclared := 0
		if comparison == "nonconforming-notifications" {
			undeclared = 1
		}
		details["windowCount"] = 1
		details["quiescenceWindowCount"] = 1
		details["declaredPatternCount"] = 1
		details["comparedNotificationCount"] = 2
		details["allowedNotificationCount"] = 2 - undeclared
		details["undeclaredNotificationCount"] = undeclared
		details["mutationCounts"] = []string{
			"create=1", "delete=0", "write=1", "rename=0", "metadata=0",
		}
		return domain.ObservationEvent{
			SchemaVersion: "1", Phase: domain.PhaseCleanup,
			Actor:     "trusted-runner",
			Operation: "filesystem.operation-notification.summary",
			Resource:  "/outputs", Result: "observed",
			Observer: "docker-python-outputs-inotify-comparison",
			Coverage: "best-effort", Confidence: "high", Details: details,
		}
	}
	nonconforming := summary("nonconforming-notifications")
	clear := summary("no-undeclared-observed")
	notTested := summary("not-tested")

	for _, test := range []struct {
		name         string
		observations []domain.ObservationEvent
		coverage     string
		comparison   string
		counts       string
	}{
		{
			name:         "positive notification",
			observations: []domain.ObservationEvent{nonconforming},
			coverage:     "BEST-EFFORT",
			comparison:   "NONCONFORMING",
			counts:       "windows 1; declared-pattern total 1; compared 2; allowed 1; undeclared 1; create 1; delete 0; write 1; rename 0; metadata 0 across 1 summary",
		},
		{
			name:         "clear notification is not conforming",
			observations: []domain.ObservationEvent{clear},
			coverage:     "BEST-EFFORT",
			comparison:   "NO-UNDECLARED-OBSERVED",
			counts:       "windows 1; declared-pattern total 1; compared 2; allowed 2; undeclared 0; create 1; delete 0; write 1; rename 0; metadata 0 across 1 summary",
		},
		{
			name:         "not tested",
			observations: []domain.ObservationEvent{notTested},
			coverage:     "UNAVAILABLE",
			comparison:   "NOT-TESTED",
			counts:       "not reported",
		},
		{
			name:         "nonconforming outranks not tested",
			observations: []domain.ObservationEvent{nonconforming, notTested},
			coverage:     "UNAVAILABLE",
			comparison:   "NONCONFORMING",
			counts:       "not reported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := filesystemSummaryView(domain.VerificationResult{
				Repeats: domain.RepeatSummary{
					Requested: len(test.observations),
					Completed: len(test.observations),
					Matching:  len(test.observations),
				},
				Observations: test.observations,
			})
			if view.OperationNotificationCoverage != test.coverage ||
				view.OperationNotificationComparison != test.comparison ||
				view.OperationNotificationCounts != test.counts {
				t.Fatalf("operation notification view = %#v", view)
			}
		})
	}
	decoded := clear
	decoded.Details = make(map[string]any, len(clear.Details))
	for key, value := range clear.Details {
		decoded.Details[key] = value
	}
	decoded.Details["notificationLimit"] = json.Number("4096")
	decoded.Details["ruleLimitPerWindow"] = float64(256)
	if view := filesystemSummaryView(domain.VerificationResult{
		Repeats:      domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
		Observations: []domain.ObservationEvent{decoded},
	}); view.OperationNotificationComparison != "NO-UNDECLARED-OBSERVED" {
		t.Fatalf("decoded aggregate counts were rejected: %#v", view)
	}

	result := domain.VerificationResult{
		VerificationID: "vrf_operation_notification",
		Repeats:        domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
		Observations:   []domain.ObservationEvent{nonconforming},
	}
	text := Text(result)
	if !strings.Contains(text, "Operation notification result:          NONCONFORMING") ||
		!strings.Contains(text, "Operation notification counts:          windows 1;") {
		t.Fatalf("text report omitted operation notification view:\n%s", text)
	}
	page, err := HTML(result)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(string(page), "<th>Operation notification result</th><td>NONCONFORMING</td>") {
		t.Fatalf("HTML report omitted operation notification view:\n%s", page)
	}

	const rawMarker = "/outputs/RAW-ALPHA24-OPERATION-PATH-MARKER"
	for _, injection := range []struct {
		name  string
		key   string
		value string
	}{
		{"raw path", "rawPath", rawMarker},
		{"rule text", "ruleText", "/outputs/RAW-ALPHA24-RULE-MARKER/**"},
		{"token", "sessionToken", "RAW-ALPHA24-TOKEN-MARKER"},
	} {
		t.Run("privacy rejects "+injection.name, func(t *testing.T) {
			unsafe := nonconforming
			unsafe.Details = make(map[string]any, len(nonconforming.Details)+1)
			for key, value := range nonconforming.Details {
				unsafe.Details[key] = value
			}
			unsafe.Details[injection.key] = injection.value
			view := filesystemSummaryView(domain.VerificationResult{
				Repeats:      domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
				Observations: []domain.ObservationEvent{unsafe},
			})
			if view.OperationNotificationComparison != "NOT REPORTED" ||
				view.OperationNotificationCounts != "not reported" {
				t.Fatalf("unsafe operation detail was rendered: %#v", view)
			}
			unsafeResult := domain.VerificationResult{
				Repeats:      domain.RepeatSummary{Requested: 1, Completed: 1, Matching: 1},
				Observations: []domain.ObservationEvent{unsafe},
			}
			html, err := HTML(unsafeResult)
			if err != nil {
				t.Fatalf("HTML: %v", err)
			}
			for _, report := range []string{Text(unsafeResult), string(html)} {
				if strings.Contains(report, injection.value) ||
					strings.Contains(report, "RAW-ALPHA24") {
					t.Fatalf("report leaked %s: %s", injection.name, report)
				}
			}
		})
	}
}

func TestFilesystemSummaryViewRequiresOneBoundedNumericSummary(
	t *testing.T,
) {
	summary := func(value any) domain.ObservationEvent {
		details := map[string]any{}
		if value != nil {
			details["changeCount"] = value
		}
		return domain.ObservationEvent{
			Operation: "filesystem.retained-state.summary",
			Coverage:  "high",
			Details:   details,
		}
	}
	tests := []struct {
		name         string
		observations []domain.ObservationEvent
		completed    int
		want         string
	}{
		{
			name:      "missing summary",
			completed: 1,
			want:      "not reported",
		},
		{
			name:         "missing count",
			observations: []domain.ObservationEvent{summary(nil)},
			want:         "not reported",
		},
		{
			name:         "non numeric",
			observations: []domain.ObservationEvent{summary("3")},
			want:         "not reported",
		},
		{
			name:         "fractional",
			observations: []domain.ObservationEvent{summary(1.5)},
			want:         "not reported",
		},
		{
			name:         "negative",
			observations: []domain.ObservationEvent{summary(-1)},
			want:         "not reported",
		},
		{
			name: "over bound",
			observations: []domain.ObservationEvent{
				summary(filesystemRetainedStateChangeLimit + 1),
			},
			want: "not reported",
		},
		{
			name: "duplicate summaries",
			observations: []domain.ObservationEvent{
				summary(1),
				summary(1),
			},
			completed: 1,
			want:      "not reported",
		},
		{
			name:         "zero",
			observations: []domain.ObservationEvent{summary(0)},
			want:         "0",
		},
		{
			name: "inclusive bound",
			observations: []domain.ObservationEvent{
				summary(json.Number("256")),
			},
			want: "256",
		},
		{
			name:         "decoded integer",
			observations: []domain.ObservationEvent{summary(float64(7))},
			want:         "7",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completed := test.completed
			if completed == 0 {
				completed = len(test.observations)
			}
			view := filesystemSummaryView(domain.VerificationResult{
				Observations: test.observations,
				Repeats: domain.RepeatSummary{
					Requested: completed,
					Completed: completed,
					Matching:  completed,
				},
			})
			if view.ChangeCount != test.want {
				t.Fatalf(
					"change count = %q, want %q",
					view.ChangeCount,
					test.want,
				)
			}
		})
	}
}

func TestFilesystemSummaryViewUsesLowestCoverageAcrossRepeats(
	t *testing.T,
) {
	result := domain.VerificationResult{
		Runner: domain.RunnerFeatures{
			FilesystemWriteObservation: "best-effort",
		},
		Repeats: domain.RepeatSummary{
			Requested: 3,
			Completed: 3,
			Matching:  3,
		},
		Observations: []domain.ObservationEvent{
			{
				Operation: "filesystem.retained-state.summary",
				Coverage:  "full",
				Details:   map[string]any{"changeCount": 1},
			},
			{
				Operation: "filesystem.retained-state.summary",
				Coverage:  "high",
				Details:   map[string]any{"changeCount": 2},
			},
			{
				Operation: "filesystem.retained-state.summary",
				Coverage:  "best-effort",
				Details:   map[string]any{"changeCount": 3},
			},
		},
	}
	view := filesystemSummaryView(result)
	if view.WriteCoverage != "BEST-EFFORT" ||
		view.RetainedStateCoverage != "BEST-EFFORT" ||
		view.ChangeCount != "6 total across 3 summaries" {
		t.Fatalf("filesystem repeat summary = %#v", view)
	}

	result.Repeats.Completed = 2
	view = filesystemSummaryView(result)
	if view.RetainedStateCoverage != "UNAVAILABLE" ||
		view.ChangeCount != "not reported" {
		t.Fatalf("ambiguous summary count was accepted: %#v", view)
	}

	result.Repeats.Completed = 3
	result.Observations[2].Coverage = "enforcement-only"
	view = filesystemSummaryView(result)
	if view.RetainedStateCoverage != "UNAVAILABLE" ||
		view.ChangeCount != "not reported" {
		t.Fatalf("invalid retained coverage was accepted: %#v", view)
	}
}

func TestEngineDiffSummaryViewRequiresEveryExactSummary(t *testing.T) {
	summary := func(byteCount any, nonEmpty bool) domain.ObservationEvent {
		return domain.ObservationEvent{
			Operation: "filesystem.engine-diff.summary",
			Result:    "observed",
			Observer:  "docker-container-diff",
			Coverage:  "best-effort",
			Details: map[string]any{
				"finalByteCount": byteCount,
				"finalNonEmpty":  nonEmpty,
			},
		}
	}
	result := domain.VerificationResult{
		Repeats: domain.RepeatSummary{
			Requested: 2,
			Completed: 2,
			Matching:  2,
		},
		Observations: []domain.ObservationEvent{
			summary(json.Number("0"), false),
			summary(uint64(9), true),
		},
	}
	view := filesystemSummaryView(result)
	if view.EngineDiffCoverage != "BEST-EFFORT" ||
		view.EngineDiffTranscript !=
			"9 total across 2 summaries (1 non-empty)" {
		t.Fatalf("engine diff summary = %#v", view)
	}

	tests := []struct {
		name         string
		observations []domain.ObservationEvent
	}{
		{
			name:         "missing repeat",
			observations: result.Observations[:1],
		},
		{
			name: "duplicate repeat",
			observations: append(
				append([]domain.ObservationEvent{}, result.Observations...),
				summary(0, false),
			),
		},
		{
			name: "overstated coverage",
			observations: []domain.ObservationEvent{
				summary(0, false),
				summary(0, false),
			},
		},
		{
			name: "byte limit exceeded",
			observations: []domain.ObservationEvent{
				summary(0, false),
				summary(4<<20+1, true),
			},
		},
		{
			name: "nonempty mismatch",
			observations: []domain.ObservationEvent{
				summary(0, false),
				summary(0, true),
			},
		},
	}
	tests[2].observations[1].Coverage = "high"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := result
			candidate.Observations = test.observations
			got := filesystemSummaryView(candidate)
			if got.EngineDiffCoverage != "UNAVAILABLE" ||
				got.EngineDiffTranscript != "not reported" {
				t.Fatalf("invalid engine diff summary accepted: %#v", got)
			}
		})
	}

	unavailable := summary(0, false)
	unavailable.Result = "unavailable"
	unavailable.Coverage = "unavailable"
	unavailable.Details = map[string]any{}
	result.Observations[1] = unavailable
	view = filesystemSummaryView(result)
	if view.EngineDiffCoverage != "UNAVAILABLE" ||
		view.EngineDiffTranscript != "not reported" {
		t.Fatalf("partial engine diff coverage accepted: %#v", view)
	}
}

func TestActivityTraceSummaryViewRequiresEveryExactSummary(t *testing.T) {
	summary := func(
		notifications any,
		rename any,
		change any,
	) domain.ObservationEvent {
		return domain.ObservationEvent{
			SchemaVersion: "1",
			Phase:         domain.PhaseCleanup,
			Actor:         "trusted-runner",
			Operation:     "filesystem.activity-trace.summary",
			Resource:      "/outputs",
			Result:        "observed",
			Observer:      "docker-outputs-activity-trace",
			Coverage:      "best-effort",
			Confidence:    "high",
			Details: map[string]any{
				"scope": "outputs-activity-notification-trace",
				"traceBoundary": "post-preflight-pre-workload-to-" +
					"post-quiesce-pre-retained-final",
				"notificationSemantics": "runtime-filesystem-" +
					"notification-hints",
				"activityTraceCoverage":       "best-effort",
				"operationHistoryCoverage":    "unavailable",
				"actorAttribution":            "unavailable",
				"phaseAttribution":            "controller-window-hint",
				"operationClassification":     "hint-only",
				"rawPathIncluded":             false,
				"contentIncluded":             false,
				"publicEvidence":              "aggregate-only",
				"observerPlacement":           "in-sandbox-trusted-helper",
				"sharesSandboxResourceBudget": true,
				"startIdentityVerified":       true,
				"readyIdentityVerified":       true,
				"stopIdentityVerified":        true,
				"finalIdentityVerified":       true,
				"workloadQuiescenceVerified":  true,
				"transport":                   "controller-stdin-stdout-jsonl",
				"transportBoundBytes":         16 << 10,
				"notificationLimit":           4096,
				"watchLimit":                  2048,
				"observerAdapter":             "node-fs-watch-linux",
				"kernelOverflowDetection":     "unavailable",
				"blindSpots": []string{
					"outside-outputs",
					"exact-process-and-actor",
					"syscall-and-operation-history",
					"kernel-or-runtime-notification-coalescing",
					"node-kernel-queue-overflow-unobservable",
					"new-directory-watch-install-race",
					"watched-directory-delete-recreate",
					"phase-boundary-race",
					"rename-pairing",
					"read-activity",
				},
				"notificationCount": notifications,
				"renameHintCount":   rename,
				"changeHintCount":   change,
				"phaseCounts": []string{
					"setup=0",
					"build=0",
					"run=0",
					"exercise=" + fmt.Sprint(notifications),
					"cleanup=0",
					"unknown=0",
				},
				"canonicalTranscriptDigest": "sha256:" +
					strings.Repeat("a", 64),
				"canonicalByteCount": 64,
			},
		}
	}
	result := domain.VerificationResult{
		Repeats: domain.RepeatSummary{
			Requested: 2,
			Completed: 2,
			Matching:  2,
		},
		Observations: []domain.ObservationEvent{
			summary(json.Number("1"), 1, 0),
			summary(uint64(3), 2, 1),
		},
	}
	view := filesystemSummaryView(result)
	if view.ActivityTraceCoverage != "BEST-EFFORT" ||
		view.ActivityNotifications !=
			"4 total across 2 summaries" {
		t.Fatalf("activity trace summary = %#v", view)
	}

	tests := []struct {
		name   string
		mutate func(*domain.VerificationResult)
	}{
		{
			name: "missing repeat",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations =
					candidate.Observations[:1]
			},
		},
		{
			name: "duplicate repeat",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations = append(
					candidate.Observations,
					summary(0, 0, 0),
				)
			},
		},
		{
			name: "overstated coverage",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Coverage = "high"
			},
		},
		{
			name: "wrong event metadata",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Phase = domain.PhaseRun
			},
		},
		{
			name: "identity gate missing",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["readyIdentityVerified"] = false
			},
		},
		{
			name: "transport contract mismatch",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["transportBoundBytes"] = 16<<10 - 1
			},
		},
		{
			name: "watch limit mismatch",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["watchLimit"] = 2049
			},
		},
		{
			name: "unknown adapter",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["observerAdapter"] = "untrusted-watch"
			},
		},
		{
			name: "adapter overflow contract mismatch",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["kernelOverflowDetection"] =
					"inotify-queue-overflow-fail-closed"
			},
		},
		{
			name: "notification bound",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1] =
					summary(4097, 4097, 0)
			},
		},
		{
			name: "classification mismatch",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1] =
					summary(3, 1, 1)
			},
		},
		{
			name: "phase count mismatch",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].Details["phaseCounts"] =
					[]any{
						"setup=0",
						"build=0",
						"run=0",
						"exercise=2",
						"cleanup=0",
						"unknown=0",
					}
			},
		},
		{
			name: "phase key mismatch",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].Details["phaseCounts"] =
					[]string{
						"setup=0",
						"build=0",
						"run=0",
						"exercise=3",
						"cleanup=0",
						"cleanup=0",
					}
			},
		},
		{
			name: "canonical bound",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["canonicalByteCount"] = 1<<20 + 1
			},
		},
		{
			name: "invalid commitment",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["canonicalTranscriptDigest"] =
					"sha256:bad"
			},
		},
		{
			name: "operation history overclaim",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["operationHistoryCoverage"] =
					"best-effort"
			},
		},
		{
			name: "raw path overclaim",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].
					Details["rawPathIncluded"] = true
			},
		},
		{
			name: "unknown raw path detail",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].Details["rawPath"] =
					"/outputs/private"
			},
		},
		{
			name: "missing blind spots",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				delete(
					candidate.Observations[1].Details,
					"blindSpots",
				)
			},
		},
		{
			name: "mutated blind spot",
			mutate: func(candidate *domain.VerificationResult) {
				candidate.Observations[1].Details =
					cloneRenderDetails(
						candidate.Observations[1].Details,
					)
				candidate.Observations[1].Details["blindSpots"] =
					[]any{
						"outside-outputs",
						"exact-process-and-actor",
						"syscall-and-operation-history",
						"kernel-or-runtime-notification-coalescing",
						"node-kernel-queue-overflow-unobservable",
						"new-directory-watch-install-race",
						"watched-directory-delete-recreate",
						"phase-boundary-race",
						"rename-pairing",
						"read-activity-overstated",
					}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := result
			candidate.Observations = append(
				[]domain.ObservationEvent(nil),
				result.Observations...,
			)
			test.mutate(&candidate)
			got := filesystemSummaryView(candidate)
			if got.ActivityTraceCoverage != "UNAVAILABLE" ||
				got.ActivityNotifications != "not reported" {
				t.Fatalf(
					"invalid activity trace summary accepted: %#v",
					got,
				)
			}
		})
	}
}

func cloneRenderDetails(value map[string]any) map[string]any {
	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func TestFilesystemCoverageDefaultsToUnavailable(t *testing.T) {
	result := domain.VerificationResult{
		Runner: domain.RunnerFeatures{
			FilesystemWriteObservation: "",
		},
	}
	view := filesystemSummaryView(result)
	if view.WriteCoverage != "UNAVAILABLE" ||
		view.RetainedStateCoverage != "UNAVAILABLE" ||
		view.EngineDiffCoverage != "UNAVAILABLE" ||
		view.EngineDiffTranscript != "not reported" ||
		view.ActivityTraceCoverage != "UNAVAILABLE" ||
		view.ActivityNotifications != "not reported" {
		t.Fatalf("filesystem coverage was overstated: %#v", view)
	}
	text := Text(result)
	if !strings.Contains(
		text,
		"Composite write observation (required): UNAVAILABLE",
	) ||
		!strings.Contains(
			text,
			"Retained state observation (optional):  UNAVAILABLE",
		) ||
		!strings.Contains(
			text,
			"Retained-state change count:            not reported",
		) ||
		!strings.Contains(
			text,
			"Docker engine diff (optional):          UNAVAILABLE",
		) ||
		!strings.Contains(
			text,
			"Opaque final transcript bytes:          not reported",
		) ||
		!strings.Contains(
			text,
			"/outputs activity trace (optional):     UNAVAILABLE",
		) ||
		!strings.Contains(
			text,
			"Activity notification hints:            not reported",
		) {
		t.Fatalf("text report omitted unavailable filesystem state:\n%s", text)
	}
}
