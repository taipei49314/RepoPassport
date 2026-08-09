package rendering

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func JSON(value any) ([]byte, error) {
	return canonicaljson.Indent(value)
}

func Text(result domain.VerificationResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "RepoPassport verification %s\n", result.VerificationID)
	fmt.Fprintf(&builder, "Source:          %s\n", result.Subject.TreeDigest)
	fmt.Fprintf(&builder, "Plan:            %s\n", result.Plan.PlanDigest)
	fmt.Fprintf(&builder, "Functional:      %s\n", strings.ToUpper(string(result.Results.Functional)))
	fmt.Fprintf(&builder, "Capability:      %s\n", strings.ToUpper(string(result.Results.Capability)))
	fmt.Fprintf(&builder, "Reproducibility: %s\n", strings.ToUpper(string(result.Results.Reproducibility)))
	fmt.Fprintf(&builder, "Cleanup:         %s\n", strings.ToUpper(string(result.Results.Cleanup)))
	fmt.Fprintf(&builder, "Evidence:        %s\n", strings.ToUpper(string(result.Results.Evidence)))
	fmt.Fprintf(&builder, "Freshness:       %s\n", strings.ToUpper(string(result.Results.Freshness)))
	fmt.Fprintf(&builder, "Overall:         %s\n", strings.ToUpper(string(result.Results.Overall)))
	filesystem := filesystemSummaryView(result)
	builder.WriteString("\nFilesystem observation:\n")
	fmt.Fprintf(&builder, "- Composite write observation (required): %s\n", filesystem.WriteCoverage)
	fmt.Fprintf(&builder, "- Retained state observation (optional):  %s\n", filesystem.RetainedStateCoverage)
	fmt.Fprintf(&builder, "- Retained-state change count:            %s\n", filesystem.ChangeCount)
	fmt.Fprintf(&builder, "- Retained declaration comparison:       %s\n", filesystem.DeclarationComparison)
	fmt.Fprintf(&builder, "- Retained declaration counts:           %s\n", filesystem.DeclarationCounts)
	fmt.Fprintf(&builder, "- Docker engine diff (optional):          %s\n", filesystem.EngineDiffCoverage)
	fmt.Fprintf(&builder, "- Opaque final transcript bytes:          %s\n", filesystem.EngineDiffTranscript)
	fmt.Fprintf(&builder, "- /outputs activity trace (optional):     %s\n", filesystem.ActivityTraceCoverage)
	fmt.Fprintf(&builder, "- Activity notification hints:            %s\n", filesystem.ActivityNotifications)
	fmt.Fprintf(&builder, "- Operation notification comparison:      %s\n", filesystem.OperationNotificationCoverage)
	fmt.Fprintf(&builder, "- Operation notification result:          %s\n", filesystem.OperationNotificationComparison)
	fmt.Fprintf(&builder, "- Operation notification counts:          %s\n", filesystem.OperationNotificationCounts)
	ports := portListenerSummaryView(result)
	builder.WriteString("\nTCP listener observation:\n")
	fmt.Fprintf(&builder, "- Peer listener comparison (optional):    %s\n", ports.Coverage)
	fmt.Fprintf(&builder, "- Peer listener result:                   %s\n", ports.Comparison)
	fmt.Fprintf(&builder, "- Peer listener counts:                   %s\n", ports.Counts)
	resources := resourceSummaryView(result)
	builder.WriteString("\nResource usage:\n")
	fmt.Fprintf(&builder, "- Observation coverage:          %s\n", resources.Coverage)
	fmt.Fprintf(&builder, "- Limit enforcement:             %s\n", resources.Enforcement)
	fmt.Fprintf(&builder, "- Observed fields:               %s\n", resources.ObservedFields)
	fmt.Fprintf(&builder, "- Duration:                      %s\n", resources.Duration)
	fmt.Fprintf(&builder, "- Sandbox peak memory:           %s\n", resources.SandboxPeakMemory)
	fmt.Fprintf(&builder, "- Sandbox CPU time:              %s\n", resources.SandboxCPUTime)
	fmt.Fprintf(&builder, "- Maximum tasks (TIDs):          %s\n", resources.MaxTasks)
	fmt.Fprintf(&builder, "- Log bytes:                     %s\n", resources.LogBytes)
	fmt.Fprintf(&builder, "- Writable bytes (snapshot):     %s\n", resources.WritableBytes)
	fmt.Fprintf(&builder, "- Verified output bytes:         %s\n", resources.OutputBytes)
	if len(result.Errors) > 0 {
		builder.WriteString("\nFindings:\n")
		for _, item := range result.Errors {
			if item == nil {
				continue
			}
			fmt.Fprintf(&builder, "- %s: %s\n", item.Code, item.Message)
		}
	}
	return builder.String()
}

func HTML(result domain.VerificationResult) ([]byte, error) {
	const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>RepoPassport {{.VerificationID}}</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:72rem;margin:0 auto;padding:2rem;line-height:1.5}
h1,h2{line-height:1.15}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.75rem}.card{border:1px solid #8886;border-radius:.6rem;padding:1rem}
.status{font-size:1.05rem;font-weight:700}.mono{font-family:ui-monospace,monospace;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #8886;padding:.55rem}
.notice{border-left:.35rem solid #d99100;padding:.7rem 1rem;background:#d9910015}
</style>
</head>
<body>
<main>
<h1>Repository Passport</h1>
<p class="notice">This report is a bounded verification result, not a malware-free or absolute-safety guarantee.</p>
<p><strong>Verification ID:</strong> <span class="mono">{{.VerificationID}}</span></p>
<div class="grid">
{{range .Verdicts}}<section class="card"><div>{{.Label}}</div><div class="status">{{.Value}}</div></section>{{end}}
</div>
<h2>Bound subject</h2>
<table><tbody>
<tr><th>Tree digest</th><td class="mono">{{.TreeDigest}}</td></tr>
<tr><th>Plan digest</th><td class="mono">{{.PlanDigest}}</td></tr>
<tr><th>Policy digest</th><td class="mono">{{.PolicyDigest}}</td></tr>
<tr><th>Runner</th><td>{{.Runner}}</td></tr>
</tbody></table>
<h2>Observer coverage</h2>
<table><thead><tr><th>Feature</th><th>Coverage</th><th>Required</th><th>Reason</th></tr></thead><tbody>
{{range .Coverage}}<tr><td>{{.Feature}}</td><td>{{.Coverage}}</td><td>{{.Required}}</td><td>{{.Reason}}</td></tr>{{end}}
</tbody></table>
<h2>Filesystem observation</h2>
<table><tbody>
<tr><th>Composite write observation (required)</th><td>{{.Filesystem.WriteCoverage}}</td></tr>
<tr><th>Retained state observation (optional)</th><td>{{.Filesystem.RetainedStateCoverage}}</td></tr>
<tr><th>Retained-state change count</th><td>{{.Filesystem.ChangeCount}}</td></tr>
<tr><th>Retained declaration comparison</th><td>{{.Filesystem.DeclarationComparison}}</td></tr>
<tr><th>Retained declaration counts</th><td>{{.Filesystem.DeclarationCounts}}</td></tr>
<tr><th>Docker engine diff (optional)</th><td>{{.Filesystem.EngineDiffCoverage}}</td></tr>
<tr><th>Opaque final transcript bytes</th><td>{{.Filesystem.EngineDiffTranscript}}</td></tr>
<tr><th>/outputs activity trace (optional)</th><td>{{.Filesystem.ActivityTraceCoverage}}</td></tr>
<tr><th>Activity notification hints</th><td>{{.Filesystem.ActivityNotifications}}</td></tr>
<tr><th>Operation notification comparison (optional)</th><td>{{.Filesystem.OperationNotificationCoverage}}</td></tr>
<tr><th>Operation notification result</th><td>{{.Filesystem.OperationNotificationComparison}}</td></tr>
<tr><th>Operation notification counts</th><td>{{.Filesystem.OperationNotificationCounts}}</td></tr>
</tbody></table>
<h2>TCP listener observation</h2>
<table><tbody>
<tr><th>Peer listener comparison (optional)</th><td>{{.Ports.Coverage}}</td></tr>
<tr><th>Peer listener result</th><td>{{.Ports.Comparison}}</td></tr>
<tr><th>Peer listener counts</th><td>{{.Ports.Counts}}</td></tr>
</tbody></table>
<h2>Resource usage</h2>
<table><tbody>
<tr><th>Observation coverage</th><td>{{.Resources.Coverage}}</td></tr>
<tr><th>Limit enforcement</th><td>{{.Resources.Enforcement}}</td></tr>
<tr><th>Observed fields</th><td>{{.Resources.ObservedFields}}</td></tr>
<tr><th>Duration</th><td>{{.Resources.Duration}}</td></tr>
<tr><th>Sandbox peak memory</th><td>{{.Resources.SandboxPeakMemory}}</td></tr>
<tr><th>Sandbox CPU time</th><td>{{.Resources.SandboxCPUTime}}</td></tr>
<tr><th>Maximum tasks (TIDs)</th><td>{{.Resources.MaxTasks}}</td></tr>
<tr><th>Log bytes</th><td>{{.Resources.LogBytes}}</td></tr>
<tr><th>Writable bytes (snapshot)</th><td>{{.Resources.WritableBytes}}</td></tr>
<tr><th>Verified output bytes</th><td>{{.Resources.OutputBytes}}</td></tr>
</tbody></table>
<h2>Assertions</h2>
<table><thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Message</th></tr></thead><tbody>
{{range .Assertions}}<tr><td>{{.ID}}</td><td>{{.Type}}</td><td>{{.Status}}</td><td>{{.Message}}</td></tr>{{else}}<tr><td colspan="4">No assertions were completed.</td></tr>{{end}}
</tbody></table>
<h2>Findings</h2>
<table><thead><tr><th>Code</th><th>Severity</th><th>Message</th></tr></thead><tbody>
{{range .Errors}}<tr><td class="mono">{{.Code}}</td><td>{{.Severity}}</td><td>{{.Message}}</td></tr>{{else}}<tr><td colspan="3">No findings.</td></tr>{{end}}
</tbody></table>
<h2>Integrity</h2>
<p class="mono">Verification digest: {{.VerificationDigest}}</p>
</main>
</body>
</html>
`
	view := struct {
		VerificationID     string
		Verdicts           []struct{ Label, Value string }
		TreeDigest         string
		PlanDigest         string
		PolicyDigest       string
		Runner             string
		Coverage           []domain.ObserverCoverage
		Filesystem         filesystemReportView
		Ports              portListenerReportView
		Resources          resourceReportView
		Assertions         []domain.AssertionResult
		Errors             []*domain.Error
		VerificationDigest string
	}{
		VerificationID: result.VerificationID,
		TreeDigest:     result.Subject.TreeDigest, PlanDigest: result.Plan.PlanDigest,
		PolicyDigest: result.Plan.PolicyBundleDigest, Runner: result.Runner.Backend,
		Coverage: result.ObserverCoverage, Filesystem: filesystemSummaryView(result),
		Ports:      portListenerSummaryView(result),
		Resources:  resourceSummaryView(result),
		Assertions: result.Assertions, Errors: nonNilErrors(result.Errors),
		VerificationDigest: result.Digests.Verification,
	}
	view.Verdicts = []struct{ Label, Value string }{
		{"Functional", strings.ToUpper(string(result.Results.Functional))},
		{"Capability", strings.ToUpper(string(result.Results.Capability))},
		{"Reproducibility", strings.ToUpper(string(result.Results.Reproducibility))},
		{"Cleanup", strings.ToUpper(string(result.Results.Cleanup))},
		{"Evidence", strings.ToUpper(string(result.Results.Evidence))},
		{"Freshness", strings.ToUpper(string(result.Results.Freshness))},
		{"Overall", strings.ToUpper(string(result.Results.Overall))},
	}
	parsed, err := template.New("report").Parse(page)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := parsed.Execute(&output, view); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

const filesystemRetainedStateChangeLimit = 256

type filesystemReportView struct {
	WriteCoverage                   string
	RetainedStateCoverage           string
	ChangeCount                     string
	DeclarationComparison           string
	DeclarationCounts               string
	EngineDiffCoverage              string
	EngineDiffTranscript            string
	ActivityTraceCoverage           string
	ActivityNotifications           string
	OperationNotificationCoverage   string
	OperationNotificationComparison string
	OperationNotificationCounts     string
}

type portListenerReportView struct {
	Coverage   string
	Comparison string
	Counts     string
}

func portListenerSummaryView(
	result domain.VerificationResult,
) portListenerReportView {
	view := portListenerReportView{
		Coverage:   "UNAVAILABLE",
		Comparison: "NOT REPORTED",
		Counts:     "not reported",
	}
	expected := result.Repeats.Completed
	if result.Repeats.Requested < 1 || result.Repeats.Requested > 10 ||
		expected < 1 || expected > result.Repeats.Requested {
		return view
	}
	summaries := make([]domain.ObservationEvent, 0, expected)
	for index := range result.Observations {
		if result.Observations[index].Operation !=
			"port.listener-trace.summary" {
			continue
		}
		summaries = append(summaries, result.Observations[index])
		if len(summaries) > expected {
			return view
		}
	}
	if len(summaries) != expected {
		return view
	}

	hasNonconforming := false
	hasNotTested := false
	baselineTotal := 0
	declaredTotal := 0
	sampledTotal := 0
	undeclaredTotal := 0
	for _, summary := range summaries {
		if summary.SchemaVersion != "1" ||
			summary.Phase != domain.PhaseCleanup ||
			summary.Actor != "trusted-runner" ||
			summary.Resource != "tcp-listeners" ||
			summary.Observer != "docker-peer-port-listener-trace" ||
			!validRenderedPeerPortStaticDetails(summary.Details) {
			return view
		}
		comparison, ok := summary.Details["comparisonResult"].(string)
		if !ok {
			return view
		}
		switch comparison {
		case "nonconforming-listeners", "no-undeclared-observed":
			if !renderedExactDetailKeys(summary.Details,
				renderedPeerPortCompleteDetailKeys,
			) || summary.Result != "observed" ||
				summary.Coverage != "best-effort" ||
				summary.Confidence != "high" {
				return view
			}
			baseline, baselineOK := renderedPortListenerCount(
				summary.Details["baselineEndpointCount"], 0, 0,
			)
			declared, declaredOK := renderedPortListenerCount(
				summary.Details["declaredEndpointCount"], 1, 1,
			)
			sampled, sampledOK := renderedPortListenerCount(
				summary.Details["sampledEndpointCount"], 1, 16,
			)
			undeclared, undeclaredOK := renderedPortListenerCount(
				summary.Details["undeclaredEndpointCount"], 0, 15,
			)
			_, sampleCountOK := renderedPortListenerCount(
				summary.Details["sampleCount"], 3, 1200,
			)
			_, maxSampleGapOK := renderedPortListenerCount(
				summary.Details["maxSampleGapMillis"], 0, 1000,
			)
			_, transitionsOK := renderedPortListenerCount(
				summary.Details["transitionCount"], 2, 4096,
			)
			if !baselineOK || !declaredOK || !sampledOK || !undeclaredOK ||
				!sampleCountOK || !maxSampleGapOK || !transitionsOK ||
				summary.Details["observerAdapter"] != "node-proc-net-tcp-linux" &&
					summary.Details["observerAdapter"] != "python-proc-net-tcp-linux" ||
				!validRenderedSHA256(summary.Details["canonicalSampleDigest"]) ||
				summary.Details["identityVerified"] != true ||
				summary.Details["namespaceIsolationVerified"] != true ||
				summary.Details["workloadQuiescenceVerified"] != true ||
				summary.Details["peerRemoveVerified"] != true ||
				sampled != declared+undeclared ||
				comparison == "nonconforming-listeners" && undeclared == 0 ||
				comparison == "no-undeclared-observed" && undeclared != 0 {
				return view
			}
			if comparison == "nonconforming-listeners" {
				hasNonconforming = true
			}
			baselineTotal += baseline
			declaredTotal += declared
			sampledTotal += sampled
			undeclaredTotal += undeclared
		case "not-tested":
			if !(renderedExactDetailKeys(summary.Details,
				renderedPeerPortUntestedDetailKeys,
			) || renderedExactDetailKeys(summary.Details,
				append(renderedPeerPortUntestedDetailKeys, "failure"),
			)) || summary.Result != "unavailable" ||
				summary.Coverage != "unavailable" ||
				summary.Confidence != "unknown" ||
				!validRenderedPeerPortFailure(summary.Details["failure"]) {
				return view
			}
			hasNotTested = true
		default:
			return view
		}
	}

	if hasNotTested {
		if hasNonconforming {
			view.Comparison = "NONCONFORMING"
		} else {
			view.Comparison = "NOT-TESTED"
		}
		return view
	}
	view.Coverage = "BEST-EFFORT"
	if hasNonconforming {
		view.Comparison = "NONCONFORMING"
	} else {
		view.Comparison = "NO-UNDECLARED-OBSERVED"
	}
	label := "summary"
	if len(summaries) != 1 {
		label = "summaries"
	}
	view.Counts = fmt.Sprintf(
		"baseline total %d; declared total %d; sampled total %d; undeclared total %d across %d %s",
		baselineTotal,
		declaredTotal,
		sampledTotal,
		undeclaredTotal,
		len(summaries),
		label,
	)
	return view
}

func renderedPortListenerCount(value any, minimum, maximum int) (int, bool) {
	return renderedOperationNotificationCount(value, minimum, maximum)
}

var renderedPeerPortUntestedDetailKeys = []string{
	"observerPlacement", "sharesTargetPIDNamespace",
	"sharesTargetMountNamespace", "sharesTargetIPCNamespace",
	"sharesTargetCgroup", "processAttribution", "lifetimeSemantics",
	"kernelEventCoverage", "shortLivedListenerGap", "udpUnavailable",
	"publicEvidence", "evidenceBasis", "comparisonResult", "sampleLimit",
	"intervalMillis", "maxAllowedGapMillis", "identityVerified",
	"namespaceIsolationVerified", "workloadQuiescenceVerified",
	"peerRemoveVerified", "canonicalDigestSemantics",
}

var renderedPeerPortCompleteDetailKeys = append(
	append([]string{}, renderedPeerPortUntestedDetailKeys...),
	"observerAdapter", "declaredEndpointCount", "baselineEndpointCount",
	"sampledEndpointCount", "undeclaredEndpointCount", "sampleCount",
	"maxSampleGapMillis", "transitionCount", "canonicalSampleDigest",
)

func validRenderedPeerPortStaticDetails(details map[string]any) bool {
	sampleLimit, sampleLimitOK := renderedPortListenerCount(
		details["sampleLimit"], 1200, 1200,
	)
	interval, intervalOK := renderedPortListenerCount(
		details["intervalMillis"], 100, 100,
	)
	maxGap, maxGapOK := renderedPortListenerCount(
		details["maxAllowedGapMillis"], 1000, 1000,
	)
	if details["observerPlacement"] !=
		"peer-container-shared-network-namespace" ||
		details["processAttribution"] != "unavailable" ||
		details["lifetimeSemantics"] != "sample-window-only" ||
		details["kernelEventCoverage"] != "unavailable" ||
		details["shortLivedListenerGap"] != true ||
		details["udpUnavailable"] != true ||
		details["publicEvidence"] != "aggregate-only" ||
		details["evidenceBasis"] != "aggregate-only" ||
		!sampleLimitOK || sampleLimit != 1200 || !intervalOK || interval != 100 ||
		!maxGapOK || maxGap != 1000 ||
		details["canonicalDigestSemantics"] !=
			"helper-commitment-not-controller-recomputed" {
		return false
	}
	for _, key := range []string{
		"sharesTargetPIDNamespace", "sharesTargetMountNamespace",
		"sharesTargetIPCNamespace", "sharesTargetCgroup", "identityVerified",
		"namespaceIsolationVerified", "workloadQuiescenceVerified",
		"peerRemoveVerified",
	} {
		if _, ok := details[key].(bool); !ok {
			return false
		}
	}
	return true
}

func validRenderedPeerPortFailure(value any) bool {
	if value == nil {
		return true
	}
	failure, ok := value.(string)
	if !ok {
		return false
	}
	switch failure {
	case "backend-not-live-qualified", "unsupported-http-profile",
		"immutable-container-identity-unavailable", "ready-transport-failed",
		"final-transport-failed", "workload-quiescence-failed",
		"observer-not-started", "peer-remove-failed":
		return true
	default:
		return false
	}
}

func filesystemSummaryView(
	result domain.VerificationResult,
) filesystemReportView {
	view := filesystemReportView{
		WriteCoverage: observationCoverageLabel(
			result.Runner.FilesystemWriteObservation,
		),
		RetainedStateCoverage:           "UNAVAILABLE",
		ChangeCount:                     "not reported",
		DeclarationComparison:           "NOT REPORTED",
		DeclarationCounts:               "not reported",
		EngineDiffCoverage:              "UNAVAILABLE",
		EngineDiffTranscript:            "not reported",
		ActivityTraceCoverage:           "UNAVAILABLE",
		ActivityNotifications:           "not reported",
		OperationNotificationCoverage:   "UNAVAILABLE",
		OperationNotificationComparison: "NOT REPORTED",
		OperationNotificationCounts:     "not reported",
	}
	expected := result.Repeats.Completed
	if result.Repeats.Requested < 1 ||
		result.Repeats.Requested > 10 ||
		expected < 1 ||
		expected > result.Repeats.Requested {
		return view
	}
	view.EngineDiffCoverage, view.EngineDiffTranscript =
		engineDiffSummaryView(result, expected)
	view.ActivityTraceCoverage, view.ActivityNotifications =
		activityTraceSummaryView(result, expected)
	view.OperationNotificationCoverage,
		view.OperationNotificationComparison,
		view.OperationNotificationCounts = operationNotificationSummaryView(
		result,
		expected,
	)
	summaries := make([]domain.ObservationEvent, 0, expected)
	for index := range result.Observations {
		if result.Observations[index].Operation !=
			"filesystem.retained-state.summary" {
			continue
		}
		summaries = append(summaries, result.Observations[index])
		if len(summaries) > expected {
			return view
		}
	}
	if len(summaries) != expected {
		return view
	}
	view.DeclarationComparison, view.DeclarationCounts =
		retainedDeclarationComparisonView(summaries)
	retainedCoverage := "full"
	totalChanges := 0
	countsValid := true
	for _, summary := range summaries {
		coverage, ok := retainedObservationCoverage(summary.Coverage)
		if !ok {
			return view
		}
		if retainedCoverageRank(coverage) <
			retainedCoverageRank(retainedCoverage) {
			retainedCoverage = coverage
		}
		count, ok := boundedFilesystemChangeCount(
			summary.Details["changeCount"],
		)
		if !ok {
			countsValid = false
			continue
		}
		totalChanges += count
	}
	view.RetainedStateCoverage = observationCoverageLabel(
		retainedCoverage,
	)
	if countsValid && retainedCoverage != "unavailable" {
		view.ChangeCount = fmt.Sprintf("%d", totalChanges)
		if len(summaries) > 1 {
			view.ChangeCount = fmt.Sprintf(
				"%d total across %d summaries",
				totalChanges,
				len(summaries),
			)
		}
	}
	return view
}

func retainedDeclarationComparisonView(
	summaries []domain.ObservationEvent,
) (string, string) {
	if len(summaries) == 0 {
		return "NOT REPORTED", "not reported"
	}
	hasNonconforming := false
	hasNotTested := false
	countsComplete := true
	declaredPatterns := 0
	comparedChanges := 0
	allowedChanges := 0
	undeclaredChanges := 0
	for _, summary := range summaries {
		if summary.Details["declarationComparisonScope"] !=
			"executed-phase-filesystem-write-union" ||
			summary.Details["declarationComparisonVersion"] != "0.1.0" {
			return "NOT REPORTED", "not reported"
		}
		result, ok := summary.Details["declarationComparisonResult"].(string)
		if !ok {
			return "NOT REPORTED", "not reported"
		}
		switch result {
		case "conforming-retained-state":
		case "nonconforming-retained-state":
			hasNonconforming = true
		case "not-tested":
			hasNotTested = true
		default:
			return "NOT REPORTED", "not reported"
		}
		if result == "not-tested" {
			for _, key := range []string{
				"declaredPatternCount",
				"comparedChangeCount",
				"allowedChangeCount",
				"undeclaredChangeCount",
			} {
				if _, present := summary.Details[key]; present {
					countsComplete = false
				}
			}
			continue
		}
		declared, declaredOK := boundedFilesystemChangeCount(
			summary.Details["declaredPatternCount"],
		)
		compared, comparedOK := boundedFilesystemChangeCount(
			summary.Details["comparedChangeCount"],
		)
		allowed, allowedOK := boundedFilesystemChangeCount(
			summary.Details["allowedChangeCount"],
		)
		undeclared, undeclaredOK := boundedFilesystemChangeCount(
			summary.Details["undeclaredChangeCount"],
		)
		if !declaredOK || !comparedOK || !allowedOK ||
			!undeclaredOK || allowed+undeclared != compared {
			countsComplete = false
			continue
		}
		if result == "conforming-retained-state" && undeclared != 0 ||
			result == "nonconforming-retained-state" && undeclared == 0 {
			countsComplete = false
			continue
		}
		declaredPatterns += declared
		comparedChanges += compared
		allowedChanges += allowed
		undeclaredChanges += undeclared
	}
	comparisonResult := "CONFORMING"
	if hasNonconforming {
		comparisonResult = "NONCONFORMING"
	} else if hasNotTested {
		comparisonResult = "NOT-TESTED"
	}
	if hasNotTested || !countsComplete {
		return comparisonResult, "not reported"
	}
	counts := fmt.Sprintf(
		"declared-pattern total %d; compared %d; allowed %d; undeclared %d",
		declaredPatterns,
		comparedChanges,
		allowedChanges,
		undeclaredChanges,
	)
	if len(summaries) > 1 {
		counts += fmt.Sprintf(" across %d summaries", len(summaries))
	}
	return comparisonResult, counts
}

func engineDiffSummaryView(
	result domain.VerificationResult,
	expected int,
) (string, string) {
	summaries := make([]domain.ObservationEvent, 0, expected)
	for index := range result.Observations {
		if result.Observations[index].Operation !=
			"filesystem.engine-diff.summary" {
			continue
		}
		summaries = append(summaries, result.Observations[index])
		if len(summaries) > expected {
			return "UNAVAILABLE", "not reported"
		}
	}
	if len(summaries) != expected {
		return "UNAVAILABLE", "not reported"
	}
	totalBytes := 0
	nonEmpty := 0
	for _, summary := range summaries {
		switch summary.Coverage {
		case "best-effort":
			if summary.Result != "observed" ||
				summary.Observer != "docker-container-diff" {
				return "UNAVAILABLE", "not reported"
			}
		case "unavailable":
			return "UNAVAILABLE", "not reported"
		default:
			return "UNAVAILABLE", "not reported"
		}
		byteCount, ok := boundedEngineDiffByteCount(
			summary.Details["finalByteCount"],
		)
		if !ok {
			return "UNAVAILABLE", "not reported"
		}
		isNonEmpty, ok := summary.Details["finalNonEmpty"].(bool)
		if !ok || isNonEmpty != (byteCount != 0) {
			return "UNAVAILABLE", "not reported"
		}
		totalBytes += byteCount
		if isNonEmpty {
			nonEmpty++
		}
	}
	summaryLabel := "summary"
	if len(summaries) != 1 {
		summaryLabel = "summaries"
	}
	transcript := fmt.Sprintf(
		"%d total across %d %s (%d non-empty)",
		totalBytes,
		len(summaries),
		summaryLabel,
		nonEmpty,
	)
	return observationCoverageLabel("best-effort"), transcript
}

func activityTraceSummaryView(
	result domain.VerificationResult,
	expected int,
) (string, string) {
	summaries := make([]domain.ObservationEvent, 0, expected)
	for index := range result.Observations {
		if result.Observations[index].Operation !=
			"filesystem.activity-trace.summary" {
			continue
		}
		summaries = append(
			summaries,
			result.Observations[index],
		)
		if len(summaries) > expected {
			return "UNAVAILABLE", "not reported"
		}
	}
	if len(summaries) != expected {
		return "UNAVAILABLE", "not reported"
	}
	totalNotifications := 0
	for _, summary := range summaries {
		if !renderedExactDetailKeys(
			summary.Details,
			[]string{
				"scope",
				"traceBoundary",
				"notificationSemantics",
				"rawPathIncluded",
				"contentIncluded",
				"publicEvidence",
				"actorAttribution",
				"phaseAttribution",
				"operationClassification",
				"operationHistoryCoverage",
				"observerPlacement",
				"sharesSandboxResourceBudget",
				"startIdentityVerified",
				"readyIdentityVerified",
				"stopIdentityVerified",
				"finalIdentityVerified",
				"workloadQuiescenceVerified",
				"transport",
				"transportBoundBytes",
				"notificationLimit",
				"watchLimit",
				"activityTraceCoverage",
				"blindSpots",
				"observerAdapter",
				"notificationCount",
				"renameHintCount",
				"changeHintCount",
				"phaseCounts",
				"canonicalTranscriptDigest",
				"canonicalByteCount",
				"kernelOverflowDetection",
			},
		) ||
			!renderedExactStringList(
				summary.Details["blindSpots"],
				[]string{
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
			) {
			return "UNAVAILABLE", "not reported"
		}
		if summary.SchemaVersion != "1" ||
			summary.Phase != domain.PhaseCleanup ||
			summary.Actor != "trusted-runner" ||
			summary.Resource != "/outputs" ||
			summary.Confidence != "high" ||
			summary.Coverage != "best-effort" ||
			summary.Result != "observed" ||
			summary.Observer != "docker-outputs-activity-trace" ||
			summary.Details["scope"] !=
				"outputs-activity-notification-trace" ||
			summary.Details["traceBoundary"] !=
				"post-preflight-pre-workload-to-post-quiesce-pre-retained-final" ||
			summary.Details["notificationSemantics"] !=
				"runtime-filesystem-notification-hints" ||
			summary.Details["activityTraceCoverage"] !=
				"best-effort" ||
			summary.Details["operationHistoryCoverage"] !=
				"unavailable" ||
			summary.Details["actorAttribution"] != "unavailable" ||
			summary.Details["phaseAttribution"] !=
				"controller-window-hint" ||
			summary.Details["operationClassification"] != "hint-only" ||
			summary.Details["rawPathIncluded"] != false ||
			summary.Details["contentIncluded"] != false ||
			summary.Details["publicEvidence"] != "aggregate-only" ||
			summary.Details["observerPlacement"] !=
				"in-sandbox-trusted-helper" ||
			summary.Details["sharesSandboxResourceBudget"] != true ||
			summary.Details["startIdentityVerified"] != true ||
			summary.Details["readyIdentityVerified"] != true ||
			summary.Details["stopIdentityVerified"] != true ||
			summary.Details["finalIdentityVerified"] != true ||
			summary.Details["workloadQuiescenceVerified"] != true ||
			summary.Details["transport"] !=
				"controller-stdin-stdout-jsonl" {
			return "UNAVAILABLE", "not reported"
		}
		transportBound, ok := boundedEngineDiffByteCount(
			summary.Details["transportBoundBytes"],
		)
		if !ok || transportBound != 16<<10 {
			return "UNAVAILABLE", "not reported"
		}
		notificationLimit, ok := boundedEngineDiffByteCount(
			summary.Details["notificationLimit"],
		)
		if !ok || notificationLimit != 4096 {
			return "UNAVAILABLE", "not reported"
		}
		watchLimit, ok := boundedEngineDiffByteCount(
			summary.Details["watchLimit"],
		)
		if !ok || watchLimit != 2048 {
			return "UNAVAILABLE", "not reported"
		}
		adapter, ok := summary.Details["observerAdapter"].(string)
		if !ok {
			return "UNAVAILABLE", "not reported"
		}
		switch adapter {
		case "node-fs-watch-linux":
			if summary.Details["kernelOverflowDetection"] !=
				"unavailable" {
				return "UNAVAILABLE", "not reported"
			}
		case "python-inotify-linux":
			if summary.Details["kernelOverflowDetection"] !=
				"inotify-queue-overflow-fail-closed" {
				return "UNAVAILABLE", "not reported"
			}
		default:
			return "UNAVAILABLE", "not reported"
		}
		notificationCount, ok := boundedEngineDiffByteCount(
			summary.Details["notificationCount"],
		)
		if !ok || notificationCount > 4096 {
			return "UNAVAILABLE", "not reported"
		}
		renameCount, ok := boundedEngineDiffByteCount(
			summary.Details["renameHintCount"],
		)
		if !ok || renameCount > 4096 {
			return "UNAVAILABLE", "not reported"
		}
		changeCount, ok := boundedEngineDiffByteCount(
			summary.Details["changeHintCount"],
		)
		if !ok || changeCount > 4096 ||
			renameCount+changeCount != notificationCount {
			return "UNAVAILABLE", "not reported"
		}
		phaseTotal, ok := renderedActivityTracePhaseTotal(
			summary.Details["phaseCounts"],
		)
		if !ok || phaseTotal != notificationCount {
			return "UNAVAILABLE", "not reported"
		}
		canonicalBytes, ok := boundedEngineDiffByteCount(
			summary.Details["canonicalByteCount"],
		)
		if !ok || canonicalBytes > 1<<20 ||
			!validRenderedSHA256(
				summary.Details["canonicalTranscriptDigest"],
			) {
			return "UNAVAILABLE", "not reported"
		}
		totalNotifications += notificationCount
	}
	label := "summary"
	if len(summaries) != 1 {
		label = "summaries"
	}
	return observationCoverageLabel("best-effort"), fmt.Sprintf(
		"%d total across %d %s",
		totalNotifications,
		len(summaries),
		label,
	)
}

func operationNotificationSummaryView(
	result domain.VerificationResult,
	expected int,
) (string, string, string) {
	summaries := make([]domain.ObservationEvent, 0, expected)
	for index := range result.Observations {
		if result.Observations[index].Operation !=
			"filesystem.operation-notification.summary" {
			continue
		}
		summaries = append(summaries, result.Observations[index])
		if len(summaries) > expected {
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
	}
	if len(summaries) != expected {
		return "UNAVAILABLE", "NOT REPORTED", "not reported"
	}

	hasNonconforming := false
	hasNotTested := false
	countsComplete := true
	windowTotal := 0
	declaredTotal := 0
	comparedTotal := 0
	allowedTotal := 0
	undeclaredTotal := 0
	mutationTotals := [5]int{}
	for _, summary := range summaries {
		if summary.SchemaVersion != "1" ||
			summary.Phase != domain.PhaseCleanup ||
			summary.Actor != "trusted-runner" ||
			summary.Resource != "/outputs" ||
			summary.Observer != "docker-python-outputs-inotify-comparison" ||
			summary.Details["scope"] !=
				"outputs-operation-notification-comparison" ||
			summary.Details["publicEvidence"] != "aggregate-only" ||
			summary.Details["evidenceBasis"] != "aggregate-only" ||
			summary.Details["rawPathIncluded"] != false ||
			summary.Details["ruleTextIncluded"] != false ||
			summary.Details["contentIncluded"] != false ||
			summary.Details["actorAttribution"] != "unavailable" ||
			summary.Details["renamePairing"] != "unavailable" ||
			!renderedExactStringList(
				summary.Details["blindSpots"],
				[]string{
					"outside-outputs", "read-and-syscall-history",
					"actor-and-process-attribution", "rename-pairing",
					"inotify-coalescing", "new-directory-watch-race",
				},
			) {
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
		if _, ok := renderedOperationNotificationCount(
			summary.Details["notificationLimit"], 4096, 4096,
		); !ok {
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
		if _, ok := renderedOperationNotificationCount(
			summary.Details["ruleLimitPerWindow"], 256, 256,
		); !ok {
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
		if _, ok := renderedOperationNotificationCount(
			summary.Details["windowLimit"], 128, 128,
		); !ok {
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
		comparison, ok := summary.Details["comparisonResult"].(string)
		if !ok {
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
		switch comparison {
		case "nonconforming-notifications", "no-undeclared-observed":
			if !renderedExactDetailKeys(
				summary.Details,
				[]string{
					"scope", "publicEvidence", "rawPathIncluded",
					"ruleTextIncluded", "contentIncluded", "actorAttribution",
					"renamePairing", "preDispatchQuiescenceVerified",
					"postDispatchQuiescenceVerified",
					"phaseAcknowledgementsComplete", "notificationLimit",
					"ruleLimitPerWindow", "windowLimit", "evidenceBasis",
					"comparisonResult", "blindSpots", "windowCount",
					"quiescenceWindowCount", "declaredPatternCount",
					"comparedNotificationCount", "allowedNotificationCount",
					"undeclaredNotificationCount", "mutationCounts",
				},
			) ||
				summary.Result != "observed" ||
				summary.Coverage != "best-effort" ||
				summary.Confidence != "high" ||
				summary.Details["preDispatchQuiescenceVerified"] != true ||
				summary.Details["postDispatchQuiescenceVerified"] != true ||
				summary.Details["phaseAcknowledgementsComplete"] != true {
				return "UNAVAILABLE", "NOT REPORTED", "not reported"
			}
			windowCount, windowOK := renderedOperationNotificationCount(
				summary.Details["windowCount"], 1, 128,
			)
			quiescenceWindows, quiescenceOK := renderedOperationNotificationCount(
				summary.Details["quiescenceWindowCount"], 1, 128,
			)
			declared, declaredOK := renderedOperationNotificationCount(
				summary.Details["declaredPatternCount"], 0, windowCount*256,
			)
			compared, comparedOK := renderedOperationNotificationCount(
				summary.Details["comparedNotificationCount"], 0, 4096,
			)
			allowed, allowedOK := renderedOperationNotificationCount(
				summary.Details["allowedNotificationCount"], 0, 4096,
			)
			undeclared, undeclaredOK := renderedOperationNotificationCount(
				summary.Details["undeclaredNotificationCount"], 0, 4096,
			)
			mutations, mutationsOK := renderedOperationNotificationMutationCounts(
				summary.Details["mutationCounts"],
			)
			if !windowOK || !quiescenceOK || quiescenceWindows != windowCount ||
				!declaredOK || !comparedOK || !allowedOK || !undeclaredOK ||
				allowed+undeclared != compared || !mutationsOK ||
				mutations[0]+mutations[1]+mutations[2]+mutations[3]+mutations[4] != compared ||
				comparison == "nonconforming-notifications" && undeclared == 0 ||
				comparison == "no-undeclared-observed" && undeclared != 0 {
				return "UNAVAILABLE", "NOT REPORTED", "not reported"
			}
			if comparison == "nonconforming-notifications" {
				hasNonconforming = true
			}
			windowTotal += windowCount
			declaredTotal += declared
			comparedTotal += compared
			allowedTotal += allowed
			undeclaredTotal += undeclared
			for index := range mutationTotals {
				mutationTotals[index] += mutations[index]
			}
		case "not-tested":
			if !renderedExactDetailKeys(
				summary.Details,
				[]string{
					"scope", "publicEvidence", "rawPathIncluded",
					"ruleTextIncluded", "contentIncluded", "actorAttribution",
					"renamePairing", "preDispatchQuiescenceVerified",
					"postDispatchQuiescenceVerified",
					"phaseAcknowledgementsComplete", "notificationLimit",
					"ruleLimitPerWindow", "windowLimit", "evidenceBasis",
					"comparisonResult", "blindSpots", "failure",
				},
			) ||
				summary.Result != "unavailable" ||
				summary.Coverage != "unavailable" ||
				summary.Confidence != "unknown" ||
				!renderedOperationNotificationFailure(summary.Details["failure"]) {
				return "UNAVAILABLE", "NOT REPORTED", "not reported"
			}
			hasNotTested = true
			countsComplete = false
		default:
			return "UNAVAILABLE", "NOT REPORTED", "not reported"
		}
	}

	comparison := "NO-UNDECLARED-OBSERVED"
	if hasNonconforming {
		comparison = "NONCONFORMING"
	} else if hasNotTested {
		comparison = "NOT-TESTED"
	}
	if hasNotTested || !countsComplete {
		return "UNAVAILABLE", comparison, "not reported"
	}
	label := "summary"
	if len(summaries) != 1 {
		label = "summaries"
	}
	return observationCoverageLabel("best-effort"), comparison, fmt.Sprintf(
		"windows %d; declared-pattern total %d; compared %d; allowed %d; undeclared %d; create %d; delete %d; write %d; rename %d; metadata %d across %d %s",
		windowTotal,
		declaredTotal,
		comparedTotal,
		allowedTotal,
		undeclaredTotal,
		mutationTotals[0],
		mutationTotals[1],
		mutationTotals[2],
		mutationTotals[3],
		mutationTotals[4],
		len(summaries),
		label,
	)
}

func renderedOperationNotificationCount(value any, minimum, maximum int) (int, bool) {
	count, ok := boundedEngineDiffByteCount(value)
	if !ok || count < minimum || count > maximum {
		return 0, false
	}
	return count, true
}

func renderedOperationNotificationMutationCounts(value any) ([5]int, bool) {
	values := [5]int{}
	expected := []string{"create", "delete", "write", "rename", "metadata"}
	var items []string
	switch typed := value.(type) {
	case []string:
		items = typed
	case []any:
		items = make([]string, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return values, false
			}
			items[index] = text
		}
	default:
		return values, false
	}
	if len(items) != len(expected) {
		return values, false
	}
	for index, name := range expected {
		prefix := name + "="
		if !strings.HasPrefix(items[index], prefix) {
			return values, false
		}
		count, err := strconv.Atoi(strings.TrimPrefix(items[index], prefix))
		if err != nil || count < 0 || count > 4096 ||
			strconv.Itoa(count) != strings.TrimPrefix(items[index], prefix) {
			return values, false
		}
		values[index] = count
	}
	return values, true
}

func renderedOperationNotificationFailure(value any) bool {
	failure, ok := value.(string)
	return ok && failure != "" && len(failure) <= 256
}

func renderedExactDetailKeys(
	value map[string]any,
	keys []string,
) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := value[key]; !present {
			return false
		}
	}
	return true
}

func renderedExactStringList(value any, expected []string) bool {
	var actual []string
	switch typed := value.(type) {
	case []string:
		actual = typed
	case []any:
		actual = make([]string, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return false
			}
			actual[index] = text
		}
	default:
		return false
	}
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func renderedActivityTracePhaseTotal(value any) (int, bool) {
	var entries []string
	switch typed := value.(type) {
	case []string:
		entries = typed
	case []any:
		entries = make([]string, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return 0, false
			}
			entries[index] = text
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
	if len(entries) != len(names) {
		return 0, false
	}
	total := 0
	for index, name := range names {
		prefix := name + "="
		if !strings.HasPrefix(entries[index], prefix) {
			return 0, false
		}
		raw := strings.TrimPrefix(entries[index], prefix)
		if raw == "" {
			return 0, false
		}
		for _, character := range raw {
			if character < '0' || character > '9' {
				return 0, false
			}
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

func validRenderedSHA256(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != len("sha256:")+64 ||
		!strings.HasPrefix(text, "sha256:") {
		return false
	}
	for _, character := range text[len("sha256:"):] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func retainedObservationCoverage(value string) (string, bool) {
	switch value {
	case "full", "high", "best-effort", "unavailable":
		return value, true
	default:
		return "", false
	}
}

func retainedCoverageRank(value string) int {
	switch value {
	case "full":
		return 3
	case "high":
		return 2
	case "best-effort":
		return 1
	default:
		return 0
	}
}

func boundedFilesystemChangeCount(value any) (int, bool) {
	var numeric float64
	switch typed := value.(type) {
	case int:
		if typed < 0 || typed > filesystemRetainedStateChangeLimit {
			return 0, false
		}
		return typed, true
	case int8:
		numeric = float64(typed)
	case int16:
		numeric = float64(typed)
	case int32:
		numeric = float64(typed)
	case int64:
		numeric = float64(typed)
	case uint:
		if typed > filesystemRetainedStateChangeLimit {
			return 0, false
		}
		return int(typed), true
	case uint8:
		numeric = float64(typed)
	case uint16:
		numeric = float64(typed)
	case uint32:
		numeric = float64(typed)
	case uint64:
		if typed > filesystemRetainedStateChangeLimit {
			return 0, false
		}
		return int(typed), true
	case float32:
		numeric = float64(typed)
	case float64:
		numeric = typed
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		numeric = parsed
	default:
		return 0, false
	}
	if math.IsNaN(numeric) || math.IsInf(numeric, 0) ||
		numeric < 0 ||
		numeric > filesystemRetainedStateChangeLimit ||
		math.Trunc(numeric) != numeric {
		return 0, false
	}
	return int(numeric), true
}

func boundedEngineDiffByteCount(value any) (int, bool) {
	var numeric float64
	switch typed := value.(type) {
	case int:
		if typed < 0 || typed > 4<<20 {
			return 0, false
		}
		return typed, true
	case int8:
		numeric = float64(typed)
	case int16:
		numeric = float64(typed)
	case int32:
		numeric = float64(typed)
	case int64:
		numeric = float64(typed)
	case uint:
		if typed > 4<<20 {
			return 0, false
		}
		return int(typed), true
	case uint8:
		numeric = float64(typed)
	case uint16:
		numeric = float64(typed)
	case uint32:
		numeric = float64(typed)
	case uint64:
		if typed > 4<<20 {
			return 0, false
		}
		return int(typed), true
	case float32:
		numeric = float64(typed)
	case float64:
		numeric = typed
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		numeric = parsed
	default:
		return 0, false
	}
	if math.IsNaN(numeric) || math.IsInf(numeric, 0) ||
		numeric < 0 || numeric > 4<<20 ||
		math.Trunc(numeric) != numeric {
		return 0, false
	}
	return int(numeric), true
}

type resourceReportView struct {
	Coverage          string
	Enforcement       string
	ObservedFields    string
	SandboxPeakMemory string
	SandboxCPUTime    string
	Duration          string
	MaxTasks          string
	LogBytes          string
	WritableBytes     string
	OutputBytes       string
}

func resourceSummaryView(result domain.VerificationResult) resourceReportView {
	observedFields := "none reported"
	if len(result.Resources.ObservedFields) > 0 {
		values := make([]string, len(result.Resources.ObservedFields))
		for index, field := range result.Resources.ObservedFields {
			values[index] = string(field)
		}
		observedFields = strings.Join(values, ", ")
	}
	enforcement := "not reported"
	if result.Runner.ResourceLimitEnforcement {
		enforcement = "ACTIVE"
	}
	return resourceReportView{
		Coverage:       observationCoverageLabel(result.Runner.ResourceUsage),
		Enforcement:    enforcement,
		ObservedFields: observedFields,
		SandboxPeakMemory: observedMetric(
			result.Resources.SandboxPeakMemoryBytes,
			domain.ResourceObservedSandboxPeakMemoryBytes,
			result.Resources.ObservedFields,
			"bytes",
		),
		SandboxCPUTime: observedMetric(
			result.Resources.SandboxCPUTimeMillis,
			domain.ResourceObservedSandboxCPUTimeMillis,
			result.Resources.ObservedFields,
			"ms",
		),
		Duration: fmt.Sprintf(
			"%d ms",
			maxInt64(result.Resources.DurationMillis, 0),
		),
		MaxTasks: observedCount(
			result.Resources.MaxTasks,
			domain.ResourceObservedMaxTasks,
			result.Resources.ObservedFields,
		),
		LogBytes: optionalMetric(result.Resources.LogBytes, "bytes"),
		WritableBytes: observedMetric(
			result.Resources.WritableBytes,
			domain.ResourceObservedWritableBytes,
			result.Resources.ObservedFields,
			"bytes",
		),
		OutputBytes: observedMetric(
			result.Resources.OutputBytes,
			domain.ResourceObservedOutputBytes,
			result.Resources.ObservedFields,
			"bytes",
		),
	}
}

func observationCoverageLabel(value string) string {
	switch value {
	case "full", "high", "best-effort", "unavailable":
		return strings.ToUpper(value)
	default:
		return "UNAVAILABLE"
	}
}

func optionalMetric(value int64, unit string) string {
	if value <= 0 {
		return "not reported"
	}
	return fmt.Sprintf("%d %s", value, unit)
}

func observedMetric(
	value int64,
	field domain.ResourceObservedField,
	observed []domain.ResourceObservedField,
	unit string,
) string {
	if !containsObservedField(observed, field) {
		return "not reported"
	}
	return fmt.Sprintf("%d %s", maxInt64(value, 0), unit)
}

func observedCount(
	value int,
	field domain.ResourceObservedField,
	observed []domain.ResourceObservedField,
) string {
	if !containsObservedField(observed, field) {
		return "not reported"
	}
	if value < 0 {
		value = 0
	}
	return fmt.Sprintf("%d", value)
}

func containsObservedField(
	values []domain.ResourceObservedField,
	wanted domain.ResourceObservedField,
) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func DecodeVerification(data []byte) (domain.VerificationResult, error) {
	var result domain.VerificationResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return domain.VerificationResult{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return domain.VerificationResult{}, fmt.Errorf("verification JSON contains trailing data")
	}
	for index, item := range result.Errors {
		if item == nil {
			err := domain.NewError(
				domain.CodeEvidenceDigestMismatch,
				domain.SeverityHigh,
				"Verification findings contain a null item.",
			)
			err.Details = map[string]any{"index": index}
			return domain.VerificationResult{}, err
		}
	}
	return result, nil
}

func nonNilErrors(values []*domain.Error) []*domain.Error {
	result := make([]*domain.Error, 0, len(values))
	for _, value := range values {
		if value != nil {
			result = append(result, value)
		}
	}
	return result
}
