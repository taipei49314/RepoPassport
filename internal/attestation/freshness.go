package attestation

import (
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/spdx"
)

const (
	FreshnessNotEvaluated = "not-evaluated"
	FreshnessCurrent      = "current"
	FreshnessStale        = "stale"
	FreshnessUnknown      = "unknown"

	FreshnessProfileLocalReobserveV1 = "local-reobserve-v1"
	FreshnessRunnerStableV1          = "runner-stable-v1"
)

const (
	FreshnessReasonNone                      = "none"
	FreshnessReasonSourceChanged             = "source-changed"
	FreshnessReasonPolicyChanged             = "policy-changed"
	FreshnessReasonPlanChanged               = "plan-changed"
	FreshnessReasonRunnerChanged             = "runner-changed"
	FreshnessReasonSourceUnavailable         = "source-unavailable"
	FreshnessReasonSourceUnstable            = "source-unstable"
	FreshnessReasonSourceIdentityUnavailable = "source-identity-unavailable"
	FreshnessReasonPlanUnavailable           = "plan-unavailable"
	FreshnessReasonRunnerUnavailable         = "runner-unavailable"
)

const (
	FreshnessStatusMatch        = "match"
	FreshnessStatusMismatch     = "mismatch"
	FreshnessStatusUnknown      = "unknown"
	FreshnessStatusNotEvaluated = "not-evaluated"
)

// AcceptedClaims is returned only after the bundle signature and the exact
// caller-provided SPKI trust key have both been accepted.
type AcceptedClaims struct {
	Source  domain.PlanSource      `json:"source"`
	Plan    PredicatePlan          `json:"plan"`
	Runner  domain.RunnerFeatures  `json:"runner"`
	Derived *AcceptedDerivedClaims `json:"derived,omitempty"`
}

type AcceptedDerivedClaims struct {
	Provenance spdx.DerivedProvenance `json:"provenance"`
	SBOMDigest string                 `json:"sbomDigest"`
}

type FreshnessCheck struct {
	Dimension        string `json:"dimension"`
	Status           string `json:"status"`
	HistoricalDigest string `json:"historicalDigest,omitempty"`
	CurrentDigest    string `json:"currentDigest,omitempty"`
}

type FreshnessReport struct {
	Profile       string           `json:"profile"`
	RunnerProfile string           `json:"runnerProfile"`
	Reason        string           `json:"reason"`
	Checks        []FreshnessCheck `json:"checks"`
}

// CurrentFreshnessObservation is a pure evaluator input. A nil value means
// that the corresponding observation was not completed reliably.
type CurrentFreshnessObservation struct {
	Source             *domain.PlanSource
	PolicyBundleDigest *string
	PlanDigest         *string
	Runner             *domain.RunnerFeatures
	UnavailableReason  string
}

type RunnerStableProjection struct {
	Backend       string `json:"backend"`
	ControllerOS  string `json:"controllerOS"`
	WorkloadOS    string `json:"workloadOS"`
	Rootless      string `json:"rootless"`
	EngineVersion string `json:"engineVersion"`
}

// RunnerStableDigest returns the canonical runner-stable-v1 projection
// digest. The boolean is false for a profile that cannot be compared safely.
func RunnerStableDigest(features domain.RunnerFeatures) (string, bool) {
	if !features.Available ||
		(features.Backend != "docker" && features.Backend != "podman") ||
		features.ControllerOS == "" ||
		features.WorkloadOS != "linux" ||
		(features.Rootless != "yes" && features.Rootless != "no") ||
		features.EngineVersion == "" {
		return "", false
	}
	digest, err := canonicaljson.Digest(RunnerStableProjection{
		Backend:       features.Backend,
		ControllerOS:  features.ControllerOS,
		WorkloadOS:    features.WorkloadOS,
		Rootless:      features.Rootless,
		EngineVersion: features.EngineVersion,
	})
	return digest, err == nil
}

// EvaluateFreshness compares only the bounded local-reobserve-v1 dimensions.
// It never mutates or re-aggregates the signed historical results.
func EvaluateFreshness(historical AcceptedClaims, current CurrentFreshnessObservation) (string, FreshnessReport) {
	report := newFreshnessReport(historical)

	if isSourceUnavailableReason(current.UnavailableReason) {
		setCheckStatus(&report, "source", FreshnessStatusUnknown, "")
		report.Reason = current.UnavailableReason
		return FreshnessUnknown, report
	}
	if !supportedLocalSource(historical.Source) {
		setCheckStatus(&report, "source", FreshnessStatusUnknown, "")
		report.Reason = FreshnessReasonSourceIdentityUnavailable
		return FreshnessUnknown, report
	}
	if current.Source == nil {
		setCheckStatus(&report, "source", FreshnessStatusUnknown, "")
		report.Reason = FreshnessReasonSourceUnavailable
		return FreshnessUnknown, report
	}
	currentSourceDigest, _ := canonicaljson.Digest(*current.Source)
	if !supportedLocalSource(*current.Source) {
		setCheckStatus(&report, "source", FreshnessStatusUnknown, currentSourceDigest)
		report.Reason = FreshnessReasonSourceIdentityUnavailable
		return FreshnessUnknown, report
	}
	if historical.Source != *current.Source {
		setCheckStatus(&report, "source", FreshnessStatusMismatch, currentSourceDigest)
		report.Reason = FreshnessReasonSourceChanged
		return FreshnessStale, report
	}
	setCheckStatus(&report, "source", FreshnessStatusMatch, currentSourceDigest)

	if current.UnavailableReason == FreshnessReasonPlanUnavailable ||
		current.PolicyBundleDigest == nil || current.PlanDigest == nil {
		setCheckStatus(&report, "policy", FreshnessStatusUnknown, "")
		setCheckStatus(&report, "plan", FreshnessStatusUnknown, "")
		report.Reason = FreshnessReasonPlanUnavailable
		return FreshnessUnknown, report
	}
	if historical.Plan.PolicyBundleDigest != *current.PolicyBundleDigest {
		setCheckStatus(&report, "policy", FreshnessStatusMismatch, *current.PolicyBundleDigest)
		report.Reason = FreshnessReasonPolicyChanged
		return FreshnessStale, report
	}
	setCheckStatus(&report, "policy", FreshnessStatusMatch, *current.PolicyBundleDigest)
	if historical.Plan.PlanDigest != *current.PlanDigest {
		setCheckStatus(&report, "plan", FreshnessStatusMismatch, *current.PlanDigest)
		report.Reason = FreshnessReasonPlanChanged
		return FreshnessStale, report
	}
	setCheckStatus(&report, "plan", FreshnessStatusMatch, *current.PlanDigest)

	if current.UnavailableReason == FreshnessReasonRunnerUnavailable || current.Runner == nil {
		setCheckStatus(&report, "runner", FreshnessStatusUnknown, "")
		report.Reason = FreshnessReasonRunnerUnavailable
		return FreshnessUnknown, report
	}
	historicalRunnerDigest, historicalOK := RunnerStableDigest(historical.Runner)
	currentRunnerDigest, currentOK := RunnerStableDigest(*current.Runner)
	if !historicalOK || !currentOK {
		currentDigest := ""
		if currentOK {
			currentDigest = currentRunnerDigest
		}
		setCheckStatus(&report, "runner", FreshnessStatusUnknown, currentDigest)
		report.Reason = FreshnessReasonRunnerUnavailable
		return FreshnessUnknown, report
	}
	if historicalRunnerDigest != currentRunnerDigest {
		setCheckStatus(&report, "runner", FreshnessStatusMismatch, currentRunnerDigest)
		report.Reason = FreshnessReasonRunnerChanged
		return FreshnessStale, report
	}
	setCheckStatus(&report, "runner", FreshnessStatusMatch, currentRunnerDigest)
	return FreshnessCurrent, report
}

func newFreshnessReport(historical AcceptedClaims) FreshnessReport {
	sourceDigest, _ := canonicaljson.Digest(historical.Source)
	runnerDigest, _ := RunnerStableDigest(historical.Runner)
	return FreshnessReport{
		Profile:       FreshnessProfileLocalReobserveV1,
		RunnerProfile: FreshnessRunnerStableV1,
		Reason:        FreshnessReasonNone,
		Checks: []FreshnessCheck{
			{Dimension: "source", Status: FreshnessStatusNotEvaluated, HistoricalDigest: sourceDigest},
			{Dimension: "policy", Status: FreshnessStatusNotEvaluated, HistoricalDigest: historical.Plan.PolicyBundleDigest},
			{Dimension: "plan", Status: FreshnessStatusNotEvaluated, HistoricalDigest: historical.Plan.PlanDigest},
			{Dimension: "runner", Status: FreshnessStatusNotEvaluated, HistoricalDigest: runnerDigest},
		},
	}
}

func setCheckStatus(report *FreshnessReport, dimension, status, currentDigest string) {
	for index := range report.Checks {
		if report.Checks[index].Dimension == dimension {
			report.Checks[index].Status = status
			report.Checks[index].CurrentDigest = currentDigest
			return
		}
	}
}

func supportedLocalSource(source domain.PlanSource) bool {
	return source.Commit == "" && source.TreeDigest != "" && source.Identity == source.TreeDigest
}

func isSourceUnavailableReason(reason string) bool {
	return reason == FreshnessReasonSourceUnavailable ||
		reason == FreshnessReasonSourceUnstable ||
		reason == FreshnessReasonSourceIdentityUnavailable
}
