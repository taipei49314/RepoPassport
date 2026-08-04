package attestation

import "github.com/repopass/repopass/internal/spdx"

const (
	SBOMCurrentnessProfile      = "npm-package-lock-currentness-v1"
	SBOMCurrentnessNotEvaluated = "not-evaluated"
	SBOMCurrentnessFresh        = "fresh"
	SBOMCurrentnessStale        = "stale"
	SBOMCurrentnessUnknown      = "unknown"

	SBOMCurrentnessReasonNone              = "none"
	SBOMCurrentnessReasonInputsChanged     = "derivation-inputs-changed"
	SBOMCurrentnessReasonSBOMChanged       = "canonical-sbom-changed"
	SBOMCurrentnessReasonSourceUnavailable = "source-unavailable"
	SBOMCurrentnessReasonSourceUnstable    = "source-unstable"
	SBOMCurrentnessReasonUnsupported       = "unsupported-inputs"
	SBOMCurrentnessReasonDerivationFailed  = "derivation-failed"
	SBOMCurrentnessReasonPrivacyBlocked    = "privacy-blocked"
	SBOMCurrentnessReasonUnknownRuleset    = "unknown-ruleset"
)

type SBOMCurrentnessCheck struct {
	Dimension        string `json:"dimension"`
	Status           string `json:"status"`
	HistoricalDigest string `json:"historicalDigest"`
	CurrentDigest    string `json:"currentDigest,omitempty"`
}

type SBOMCurrentnessReport struct {
	Profile string                 `json:"profile"`
	Status  string                 `json:"status"`
	Reason  string                 `json:"reason"`
	Checks  []SBOMCurrentnessCheck `json:"checks"`
}

func EvaluateSBOMCurrentness(
	historical AcceptedDerivedClaims,
	current *spdx.DerivedArtifact,
	unavailableReason string,
) (string, SBOMCurrentnessReport) {
	report := SBOMCurrentnessReport{
		Profile: SBOMCurrentnessProfile, Status: SBOMCurrentnessUnknown,
		Reason: normalizeSBOMCurrentnessReason(unavailableReason),
		Checks: []SBOMCurrentnessCheck{
			{Dimension: "derivation-inputs", Status: FreshnessStatusNotEvaluated, HistoricalDigest: historical.Provenance.DerivationInputDigest},
			{Dimension: "canonical-sbom", Status: FreshnessStatusNotEvaluated, HistoricalDigest: historical.SBOMDigest},
		},
	}
	if historical.Provenance.RulesetDigest != spdx.DerivedRulesetDigest {
		report.Reason = SBOMCurrentnessReasonUnknownRuleset
		return SBOMCurrentnessUnknown, report
	}
	if current == nil {
		if report.Reason == "" {
			report.Reason = SBOMCurrentnessReasonSourceUnavailable
		}
		return SBOMCurrentnessUnknown, report
	}
	if current.Provenance.RulesetDigest != historical.Provenance.RulesetDigest {
		report.Reason = SBOMCurrentnessReasonUnknownRuleset
		return SBOMCurrentnessUnknown, report
	}
	report.Checks[0].CurrentDigest = current.Provenance.DerivationInputDigest
	if current.Provenance.DerivationInputDigest != historical.Provenance.DerivationInputDigest {
		report.Checks[0].Status = FreshnessStatusMismatch
		report.Status = SBOMCurrentnessStale
		report.Reason = SBOMCurrentnessReasonInputsChanged
		return SBOMCurrentnessStale, report
	}
	report.Checks[0].Status = FreshnessStatusMatch
	currentSBOMDigest := spdx.Digest(current.SPDX)
	report.Checks[1].CurrentDigest = currentSBOMDigest
	if currentSBOMDigest != historical.SBOMDigest {
		report.Checks[1].Status = FreshnessStatusMismatch
		report.Status = SBOMCurrentnessStale
		report.Reason = SBOMCurrentnessReasonSBOMChanged
		return SBOMCurrentnessStale, report
	}
	report.Checks[1].Status = FreshnessStatusMatch
	report.Status = SBOMCurrentnessFresh
	report.Reason = SBOMCurrentnessReasonNone
	return SBOMCurrentnessFresh, report
}

func normalizeSBOMCurrentnessReason(reason string) string {
	switch reason {
	case "":
		return ""
	case SBOMCurrentnessReasonSourceUnavailable,
		SBOMCurrentnessReasonSourceUnstable,
		SBOMCurrentnessReasonUnsupported,
		SBOMCurrentnessReasonDerivationFailed,
		SBOMCurrentnessReasonPrivacyBlocked,
		SBOMCurrentnessReasonUnknownRuleset:
		return reason
	default:
		return SBOMCurrentnessReasonDerivationFailed
	}
}
