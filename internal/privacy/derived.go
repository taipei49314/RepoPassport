package privacy

import (
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/spdx"
)

const (
	DerivedProjectionProfile        = "minimal-public-derived-projection-v1"
	DerivedProjectionPolicy         = "minimal-public-derived-projection-v1"
	DerivedProjectionRulesetDigest  = "sha256:2843165f0a7c5ebf01a534b05a0a691ec400054f6667a1d0a177c8f549387db7"
	DerivedBasePrivacyRulesetDigest = "sha256:b77ef257f122a975bb033637dfcc1aab3872ab894cd73066565141e7de773db4"
)

const derivedProjectionDescriptor = `{"basePrivacyRulesetDigest":"sha256:b77ef257f122a975bb033637dfcc1aab3872ab894cd73066565141e7de773db4","profile":"minimal-public-derived-projection-v1","repositoryStrings":["package.name","package.versionInfo"],"structuralFieldsExcluded":["derivation-digests","fixed-enumerations","fixed-relative-paths","ids","namespace","sizes"],"validatedLockChecksumExcluded":{"field":"package.checksums","registryArtifactVerified":false,"repositoryControlledPossible":true,"source":"repository-package-lock-integrity","validation":"sha512-shape-only"},"version":"1"}`

type DerivedEvaluation struct {
	PrivacyProfile       string `json:"privacyProfile"`
	PrivacyPolicy        string `json:"privacyPolicy"`
	PrivacyRulesetDigest string `json:"privacyRulesetDigest"`
	PrivacyEvaluation    string `json:"privacyEvaluation"`
}

type derivedProjection struct {
	Profile  string                     `json:"profile"`
	Packages []derivedPackageProjection `json:"packages"`
}

type derivedPackageProjection struct {
	Name        string `json:"name"`
	VersionInfo string `json:"versionInfo"`
}

// EvaluateDerivedPair first validates the complete canonical derived payload
// pair. It then scans only the repository-controlled public strings using the
// frozen minimal-public scanner. Structural IDs, namespaces, digests, fixed
// relative paths, sizes, and enumerations are excluded by the named
// projection. Package checksums are also excluded, but they are only
// strict-shaped SHA-512 values copied from the repository lockfile: they may
// be repository-controlled and do not prove any registry artifact.
func EvaluateDerivedPair(spdxRaw, provenanceRaw []byte) (DerivedEvaluation, error) {
	document, _, err := spdx.ValidateDerivedPair(spdxRaw, provenanceRaw)
	if err != nil {
		return DerivedEvaluation{}, err
	}
	projection := derivedProjection{
		Profile:  DerivedProjectionProfile,
		Packages: make([]derivedPackageProjection, 0, len(document.Packages)),
	}
	for _, item := range document.Packages {
		projection.Packages = append(projection.Packages, derivedPackageProjection{
			Name: item.Name, VersionInfo: item.VersionInfo,
		})
	}
	canonical, err := canonicaljson.Marshal(projection)
	if err != nil {
		return DerivedEvaluation{}, err
	}
	evaluation, err := Evaluate(canonical)
	if err != nil {
		return DerivedEvaluation{}, err
	}
	if err := validateDerivedBaseEvaluation(evaluation); err != nil {
		return DerivedEvaluation{}, err
	}
	return DerivedEvaluation{
		PrivacyProfile: DerivedProjectionProfile, PrivacyPolicy: DerivedProjectionPolicy,
		PrivacyRulesetDigest: DerivedProjectionRulesetDigest,
		PrivacyEvaluation:    evaluation.PrivacyEvaluation,
	}, nil
}

func validateDerivedBaseEvaluation(evaluation Evaluation) error {
	if evaluation.PrivacyProfile == Profile &&
		evaluation.PrivacyPolicy == Policy &&
		evaluation.PrivacyRulesetDigest == DerivedBasePrivacyRulesetDigest &&
		evaluation.PrivacyEvaluation == EvaluationPassed {
		return nil
	}
	err := domain.NewError(
		domain.CodeEvidencePrivacyBlocked,
		domain.SeverityHigh,
		"The derived SPDX privacy projection does not match its frozen base policy.",
	)
	err.Details = map[string]any{
		"privacyProfile":       DerivedProjectionProfile,
		"privacyPolicy":        DerivedProjectionPolicy,
		"privacyRulesetDigest": DerivedProjectionRulesetDigest,
		"privacyEvaluation":    "blocked",
	}
	return err
}

func DerivedProjectionDescriptor() string { return derivedProjectionDescriptor }

func init() {
	if DerivedBasePrivacyRulesetDigest != RulesetDigest {
		panic("derived privacy projection base ruleset digest mismatch")
	}
	if spdx.Digest([]byte(derivedProjectionDescriptor)) != DerivedProjectionRulesetDigest {
		panic("derived privacy projection descriptor digest mismatch")
	}
}
