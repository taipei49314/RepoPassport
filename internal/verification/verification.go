package verification

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

type Input struct {
	RunID            string
	VerificationID   string
	Plan             domain.ResolvedPlan
	Runner           domain.RunnerFeatures
	StartedAt        time.Time
	CompletedAt      time.Time
	Observations     []domain.ObservationEvent
	Assertions       []domain.AssertionResult
	Errors           []*domain.Error
	Requested        int
	Completed        int
	Matching         int
	SuccessThreshold int
	Cleanup          domain.CleanupVerdict
	Resources        domain.ResourceSummary
}

func Build(input Input) (domain.VerificationResult, error) {
	if input.RunID == "" {
		input.RunID = newOpaqueID("run")
	}
	if input.VerificationID == "" {
		input.VerificationID = newOpaqueID("vrf")
	}
	if input.StartedAt.IsZero() {
		input.StartedAt = time.Now().UTC()
	}
	if input.CompletedAt.IsZero() {
		input.CompletedAt = time.Now().UTC()
	}
	if input.Requested <= 0 {
		input.Requested = 1
	}
	if input.SuccessThreshold <= 0 || input.SuccessThreshold > input.Requested {
		input.SuccessThreshold = input.Requested
	}
	if input.Plan.RepeatCount <= 0 {
		input.Plan.RepeatCount = input.Requested
	}
	if input.Plan.SuccessThreshold <= 0 || input.Plan.SuccessThreshold > input.Plan.RepeatCount {
		input.Plan.SuccessThreshold = input.SuccessThreshold
	}
	input.Runner = normalizeRunner(input.Runner)
	if index := nilErrorIndex(input.Errors); index >= 0 {
		err := domain.NewError(
			domain.CodeObservationSchemaInvalid,
			domain.SeverityHigh,
			"Verification findings contain a null item.",
		)
		err.Details = map[string]any{"index": index}
		return domain.VerificationResult{}, err
	}
	coverage, coverageComplete := coverageFor(input.Plan.ObserverSet, input.Runner)
	functional := functionalVerdict(input)
	capability := capabilityVerdict(input.Errors, coverageComplete)
	observedCleanup, cleanupEvidenceErr := cleanupVerdictFromObservations(
		input.Observations,
		input.Completed,
	)
	if cleanupEvidenceErr != nil {
		return domain.VerificationResult{}, domain.WrapError(
			domain.CodeObservationSchemaInvalid,
			domain.SeverityHigh,
			"Cleanup observations do not satisfy the authoritative evidence contract.",
			cleanupEvidenceErr,
		)
	}
	cleanup := cleanupVerdict(
		observedCleanup,
		input.Completed,
		input.Errors,
	)
	if input.Cleanup != cleanup {
		err := domain.NewError(
			domain.CodeObservationSchemaInvalid,
			domain.SeverityHigh,
			"Caller cleanup verdict does not match cleanup observations and findings.",
		)
		err.Details = map[string]any{
			"caller":   input.Cleanup,
			"observed": cleanup,
		}
		return domain.VerificationResult{}, err
	}
	if err := validatePortListenerEvidence(
		observerRequired(input.Plan.ObserverSet, "port-listen"),
		input.Completed,
		input.Observations,
		input.Errors,
	); err != nil {
		return domain.VerificationResult{}, domain.WrapError(
			domain.CodeObservationSchemaInvalid,
			domain.SeverityHigh,
			"Peer TCP listener evidence does not satisfy the authoritative public contract.",
			err,
		)
	}
	reproducibility := reproducibilityVerdict(
		input.Requested,
		input.Completed,
		input.Matching,
		input.SuccessThreshold,
	)
	policy := baselinePolicy(input.Plan, input.Runner, coverageComplete)
	verdicts := domain.Verdicts{
		Functional:      functional,
		Capability:      capability,
		Reproducibility: reproducibility,
		Cleanup:         cleanup,
		Evidence:        domain.EvidenceUnsigned,
		Freshness:       domain.FreshnessCurrent,
	}
	verdicts.Overall = aggregate(verdicts)
	result := domain.VerificationResult{
		SchemaVersion:  "1",
		VerificationID: input.VerificationID,
		RunID:          input.RunID,
		StartedAt:      input.StartedAt.UTC(),
		CompletedAt:    input.CompletedAt.UTC(),
		Subject:        input.Plan.Source,
		Plan: domain.VerificationPlanRef{
			Scenario: input.Plan.Scenario, Environment: input.Plan.Environment,
			PlanDigest: input.Plan.PlanDigest, PolicyBundleDigest: input.Plan.PolicyBundleDigest,
			RepeatCount: input.Plan.RepeatCount, SuccessThreshold: input.Plan.SuccessThreshold,
			ResolvedPlanSchemaVersion: input.Plan.SchemaVersion,
			Evidence: domain.PlanEvidence{
				Profile: input.Plan.Evidence.Profile,
				Include: append([]string{}, input.Plan.Evidence.Include...),
				Exclude: append([]string{}, input.Plan.Evidence.Exclude...),
			},
		},
		Runner:           input.Runner,
		Results:          verdicts,
		ObserverCoverage: coverage,
		Observations:     nonNilObservations(input.Observations),
		Assertions:       nonNilAssertions(input.Assertions),
		PolicyDecisions:  policy,
		Errors:           input.Errors,
		Repeats: domain.RepeatSummary{
			Requested: input.Requested, Completed: input.Completed, Matching: input.Matching,
		},
		Resources: input.Resources,
	}
	if result.Resources.DurationMillis == 0 {
		result.Resources.DurationMillis = input.CompletedAt.Sub(input.StartedAt).Milliseconds()
	}
	if field := invalidResourceSummaryField(result.Resources); field != "" {
		err := domain.NewError(
			domain.CodeObservationSchemaInvalid,
			domain.SeverityHigh,
			"Resource usage evidence does not match the bounded contract.",
		)
		err.Details = map[string]any{"field": field}
		return domain.VerificationResult{}, err
	}
	var err error
	result.Digests.Observations, err = canonicaljson.Digest(result.Observations)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	result.Digests.Assertions, err = canonicaljson.Digest(result.Assertions)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	result.Digests.PolicyDecisions, err = canonicaljson.Digest(result.PolicyDecisions)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	result.Digests.Verification, err = verificationDigest(result)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	return result, nil
}

func aggregate(result domain.Verdicts) domain.OverallVerdict {
	if result.Evidence == domain.EvidenceTampered || result.Evidence == domain.EvidenceUntrustedSigner {
		return domain.OverallNonconforming
	}
	if result.Freshness != domain.FreshnessCurrent {
		return domain.OverallStale
	}
	if result.Functional == domain.FunctionalBlocked {
		return domain.OverallBlocked
	}
	if result.Functional == domain.FunctionalInconclusive {
		return domain.OverallInconclusive
	}
	if result.Functional == domain.FunctionalFail {
		return domain.OverallFailed
	}
	if result.Capability == domain.CapabilityNonconforming || result.Cleanup == domain.CleanupUndeclaredResidue {
		return domain.OverallNonconforming
	}
	if result.Capability == domain.CapabilityIncomplete ||
		result.Cleanup == domain.CleanupNotTested ||
		result.Reproducibility == domain.ReproducibilityFlaky ||
		result.Reproducibility == domain.ReproducibilityNotReproducible {
		return domain.OverallInconclusive
	}
	if result.Functional == domain.FunctionalPass &&
		(result.Capability == domain.CapabilityConforming || result.Capability == domain.CapabilityWarning) &&
		(result.Cleanup == domain.CleanupClean || result.Cleanup == domain.CleanupAllowedResidue) {
		if result.Capability == domain.CapabilityWarning ||
			result.Reproducibility == domain.ReproducibilityNotTested ||
			result.Evidence == domain.EvidenceNone ||
			result.Evidence == domain.EvidenceUnsigned ||
			result.Evidence == domain.EvidenceSelfSigned ||
			result.Cleanup == domain.CleanupAllowedResidue {
			return domain.OverallVerifiedWithWarnings
		}
		return domain.OverallVerified
	}
	return domain.OverallInconclusive
}

func functionalVerdict(input Input) domain.FunctionalVerdict {
	for _, item := range input.Errors {
		if item == nil {
			continue
		}
		switch item.Code {
		case domain.CodeRunnerUnavailable, domain.CodeRunnerFeatureUnavailable,
			domain.CodeSandboxPrepareFailed, domain.CodeMutableBaseImage,
			domain.CodeRuntimeVersionUnresolved:
			return domain.FunctionalBlocked
		}
	}
	for _, item := range input.Errors {
		if item == nil {
			continue
		}
		switch item.Code {
		case domain.CodeJourneyAssertionFailed, domain.CodeSetupFailed,
			domain.CodeBuildFailed, domain.CodeServiceStartFailed,
			domain.CodeReadinessFailed:
			return domain.FunctionalFail
		}
	}
	for _, assertion := range input.Assertions {
		switch assertion.Status {
		case "fail", "failed":
			return domain.FunctionalFail
		case "blocked":
			return domain.FunctionalBlocked
		case "inconclusive":
			return domain.FunctionalInconclusive
		}
	}
	for _, item := range input.Errors {
		switch item.Code {
		case domain.CodeTimeout, domain.CodeObserverIncomplete,
			domain.CodeObservationSchemaInvalid, domain.CodeNondeterministicResult,
			domain.CodeSourceDigestMismatch:
			return domain.FunctionalInconclusive
		}
	}
	if input.Completed == 0 || len(input.Assertions) == 0 {
		return domain.FunctionalInconclusive
	}
	for _, assertion := range input.Assertions {
		if assertion.Status != "pass" && assertion.Status != "passed" {
			return domain.FunctionalInconclusive
		}
	}
	return domain.FunctionalPass
}

func capabilityVerdict(errs []*domain.Error, coverageComplete bool) domain.CapabilityVerdict {
	for _, item := range errs {
		if item == nil {
			continue
		}
		switch item.Code {
		case domain.CodeUndeclaredFilesystemWrite, domain.CodeForbiddenFilesystemAccess,
			domain.CodeUndeclaredNetwork, domain.CodeForbiddenNetworkAttempt,
			domain.CodeUndeclaredPortListen, domain.CodeUndeclaredProcessExec:
			return domain.CapabilityNonconforming
		}
	}
	if !coverageComplete {
		return domain.CapabilityIncomplete
	}
	return domain.CapabilityConforming
}

func cleanupVerdict(
	declared domain.CleanupVerdict,
	completed int,
	errs []*domain.Error,
) domain.CleanupVerdict {
	if completed == 0 {
		return domain.CleanupNotTested
	}
	switch declared {
	case domain.CleanupClean, domain.CleanupAllowedResidue,
		domain.CleanupUndeclaredResidue, domain.CleanupNotTested:
	default:
		declared = domain.CleanupNotTested
	}
	undeclared := declared == domain.CleanupUndeclaredResidue
	technicalFailure := false
	for _, item := range errs {
		if item == nil {
			continue
		}
		switch item.Code {
		case domain.CodeCleanupResidue, domain.CodeProcessLeak:
			undeclared = true
		case domain.CodeCleanupFailed, domain.CodeSandboxDestroyFailed:
			technicalFailure = true
		}
	}
	if undeclared {
		return domain.CleanupUndeclaredResidue
	}
	if technicalFailure {
		return domain.CleanupNotTested
	}
	return declared
}

const (
	cleanupObservationOperation  = "cleanup.residue.summary"
	cleanupObservationObserver   = "controller-cleanup-residue-classifier"
	cleanupObservationResource   = "/outputs"
	cleanupObservationBoundary   = "post-quiescence-post-final-observers-post-disposable-pre-repair-pre-export-pre-destroy"
	cleanupObservationClassifier = "0.1.0"
)

type cleanupObservationDetails struct {
	AllowedPatternCount       int    `json:"allowedPatternCount"`
	AllowedProfile            string `json:"allowedProfile"`
	Boundary                  string `json:"boundary"`
	ClassifierVersion         string `json:"classifierVersion"`
	DirectoryCount            int    `json:"directoryCount"`
	DisposableCleanupVerified bool   `json:"disposableCleanupVerified"`
	EntryCount                int    `json:"entryCount"`
	IdentityVerified          bool   `json:"identityVerified"`
	InventoryComplete         bool   `json:"inventoryComplete"`
	MaxControlBytes           int    `json:"maxControlBytes"`
	MaxDepth                  int    `json:"maxDepth"`
	MaxEntries                int    `json:"maxEntries"`
	MaxPathBytes              int    `json:"maxPathBytes"`
	OpaqueInventoryToken      string `json:"opaqueInventoryToken,omitempty"`
	QuiescenceConfirmed       bool   `json:"quiescenceConfirmed"`
	RegularFileCount          int    `json:"regularFileCount"`
	Scope                     string `json:"scope"`
	SpecialCount              int    `json:"specialCount"`
	SymlinkCount              int    `json:"symlinkCount"`
	TokenScheme               string `json:"tokenScheme,omitempty"`
	UnmatchedCount            int    `json:"unmatchedCount"`
	Verdict                   string `json:"verdict"`
	Failure                   string `json:"failure,omitempty"`
}

func cleanupVerdictFromObservations(
	observations []domain.ObservationEvent,
	completed int,
) (domain.CleanupVerdict, error) {
	if completed < 0 {
		return "", fmt.Errorf("completed repeat count is negative")
	}
	declared := domain.CleanupClean
	found := 0
	for _, observation := range observations {
		if observation.Operation != cleanupObservationOperation {
			continue
		}
		found++
		verdict, err := cleanupVerdictFromObservation(observation)
		if err != nil {
			return "", fmt.Errorf(
				"cleanup observation %d: %w",
				found,
				err,
			)
		}
		declared = aggregateCleanupVerdict(declared, verdict)
	}
	if found != completed {
		return "", fmt.Errorf(
			"cleanup observation count %d does not match completed repeat count %d",
			found,
			completed,
		)
	}
	if completed == 0 {
		return domain.CleanupNotTested, nil
	}
	return declared, nil
}

func cleanupVerdictFromObservation(
	observation domain.ObservationEvent,
) (domain.CleanupVerdict, error) {
	if observation.SchemaVersion != "1" ||
		observation.Phase != domain.PhaseCleanup ||
		observation.Actor != "trusted-runner" ||
		observation.Operation != cleanupObservationOperation ||
		observation.Resource != cleanupObservationResource ||
		observation.Observer != cleanupObservationObserver {
		return "", fmt.Errorf("cleanup observation identity is not exact")
	}
	if observation.Timestamp.IsZero() {
		return "", fmt.Errorf("cleanup observation timestamp is absent")
	}
	raw, err := json.Marshal(observation.Details)
	if err != nil {
		return "", fmt.Errorf("cleanup observation details: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", fmt.Errorf("cleanup observation details: %w", err)
	}
	for _, field := range []string{
		"allowedPatternCount",
		"allowedProfile",
		"boundary",
		"classifierVersion",
		"directoryCount",
		"disposableCleanupVerified",
		"entryCount",
		"identityVerified",
		"inventoryComplete",
		"maxControlBytes",
		"maxDepth",
		"maxEntries",
		"maxPathBytes",
		"quiescenceConfirmed",
		"regularFileCount",
		"scope",
		"specialCount",
		"symlinkCount",
		"unmatchedCount",
		"verdict",
	} {
		if _, ok := fields[field]; !ok {
			return "", fmt.Errorf("cleanup observation detail %q is absent", field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var details cleanupObservationDetails
	if err := decoder.Decode(&details); err != nil {
		return "", fmt.Errorf("cleanup observation details are not exact: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return "", fmt.Errorf("cleanup observation details contain trailing data")
	}
	verdict := domain.CleanupVerdict(details.Verdict)
	switch verdict {
	case domain.CleanupClean,
		domain.CleanupAllowedResidue,
		domain.CleanupUndeclaredResidue,
		domain.CleanupNotTested:
	default:
		return "", fmt.Errorf("cleanup observation verdict is unsupported")
	}
	if details.ClassifierVersion != cleanupObservationClassifier ||
		details.Boundary != cleanupObservationBoundary ||
		details.Scope != cleanupObservationResource ||
		details.MaxControlBytes != 512<<10 ||
		details.MaxDepth != 64 ||
		details.MaxEntries != 2048 ||
		details.MaxPathBytes != 1024 {
		return "", fmt.Errorf("cleanup observation classifier boundary is not exact")
	}
	if details.AllowedPatternCount < 0 ||
		details.AllowedPatternCount > 1 ||
		details.AllowedPatternCount == 0 &&
			details.AllowedProfile != "none" ||
		details.AllowedPatternCount == 1 &&
			details.AllowedProfile != "outputs-descendants" {
		return "", fmt.Errorf("cleanup observation allowed-residue profile is invalid")
	}
	counts := []int{
		details.EntryCount,
		details.DirectoryCount,
		details.RegularFileCount,
		details.SpecialCount,
		details.SymlinkCount,
		details.UnmatchedCount,
	}
	for _, count := range counts {
		if count < 0 {
			return "", fmt.Errorf("cleanup observation count is negative")
		}
	}
	if details.EntryCount != details.DirectoryCount+
		details.RegularFileCount+
		details.SpecialCount+
		details.SymlinkCount ||
		details.UnmatchedCount > details.EntryCount ||
		details.EntryCount > details.MaxEntries {
		return "", fmt.Errorf("cleanup observation counts are inconsistent")
	}
	expectedUnmatched := details.EntryCount
	if details.AllowedPatternCount == 1 {
		expectedUnmatched = details.SpecialCount + details.SymlinkCount
	}
	if details.UnmatchedCount != expectedUnmatched {
		return "", fmt.Errorf("cleanup observation unmatched count conflicts with allowed profile")
	}
	if !details.InventoryComplete &&
		(details.EntryCount != 0 ||
			details.DirectoryCount != 0 ||
			details.RegularFileCount != 0 ||
			details.SpecialCount != 0 ||
			details.SymlinkCount != 0 ||
			details.UnmatchedCount != 0 ||
			details.OpaqueInventoryToken != "" ||
			details.TokenScheme != "") {
		return "", fmt.Errorf("incomplete cleanup inventory exposes impossible aggregate data")
	}
	expectedResult := "succeeded"
	expectedCoverage := "enforcement-only"
	expectedConfidence := "high"
	if verdict == domain.CleanupNotTested {
		expectedResult = "failed"
		expectedCoverage = "unavailable"
		expectedConfidence = "unknown"
		if err := validateNotTestedCleanupDetails(details); err != nil {
			return "", err
		}
	} else {
		if details.Failure != "" ||
			!details.InventoryComplete ||
			!details.QuiescenceConfirmed ||
			!details.DisposableCleanupVerified ||
			!details.IdentityVerified {
			return "", fmt.Errorf("decisive cleanup observation lacks trusted boundary flags")
		}
	}
	if observation.Result != expectedResult ||
		observation.Coverage != expectedCoverage ||
		observation.Confidence != expectedConfidence {
		return "", fmt.Errorf("cleanup observation result metadata does not match verdict")
	}
	switch verdict {
	case domain.CleanupClean:
		if details.EntryCount != 0 || details.UnmatchedCount != 0 {
			return "", fmt.Errorf("clean cleanup observation has residue")
		}
	case domain.CleanupAllowedResidue:
		if details.EntryCount == 0 ||
			details.UnmatchedCount != 0 ||
			details.AllowedPatternCount != 1 ||
			details.SymlinkCount != 0 ||
			details.SpecialCount != 0 {
			return "", fmt.Errorf("allowed-residue cleanup observation is inconsistent")
		}
	case domain.CleanupUndeclaredResidue:
		if details.EntryCount == 0 || details.UnmatchedCount == 0 {
			return "", fmt.Errorf("undeclared-residue cleanup observation is inconsistent")
		}
	}
	if details.OpaqueInventoryToken == "" {
		if details.TokenScheme != "" {
			return "", fmt.Errorf("cleanup observation token scheme has no token")
		}
	} else {
		if details.TokenScheme != "ephemeral-keyed-hmac-sha256" ||
			!validOpaqueCleanupToken(details.OpaqueInventoryToken) {
			return "", fmt.Errorf("cleanup observation token is invalid")
		}
	}
	if verdict != domain.CleanupNotTested &&
		details.OpaqueInventoryToken == "" {
		return "", fmt.Errorf("decisive cleanup observation has no opaque token")
	}
	return verdict, nil
}

func validateNotTestedCleanupDetails(
	details cleanupObservationDetails,
) error {
	if details.Failure == "" {
		return fmt.Errorf("not-tested cleanup observation has no failure class")
	}
	if !details.QuiescenceConfirmed &&
		(details.DisposableCleanupVerified ||
			details.IdentityVerified ||
			details.InventoryComplete) ||
		!details.DisposableCleanupVerified &&
			(details.IdentityVerified || details.InventoryComplete) ||
		!details.IdentityVerified && details.InventoryComplete {
		return fmt.Errorf("not-tested cleanup observation boundary flags are not monotonic")
	}
	stage := ""
	switch details.Failure {
	case "sandbox-boundary-unavailable",
		"inventory-not-attempted",
		"workload-quiescence-failed",
		"immutable-container-identity-unavailable":
		stage = "quiescence"
	case "disposable-removal-unavailable",
		"disposable-removal-failed":
		stage = "disposable"
	case "container-identity-readback-failed":
		stage = "identity"
	case "inventory-helper-unavailable",
		"control-limit",
		"dirty-stderr",
		"helper-failed",
		"invalid-control",
		"count-mismatch",
		"entry-limit",
		"invalid-entry",
		"unsorted-or-duplicate",
		"inventory-unavailable":
		stage = "inventory"
	case "invalid-plan-contract",
		"random-unavailable",
		"token-unavailable":
		stage = "classification"
	default:
		return fmt.Errorf("not-tested cleanup observation failure class is unsupported")
	}
	switch stage {
	case "quiescence":
		if details.QuiescenceConfirmed ||
			details.DisposableCleanupVerified ||
			details.IdentityVerified ||
			details.InventoryComplete {
			return fmt.Errorf("cleanup failure class conflicts with quiescence flags")
		}
	case "disposable":
		if !details.QuiescenceConfirmed ||
			details.DisposableCleanupVerified ||
			details.IdentityVerified ||
			details.InventoryComplete {
			return fmt.Errorf("cleanup failure class conflicts with disposable flags")
		}
	case "identity":
		if !details.QuiescenceConfirmed ||
			!details.DisposableCleanupVerified ||
			details.IdentityVerified ||
			details.InventoryComplete {
			return fmt.Errorf("cleanup failure class conflicts with identity flags")
		}
	case "inventory":
		if !details.QuiescenceConfirmed ||
			!details.DisposableCleanupVerified ||
			!details.IdentityVerified ||
			details.InventoryComplete {
			return fmt.Errorf("cleanup failure class conflicts with inventory flags")
		}
	case "classification":
		if !details.QuiescenceConfirmed ||
			!details.DisposableCleanupVerified ||
			!details.IdentityVerified ||
			!details.InventoryComplete {
			return fmt.Errorf("cleanup failure class conflicts with classification flags")
		}
	}
	return nil
}

func validOpaqueCleanupToken(value string) bool {
	const prefix = "hmac-sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(value, prefix)
	if len(encoded) != 64 {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func aggregateCleanupVerdict(
	left domain.CleanupVerdict,
	right domain.CleanupVerdict,
) domain.CleanupVerdict {
	rank := func(value domain.CleanupVerdict) int {
		switch value {
		case domain.CleanupUndeclaredResidue:
			return 4
		case domain.CleanupNotTested:
			return 3
		case domain.CleanupAllowedResidue:
			return 2
		case domain.CleanupClean:
			return 1
		default:
			return 0
		}
	}
	if rank(right) > rank(left) {
		return right
	}
	return left
}

func nilErrorIndex(values []*domain.Error) int {
	for index, value := range values {
		if value == nil {
			return index
		}
	}
	return -1
}

func reproducibilityVerdict(requested, completed, matching, threshold int) domain.ReproducibilityVerdict {
	if requested <= 1 || completed == 0 {
		return domain.ReproducibilityNotTested
	}
	if completed != requested {
		return domain.ReproducibilityNotReproducible
	}
	if matching == requested {
		return domain.ReproducibilityStable
	}
	if matching < threshold {
		return domain.ReproducibilityNotReproducible
	}
	return domain.ReproducibilityFlaky
}

var portListenerUntestedDetailKeys = []string{
	"observerPlacement", "sharesTargetPIDNamespace",
	"sharesTargetMountNamespace", "sharesTargetIPCNamespace",
	"sharesTargetCgroup", "processAttribution", "lifetimeSemantics",
	"kernelEventCoverage", "shortLivedListenerGap", "udpUnavailable",
	"publicEvidence", "evidenceBasis", "comparisonResult", "sampleLimit",
	"intervalMillis", "maxAllowedGapMillis", "identityVerified",
	"namespaceIsolationVerified", "workloadQuiescenceVerified",
	"peerRemoveVerified", "canonicalDigestSemantics",
}

var portListenerCompleteDetailKeys = append(
	append([]string{}, portListenerUntestedDetailKeys...),
	"observerAdapter", "declaredEndpointCount", "baselineEndpointCount",
	"sampledEndpointCount", "undeclaredEndpointCount", "sampleCount",
	"maxSampleGapMillis", "transitionCount", "canonicalSampleDigest",
)

func validatePortListenerEvidence(
	required bool,
	completed int,
	observations []domain.ObservationEvent,
	errorsList []*domain.Error,
) error {
	if completed < 0 {
		return fmt.Errorf("port listener repeat count is invalid")
	}
	summaryCount := 0
	hasPositiveSummary := false
	positiveCount := 0
	for _, observation := range observations {
		if observation.Operation != "port.listener-trace.summary" {
			continue
		}
		if !required {
			return fmt.Errorf("port listener summary is not required by the plan")
		}
		summaryCount++
		positive, count, err := validatePortListenerSummary(observation)
		if err != nil {
			return err
		}
		if positive {
			if hasPositiveSummary && positiveCount != count {
				return fmt.Errorf("positive port listener summaries disagree on undeclared endpoint count")
			}
			hasPositiveSummary = true
			positiveCount = count
		}
	}
	if required && summaryCount != completed {
		return fmt.Errorf("port listener summary count does not match completed repeats")
	}

	portFindings := make([]*domain.Error, 0, 1)
	for _, item := range errorsList {
		if item != nil && item.Code == domain.CodeUndeclaredPortListen {
			portFindings = append(portFindings, item)
		}
	}
	if !required && len(portFindings) != 0 {
		return fmt.Errorf("port listener finding is not required by the plan")
	}
	if !hasPositiveSummary {
		if len(portFindings) != 0 {
			return fmt.Errorf("port listener finding has no positive summary")
		}
		return nil
	}
	if len(portFindings) != 1 {
		return fmt.Errorf("positive port listener summaries require one aggregate finding")
	}
	count, err := validUndeclaredPortFinding(portFindings[0])
	if err != nil {
		return err
	}
	if count != positiveCount {
		return fmt.Errorf("port listener finding does not match positive summaries")
	}
	return nil
}

func validatePortListenerSummary(
	observation domain.ObservationEvent,
) (bool, int, error) {
	if observation.SchemaVersion != "1" || observation.Timestamp.IsZero() ||
		observation.Phase != domain.PhaseCleanup ||
		observation.Actor != "trusted-runner" ||
		observation.Resource != "tcp-listeners" ||
		observation.Observer != "docker-peer-port-listener-trace" ||
		!validPortListenerStaticDetails(observation.Details) {
		return false, 0, fmt.Errorf("port listener summary metadata is invalid")
	}
	comparison, ok := observation.Details["comparisonResult"].(string)
	if !ok {
		return false, 0, fmt.Errorf("port listener comparison result is invalid")
	}
	switch comparison {
	case "nonconforming-listeners", "no-undeclared-observed":
		if !exactDetailKeys(observation.Details, portListenerCompleteDetailKeys) ||
			observation.Result != "observed" ||
			observation.Coverage != "best-effort" ||
			observation.Confidence != "high" ||
			observation.Details["observerAdapter"] != "node-proc-net-tcp-linux" &&
				observation.Details["observerAdapter"] != "python-proc-net-tcp-linux" ||
			observation.Details["identityVerified"] != true ||
			observation.Details["namespaceIsolationVerified"] != true ||
			observation.Details["workloadQuiescenceVerified"] != true ||
			observation.Details["peerRemoveVerified"] != true ||
			!validPortDigest(observation.Details["canonicalSampleDigest"]) {
			return false, 0, fmt.Errorf("complete port listener summary is invalid")
		}
		baseline, baselineOK := boundedPortInteger(
			observation.Details["baselineEndpointCount"], 0, 0,
		)
		declared, declaredOK := boundedPortInteger(
			observation.Details["declaredEndpointCount"], 1, 1,
		)
		sampled, sampledOK := boundedPortInteger(
			observation.Details["sampledEndpointCount"], 1, 16,
		)
		undeclared, undeclaredOK := boundedPortInteger(
			observation.Details["undeclaredEndpointCount"], 0, 15,
		)
		_, samplesOK := boundedPortInteger(
			observation.Details["sampleCount"], 3, 1200,
		)
		_, gapOK := boundedPortInteger(
			observation.Details["maxSampleGapMillis"], 0, 1000,
		)
		_, transitionsOK := boundedPortInteger(
			observation.Details["transitionCount"], 2, 4096,
		)
		if !baselineOK || !declaredOK || !sampledOK || !undeclaredOK ||
			!samplesOK || !gapOK || !transitionsOK || baseline != 0 ||
			sampled != declared+undeclared ||
			comparison == "nonconforming-listeners" && undeclared == 0 ||
			comparison == "no-undeclared-observed" && undeclared != 0 {
			return false, 0, fmt.Errorf("port listener aggregate counts are invalid")
		}
		return comparison == "nonconforming-listeners", undeclared, nil
	case "not-tested":
		if !(exactDetailKeys(observation.Details, portListenerUntestedDetailKeys) ||
			exactDetailKeys(observation.Details,
				append(portListenerUntestedDetailKeys, "failure"),
			)) || observation.Result != "unavailable" ||
			observation.Coverage != "unavailable" ||
			observation.Confidence != "unknown" ||
			!validPortFailure(observation.Details["failure"]) {
			return false, 0, fmt.Errorf("not-tested port listener summary is invalid")
		}
		return false, 0, nil
	default:
		return false, 0, fmt.Errorf("port listener comparison result is unsupported")
	}
}

func validPortListenerStaticDetails(details map[string]any) bool {
	if details["observerPlacement"] !=
		"peer-container-shared-network-namespace" ||
		details["sharesTargetPIDNamespace"] != false ||
		details["sharesTargetMountNamespace"] != false ||
		details["sharesTargetIPCNamespace"] != false ||
		details["sharesTargetCgroup"] != false ||
		details["processAttribution"] != "unavailable" ||
		details["lifetimeSemantics"] != "sample-window-only" ||
		details["kernelEventCoverage"] != "unavailable" ||
		details["shortLivedListenerGap"] != true ||
		details["udpUnavailable"] != true ||
		details["publicEvidence"] != "aggregate-only" ||
		details["evidenceBasis"] != "aggregate-only" ||
		details["canonicalDigestSemantics"] !=
			"helper-commitment-not-controller-recomputed" {
		return false
	}
	_, samplesOK := boundedPortInteger(details["sampleLimit"], 1200, 1200)
	_, intervalOK := boundedPortInteger(details["intervalMillis"], 100, 100)
	_, maxGapOK := boundedPortInteger(
		details["maxAllowedGapMillis"], 1000, 1000,
	)
	if !samplesOK || !intervalOK || !maxGapOK {
		return false
	}
	for _, key := range []string{
		"identityVerified", "namespaceIsolationVerified",
		"workloadQuiescenceVerified", "peerRemoveVerified",
	} {
		if _, ok := details[key].(bool); !ok {
			return false
		}
	}
	return true
}

func validUndeclaredPortFinding(item *domain.Error) (int, error) {
	if item == nil || item.SchemaVersion != "1" ||
		item.Code != domain.CodeUndeclaredPortListen ||
		item.Phase != "" || item.Severity != domain.SeverityHigh ||
		item.Message != "Bounded peer TCP samples observed one or more listeners outside the declared service endpoint." ||
		item.Cause != nil || len(item.EvidenceRefs) != 0 ||
		item.Suggestion != "" || item.Retryable || len(item.Details) != 3 ||
		item.Details["observer"] != "docker-peer-port-listener-trace" ||
		item.Details["evidenceBasis"] != "aggregate-only" {
		return 0, fmt.Errorf("port listener finding is invalid")
	}
	count, ok := boundedPortInteger(item.Details["undeclaredEndpointCount"], 1, 15)
	if !ok {
		return 0, fmt.Errorf("port listener finding count is invalid")
	}
	return count, nil
}

func boundedPortInteger(value any, minimum, maximum int) (int, bool) {
	var numeric float64
	switch typed := value.(type) {
	case int:
		numeric = float64(typed)
	case int8:
		numeric = float64(typed)
	case int16:
		numeric = float64(typed)
	case int32:
		numeric = float64(typed)
	case int64:
		numeric = float64(typed)
	case uint:
		numeric = float64(typed)
	case uint8:
		numeric = float64(typed)
	case uint16:
		numeric = float64(typed)
	case uint32:
		numeric = float64(typed)
	case uint64:
		if typed > uint64(maximum) {
			return 0, false
		}
		numeric = float64(typed)
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
		numeric < float64(minimum) || numeric > float64(maximum) ||
		math.Trunc(numeric) != numeric {
		return 0, false
	}
	return int(numeric), true
}

func validPortDigest(value any) bool {
	digest, ok := value.(string)
	if !ok || len(digest) != len("sha256:")+64 ||
		!strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, value := range digest[len("sha256:"):] {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}

func validPortFailure(value any) bool {
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

func exactDetailKeys(details map[string]any, keys []string) bool {
	if len(details) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := details[key]; !ok {
			return false
		}
	}
	return true
}

func observerRequired(observers []string, target string) bool {
	for _, observer := range observers {
		if observer == target {
			return true
		}
	}
	return false
}

func coverageFor(required []string, runner domain.RunnerFeatures) ([]domain.ObserverCoverage, bool) {
	result := make([]domain.ObserverCoverage, 0, len(required))
	complete := true
	for _, observer := range required {
		coverage := "unavailable"
		switch observer {
		case "network-enforcement":
			if runner.NetworkDeny {
				coverage = "full"
			}
		case "filesystem-write":
			coverage = normalizeObservationCoverage(
				runner.FilesystemWriteObservation,
			)
		case "process-exec":
			coverage = normalizeObservationCoverage(
				runner.ProcessExecObservation,
			)
		case "port-listen":
			coverage = normalizeObservationCoverage(runner.PortObservation)
		case "resource-usage":
			coverage = normalizeObservationCoverage(runner.ResourceUsage)
		}
		if observer == "network-enforcement" {
			coverage = normalizeCoverage(coverage)
		}
		adequate := coverage == "full" || coverage == "high"
		if !adequate {
			complete = false
		}
		item := domain.ObserverCoverage{
			Observer: observer, Feature: observer, Coverage: coverage, Required: true,
		}
		if !adequate {
			item.Reason = "Required coverage is unavailable or below the v0.1 acceptance threshold."
		}
		result = append(result, item)
	}
	return result, complete
}

func normalizeRunner(value domain.RunnerFeatures) domain.RunnerFeatures {
	if value.Backend == "" {
		value.Backend = "none"
	}
	if value.ControllerOS == "" {
		value.ControllerOS = "unknown"
	}
	if value.WorkloadOS == "" {
		value.WorkloadOS = "unknown"
	}
	if value.Rootless == "" {
		value.Rootless = "unknown"
	}
	value.NetworkAttemptObservation = normalizeCoverage(value.NetworkAttemptObservation)
	value.ProcessExecObservation = normalizeObservationCoverage(value.ProcessExecObservation)
	value.FilesystemWriteObservation = normalizeObservationCoverage(value.FilesystemWriteObservation)
	value.FilesystemReadObservation = normalizeObservationCoverage(value.FilesystemReadObservation)
	value.PortObservation = normalizeObservationCoverage(value.PortObservation)
	value.ResourceUsage = normalizeObservationCoverage(value.ResourceUsage)
	return value
}

func normalizeCoverage(value string) string {
	switch value {
	case "full", "high", "best-effort", "enforcement-only", "unavailable":
		return value
	default:
		return "unavailable"
	}
}

func normalizeObservationCoverage(value string) string {
	switch value {
	case "full", "high", "best-effort", "unavailable":
		return value
	default:
		return "unavailable"
	}
}

func baselinePolicy(
	plan domain.ResolvedPlan,
	runner domain.RunnerFeatures,
	coverageComplete bool,
) []domain.PolicyDecision {
	networkDecision := "allow"
	networkMessage := "Runtime network deny is enforced."
	if !runner.NetworkDeny {
		networkDecision = "deny"
		networkMessage = "Runtime network deny is not enforced."
	}
	coverageDecision := "allow"
	coverageMessage := "Required observer coverage is sufficient."
	if !coverageComplete {
		coverageDecision = "deny"
		coverageMessage = "Required observer coverage is incomplete."
	}
	resourceDecision := "allow"
	resourceMessage := "Resource limits are enforced by the runner."
	if !runner.ResourceLimitEnforcement {
		resourceDecision = "deny"
		resourceMessage = "Resource-limit enforcement is not reported as active."
	}
	return []domain.PolicyDecision{
		{
			PolicyID: "core.runtime-network-deny", PolicyBundleDigest: plan.PolicyBundleDigest,
			Decision: networkDecision, Severity: domain.SeverityHigh, Message: networkMessage,
		},
		{
			PolicyID: "core.required-observer-coverage", PolicyBundleDigest: plan.PolicyBundleDigest,
			Decision: coverageDecision, Severity: domain.SeverityHigh, Message: coverageMessage,
		},
		{
			PolicyID: "core.resource-limit-enforcement", PolicyBundleDigest: plan.PolicyBundleDigest,
			Decision: resourceDecision, Severity: domain.SeverityHigh, Message: resourceMessage,
		},
	}
}

func verificationDigest(result domain.VerificationResult) (string, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	var semantic map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&semantic); err != nil {
		return "", err
	}
	digests, _ := semantic["digests"].(map[string]any)
	if digests != nil {
		delete(digests, "verification")
	}
	return canonicaljson.Digest(semantic)
}

func VerifyIntegrity(result domain.VerificationResult) error {
	if result.SchemaVersion != "1" ||
		result.RunID == "" ||
		result.VerificationID == "" ||
		result.StartedAt.IsZero() ||
		result.CompletedAt.Before(result.StartedAt) {
		return integrityError("Verification artifact identity or timestamps are invalid.", nil)
	}
	if result.Results.Evidence != domain.EvidenceUnsigned {
		return integrityError(
			"Signed or alternate evidence states are unsupported until signature trust verification is implemented.",
			map[string]any{"evidence": result.Results.Evidence},
		)
	}
	if result.Results.Freshness != domain.FreshnessCurrent {
		return integrityError(
			"Stored freshness overrides are unsupported; freshness must be evaluated against current inputs.",
			map[string]any{"freshness": result.Results.Freshness},
		)
	}
	if index := nilErrorIndex(result.Errors); index >= 0 {
		return integrityError(
			"Verification findings contain a null item.",
			map[string]any{"index": index},
		)
	}
	if normalized := normalizeRunner(result.Runner); normalized != result.Runner {
		return integrityError("Runner feature coverage is not normalized.", nil)
	}
	if field := invalidResourceSummaryField(result.Resources); field != "" {
		return integrityError(
			"Resource usage evidence does not match the bounded contract.",
			map[string]any{"field": field},
		)
	}

	collectionChecks := []struct {
		name     string
		value    any
		expected string
	}{
		{"observations", result.Observations, result.Digests.Observations},
		{"assertions", result.Assertions, result.Digests.Assertions},
		{"policyDecisions", result.PolicyDecisions, result.Digests.PolicyDecisions},
	}
	for _, check := range collectionChecks {
		actual, err := canonicaljson.Digest(check.value)
		if err != nil {
			return integrityError("Verification component digest could not be recomputed.", map[string]any{"component": check.name})
		}
		if actual != check.expected {
			return integrityError(
				"Verification component digest does not match its content.",
				map[string]any{"component": check.name, "expected": check.expected, "actual": actual},
			)
		}
	}

	if result.Plan.RepeatCount != result.Repeats.Requested ||
		result.Plan.SuccessThreshold <= 0 ||
		result.Plan.SuccessThreshold > result.Plan.RepeatCount {
		return integrityError("Verification repeat policy is not bound consistently.", nil)
	}
	if result.Plan.ResolvedPlanSchemaVersion != "4" || !validVerificationEvidence(result.Plan.Evidence) {
		return integrityError("Verification evidence selection is not bound consistently.", nil)
	}
	expectedFunctional := functionalVerdict(Input{
		Assertions: result.Assertions,
		Errors:     result.Errors,
		Completed:  result.Repeats.Completed,
	})
	requiredObservers := make([]string, 0, len(result.ObserverCoverage))
	for _, coverage := range result.ObserverCoverage {
		if !coverage.Required {
			return integrityError("Unsupported optional observer coverage was found in an authoritative artifact.", nil)
		}
		requiredObservers = append(requiredObservers, coverage.Feature)
	}
	expectedCoverage, coverageComplete := coverageFor(requiredObservers, result.Runner)
	expectedCoverageDigest, err := canonicaljson.Digest(expectedCoverage)
	if err != nil {
		return integrityError("Observer coverage could not be recomputed.", nil)
	}
	actualCoverageDigest, err := canonicaljson.Digest(result.ObserverCoverage)
	if err != nil || actualCoverageDigest != expectedCoverageDigest {
		return integrityError("Observer coverage does not match runner features.", nil)
	}
	if err := validatePortListenerEvidence(
		observerRequired(requiredObservers, "port-listen"),
		result.Repeats.Completed,
		result.Observations,
		result.Errors,
	); err != nil {
		return integrityError(
			"Peer TCP listener evidence does not satisfy the authoritative public contract.",
			nil,
		)
	}
	expectedCapability := capabilityVerdict(result.Errors, coverageComplete)
	observedCleanup, cleanupEvidenceErr := cleanupVerdictFromObservations(
		result.Observations,
		result.Repeats.Completed,
	)
	if cleanupEvidenceErr != nil {
		return integrityError(
			"Cleanup observations do not satisfy the authoritative evidence contract.",
			map[string]any{"reason": cleanupEvidenceErr.Error()},
		)
	}
	expectedCleanup := cleanupVerdict(
		observedCleanup,
		result.Repeats.Completed,
		result.Errors,
	)
	expectedReproducibility := reproducibilityVerdict(
		result.Repeats.Requested,
		result.Repeats.Completed,
		result.Repeats.Matching,
		result.Plan.SuccessThreshold,
	)
	expectedVerdicts := domain.Verdicts{
		Functional:      expectedFunctional,
		Capability:      expectedCapability,
		Reproducibility: expectedReproducibility,
		Cleanup:         expectedCleanup,
		Evidence:        domain.EvidenceUnsigned,
		Freshness:       domain.FreshnessCurrent,
	}
	expectedVerdicts.Overall = aggregate(expectedVerdicts)
	if result.Results != expectedVerdicts {
		return integrityError(
			"Stored verdicts do not match assertions, findings, coverage, and repeat policy.",
			map[string]any{"expected": expectedVerdicts, "actual": result.Results},
		)
	}
	expectedPolicy := baselinePolicy(
		domain.ResolvedPlan{PolicyBundleDigest: result.Plan.PolicyBundleDigest},
		result.Runner,
		coverageComplete,
	)
	expectedPolicyDigest, err := canonicaljson.Digest(expectedPolicy)
	if err != nil {
		return integrityError("Policy decisions could not be recomputed.", nil)
	}
	actualPolicyDigest, err := canonicaljson.Digest(result.PolicyDecisions)
	if err != nil || actualPolicyDigest != expectedPolicyDigest {
		return integrityError("Stored policy decisions do not match the baseline policy.", nil)
	}

	actual, err := verificationDigest(result)
	if err != nil {
		return domain.WrapError(domain.CodeEvidenceDigestMismatch, domain.SeverityHigh, "Verification digest could not be recomputed.", err)
	}
	if actual != result.Digests.Verification {
		e := domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Verification artifact digest does not match its protected content.")
		e.Details = map[string]any{"expected": result.Digests.Verification, "actual": actual}
		return e
	}
	return nil
}

func validVerificationEvidence(value domain.PlanEvidence) bool {
	if value.Profile != "minimal-public" ||
		!sameStrings(value.Exclude, []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"}) {
		return false
	}
	return sameStrings(value.Include, []string{"normalized-observations", "verification-summary"}) ||
		sameStrings(value.Include, []string{"normalized-observations", "sbom", "verification-summary"})
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func invalidResourceSummaryField(value domain.ResourceSummary) string {
	switch {
	case value.PeakMemoryBytes < 0:
		return "peakMemoryBytes"
	case value.CPUTimeMillis < 0:
		return "cpuTimeMillis"
	case value.DurationMillis < 0:
		return "durationMillis"
	case value.MaxProcesses < 0:
		return "maxProcesses"
	case value.LogBytes < 0:
		return "logBytes"
	case value.SandboxPeakMemoryBytes < 0:
		return "sandboxPeakMemoryBytes"
	case value.SandboxCPUTimeMillis < 0:
		return "sandboxCPUTimeMillis"
	case value.MaxTasks < 0:
		return "maxTasks"
	case value.WritableBytes < 0:
		return "writableBytes"
	case value.OutputBytes < 0:
		return "outputBytes"
	}

	observed := make(
		map[domain.ResourceObservedField]struct{},
		len(value.ObservedFields),
	)
	previous := ""
	for index, field := range value.ObservedFields {
		if !validResourceObservedField(field) {
			return fmt.Sprintf("observedFields[%d]", index)
		}
		current := string(field)
		if index > 0 && current <= previous {
			return "observedFields"
		}
		observed[field] = struct{}{}
		previous = current
	}
	for _, item := range []struct {
		field domain.ResourceObservedField
		value int64
	}{
		{domain.ResourceObservedMaxTasks, int64(value.MaxTasks)},
		{domain.ResourceObservedOutputBytes, value.OutputBytes},
		{
			domain.ResourceObservedSandboxCPUTimeMillis,
			value.SandboxCPUTimeMillis,
		},
		{
			domain.ResourceObservedSandboxPeakMemoryBytes,
			value.SandboxPeakMemoryBytes,
		},
		{domain.ResourceObservedWritableBytes, value.WritableBytes},
	} {
		if item.value == 0 {
			continue
		}
		if _, exists := observed[item.field]; !exists {
			return string(item.field)
		}
	}
	return ""
}

func validResourceObservedField(value domain.ResourceObservedField) bool {
	switch value {
	case domain.ResourceObservedMaxTasks,
		domain.ResourceObservedOutputBytes,
		domain.ResourceObservedSandboxCPUTimeMillis,
		domain.ResourceObservedSandboxPeakMemoryBytes,
		domain.ResourceObservedWritableBytes:
		return true
	default:
		return false
	}
}

func integrityError(message string, details map[string]any) error {
	err := domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, message)
	err.Details = details
	return err
}

func newOpaqueID(prefix string) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return prefix + "_" + time.Now().UTC().Format("20060102t150405000000000")
	}
	return prefix + "_" + hex.EncodeToString(random)
}

func nonNilObservations(values []domain.ObservationEvent) []domain.ObservationEvent {
	if values == nil {
		return []domain.ObservationEvent{}
	}
	return values
}

func nonNilAssertions(values []domain.AssertionResult) []domain.AssertionResult {
	if values == nil {
		return []domain.AssertionResult{}
	}
	for index := range values {
		if values[index].SchemaVersion == "" {
			values[index].SchemaVersion = "1"
		}
		if values[index].ID == "" {
			values[index].ID = fmt.Sprintf("assertion-%d", index+1)
		}
		if !values[index].Required {
			values[index].Required = true
		}
		if values[index].EvidenceRefs == nil {
			values[index].EvidenceRefs = []string{}
		}
		switch values[index].Status {
		case "pass":
			values[index].Status = "passed"
		case "fail":
			values[index].Status = "failed"
		}
	}
	return values
}
