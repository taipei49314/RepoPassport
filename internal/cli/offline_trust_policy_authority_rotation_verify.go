package cli

import (
	"context"
	"errors"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/trustrotationstate"
)

const rotatedSignedOfflineTrustPolicyBasis = "signed-offline-policy-v2+authority-transition-v1"

type rotatedSignedOfflineTrustPolicyReaders struct {
	readRoot       func(string) ([]byte, error)
	readTerminal   func(string) ([]byte, error)
	readTransition func(string) ([]byte, error)
	readPolicy     func(string) ([]byte, error)
}

var defaultRotatedSignedOfflineTrustPolicyReaders = rotatedSignedOfflineTrustPolicyReaders{
	readRoot:       attestation.ReadTrustPolicyAuthorityTransitionRootKey,
	readTerminal:   attestation.ReadTrustPolicyAuthorityTransitionTerminalKey,
	readTransition: attestation.ReadTrustPolicyAuthorityTransition,
	readPolicy:     attestation.ReadSignedOfflineTrustPolicyEnvelope,
}

// verifyWithRotatedSignedOfflineTrustPolicy performs the one-hop extension of
// Alpha.31 signed-policy verification. All flag shape has already been
// resolved by the caller; this function preserves the intrinsic-bundle-first
// I/O boundary and commits only one root-scoped combined state record.
func (a App) verifyWithRotatedSignedOfflineTrustPolicy(
	ctx context.Context,
	global globalOptions,
	bundle []byte,
	report attestation.VerificationReport,
	signed signedTrustPolicyCLIOptions,
	rotation signedTrustPolicyAuthorityRotationCLIOptions,
	persist persistTrustPolicyStateCLIOptions,
	freshnessRequested bool,
) (attestation.VerificationReport, attestation.AcceptedClaims, error) {
	return a.verifyWithRotatedSignedOfflineTrustPolicyReaders(
		ctx, global, bundle, report, signed, rotation, persist, freshnessRequested,
		defaultRotatedSignedOfflineTrustPolicyReaders,
	)
}

func (a App) verifyWithRotatedSignedOfflineTrustPolicyReaders(
	ctx context.Context,
	global globalOptions,
	bundle []byte,
	report attestation.VerificationReport,
	signed signedTrustPolicyCLIOptions,
	rotation signedTrustPolicyAuthorityRotationCLIOptions,
	persist persistTrustPolicyStateCLIOptions,
	freshnessRequested bool,
	readers rotatedSignedOfflineTrustPolicyReaders,
) (attestation.VerificationReport, attestation.AcceptedClaims, error) {
	var claims attestation.AcceptedClaims
	report.TrustBasis = rotatedSignedOfflineTrustPolicyBasis
	report.TrustDecision = "rejected"
	report.TrustReason = "invalid-or-unavailable"
	report.MinimumTrustPolicyGeneration = signed.MinimumGeneration
	report.MinimumTrustPolicyAuthorityGeneration = rotation.MinimumGeneration

	rootSPKI, err := readers.readRoot(rotation.TrustRootPath)
	if err != nil {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}
	terminalSPKI, err := readers.readTerminal(signed.AuthorityKeyPath)
	if err != nil {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}
	if err := attestation.ValidateOfflineTrustPolicyAuthorityTransitionKeyPair(rootSPKI, terminalSPKI); err != nil {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}
	transitionRaw, err := readers.readTransition(rotation.TransitionPath)
	if err != nil {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}
	transition, err := attestation.VerifyOfflineTrustPolicyAuthorityTransition(
		transitionRaw,
		rootSPKI,
		terminalSPKI,
		rotation.MinimumGeneration,
	)
	if err != nil || transition == nil {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}

	policyRaw, err := readers.readPolicy(signed.EnvelopePath)
	if err != nil {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}
	policy, err := attestation.ParseSignedOfflineTrustPolicy(policyRaw, terminalSPKI)
	if errors.Is(err, attestation.ErrSignedOfflineTrustPolicyAuthorityRoleConflict) {
		report.TrustDecision = "rejected"
		report.TrustReason = "authority-role-conflict"
		return report, claims, rotatedSignedOfflineTrustPolicyRoleError()
	}
	if err != nil || policy == nil || policy.AuthorityKeyID() != transition.NextAuthorityKeyID() {
		return report, claims, rotatedSignedOfflineTrustPolicyUnavailableError()
	}
	report, err = attestation.VerifySignedOfflineTrustPolicyFloor(report, policy, signed.MinimumGeneration)
	report.TrustBasis = rotatedSignedOfflineTrustPolicyBasis
	if err != nil {
		return report, claims, withRotatedSignedOfflineTrustPolicyBasis(err)
	}
	rootRole, err := policy.EvaluateSignerKeyID(transition.PreviousAuthorityKeyID())
	if err != nil || rootRole != attestation.TrustDecisionNotListed {
		report.TrustDecision = "rejected"
		report.TrustReason = "authority-role-conflict"
		return report, claims, rotatedSignedOfflineTrustPolicyRoleError()
	}

	// Attach only facts authenticated by the complete transition + terminal
	// policy tuple. Earlier failures deliberately expose no transition-derived
	// metadata.
	report.TrustPolicyAuthorityTransitionDigest = transition.PayloadDigest()
	report.TrustPolicyAuthorityTransitionEnvelopeDigest = transition.EnvelopeDigest()
	report.TrustPolicyAuthorityTrustRootKeyID = transition.PreviousAuthorityKeyID()
	report.TrustPolicyAuthorityTransitionGeneration = transition.Generation()

	if persist.Enabled {
		dataRoot := global.DataDir
		if dataRoot == "" {
			dataRoot, err = defaultDataDir()
		}
		if err == nil {
			err = rejectRepositoryLocalDataRoot(dataRoot)
		}
		if err != nil {
			report.TrustPolicyAuthorityStateEvaluation = string(trustrotationstate.EvaluationUnavailable)
			return rejectRotatedTrustPolicyState(report, claims, "state-unavailable")
		}
		state, observeErr := trustrotationstate.Observe(ctx, dataRoot, trustrotationstate.Observation{
			TrustRootKeyID:           transition.PreviousAuthorityKeyID(),
			Purpose:                  trustrotationstate.Purpose,
			PolicyPayloadType:        trustrotationstate.PolicyPayloadType,
			TransitionGeneration:     transition.Generation(),
			TransitionPayloadDigest:  transition.PayloadDigest(),
			TransitionEnvelopeDigest: transition.EnvelopeDigest(),
			TerminalAuthorityKeyID:   transition.NextAuthorityKeyID(),
			PolicyGeneration:         policy.Generation(),
			PolicyPayloadDigest:      policy.PayloadDigest(),
		})
		report.TrustPolicyAuthorityStateEvaluation = string(state.Evaluation)
		report.TrustPolicyAuthorityStateTransitionGeneration = state.TransitionGeneration
		report.TrustPolicyAuthorityStatePolicyGeneration = state.PolicyGeneration
		if observeErr != nil {
			return rejectRotatedTrustPolicyState(report, claims, rotatedTrustPolicyStateFailureReason(observeErr))
		}
		if !acceptedRotatedTrustPolicyStateEvaluation(state.Evaluation) {
			report.TrustPolicyAuthorityStateEvaluation = string(trustrotationstate.EvaluationUnavailable)
			report.TrustPolicyAuthorityStateTransitionGeneration = 0
			report.TrustPolicyAuthorityStatePolicyGeneration = 0
			return rejectRotatedTrustPolicyState(report, claims, "state-unavailable")
		}
	}

	if freshnessRequested {
		report, claims, err = attestation.VerifyAcceptedSignedOfflineTrustPolicySigner(bundle, report, policy)
	} else {
		report, err = attestation.VerifySignedOfflineTrustPolicySigner(report, policy)
	}
	report.TrustBasis = rotatedSignedOfflineTrustPolicyBasis
	return report, claims, withRotatedSignedOfflineTrustPolicyBasis(err)
}

func rejectRotatedTrustPolicyState(report attestation.VerificationReport, claims attestation.AcceptedClaims, reason string) (attestation.VerificationReport, attestation.AcceptedClaims, error) {
	report, err := attestation.RejectSignedOfflineTrustPolicyState(report, reason)
	report.TrustBasis = rotatedSignedOfflineTrustPolicyBasis
	return report, claims, withRotatedSignedOfflineTrustPolicyBasis(err)
}

func acceptedRotatedTrustPolicyStateEvaluation(evaluation trustrotationstate.Evaluation) bool {
	switch evaluation {
	case trustrotationstate.EvaluationInitialized, trustrotationstate.EvaluationMatched, trustrotationstate.EvaluationAdvanced:
		return true
	default:
		return false
	}
}

func rotatedTrustPolicyStateFailureReason(err error) string {
	switch {
	case errors.Is(err, trustrotationstate.ErrGenerationRollback):
		return "state-generation-rollback"
	case errors.Is(err, trustrotationstate.ErrAuthorityEquivocation), errors.Is(err, trustrotationstate.ErrPolicyEquivocation):
		return "state-generation-equivocation"
	default:
		return "state-unavailable"
	}
}

func rotatedSignedOfflineTrustPolicyUnavailableError() error {
	err := domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityHigh,
		"The signed offline trust policy authority transition is invalid or unavailable.")
	err.Details = map[string]any{
		"signatureValid": true,
		"trustDecision":  "rejected",
		"trustBasis":     rotatedSignedOfflineTrustPolicyBasis,
		"trustReason":    "invalid-or-unavailable",
	}
	return err
}

func rotatedSignedOfflineTrustPolicyRoleError() error {
	err := domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityHigh,
		"The signed offline trust policy violates authority and evidence-signer role separation.")
	err.Details = map[string]any{
		"signatureValid": true,
		"trustDecision":  "rejected",
		"trustBasis":     rotatedSignedOfflineTrustPolicyBasis,
		"trustReason":    "authority-role-conflict",
	}
	return err
}

func withRotatedSignedOfflineTrustPolicyBasis(err error) error {
	if err == nil {
		return nil
	}
	var typed *domain.Error
	if errors.As(err, &typed) {
		if typed.Details == nil {
			typed.Details = map[string]any{}
		}
		typed.Details["trustBasis"] = rotatedSignedOfflineTrustPolicyBasis
	}
	return err
}
