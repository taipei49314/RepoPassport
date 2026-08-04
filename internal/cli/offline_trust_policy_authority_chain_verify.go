package cli

import (
	"context"
	"errors"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/trustchainstate"
)

const chainedSignedOfflineTrustPolicyBasis = "signed-offline-policy-v2+authority-transition-chain-v1"

type chainedSignedOfflineTrustPolicyReaders struct {
	readRoot     func(string) ([]byte, error)
	readTerminal func(string) ([]byte, error)
	readChain    func(string) ([]byte, error)
	readPolicy   func(string) ([]byte, error)
}

var defaultChainedSignedOfflineTrustPolicyReaders = chainedSignedOfflineTrustPolicyReaders{
	readRoot:     attestation.ReadTrustPolicyAuthorityTransitionRootKey,
	readTerminal: attestation.ReadTrustPolicyAuthorityTransitionTerminalKey,
	readChain:    attestation.ReadTrustPolicyAuthorityTransitionChain,
	readPolicy:   attestation.ReadSignedOfflineTrustPolicyEnvelope,
}

func (a App) verifyWithChainedSignedOfflineTrustPolicy(
	ctx context.Context,
	global globalOptions,
	bundle []byte,
	report attestation.VerificationReport,
	signed signedTrustPolicyCLIOptions,
	rotation signedTrustPolicyAuthorityRotationCLIOptions,
	persist persistTrustPolicyStateCLIOptions,
	freshnessRequested bool,
) (attestation.VerificationReport, attestation.AcceptedClaims, error) {
	return a.verifyWithChainedSignedOfflineTrustPolicyReaders(
		ctx, global, bundle, report, signed, rotation, persist, freshnessRequested,
		defaultChainedSignedOfflineTrustPolicyReaders,
	)
}

func (a App) verifyWithChainedSignedOfflineTrustPolicyReaders(
	ctx context.Context,
	global globalOptions,
	bundle []byte,
	report attestation.VerificationReport,
	signed signedTrustPolicyCLIOptions,
	rotation signedTrustPolicyAuthorityRotationCLIOptions,
	persist persistTrustPolicyStateCLIOptions,
	freshnessRequested bool,
	readers chainedSignedOfflineTrustPolicyReaders,
) (attestation.VerificationReport, attestation.AcceptedClaims, error) {
	var claims attestation.AcceptedClaims
	report.TrustBasis = chainedSignedOfflineTrustPolicyBasis
	report.TrustDecision = "rejected"
	report.TrustReason = "invalid-or-unavailable"
	report.MinimumTrustPolicyGeneration = signed.MinimumGeneration
	report.MinimumTrustPolicyAuthorityGeneration = rotation.MinimumGeneration

	rootSPKI, err := readers.readRoot(rotation.TrustRootPath)
	if err != nil {
		return report, claims, chainedSignedOfflineTrustPolicyUnavailableError()
	}
	terminalSPKI, err := readers.readTerminal(signed.AuthorityKeyPath)
	if err != nil || attestation.ValidateOfflineTrustPolicyAuthorityTransitionKeyPair(rootSPKI, terminalSPKI) != nil {
		return report, claims, chainedSignedOfflineTrustPolicyUnavailableError()
	}
	chainRaw, err := readers.readChain(rotation.TransitionChainPath)
	if err != nil {
		return report, claims, chainedSignedOfflineTrustPolicyUnavailableError()
	}
	chain, err := attestation.VerifyOfflineTrustPolicyAuthorityTransitionChain(
		chainRaw, rootSPKI, terminalSPKI, rotation.MinimumGeneration,
	)
	if err != nil || chain == nil {
		return report, claims, chainedSignedOfflineTrustPolicyUnavailableError()
	}

	policyRaw, err := readers.readPolicy(signed.EnvelopePath)
	if err != nil {
		return report, claims, chainedSignedOfflineTrustPolicyUnavailableError()
	}
	policy, err := attestation.ParseSignedOfflineTrustPolicy(policyRaw, terminalSPKI)
	if errors.Is(err, attestation.ErrSignedOfflineTrustPolicyAuthorityRoleConflict) {
		report.TrustDecision = "rejected"
		report.TrustReason = "authority-role-conflict"
		return report, claims, chainedSignedOfflineTrustPolicyRoleError()
	}
	if err != nil || policy == nil || policy.AuthorityKeyID() != chain.TerminalAuthorityKeyID() {
		return report, claims, chainedSignedOfflineTrustPolicyUnavailableError()
	}
	report, err = attestation.VerifySignedOfflineTrustPolicyFloor(report, policy, signed.MinimumGeneration)
	report.TrustBasis = chainedSignedOfflineTrustPolicyBasis
	if err != nil {
		return report, claims, withChainedSignedOfflineTrustPolicyBasis(err)
	}
	for _, authorityKeyID := range chain.AuthorityKeyIDs() {
		role, roleErr := policy.EvaluateSignerKeyID(authorityKeyID)
		if roleErr != nil || role != attestation.TrustDecisionNotListed {
			report.TrustDecision = "rejected"
			report.TrustReason = "authority-role-conflict"
			return report, claims, chainedSignedOfflineTrustPolicyRoleError()
		}
	}

	// Chain metadata is released only after the complete chain, terminal policy,
	// both floors, and all-authority role separation have passed.
	report.TrustPolicyAuthorityTransitionChainDigest = chain.Digest()
	report.TrustPolicyAuthorityTransitionChainHopCount = chain.HopCount()
	report.TrustPolicyAuthorityTransitionChainGeneration = chain.TerminalGeneration()
	report.TrustPolicyAuthorityTransitionChainRootKeyID = chain.RootAuthorityKeyID()
	report.TrustPolicyAuthorityTransitionChainTerminalKeyID = chain.TerminalAuthorityKeyID()

	if persist.Enabled {
		dataRoot := global.DataDir
		if dataRoot == "" {
			dataRoot, err = defaultDataDir()
		}
		if err == nil {
			err = rejectRepositoryLocalDataRoot(dataRoot)
		}
		if err != nil {
			report.TrustPolicyAuthorityTransitionChainStateEvaluation = string(trustchainstate.EvaluationUnavailable)
			return rejectChainedTrustPolicyState(report, claims, "state-unavailable")
		}
		state, observeErr := trustchainstate.Observe(ctx, dataRoot, trustchainstate.Observation{
			TrustRootKeyID: chain.RootAuthorityKeyID(), Purpose: trustchainstate.Purpose,
			PolicyPayloadType:       trustchainstate.PolicyPayloadType,
			ChainTerminalGeneration: chain.TerminalGeneration(), ChainDigest: chain.Digest(), ChainHopCount: chain.HopCount(),
			TerminalAuthorityKeyID: chain.TerminalAuthorityKeyID(), PolicyGeneration: policy.Generation(), PolicyPayloadDigest: policy.PayloadDigest(),
		})
		report.TrustPolicyAuthorityTransitionChainStateEvaluation = string(state.Evaluation)
		report.TrustPolicyAuthorityTransitionChainStateGeneration = state.ChainTerminalGeneration
		report.TrustPolicyAuthorityTransitionChainStatePolicyGeneration = state.PolicyGeneration
		if observeErr != nil {
			return rejectChainedTrustPolicyState(report, claims, chainedTrustPolicyStateFailureReason(observeErr))
		}
		if !acceptedChainedTrustPolicyStateEvaluation(state.Evaluation) {
			report.TrustPolicyAuthorityTransitionChainStateEvaluation = string(trustchainstate.EvaluationUnavailable)
			report.TrustPolicyAuthorityTransitionChainStateGeneration = 0
			report.TrustPolicyAuthorityTransitionChainStatePolicyGeneration = 0
			return rejectChainedTrustPolicyState(report, claims, "state-unavailable")
		}
	}

	if freshnessRequested {
		report, claims, err = attestation.VerifyAcceptedSignedOfflineTrustPolicySigner(bundle, report, policy)
	} else {
		report, err = attestation.VerifySignedOfflineTrustPolicySigner(report, policy)
	}
	report.TrustBasis = chainedSignedOfflineTrustPolicyBasis
	return report, claims, withChainedSignedOfflineTrustPolicyBasis(err)
}

func rejectChainedTrustPolicyState(report attestation.VerificationReport, claims attestation.AcceptedClaims, reason string) (attestation.VerificationReport, attestation.AcceptedClaims, error) {
	report, err := attestation.RejectSignedOfflineTrustPolicyState(report, reason)
	report.TrustBasis = chainedSignedOfflineTrustPolicyBasis
	return report, claims, withChainedSignedOfflineTrustPolicyBasis(err)
}

func acceptedChainedTrustPolicyStateEvaluation(evaluation trustchainstate.Evaluation) bool {
	switch evaluation {
	case trustchainstate.EvaluationInitialized, trustchainstate.EvaluationMatched, trustchainstate.EvaluationAdvanced:
		return true
	default:
		return false
	}
}

func chainedTrustPolicyStateFailureReason(err error) string {
	switch {
	case errors.Is(err, trustchainstate.ErrGenerationRollback):
		return "state-generation-rollback"
	case errors.Is(err, trustchainstate.ErrAuthorityEquivocation), errors.Is(err, trustchainstate.ErrPolicyEquivocation):
		return "state-generation-equivocation"
	default:
		return "state-unavailable"
	}
}

func chainedSignedOfflineTrustPolicyUnavailableError() error {
	err := domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityHigh,
		"The signed offline trust policy authority transition chain is invalid or unavailable.")
	err.Details = map[string]any{
		"signatureValid": true, "trustDecision": "rejected",
		"trustBasis": chainedSignedOfflineTrustPolicyBasis, "trustReason": "invalid-or-unavailable",
	}
	return err
}

func chainedSignedOfflineTrustPolicyRoleError() error {
	err := domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityHigh,
		"The signed offline trust policy violates authority-chain and evidence-signer role separation.")
	err.Details = map[string]any{
		"signatureValid": true, "trustDecision": "rejected",
		"trustBasis": chainedSignedOfflineTrustPolicyBasis, "trustReason": "authority-role-conflict",
	}
	return err
}

func withChainedSignedOfflineTrustPolicyBasis(err error) error {
	if err == nil {
		return nil
	}
	var typed *domain.Error
	if errors.As(err, &typed) {
		if typed.Details == nil {
			typed.Details = map[string]any{}
		}
		typed.Details["trustBasis"] = chainedSignedOfflineTrustPolicyBasis
	}
	return err
}
