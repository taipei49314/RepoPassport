package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/releaseindex"
	"github.com/taipei49314/RepoPassport/internal/releasestate"
)

type releaseIndexVerificationReport struct {
	SchemaVersion                           string `json:"schemaVersion"`
	IndexIntegrity                          string `json:"indexIntegrity"`
	ArtifactIntegrity                       string `json:"artifactIntegrity"`
	SignatureValidity                       string `json:"signatureValidity"`
	ReleaseSignerKeyID                      string `json:"releaseSignerKeyId"`
	TrustDecision                           string `json:"trustDecision"`
	TrustBasis                              string `json:"trustBasis"`
	TrustRootKeyID                          string `json:"trustRootKeyId"`
	PolicyAuthorityKeyID                    string `json:"policyAuthorityKeyId,omitempty"`
	AuthorityTransitionPayloadDigest        string `json:"authorityTransitionPayloadDigest,omitempty"`
	AuthorityTransitionEnvelopeDigest       string `json:"authorityTransitionEnvelopeDigest,omitempty"`
	AuthorityTransitionGeneration           uint64 `json:"authorityTransitionGeneration,omitempty"`
	MinimumAuthorityTransitionGeneration    uint64 `json:"minimumAuthorityTransitionGeneration,omitempty"`
	AuthorityTransitionStateEvaluation      string `json:"authorityTransitionStateEvaluation,omitempty"`
	AuthorityTransitionStateGeneration      uint64 `json:"authorityTransitionStateGeneration,omitempty"`
	AuthorityTransitionChainDigest          string `json:"authorityTransitionChainDigest,omitempty"`
	AuthorityTransitionChainHopCount        uint64 `json:"authorityTransitionChainHopCount,omitempty"`
	AuthorityTransitionChainGeneration      uint64 `json:"authorityTransitionChainGeneration,omitempty"`
	AuthorityTransitionChainStateEvaluation string `json:"authorityTransitionChainStateEvaluation,omitempty"`
	AuthorityTransitionChainStateGeneration uint64 `json:"authorityTransitionChainStateGeneration,omitempty"`
	PolicyPayloadDigest                     string `json:"policyPayloadDigest"`
	PolicyEnvelopeDigest                    string `json:"policyEnvelopeDigest"`
	PolicyGeneration                        uint64 `json:"policyGeneration"`
	MinimumPolicyGeneration                 uint64 `json:"minimumPolicyGeneration"`
	PolicyStateEvaluation                   string `json:"policyStateEvaluation,omitempty"`
	PolicyStateGeneration                   uint64 `json:"policyStateGeneration,omitempty"`
	ReleaseIndexDigest                      string `json:"releaseIndexDigest"`
	ReleaseIndexEnvelopeDigest              string `json:"releaseIndexEnvelopeDigest"`
	Product                                 string `json:"product"`
	Channel                                 string `json:"channel"`
	ProductVersion                          string `json:"productVersion"`
	ReleaseGeneration                       uint64 `json:"releaseGeneration"`
	MinimumReleaseGeneration                uint64 `json:"minimumReleaseGeneration"`
	ReleaseStateEvaluation                  string `json:"releaseStateEvaluation,omitempty"`
	ReleaseStateGeneration                  uint64 `json:"releaseStateGeneration,omitempty"`
	PublisherIdentityAttestation            string `json:"publisherIdentityAttestation"`
	TimeAttestation                         string `json:"timeAttestation"`
	FormalClaim                             bool   `json:"formalClaim"`
	Capability                              string `json:"capability"`
	Overall                                 string `json:"overall"`
}

func (a App) runSignReleaseIndex(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, signReleaseIndexHelp())
		return 0
	}
	options, err := validateSignReleaseIndexArgs(args)
	if err != nil {
		return a.fail("sign-release-index", global, err)
	}
	if err := ctx.Err(); err != nil {
		return a.fail("sign-release-index", global, cancelledReleaseError())
	}
	indexRaw, err := releaseindex.BuildIndex(options.ArtifactRoot, options.ProductVersion, options.ReleaseGeneration)
	if err != nil {
		return a.fail("sign-release-index", global, releaseBuildError())
	}
	dataRoot, err := releaseDataRoot(global)
	if err != nil {
		return a.fail("sign-release-index", global, err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return a.fail("sign-release-index", global, releaseSigningError())
	}
	privateKey, err := releaseindex.LoadPrivateKeyForRelease(
		options.KeyPath, dataRoot, options.ArtifactRoot, options.OutputDirectory, workingDirectory,
	)
	if err != nil {
		return a.fail("sign-release-index", global, releaseSigningError())
	}
	defer clear(privateKey)
	envelopeRaw, signerSPKI, err := releaseindex.SignIndex(indexRaw, privateKey)
	if err != nil {
		return a.fail("sign-release-index", global, releaseSigningError())
	}
	signerKeyID, err := releaseindex.PublicKeyID(signerSPKI)
	if err != nil {
		return a.fail("sign-release-index", global, releaseSigningError())
	}
	if err := releaseindex.PublishSignedSidecars(options.OutputDirectory, indexRaw, envelopeRaw, signerSPKI); err != nil {
		return a.fail("sign-release-index", global, releaseSigningError())
	}
	verifiedIndex, err := releaseindex.ParseIndex(indexRaw)
	if err != nil {
		return a.fail("sign-release-index", global, releaseSigningError())
	}
	data := map[string]any{
		"schemaVersion": "1", "artifactType": verifiedIndex.ArtifactType,
		"product": verifiedIndex.Product, "channel": verifiedIndex.Channel,
		"productVersion": verifiedIndex.ProductVersion, "releaseGeneration": verifiedIndex.ReleaseGeneration,
		"releaseIndexDigest": releaseDigest(indexRaw), "releaseIndexEnvelopeDigest": releaseDigest(envelopeRaw),
		"signerKeyId": signerKeyID, "sidecarDirectory": options.OutputDirectory,
		"formalClaim": false, "capability": "incomplete", "overall": "inconclusive",
		"publisherIdentityAttestation": "none", "timeAttestation": "none",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "sign-release-index", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote signed release-index sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Release index digest: %s\n", data["releaseIndexDigest"])
	fmt.Fprintf(a.Stdout, "Release generation:   %d\n", options.ReleaseGeneration)
	fmt.Fprintln(a.Stdout, "Publisher identity attestation: NONE")
	fmt.Fprintln(a.Stdout, "Time attestation:               NONE")
	return 0
}

func (a App) runSignReleasePolicy(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, signReleasePolicyHelp())
		return 0
	}
	options, err := validateSignReleasePolicyArgs(args)
	if err != nil {
		return a.fail("sign-release-policy", global, err)
	}
	if err := ctx.Err(); err != nil {
		return a.fail("sign-release-policy", global, cancelledReleaseError())
	}
	policyRaw, err := releaseindex.ReadPolicyPayload(options.PolicyPath)
	if err != nil {
		return a.fail("sign-release-policy", global, releaseSigningError())
	}
	policy, err := releaseindex.ParsePolicyPayload(policyRaw)
	if err != nil {
		return a.fail("sign-release-policy", global, releaseSigningError())
	}
	dataRoot, err := releaseDataRoot(global)
	if err != nil {
		return a.fail("sign-release-policy", global, err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return a.fail("sign-release-policy", global, releaseSigningError())
	}
	privateKey, err := releaseindex.LoadPrivateKeyForPolicy(
		options.KeyPath, dataRoot, options.PolicyPath, options.OutputDirectory, workingDirectory,
	)
	if err != nil {
		return a.fail("sign-release-policy", global, releaseSigningError())
	}
	defer clear(privateKey)
	envelopeRaw, authoritySPKI, authorityKeyID, err := releaseindex.SignPolicyWithAuthority(*policy, privateKey)
	if err != nil {
		return a.fail("sign-release-policy", global, releaseSigningError())
	}
	if err := releaseindex.PublishSignedPolicySidecars(options.OutputDirectory, envelopeRaw, authoritySPKI); err != nil {
		return a.fail("sign-release-policy", global, releaseSigningError())
	}
	data := map[string]any{
		"schemaVersion": "1", "product": policy.Product, "channel": policy.Channel,
		"purpose": policy.Purpose, "policyGeneration": policy.Generation,
		"policyEnvelopeDigest": releaseDigest(envelopeRaw), "authorityKeyId": authorityKeyID,
		"sidecarDirectory": options.OutputDirectory,
		"formalClaim":      false, "publisherIdentityAttestation": "none", "timeAttestation": "none",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "sign-release-policy", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote signed release-key-policy sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Authority key ID: %s\n", authorityKeyID)
	fmt.Fprintf(a.Stdout, "Policy generation: %d\n", policy.Generation)
	return 0
}

func (a App) runSignReleaseAuthorityTransition(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, signReleaseAuthorityTransitionHelp())
		return 0
	}
	options, err := validateSignReleaseAuthorityTransitionArgs(args)
	if err != nil {
		return a.fail("sign-release-authority-transition", global, err)
	}
	if err := ctx.Err(); err != nil {
		return a.fail("sign-release-authority-transition", global, cancelledReleaseError())
	}
	// The releaseindex implementation owns strict stable reads, key parsing,
	// private-key containment, and atomic exact-three publication.
	dataRoot, err := releaseDataRoot(global)
	if err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	privateKey, nextAuthoritySPKI, err := releaseindex.LoadPrivateKeyForAuthorityTransition(
		options.KeyPath, dataRoot, options.NextAuthorityKeyPath, options.OutputDirectory, workingDirectory,
	)
	if err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	defer clear(privateKey)
	envelopeRaw, previousAuthoritySPKI, err := releaseindex.SignAuthorityTransition(
		nextAuthoritySPKI, options.Generation, privateKey, releaseindex.DefaultAuthorityTransitionScope(),
	)
	if err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	previousAuthorityKeyID, err := releaseindex.PublicKeyID(previousAuthoritySPKI)
	if err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	nextAuthorityKeyID, err := releaseindex.PublicKeyID(nextAuthoritySPKI)
	if err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	if err := releaseindex.PublishAuthorityTransitionSidecars(
		options.OutputDirectory, nextAuthoritySPKI, envelopeRaw, previousAuthoritySPKI,
	); err != nil {
		return a.fail("sign-release-authority-transition", global, releaseSigningError())
	}
	data := map[string]any{
		"schemaVersion": "1", "product": options.Product, "channel": options.Channel,
		"purpose": "release-policy-authority-rotation", "authorityTransitionGeneration": options.Generation,
		"previousAuthorityKeyId": previousAuthorityKeyID, "nextAuthorityKeyId": nextAuthorityKeyID,
		"authorityTransitionEnvelopeDigest": releaseDigest(envelopeRaw), "sidecarDirectory": options.OutputDirectory,
		"formalClaim": false, "capability": "incomplete", "overall": "inconclusive",
		"publisherIdentityAttestation": "none", "timeAttestation": "none",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "sign-release-authority-transition", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote release-authority transition sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Previous authority key ID: %s\n", previousAuthorityKeyID)
	fmt.Fprintf(a.Stdout, "Next authority key ID:     %s\n", nextAuthorityKeyID)
	fmt.Fprintf(a.Stdout, "Authority generation:      %d\n", options.Generation)
	return 0
}

func (a App) runAssembleReleaseAuthorityTransitionChain(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, assembleReleaseAuthorityTransitionChainHelp())
		return 0
	}
	options, err := validateAssembleReleaseAuthorityTransitionChainArgs(args)
	if err != nil {
		return a.fail("assemble-release-authority-transition-chain", global, err)
	}
	if err := ctx.Err(); err != nil {
		return a.fail("assemble-release-authority-transition-chain", global, cancelledReleaseError())
	}
	// Parse shape above before any I/O. From here, all inputs are stable,
	// bounded snapshots and no output is created until Build+Verify succeeds.
	explicitRootSPKI, err := releaseindex.ReadPublicKey(options.AuthorityTrustRoot)
	if err != nil {
		return a.fail("assemble-release-authority-transition-chain", global, releaseSigningError())
	}
	hopEnvelopes := make([][]byte, len(options.HopEnvelopePaths))
	hopNextAuthoritySPKIs := make([][]byte, len(options.HopNextAuthorityKeys))
	for index := range options.HopEnvelopePaths {
		hopEnvelopes[index], err = releaseindex.ReadAuthorityTransition(options.HopEnvelopePaths[index])
		if err != nil {
			return a.fail("assemble-release-authority-transition-chain", global, releaseSigningError())
		}
		hopNextAuthoritySPKIs[index], err = releaseindex.ReadPublicKey(options.HopNextAuthorityKeys[index])
		if err != nil {
			return a.fail("assemble-release-authority-transition-chain", global, releaseSigningError())
		}
	}
	scope := releaseindex.DefaultAuthorityTransitionChainScope()
	chainRaw, err := releaseindex.BuildAuthorityTransitionChain(hopEnvelopes, hopNextAuthoritySPKIs, explicitRootSPKI, scope)
	if err != nil {
		return a.fail("assemble-release-authority-transition-chain", global, releaseSigningError())
	}
	verified, err := releaseindex.VerifyAuthorityTransitionChain(
		chainRaw, explicitRootSPKI, hopNextAuthoritySPKIs[len(hopNextAuthoritySPKIs)-1], scope, options.MinimumGeneration,
	)
	if err != nil {
		return a.fail("assemble-release-authority-transition-chain", global, releaseSigningError())
	}
	if err := releaseindex.PublishAuthorityTransitionChainSidecars(
		options.OutputDirectory, chainRaw, explicitRootSPKI, hopNextAuthoritySPKIs[len(hopNextAuthoritySPKIs)-1],
	); err != nil {
		return a.fail("assemble-release-authority-transition-chain", global, releaseSigningError())
	}
	data := map[string]any{
		"schemaVersion": "1", "product": options.Product, "channel": options.Channel,
		"purpose": "release-policy-authority-rotation-chain", "authorityTransitionChainDigest": verified.Digest(),
		"authorityTransitionChainHopCount": verified.HopCount(), "authorityTransitionChainGeneration": verified.TerminalGeneration(),
		"authorityTrustRootKeyId": verified.RootAuthorityKeyID(), "terminalAuthorityKeyId": verified.TerminalAuthorityKeyID(),
		"minimumAuthorityGeneration": options.MinimumGeneration, "sidecarDirectory": options.OutputDirectory,
		"publisherIdentityAttestation": "none", "timeAttestation": "none", "formalClaim": false, "capability": "incomplete", "overall": "inconclusive",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "assemble-release-authority-transition-chain", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote authority transition chain sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Authority transition chain digest: %s\n", verified.Digest())
	fmt.Fprintf(a.Stdout, "Authority transition hops: %d\n", verified.HopCount())
	return 0
}

func (a App) runVerifyReleaseIndex(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, verifyReleaseIndexHelp())
		return 0
	}
	options, err := validateVerifyReleaseIndexArgs(args)
	if err != nil {
		return a.fail("verify-release-index", global, err)
	}
	indexRaw, err := releaseindex.ReadIndex(options.IndexPath)
	if err != nil {
		return a.fail("verify-release-index", global, releaseIntegrityError())
	}
	if options.ExpectedIndexDigest != "" {
		if err := releaseindex.CheckExpectedIndexDigest(indexRaw, options.ExpectedIndexDigest); err != nil {
			return a.fail("verify-release-index", global, releaseIntegrityError())
		}
	}
	if _, err := releaseindex.ParseIndex(indexRaw); err != nil {
		return a.fail("verify-release-index", global, releaseIntegrityError())
	}
	envelopeRaw, err := releaseindex.ReadEnvelope(options.SignaturePath)
	if err != nil {
		return a.fail("verify-release-index", global, releaseSignatureError())
	}
	signerSPKI, err := releaseindex.ReadPublicKey(options.SignerKeyPath)
	if err != nil {
		return a.fail("verify-release-index", global, releaseSignatureError())
	}
	scope := releaseindex.Scope{Product: options.Product, Channel: options.Channel, Purpose: releaseindex.Purpose}
	authenticated, err := releaseindex.AuthenticateSignedIndex(
		indexRaw, envelopeRaw, signerSPKI, scope, options.MinimumReleaseGeneration,
	)
	if err != nil {
		return a.fail("verify-release-index", global, releaseSignatureError())
	}
	var dataRoot string
	var authorityTransition *releaseindex.VerifiedAuthorityTransition
	var authorityTransitionChain *releaseindex.VerifiedAuthorityTransitionChain
	var authorityState releasestate.Result
	var authoritySPKI []byte
	if options.Rotation {
		trustRootSPKI, readErr := releaseindex.ReadPublicKey(options.AuthorityTrustRootPath)
		if readErr != nil {
			return a.fail("verify-release-index", global, releaseTrustError())
		}
		authoritySPKI, readErr = releaseindex.ReadPublicKey(options.PolicyAuthorityKeyPath)
		if readErr != nil {
			return a.fail("verify-release-index", global, releaseTrustError())
		}
		if options.Chain {
			chainRaw, chainErr := releaseindex.ReadAuthorityTransitionChain(options.AuthorityTransitionChainPath)
			if chainErr != nil {
				return a.fail("verify-release-index", global, releaseTrustError())
			}
			authorityTransitionChain, readErr = releaseindex.VerifyAuthorityTransitionChain(
				chainRaw, trustRootSPKI, authoritySPKI, releaseindex.DefaultAuthorityTransitionChainScope(), options.MinimumAuthorityGeneration,
			)
		} else {
			transitionEnvelope, transitionErr := releaseindex.ReadAuthorityTransition(options.AuthorityTransitionPath)
			if transitionErr != nil {
				return a.fail("verify-release-index", global, releaseTrustError())
			}
			authorityTransition, readErr = releaseindex.VerifyAuthorityTransition(
				transitionEnvelope, trustRootSPKI, authoritySPKI, releaseindex.DefaultAuthorityTransitionScope(), options.MinimumAuthorityGeneration,
			)
		}
		if readErr != nil {
			return a.fail("verify-release-index", global, releaseTrustError())
		}
		if options.PersistState {
			dataRoot, err = releaseDataRoot(global)
			if err != nil {
				return a.fail("verify-release-index", global, releaseStateError())
			}
			if options.Chain {
				authorityState, err = releasestate.ObserveAuthorityChain(
					ctx, dataRoot, authorityTransitionChain.RootAuthorityKeyID(), scope.Product, scope.Channel,
					authorityTransitionChain.TerminalGeneration(), authorityTransitionChain.Digest(),
				)
			} else {
				authorityState, err = releasestate.ObserveAuthority(
					ctx, dataRoot, authorityTransition.PreviousAuthorityKeyID(), scope.Product, scope.Channel,
					authorityTransition.Generation(), authorityTransition.PayloadDigest(),
				)
			}
			if err != nil {
				return a.fail("verify-release-index", global, releaseStateError())
			}
		}
	} else {
		authoritySPKI, err = releaseindex.ReadPublicKey(options.PolicyAuthorityKeyPath)
		if err != nil {
			return a.fail("verify-release-index", global, releaseTrustError())
		}
	}
	policyEnvelope, err := releaseindex.ReadPolicy(options.PolicyEnvelopePath)
	if err != nil {
		return a.fail("verify-release-index", global, releaseTrustError())
	}
	policy, err := releaseindex.VerifyPolicy(
		policyEnvelope, authoritySPKI, scope, options.MinimumPolicyGeneration,
	)
	if err != nil {
		return a.fail("verify-release-index", global, releaseTrustError())
	}
	var policyState releasestate.Result
	if options.PersistState {
		if !options.Rotation {
			dataRoot, err = releaseDataRoot(global)
			if err != nil {
				return a.fail("verify-release-index", global, releaseStateError())
			}
		}
	}
	if options.PersistState {
		policyState, err = releasestate.ObservePolicy(
			ctx, dataRoot, policy.AuthorityKeyID(), scope.Product, scope.Channel,
			policy.Generation(), policy.PayloadDigest(),
		)
		if err != nil {
			return a.fail("verify-release-index", global, releaseStateError())
		}
	}
	verified, err := releaseindex.AuthorizeSignedIndex(authenticated, policy)
	if err != nil {
		return a.fail("verify-release-index", global, releaseTrustError())
	}
	if err := releaseindex.VerifyArtifacts(options.ArtifactRoot, verified); err != nil {
		return a.fail("verify-release-index", global, releaseIntegrityError())
	}
	var releaseState releasestate.Result
	if options.PersistState {
		releaseState, err = releasestate.ObserveIndex(
			ctx, dataRoot, policy.AuthorityKeyID(), scope.Product, scope.Channel,
			verified.ReleaseGeneration(), verified.IndexDigest(),
		)
		if err != nil {
			return a.fail("verify-release-index", global, releaseStateError())
		}
	}
	index := verified.Index()
	report := releaseIndexVerificationReport{
		SchemaVersion: "1", IndexIntegrity: "valid", ArtifactIntegrity: "valid", SignatureValidity: "valid",
		ReleaseSignerKeyID: verified.SignerKeyID(), TrustDecision: "accepted",
		TrustBasis: "release-key-policy-v1", TrustRootKeyID: policy.AuthorityKeyID(),
		PolicyPayloadDigest: policy.PayloadDigest(), PolicyEnvelopeDigest: policy.EnvelopeDigest(),
		PolicyGeneration: policy.Generation(), MinimumPolicyGeneration: options.MinimumPolicyGeneration,
		ReleaseIndexDigest: verified.IndexDigest(), ReleaseIndexEnvelopeDigest: verified.EnvelopeDigest(),
		Product: index.Product, Channel: index.Channel, ProductVersion: index.ProductVersion,
		ReleaseGeneration: index.ReleaseGeneration, MinimumReleaseGeneration: options.MinimumReleaseGeneration,
		PublisherIdentityAttestation: "none", TimeAttestation: "none",
		FormalClaim: false, Capability: "incomplete", Overall: "inconclusive",
	}
	if options.Rotation && !options.Chain {
		report.TrustBasis = "release-key-policy-v1+authority-transition-v1"
		report.TrustRootKeyID = authorityTransition.PreviousAuthorityKeyID()
		report.PolicyAuthorityKeyID = authorityTransition.NextAuthorityKeyID()
		report.AuthorityTransitionPayloadDigest = authorityTransition.PayloadDigest()
		report.AuthorityTransitionEnvelopeDigest = authorityTransition.EnvelopeDigest()
		report.AuthorityTransitionGeneration = authorityTransition.Generation()
		report.MinimumAuthorityTransitionGeneration = options.MinimumAuthorityGeneration
		if options.PersistState {
			report.AuthorityTransitionStateEvaluation = string(authorityState.Evaluation)
			report.AuthorityTransitionStateGeneration = authorityState.Generation
		}
	}
	if options.Chain {
		report.TrustBasis = "release-key-policy-v1+authority-transition-chain-v1"
		report.TrustRootKeyID = authorityTransitionChain.RootAuthorityKeyID()
		report.PolicyAuthorityKeyID = authorityTransitionChain.TerminalAuthorityKeyID()
		report.AuthorityTransitionChainDigest = authorityTransitionChain.Digest()
		report.AuthorityTransitionChainHopCount = uint64(authorityTransitionChain.HopCount())
		report.AuthorityTransitionChainGeneration = authorityTransitionChain.TerminalGeneration()
		report.MinimumAuthorityTransitionGeneration = options.MinimumAuthorityGeneration
		if options.PersistState {
			report.AuthorityTransitionChainStateEvaluation = string(authorityState.Evaluation)
			report.AuthorityTransitionChainStateGeneration = authorityState.Generation
		}
	}
	if options.PersistState {
		report.PolicyStateEvaluation = string(policyState.Evaluation)
		report.PolicyStateGeneration = policyState.Generation
		report.ReleaseStateEvaluation = string(releaseState.Evaluation)
		report.ReleaseStateGeneration = releaseState.Generation
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "verify-release-index", Status: "ok", Data: report})
	}
	writeReleaseIndexReport(a.Stdout, report)
	return 0
}

func releaseDataRoot(global globalOptions) (string, error) {
	root := global.DataDir
	if root == "" {
		value, err := defaultDataDir()
		if err != nil {
			return "", releaseStateError()
		}
		root = value
	}
	if err := rejectRepositoryLocalDataRoot(root); err != nil {
		return "", releaseStateError()
	}
	return root, nil
}

func releaseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeReleaseIndexReport(output io.Writer, report releaseIndexVerificationReport) {
	fmt.Fprintf(output, "Index integrity:       %s\n", strings.ToUpper(report.IndexIntegrity))
	fmt.Fprintf(output, "Artifact integrity:    %s\n", strings.ToUpper(report.ArtifactIntegrity))
	fmt.Fprintf(output, "Signature validity:    %s\n", strings.ToUpper(report.SignatureValidity))
	fmt.Fprintf(output, "Trust decision:        %s\n", strings.ToUpper(report.TrustDecision))
	fmt.Fprintf(output, "Trust basis:           %s\n", report.TrustBasis)
	fmt.Fprintf(output, "Release signer key ID: %s\n", report.ReleaseSignerKeyID)
	fmt.Fprintf(output, "Authority root key ID: %s\n", report.TrustRootKeyID)
	if report.AuthorityTransitionPayloadDigest != "" {
		fmt.Fprintf(output, "Policy authority key ID: %s\n", report.PolicyAuthorityKeyID)
		fmt.Fprintf(output, "Authority transition generation: %d\n", report.AuthorityTransitionGeneration)
		fmt.Fprintf(output, "Minimum authority generation: %d\n", report.MinimumAuthorityTransitionGeneration)
		if report.AuthorityTransitionStateEvaluation != "" {
			fmt.Fprintf(output, "Authority transition state: %s\n", strings.ToUpper(report.AuthorityTransitionStateEvaluation))
		}
	}
	if report.AuthorityTransitionChainDigest != "" {
		fmt.Fprintf(output, "Policy authority key ID: %s\n", report.PolicyAuthorityKeyID)
		fmt.Fprintf(output, "Authority transition chain digest: %s\n", report.AuthorityTransitionChainDigest)
		fmt.Fprintf(output, "Authority transition chain hops: %d\n", report.AuthorityTransitionChainHopCount)
		fmt.Fprintf(output, "Authority transition terminal generation: %d\n", report.AuthorityTransitionChainGeneration)
		fmt.Fprintf(output, "Minimum authority generation: %d\n", report.MinimumAuthorityTransitionGeneration)
		if report.AuthorityTransitionChainStateEvaluation != "" {
			fmt.Fprintf(output, "Authority transition chain state: %s\n", strings.ToUpper(report.AuthorityTransitionChainStateEvaluation))
		}
	}
	fmt.Fprintf(output, "Release generation:    %d\n", report.ReleaseGeneration)
	fmt.Fprintf(output, "Publisher identity:    %s\n", strings.ToUpper(report.PublisherIdentityAttestation))
	fmt.Fprintf(output, "Trusted time:          %s\n", strings.ToUpper(report.TimeAttestation))
	fmt.Fprintf(output, "Capability:            %s\n", strings.ToUpper(report.Capability))
	fmt.Fprintf(output, "Overall:               %s\n", strings.ToUpper(report.Overall))
}

func releaseCommandHelpRequested(args []string) bool {
	return len(args) == 1 && (args[0] == "--help" || args[0] == "-h")
}

func signReleaseIndexHelp() string {
	return `Usage:
  repopass sign-release-index --artifact-root DIR --product-version 0.1.0-alpha.33 --release-generation N --key PRIVATE.pem --out-dir NEW_DIR

Builds a canonical exact artifact index, signs it with Ed25519, and atomically
publishes three external sidecars. The signer companion is not a trust root.
`
}

func signReleasePolicyHelp() string {
	return `Usage:
  repopass sign-release-policy --policy POLICY.json --key AUTHORITY_PRIVATE.pem --out-dir NEW_DIR

Signs one canonical purpose-separated release-key-policy-v1 payload and
publishes the policy envelope plus authority public-key companion.
`
}

func verifyReleaseIndexHelp() string {
	return `Usage:
  repopass-verify verify-release-index --index FILE --signature FILE --signer-key FILE --artifact-root DIR --policy-envelope FILE --policy-authority-key FILE --product repopass --channel alpha --minimum-policy-generation N --minimum-release-generation N (--persist-release-state | --expect-release-index-digest sha256:HEX) [(--authority-transition FILE | --authority-transition-chain FILE) --authority-trust-root FILE --minimum-authority-generation N]

Acceptance is relative only to the explicit authority root and purpose-separated
policy supplied for this invocation. Publisher identity and trusted time remain
unattested.
`
}

func assembleReleaseAuthorityTransitionChainHelp() string {
	return `Usage:
  repopass assemble-release-authority-transition-chain --hop-envelope FILE --hop-next-authority-key FILE [repeat 2..8 in order] --authority-trust-root FILE --product repopass --channel alpha --minimum-authority-generation N --out-dir NEW_DIR

Authenticates and atomically publishes exactly three offline authority-chain
sidecars. The root and terminal companions are not implicit trust anchors.
`
}

func signReleaseAuthorityTransitionHelp() string {
	return `Usage:
  repopass sign-release-authority-transition --next-authority-key FILE --generation N --product repopass --channel alpha --key PREVIOUS_AUTHORITY_PRIVATE.pem --out-dir NEW_DIR

Signs a one-hop, previous-authority-authorized release policy authority
transition and atomically publishes exactly three external sidecars. The
previous-root companion is not implicitly trusted.
`
}

func releaseBuildError() error {
	return domain.NewError(domain.CodeEvidenceBuildFailed, domain.SeverityHigh,
		"The external release index could not be built from an exact safe artifact root.")
}

func releaseSigningError() error {
	return domain.NewError(domain.CodeSigningFailed, domain.SeverityHigh,
		"The release signing inputs or new sidecar destination were not accepted.")
}

func releaseIntegrityError() error {
	return domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical,
		"The external release index or exact artifact set failed integrity verification.")
}

func releaseSignatureError() error {
	return domain.NewError(domain.CodeAttestationInvalid, domain.SeverityCritical,
		"The release-index signature or signer companion is invalid.")
}

func releaseTrustError() error {
	return domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityCritical,
		"The release index was not accepted relative to the explicit authority root.")
}

func releaseStateError() error {
	return domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityCritical,
		"The purpose-separated release state is unavailable, rolled back, or equivocated.")
}

func cancelledReleaseError() error {
	return domain.NewError(domain.CodeCancelled, domain.SeverityHigh, "The release operation was cancelled.")
}
