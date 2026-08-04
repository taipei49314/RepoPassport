package cli

import (
	"bytes"
	"context"
	"fmt"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/releaseindex"
)

type offlineTrustPolicyAuthorityTransitionChainData struct {
	SchemaVersion                         string `json:"schemaVersion"`
	Purpose                               string `json:"purpose"`
	AuthorityTransitionChainDigest        string `json:"authorityTransitionChainDigest"`
	AuthorityTransitionChainHopCount      uint64 `json:"authorityTransitionChainHopCount"`
	AuthorityTransitionChainGeneration    uint64 `json:"authorityTransitionChainGeneration"`
	AuthorityTransitionChainRootKeyID     string `json:"authorityTransitionChainRootKeyId"`
	AuthorityTransitionChainTerminalKeyID string `json:"authorityTransitionChainTerminalKeyId"`
	MinimumTrustPolicyAuthorityGeneration uint64 `json:"minimumTrustPolicyAuthorityGeneration"`
	SidecarDirectory                      string `json:"sidecarDirectory"`
	PublisherIdentityAttestation          string `json:"publisherIdentityAttestation"`
	TimeAttestation                       string `json:"timeAttestation"`
	FormalClaim                           bool   `json:"formalClaim"`
	Capability                            string `json:"capability"`
	Overall                               string `json:"overall"`
}

func (a App) runAssembleOfflineTrustPolicyAuthorityTransitionChain(ctx context.Context, global globalOptions, args []string) int {
	const command = "assemble-offline-trust-policy-authority-transition-chain"
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, assembleOfflineTrustPolicyAuthorityTransitionChainHelp())
		return 0
	}
	options, err := validateAssembleOfflineTrustPolicyAuthorityTransitionChainArgs(args)
	if err != nil {
		return a.fail(command, global, err)
	}
	if ctx.Err() != nil {
		return a.fail(command, global, cancelledOfflineTrustPolicyAuthorityTransitionChainError())
	}

	rootSPKI, err := a.readOfflineTrustPolicyAuthorityChainRoot(options.AuthorityTrustRoot)
	if err != nil || attestation.ValidateTrustPolicyAuthorityKey(rootSPKI) != nil {
		return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
	}
	hopEnvelopes := make([][]byte, len(options.HopEnvelopePaths))
	hopNextKeys := make([][]byte, len(options.HopNextAuthorityKeys))
	for index := range options.HopEnvelopePaths {
		if ctx.Err() != nil {
			return a.fail(command, global, cancelledOfflineTrustPolicyAuthorityTransitionChainError())
		}
		hopEnvelopes[index], err = attestation.ReadTrustPolicyAuthorityTransition(options.HopEnvelopePaths[index])
		if err != nil {
			return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
		}
		hopNextKeys[index], err = a.readOfflineTrustPolicyAuthorityChainNext(options.HopNextAuthorityKeys[index])
		if err != nil || attestation.ValidateTrustPolicyAuthorityKey(hopNextKeys[index]) != nil {
			return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
		}
	}
	chainRaw, err := attestation.BuildOfflineTrustPolicyAuthorityTransitionChain(hopEnvelopes, hopNextKeys, rootSPKI)
	if err != nil {
		return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
	}
	verified, err := attestation.VerifyOfflineTrustPolicyAuthorityTransitionChain(
		chainRaw, rootSPKI, hopNextKeys[len(hopNextKeys)-1], options.MinimumGeneration,
	)
	if err != nil || verified == nil || verified.HopCount() != uint64(len(hopEnvelopes)) ||
		verified.TerminalGeneration() < options.MinimumGeneration || verified.Digest() == "" {
		return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
	}

	// Re-read every authoring input after full authentication. Publication is
	// allowed only when the complete ordered input tuple remained byte-stable.
	currentRoot, err := a.readOfflineTrustPolicyAuthorityChainRoot(options.AuthorityTrustRoot)
	if err != nil || !bytes.Equal(rootSPKI, currentRoot) {
		return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
	}
	for index := range options.HopEnvelopePaths {
		currentEnvelope, readErr := attestation.ReadTrustPolicyAuthorityTransition(options.HopEnvelopePaths[index])
		if readErr != nil || !bytes.Equal(hopEnvelopes[index], currentEnvelope) {
			return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
		}
		currentKey, readErr := a.readOfflineTrustPolicyAuthorityChainNext(options.HopNextAuthorityKeys[index])
		if readErr != nil || !bytes.Equal(hopNextKeys[index], currentKey) {
			return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
		}
	}
	if ctx.Err() != nil {
		return a.fail(command, global, cancelledOfflineTrustPolicyAuthorityTransitionChainError())
	}
	if err := releaseindex.PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars(
		options.OutputDirectory, hopNextKeys[len(hopNextKeys)-1], chainRaw, rootSPKI,
	); err != nil {
		return a.fail(command, global, offlineTrustPolicyAuthorityTransitionChainBuildError())
	}

	data := offlineTrustPolicyAuthorityTransitionChainData{
		SchemaVersion: "1", Purpose: "offline-trust-policy-authority-rotation-chain",
		AuthorityTransitionChainDigest: verified.Digest(), AuthorityTransitionChainHopCount: verified.HopCount(),
		AuthorityTransitionChainGeneration: verified.TerminalGeneration(), AuthorityTransitionChainRootKeyID: verified.RootAuthorityKeyID(),
		AuthorityTransitionChainTerminalKeyID: verified.TerminalAuthorityKeyID(), MinimumTrustPolicyAuthorityGeneration: options.MinimumGeneration,
		SidecarDirectory: options.OutputDirectory, PublisherIdentityAttestation: "none", TimeAttestation: "none",
		FormalClaim: false, Capability: "incomplete", Overall: "inconclusive",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: command, Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote offline trust-policy authority-transition-chain sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Authority transition chain digest: %s\n", data.AuthorityTransitionChainDigest)
	fmt.Fprintf(a.Stdout, "Authority transition chain hops:   %d\n", data.AuthorityTransitionChainHopCount)
	fmt.Fprintf(a.Stdout, "Authority terminal generation:     %d\n", data.AuthorityTransitionChainGeneration)
	fmt.Fprintln(a.Stdout, "Publisher identity attestation:    NONE")
	fmt.Fprintln(a.Stdout, "Time attestation:                  NONE")
	return 0
}

func (a App) readOfflineTrustPolicyAuthorityChainRoot(path string) ([]byte, error) {
	if a.Deps.OfflineTrustPolicyAuthoritySnapshot != nil {
		return a.Deps.OfflineTrustPolicyAuthoritySnapshot(path)
	}
	return attestation.ReadTrustPolicyAuthorityTransitionRootKey(path)
}

func (a App) readOfflineTrustPolicyAuthorityChainNext(path string) ([]byte, error) {
	if a.Deps.OfflineTrustPolicyAuthoritySnapshot != nil {
		return a.Deps.OfflineTrustPolicyAuthoritySnapshot(path)
	}
	return attestation.ReadTrustPolicyAuthorityTransitionTerminalKey(path)
}

func assembleOfflineTrustPolicyAuthorityTransitionChainHelp() string {
	return `Usage:
  repopass assemble-offline-trust-policy-authority-transition-chain --hop-envelope HOP.dsse.json --hop-next-authority-key NEXT_PUBLIC.pem [repeat each 2..8 times] --trust-policy-authority-trust-root ROOT_PUBLIC.pem --minimum-trust-policy-authority-generation N --out-dir NEW_DIR

Authenticates and assembles one bounded two-through-eight-hop offline trust-policy
authority transition chain, then atomically publishes exactly three companions.
The root and terminal companions are transport material, never trust anchors.
`
}

func offlineTrustPolicyAuthorityTransitionChainBuildError() error {
	return domain.NewError(domain.CodeSigningFailed, domain.SeverityHigh,
		"The offline trust-policy authority-transition-chain inputs or new sidecar destination were not accepted.")
}

func cancelledOfflineTrustPolicyAuthorityTransitionChainError() error {
	return domain.NewError(domain.CodeCancelled, domain.SeverityHigh,
		"The offline trust-policy authority-transition-chain operation was cancelled.")
}
