package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/releaseindex"
)

type offlineTrustPolicyAuthorityTransitionData struct {
	SchemaVersion                     string `json:"schemaVersion"`
	Purpose                           string `json:"purpose"`
	AuthorityTransitionGeneration     uint64 `json:"authorityTransitionGeneration"`
	PreviousAuthorityKeyID            string `json:"previousAuthorityKeyId"`
	NextAuthorityKeyID                string `json:"nextAuthorityKeyId"`
	AuthorityTransitionPayloadDigest  string `json:"authorityTransitionPayloadDigest"`
	AuthorityTransitionEnvelopeDigest string `json:"authorityTransitionEnvelopeDigest"`
	SidecarDirectory                  string `json:"sidecarDirectory"`
	PublisherIdentityAttestation      string `json:"publisherIdentityAttestation"`
	TimeAttestation                   string `json:"timeAttestation"`
	FormalClaim                       bool   `json:"formalClaim"`
	Capability                        string `json:"capability"`
	Overall                           string `json:"overall"`
}

func (a App) runSignOfflineTrustPolicyAuthorityTransition(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, signOfflineTrustPolicyAuthorityTransitionHelp())
		return 0
	}
	options, err := validateSignOfflineTrustPolicyAuthorityTransitionArgs(args)
	if err != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, err)
	}
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, cancelledOfflineTrustPolicyAuthorityTransitionError())
	}

	// Snapshot the public terminal before private-key I/O. The same bounded
	// reader is used again immediately before publication to reject drift.
	nextAuthoritySPKI, err := a.readOfflineTrustPolicyAuthorityKey(options.NextAuthorityKeyPath)
	if err != nil || attestation.ValidateTrustPolicyAuthorityKey(nextAuthoritySPKI) != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, cancelledOfflineTrustPolicyAuthorityTransitionError())
	}
	dataRoot, err := releaseDataRoot(global)
	if err != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	previousAuthorityPrivate, err := attestation.LoadPrivateKeyForArtifacts(
		options.KeyPath, dataRoot, options.OutputDirectory, "", workingDirectory,
	)
	if err != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	defer clear(previousAuthorityPrivate)
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, cancelledOfflineTrustPolicyAuthorityTransitionError())
	}

	envelopeRaw, previousAuthoritySPKI, signed, err := attestation.SignOfflineTrustPolicyAuthorityTransition(
		nextAuthoritySPKI, options.Generation, previousAuthorityPrivate,
	)
	if err != nil || signed == nil || signed.Generation() != options.Generation ||
		signed.PreviousAuthorityKeyID() == "" || signed.NextAuthorityKeyID() == "" ||
		signed.PayloadDigest() == "" || signed.EnvelopeDigest() != releaseDigest(envelopeRaw) {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, cancelledOfflineTrustPolicyAuthorityTransitionError())
	}
	currentNextAuthoritySPKI, err := a.readOfflineTrustPolicyAuthorityKey(options.NextAuthorityKeyPath)
	if err != nil || !bytes.Equal(nextAuthoritySPKI, currentNextAuthoritySPKI) {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	verified, err := attestation.VerifyOfflineTrustPolicyAuthorityTransition(
		envelopeRaw, previousAuthoritySPKI, nextAuthoritySPKI, options.Generation,
	)
	if err != nil || verified == nil || verified.Generation() != signed.Generation() ||
		verified.PreviousAuthorityKeyID() != signed.PreviousAuthorityKeyID() ||
		verified.NextAuthorityKeyID() != signed.NextAuthorityKeyID() ||
		verified.PayloadDigest() != signed.PayloadDigest() || verified.EnvelopeDigest() != signed.EnvelopeDigest() {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}
	if err := releaseindex.PublishSignedOfflineTrustPolicyAuthorityTransitionSidecars(
		options.OutputDirectory, nextAuthoritySPKI, envelopeRaw, previousAuthoritySPKI,
	); err != nil {
		return a.fail("sign-offline-trust-policy-authority-transition", global, offlineTrustPolicyAuthorityTransitionSigningError())
	}

	data := offlineTrustPolicyAuthorityTransitionData{
		SchemaVersion: "1", Purpose: "offline-trust-policy-authority-rotation", AuthorityTransitionGeneration: verified.Generation(),
		PreviousAuthorityKeyID: verified.PreviousAuthorityKeyID(), NextAuthorityKeyID: verified.NextAuthorityKeyID(),
		AuthorityTransitionPayloadDigest: verified.PayloadDigest(), AuthorityTransitionEnvelopeDigest: verified.EnvelopeDigest(),
		SidecarDirectory: options.OutputDirectory, PublisherIdentityAttestation: "none", TimeAttestation: "none",
		FormalClaim: false, Capability: "incomplete", Overall: "inconclusive",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "sign-offline-trust-policy-authority-transition", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote offline trust-policy authority-transition sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Previous authority key ID: %s\n", data.PreviousAuthorityKeyID)
	fmt.Fprintf(a.Stdout, "Next authority key ID:     %s\n", data.NextAuthorityKeyID)
	fmt.Fprintf(a.Stdout, "Authority generation:      %d\n", data.AuthorityTransitionGeneration)
	fmt.Fprintln(a.Stdout, "Publisher identity attestation: NONE")
	fmt.Fprintln(a.Stdout, "Time attestation:               NONE")
	return 0
}

func (a App) readOfflineTrustPolicyAuthorityKey(path string) ([]byte, error) {
	if a.Deps.OfflineTrustPolicyAuthoritySnapshot != nil {
		return a.Deps.OfflineTrustPolicyAuthoritySnapshot(path)
	}
	return attestation.ReadTrustPolicyAuthorityKey(path)
}

func signOfflineTrustPolicyAuthorityTransitionHelp() string {
	return `Usage:
  repopass sign-offline-trust-policy-authority-transition --next-authority-key NEXT_AUTHORITY_PUBLIC.pem --generation N --key PREVIOUS_AUTHORITY_PRIVATE.pem --out-dir NEW_DIR

Builds and signs one canonical one-hop offline trust-policy authority transition,
self-verifies the exact tuple, and atomically publishes exactly three companions.
Neither public-key companion is a trust anchor; verification requires an explicit
previous root and explicit terminal authority through an independent trusted path.
`
}

func offlineTrustPolicyAuthorityTransitionSigningError() error {
	return domain.NewError(domain.CodeSigningFailed, domain.SeverityHigh,
		"The offline trust-policy authority-transition signing inputs or new sidecar destination were not accepted.")
}

func cancelledOfflineTrustPolicyAuthorityTransitionError() error {
	return domain.NewError(domain.CodeCancelled, domain.SeverityHigh,
		"The offline trust-policy authority-transition operation was cancelled.")
}
