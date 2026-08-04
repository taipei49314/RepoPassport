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

type offlineTrustPolicyIssuanceData struct {
	SchemaVersion                string `json:"schemaVersion"`
	PolicyGeneration             uint64 `json:"policyGeneration"`
	TrustedSignerCount           int    `json:"trustedSignerCount"`
	RevokedSignerCount           int    `json:"revokedSignerCount"`
	TotalSignerCount             int    `json:"totalSignerCount"`
	PolicyPayloadDigest          string `json:"policyPayloadDigest"`
	PolicyEnvelopeDigest         string `json:"policyEnvelopeDigest"`
	AuthorityKeyID               string `json:"authorityKeyId"`
	SidecarDirectory             string `json:"sidecarDirectory"`
	PublisherIdentityAttestation string `json:"publisherIdentityAttestation"`
	TimeAttestation              string `json:"timeAttestation"`
	FormalClaim                  bool   `json:"formalClaim"`
	Capability                   string `json:"capability"`
	Overall                      string `json:"overall"`
}

func (a App) runSignOfflineTrustPolicy(ctx context.Context, global globalOptions, args []string) int {
	if releaseCommandHelpRequested(args) {
		fmt.Fprint(a.Stdout, signOfflineTrustPolicyHelp())
		return 0
	}
	options, err := validateSignOfflineTrustPolicyArgs(args)
	if err != nil {
		return a.fail("sign-offline-trust-policy", global, err)
	}
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy", global, cancelledOfflineTrustPolicyIssuanceError())
	}

	snapshots := make([][]byte, len(options.SignerKeys))
	issuerKeys := make([]attestation.OfflineTrustPolicySignerKey, len(options.SignerKeys))
	trustedCount := 0
	for index, input := range options.SignerKeys {
		if ctx.Err() != nil {
			return a.fail("sign-offline-trust-policy", global, cancelledOfflineTrustPolicyIssuanceError())
		}
		raw, readErr := a.readOfflineTrustPolicySignerKey(input.Path)
		if readErr != nil {
			return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
		}
		snapshots[index] = raw
		issuerKeys[index] = attestation.OfflineTrustPolicySignerKey{SPKI: append([]byte(nil), raw...), Decision: input.Decision}
		if input.Decision == attestation.TrustDecisionTrusted {
			trustedCount++
		}
	}

	dataRoot, err := releaseDataRoot(global)
	if err != nil {
		return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
	}
	privateKey, err := attestation.LoadPrivateKeyForArtifacts(
		options.KeyPath, dataRoot, options.OutputDirectory, "", workingDirectory,
	)
	if err != nil {
		return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
	}
	defer clear(privateKey)
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy", global, cancelledOfflineTrustPolicyIssuanceError())
	}

	envelopeRaw, authoritySPKI, signed, err := attestation.SignOfflineTrustPolicy(options.Generation, issuerKeys, privateKey)
	if err != nil || signed == nil {
		return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
	}
	verified, err := attestation.ParseSignedOfflineTrustPolicy(envelopeRaw, authoritySPKI)
	if err != nil || verified == nil || verified.Generation() != options.Generation ||
		verified.PayloadDigest() != signed.PayloadDigest() || verified.EnvelopeDigest() != signed.EnvelopeDigest() ||
		verified.AuthorityKeyID() != signed.AuthorityKeyID() || verified.EnvelopeDigest() != releaseDigest(envelopeRaw) {
		return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
	}
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy", global, cancelledOfflineTrustPolicyIssuanceError())
	}

	for index, input := range options.SignerKeys {
		if ctx.Err() != nil {
			return a.fail("sign-offline-trust-policy", global, cancelledOfflineTrustPolicyIssuanceError())
		}
		current, readErr := a.readOfflineTrustPolicySignerKey(input.Path)
		if readErr != nil || !bytes.Equal(current, snapshots[index]) {
			return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
		}
	}
	if ctx.Err() != nil {
		return a.fail("sign-offline-trust-policy", global, cancelledOfflineTrustPolicyIssuanceError())
	}
	if err := releaseindex.PublishSignedOfflineTrustPolicySidecars(options.OutputDirectory, envelopeRaw, authoritySPKI); err != nil {
		return a.fail("sign-offline-trust-policy", global, offlineTrustPolicySigningError())
	}

	data := offlineTrustPolicyIssuanceData{
		SchemaVersion: "1", PolicyGeneration: options.Generation,
		TrustedSignerCount: trustedCount, RevokedSignerCount: len(options.SignerKeys) - trustedCount, TotalSignerCount: len(options.SignerKeys),
		PolicyPayloadDigest: verified.PayloadDigest(), PolicyEnvelopeDigest: verified.EnvelopeDigest(), AuthorityKeyID: verified.AuthorityKeyID(),
		SidecarDirectory: options.OutputDirectory, PublisherIdentityAttestation: "none", TimeAttestation: "none",
		FormalClaim: false, Capability: "incomplete", Overall: "inconclusive",
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "sign-offline-trust-policy", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Wrote signed offline trust-policy sidecars: %s\n", options.OutputDirectory)
	fmt.Fprintf(a.Stdout, "Policy generation: %d\n", data.PolicyGeneration)
	fmt.Fprintf(a.Stdout, "Authority key ID:  %s\n", data.AuthorityKeyID)
	fmt.Fprintf(a.Stdout, "Policy signers:    %d trusted, %d revoked\n", data.TrustedSignerCount, data.RevokedSignerCount)
	fmt.Fprintln(a.Stdout, "Publisher identity attestation: NONE")
	fmt.Fprintln(a.Stdout, "Time attestation:               NONE")
	return 0
}

func (a App) readOfflineTrustPolicySignerKey(path string) ([]byte, error) {
	if a.Deps.OfflineTrustPolicySignerSnapshot != nil {
		return a.Deps.OfflineTrustPolicySignerSnapshot(path)
	}
	return attestation.ReadTrustKey(path)
}

func signOfflineTrustPolicyHelp() string {
	return `Usage:
  repopass sign-offline-trust-policy --generation N (--trusted-signer-key FILE | --revoked-signer-key FILE) [repeat, 1..32 combined] --key AUTHORITY_PRIVATE.pem --out-dir NEW_DIR

Builds and signs one canonical offline-trust-policy-v2 document, self-verifies
it, and atomically publishes exactly two sidecars. The authority companion is
not a trust anchor; verifier trust still requires an independently supplied key.
`
}

func offlineTrustPolicySigningError() error {
	return domain.NewError(domain.CodeSigningFailed, domain.SeverityHigh,
		"The offline trust-policy signing inputs or new sidecar destination were not accepted.")
}

func cancelledOfflineTrustPolicyIssuanceError() error {
	return domain.NewError(domain.CodeCancelled, domain.SeverityHigh,
		"The offline trust-policy issuance operation was cancelled.")
}
