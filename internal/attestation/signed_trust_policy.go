package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/schemas"
)

const (
	MaxSignedOfflineTrustPolicyEnvelopeBytes = 96 << 10
	SignedOfflineTrustPolicyPayloadType      = "application/vnd.repopass.offline-trust-policy.v2+json"
	MaxTrustPolicyGeneration                 = uint64(9007199254740991)
)

var (
	ErrSignedOfflineTrustPolicyInvalid               = errors.New("signed offline trust policy is invalid")
	ErrSignedOfflineTrustPolicyTooLarge              = errors.New("signed offline trust policy exceeds 98304 bytes")
	ErrSignedOfflineTrustPolicyAuthorityRoleConflict = errors.New("signed offline trust policy authority role conflict")
)

// signedOfflineTrustPolicyAuthorityRoleConflict preserves the generic invalid
// boundary while allowing an already authenticated caller to classify the
// exact authority/evidence-signer collision without exposing policy content.
type signedOfflineTrustPolicyAuthorityRoleConflict struct{}

func (signedOfflineTrustPolicyAuthorityRoleConflict) Error() string {
	return ErrSignedOfflineTrustPolicyInvalid.Error()
}

func (signedOfflineTrustPolicyAuthorityRoleConflict) Is(target error) bool {
	return target == ErrSignedOfflineTrustPolicyInvalid || target == ErrSignedOfflineTrustPolicyAuthorityRoleConflict
}

type signedOfflineTrustPolicyEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

type offlineTrustPolicyV2Document struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	Generation     uint64                  `json:"generation"`
	KeyAlgorithm   string                  `json:"keyAlgorithm"`
	KeyIDAlgorithm string                  `json:"keyIdAlgorithm"`
	Keys           []offlineTrustPolicyKey `json:"keys"`
}

// SignedOfflineTrustPolicy is authenticated against a caller-supplied
// canonical authority SPKI. Its payload remains private until its DSSE
// signature has verified.
type SignedOfflineTrustPolicy struct {
	authenticated  bool
	keyStatus      map[string]trustKeyStatus
	payloadDigest  string
	envelopeDigest string
	authorityKeyID string
	generation     uint64
}

// ValidateTrustPolicyAuthorityKey canonicalizes the separate authority SPKI
// before a caller reads an untrusted policy envelope.
func ValidateTrustPolicyAuthorityKey(raw []byte) error {
	if _, _, err := parsePublicKey(raw); err != nil {
		return ErrSignedOfflineTrustPolicyInvalid
	}
	return nil
}

func (p *SignedOfflineTrustPolicy) PayloadDigest() string {
	if p == nil {
		return ""
	}
	return p.payloadDigest
}
func (p *SignedOfflineTrustPolicy) EnvelopeDigest() string {
	if p == nil {
		return ""
	}
	return p.envelopeDigest
}
func (p *SignedOfflineTrustPolicy) AuthorityKeyID() string {
	if p == nil {
		return ""
	}
	return p.authorityKeyID
}
func (p *SignedOfflineTrustPolicy) Generation() uint64 {
	if p == nil {
		return 0
	}
	return p.generation
}

// ParseSignedOfflineTrustPolicy authenticates one exact canonical v2 envelope
// before parsing its payload. It never returns payload-derived metadata on an
// invalid envelope, key ID, or signature.
func ParseSignedOfflineTrustPolicy(raw, authorityPEM []byte) (*SignedOfflineTrustPolicy, error) {
	if len(raw) > MaxSignedOfflineTrustPolicyEnvelopeBytes {
		return nil, ErrSignedOfflineTrustPolicyTooLarge
	}
	if len(raw) == 0 || bytes.Contains(raw, []byte{'\r'}) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	authority, authorityDER, err := parsePublicKey(authorityPEM)
	if err != nil {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	if err := schemas.ValidateOfflineTrustPolicyV2EnvelopeJSON(raw); err != nil {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	var envelope signedOfflineTrustPolicyEnvelope
	if err := decodeCanonicalJSON(raw, MaxSignedOfflineTrustPolicyEnvelopeBytes, &envelope); err != nil ||
		envelope.PayloadType != SignedOfflineTrustPolicyPayloadType || len(envelope.Signatures) != 1 {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	authorityKeyID := digestBytes(authorityDER)
	if envelope.Signatures[0].KeyID != authorityKeyID {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	payload, err := decodeBase64Bounded(envelope.Payload, MaxOfflineTrustPolicyBytes)
	if err != nil {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	signature, err := decodeBase64Bounded(envelope.Signatures[0].Sig, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(authority, pae(envelope.PayloadType, payload), signature) {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}

	policy, err := parseOfflineTrustPolicyV2(payload)
	if err != nil {
		return nil, err
	}
	// A policy-authority key is purpose-separated from evidence signers. The
	// issuer and publisher already reject this role collision; enforce the same
	// invariant for every externally authored policy accepted by the consumer.
	if _, selfListed := policy.keyStatus[authorityKeyID]; selfListed {
		return nil, signedOfflineTrustPolicyAuthorityRoleConflict{}
	}
	return &SignedOfflineTrustPolicy{
		authenticated:  true,
		keyStatus:      policy.keyStatus,
		payloadDigest:  policy.digest,
		envelopeDigest: digestBytes(raw),
		authorityKeyID: authorityKeyID,
		generation:     policy.generation,
	}, nil
}

type parsedOfflineTrustPolicyV2 struct {
	keyStatus  map[string]trustKeyStatus
	digest     string
	generation uint64
}

func parseOfflineTrustPolicyV2(raw []byte) (*parsedOfflineTrustPolicyV2, error) {
	if len(raw) == 0 || len(raw) > MaxOfflineTrustPolicyBytes || bytes.Contains(raw, []byte{'\r'}) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	if err := schemas.ValidateOfflineTrustPolicyV2JSON(raw); err != nil {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	var document offlineTrustPolicyV2Document
	if err := json.Unmarshal(raw, &document); err != nil || document.Generation == 0 || document.Generation > MaxTrustPolicyGeneration {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	canonical, err := canonicaljson.Marshal(document)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrSignedOfflineTrustPolicyInvalid
	}
	statuses := make(map[string]trustKeyStatus, len(document.Keys))
	previous := ""
	for index, key := range document.Keys {
		if !validKeyID(key.KeyID) || (index > 0 && previous >= key.KeyID) {
			return nil, ErrSignedOfflineTrustPolicyInvalid
		}
		previous = key.KeyID
		statuses[key.KeyID] = key.Status
	}
	sum := sha256.Sum256(raw)
	return &parsedOfflineTrustPolicyV2{keyStatus: statuses, digest: "sha256:" + hex.EncodeToString(sum[:]), generation: document.Generation}, nil
}

func (p *SignedOfflineTrustPolicy) EvaluateSignerKeyID(signerKeyID string) (TrustDecision, error) {
	if p == nil || !validKeyID(signerKeyID) {
		return TrustDecisionNotListed, ErrSignedOfflineTrustPolicyInvalid
	}
	switch p.keyStatus[signerKeyID] {
	case trustKeyStatusTrusted:
		return TrustDecisionTrusted, nil
	case trustKeyStatusRevoked:
		return TrustDecisionRevoked, nil
	default:
		return TrustDecisionNotListed, nil
	}
}

// VerifyWithSignedOfflineTrustPolicy applies an already-authenticated v2
// policy only after normal bundle verification has produced the recomputed
// embedded signer key ID.
func VerifyWithSignedOfflineTrustPolicy(bundle []byte, policy *SignedOfflineTrustPolicy, minimum uint64) (VerificationReport, error) {
	report, err := Verify(bundle, nil)
	if err != nil && domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
		return report, err
	}
	report, err = VerifySignedOfflineTrustPolicyFloor(report, policy, minimum)
	if err != nil {
		return report, err
	}
	return VerifySignedOfflineTrustPolicySigner(report, policy)
}

// VerifyAcceptedWithSignedOfflineTrustPolicy releases claims only when the
// authenticated policy accepts the evidence signer and its generation floor.
func VerifyAcceptedWithSignedOfflineTrustPolicy(bundle []byte, policy *SignedOfflineTrustPolicy, minimum uint64) (VerificationReport, AcceptedClaims, error) {
	report, err := VerifyWithSignedOfflineTrustPolicy(bundle, policy, minimum)
	if err != nil {
		return report, AcceptedClaims{}, err
	}
	claims, err := acceptedClaimsFromBundle(bundle)
	if err != nil {
		return VerificationReport{}, AcceptedClaims{}, err
	}
	return report, claims, nil
}

// VerifySignedOfflineTrustPolicyFloor attaches authenticated signed-policy
// metadata and enforces the caller-selected generation floor. It deliberately
// does not evaluate the evidence signer: callers using local monotonic policy
// state must observe an authenticated floor-qualified policy before deciding
// whether that signer is trusted.
func VerifySignedOfflineTrustPolicyFloor(report VerificationReport, policy *SignedOfflineTrustPolicy, minimum uint64) (VerificationReport, error) {
	report.TrustBasis = "signed-offline-policy-v2"
	if policy == nil || !policy.authenticated || minimum == 0 || minimum > MaxTrustPolicyGeneration {
		report.TrustDecision = "rejected"
		report.TrustReason = "invalid-or-unavailable"
		// A missing or unauthenticated policy supplies no signature-authenticated
		// facts. In particular, it must not be represented as an invalid
		// signature: no policy signature was successfully available to verify.
		return report, signedOfflineTrustPolicyUnavailableError()
	}
	report.TrustPolicyDigest = policy.PayloadDigest()
	report.TrustPolicyEnvelopeDigest = policy.EnvelopeDigest()
	report.TrustPolicyAuthorityKeyID = policy.AuthorityKeyID()
	report.TrustPolicyGeneration = policy.Generation()
	report.MinimumTrustPolicyGeneration = minimum
	report.TrustPolicySignatureValidity = "valid"
	if policy.Generation() < minimum {
		report.TrustDecision = "rejected"
		report.TrustReason = "generation-below-minimum"
		return report, signedOfflineTrustPolicyGenerationError()
	}
	return report, nil
}

// VerifySignedOfflineTrustPolicySigner evaluates the recomputed embedded
// signer against an authenticated, floor-qualified signed policy. It is kept
// separate from floor validation so a caller can interpose persistent local
// state without releasing accepted claims prematurely.
func VerifySignedOfflineTrustPolicySigner(report VerificationReport, policy *SignedOfflineTrustPolicy) (VerificationReport, error) {
	if policy == nil || !policy.authenticated {
		report.TrustBasis = "signed-offline-policy-v2"
		report.TrustDecision = "rejected"
		report.TrustReason = "invalid-or-unavailable"
		return report, signedOfflineTrustPolicyUnavailableError()
	}
	decision, err := policy.EvaluateSignerKeyID(report.SignerKeyID)
	if err != nil {
		report.TrustDecision = "rejected"
		report.TrustReason = "invalid-or-unavailable"
		return report, signedOfflineTrustPolicyUnavailableError()
	}
	switch decision {
	case TrustDecisionTrusted:
		report.TrustDecision = "accepted"
		report.TrustReason = "trusted"
		return report, nil
	case TrustDecisionRevoked:
		report.TrustDecision = "rejected"
		report.TrustReason = "revoked"
		return report, signedOfflineTrustPolicyDecisionError("The verified signer is revoked by the signed offline trust policy.", report.TrustReason)
	default:
		report.TrustDecision = "rejected"
		report.TrustReason = "not-listed"
		return report, signedOfflineTrustPolicyDecisionError("The verified signer is not listed by the signed offline trust policy.", report.TrustReason)
	}
}

// evaluateSignedOfflineTrustPolicy remains the internal combined helper used
// by the Alpha20 unit coverage. Alpha21 callers that persist local state use
// the exported floor and signer stages above instead.
func evaluateSignedOfflineTrustPolicy(report VerificationReport, policy *SignedOfflineTrustPolicy, minimum uint64) (VerificationReport, error) {
	report, err := VerifySignedOfflineTrustPolicyFloor(report, policy, minimum)
	if err != nil {
		return report, err
	}
	return VerifySignedOfflineTrustPolicySigner(report, policy)
}

// VerifyAcceptedSignedOfflineTrustPolicySigner evaluates a previously
// authenticated, floor-qualified policy against the embedded signer before it
// releases replay claims. A caller may invoke it only after any opt-in local
// state gate has accepted the same policy.
func VerifyAcceptedSignedOfflineTrustPolicySigner(bundle []byte, report VerificationReport, policy *SignedOfflineTrustPolicy) (VerificationReport, AcceptedClaims, error) {
	report, err := VerifySignedOfflineTrustPolicySigner(report, policy)
	if err != nil {
		return report, AcceptedClaims{}, err
	}
	claims, err := acceptedClaimsFromBundle(bundle)
	if err != nil {
		return VerificationReport{}, AcceptedClaims{}, err
	}
	return report, claims, nil
}

// RejectSignedOfflineTrustPolicyState turns a local state failure into the
// fixed public untrusted result. Callers must pass only contract reason
// values; no local path, parser, lock, or OS detail is exposed.
func RejectSignedOfflineTrustPolicyState(report VerificationReport, reason string) (VerificationReport, error) {
	switch reason {
	case "state-generation-rollback", "state-generation-equivocation", "state-unavailable":
	default:
		reason = "state-unavailable"
	}
	report.TrustDecision = "rejected"
	report.TrustReason = reason
	err := untrustedSignatureError("The local signed trust-policy state cannot accept this policy.", "rejected")
	typed := err.(*domain.Error)
	typed.Details["trustBasis"] = "signed-offline-policy-v2"
	typed.Details["trustReason"] = reason
	return report, err
}
