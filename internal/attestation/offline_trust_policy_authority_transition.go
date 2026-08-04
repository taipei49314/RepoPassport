package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/schemas"
)

const (
	OfflineTrustPolicyAuthorityTransitionPurpose          = "offline-trust-policy-authority-rotation"
	OfflineTrustPolicyAuthorityTransitionPayloadType      = "application/vnd.repopass.offline-trust-policy-authority-transition.v1+json"
	MaxOfflineTrustPolicyAuthorityTransitionPayloadBytes  = 16 << 10
	MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes = 32 << 10
)

var (
	ErrOfflineTrustPolicyAuthorityTransitionInvalid       = errors.New("offline trust policy authority transition is invalid")
	ErrOfflineTrustPolicyAuthorityTransitionSigningFailed = errors.New("offline trust policy authority transition signing failed")
)

// OfflineTrustPolicyAuthorityTransition is one canonical, purpose-separated
// old-root-authorized transition to the key that may authenticate v2 offline
// trust policies. Public fields are an authoring representation only; verifier
// callers consume authenticated facts through VerifiedOfflineTrustPolicyAuthorityTransition.
type OfflineTrustPolicyAuthorityTransition struct {
	SchemaVersion          string `json:"schemaVersion"`
	Purpose                string `json:"purpose"`
	PolicyPayloadType      string `json:"policyPayloadType"`
	Generation             uint64 `json:"generation"`
	KeyAlgorithm           string `json:"keyAlgorithm"`
	KeyIDAlgorithm         string `json:"keyIdAlgorithm"`
	PreviousAuthorityKeyID string `json:"previousAuthorityKeyId"`
	NextAuthorityKeyID     string `json:"nextAuthorityKeyId"`
}

type offlineTrustPolicyAuthorityTransitionEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// VerifiedOfflineTrustPolicyAuthorityTransition exposes only facts that were
// authenticated from the explicit previous root and bound to the explicit
// terminal policy-authority key.
type VerifiedOfflineTrustPolicyAuthorityTransition struct {
	transition     OfflineTrustPolicyAuthorityTransition
	payloadDigest  string
	envelopeDigest string
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransition) PreviousAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.transition.PreviousAuthorityKeyID
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransition) NextAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.transition.NextAuthorityKeyID
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransition) Generation() uint64 {
	if v == nil {
		return 0
	}
	return v.transition.Generation
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransition) PayloadDigest() string {
	if v == nil {
		return ""
	}
	return v.payloadDigest
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransition) EnvelopeDigest() string {
	if v == nil {
		return ""
	}
	return v.envelopeDigest
}

// ParseOfflineTrustPolicyAuthorityTransitionPayload is an authoring helper.
// Trust decisions must use VerifyOfflineTrustPolicyAuthorityTransition so no
// payload field is consumed before the explicit-root signature verifies.
func ParseOfflineTrustPolicyAuthorityTransitionPayload(raw []byte) (*OfflineTrustPolicyAuthorityTransition, error) {
	if len(raw) == 0 || len(raw) > MaxOfflineTrustPolicyAuthorityTransitionPayloadBytes ||
		bytes.Contains(raw, []byte{'\r'}) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) ||
		schemas.ValidateOfflineTrustPolicyAuthorityTransitionV1JSON(raw) != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	var transition OfflineTrustPolicyAuthorityTransition
	if err := decodeCanonicalJSON(raw, MaxOfflineTrustPolicyAuthorityTransitionPayloadBytes, &transition); err != nil ||
		validateOfflineTrustPolicyAuthorityTransition(transition) != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	return &transition, nil
}

// ValidateOfflineTrustPolicyAuthorityTransitionKeyPair canonicalizes the
// explicit previous root and terminal authority before a caller reads the
// untrusted transition envelope. The two roles must be held by distinct
// Ed25519 keys.
func ValidateOfflineTrustPolicyAuthorityTransitionKeyPair(previousAuthoritySPKI, nextAuthoritySPKI []byte) error {
	_, previousDER, err := parsePublicKey(previousAuthoritySPKI)
	if err != nil {
		return ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	_, nextDER, err := parsePublicKey(nextAuthoritySPKI)
	if err != nil || subtle.ConstantTimeCompare(previousDER, nextDER) == 1 {
		return ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	return nil
}

// SignOfflineTrustPolicyAuthorityTransition builds a canonical single-hop
// transition, signs it with the previous authority, and authenticates the
// exact tuple again before returning any result.
func SignOfflineTrustPolicyAuthorityTransition(nextAuthoritySPKI []byte, generation uint64, previousAuthority ed25519.PrivateKey) (envelopeRaw, previousAuthoritySPKI []byte, verified *VerifiedOfflineTrustPolicyAuthorityTransition, err error) {
	fail := func() ([]byte, []byte, *VerifiedOfflineTrustPolicyAuthorityTransition, error) {
		return nil, nil, nil, ErrOfflineTrustPolicyAuthorityTransitionSigningFailed
	}
	if generation == 0 || generation > MaxTrustPolicyGeneration || len(previousAuthority) != ed25519.PrivateKeySize {
		return fail()
	}

	normalizedPrevious := ed25519.NewKeyFromSeed(previousAuthority[:ed25519.SeedSize])
	defer clear(normalizedPrevious)
	if subtle.ConstantTimeCompare(previousAuthority, normalizedPrevious) != 1 {
		return fail()
	}
	previousPublic, ok := normalizedPrevious.Public().(ed25519.PublicKey)
	if !ok || len(previousPublic) != ed25519.PublicKeySize {
		return fail()
	}
	previousAuthoritySPKI, previousDER, marshalErr := marshalPublicKey(previousPublic)
	if marshalErr != nil {
		return fail()
	}
	_, nextDER, parseErr := parsePublicKey(nextAuthoritySPKI)
	if parseErr != nil {
		return fail()
	}
	previousID, nextID := digestBytes(previousDER), digestBytes(nextDER)
	if previousID == nextID {
		return fail()
	}

	payload, marshalErr := canonicaljson.Marshal(OfflineTrustPolicyAuthorityTransition{
		SchemaVersion: "1", Purpose: OfflineTrustPolicyAuthorityTransitionPurpose,
		PolicyPayloadType: SignedOfflineTrustPolicyPayloadType, Generation: generation,
		KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		PreviousAuthorityKeyID: previousID, NextAuthorityKeyID: nextID,
	})
	if marshalErr != nil || len(payload) > MaxOfflineTrustPolicyAuthorityTransitionPayloadBytes {
		return fail()
	}
	if parsed, parseErr := ParseOfflineTrustPolicyAuthorityTransitionPayload(payload); parseErr != nil ||
		parsed.Generation != generation || parsed.PreviousAuthorityKeyID != previousID || parsed.NextAuthorityKeyID != nextID {
		return fail()
	}

	signature := ed25519.Sign(normalizedPrevious, pae(OfflineTrustPolicyAuthorityTransitionPayloadType, payload))
	defer clear(signature)
	envelopeRaw, marshalErr = canonicaljson.Marshal(offlineTrustPolicyAuthorityTransitionEnvelope{
		PayloadType: OfflineTrustPolicyAuthorityTransitionPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: previousID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	})
	if marshalErr != nil || len(envelopeRaw) > MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes {
		return fail()
	}
	verified, parseErr = VerifyOfflineTrustPolicyAuthorityTransition(
		envelopeRaw, previousAuthoritySPKI, nextAuthoritySPKI, generation,
	)
	if parseErr != nil || verified == nil || verified.Generation() != generation ||
		verified.PreviousAuthorityKeyID() != previousID || verified.NextAuthorityKeyID() != nextID ||
		verified.PayloadDigest() != digestBytes(payload) || verified.EnvelopeDigest() != digestBytes(envelopeRaw) {
		return fail()
	}
	return envelopeRaw, previousAuthoritySPKI, verified, nil
}

// VerifyOfflineTrustPolicyAuthorityTransition authenticates exactly one
// canonical transition with the explicit previous root, binds the exact
// explicit terminal key, and enforces the caller-supplied authority floor.
func VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, previousAuthoritySPKI, nextAuthoritySPKI []byte, minimumGeneration uint64) (*VerifiedOfflineTrustPolicyAuthorityTransition, error) {
	if minimumGeneration == 0 || minimumGeneration > MaxTrustPolicyGeneration ||
		len(envelopeRaw) == 0 || len(envelopeRaw) > MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes ||
		bytes.Contains(envelopeRaw, []byte{'\r'}) || bytes.HasPrefix(envelopeRaw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	previousPublic, previousDER, err := parsePublicKey(previousAuthoritySPKI)
	if err != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	_, nextDER, err := parsePublicKey(nextAuthoritySPKI)
	if err != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	previousID, nextID := digestBytes(previousDER), digestBytes(nextDER)
	if previousID == nextID || schemas.ValidateOfflineTrustPolicyAuthorityTransitionEnvelopeV1JSON(envelopeRaw) != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}

	var envelope offlineTrustPolicyAuthorityTransitionEnvelope
	if err := decodeCanonicalJSON(envelopeRaw, MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes, &envelope); err != nil ||
		envelope.PayloadType != OfflineTrustPolicyAuthorityTransitionPayloadType || len(envelope.Signatures) != 1 ||
		envelope.Signatures[0].KeyID != previousID {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	payload, err := decodeBase64Bounded(envelope.Payload, MaxOfflineTrustPolicyAuthorityTransitionPayloadBytes)
	if err != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	signature, err := decodeBase64Bounded(envelope.Signatures[0].Sig, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(previousPublic, pae(envelope.PayloadType, payload), signature) {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}

	transition, err := ParseOfflineTrustPolicyAuthorityTransitionPayload(payload)
	if err != nil || transition.PreviousAuthorityKeyID != previousID || transition.NextAuthorityKeyID != nextID ||
		transition.Generation < minimumGeneration {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	return &VerifiedOfflineTrustPolicyAuthorityTransition{
		transition: *transition, payloadDigest: digestBytes(payload), envelopeDigest: digestBytes(envelopeRaw),
	}, nil
}

func validateOfflineTrustPolicyAuthorityTransition(transition OfflineTrustPolicyAuthorityTransition) error {
	if transition.SchemaVersion != "1" || transition.Purpose != OfflineTrustPolicyAuthorityTransitionPurpose ||
		transition.PolicyPayloadType != SignedOfflineTrustPolicyPayloadType || transition.Generation == 0 ||
		transition.Generation > MaxTrustPolicyGeneration || transition.KeyAlgorithm != "ed25519" ||
		transition.KeyIDAlgorithm != "spki-sha256" || !validKeyID(transition.PreviousAuthorityKeyID) ||
		!validKeyID(transition.NextAuthorityKeyID) || transition.PreviousAuthorityKeyID == transition.NextAuthorityKeyID {
		return ErrOfflineTrustPolicyAuthorityTransitionInvalid
	}
	return nil
}
