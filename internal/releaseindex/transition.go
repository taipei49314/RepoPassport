package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/schemas"
)

const (
	AuthorityTransitionPurpose          = "release-policy-authority-rotation"
	AuthorityTransitionPayloadType      = "application/vnd.repopass.release-authority-transition.v1+json"
	MaxAuthorityTransitionBytes         = 16 << 10
	MaxAuthorityTransitionEnvelopeBytes = 32 << 10
)

var ErrAuthorityTransitionInvalid = errors.New("release authority transition is invalid")

// AuthorityTransition is the canonical one-hop old-root-authorized policy
// authority transition. Key adjacency alone never confers trust.
type AuthorityTransition struct {
	SchemaVersion          string `json:"schemaVersion"`
	Product                string `json:"product"`
	Channel                string `json:"channel"`
	Purpose                string `json:"purpose"`
	Generation             uint64 `json:"generation"`
	KeyAlgorithm           string `json:"keyAlgorithm"`
	KeyIDAlgorithm         string `json:"keyIdAlgorithm"`
	PreviousAuthorityKeyID string `json:"previousAuthorityKeyId"`
	NextAuthorityKeyID     string `json:"nextAuthorityKeyId"`
}

// VerifiedAuthorityTransition exposes only facts authenticated by the
// explicit previous trust root and bound to the explicit next policy key.
type VerifiedAuthorityTransition struct {
	transition     AuthorityTransition
	payloadDigest  string
	envelopeDigest string
}

func DefaultAuthorityTransitionScope() Scope {
	return Scope{Product: Product, Channel: Channel, Purpose: AuthorityTransitionPurpose}
}

func (v *VerifiedAuthorityTransition) PreviousAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.transition.PreviousAuthorityKeyID
}

func (v *VerifiedAuthorityTransition) NextAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.transition.NextAuthorityKeyID
}

func (v *VerifiedAuthorityTransition) Generation() uint64 {
	if v == nil {
		return 0
	}
	return v.transition.Generation
}

func (v *VerifiedAuthorityTransition) PayloadDigest() string {
	if v == nil {
		return ""
	}
	return v.payloadDigest
}

func (v *VerifiedAuthorityTransition) EnvelopeDigest() string {
	if v == nil {
		return ""
	}
	return v.envelopeDigest
}

func (v *VerifiedAuthorityTransition) Scope() Scope {
	if v == nil {
		return Scope{}
	}
	return Scope{Product: v.transition.Product, Channel: v.transition.Channel, Purpose: v.transition.Purpose}
}

// ParseAuthorityTransitionPayload is an authoring helper. Verification callers
// must use VerifyAuthorityTransition so payload metadata is consumed only after
// the explicitly supplied previous-root signature authenticates.
func ParseAuthorityTransitionPayload(raw []byte) (*AuthorityTransition, error) {
	if !validRawJSON(raw, MaxAuthorityTransitionBytes) || schemas.ValidateReleaseAuthorityTransitionV1JSON(raw) != nil {
		return nil, ErrAuthorityTransitionInvalid
	}
	var transition AuthorityTransition
	if err := decodeExact(raw, &transition); err != nil || validateAuthorityTransition(transition) != nil {
		return nil, ErrAuthorityTransitionInvalid
	}
	canonical, err := canonicaljson.Marshal(transition)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrAuthorityTransitionInvalid
	}
	return &transition, nil
}

// SignAuthorityTransition constructs and signs an exact canonical transition.
// The returned previous SPKI is a companion only; verifiers must still receive
// it through their explicit trust-root input.
func SignAuthorityTransition(nextAuthoritySPKI []byte, generation uint64, previousAuthorityKey ed25519.PrivateKey, scope Scope) ([]byte, []byte, error) {
	if !validAuthorityTransitionScope(scope) || !validGeneration(generation) || !validPrivateKey(previousAuthorityKey) {
		return nil, nil, ErrSigningFailed
	}
	_, nextDER, err := parseCanonicalSPKI(nextAuthoritySPKI)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	previousDER, err := x509.MarshalPKIXPublicKey(previousAuthorityKey.Public())
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	previousSPKI := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: previousDER})
	previousID, nextID := digest(previousDER), digest(nextDER)
	transition := AuthorityTransition{
		SchemaVersion: SchemaVersion, Product: scope.Product, Channel: scope.Channel,
		Purpose: scope.Purpose, Generation: generation, KeyAlgorithm: "ed25519",
		KeyIDAlgorithm: "spki-sha256", PreviousAuthorityKeyID: previousID,
		NextAuthorityKeyID: nextID,
	}
	if err := validateAuthorityTransition(transition); err != nil {
		return nil, nil, ErrSigningFailed
	}
	payload, err := canonicaljson.Marshal(transition)
	if err != nil || len(payload) > MaxAuthorityTransitionBytes {
		return nil, nil, ErrSigningFailed
	}
	envelopeRaw, returnedPreviousSPKI, err := signPayload(AuthorityTransitionPayloadType, payload, previousAuthorityKey)
	if err != nil || len(envelopeRaw) > MaxAuthorityTransitionEnvelopeBytes || !bytes.Equal(previousSPKI, returnedPreviousSPKI) {
		return nil, nil, ErrSigningFailed
	}
	if _, err := VerifyAuthorityTransition(envelopeRaw, previousSPKI, nextAuthoritySPKI, scope, generation); err != nil {
		return nil, nil, ErrSigningFailed
	}
	return envelopeRaw, previousSPKI, nil
}

// VerifyAuthorityTransition authenticates exactly one canonical transition
// under the explicit previous root and binds it to the explicit next key.
func VerifyAuthorityTransition(envelopeRaw, previousAuthoritySPKI, nextAuthoritySPKI []byte, scope Scope, minimumGeneration uint64) (*VerifiedAuthorityTransition, error) {
	if !validAuthorityTransitionScope(scope) || !validGeneration(minimumGeneration) {
		return nil, ErrAuthorityTransitionInvalid
	}
	previousPublic, previousDER, err := parseCanonicalSPKI(previousAuthoritySPKI)
	if err != nil {
		return nil, ErrAuthorityTransitionInvalid
	}
	_, nextDER, err := parseCanonicalSPKI(nextAuthoritySPKI)
	if err != nil {
		return nil, ErrAuthorityTransitionInvalid
	}
	previousID, nextID := digest(previousDER), digest(nextDER)
	if previousID == nextID {
		return nil, ErrAuthorityTransitionInvalid
	}
	payload, envelopeDigest, err := authenticateEnvelope(
		envelopeRaw, AuthorityTransitionPayloadType, previousPublic, previousID,
		MaxAuthorityTransitionEnvelopeBytes, MaxAuthorityTransitionBytes,
	)
	if err != nil {
		return nil, ErrAuthorityTransitionInvalid
	}
	transition, err := ParseAuthorityTransitionPayload(payload)
	if err != nil || transition.Product != scope.Product || transition.Channel != scope.Channel ||
		transition.Purpose != scope.Purpose || transition.PreviousAuthorityKeyID != previousID ||
		transition.NextAuthorityKeyID != nextID || transition.Generation < minimumGeneration {
		return nil, ErrAuthorityTransitionInvalid
	}
	return &VerifiedAuthorityTransition{
		transition: *transition, payloadDigest: digest(payload), envelopeDigest: envelopeDigest,
	}, nil
}

func validateAuthorityTransition(transition AuthorityTransition) error {
	if transition.SchemaVersion != SchemaVersion || transition.Product != Product ||
		transition.Channel != Channel || transition.Purpose != AuthorityTransitionPurpose ||
		!validGeneration(transition.Generation) || transition.KeyAlgorithm != "ed25519" ||
		transition.KeyIDAlgorithm != "spki-sha256" ||
		!validDigest(transition.PreviousAuthorityKeyID) ||
		!validDigest(transition.NextAuthorityKeyID) ||
		transition.PreviousAuthorityKeyID == transition.NextAuthorityKeyID {
		return ErrAuthorityTransitionInvalid
	}
	return nil
}

func validAuthorityTransitionScope(scope Scope) bool {
	return scope == DefaultAuthorityTransitionScope()
}
