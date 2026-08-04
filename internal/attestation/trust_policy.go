package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/schemas"
)

const MaxOfflineTrustPolicyBytes = 64 << 10

var (
	ErrOfflineTrustPolicyInvalid  = errors.New("offline trust policy is invalid")
	ErrOfflineTrustPolicyTooLarge = errors.New("offline trust policy exceeds 65536 bytes")
	ErrSignerKeyIDInvalid         = errors.New("signer key ID is invalid")
)

type TrustDecision string

const (
	TrustDecisionTrusted   TrustDecision = "trusted"
	TrustDecisionRevoked   TrustDecision = "revoked"
	TrustDecisionNotListed TrustDecision = "not-listed"
)

type trustKeyStatus string

const (
	trustKeyStatusTrusted trustKeyStatus = "trusted"
	trustKeyStatusRevoked trustKeyStatus = "revoked"
)

type offlineTrustPolicyDocument struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	KeyAlgorithm   string                  `json:"keyAlgorithm"`
	KeyIDAlgorithm string                  `json:"keyIdAlgorithm"`
	Keys           []offlineTrustPolicyKey `json:"keys"`
}

type offlineTrustPolicyKey struct {
	KeyID  string         `json:"keyId"`
	Status trustKeyStatus `json:"status"`
}

// OfflineTrustPolicy is an immutable, canonical offline trust policy. Its
// fields are deliberately private so callers cannot alter a policy after its
// canonical bytes and digest have been checked.
type OfflineTrustPolicy struct {
	keyStatus map[string]trustKeyStatus
	digest    string
}

// ParseOfflineTrustPolicy accepts exactly one canonical offline-trust-policy-v1
// document. Alternate whitespace, object-key order, duplicate/unknown fields,
// invalid UTF-8, BOMs, CR bytes, trailing data, and non-strict key ordering are
// rejected. Returned errors are fixed and do not echo policy content.
func ParseOfflineTrustPolicy(raw []byte) (*OfflineTrustPolicy, error) {
	if len(raw) > MaxOfflineTrustPolicyBytes {
		return nil, ErrOfflineTrustPolicyTooLarge
	}
	if len(raw) == 0 || bytes.Contains(raw, []byte{'\r'}) ||
		bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, ErrOfflineTrustPolicyInvalid
	}
	if err := schemas.ValidateOfflineTrustPolicyV1JSON(raw); err != nil {
		return nil, ErrOfflineTrustPolicyInvalid
	}

	var document offlineTrustPolicyDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, ErrOfflineTrustPolicyInvalid
	}
	canonical, err := canonicaljson.Marshal(document)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrOfflineTrustPolicyInvalid
	}

	statuses := make(map[string]trustKeyStatus, len(document.Keys))
	previous := ""
	for index, key := range document.Keys {
		if !validKeyID(key.KeyID) || (index > 0 && previous >= key.KeyID) {
			return nil, ErrOfflineTrustPolicyInvalid
		}
		previous = key.KeyID
		statuses[key.KeyID] = key.Status
	}

	sum := sha256.Sum256(raw)
	return &OfflineTrustPolicy{
		keyStatus: statuses,
		digest:    "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

// Digest returns the SHA-256 digest of the exact canonical policy bytes that
// ParseOfflineTrustPolicy accepted.
func (p *OfflineTrustPolicy) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

// EvaluateSignerKeyID evaluates only the signer key ID supplied by the
// verifier after it has parsed canonical Ed25519 SPKI DER and recomputed
// sha256:<lowercase hex>. Envelope-reported key IDs are not an input here.
func (p *OfflineTrustPolicy) EvaluateSignerKeyID(signerKeyID string) (TrustDecision, error) {
	if p == nil {
		return TrustDecisionNotListed, ErrOfflineTrustPolicyInvalid
	}
	if !validKeyID(signerKeyID) {
		return TrustDecisionNotListed, ErrSignerKeyIDInvalid
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

func validKeyID(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
