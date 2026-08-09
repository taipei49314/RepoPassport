package attestation

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

const maxOfflineTrustPolicySignerKeys = 32

// ErrOfflineTrustPolicySigningFailed is the fixed failure boundary for
// rejected policy inputs and post-sign self-verification. It deliberately
// carries no key, policy, or caller-supplied content.
var ErrOfflineTrustPolicySigningFailed = errors.New("offline trust policy signing failed")

// OfflineTrustPolicySignerKey is one canonical Ed25519 SPKI and the decision
// that the issued policy applies to it. Not-listed is an evaluation result,
// not an issuable policy status.
type OfflineTrustPolicySignerKey struct {
	SPKI     []byte
	Decision TrustDecision
}

// SignOfflineTrustPolicy constructs a canonical v2 policy and purpose-
// separated single-signature DSSE envelope. Signer identities are derived
// only from canonical Ed25519 SPKI DER, globally sorted, and required to be
// unique. The authority is role-separated from every policy signer.
//
// Before returning, the exact envelope is authenticated with the exact
// authority SPKI returned to the caller. Every rejected input or internal
// self-check returns the same non-disclosing error.
func SignOfflineTrustPolicy(generation uint64, keys []OfflineTrustPolicySignerKey, authority ed25519.PrivateKey) (envelopeRaw, authoritySPKI []byte, verified *SignedOfflineTrustPolicy, err error) {
	fail := func() ([]byte, []byte, *SignedOfflineTrustPolicy, error) {
		return nil, nil, nil, ErrOfflineTrustPolicySigningFailed
	}
	if generation == 0 || generation > MaxTrustPolicyGeneration || len(keys) == 0 || len(keys) > maxOfflineTrustPolicySignerKeys || len(authority) != ed25519.PrivateKeySize {
		return fail()
	}

	normalizedAuthority := ed25519.NewKeyFromSeed(authority[:ed25519.SeedSize])
	defer clear(normalizedAuthority)
	if subtle.ConstantTimeCompare(authority, normalizedAuthority) != 1 {
		return fail()
	}
	authorityPublic, ok := normalizedAuthority.Public().(ed25519.PublicKey)
	if !ok || len(authorityPublic) != ed25519.PublicKeySize {
		return fail()
	}
	authoritySPKI, authorityDER, marshalErr := marshalPublicKey(authorityPublic)
	if marshalErr != nil {
		return fail()
	}
	authorityKeyID := digestBytes(authorityDER)

	policyKeys := make([]offlineTrustPolicyKey, 0, len(keys))
	decisions := make(map[string]TrustDecision, len(keys))
	for _, key := range keys {
		var status trustKeyStatus
		switch key.Decision {
		case TrustDecisionTrusted:
			status = trustKeyStatusTrusted
		case TrustDecisionRevoked:
			status = trustKeyStatusRevoked
		default:
			return fail()
		}

		_, signerDER, parseErr := parsePublicKey(key.SPKI)
		if parseErr != nil {
			return fail()
		}
		keyID := digestBytes(signerDER)
		if keyID == authorityKeyID {
			return fail()
		}
		if _, exists := decisions[keyID]; exists {
			return fail()
		}
		decisions[keyID] = key.Decision
		policyKeys = append(policyKeys, offlineTrustPolicyKey{KeyID: keyID, Status: status})
	}
	sort.Slice(policyKeys, func(left, right int) bool {
		return policyKeys[left].KeyID < policyKeys[right].KeyID
	})

	payload, marshalErr := canonicaljson.Marshal(offlineTrustPolicyV2Document{
		SchemaVersion:  "2",
		Generation:     generation,
		KeyAlgorithm:   "ed25519",
		KeyIDAlgorithm: "spki-sha256",
		Keys:           policyKeys,
	})
	if marshalErr != nil || len(payload) > MaxOfflineTrustPolicyBytes {
		return fail()
	}
	parsedPayload, parseErr := parseOfflineTrustPolicyV2(payload)
	if parseErr != nil || parsedPayload.generation != generation || parsedPayload.digest != digestBytes(payload) {
		return fail()
	}

	signature := ed25519.Sign(normalizedAuthority, pae(SignedOfflineTrustPolicyPayloadType, payload))
	defer clear(signature)
	envelopeRaw, marshalErr = canonicaljson.Marshal(signedOfflineTrustPolicyEnvelope{
		PayloadType: SignedOfflineTrustPolicyPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: authorityKeyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	})
	if marshalErr != nil || len(envelopeRaw) > MaxSignedOfflineTrustPolicyEnvelopeBytes {
		return fail()
	}

	verified, parseErr = ParseSignedOfflineTrustPolicy(envelopeRaw, authoritySPKI)
	if parseErr != nil || verified == nil || verified.Generation() != generation ||
		verified.AuthorityKeyID() != authorityKeyID || verified.PayloadDigest() != digestBytes(payload) ||
		verified.EnvelopeDigest() != digestBytes(envelopeRaw) {
		return fail()
	}
	for _, policyKey := range policyKeys {
		decision, evaluateErr := verified.EvaluateSignerKeyID(policyKey.KeyID)
		if evaluateErr != nil || decision != decisions[policyKey.KeyID] {
			return fail()
		}
	}
	return envelopeRaw, authoritySPKI, verified, nil
}
