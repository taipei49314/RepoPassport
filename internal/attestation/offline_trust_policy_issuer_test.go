package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"sort"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

type issuerTestSigner struct {
	input OfflineTrustPolicySignerKey
	keyID string
}

func issuerTestPrivate(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
}

func issuerTestSPKI(t *testing.T, private ed25519.PrivateKey) ([]byte, string) {
	t.Helper()
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("test private key did not expose an Ed25519 public key")
	}
	spki, der, err := marshalPublicKey(public)
	if err != nil {
		t.Fatalf("marshal test SPKI: %v", err)
	}
	return spki, digestBytes(der)
}

func issuerTestFailure(t *testing.T, generation uint64, keys []OfflineTrustPolicySignerKey, authority ed25519.PrivateKey) {
	t.Helper()
	envelope, spki, verified, err := SignOfflineTrustPolicy(generation, keys, authority)
	if err != ErrOfflineTrustPolicySigningFailed {
		t.Fatalf("error = %v, want exact fixed signing error", err)
	}
	if envelope != nil || spki != nil || verified != nil {
		t.Fatalf("failure leaked a partial result: envelope=%t spki=%t policy=%t", envelope != nil, spki != nil, verified != nil)
	}
}

func TestSignOfflineTrustPolicyCanonicalDeterministicAndSelfVerified(t *testing.T) {
	authority := issuerTestPrivate(0xa1)
	authorityWant, authorityID := issuerTestSPKI(t, authority)

	signers := make([]issuerTestSigner, 0, 3)
	for index, seed := range []byte{0x11, 0x22, 0x33} {
		spki, keyID := issuerTestSPKI(t, issuerTestPrivate(seed))
		decision := TrustDecisionTrusted
		if index == 1 {
			decision = TrustDecisionRevoked
		}
		signers = append(signers, issuerTestSigner{
			input: OfflineTrustPolicySignerKey{SPKI: spki, Decision: decision},
			keyID: keyID,
		})
	}
	sort.Slice(signers, func(left, right int) bool { return signers[left].keyID > signers[right].keyID })
	descending := make([]OfflineTrustPolicySignerKey, len(signers))
	ascending := make([]OfflineTrustPolicySignerKey, len(signers))
	for index, signer := range signers {
		descending[index] = signer.input
		ascending[len(signers)-1-index] = signer.input
	}

	envelope, authoritySPKI, verified, err := SignOfflineTrustPolicy(17, descending, authority)
	if err != nil {
		t.Fatalf("SignOfflineTrustPolicy: %v", err)
	}
	reorderedEnvelope, reorderedAuthority, reorderedVerified, err := SignOfflineTrustPolicy(17, ascending, authority)
	if err != nil {
		t.Fatalf("SignOfflineTrustPolicy reordered: %v", err)
	}
	if !bytes.Equal(envelope, reorderedEnvelope) || !bytes.Equal(authoritySPKI, reorderedAuthority) {
		t.Fatal("equivalent signer sets did not produce byte-identical output")
	}
	if !bytes.Equal(authoritySPKI, authorityWant) || verified == nil || reorderedVerified == nil {
		t.Fatal("authority companion or self-verified policy is missing")
	}
	if verified.Generation() != 17 || verified.AuthorityKeyID() != authorityID ||
		verified.EnvelopeDigest() != digestBytes(envelope) ||
		reorderedVerified.EnvelopeDigest() != verified.EnvelopeDigest() {
		t.Fatalf("unexpected verified metadata: generation=%d authority=%q envelope=%q", verified.Generation(), verified.AuthorityKeyID(), verified.EnvelopeDigest())
	}

	var wire signedOfflineTrustPolicyEnvelope
	if err := json.Unmarshal(envelope, &wire); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	canonicalEnvelope, err := canonicaljson.Marshal(wire)
	if err != nil || !bytes.Equal(envelope, canonicalEnvelope) {
		t.Fatalf("envelope is not canonical: %v", err)
	}
	if wire.PayloadType != SignedOfflineTrustPolicyPayloadType || len(wire.Signatures) != 1 || wire.Signatures[0].KeyID != authorityID {
		t.Fatalf("unexpected DSSE contract: %#v", wire)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(wire.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var document offlineTrustPolicyV2Document
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode payload JSON: %v", err)
	}
	canonicalPayload, err := canonicaljson.Marshal(document)
	if err != nil || !bytes.Equal(payload, canonicalPayload) {
		t.Fatalf("payload is not canonical: %v", err)
	}
	if document.SchemaVersion != "2" || document.Generation != 17 || document.KeyAlgorithm != "ed25519" || document.KeyIDAlgorithm != "spki-sha256" || len(document.Keys) != len(signers) {
		t.Fatalf("unexpected policy document: %#v", document)
	}
	previous := ""
	for _, key := range document.Keys {
		if key.KeyID <= previous || key.KeyID == authorityID {
			t.Fatalf("policy keys are not strictly sorted and role-separated: %#v", document.Keys)
		}
		previous = key.KeyID
		decision, evaluateErr := verified.EvaluateSignerKeyID(key.KeyID)
		if evaluateErr != nil || (decision != TrustDecisionTrusted && decision != TrustDecisionRevoked) {
			t.Fatalf("self-verified decision for %q = %q, %v", key.KeyID, decision, evaluateErr)
		}
		if (key.Status == trustKeyStatusTrusted) != (decision == TrustDecisionTrusted) {
			t.Fatalf("wire status %q and verified decision %q differ", key.Status, decision)
		}
	}
}

func TestSignOfflineTrustPolicyGenerationAndSignerCountBounds(t *testing.T) {
	authority := issuerTestPrivate(0xf0)
	oneSPKI, _ := issuerTestSPKI(t, issuerTestPrivate(1))
	one := []OfflineTrustPolicySignerKey{{SPKI: oneSPKI, Decision: TrustDecisionTrusted}}

	for _, generation := range []uint64{1, MaxTrustPolicyGeneration} {
		if _, _, verified, err := SignOfflineTrustPolicy(generation, one, authority); err != nil || verified == nil || verified.Generation() != generation {
			t.Fatalf("generation %d: policy=%t error=%v", generation, verified != nil, err)
		}
	}
	issuerTestFailure(t, 0, one, authority)
	issuerTestFailure(t, MaxTrustPolicyGeneration+1, one, authority)
	issuerTestFailure(t, 1, nil, authority)

	maximum := make([]OfflineTrustPolicySignerKey, maxOfflineTrustPolicySignerKeys)
	for index := range maximum {
		spki, _ := issuerTestSPKI(t, issuerTestPrivate(byte(index+1)))
		maximum[index] = OfflineTrustPolicySignerKey{SPKI: spki, Decision: TrustDecisionTrusted}
	}
	if _, _, verified, err := SignOfflineTrustPolicy(1, maximum, authority); err != nil || verified == nil {
		t.Fatalf("32 signer keys: policy=%t error=%v", verified != nil, err)
	}
	tooMany := append(append([]OfflineTrustPolicySignerKey(nil), maximum...), OfflineTrustPolicySignerKey{SPKI: oneSPKI, Decision: TrustDecisionRevoked})
	issuerTestFailure(t, 1, tooMany, authority)
}

func TestSignOfflineTrustPolicyRejectsInvalidSignerRolesAndEncoding(t *testing.T) {
	authority := issuerTestPrivate(0xe1)
	signerSPKI, _ := issuerTestSPKI(t, issuerTestPrivate(0xe2))
	authoritySPKI, _ := issuerTestSPKI(t, authority)

	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{
		{SPKI: signerSPKI, Decision: TrustDecisionTrusted},
		{SPKI: signerSPKI, Decision: TrustDecisionTrusted},
	}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{
		{SPKI: signerSPKI, Decision: TrustDecisionTrusted},
		{SPKI: signerSPKI, Decision: TrustDecisionRevoked},
	}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: signerSPKI, Decision: TrustDecisionNotListed}}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: signerSPKI, Decision: TrustDecision("disabled")}}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: authoritySPKI, Decision: TrustDecisionTrusted}}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: nil, Decision: TrustDecisionTrusted}}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: []byte("PRIVATE-CONTENT-MUST-NOT-LEAK"), Decision: TrustDecisionTrusted}}, authority)
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: append(append([]byte(nil), signerSPKI...), '\n'), Decision: TrustDecisionTrusted}}, authority)

	nonEd25519, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate non-Ed25519 test key: %v", err)
	}
	nonEd25519DER, err := x509.MarshalPKIXPublicKey(&nonEd25519.PublicKey)
	if err != nil {
		t.Fatalf("marshal non-Ed25519 test key: %v", err)
	}
	nonEd25519SPKI := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: nonEd25519DER})
	issuerTestFailure(t, 1, []OfflineTrustPolicySignerKey{{SPKI: nonEd25519SPKI, Decision: TrustDecisionRevoked}}, authority)
}

func TestSignOfflineTrustPolicyRejectsMalformedAuthorityWithoutPartialResult(t *testing.T) {
	signerSPKI, _ := issuerTestSPKI(t, issuerTestPrivate(0xd1))
	keys := []OfflineTrustPolicySignerKey{{SPKI: signerSPKI, Decision: TrustDecisionTrusted}}
	issuerTestFailure(t, 1, keys, nil)
	issuerTestFailure(t, 1, keys, ed25519.PrivateKey(bytes.Repeat([]byte{0}, ed25519.PrivateKeySize-1)))
	issuerTestFailure(t, 1, keys, ed25519.PrivateKey(bytes.Repeat([]byte{0}, ed25519.PrivateKeySize)))

	inconsistent := append(ed25519.PrivateKey(nil), issuerTestPrivate(0xd2)...)
	inconsistent[len(inconsistent)-1] ^= 0xff
	issuerTestFailure(t, 1, keys, inconsistent)
}
