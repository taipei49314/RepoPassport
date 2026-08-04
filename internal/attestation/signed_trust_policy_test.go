package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/canonicaljson"
)

func TestSignedOfflineTrustPolicyAuthoritySignatureAuthenticatesBeforeParsingV2Payload(t *testing.T) {
	_, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPEM, authorityDER, err := marshalPublicKey(authorityPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	signerID := "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	payload, err := canonicaljson.Marshal(offlineTrustPolicyV2Document{
		SchemaVersion: "2", Generation: 7, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		Keys: []offlineTrustPolicyKey{{KeyID: signerID, Status: trustKeyStatusTrusted}},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedOfflineTrustPolicyEnvelope{
		PayloadType: SignedOfflineTrustPolicyPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: digestBytes(authorityDER),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivate, pae(SignedOfflineTrustPolicyPayloadType, payload))),
		}},
	}
	raw, err := canonicaljson.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParseSignedOfflineTrustPolicy(raw, authorityPEM)
	if err != nil {
		t.Fatalf("ParseSignedOfflineTrustPolicy: %v", err)
	}
	if policy.Generation() != 7 || policy.AuthorityKeyID() != digestBytes(authorityDER) {
		t.Fatalf("unexpected authenticated policy metadata: %#v", policy)
	}
	if decision, err := policy.EvaluateSignerKeyID(signerID); err != nil || decision != TrustDecisionTrusted {
		t.Fatalf("authenticated signer decision = %q, %v", decision, err)
	}

	envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tampered, err := canonicaljson.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSignedOfflineTrustPolicy(tampered, authorityPEM); err != ErrSignedOfflineTrustPolicyInvalid {
		t.Fatalf("forged signature error = %v", err)
	}
}

func TestSignedOfflineTrustPolicyRejectsBelowMinimum(t *testing.T) {
	policy := &SignedOfflineTrustPolicy{authenticated: true, generation: 2, keyStatus: map[string]trustKeyStatus{}}
	report, err := evaluateSignedOfflineTrustPolicy(VerificationReport{}, policy, 3)
	if err == nil || report.TrustReason != "generation-below-minimum" || report.TrustPolicySignatureValidity != "valid" {
		t.Fatalf("below minimum report = %#v, %v", report, err)
	}
}

func TestSignedOfflineTrustPolicyRejectsSelfListedAuthority(t *testing.T) {
	fixture := newSignedPolicyTestFixture(t)
	authorityID := digestBytes(fixture.authorityDER)
	for _, status := range []trustKeyStatus{trustKeyStatusTrusted, trustKeyStatusRevoked} {
		t.Run(string(status), func(t *testing.T) {
			payload := signedPolicyPayload(t, authorityID, status, 7)
			envelope := fixture.sign(t, payload, SignedOfflineTrustPolicyPayloadType, fixture.authority, authorityID)
			if policy, err := ParseSignedOfflineTrustPolicy(envelope, fixture.authorityPEM); policy != nil ||
				!errors.Is(err, ErrSignedOfflineTrustPolicyInvalid) || !errors.Is(err, ErrSignedOfflineTrustPolicyAuthorityRoleConflict) {
				t.Fatalf("self-listed authority accepted: policy=%#v err=%v", policy, err)
			}
		})
	}
}

type signedPolicyTestFixture struct {
	authorityPEM []byte
	authorityDER []byte
	authority    ed25519.PrivateKey
	other        ed25519.PrivateKey
	signer       string
	otherSigner  string
	payload      []byte
	envelope     []byte
}

func newSignedPolicyTestFixture(t *testing.T) signedPolicyTestFixture {
	t.Helper()
	authority := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	authorityPEM, authorityDER, err := marshalPublicKey(authority.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	fixture := signedPolicyTestFixture{
		authorityPEM: authorityPEM, authorityDER: authorityDER, authority: authority, other: other,
		signer: "sha256:" + strings.Repeat("1", 64), otherSigner: "sha256:" + strings.Repeat("2", 64),
	}
	fixture.payload = signedPolicyPayload(t, fixture.signer, trustKeyStatusTrusted, 7)
	fixture.envelope = fixture.sign(t, fixture.payload, SignedOfflineTrustPolicyPayloadType, authority, digestBytes(authorityDER))
	return fixture
}

func signedPolicyPayload(t *testing.T, signer string, status trustKeyStatus, generation uint64) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(offlineTrustPolicyV2Document{
		SchemaVersion: "2", Generation: generation, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		Keys: []offlineTrustPolicyKey{{KeyID: signer, Status: status}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (fixture signedPolicyTestFixture) sign(t *testing.T, payload []byte, payloadType string, private ed25519.PrivateKey, keyID string) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(signedOfflineTrustPolicyEnvelope{
		PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(private, pae(payloadType, payload))),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedOfflineTrustPolicyAdversarialCanonicalMatrix(t *testing.T) {
	fixture := newSignedPolicyTestFixture(t)
	wrongAuthorityPEM, wrongAuthorityDER, err := marshalPublicKey(fixture.other.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	valid := func(payload []byte) []byte {
		return fixture.sign(t, payload, SignedOfflineTrustPolicyPayloadType, fixture.authority, digestBytes(fixture.authorityDER))
	}
	mutateEnvelope := func(mutate func(*signedOfflineTrustPolicyEnvelope)) []byte {
		var envelope signedOfflineTrustPolicyEnvelope
		if err := decodeCanonicalJSON(fixture.envelope, MaxSignedOfflineTrustPolicyEnvelopeBytes, &envelope); err != nil {
			t.Fatal(err)
		}
		mutate(&envelope)
		raw, err := canonicaljson.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	payloadWith := func(replacement string) []byte {
		return []byte(strings.Replace(string(fixture.payload), `"generation":7`, replacement, 1))
	}
	outerNoncanonical := []byte(`{"signatures":`)
	var base signedOfflineTrustPolicyEnvelope
	if err := decodeCanonicalJSON(fixture.envelope, MaxSignedOfflineTrustPolicyEnvelopeBytes, &base); err != nil {
		t.Fatal(err)
	}
	signatures, err := canonicaljson.Marshal(base.Signatures)
	if err != nil {
		t.Fatal(err)
	}
	outerNoncanonical = append(outerNoncanonical, signatures...)
	outerNoncanonical = append(outerNoncanonical, []byte(`,"payload":"`+base.Payload+`","payloadType":"`+base.PayloadType+`"}`)...)

	tests := []struct {
		name      string
		raw       []byte
		authority []byte
	}{
		{"generation zero", valid(payloadWith(`"generation":0`)), fixture.authorityPEM},
		{"generation max plus one", valid(payloadWith(`"generation":9007199254740992`)), fixture.authorityPEM},
		{"generation fraction", valid(payloadWith(`"generation":1.5`)), fixture.authorityPEM},
		{"generation exponent", valid(payloadWith(`"generation":1e1`)), fixture.authorityPEM},
		{"generation leading zero", valid(payloadWith(`"generation":07`)), fixture.authorityPEM},
		{"payload key order", valid([]byte(strings.Replace(string(fixture.payload), `{"generation":7,"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":`, `{"keyAlgorithm":"ed25519","generation":7,"keyIdAlgorithm":"spki-sha256","keys":`, 1))), fixture.authorityPEM},
		{"payload unknown field", valid(append(append([]byte{}, fixture.payload[:len(fixture.payload)-1]...), []byte(`,"unexpected":true}`)...)), fixture.authorityPEM},
		{"payload duplicate field", valid(append(append([]byte{}, fixture.payload[:len(fixture.payload)-1]...), []byte(`,"generation":7}`)...)), fixture.authorityPEM},
		{"v1 downgrade", valid([]byte(strings.Replace(string(fixture.payload), `"schemaVersion":"2"`, `"schemaVersion":"1"`, 1))), fixture.authorityPEM},
		{"wrong authority", fixture.envelope, wrongAuthorityPEM},
		// authoritySignatureKeyidDomainSeparation: a valid authority signature
		// remains unacceptable when its envelope key ID names another SPKI.
		{"forged key id", fixture.sign(t, fixture.payload, SignedOfflineTrustPolicyPayloadType, fixture.authority, digestBytes(wrongAuthorityDER)), fixture.authorityPEM},
		{"payload tamper", mutateEnvelope(func(envelope *signedOfflineTrustPolicyEnvelope) {
			envelope.Payload = base64.StdEncoding.EncodeToString(append(fixture.payload, ' '))
		}), fixture.authorityPEM},
		{"signature tamper", mutateEnvelope(func(envelope *signedOfflineTrustPolicyEnvelope) {
			envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}), fixture.authorityPEM},
		{"malformed base64", mutateEnvelope(func(envelope *signedOfflineTrustPolicyEnvelope) { envelope.Payload = "!!!!" }), fixture.authorityPEM},
		{"noncanonical base64", mutateEnvelope(func(envelope *signedOfflineTrustPolicyEnvelope) { envelope.Payload = "AB==" }), fixture.authorityPEM},
		{"multiple signatures", mutateEnvelope(func(envelope *signedOfflineTrustPolicyEnvelope) {
			envelope.Signatures = append(envelope.Signatures, envelope.Signatures[0])
		}), fixture.authorityPEM},
		{"wrong payload type", fixture.sign(t, fixture.payload, "application/vnd.repopass.other+json", fixture.authority, digestBytes(fixture.authorityDER)), fixture.authorityPEM},
		{"cross protocol payload type", fixture.sign(t, fixture.payload, "application/vnd.in-toto+json", fixture.authority, digestBytes(fixture.authorityDER)), fixture.authorityPEM},
		{"noncanonical outer", outerNoncanonical, fixture.authorityPEM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if policy, err := ParseSignedOfflineTrustPolicy(test.raw, test.authority); err != ErrSignedOfflineTrustPolicyInvalid || policy != nil {
				t.Fatalf("ParseSignedOfflineTrustPolicy = %#v, %v", policy, err)
			}
		})
	}
}

func TestSignedOfflineTrustPolicySignerDecisionsAndAuthenticationBoundary(t *testing.T) {
	fixture := newSignedPolicyTestFixture(t)
	for _, test := range []struct {
		name       string
		status     trustKeyStatus
		signer     string
		generation uint64
		minimum    uint64
		decision   string
		reason     string
	}{
		{"trusted at floor", trustKeyStatusTrusted, fixture.signer, 7, 7, "accepted", "trusted"},
		{"trusted above floor", trustKeyStatusTrusted, fixture.signer, 8, 7, "accepted", "trusted"},
		{"revoked", trustKeyStatusRevoked, fixture.signer, 7, 7, "rejected", "revoked"},
		{"not listed", trustKeyStatusTrusted, fixture.otherSigner, 7, 7, "rejected", "not-listed"},
		{"below floor", trustKeyStatusTrusted, fixture.signer, 6, 7, "rejected", "generation-below-minimum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policyRaw := signedPolicyPayload(t, fixture.signer, test.status, test.generation)
			if test.name == "not listed" {
				policyRaw = signedPolicyPayload(t, fixture.otherSigner, test.status, test.generation)
			}
			policy, err := ParseSignedOfflineTrustPolicy(fixture.sign(t, policyRaw, SignedOfflineTrustPolicyPayloadType, fixture.authority, digestBytes(fixture.authorityDER)), fixture.authorityPEM)
			if err != nil {
				t.Fatal(err)
			}
			report, evaluationErr := evaluateSignedOfflineTrustPolicy(VerificationReport{SignerKeyID: fixture.signer}, policy, test.minimum)
			if report.TrustDecision != test.decision || report.TrustReason != test.reason || report.TrustPolicySignatureValidity != "valid" ||
				report.TrustPolicyDigest == "" || report.TrustPolicyEnvelopeDigest == "" || report.TrustPolicyAuthorityKeyID == "" || report.TrustPolicyGeneration != test.generation || report.MinimumTrustPolicyGeneration != test.minimum {
				t.Fatalf("report = %#v", report)
			}
			if (test.decision == "accepted") != (evaluationErr == nil) {
				t.Fatalf("evaluation error = %v", evaluationErr)
			}
		})
	}

	for name, policy := range map[string]*SignedOfflineTrustPolicy{"nil": nil, "zero value": {}} {
		t.Run(name, func(t *testing.T) {
			report, err := evaluateSignedOfflineTrustPolicy(VerificationReport{}, policy, 7)
			if err == nil || report.TrustPolicyDigest != "" || report.TrustPolicyEnvelopeDigest != "" || report.TrustPolicyAuthorityKeyID != "" || report.TrustPolicyGeneration != 0 || report.TrustPolicySignatureValidity != "" || report.MinimumTrustPolicyGeneration != 0 {
				t.Fatalf("unauthenticated policy report = %#v, %v", report, err)
			}
		})
	}
}

func TestVerifyAcceptedWithSignedOfflineTrustPolicyDoesNotReleaseRejectedClaims(t *testing.T) {
	fixture := newSignedPolicyTestFixture(t)
	_, signerPrivate := generateKey(t)
	built, err := Build(validResult(t, "inconclusive"), signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	unsignedReport, verifyErr := Verify(built.Bundle, nil)
	if verifyErr == nil || unsignedReport.SignerKeyID == "" {
		t.Fatalf("untrusted bundle report = %#v, %v", unsignedReport, verifyErr)
	}
	revokedPayload := signedPolicyPayload(t, unsignedReport.SignerKeyID, trustKeyStatusRevoked, 7)
	policy, err := ParseSignedOfflineTrustPolicy(fixture.sign(t, revokedPayload, SignedOfflineTrustPolicyPayloadType, fixture.authority, digestBytes(fixture.authorityDER)), fixture.authorityPEM)
	if err != nil {
		t.Fatal(err)
	}
	report, claims, err := VerifyAcceptedWithSignedOfflineTrustPolicy(built.Bundle, policy, 7)
	if err == nil || report.TrustReason != "revoked" || !reflect.DeepEqual(claims, AcceptedClaims{}) {
		t.Fatalf("rejected claims report=%#v claims=%#v err=%v", report, claims, err)
	}
}
