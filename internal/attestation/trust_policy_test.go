package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

const canonicalTrustPolicy = `{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[{"keyId":"sha256:1111111111111111111111111111111111111111111111111111111111111111","status":"trusted"},{"keyId":"sha256:2222222222222222222222222222222222222222222222222222222222222222","status":"revoked"}],"schemaVersion":"1"}`

func TestOfflineTrustPolicyDigestAndDecisions(t *testing.T) {
	raw := []byte(canonicalTrustPolicy)
	policy, err := ParseOfflineTrustPolicy(raw)
	if err != nil {
		t.Fatalf("ParseOfflineTrustPolicy: %v", err)
	}
	sum := sha256.Sum256(raw)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	if policy.Digest() != wantDigest {
		t.Fatalf("Digest = %q, want %q", policy.Digest(), wantDigest)
	}

	for _, test := range []struct {
		keyID string
		want  TrustDecision
	}{
		{"sha256:" + strings.Repeat("1", 64), TrustDecisionTrusted},
		{"sha256:" + strings.Repeat("2", 64), TrustDecisionRevoked},
		{"sha256:" + strings.Repeat("3", 64), TrustDecisionNotListed},
	} {
		decision, evaluateErr := policy.EvaluateSignerKeyID(test.keyID)
		if evaluateErr != nil || decision != test.want {
			t.Fatalf("EvaluateSignerKeyID(%q) = %q, %v; want %q", test.keyID, decision, evaluateErr, test.want)
		}
	}
}

func TestOfflineTrustPolicyRejectsNonCanonicalAndMalformedDocuments(t *testing.T) {
	validKey := `{"keyId":"sha256:` + strings.Repeat("1", 64) + `","status":"trusted"}`
	canonical := `{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + validKey + `],"schemaVersion":"1"}`
	tests := map[string][]byte{
		"empty":                    nil,
		"leading whitespace":       append([]byte(" "), []byte(canonical)...),
		"trailing newline":         append([]byte(canonical), '\n'),
		"alternate property order": []byte(`{"schemaVersion":"1","keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + validKey + `]}`),
		"duplicate property":       []byte(`{"keyAlgorithm":"ed25519","keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + validKey + `],"schemaVersion":"1"}`),
		"escaped duplicate":        []byte(`{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + validKey + `],"schemaVersion":"1","schema\u0056ersion":"1"}`),
		"unknown property":         []byte(`{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + validKey + `],"schemaVersion":"1","unknown":true}`),
		"trailing JSON":            append([]byte(canonical), []byte(`{}`)...),
		"BOM":                      append([]byte{0xef, 0xbb, 0xbf}, []byte(canonical)...),
		"CR":                       []byte(strings.Replace(canonical, `,"keys"`, ",\r\"keys\"", 1)),
		"invalid UTF-8":            append([]byte(canonical), 0xff),
		"wrong schema":             []byte(strings.Replace(canonical, `"schemaVersion":"1"`, `"schemaVersion":"2"`, 1)),
		"wrong key algorithm":      []byte(strings.Replace(canonical, `"ed25519"`, `"rsa"`, 1)),
		"wrong key ID algorithm":   []byte(strings.Replace(canonical, `"spki-sha256"`, `"raw-sha256"`, 1)),
		"empty keys":               []byte(strings.Replace(canonical, `[`+validKey+`]`, `[]`, 1)),
		"uppercase key ID":         []byte(strings.Replace(canonical, strings.Repeat("1", 64), strings.Repeat("A", 64), 1)),
		"bad status":               []byte(strings.Replace(canonical, `"trusted"`, `"disabled"`, 1)),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseOfflineTrustPolicy(raw)
			if !errors.Is(err, ErrOfflineTrustPolicyInvalid) {
				t.Fatalf("error = %v, want fixed invalid-policy error", err)
			}
		})
	}
}

func TestOfflineTrustPolicyRequiresStrictOrdinalUniqueKeyOrder(t *testing.T) {
	key := func(digit, status string) string {
		return `{"keyId":"sha256:` + strings.Repeat(digit, 64) + `","status":"` + status + `"}`
	}
	document := func(keys string) []byte {
		return []byte(`{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + keys + `],"schemaVersion":"1"}`)
	}
	for name, raw := range map[string][]byte{
		"descending":                 document(key("2", "trusted") + `,` + key("1", "trusted")),
		"duplicate same status":      document(key("1", "trusted") + `,` + key("1", "trusted")),
		"duplicate different status": document(key("1", "revoked") + `,` + key("1", "trusted")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOfflineTrustPolicy(raw); !errors.Is(err, ErrOfflineTrustPolicyInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOfflineTrustPolicyBoundsAndFixedSafeErrors(t *testing.T) {
	tooLarge := make([]byte, MaxOfflineTrustPolicyBytes+1)
	if _, err := ParseOfflineTrustPolicy(tooLarge); !errors.Is(err, ErrOfflineTrustPolicyTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
	policy, err := ParseOfflineTrustPolicy([]byte(canonicalTrustPolicy))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "sha256:short", "sha256:" + strings.Repeat("A", 64)} {
		decision, evaluateErr := policy.EvaluateSignerKeyID(invalid)
		if decision != TrustDecisionNotListed || !errors.Is(evaluateErr, ErrSignerKeyIDInvalid) {
			t.Fatalf("invalid signer result = %q, %v", decision, evaluateErr)
		}
	}
	var nilPolicy *OfflineTrustPolicy
	if decision, evaluateErr := nilPolicy.EvaluateSignerKeyID("sha256:" + strings.Repeat("1", 64)); decision != TrustDecisionNotListed || !errors.Is(evaluateErr, ErrOfflineTrustPolicyInvalid) {
		t.Fatalf("nil policy result = %q, %v", decision, evaluateErr)
	}
}

func TestOfflineTrustPolicyRejectsMoreThanThirtyTwoKeys(t *testing.T) {
	keys := make([]string, 33)
	for index := range keys {
		keys[index] = `{"keyId":"sha256:` + strings.Repeat("0", 62) +
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"[index:index+2] +
			`","status":"trusted"}`
	}
	raw := []byte(`{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` + strings.Join(keys, ",") + `],"schemaVersion":"1"}`)
	if _, err := ParseOfflineTrustPolicy(raw); !errors.Is(err, ErrOfflineTrustPolicyInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestOfflineTrustPolicyVerifierTrustedRevokedNotListedAndClaims(t *testing.T) {
	_, trustedPrivate := generateKey(t)
	trustedBundle, err := Build(validResult(t, "inconclusive"), trustedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPrivate := generateKey(t)
	attackerBundle, err := Build(validResult(t, "inconclusive"), attackerPrivate)
	if err != nil {
		t.Fatal(err)
	}

	trustedPolicy := mustOfflinePolicyForTest(t, map[string]string{
		trustedBundle.SignerKeyID: "trusted",
	})
	report, claims, err := VerifyAcceptedWithOfflineTrustPolicy(trustedBundle.Bundle, trustedPolicy)
	if err != nil || report.SignatureValidity != "valid" || report.TrustDecision != "accepted" ||
		report.TrustBasis != "offline-policy-v1" || report.TrustReason != "trusted" ||
		report.TrustPolicyDigest != trustedPolicy.Digest() || claims.Plan.PlanDigest == "" {
		t.Fatalf("trusted report=%#v claims=%#v err=%v", report, claims, err)
	}

	revokedPolicy := mustOfflinePolicyForTest(t, map[string]string{
		trustedBundle.SignerKeyID: "revoked",
	})
	report, claims, err = VerifyAcceptedWithOfflineTrustPolicy(trustedBundle.Bundle, revokedPolicy)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted ||
		report.SignatureValidity != "valid" || report.TrustDecision != "rejected" ||
		report.TrustReason != "revoked" || !reflect.DeepEqual(claims, AcceptedClaims{}) {
		t.Fatalf("revoked report=%#v claims=%#v err=%v", report, claims, err)
	}

	report, claims, err = VerifyAcceptedWithOfflineTrustPolicy(attackerBundle.Bundle, trustedPolicy)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted ||
		report.SignatureValidity != "valid" || report.TrustDecision != "rejected" ||
		report.TrustReason != "not-listed" || !reflect.DeepEqual(claims, AcceptedClaims{}) {
		t.Fatalf("attacker resign report=%#v claims=%#v err=%v", report, claims, err)
	}
}

func TestOfflineTrustPolicyVerifierRejectsNilAndForgedEnvelopeKeyIDBeforePolicy(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "inconclusive"), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	report, err := VerifyWithOfflineTrustPolicy(built.Bundle, nil)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted ||
		report.TrustDecision != "rejected" || report.TrustReason != "invalid-or-unavailable" {
		t.Fatalf("nil policy report=%#v err=%v", report, err)
	}

	forgedKeyID := "sha256:" + strings.Repeat("0", 64)
	files := parsedFiles(t, built.Bundle)
	var envelope Envelope
	mustJSON(t, files[signaturePath], &envelope)
	envelope.Signatures[0].KeyID = forgedKeyID
	files[signaturePath] = mustCanonical(t, envelope)
	forgedBundle, err := buildCanonicalTar(files)
	if err != nil {
		t.Fatal(err)
	}
	forgedPolicy := mustOfflinePolicyForTest(t, map[string]string{forgedKeyID: "trusted"})
	report, err = VerifyWithOfflineTrustPolicy(forgedBundle, forgedPolicy)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid || report.TrustBasis != "" ||
		report.TrustDecision != "" {
		t.Fatalf("forged envelope key ID report=%#v err=%v", report, err)
	}
}

func TestOfflineTrustPolicyPrivacyBlockedBeforePolicyEvaluation(t *testing.T) {
	_, privateKey := generateKey(t)
	blocked := rebuildResultWithPrivacyMarker(t, validResult(t, "verified"), "synthetic.user@example.invalid")
	bundle := buildPrivacyAttackBundle(t, blocked, privateKey)
	_, publicKeyDER, err := marshalPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	policy := mustOfflinePolicyForTest(t, map[string]string{
		digestBytes(publicKeyDER): "trusted",
	})

	report, err := VerifyWithOfflineTrustPolicy(bundle, policy)
	if domain.ErrorCodeOf(err) != domain.CodeEvidencePrivacyBlocked || report.TrustDecision != "" ||
		report.TrustBasis != "" || report.TrustPolicyDigest != "" || report.TrustReason != "" {
		t.Fatalf("privacy-blocked policy report=%#v err=%v", report, err)
	}
}

func TestOfflineTrustPolicyLegacyVerifyAndVerifyAcceptedRemainPolicyFieldFree(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "inconclusive"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := Verify(built.Bundle, nil)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || unknown.TrustDecision != "unknown" ||
		unknown.TrustBasis != "" || unknown.TrustPolicyDigest != "" || unknown.TrustReason != "" {
		t.Fatalf("legacy unknown report=%#v err=%v", unknown, err)
	}
	accepted, claims, err := VerifyAccepted(built.Bundle, built.PublicKeyPEM)
	if err != nil || accepted.TrustDecision != "accepted" || accepted.TrustBasis != "" ||
		accepted.TrustPolicyDigest != "" || accepted.TrustReason != "" || claims.Plan.PlanDigest == "" {
		t.Fatalf("legacy accepted report=%#v claims=%#v err=%v", accepted, claims, err)
	}
}

func mustOfflinePolicyForTest(t *testing.T, statuses map[string]string) *OfflineTrustPolicy {
	t.Helper()
	keyIDs := make([]string, 0, len(statuses))
	for keyID := range statuses {
		keyIDs = append(keyIDs, keyID)
	}
	for left := 0; left < len(keyIDs); left++ {
		for right := left + 1; right < len(keyIDs); right++ {
			if keyIDs[right] < keyIDs[left] {
				keyIDs[left], keyIDs[right] = keyIDs[right], keyIDs[left]
			}
		}
	}
	keys := make([]string, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		keys = append(keys, `{"keyId":"`+keyID+`","status":"`+statuses[keyID]+`"}`)
	}
	raw := []byte(`{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[` +
		strings.Join(keys, ",") + `],"schemaVersion":"1"}`)
	policy, err := ParseOfflineTrustPolicy(raw)
	if err != nil {
		t.Fatalf("parse policy: %v\n%s", err, raw)
	}
	return policy
}
