package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/canonicaljson"
)

type offlineTrustPolicyPublicationKey struct {
	KeyID  string `json:"keyId"`
	Status string `json:"status"`
}

type offlineTrustPolicyPublicationDocument struct {
	SchemaVersion  string                             `json:"schemaVersion"`
	Generation     uint64                             `json:"generation"`
	KeyAlgorithm   string                             `json:"keyAlgorithm"`
	KeyIDAlgorithm string                             `json:"keyIdAlgorithm"`
	Keys           []offlineTrustPolicyPublicationKey `json:"keys"`
}

func makeOfflineTrustPolicyPublication(t *testing.T, authority ed25519.PrivateKey, authoritySPKI []byte, keys []offlineTrustPolicyPublicationKey) ([]byte, []byte) {
	t.Helper()
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	payload, err := canonicaljson.Marshal(offlineTrustPolicyPublicationDocument{
		SchemaVersion: "2", Generation: 1, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256", Keys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, publishedAuthoritySPKI, err := signPayload(attestation.SignedOfflineTrustPolicyPayloadType, payload, authority)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedAuthoritySPKI, authoritySPKI) {
		t.Fatal("authority public companion drifted")
	}
	return envelopeRaw, authoritySPKI
}

func TestPublishSignedOfflineTrustPolicySidecarsIsExactAtomicAndNoOverwrite(t *testing.T) {
	authority, authoritySPKI := keyPair(t)
	_, signerSPKI := keyPair(t)
	envelopeRaw, authoritySPKI := makeOfflineTrustPolicyPublication(t, authority, authoritySPKI, []offlineTrustPolicyPublicationKey{{KeyID: keyIDFromSPKI(t, signerSPKI), Status: "trusted"}})
	root := t.TempDir()
	output := filepath.Join(root, "published")
	if err := PublishSignedOfflineTrustPolicySidecars(output, envelopeRaw, authoritySPKI); err != nil {
		t.Fatalf("publish: %v", err)
	}
	names, err := directoryNames(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"offline-trust-policy-authority-public-key.pem", "offline-trust-policy.dsse.json"}
	if len(names) != len(want) {
		t.Fatalf("published inventory = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("published inventory = %v, want %v", names, want)
		}
	}
	for name, wantBytes := range map[string][]byte{
		"offline-trust-policy-authority-public-key.pem": authoritySPKI,
		"offline-trust-policy.dsse.json":                envelopeRaw,
	} {
		got, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || !bytes.Equal(got, wantBytes) {
			t.Fatalf("published %s mismatch: err=%v", name, err)
		}
	}
	if err := PublishSignedOfflineTrustPolicySidecars(output, envelopeRaw, authoritySPKI); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("existing output accepted: %v", err)
	}
}

func TestPublishSignedOfflineTrustPolicySidecarsRejectsTamperAndSelfRoleWithoutOutput(t *testing.T) {
	t.Run("tampered envelope", func(t *testing.T) {
		authority, authoritySPKI := keyPair(t)
		_, signerSPKI := keyPair(t)
		envelopeRaw, authoritySPKI := makeOfflineTrustPolicyPublication(t, authority, authoritySPKI, []offlineTrustPolicyPublicationKey{{KeyID: keyIDFromSPKI(t, signerSPKI), Status: "trusted"}})
		tampered := append([]byte(nil), envelopeRaw...)
		tampered[len(tampered)-2] ^= 1
		output := filepath.Join(t.TempDir(), "tampered")
		if err := PublishSignedOfflineTrustPolicySidecars(output, tampered, authoritySPKI); !errors.Is(err, ErrPublishFailed) {
			t.Fatalf("tampered envelope accepted: %v", err)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("tampered publication materialized output: %v", err)
		}
	})
	t.Run("authority self role", func(t *testing.T) {
		authority, authoritySPKI := keyPair(t)
		envelopeRaw, authoritySPKI := makeOfflineTrustPolicyPublication(t, authority, authoritySPKI, []offlineTrustPolicyPublicationKey{{KeyID: keyIDFromSPKI(t, authoritySPKI), Status: "revoked"}})
		output := filepath.Join(t.TempDir(), "self-role")
		if err := PublishSignedOfflineTrustPolicySidecars(output, envelopeRaw, authoritySPKI); !errors.Is(err, ErrPublishFailed) {
			t.Fatalf("authority self-role accepted: %v", err)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("self-role publication materialized output: %v", err)
		}
	})
}
