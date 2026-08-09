package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
)

func makeOfflineTrustPolicyAuthorityTransitionPublication(t *testing.T) (ed25519.PrivateKey, []byte, []byte, []byte) {
	t.Helper()
	previous, previousSPKI := keyPair(t)
	_, nextSPKI := keyPair(t)
	envelopeRaw, returnedPrevious, verified, err := attestation.SignOfflineTrustPolicyAuthorityTransition(nextSPKI, 1, previous)
	if err != nil || verified == nil || !bytes.Equal(previousSPKI, returnedPrevious) {
		t.Fatalf("sign transition verified=%#v err=%v", verified, err)
	}
	return previous, previousSPKI, nextSPKI, envelopeRaw
}

func TestPublishSignedOfflineTrustPolicyAuthorityTransitionSidecarsExactAtomicNoOverwrite(t *testing.T) {
	_, previousSPKI, nextSPKI, envelopeRaw := makeOfflineTrustPolicyAuthorityTransitionPublication(t)
	output := filepath.Join(t.TempDir(), "published")
	if err := PublishSignedOfflineTrustPolicyAuthorityTransitionSidecars(output, nextSPKI, envelopeRaw, previousSPKI); err != nil {
		t.Fatalf("publish: %v", err)
	}
	names, err := directoryNames(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"offline-trust-policy-authority-public-key.pem",
		"offline-trust-policy-authority-transition.dsse.json",
		"offline-trust-policy-authority-trust-root-public-key.pem",
	}
	if len(names) != len(want) {
		t.Fatalf("published inventory=%v want=%v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("published inventory=%v want=%v", names, want)
		}
	}
	for name, wantBytes := range map[string][]byte{
		"offline-trust-policy-authority-public-key.pem":            nextSPKI,
		"offline-trust-policy-authority-transition.dsse.json":      envelopeRaw,
		"offline-trust-policy-authority-trust-root-public-key.pem": previousSPKI,
	} {
		got, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || !bytes.Equal(got, wantBytes) {
			t.Fatalf("published %s mismatch: err=%v", name, err)
		}
	}
	if err := PublishSignedOfflineTrustPolicyAuthorityTransitionSidecars(output, nextSPKI, envelopeRaw, previousSPKI); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("existing output accepted: %v", err)
	}
}

func TestPublishSignedOfflineTrustPolicyAuthorityTransitionSidecarsRejectsInvalidWithoutOutput(t *testing.T) {
	_, previousSPKI, nextSPKI, envelopeRaw := makeOfflineTrustPolicyAuthorityTransitionPublication(t)
	for name, args := range map[string]struct {
		next     []byte
		envelope []byte
		previous []byte
	}{
		"tampered envelope":  {next: nextSPKI, envelope: append(envelopeRaw[:len(envelopeRaw)-1], 'x'), previous: previousSPKI},
		"same root and next": {next: previousSPKI, envelope: envelopeRaw, previous: previousSPKI},
	} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "invalid")
			if err := PublishSignedOfflineTrustPolicyAuthorityTransitionSidecars(output, args.next, args.envelope, args.previous); !errors.Is(err, ErrPublishFailed) {
				t.Fatalf("invalid transition accepted: %v", err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("invalid publication materialized output: %v", err)
			}
		})
	}
}
