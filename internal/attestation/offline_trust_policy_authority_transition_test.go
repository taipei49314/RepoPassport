package attestation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func transitionTestPrivate(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func transitionTestSPKI(t *testing.T, private ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	spki, der, err := marshalPublicKey(private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return spki, der
}

func decodeTransitionEnvelopeForTest(t *testing.T, raw []byte) offlineTrustPolicyAuthorityTransitionEnvelope {
	t.Helper()
	var envelope offlineTrustPolicyAuthorityTransitionEnvelope
	if err := decodeCanonicalJSON(raw, MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func signTransitionEnvelopeForTest(t *testing.T, payloadType string, payload []byte, previous ed25519.PrivateKey, keyID string) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(offlineTrustPolicyAuthorityTransitionEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(previous, pae(payloadType, payload))),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOfflineTrustPolicyAuthorityTransitionCanonicalSignVerifyAndAccessors(t *testing.T) {
	previous := transitionTestPrivate(0x51)
	next := transitionTestPrivate(0x52)
	nextSPKI, nextDER := transitionTestSPKI(t, next)
	previousSPKI, previousDER := transitionTestSPKI(t, previous)

	envelopeRaw, returnedPreviousSPKI, verified, err := SignOfflineTrustPolicyAuthorityTransition(nextSPKI, 7, previous)
	if err != nil {
		t.Fatalf("sign transition: %v", err)
	}
	if !bytes.Equal(returnedPreviousSPKI, previousSPKI) {
		t.Fatal("returned previous SPKI differs from signing key")
	}
	wantPreviousID, wantNextID := digestBytes(previousDER), digestBytes(nextDER)
	if verified.PreviousAuthorityKeyID() != wantPreviousID || verified.NextAuthorityKeyID() != wantNextID ||
		verified.Generation() != 7 || verified.EnvelopeDigest() != digestBytes(envelopeRaw) {
		t.Fatalf("unexpected verified facts: %#v", verified)
	}
	envelope := decodeTransitionEnvelopeForTest(t, envelopeRaw)
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PayloadDigest() != digestBytes(payload) {
		t.Fatalf("payload digest = %q, want %q", verified.PayloadDigest(), digestBytes(payload))
	}
	parsed, err := ParseOfflineTrustPolicyAuthorityTransitionPayload(payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if parsed.SchemaVersion != "1" || parsed.Purpose != OfflineTrustPolicyAuthorityTransitionPurpose ||
		parsed.PolicyPayloadType != SignedOfflineTrustPolicyPayloadType || parsed.KeyAlgorithm != "ed25519" ||
		parsed.KeyIDAlgorithm != "spki-sha256" {
		t.Fatalf("unexpected payload: %#v", parsed)
	}
	secondRaw, secondPrevious, secondVerified, err := SignOfflineTrustPolicyAuthorityTransition(nextSPKI, 7, previous)
	if err != nil || !bytes.Equal(envelopeRaw, secondRaw) || !bytes.Equal(returnedPreviousSPKI, secondPrevious) ||
		verified.PayloadDigest() != secondVerified.PayloadDigest() {
		t.Fatalf("determinism mismatch: err=%v", err)
	}
	if floorVerified, err := VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, previousSPKI, nextSPKI, 7); err != nil || floorVerified.Generation() != 7 {
		t.Fatalf("verify at floor: verified=%#v err=%v", floorVerified, err)
	}
	if got := (*VerifiedOfflineTrustPolicyAuthorityTransition)(nil); got.PreviousAuthorityKeyID() != "" ||
		got.NextAuthorityKeyID() != "" || got.Generation() != 0 || got.PayloadDigest() != "" || got.EnvelopeDigest() != "" {
		t.Fatal("nil verified transition exposed facts")
	}
}

func TestOfflineTrustPolicyAuthorityTransitionRejectsCrossProtocolAndBindingMatrix(t *testing.T) {
	previous := transitionTestPrivate(0x61)
	next := transitionTestPrivate(0x62)
	otherPrevious := transitionTestPrivate(0x63)
	otherNext := transitionTestPrivate(0x64)
	nextSPKI, _ := transitionTestSPKI(t, next)
	previousSPKI, previousDER := transitionTestSPKI(t, previous)
	otherPreviousSPKI, _ := transitionTestSPKI(t, otherPrevious)
	otherNextSPKI, _ := transitionTestSPKI(t, otherNext)
	envelopeRaw, _, _, err := SignOfflineTrustPolicyAuthorityTransition(nextSPKI, 5, previous)
	if err != nil {
		t.Fatal(err)
	}

	for name, invocation := range map[string]func() (*VerifiedOfflineTrustPolicyAuthorityTransition, error){
		"wrong previous root": func() (*VerifiedOfflineTrustPolicyAuthorityTransition, error) {
			return VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, otherPreviousSPKI, nextSPKI, 1)
		},
		"wrong terminal": func() (*VerifiedOfflineTrustPolicyAuthorityTransition, error) {
			return VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, previousSPKI, otherNextSPKI, 1)
		},
		"root equals terminal": func() (*VerifiedOfflineTrustPolicyAuthorityTransition, error) {
			return VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, previousSPKI, previousSPKI, 1)
		},
		"below authority floor": func() (*VerifiedOfflineTrustPolicyAuthorityTransition, error) {
			return VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, previousSPKI, nextSPKI, 6)
		},
		"zero floor": func() (*VerifiedOfflineTrustPolicyAuthorityTransition, error) {
			return VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, previousSPKI, nextSPKI, 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			verified, err := invocation()
			if verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionInvalid) {
				t.Fatalf("invalid binding accepted: verified=%#v err=%v", verified, err)
			}
		})
	}

	envelope := decodeTransitionEnvelopeForTest(t, envelopeRaw)
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	releaseType := "application/vnd.repopass.release-authority-transition.v1+json"
	releaseEnvelope := signTransitionEnvelopeForTest(t, releaseType, payload, previous, digestBytes(previousDER))
	releasePayload := []byte(strings.Replace(string(payload), OfflineTrustPolicyAuthorityTransitionPurpose, "release-policy-authority-rotation", 1))
	attestationEnvelopeWithReleasePayload := signTransitionEnvelopeForTest(
		t, OfflineTrustPolicyAuthorityTransitionPayloadType, releasePayload, previous, digestBytes(previousDER),
	)
	tamperedSignature := append([]byte(nil), envelopeRaw...)
	tamperedSignature[len(tamperedSignature)-3] ^= 1
	for name, raw := range map[string][]byte{
		"release envelope payload type": releaseEnvelope,
		"release purpose payload":       attestationEnvelopeWithReleasePayload,
		"tampered signature":            tamperedSignature,
		"noncanonical trailing newline": append(append([]byte(nil), envelopeRaw...), '\n'),
		"oversize envelope":             bytes.Repeat([]byte{'x'}, MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			verified, err := VerifyOfflineTrustPolicyAuthorityTransition(raw, previousSPKI, nextSPKI, 1)
			if verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionInvalid) {
				t.Fatalf("cross-protocol or malformed envelope accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
}

func TestOfflineTrustPolicyAuthorityTransitionSignerRejectsInvalidInputsWithoutPartialResult(t *testing.T) {
	previous := transitionTestPrivate(0x71)
	next := transitionTestPrivate(0x72)
	nextSPKI, _ := transitionTestSPKI(t, next)
	previousSPKI, previousDER := transitionTestSPKI(t, previous)
	mutatedPrivate := append(ed25519.PrivateKey(nil), previous...)
	mutatedPrivate[len(mutatedPrivate)-1] ^= 1

	for name, input := range map[string]struct {
		next       []byte
		generation uint64
		previous   ed25519.PrivateKey
	}{
		"zero generation":      {nextSPKI, 0, previous},
		"unsafe generation":    {nextSPKI, MaxTrustPolicyGeneration + 1, previous},
		"same authority":       {previousSPKI, 1, previous},
		"invalid next SPKI":    {[]byte("not a public key"), 1, previous},
		"noncanonical private": {nextSPKI, 1, mutatedPrivate},
		"missing private":      {nextSPKI, 1, nil},
	} {
		t.Run(name, func(t *testing.T) {
			raw, root, verified, err := SignOfflineTrustPolicyAuthorityTransition(input.next, input.generation, input.previous)
			if raw != nil || root != nil || verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionSigningFailed) {
				t.Fatalf("invalid input returned a partial result: raw=%q root=%q verified=%#v err=%v", raw, root, verified, err)
			}
		})
	}

	equalPayload, err := canonicaljson.Marshal(OfflineTrustPolicyAuthorityTransition{
		SchemaVersion: "1", Purpose: OfflineTrustPolicyAuthorityTransitionPurpose,
		PolicyPayloadType: SignedOfflineTrustPolicyPayloadType, Generation: 1,
		KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		PreviousAuthorityKeyID: digestBytes(previousDER), NextAuthorityKeyID: digestBytes(previousDER),
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseOfflineTrustPolicyAuthorityTransitionPayload(equalPayload); parsed != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionInvalid) {
		t.Fatalf("equal authority IDs accepted: parsed=%#v err=%v", parsed, err)
	}
}

func TestOfflineTrustPolicyAuthorityTransitionReadersAreStableAndBounded(t *testing.T) {
	previous := transitionTestPrivate(0x81)
	next := transitionTestPrivate(0x82)
	nextSPKI, _ := transitionTestSPKI(t, next)
	transition, previousSPKI, _, err := SignOfflineTrustPolicyAuthorityTransition(nextSPKI, 3, previous)
	if err != nil {
		t.Fatal(err)
	}
	root := unlinkedTempDir(t)
	transitionPath := filepath.Join(root, "transition.dsse.json")
	previousPath := filepath.Join(root, "previous.pem")
	nextPath := filepath.Join(root, "next.pem")
	for path, raw := range map[string][]byte{transitionPath: transition, previousPath: previousSPKI, nextPath: nextSPKI} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	readTransition, err := ReadTrustPolicyAuthorityTransition(transitionPath)
	if err != nil || !bytes.Equal(readTransition, transition) {
		t.Fatalf("transition reader mismatch: err=%v", err)
	}
	readRoot, err := ReadTrustPolicyAuthorityTransitionRootKey(previousPath)
	if err != nil || !bytes.Equal(readRoot, previousSPKI) {
		t.Fatalf("root reader mismatch: err=%v", err)
	}
	readTerminal, err := ReadTrustPolicyAuthorityTransitionTerminalKey(nextPath)
	if err != nil || !bytes.Equal(readTerminal, nextSPKI) {
		t.Fatalf("terminal reader mismatch: err=%v", err)
	}

	oversize := filepath.Join(root, "oversize.dsse.json")
	if err := os.WriteFile(oversize, bytes.Repeat([]byte{'x'}, MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadTrustPolicyAuthorityTransition(oversize); raw != nil || domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || strings.Contains(err.Error(), oversize) {
		t.Fatalf("oversize transition reader leaked or misclassified: raw=%q err=%v", raw, err)
	}
	if raw, err := ReadTrustPolicyAuthorityTransition(root); raw != nil || domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || strings.Contains(err.Error(), root) {
		t.Fatalf("directory transition reader leaked or misclassified: raw=%q err=%v", raw, err)
	}
	linked := filepath.Join(root, "linked.dsse.json")
	if err := os.Symlink(transitionPath, linked); err == nil {
		if raw, err := ReadTrustPolicyAuthorityTransition(linked); raw != nil || domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
			t.Fatalf("linked transition accepted: raw=%q err=%v", raw, err)
		}
	}
	hardlinked := filepath.Join(root, "hardlinked.dsse.json")
	if err := os.Link(transitionPath, hardlinked); err == nil {
		if raw, err := ReadTrustPolicyAuthorityTransition(transitionPath); raw != nil || domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
			t.Fatalf("hardlinked transition accepted: raw=%q err=%v", raw, err)
		}
		if raw, err := ReadTrustPolicyAuthorityTransition(hardlinked); raw != nil || domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
			t.Fatalf("hardlink alias accepted: raw=%q err=%v", raw, err)
		}
	}
}
