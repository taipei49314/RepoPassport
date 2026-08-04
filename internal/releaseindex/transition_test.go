package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/canonicaljson"
)

func TestAuthorityTransitionCanonicalSignVerifyAndGetters(t *testing.T) {
	previousPrivate, previousSPKI := keyPair(t)
	_, nextSPKI := keyPair(t)
	envelopeRaw, returnedPreviousSPKI, err := SignAuthorityTransition(
		nextSPKI, 7, previousPrivate, DefaultAuthorityTransitionScope(),
	)
	if err != nil {
		t.Fatalf("SignAuthorityTransition: %v", err)
	}
	if !bytes.Equal(returnedPreviousSPKI, previousSPKI) {
		t.Fatal("signer returned a noncanonical previous-root companion")
	}
	verified, err := VerifyAuthorityTransition(
		envelopeRaw, previousSPKI, nextSPKI, DefaultAuthorityTransitionScope(), 7,
	)
	if err != nil {
		t.Fatalf("VerifyAuthorityTransition: %v", err)
	}
	if verified.PreviousAuthorityKeyID() != keyIDFromSPKI(t, previousSPKI) ||
		verified.NextAuthorityKeyID() != keyIDFromSPKI(t, nextSPKI) ||
		verified.Generation() != 7 || verified.Scope() != DefaultAuthorityTransitionScope() ||
		verified.PayloadDigest() == "" || verified.EnvelopeDigest() != digest(envelopeRaw) {
		t.Fatalf("unexpected verified transition metadata: %#v", verified)
	}
	var env envelope
	if err := decodeExact(envelopeRaw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthorityTransitionPayload(payload)
	if err != nil || parsed.Generation != 7 {
		t.Fatalf("ParseAuthorityTransitionPayload: %#v, %v", parsed, err)
	}
	if got := (*VerifiedAuthorityTransition)(nil); got.Generation() != 0 || got.Scope() != (Scope{}) ||
		got.PreviousAuthorityKeyID() != "" || got.NextAuthorityKeyID() != "" ||
		got.PayloadDigest() != "" || got.EnvelopeDigest() != "" {
		t.Fatal("nil transition getters exposed nonzero metadata")
	}
}

func TestAuthorityTransitionRejectsAdversarialEnvelopeAndKeyMatrix(t *testing.T) {
	previousPrivate, previousSPKI := keyPair(t)
	_, nextSPKI := keyPair(t)
	_, wrongPreviousSPKI := keyPair(t)
	_, wrongNextSPKI := keyPair(t)
	baseRaw, _, err := SignAuthorityTransition(nextSPKI, 4, previousPrivate, DefaultAuthorityTransitionScope())
	if err != nil {
		t.Fatal(err)
	}
	var base envelope
	if err := decodeExact(baseRaw, &base); err != nil {
		t.Fatal(err)
	}

	envelopeMutation := func(t *testing.T, mutate func(*envelope)) []byte {
		t.Helper()
		candidate := base
		candidate.Signatures = append([]signature(nil), base.Signatures...)
		mutate(&candidate)
		raw, err := canonicaljson.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := []struct {
		name     string
		envelope []byte
		previous []byte
		next     []byte
		scope    Scope
		minimum  uint64
	}{
		{name: "malformed", envelope: []byte("{}"), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "noncanonical envelope", envelope: append(bytes.Clone(baseRaw), '\n'), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "wrong payload type", envelope: envelopeMutation(t, func(env *envelope) { env.PayloadType = PolicyPayloadType }), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "zero signatures", envelope: envelopeMutation(t, func(env *envelope) { env.Signatures = nil }), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "multiple signatures", envelope: envelopeMutation(t, func(env *envelope) { env.Signatures = append(env.Signatures, env.Signatures[0]) }), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "wrong signature key ID", envelope: envelopeMutation(t, func(env *envelope) { env.Signatures[0].KeyID = "sha256:" + strings.Repeat("0", 64) }), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "tampered payload", envelope: envelopeMutation(t, func(env *envelope) { env.Payload = base64.StdEncoding.EncodeToString([]byte("{}")) }), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "tampered signature", envelope: envelopeMutation(t, func(env *envelope) { env.Signatures[0].Sig = strings.Repeat("A", 86) + "==" }), previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "wrong previous root", envelope: baseRaw, previous: wrongPreviousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "wrong next root", envelope: baseRaw, previous: previousSPKI, next: wrongNextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "same root", envelope: baseRaw, previous: previousSPKI, next: previousSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 1},
		{name: "wrong scope", envelope: baseRaw, previous: previousSPKI, next: nextSPKI, scope: DefaultScope(), minimum: 1},
		{name: "below floor", envelope: baseRaw, previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 5},
		{name: "zero floor", envelope: baseRaw, previous: previousSPKI, next: nextSPKI, scope: DefaultAuthorityTransitionScope(), minimum: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verified, err := VerifyAuthorityTransition(tc.envelope, tc.previous, tc.next, tc.scope, tc.minimum); verified != nil || !errors.Is(err, ErrAuthorityTransitionInvalid) {
				t.Fatalf("adversarial transition accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
}

func TestAuthorityTransitionRejectsAuthenticatedInvalidPayloadMatrix(t *testing.T) {
	previousPrivate, previousSPKI := keyPair(t)
	_, nextSPKI := keyPair(t)
	base := AuthorityTransition{
		SchemaVersion: SchemaVersion, Product: Product, Channel: Channel,
		Purpose: AuthorityTransitionPurpose, Generation: 3, KeyAlgorithm: "ed25519",
		KeyIDAlgorithm: "spki-sha256", PreviousAuthorityKeyID: keyIDFromSPKI(t, previousSPKI),
		NextAuthorityKeyID: keyIDFromSPKI(t, nextSPKI),
	}
	for name, mutate := range map[string]func(*AuthorityTransition){
		"wrong previous ID": func(value *AuthorityTransition) { value.PreviousAuthorityKeyID = "sha256:" + strings.Repeat("0", 64) },
		"wrong next ID":     func(value *AuthorityTransition) { value.NextAuthorityKeyID = "sha256:" + strings.Repeat("0", 64) },
		"same root":         func(value *AuthorityTransition) { value.NextAuthorityKeyID = value.PreviousAuthorityKeyID },
		"wrong product":     func(value *AuthorityTransition) { value.Product = "other" },
		"wrong channel":     func(value *AuthorityTransition) { value.Channel = "stable" },
		"wrong purpose":     func(value *AuthorityTransition) { value.Purpose = Purpose },
		"wrong algorithm":   func(value *AuthorityTransition) { value.KeyAlgorithm = "rsa" },
		"zero generation":   func(value *AuthorityTransition) { value.Generation = 0 },
		"unsafe generation": func(value *AuthorityTransition) { value.Generation = MaxGeneration + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			payload, err := canonicaljson.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			envelopeRaw, _, err := signPayload(AuthorityTransitionPayloadType, payload, previousPrivate)
			if err != nil {
				t.Fatal(err)
			}
			if verified, err := VerifyAuthorityTransition(envelopeRaw, previousSPKI, nextSPKI, DefaultAuthorityTransitionScope(), 1); verified != nil || !errors.Is(err, ErrAuthorityTransitionInvalid) {
				t.Fatalf("authenticated invalid payload accepted: verified=%#v err=%v", verified, err)
			}
		})
	}

	canonical, err := canonicaljson.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalEnvelope, _, err := signPayload(AuthorityTransitionPayloadType, append(canonical, '\n'), previousPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAuthorityTransition(noncanonicalEnvelope, previousSPKI, nextSPKI, DefaultAuthorityTransitionScope(), 1); !errors.Is(err, ErrAuthorityTransitionInvalid) {
		t.Fatalf("authenticated noncanonical payload accepted: %v", err)
	}
}

func TestPublishAuthorityTransitionSidecarsIsExactAtomicAndNoOverwrite(t *testing.T) {
	previousPrivate, previousSPKI := keyPair(t)
	_, nextSPKI := keyPair(t)
	envelopeRaw, _, err := SignAuthorityTransition(nextSPKI, 1, previousPrivate, DefaultAuthorityTransitionScope())
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	output := filepath.Join(parent, "transition")
	if err := PublishAuthorityTransitionSidecars(output, nextSPKI, envelopeRaw, previousSPKI); err != nil {
		t.Fatalf("PublishAuthorityTransitionSidecars: %v", err)
	}
	items, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"release-authority-public-key.pem",
		"release-authority-transition.dsse.json",
		"release-authority-trust-root-public-key.pem",
	}
	if len(items) != len(want) {
		t.Fatalf("published inventory count=%d want=%d", len(items), len(want))
	}
	for index, item := range items {
		if item.Name() != want[index] {
			t.Fatalf("published inventory[%d]=%q want=%q", index, item.Name(), want[index])
		}
		info, err := item.Info()
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("published member %q is not regular: %v", item.Name(), err)
		}
	}
	if err := PublishAuthorityTransitionSidecars(output, nextSPKI, envelopeRaw, previousSPKI); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("existing output overwritten: %v", err)
	}
	invalidOutput := filepath.Join(parent, "invalid")
	tampered := bytes.Clone(envelopeRaw)
	tampered[len(tampered)-2] ^= 1
	if err := PublishAuthorityTransitionSidecars(invalidOutput, nextSPKI, tampered, previousSPKI); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("tampered transition published: %v", err)
	}
	if _, err := os.Lstat(invalidOutput); !os.IsNotExist(err) {
		t.Fatalf("failed publication left output: %v", err)
	}
}

func TestAuthorityTransitionReaderAndSignerBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.dsse.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, MaxAuthorityTransitionEnvelopeBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuthorityTransition(path); !errors.Is(err, ErrReadFailed) {
		t.Fatalf("oversized transition read: %v", err)
	}
	if parsed, err := ParseAuthorityTransitionPayload(bytes.Repeat([]byte{'x'}, MaxAuthorityTransitionBytes+1)); parsed != nil || !errors.Is(err, ErrAuthorityTransitionInvalid) {
		t.Fatalf("oversized transition payload parsed: parsed=%#v err=%v", parsed, err)
	}
	previousPrivate, previousSPKI := keyPair(t)
	_, nextSPKI := keyPair(t)
	if _, _, err := SignAuthorityTransition(nextSPKI, 0, previousPrivate, DefaultAuthorityTransitionScope()); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("zero generation signed: %v", err)
	}
	if _, _, err := SignAuthorityTransition(nextSPKI, MaxGeneration+1, previousPrivate, DefaultAuthorityTransitionScope()); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("unsafe generation signed: %v", err)
	}
	if _, _, err := SignAuthorityTransition(nextSPKI, 1, previousPrivate, DefaultScope()); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("wrong scope signed: %v", err)
	}
	if _, _, err := SignAuthorityTransition(previousSPKI, 1, previousPrivate, DefaultAuthorityTransitionScope()); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("same-root transition signed: %v", err)
	}
}

func TestLoadPrivateKeyForAuthorityTransitionStrictSeparation(t *testing.T) {
	previousPrivate, _ := keyPair(t)
	_, nextSPKI := keyPair(t)
	keyRoot, nextRoot, dataRoot, workingRoot, outputRoot := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	keyPath := filepath.Join(keyRoot, "previous-private.pem")
	nextPath := filepath.Join(nextRoot, "next-public.pem")
	output := filepath.Join(outputRoot, "published")
	writeTransitionPrivateKey(t, keyPath, previousPrivate)
	if err := os.WriteFile(nextPath, nextSPKI, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, nextSnapshot, err := LoadPrivateKeyForAuthorityTransition(keyPath, dataRoot, nextPath, output, workingRoot)
	if err != nil {
		t.Fatalf("LoadPrivateKeyForAuthorityTransition: %v", err)
	}
	defer clear(loaded)
	if !bytes.Equal(loaded, previousPrivate) {
		t.Fatal("loaded private key differs")
	}
	if !bytes.Equal(nextSnapshot, nextSPKI) {
		t.Fatal("returned next-authority snapshot differs from the stable input")
	}
	previousPublicPath := filepath.Join(t.TempDir(), "previous-public.pem")
	previousDER, err := x509.MarshalPKIXPublicKey(previousPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousPublicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: previousDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPrivateKeyForAuthorityTransition(keyPath, dataRoot, previousPublicPath, filepath.Join(t.TempDir(), "same-root-output"), workingRoot); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("same previous/next authority accepted by loader: %v", err)
	}
	for name, args := range map[string][]string{
		"key in data root":     {filepath.Join(dataRoot, "key.pem"), dataRoot, nextPath, output, workingRoot},
		"next in working root": {keyPath, dataRoot, filepath.Join(workingRoot, "next.pem"), output, workingRoot},
		"output in data root":  {keyPath, dataRoot, nextPath, filepath.Join(dataRoot, "out"), workingRoot},
		"key equals next":      {nextPath, dataRoot, nextPath, output, workingRoot},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := LoadPrivateKeyForAuthorityTransition(args[0], args[1], args[2], args[3], args[4]); !errors.Is(err, ErrSigningFailed) {
				t.Fatalf("unsafe separation accepted: %v", err)
			}
		})
	}
}

func TestLoadPrivateKeyForAuthorityTransitionRejectsNextKeyReplacement(t *testing.T) {
	previousPrivate, _ := keyPair(t)
	_, nextSPKI := keyPair(t)
	_, replacementSPKI := keyPair(t)
	keyRoot, nextRoot, dataRoot, workingRoot, outputRoot := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	keyPath := filepath.Join(keyRoot, "previous-private.pem")
	nextPath := filepath.Join(nextRoot, "next-public.pem")
	writeTransitionPrivateKey(t, keyPath, previousPrivate)
	if err := os.WriteFile(nextPath, nextSPKI, 0o600); err != nil {
		t.Fatal(err)
	}
	var replacementErr error
	loaded, snapshot, err := loadPrivateKeyForAuthorityTransition(
		keyPath, dataRoot, nextPath, filepath.Join(outputRoot, "published"), workingRoot,
		func() { replacementErr = os.WriteFile(nextPath, replacementSPKI, 0o600) },
	)
	clear(loaded)
	if replacementErr != nil {
		t.Fatalf("replace next-authority key: %v", replacementErr)
	}
	if !errors.Is(err, ErrSigningFailed) || snapshot != nil {
		t.Fatalf("replaced next-authority key accepted: snapshot=%x err=%v", snapshot, err)
	}
}

func writeTransitionPrivateKey(t *testing.T, path string, private ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(raw)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	secureTransitionPrivateKeyForTest(t, path)
}
