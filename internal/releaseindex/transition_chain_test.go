package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

type chainFixture struct {
	raw       []byte
	rootSPKI  []byte
	terminal  []byte
	keys      [][]byte
	envelopes [][]byte
}

func makeAuthorityChain(t *testing.T, generations []uint64) chainFixture {
	t.Helper()
	privates := make([]ed25519.PrivateKey, len(generations)+1)
	keys := make([][]byte, len(generations)+1)
	for i := range keys {
		privates[i], keys[i] = keyPair(t)
	}
	envelopes := make([][]byte, len(generations))
	nextKeys := make([][]byte, len(generations))
	for i, generation := range generations {
		var err error
		envelopes[i], _, err = SignAuthorityTransition(keys[i+1], generation, privates[i], DefaultAuthorityTransitionScope())
		if err != nil {
			t.Fatalf("sign hop %d: %v", i, err)
		}
		nextKeys[i] = keys[i+1]
	}
	raw, err := BuildAuthorityTransitionChain(envelopes, nextKeys, keys[0], DefaultAuthorityTransitionChainScope())
	if err != nil {
		t.Fatalf("build authority chain: %v", err)
	}
	return chainFixture{raw: raw, rootSPKI: keys[0], terminal: keys[len(keys)-1], keys: keys, envelopes: envelopes}
}

func mutateChain(t *testing.T, raw []byte, mutate func(*AuthorityTransitionChain)) []byte {
	t.Helper()
	var chain AuthorityTransitionChain
	if err := decodeExact(raw, &chain); err != nil {
		t.Fatal(err)
	}
	mutate(&chain)
	result, err := canonicaljson.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func tamperChainEnvelope(t *testing.T, raw []byte, position int) []byte {
	t.Helper()
	return mutateChain(t, raw, func(chain *AuthorityTransitionChain) {
		envelopeRaw, err := base64.StdEncoding.DecodeString(chain.Hops[position].TransitionEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		var value envelope
		if err := decodeExact(envelopeRaw, &value); err != nil {
			t.Fatal(err)
		}
		if value.Signatures[0].Sig[0] == 'A' {
			value.Signatures[0].Sig = "B" + value.Signatures[0].Sig[1:]
		} else {
			value.Signatures[0].Sig = "A" + value.Signatures[0].Sig[1:]
		}
		mutated, err := canonicaljson.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		chain.Hops[position].TransitionEnvelope = base64.StdEncoding.EncodeToString(mutated)
	})
}

func TestAuthorityTransitionChainCanonicalBuildVerifyAndGetters(t *testing.T) {
	fixture := makeAuthorityChain(t, []uint64{3, 7})
	verified, err := VerifyAuthorityTransitionChain(
		fixture.raw, fixture.rootSPKI, fixture.terminal,
		DefaultAuthorityTransitionChainScope(), 7,
	)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	wantDigest := digest(append([]byte(authorityTransitionChainDigestTag), fixture.raw...))
	if verified.RootAuthorityKeyID() != keyIDFromSPKI(t, fixture.rootSPKI) ||
		verified.TerminalAuthorityKeyID() != keyIDFromSPKI(t, fixture.terminal) ||
		verified.TerminalGeneration() != 7 || verified.HopCount() != 2 || verified.Digest() != wantDigest {
		t.Fatalf("unexpected verified facts: %#v", verified)
	}
	second := makeAuthorityChainFromFixture(t, fixture)
	if !bytes.Equal(fixture.raw, second) {
		t.Fatal("same authoring inputs produced different canonical chain")
	}
	if got := (*VerifiedAuthorityTransitionChain)(nil); got.RootAuthorityKeyID() != "" ||
		got.TerminalAuthorityKeyID() != "" || got.TerminalGeneration() != 0 || got.HopCount() != 0 || got.Digest() != "" {
		t.Fatal("nil verified chain exposed facts")
	}
}

func makeAuthorityChainFromFixture(t *testing.T, fixture chainFixture) []byte {
	t.Helper()
	nextKeys := make([][]byte, len(fixture.keys)-1)
	copy(nextKeys, fixture.keys[1:])
	raw, err := BuildAuthorityTransitionChain(fixture.envelopes, nextKeys, fixture.rootSPKI, DefaultAuthorityTransitionChainScope())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthorityTransitionChainRejectsBoundAndTransportMatrix(t *testing.T) {
	fixture := makeAuthorityChain(t, []uint64{2, 5})
	wrongRoot := makeAuthorityChain(t, []uint64{1, 2}).rootSPKI
	wrongTerminal := makeAuthorityChain(t, []uint64{1, 2}).terminal
	unknown := []byte(strings.Replace(string(fixture.raw), `"hops":`, `"unknown":true,"hops":`, 1))
	cases := map[string][]byte{
		"malformed":     []byte("{}"),
		"noncanonical":  append(bytes.Clone(fixture.raw), '\n'),
		"unknown field": unknown,
		"oversize":      bytes.Repeat([]byte{'x'}, MaxAuthorityTransitionChainBytes+1),
		"noncanonical envelope base64": mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) {
			chain.Hops[0].TransitionEnvelope = "AB=="
		}),
		"invalid envelope base64": mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) { chain.Hops[0].TransitionEnvelope = "***=" }),
		"invalid key base64":      mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) { chain.Hops[0].NextAuthoritySPKI = "***=" }),
		"invalid SPKI": mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) {
			chain.Hops[0].NextAuthoritySPKI = base64.StdEncoding.EncodeToString([]byte("not a key"))
		}),
		"reordered": mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) {
			chain.Hops[0], chain.Hops[1] = chain.Hops[1], chain.Hops[0]
		}),
		"truncated": mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) { chain.Hops = chain.Hops[:1] }),
		"inserted duplicate": mutateChain(t, fixture.raw, func(chain *AuthorityTransitionChain) {
			chain.Hops = append(chain.Hops, chain.Hops[1])
		}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if verified, err := VerifyAuthorityTransitionChain(raw, fixture.rootSPKI, fixture.terminal, DefaultAuthorityTransitionChainScope(), 1); verified != nil || !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid chain accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
	for name, args := range map[string]struct {
		root, terminal []byte
		floor          uint64
		scope          Scope
	}{
		"wrong root":       {wrongRoot, fixture.terminal, 1, DefaultAuthorityTransitionChainScope()},
		"wrong terminal":   {fixture.rootSPKI, wrongTerminal, 1, DefaultAuthorityTransitionChainScope()},
		"terminal floor":   {fixture.rootSPKI, fixture.terminal, 6, DefaultAuthorityTransitionChainScope()},
		"zero floor":       {fixture.rootSPKI, fixture.terminal, 0, DefaultAuthorityTransitionChainScope()},
		"wrong scope":      {fixture.rootSPKI, fixture.terminal, 1, DefaultAuthorityTransitionScope()},
		"root as terminal": {fixture.rootSPKI, fixture.rootSPKI, 1, DefaultAuthorityTransitionChainScope()},
	} {
		t.Run(name, func(t *testing.T) {
			if verified, err := VerifyAuthorityTransitionChain(fixture.raw, args.root, args.terminal, args.scope, args.floor); verified != nil || !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid constraint accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
	badSignatureFixture := makeAuthorityChain(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8})
	for i := 0; i < len(badSignatureFixture.envelopes); i++ {
		t.Run("bad signature position "+string(rune('0'+i)), func(t *testing.T) {
			raw := tamperChainEnvelope(t, badSignatureFixture.raw, i)
			if _, err := VerifyAuthorityTransitionChain(raw, badSignatureFixture.rootSPKI, badSignatureFixture.terminal, DefaultAuthorityTransitionChainScope(), 1); !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
				t.Fatalf("bad signature at %d accepted: %v", i, err)
			}
		})
	}
	if raw, err := BuildAuthorityTransitionChain(make([][]byte, 2), make([][]byte, 3), []byte("unread"), DefaultAuthorityTransitionChainScope()); raw != nil || !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
		t.Fatalf("unpaired inputs accepted: raw=%q err=%v", raw, err)
	}
}

func TestAuthorityTransitionChainRejectsShapeGenerationAndReuse(t *testing.T) {
	for name, count := range map[string]int{"zero": 0, "one": 1, "nine": 9} {
		t.Run(name, func(t *testing.T) {
			if raw, err := BuildAuthorityTransitionChain(make([][]byte, count), make([][]byte, count), []byte("unread"), DefaultAuthorityTransitionChainScope()); raw != nil || !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid count accepted: raw=%q err=%v", raw, err)
			}
		})
	}
	for name, generations := range map[string][]uint64{
		"equal":      {2, 2},
		"decreasing": {3, 2},
	} {
		t.Run(name, func(t *testing.T) {
			makeInvalidGenerationChain(t, generations)
		})
	}
	rootPrivate, rootSPKI := keyPair(t)
	middlePrivate, middleSPKI := keyPair(t)
	first, _, err := SignAuthorityTransition(middleSPKI, 1, rootPrivate, DefaultAuthorityTransitionScope())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := SignAuthorityTransition(rootSPKI, 2, middlePrivate, DefaultAuthorityTransitionScope())
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := BuildAuthorityTransitionChain([][]byte{first, second}, [][]byte{middleSPKI, rootSPKI}, rootSPKI, DefaultAuthorityTransitionChainScope()); raw != nil || !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
		t.Fatalf("cycle accepted: raw=%q err=%v", raw, err)
	}
	eight := makeAuthorityChain(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8})
	if verified, err := VerifyAuthorityTransitionChain(eight.raw, eight.rootSPKI, eight.terminal, DefaultAuthorityTransitionChainScope(), 8); err != nil || verified.HopCount() != 8 {
		t.Fatalf("maximum valid chain rejected: verified=%#v err=%v", verified, err)
	}
}

func makeInvalidGenerationChain(t *testing.T, generations []uint64) {
	t.Helper()
	priv0, root := keyPair(t)
	priv1, middle := keyPair(t)
	_, terminal := keyPair(t)
	first, _, err := SignAuthorityTransition(middle, generations[0], priv0, DefaultAuthorityTransitionScope())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := SignAuthorityTransition(terminal, generations[1], priv1, DefaultAuthorityTransitionScope())
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := BuildAuthorityTransitionChain([][]byte{first, second}, [][]byte{middle, terminal}, root, DefaultAuthorityTransitionChainScope()); raw != nil || !errors.Is(err, ErrAuthorityTransitionChainInvalid) {
		t.Fatalf("invalid generations accepted: raw=%q err=%v", raw, err)
	}
}

func TestAuthorityTransitionChainStableReadAndAtomicExactThreePublication(t *testing.T) {
	requireHostFilesystem(t)
	fixture := makeAuthorityChain(t, []uint64{1, 4})
	root := t.TempDir()
	chainPath := filepath.Join(root, "chain.json")
	if err := os.WriteFile(chainPath, fixture.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := ReadAuthorityTransitionChain(chainPath)
	if err != nil || !bytes.Equal(read, fixture.raw) {
		t.Fatalf("stable read mismatch: err=%v", err)
	}
	oversize := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(oversize, bytes.Repeat([]byte{'x'}, MaxAuthorityTransitionChainBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuthorityTransitionChain(oversize); !errors.Is(err, ErrReadFailed) {
		t.Fatalf("oversize chain read: %v", err)
	}
	output := filepath.Join(root, "published")
	if err := PublishAuthorityTransitionChainSidecars(output, fixture.raw, fixture.rootSPKI, fixture.terminal); err != nil {
		t.Fatalf("publish: %v", err)
	}
	names, err := directoryNames(output)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	want := []string{
		"release-authority-public-key.pem",
		"release-authority-transition-chain.json",
		"release-authority-trust-root-public-key.pem",
	}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected exact3 publication: %v", names)
	}
	if err := PublishAuthorityTransitionChainSidecars(output, fixture.raw, fixture.rootSPKI, fixture.terminal); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	invalidOutput := filepath.Join(root, "invalid")
	if err := PublishAuthorityTransitionChainSidecars(invalidOutput, tamperChainEnvelope(t, fixture.raw, 1), fixture.rootSPKI, fixture.terminal); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("invalid chain published: %v", err)
	}
	if _, err := os.Lstat(invalidOutput); !os.IsNotExist(err) {
		t.Fatalf("invalid publication materialized output: %v", err)
	}
}
