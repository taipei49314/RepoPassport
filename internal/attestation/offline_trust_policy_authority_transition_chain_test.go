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
)

type offlineTrustPolicyAuthorityTransitionChainFixture struct {
	raw       []byte
	rootSPKI  []byte
	terminal  []byte
	keys      [][]byte
	privates  []ed25519.PrivateKey
	envelopes [][]byte
}

func makeOfflineTrustPolicyAuthorityTransitionChain(t *testing.T, generations []uint64) offlineTrustPolicyAuthorityTransitionChainFixture {
	t.Helper()
	privates := make([]ed25519.PrivateKey, len(generations)+1)
	keys := make([][]byte, len(generations)+1)
	for i := range keys {
		privates[i] = transitionTestPrivate(byte(0x90 + i))
		keys[i], _ = transitionTestSPKI(t, privates[i])
	}
	envelopes := make([][]byte, len(generations))
	nextKeys := make([][]byte, len(generations))
	for i, generation := range generations {
		var err error
		envelopes[i], _, _, err = SignOfflineTrustPolicyAuthorityTransition(keys[i+1], generation, privates[i])
		if err != nil {
			t.Fatalf("sign hop %d: %v", i, err)
		}
		nextKeys[i] = keys[i+1]
	}
	raw, err := BuildOfflineTrustPolicyAuthorityTransitionChain(envelopes, nextKeys, keys[0])
	if err != nil {
		t.Fatalf("build transition chain: %v", err)
	}
	return offlineTrustPolicyAuthorityTransitionChainFixture{
		raw: raw, rootSPKI: keys[0], terminal: keys[len(keys)-1],
		keys: keys, privates: privates, envelopes: envelopes,
	}
}

func mutateOfflineTrustPolicyAuthorityTransitionChain(t *testing.T, raw []byte, mutate func(*OfflineTrustPolicyAuthorityTransitionChain)) []byte {
	t.Helper()
	var chain OfflineTrustPolicyAuthorityTransitionChain
	if err := decodeCanonicalJSON(raw, MaxOfflineTrustPolicyAuthorityTransitionChainBytes, &chain); err != nil {
		t.Fatal(err)
	}
	mutate(&chain)
	result, err := canonicaljson.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestOfflineTrustPolicyAuthorityTransitionChainCanonicalBuildVerifyAndAccessors(t *testing.T) {
	fixture := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{3, 7})
	verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(fixture.raw, fixture.rootSPKI, fixture.terminal, 7)
	if err != nil {
		t.Fatalf("verify transition chain: %v", err)
	}
	wantIDs := make([]string, len(fixture.keys))
	for i, key := range fixture.keys {
		_, der, parseErr := parsePublicKey(key)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		wantIDs[i] = digestBytes(der)
	}
	digestInput := append([]byte(offlineTrustPolicyAuthorityTransitionChainDigestTag), fixture.raw...)
	if verified.RootAuthorityKeyID() != wantIDs[0] || verified.TerminalAuthorityKeyID() != wantIDs[len(wantIDs)-1] ||
		verified.TerminalGeneration() != 7 || verified.HopCount() != 2 || verified.Digest() != digestBytes(digestInput) ||
		strings.Join(verified.AuthorityKeyIDs(), "|") != strings.Join(wantIDs, "|") {
		t.Fatalf("unexpected verified facts: %#v IDs=%v", verified, verified.AuthorityKeyIDs())
	}
	returnedIDs := verified.AuthorityKeyIDs()
	returnedIDs[0] = "mutated"
	if verified.AuthorityKeyIDs()[0] != wantIDs[0] {
		t.Fatal("authority ID accessor returned verifier-owned storage")
	}
	second, err := BuildOfflineTrustPolicyAuthorityTransitionChain(fixture.envelopes, fixture.keys[1:], fixture.rootSPKI)
	if err != nil || !bytes.Equal(second, fixture.raw) {
		t.Fatalf("same authoring inputs were not deterministic: err=%v", err)
	}
	if got := (*VerifiedOfflineTrustPolicyAuthorityTransitionChain)(nil); got.RootAuthorityKeyID() != "" ||
		got.TerminalAuthorityKeyID() != "" || got.TerminalGeneration() != 0 || got.HopCount() != 0 ||
		got.Digest() != "" || got.AuthorityKeyIDs() != nil {
		t.Fatal("nil verified transition chain exposed facts")
	}

}

func TestOfflineTrustPolicyAuthorityTransitionChainRejectsCanonicalAndCrossProtocolMatrix(t *testing.T) {
	fixture := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{2, 5})
	unknown := []byte(strings.Replace(string(fixture.raw), `"hops":`, `"unknown":true,"hops":`, 1))
	for name, raw := range map[string][]byte{
		"malformed":        []byte("{}"),
		"unknown field":    unknown,
		"trailing newline": append(bytes.Clone(fixture.raw), '\n'),
		"carriage return":  append(bytes.Clone(fixture.raw), '\r'),
		"BOM":              append([]byte{0xef, 0xbb, 0xbf}, fixture.raw...),
		"oversize":         bytes.Repeat([]byte{'x'}, MaxOfflineTrustPolicyAuthorityTransitionChainBytes+1),
		"invalid envelope base64": mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
			chain.Hops[0].TransitionEnvelope = "***="
		}),
		"noncanonical envelope base64": mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
			chain.Hops[0].TransitionEnvelope = "AB=="
		}),
		"invalid key base64": mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
			chain.Hops[0].NextAuthoritySPKI = "***="
		}),
		"invalid SPKI": mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
			chain.Hops[0].NextAuthoritySPKI = base64.StdEncoding.EncodeToString([]byte("not a key"))
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(raw, fixture.rootSPKI, fixture.terminal, 1); verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid transport accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
	testOfflineTrustPolicyAuthorityTransitionChainCrossProtocol(t)
}

func testOfflineTrustPolicyAuthorityTransitionChainCrossProtocol(t *testing.T) {
	t.Helper()
	fixture := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{1, 2, 4})
	reordered := mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
		chain.Hops[0], chain.Hops[1] = chain.Hops[1], chain.Hops[0]
	})
	tamperedEnvelope := decodeTransitionEnvelopeForTest(t, fixture.envelopes[1])
	payload, err := base64.StdEncoding.DecodeString(tamperedEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	releasePayload := []byte(strings.Replace(string(payload), OfflineTrustPolicyAuthorityTransitionPurpose, "release-policy-authority-rotation", 1))
	crossProtocolEnvelope := signTransitionEnvelopeForTest(
		t, OfflineTrustPolicyAuthorityTransitionPayloadType, releasePayload, fixture.privates[1], tamperedEnvelope.Signatures[0].KeyID,
	)
	crossProtocol := mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
		chain.Hops[1].TransitionEnvelope = base64.StdEncoding.EncodeToString(crossProtocolEnvelope)
	})
	badSignatureEnvelope := bytes.Clone(fixture.envelopes[2])
	badSignatureEnvelope[len(badSignatureEnvelope)-3] ^= 1
	badSignature := mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
		chain.Hops[2].TransitionEnvelope = base64.StdEncoding.EncodeToString(badSignatureEnvelope)
	})
	for name, raw := range map[string][]byte{
		"reordered hops":         reordered,
		"cross-protocol payload": crossProtocol,
		"bad terminal signature": badSignature,
	} {
		t.Run(name, func(t *testing.T) {
			if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(raw, fixture.rootSPKI, fixture.terminal, 1); verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid adjacency accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
}

func TestOfflineTrustPolicyAuthorityTransitionChainRejectsOrderingCyclesAndGenerationMatrix(t *testing.T) {
	rootPrivate := transitionTestPrivate(0xb0)
	middlePrivate := transitionTestPrivate(0xb1)
	rootSPKI, _ := transitionTestSPKI(t, rootPrivate)
	middleSPKI, _ := transitionTestSPKI(t, middlePrivate)
	first, _, _, err := SignOfflineTrustPolicyAuthorityTransition(middleSPKI, 1, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := SignOfflineTrustPolicyAuthorityTransition(rootSPKI, 2, middlePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := BuildOfflineTrustPolicyAuthorityTransitionChain(
		[][]byte{first, second}, [][]byte{middleSPKI, rootSPKI}, rootSPKI,
	); raw != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
		t.Fatalf("authority cycle accepted: raw=%q err=%v", raw, err)
	}

	fixture := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{1, 2, 3})
	reordered := mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
		chain.Hops[0], chain.Hops[1] = chain.Hops[1], chain.Hops[0]
	})
	if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(reordered, fixture.rootSPKI, fixture.terminal, 1); verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
		t.Fatalf("reordered authority chain accepted: verified=%#v err=%v", verified, err)
	}
	reused := mutateOfflineTrustPolicyAuthorityTransitionChain(t, fixture.raw, func(chain *OfflineTrustPolicyAuthorityTransitionChain) {
		chain.Hops[2].NextAuthoritySPKI = chain.Hops[0].NextAuthoritySPKI
	})
	if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(reused, fixture.rootSPKI, fixture.terminal, 1); verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
		t.Fatalf("reused authority accepted: verified=%#v err=%v", verified, err)
	}
	testOfflineTrustPolicyAuthorityTransitionChainGenerationOrdering(t)
}

func testOfflineTrustPolicyAuthorityTransitionChainGenerationOrdering(t *testing.T) {
	t.Helper()
	for name, generations := range map[string][]uint64{
		"equal":      {2, 2},
		"decreasing": {3, 2},
	} {
		t.Run(name, func(t *testing.T) {
			privates := []ed25519.PrivateKey{transitionTestPrivate(0xc0), transitionTestPrivate(0xc1)}
			rootSPKI, _ := transitionTestSPKI(t, privates[0])
			middleSPKI, _ := transitionTestSPKI(t, privates[1])
			terminalPrivate := transitionTestPrivate(0xc2)
			terminalSPKI, _ := transitionTestSPKI(t, terminalPrivate)
			first, _, _, err := SignOfflineTrustPolicyAuthorityTransition(middleSPKI, generations[0], privates[0])
			if err != nil {
				t.Fatal(err)
			}
			second, _, _, err := SignOfflineTrustPolicyAuthorityTransition(terminalSPKI, generations[1], privates[1])
			if err != nil {
				t.Fatal(err)
			}
			if raw, err := BuildOfflineTrustPolicyAuthorityTransitionChain([][]byte{first, second}, [][]byte{middleSPKI, terminalSPKI}, rootSPKI); raw != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid generation order accepted: raw=%q err=%v", raw, err)
			}
		})
	}
}

func TestOfflineTrustPolicyAuthorityTransitionChainRejectsRootTerminalBindingAndBounds(t *testing.T) {
	fixture := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{3, 7})
	otherRoot, _ := transitionTestSPKI(t, transitionTestPrivate(0xd0))
	otherTerminal, _ := transitionTestSPKI(t, transitionTestPrivate(0xd1))
	for name, constraint := range map[string]struct {
		root, terminal []byte
	}{
		"wrong root":       {otherRoot, fixture.terminal},
		"wrong terminal":   {fixture.rootSPKI, otherTerminal},
		"root as terminal": {fixture.rootSPKI, fixture.rootSPKI},
		"invalid root":     {[]byte("not a key"), fixture.terminal},
		"invalid terminal": {fixture.rootSPKI, []byte("not a key")},
	} {
		t.Run(name, func(t *testing.T) {
			if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(fixture.raw, constraint.root, constraint.terminal, 1); verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid binding accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
	for name, count := range map[string]int{"zero hops": 0, "one hop": 1, "nine hops": 9} {
		t.Run(name, func(t *testing.T) {
			if raw, err := BuildOfflineTrustPolicyAuthorityTransitionChain(make([][]byte, count), make([][]byte, count), []byte("unread")); raw != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid hop count accepted: raw=%q err=%v", raw, err)
			}
		})
	}
	if raw, err := BuildOfflineTrustPolicyAuthorityTransitionChain(make([][]byte, 2), make([][]byte, 3), []byte("unread")); raw != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
		t.Fatalf("unpaired builder inputs accepted: raw=%q err=%v", raw, err)
	}
	maximum := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8})
	if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(maximum.raw, maximum.rootSPKI, maximum.terminal, 8); err != nil || verified.HopCount() != 8 {
		t.Fatalf("maximum chain rejected: verified=%#v err=%v", verified, err)
	}
	for name, floor := range map[string]uint64{
		"below terminal generation": 8,
		"zero":                      0,
		"unsafe":                    MaxTrustPolicyGeneration + 1,
	} {
		t.Run("floor "+name, func(t *testing.T) {
			if verified, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(fixture.raw, fixture.rootSPKI, fixture.terminal, floor); verified != nil || !errors.Is(err, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid) {
				t.Fatalf("invalid floor accepted: verified=%#v err=%v", verified, err)
			}
		})
	}
}

func TestOfflineTrustPolicyAuthorityTransitionChainReaderIsStableAndBounded(t *testing.T) {
	fixture := makeOfflineTrustPolicyAuthorityTransitionChain(t, []uint64{3, 7})
	path := filepath.Join(unlinkedTempDir(t), "chain.json")
	if err := os.WriteFile(path, fixture.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := ReadTrustPolicyAuthorityTransitionChain(path)
	if err != nil || !bytes.Equal(read, fixture.raw) {
		t.Fatalf("stable chain reader mismatch: err=%v", err)
	}
	oversize := filepath.Join(unlinkedTempDir(t), "oversize.json")
	if err := os.WriteFile(oversize, bytes.Repeat([]byte{'x'}, MaxOfflineTrustPolicyAuthorityTransitionChainBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadTrustPolicyAuthorityTransitionChain(oversize); raw != nil || err == nil {
		t.Fatalf("oversize chain reader accepted input: raw=%q err=%v", raw, err)
	}
	if raw, err := ReadTrustPolicyAuthorityTransitionChain(t.TempDir()); raw != nil || err == nil {
		t.Fatalf("directory chain reader accepted input: raw=%q err=%v", raw, err)
	}
}
