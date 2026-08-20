package releaseindex

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestCanonicalReleaseIndexReproducesAndBindsExactArtifactSet(t *testing.T) {
	root := artifactFixture(t)
	first, err := BuildIndex(root, ProductVersion, 7)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	second, err := BuildIndex(root, ProductVersion, 7)
	if err != nil || string(first) != string(second) {
		t.Fatalf("index is not reproducible: err=%v", err)
	}
	parsed, err := ParseIndex(first)
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	if parsed.TrustBoundary != requiredTrustBoundary() || parsed.ReleaseGeneration != 7 || len(parsed.Files) != 3 {
		t.Fatalf("unexpected index: %#v", parsed)
	}
	if err := CheckExpectedIndexDigest(first, digest(first)); err != nil {
		t.Fatalf("digest pin: %v", err)
	}
	if err := ValidateExpectedIndexDigest(digest(first)); err != nil {
		t.Fatalf("digest syntax: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.txt"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildIndex(root, ProductVersion, 7); !errors.Is(err, ErrArtifactsInvalid) {
		t.Fatalf("extra artifact accepted: %v", err)
	}
}

func TestSignedReleaseIndexExplicitTrustAndNoImplicitTrust(t *testing.T) {
	root := artifactFixture(t)
	index := mustIndex(t, root, 3)
	releasePrivate, releaseSPKI := keyPair(t)
	envelopeRaw, returnedSPKI, err := SignIndex(index, releasePrivate)
	if err != nil || string(returnedSPKI) != string(releaseSPKI) {
		t.Fatalf("SignIndex: %v", err)
	}
	authenticated, err := AuthenticateSignedIndex(index, envelopeRaw, releaseSPKI, DefaultScope(), 3)
	if err != nil {
		t.Fatalf("AuthenticateSignedIndex before policy I/O: %v", err)
	}
	authorityPrivate, authoritySPKI := keyPair(t)
	releaseID := keyIDFromSPKI(t, releaseSPKI)
	policyEnvelope := mustPolicyEnvelope(t, authorityPrivate, 4, []PolicyKey{{KeyID: releaseID, Status: "trusted"}})
	policy, err := VerifyPolicy(policyEnvelope, authoritySPKI, DefaultScope(), 4)
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	verified, err := AuthorizeSignedIndex(authenticated, policy)
	if err != nil {
		t.Fatalf("VerifySignedIndex: %v", err)
	}
	if verified.SignerKeyID() != releaseID || verified.ReleaseGeneration() != 3 || verified.IndexDigest() != digest(index) {
		t.Fatalf("unexpected verified metadata")
	}
	if err := VerifyArtifacts(root, verified); err != nil {
		t.Fatalf("VerifyArtifacts: %v", err)
	}
	if _, err := VerifyPolicy(policyEnvelope, releaseSPKI, DefaultScope(), 4); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("adjacent release signer became root: %v", err)
	}
	wrongPrivate, wrongRoot := keyPair(t)
	_ = wrongPrivate
	if _, err := VerifyPolicy(policyEnvelope, wrongRoot, DefaultScope(), 4); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("wrong root accepted: %v", err)
	}
}

func TestReleaseIndexRejectsCanonicalSignatureAndArtifactTamperMatrix(t *testing.T) {
	newVerified := func(t *testing.T, root string) ([]byte, []byte, []byte, *VerifiedIndex) {
		t.Helper()
		index := mustIndex(t, root, 1)
		releasePrivate, releaseSPKI := keyPair(t)
		envelopeRaw, _, err := SignIndex(index, releasePrivate)
		if err != nil {
			t.Fatal(err)
		}
		authorityPrivate, authoritySPKI := keyPair(t)
		policyRaw := mustPolicyEnvelope(t, authorityPrivate, 1, []PolicyKey{{KeyID: keyIDFromSPKI(t, releaseSPKI), Status: "trusted"}})
		policy, err := VerifyPolicy(policyRaw, authoritySPKI, DefaultScope(), 1)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifySignedIndex(index, envelopeRaw, releaseSPKI, policy, DefaultScope(), 1)
		if err != nil {
			t.Fatal(err)
		}
		return index, envelopeRaw, releaseSPKI, verified
	}

	t.Run("canonical payload mutation", func(t *testing.T) {
		root := artifactFixture(t)
		index, envelopeRaw, releaseSPKI, _ := newVerified(t, root)
		parsed, err := ParseIndex(index)
		if err != nil {
			t.Fatal(err)
		}
		parsed.ReleaseGeneration++
		mutated, err := canonicaljson.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		authorityPrivate, authoritySPKI := keyPair(t)
		policyRaw := mustPolicyEnvelope(t, authorityPrivate, 1, []PolicyKey{{KeyID: keyIDFromSPKI(t, releaseSPKI), Status: "trusted"}})
		policy, _ := VerifyPolicy(policyRaw, authoritySPKI, DefaultScope(), 1)
		if _, err := VerifySignedIndex(mutated, envelopeRaw, releaseSPKI, policy, DefaultScope(), 1); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("stale signature accepted: %v", err)
		}
	})

	t.Run("canonical envelope signature mutation", func(t *testing.T) {
		root := artifactFixture(t)
		index, envelopeRaw, releaseSPKI, _ := newVerified(t, root)
		var env envelope
		if err := decodeExact(envelopeRaw, &env); err != nil {
			t.Fatal(err)
		}
		if env.Signatures[0].Sig[0] == 'A' {
			env.Signatures[0].Sig = "B" + env.Signatures[0].Sig[1:]
		} else {
			env.Signatures[0].Sig = "A" + env.Signatures[0].Sig[1:]
		}
		mutated, err := canonicaljson.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		authorityPrivate, authoritySPKI := keyPair(t)
		policyRaw := mustPolicyEnvelope(t, authorityPrivate, 1, []PolicyKey{{KeyID: keyIDFromSPKI(t, releaseSPKI), Status: "trusted"}})
		policy, _ := VerifyPolicy(policyRaw, authoritySPKI, DefaultScope(), 1)
		if _, err := VerifySignedIndex(index, mutated, releaseSPKI, policy, DefaultScope(), 1); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("tampered signature accepted: %v", err)
		}
	})

	t.Run("payload type signature count key ID and companion matrix", func(t *testing.T) {
		root := artifactFixture(t)
		index := mustIndex(t, root, 1)
		releasePrivate, releaseSPKI := keyPair(t)
		envelopeRaw, _, err := SignIndex(index, releasePrivate)
		if err != nil {
			t.Fatal(err)
		}
		authorityPrivate, authoritySPKI := keyPair(t)
		policyRaw := mustPolicyEnvelope(t, authorityPrivate, 1, []PolicyKey{{KeyID: keyIDFromSPKI(t, releaseSPKI), Status: "trusted"}})
		policy, err := VerifyPolicy(policyRaw, authoritySPKI, DefaultScope(), 1)
		if err != nil {
			t.Fatal(err)
		}
		var original envelope
		if err := decodeExact(envelopeRaw, &original); err != nil {
			t.Fatal(err)
		}
		wrongPrivate, wrongSPKI := keyPair(t)
		_ = wrongPrivate
		cases := []struct {
			name   string
			mutate func(*envelope)
			spki   []byte
		}{
			{name: "wrong payload type", mutate: func(env *envelope) { env.PayloadType = PolicyPayloadType }, spki: releaseSPKI},
			{name: "zero signatures", mutate: func(env *envelope) { env.Signatures = nil }, spki: releaseSPKI},
			{name: "two signatures", mutate: func(env *envelope) { env.Signatures = append(env.Signatures, env.Signatures[0]) }, spki: releaseSPKI},
			{name: "wrong key ID", mutate: func(env *envelope) { env.Signatures[0].KeyID = "sha256:" + strings.Repeat("0", 64) }, spki: releaseSPKI},
			{name: "substituted companion", mutate: func(*envelope) {}, spki: wrongSPKI},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				env := original
				env.Signatures = append([]signature(nil), original.Signatures...)
				tc.mutate(&env)
				mutated, err := canonicaljson.Marshal(env)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := VerifySignedIndex(index, mutated, tc.spki, policy, DefaultScope(), 1); !errors.Is(err, ErrSignatureInvalid) {
					t.Fatalf("DSSE tamper accepted: %v", err)
				}
			})
		}
	})

	t.Run("artifact mutation", func(t *testing.T) {
		root := artifactFixture(t)
		_, _, _, verified := newVerified(t, root)
		if err := os.WriteFile(filepath.Join(root, "repopass-linux"), []byte("mutated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyArtifacts(root, verified); !errors.Is(err, ErrArtifactsInvalid) {
			t.Fatalf("artifact mutation accepted: %v", err)
		}
	})

	t.Run("checksum chain mutation", func(t *testing.T) {
		root := artifactFixture(t)
		_, _, _, verified := newVerified(t, root)
		sums := filepath.Join(root, "SHA256SUMS")
		raw, err := os.ReadFile(sums)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] = '0'
		if err := os.WriteFile(sums, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyArtifacts(root, verified); !errors.Is(err, ErrArtifactsInvalid) {
			t.Fatalf("checksum mutation accepted: %v", err)
		}
	})
}

func TestSignedReleasePolicyRotationRevocationAndNotListed(t *testing.T) {
	root := artifactFixture(t)
	index := mustIndex(t, root, 5)
	authorityPrivate, authoritySPKI := keyPair(t)
	aPrivate, aSPKI := keyPair(t)
	bPrivate, bSPKI := keyPair(t)
	cPrivate, cSPKI := keyPair(t)
	aID, bID := keyIDFromSPKI(t, aSPKI), keyIDFromSPKI(t, bSPKI)
	keysV1 := []PolicyKey{{KeyID: aID, Status: "trusted"}}
	policyV1, err := VerifyPolicy(mustPolicyEnvelope(t, authorityPrivate, 1, keysV1), authoritySPKI, DefaultScope(), 1)
	if err != nil {
		t.Fatal(err)
	}
	aEnvelope, _, _ := SignIndex(index, aPrivate)
	if _, err := VerifySignedIndex(index, aEnvelope, aSPKI, policyV1, DefaultScope(), 5); err != nil {
		t.Fatalf("initial signer rejected: %v", err)
	}
	keysV2 := []PolicyKey{{KeyID: aID, Status: "revoked"}, {KeyID: bID, Status: "trusted"}}
	sort.Slice(keysV2, func(i, j int) bool { return keysV2[i].KeyID < keysV2[j].KeyID })
	policyV2, err := VerifyPolicy(mustPolicyEnvelope(t, authorityPrivate, 2, keysV2), authoritySPKI, DefaultScope(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedIndex(index, aEnvelope, aSPKI, policyV2, DefaultScope(), 5); !errors.Is(err, ErrReleaseUntrusted) {
		t.Fatalf("revoked signer accepted: %v", err)
	}
	bEnvelope, _, _ := SignIndex(index, bPrivate)
	if _, err := VerifySignedIndex(index, bEnvelope, bSPKI, policyV2, DefaultScope(), 5); err != nil {
		t.Fatalf("rotated signer rejected: %v", err)
	}
	cEnvelope, _, _ := SignIndex(index, cPrivate)
	if _, err := VerifySignedIndex(index, cEnvelope, cSPKI, policyV2, DefaultScope(), 5); !errors.Is(err, ErrReleaseUntrusted) {
		t.Fatalf("unlisted signer accepted: %v", err)
	}
	if _, err := VerifyPolicy(mustPolicyEnvelope(t, authorityPrivate, 1, keysV1), authoritySPKI, DefaultScope(), 2); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("policy floor bypassed: %v", err)
	}
	authorityID := keyIDFromSPKI(t, authoritySPKI)
	selfPolicy := Policy{SchemaVersion: SchemaVersion, Product: Product, Channel: Channel, Purpose: Purpose, Generation: 3, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256", Keys: []PolicyKey{{KeyID: authorityID, Status: "trusted"}}}
	if _, err := SignPolicy(selfPolicy, authorityPrivate); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("authority was accepted as a release signer: %v", err)
	}
	selfPayload, err := canonicaljson.Marshal(selfPolicy)
	if err != nil {
		t.Fatal(err)
	}
	selfEnvelope, _, err := signPayload(PolicyPayloadType, selfPayload, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPolicy(selfEnvelope, authoritySPKI, DefaultScope(), 1); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("root-signed self-role policy accepted: %v", err)
	}
	invalidPayloadEnvelope, _, err := signPayload(PolicyPayloadType, []byte("{}"), authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if policy, err := VerifyPolicy(invalidPayloadEnvelope, authoritySPKI, DefaultScope(), 1); policy != nil || !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("authenticated invalid policy exposed metadata: policy=%#v err=%v", policy, err)
	}
}

func TestReleaseFloorIsEnforcedOnlyAfterPolicyAuthorization(t *testing.T) {
	root := artifactFixture(t)
	index := mustIndex(t, root, 1)
	releasePrivate, releaseSPKI := keyPair(t)
	envelopeRaw, _, err := SignIndex(index, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := AuthenticateSignedIndex(index, envelopeRaw, releaseSPKI, DefaultScope(), 2)
	if err != nil {
		t.Fatalf("valid low-generation signature was rejected before policy observation: %v", err)
	}
	authorityPrivate, authoritySPKI := keyPair(t)
	policyRaw := mustPolicyEnvelope(t, authorityPrivate, 9, []PolicyKey{{KeyID: keyIDFromSPKI(t, releaseSPKI), Status: "trusted"}})
	policy, err := VerifyPolicy(policyRaw, authoritySPKI, DefaultScope(), 9)
	if err != nil {
		t.Fatalf("new policy could not be authenticated/observed: %v", err)
	}
	if _, err := AuthorizeSignedIndex(authenticated, policy); !errors.Is(err, ErrReleaseUntrusted) {
		t.Fatalf("release floor was not enforced after authorization: %v", err)
	}
	var env envelope
	if err := decodeExact(envelopeRaw, &env); err != nil {
		t.Fatal(err)
	}
	env.Signatures[0].Sig = strings.Repeat("A", len(env.Signatures[0].Sig))
	badEnvelope, err := canonicaljson.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateSignedIndex(index, badEnvelope, releaseSPKI, DefaultScope(), 2); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("low generation masked invalid signature: %v", err)
	}
}

func TestPublishSignedSidecarsIsExactAtomicAndNoOverwrite(t *testing.T) {
	requireHostFilesystem(t)
	root := artifactFixture(t)
	index := mustIndex(t, root, 1)
	private, spki := keyPair(t)
	envelopeRaw, _, err := SignIndex(index, private)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "signed-release")
	if err := PublishSignedSidecars(output, index, envelopeRaw, spki); err != nil {
		t.Fatalf("PublishSignedSidecars: %v", err)
	}
	items, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"release-index.json", "signature.dsse.json", "signer-public-key.pem"}
	if len(items) != len(want) {
		t.Fatalf("published inventory: %v", items)
	}
	for i, item := range items {
		if item.Name() != want[i] {
			t.Fatalf("published inventory[%d]=%q", i, item.Name())
		}
		info, err := item.Info()
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("nonregular sidecar %q: %v", item.Name(), err)
		}
	}
	if err := PublishSignedSidecars(output, index, envelopeRaw, spki); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("existing output overwritten: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(output, "release-index.json")); err != nil || string(got) != string(index) {
		t.Fatalf("published index changed: err=%v", err)
	}
}

func TestReleaseArtifactReadsAreBoundedBeforeContentRead(t *testing.T) {
	t.Run("oversized checksum file", func(t *testing.T) {
		root := artifactFixture(t)
		if err := os.Truncate(filepath.Join(root, "SHA256SUMS"), MaxSHA256SUMSBytes+1); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildIndex(root, ProductVersion, 1); !errors.Is(err, ErrArtifactsInvalid) {
			t.Fatalf("oversized checksum accepted: %v", err)
		}
	})
	t.Run("oversized artifact", func(t *testing.T) {
		root := artifactFixture(t)
		if err := os.Truncate(filepath.Join(root, "repopass-linux"), MaxArtifactBytes+1); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildIndex(root, ProductVersion, 1); !errors.Is(err, ErrArtifactsInvalid) {
			t.Fatalf("oversized artifact accepted: %v", err)
		}
	})
	t.Run("hardlinked artifact", func(t *testing.T) {
		root := artifactFixture(t)
		artifact := filepath.Join(root, "repopass-linux")
		external := filepath.Join(t.TempDir(), "external-hardlink")
		if err := os.Link(artifact, external); err != nil {
			t.Skipf("hardlinks unavailable: %v", err)
		}
		if _, err := BuildIndex(root, ProductVersion, 1); !errors.Is(err, ErrArtifactsInvalid) {
			t.Fatalf("hardlinked artifact accepted: %v", err)
		}
	})
}

func TestStableFileRejectsPostReadHardlinkRace(t *testing.T) {
	root := artifactFixture(t)
	artifact := filepath.Join(root, "repopass-linux")
	external := filepath.Join(t.TempDir(), "late-hardlink")
	var hookErr error
	_, _, err := stableFileWithPostReadHook(artifact, MaxArtifactBytes, false, func() { hookErr = os.Link(artifact, external) })
	if hookErr != nil {
		t.Skipf("hardlinks unavailable: %v", hookErr)
	}
	if !errors.Is(err, ErrReadFailed) {
		t.Fatalf("post-read hardlink race accepted: %v", err)
	}
}

func TestArtifactInventoryRejectsInterFileMutation(t *testing.T) {
	root := artifactFixture(t)
	mutated := false
	_, err := inspectArtifactRootWithInterFileHook(root, nil, func(name string) {
		if name == "repopass-linux" && !mutated {
			mutated = true
			if writeErr := os.WriteFile(filepath.Join(root, name), []byte("LINUX\n"), 0o600); writeErr != nil {
				t.Fatalf("mutate prior inventory member: %v", writeErr)
			}
		}
	})
	if !mutated {
		t.Fatal("inter-file mutation hook did not run")
	}
	if !errors.Is(err, ErrArtifactsInvalid) {
		t.Fatalf("inter-file mutation accepted: %v", err)
	}
}

func TestReleaseIndexRejectsNonAlphanumericLeadingPortableNames(t *testing.T) {
	for _, name := range []string{".hidden", "_name", "-name"} {
		t.Run(name, func(t *testing.T) {
			root := artifactFixture(t)
			if err := os.WriteFile(filepath.Join(root, name), []byte("unsafe"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := BuildIndex(root, ProductVersion, 1); !errors.Is(err, ErrArtifactsInvalid) {
				t.Fatalf("unsafe leading character accepted: %v", err)
			}
		})
	}
}

func artifactFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{"repopass-linux": []byte("linux\n"), "repopass-windows.exe": []byte("windows\n")}
	names := []string{"repopass-linux", "repopass-windows.exe"}
	var sums strings.Builder
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(root, name), files[name], 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files[name])
		sums.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(sums.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustIndex(t *testing.T, root string, generation uint64) []byte {
	t.Helper()
	raw, err := BuildIndex(root, ProductVersion, generation)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	return raw
}

func keyPair(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return private, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func keyIDFromSPKI(t *testing.T, spki []byte) string {
	t.Helper()
	_, der, err := parseCanonicalSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	return digest(der)
}

func mustPolicyEnvelope(t *testing.T, authority ed25519.PrivateKey, generation uint64, keys []PolicyKey) []byte {
	t.Helper()
	policy := Policy{SchemaVersion: SchemaVersion, Product: Product, Channel: Channel, Purpose: Purpose, Generation: generation, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256", Keys: keys}
	raw, err := SignPolicy(policy, authority)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	return raw
}
