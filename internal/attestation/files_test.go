package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestLoadPrivateKeyAndWriteNewBundleSafety(t *testing.T) {
	base := unlinkedTempDir(t)
	dataRoot := filepath.Join(base, "data")
	keyRoot := filepath.Join(base, "keys")
	outputRoot := filepath.Join(base, "exports")
	for _, directory := range []string{dataRoot, keyRoot, outputRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create %s: %v", directory, err)
		}
	}
	privateKey, privatePEM := generatedPrivatePEM(t)
	keyPath := filepath.Join(keyRoot, "signing.pem")
	writePrivateFile(t, keyPath, privatePEM, 0o600)
	outputPath := filepath.Join(outputRoot, "evidence.tar")
	loaded, err := LoadPrivateKey(keyPath, dataRoot, outputPath, base)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if !bytes.Equal(loaded, privateKey) {
		t.Fatal("loaded private key differs from generated key")
	}
	clear(loaded)

	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := WriteNewBundle(outputPath, built.Bundle); err != nil {
		t.Fatalf("WriteNewBundle: %v", err)
	}
	if raw, err := ReadBundle(outputPath); err != nil || !bytes.Equal(raw, built.Bundle) {
		t.Fatalf("ReadBundle mismatch: err=%v", err)
	}
	if err := WriteNewBundle(outputPath, []byte("replacement")); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("overwrite code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
	}
}

func TestSigningPathsRejectDataAndDetectedRepository(t *testing.T) {
	base := unlinkedTempDir(t)
	dataRoot := filepath.Join(base, "data")
	keyRoot := filepath.Join(base, "keys")
	exportRoot := filepath.Join(base, "exports")
	repositoryRoot := filepath.Join(base, "repository")
	for _, directory := range []string{dataRoot, keyRoot, exportRoot, repositoryRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create %s: %v", directory, err)
		}
	}
	if err := os.WriteFile(filepath.Join(repositoryRoot, "repo-passport.yml"), []byte("apiVersion: repopass.dev/v1alpha1\n"), 0o600); err != nil {
		t.Fatalf("write repository marker: %v", err)
	}
	_, privatePEM := generatedPrivatePEM(t)
	keyPath := filepath.Join(keyRoot, "private.pem")
	writePrivateFile(t, keyPath, privatePEM, 0o600)

	dataKey := filepath.Join(dataRoot, "private.pem")
	writePrivateFile(t, dataKey, privatePEM, 0o600)
	if _, err := LoadPrivateKey(dataKey, dataRoot, filepath.Join(exportRoot, "bundle.tar"), base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("data-root key code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKey(keyPath, dataRoot, keyPath, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("key/output collision code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKey(keyPath, dataRoot, filepath.Join(dataRoot, "bundle.tar"), base); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("data-root output code = %q: %v", domain.ErrorCodeOf(err), err)
	}

	repositoryKey := filepath.Join(repositoryRoot, "private.pem")
	writePrivateFile(t, repositoryKey, privatePEM, 0o600)
	if _, err := LoadPrivateKey(repositoryKey, dataRoot, filepath.Join(exportRoot, "bundle.tar"), repositoryRoot); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("repository key code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKey(keyPath, dataRoot, filepath.Join(repositoryRoot, "bundle.tar"), repositoryRoot); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("repository output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
}

func TestSigningArtifactPathsRejectCompanionCollisionsAndIsolationViolations(t *testing.T) {
	base := unlinkedTempDir(t)
	dataRoot := filepath.Join(base, "data")
	keyRoot := filepath.Join(base, "keys")
	exportRoot := filepath.Join(base, "exports")
	repositoryRoot := filepath.Join(base, "repository")
	for _, directory := range []string{dataRoot, keyRoot, exportRoot, repositoryRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create %s: %v", directory, err)
		}
	}
	if err := os.WriteFile(filepath.Join(repositoryRoot, "repo-passport.yml"), []byte("apiVersion: repopass.dev/v1alpha1\n"), 0o600); err != nil {
		t.Fatalf("write repository marker: %v", err)
	}
	_, privatePEM := generatedPrivatePEM(t)
	keyPath := filepath.Join(keyRoot, "private.pem")
	writePrivateFile(t, keyPath, privatePEM, 0o600)
	bundlePath := filepath.Join(exportRoot, "bundle.tar")
	publicPath := filepath.Join(exportRoot, "signer-public.pem")

	loaded, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, publicPath, base)
	if err != nil {
		t.Fatalf("safe artifact paths: %v", err)
	}
	clear(loaded)
	if _, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, bundlePath, base); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("bundle/public collision code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, keyPath, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("key/public collision code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, filepath.Join(dataRoot, "public.pem"), base); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("data-root public output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, filepath.Join(repositoryRoot, "public.pem"), repositoryRoot); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("repository public output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	existingPublic := filepath.Join(exportRoot, "existing-public.pem")
	if err := os.WriteFile(existingPublic, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("write existing public output: %v", err)
	}
	if _, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, existingPublic, base); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("existing public output code = %q: %v", domain.ErrorCodeOf(err), err)
	}

	realParent := filepath.Join(base, "real-public-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("create real public parent: %v", err)
	}
	linkedParent := filepath.Join(base, "linked-public-parent")
	if err := os.Symlink(realParent, linkedParent); err == nil {
		if _, err := LoadPrivateKeyForArtifacts(keyPath, dataRoot, bundlePath, filepath.Join(linkedParent, "public.pem"), base); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
			t.Fatalf("linked public parent code = %q: %v", domain.ErrorCodeOf(err), err)
		}
	}
}

func TestDerivedSigningArtifactsAreIsolatedFromTargetRepository(t *testing.T) {
	base := unlinkedTempDir(t)
	dataRoot := filepath.Join(base, "data")
	keyRoot := filepath.Join(base, "keys")
	exportRoot := filepath.Join(base, "exports")
	targetRoot := filepath.Join(base, "target")
	for _, directory := range []string{dataRoot, keyRoot, exportRoot, targetRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_, privatePEM := generatedPrivatePEM(t)
	safeKey := filepath.Join(keyRoot, "private.pem")
	writePrivateFile(t, safeKey, privatePEM, 0o600)
	safeBundle := filepath.Join(exportRoot, "bundle.tar")
	safePublic := filepath.Join(exportRoot, "public.pem")
	loaded, err := LoadPrivateKeyForDerivedArtifacts(
		safeKey, dataRoot, safeBundle, safePublic, targetRoot, base,
	)
	if err != nil {
		t.Fatalf("safe derived signing paths: %v", err)
	}
	clear(loaded)

	targetKey := filepath.Join(targetRoot, "private.pem")
	writePrivateFile(t, targetKey, privatePEM, 0o600)
	cases := map[string]struct {
		key, bundle, public string
	}{
		"key":    {targetKey, safeBundle, safePublic},
		"bundle": {safeKey, filepath.Join(targetRoot, "bundle.tar"), safePublic},
		"public": {safeKey, safeBundle, filepath.Join(targetRoot, "public.pem")},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPrivateKeyForDerivedArtifacts(
				test.key, dataRoot, test.bundle, test.public, targetRoot, base,
			); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
				t.Fatalf("isolation error = %q: %v", domain.ErrorCodeOf(err), err)
			}
		})
	}
}

func TestPrivateKeyPermissionAndLinkChecks(t *testing.T) {
	base := unlinkedTempDir(t)
	dataRoot := filepath.Join(base, "data")
	outputRoot := filepath.Join(base, "out")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatalf("create data root: %v", err)
	}
	if err := os.Mkdir(outputRoot, 0o700); err != nil {
		t.Fatalf("create output root: %v", err)
	}
	_, privatePEM := generatedPrivatePEM(t)
	realKey := filepath.Join(base, "private.pem")
	writePrivateFile(t, realKey, privatePEM, 0o600)
	outputPath := filepath.Join(outputRoot, "bundle.tar")

	linkedKey := filepath.Join(base, "linked-private.pem")
	if err := os.Symlink(realKey, linkedKey); err == nil {
		if _, err := LoadPrivateKey(linkedKey, dataRoot, outputPath, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
			t.Fatalf("linked key code = %q: %v", domain.ErrorCodeOf(err), err)
		}
	}
	hardlinkedKey := filepath.Join(base, "hardlinked-private.pem")
	hardlinkedAlias := filepath.Join(base, "hardlinked-private-alias.pem")
	writePrivateFile(t, hardlinkedKey, privatePEM, 0o600)
	if err := os.Link(hardlinkedKey, hardlinkedAlias); err != nil {
		t.Fatalf("create private-key hardlink: %v", err)
	}
	if _, err := LoadPrivateKey(hardlinkedKey, dataRoot, outputPath, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("hardlinked key code = %q: %v", domain.ErrorCodeOf(err), err)
	}

	if runtime.GOOS != "windows" {
		permissiveKey := filepath.Join(base, "permissive.pem")
		writePrivateFile(t, permissiveKey, privatePEM, 0o640)
		if _, err := LoadPrivateKey(permissiveKey, dataRoot, outputPath, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
			t.Fatalf("permissive key code = %q: %v", domain.ErrorCodeOf(err), err)
		}
	}

	realParent := filepath.Join(base, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("create real parent: %v", err)
	}
	linkedParent := filepath.Join(base, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err == nil {
		if err := WriteNewBundle(filepath.Join(linkedParent, "bundle.tar"), []byte("bundle")); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
			t.Fatalf("linked output parent code = %q: %v", domain.ErrorCodeOf(err), err)
		}
	}
}

func TestMalformedTrustIsEvaluatedAfterBundleCryptography(t *testing.T) {
	base := unlinkedTempDir(t)
	trustPath := filepath.Join(base, "malformed-public.pem")
	if err := os.WriteFile(trustPath, []byte("not a public key\n"), 0o600); err != nil {
		t.Fatalf("write malformed trust key: %v", err)
	}
	trustRaw, err := ReadTrustKey(trustPath)
	if err != nil {
		t.Fatalf("bounded trust-key read should defer key parsing: %v", err)
	}
	if _, err := Verify([]byte("invalid bundle"), trustRaw); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
		t.Fatalf("invalid bundle precedence code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeAttestationInvalid, err)
	}

	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	report, err := Verify(built.Bundle, trustRaw)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
		t.Fatalf("valid bundle malformed trust result: report=%#v err=%v", report, err)
	}
}

func TestBundleTrustKeyAndOfflinePolicyReadersRejectUnsafePathDirectoryLinksAndOversize(t *testing.T) {
	base := unlinkedTempDir(t)
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	realBundle := filepath.Join(base, "real-bundle.tar")
	if err := os.WriteFile(realBundle, built.Bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	realTrust := filepath.Join(base, "real-public.pem")
	if err := os.WriteFile(realTrust, publicKeyPEMForTest(t, privateKey), 0o600); err != nil {
		t.Fatalf("write trust key: %v", err)
	}
	realPolicy := filepath.Join(base, "real-policy.json")
	if err := os.WriteFile(realPolicy, []byte(canonicalTrustPolicy), 0o600); err != nil {
		t.Fatalf("write trust policy: %v", err)
	}
	linkedBundle := filepath.Join(base, "linked-bundle.tar")
	linkedTrust := filepath.Join(base, "linked-public.pem")
	linkedPolicy := filepath.Join(base, "linked-policy.json")
	if bundleLinkErr := os.Symlink(realBundle, linkedBundle); bundleLinkErr == nil {
		if _, err := ReadBundle(linkedBundle); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
			t.Fatalf("linked bundle code = %q: %v", domain.ErrorCodeOf(err), err)
		}
	}
	if trustLinkErr := os.Symlink(realTrust, linkedTrust); trustLinkErr == nil {
		if _, err := ReadTrustKey(linkedTrust); domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
			t.Fatalf("linked trust code = %q: %v", domain.ErrorCodeOf(err), err)
		}
	}
	if policyLinkErr := os.Symlink(realPolicy, linkedPolicy); policyLinkErr == nil {
		if _, err := ReadOfflineTrustPolicy(linkedPolicy); domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || strings.Contains(err.Error(), linkedPolicy) {
			t.Fatalf("linked policy result = %v", err)
		}
	}
	if _, err := ReadOfflineTrustPolicy(base); domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || strings.Contains(err.Error(), base) {
		t.Fatalf("directory policy result = %v", err)
	}

	oversizeTrust := filepath.Join(base, "oversize-public.pem")
	if err := os.WriteFile(oversizeTrust, bytes.Repeat([]byte{'x'}, MaxPublicKeyBytes+1), 0o600); err != nil {
		t.Fatalf("write oversize trust key: %v", err)
	}
	if _, err := ReadTrustKey(oversizeTrust); domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
		t.Fatalf("oversize trust code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	oversizePolicy := filepath.Join(base, "oversize-policy.json")
	if err := os.WriteFile(oversizePolicy, bytes.Repeat([]byte{'x'}, MaxOfflineTrustPolicyBytes+1), 0o600); err != nil {
		t.Fatalf("write oversize policy: %v", err)
	}
	if _, err := ReadOfflineTrustPolicy(oversizePolicy); domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || strings.Contains(err.Error(), oversizePolicy) {
		t.Fatalf("oversize policy result = %v", err)
	}
	if runtime.GOOS == "windows" {
		unsafe := `\\?\C:\policy.json`
		if _, err := ReadOfflineTrustPolicy(unsafe); domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || strings.Contains(err.Error(), unsafe) {
			t.Fatalf("unsafe policy result = %v", err)
		}
	}
	oversizeBundle := filepath.Join(base, "oversize-bundle.tar")
	if err := os.WriteFile(oversizeBundle, make([]byte, MaxBundleBytes+1), 0o600); err != nil {
		t.Fatalf("write oversize bundle: %v", err)
	}
	if _, err := ReadBundle(oversizeBundle); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
		t.Fatalf("oversize bundle code = %q: %v", domain.ErrorCodeOf(err), err)
	}
}

func TestPrivateMaterialAndPathNeverEnterBundleOrSerializedError(t *testing.T) {
	base := unlinkedTempDir(t)
	dataRoot := filepath.Join(base, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatalf("create data root: %v", err)
	}
	privateKey, privatePEM := generatedPrivatePEM(t)
	secretPath := filepath.Join(base, "never-print-this-private-path.pem")
	writePrivateFile(t, secretPath, []byte("malformed private key\n"), 0o600)
	_, err := LoadPrivateKey(secretPath, dataRoot, filepath.Join(base, "bundle.tar"), base)
	assertErrorCode(t, err, domain.CodeSigningFailed)
	serialized, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("marshal error: %v", marshalErr)
	}
	for _, output := range []string{fmt.Sprint(err), string(serialized)} {
		if strings.Contains(output, secretPath) || strings.Contains(output, filepath.Base(secretPath)) {
			t.Fatalf("serialized error leaked private path: %s", output)
		}
	}

	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	seed := privateKey.Seed()
	defer clear(seed)
	for name, secret := range map[string][]byte{
		"seed":        seed,
		"private PEM": privatePEM,
		"path":        []byte(secretPath),
	} {
		if bytes.Contains(built.Bundle, secret) {
			t.Fatalf("bundle contains %s", name)
		}
	}
}

func generatedPrivatePEM(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	return privateKey, encoded
}

func writePrivateFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := writePrivateFileForTest(path, content, mode); err != nil {
		t.Fatalf("write private file: %v", err)
	}
}
