package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

type cliOfflineTrustPolicy struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	KeyAlgorithm   string                     `json:"keyAlgorithm"`
	KeyIDAlgorithm string                     `json:"keyIdAlgorithm"`
	Keys           []cliOfflineTrustPolicyKey `json:"keys"`
}

type cliOfflineTrustPolicyKey struct {
	KeyID  string `json:"keyId"`
	Status string `json:"status"`
}

type cliTrustFixture struct {
	BundleA       string
	BundleB       string
	BundleABytes  []byte
	BundleBBytes  []byte
	PrivateA      ed25519.PrivateKey
	PublicA       string
	KeyIDA        string
	KeyIDB        string
	CurrentSource string
}

func TestOfflineTrustPolicyRotationRevocationAndAttackerResign(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()

	rotationPath, rotationDigest := writeCLIOfflineTrustPolicy(t, root, "rotation.json", map[string]string{
		fixture.KeyIDA: "trusted",
		fixture.KeyIDB: "trusted",
	})
	for _, bundle := range []string{fixture.BundleA, fixture.BundleB} {
		report, envelope, exitCode := verifyCLIWithPolicy(t, bundle, rotationPath, rotationDigest)
		if exitCode != 0 || envelope.Error != nil || report.TrustDecision != "accepted" ||
			report.TrustBasis != "offline-policy-v1" || report.TrustPolicyDigest != rotationDigest ||
			report.TrustReason != "trusted" {
			t.Fatalf("rotation verify bundle=%s exit=%d report=%#v error=%#v", filepath.Base(bundle), exitCode, report, envelope.Error)
		}
	}

	revocationPath, revocationDigest := writeCLIOfflineTrustPolicy(t, root, "revocation.json", map[string]string{
		fixture.KeyIDA: "revoked",
		fixture.KeyIDB: "trusted",
	})
	revoked, revokedEnvelope, exitCode := verifyCLIWithPolicy(t, fixture.BundleA, revocationPath, revocationDigest)
	if exitCode != 7 || revokedEnvelope.Error == nil ||
		revokedEnvelope.Error.Code != domain.CodeAttestationUntrusted ||
		revoked.SignatureValidity != "valid" || revoked.TrustDecision != "rejected" ||
		revoked.TrustReason != "revoked" {
		t.Fatalf("revoked report exit=%d report=%#v envelope=%#v", exitCode, revoked, revokedEnvelope)
	}
	trusted, trustedEnvelope, exitCode := verifyCLIWithPolicy(t, fixture.BundleB, revocationPath, revocationDigest)
	if exitCode != 0 || trustedEnvelope.Error != nil || trusted.TrustDecision != "accepted" || trusted.TrustReason != "trusted" {
		t.Fatalf("rotated new signer report exit=%d report=%#v envelope=%#v", exitCode, trusted, trustedEnvelope)
	}

	attackerPath, attackerDigest := writeCLIOfflineTrustPolicy(t, root, "attacker-resign.json", map[string]string{
		fixture.KeyIDA: "trusted",
	})
	attacker, attackerEnvelope, exitCode := verifyCLIWithPolicy(t, fixture.BundleB, attackerPath, attackerDigest)
	if exitCode != 7 || attackerEnvelope.Error == nil ||
		attackerEnvelope.Error.Code != domain.CodeAttestationUntrusted ||
		attacker.SignatureValidity != "valid" || attacker.TrustDecision != "rejected" ||
		attacker.TrustReason != "not-listed" {
		t.Fatalf("attacker resign report exit=%d report=%#v envelope=%#v", exitCode, attacker, attackerEnvelope)
	}
}

func TestOfflineTrustPolicyCanonicalShapePathSizeAndLegacyOmission(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()

	for name, raw := range map[string][]byte{
		"canonical-shape": []byte("{ }"),
		"path-size":       bytes.Repeat([]byte{'x'}, attestation.MaxOfflineTrustPolicyBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			report, envelope, exitCode := verifyCLIWithPolicy(t, fixture.BundleA, path, cliSHA256Digest(raw))
			if exitCode != 7 || envelope.Error == nil || envelope.Error.Code != domain.CodeAttestationUntrusted ||
				report.SignatureValidity != "valid" || report.TrustDecision != "rejected" ||
				report.TrustBasis != "offline-policy-v1" || report.TrustReason != "invalid-or-unavailable" {
				t.Fatalf("%s exit=%d report=%#v envelope=%#v", name, exitCode, report, envelope)
			}
		})
	}

	missing := filepath.Join(root, "missing-policy.json")
	report, envelope, exitCode := verifyCLIWithPolicy(
		t,
		fixture.BundleA,
		missing,
		"sha256:"+strings.Repeat("0", 64),
	)
	if exitCode != 7 || envelope.Error == nil || envelope.Error.Code != domain.CodeAttestationUntrusted ||
		report.TrustReason != "invalid-or-unavailable" {
		t.Fatalf("missing path exit=%d report=%#v envelope=%#v", exitCode, report, envelope)
	}

	legacyModes := []struct {
		name      string
		args      []string
		wantExit  int
		wantError bool
	}{
		{name: "no-trust", args: []string{"--json", "verify-attestation", fixture.BundleA}, wantExit: 7, wantError: true},
		{name: "trust-key", args: []string{"--json", "verify-attestation", fixture.BundleA, "--trust-key", fixture.PublicA}, wantExit: 0},
	}
	for _, mode := range legacyModes {
		t.Run("legacy-omission-"+mode.name, func(t *testing.T) {
			legacyEnvelope, _, legacyStderr, exitCode := runAttestationCLI(t, mode.args...)
			if exitCode != mode.wantExit || (legacyEnvelope.Error != nil) != mode.wantError || legacyStderr != "" {
				t.Fatalf("legacy %s exit=%d envelope=%#v stderr=%s", mode.name, exitCode, legacyEnvelope, legacyStderr)
			}
			var legacy map[string]any
			decodeJSON(t, legacyEnvelope.Data, &legacy)
			for _, key := range []string{"trustBasis", "trustPolicyDigest", "trustReason"} {
				if _, present := legacy[key]; present {
					t.Fatalf("legacy %s report unexpectedly contains %s: %#v", mode.name, key, legacy)
				}
			}
		})
	}
}

func TestOfflineTrustPolicyDigestAndIOPrecedence(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	policyPath, policyDigest := writeCLIOfflineTrustPolicy(t, root, "valid.json", map[string]string{
		fixture.KeyIDA: "trusted",
	})
	missingPolicy := filepath.Join(root, "must-not-be-read.json")
	wrongBundleDigest := "sha256:" + strings.Repeat("0", 64)
	if wrongBundleDigest == cliSHA256Digest(fixture.BundleABytes) {
		wrongBundleDigest = "sha256:" + strings.Repeat("1", 64)
	}
	bundlePinEnvelope, _, bundlePinStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", fixture.BundleA,
		"--expect-bundle-digest", wrongBundleDigest,
		"--trust-policy", missingPolicy,
		"--expect-trust-policy-digest", policyDigest,
	)
	if exitCode != 7 || bundlePinEnvelope.Error == nil ||
		bundlePinEnvelope.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("bundle pin must precede policy I/O: exit=%d envelope=%#v stderr=%s", exitCode, bundlePinEnvelope, bundlePinStderr)
	}

	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	if wrongDigest == policyDigest {
		wrongDigest = "sha256:" + strings.Repeat("1", 64)
	}
	report, envelope, exitCode := verifyCLIWithPolicy(t, fixture.BundleA, policyPath, wrongDigest)
	if exitCode != 7 || envelope.Error == nil || envelope.Error.Code != domain.CodeEvidenceDigestMismatch ||
		report.SignatureValidity != "valid" || report.TrustReason != "invalid-or-unavailable" {
		t.Fatalf("policy digest mismatch exit=%d report=%#v envelope=%#v", exitCode, report, envelope)
	}

	tamperedPath := filepath.Join(root, "tampered.tar")
	tampered := append([]byte(nil), fixture.BundleABytes...)
	tampered[len(tampered)-1] ^= 1
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedEnvelope, _, tamperedStderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", tamperedPath,
		"--trust-policy", missingPolicy,
		"--expect-trust-policy-digest", policyDigest,
	)
	if exitCode != 7 || tamperedEnvelope.Error == nil || tamperedEnvelope.Error.Code != domain.CodeAttestationInvalid {
		t.Fatalf("bundle invalid must precede policy I/O: exit=%d envelope=%#v stderr=%s", exitCode, tamperedEnvelope, tamperedStderr)
	}
}

func TestOfflineTrustPolicyStrictFlagsBeforeBundleIO(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	missingBundle := filepath.Join(t.TempDir(), "must-not-be-read.tar")
	tests := map[string][]string{
		"missing-digest":        {"--trust-policy", "policy.json"},
		"missing-policy":        {"--expect-trust-policy-digest", digest},
		"duplicate-policy":      {"--trust-policy", "a.json", "--trust-policy", "b.json", "--expect-trust-policy-digest", digest},
		"duplicate-digest":      {"--trust-policy", "a.json", "--expect-trust-policy-digest", digest, "--expect-trust-policy-digest", digest},
		"empty-policy":          {"--trust-policy=", "--expect-trust-policy-digest", digest},
		"case-alias":            {"--Trust-policy", "a.json", "--expect-trust-policy-digest", digest},
		"near-prefix":           {"--trust-policy-file", "a.json", "--expect-trust-policy-digest", digest},
		"mutually-exclusive":    {"--trust-policy", "a.json", "--expect-trust-policy-digest", digest, "--trust-key", "key.pem"},
		"malformed-digest-case": {"--trust-policy", "a.json", "--expect-trust-policy-digest", "SHA256:" + strings.Repeat("1", 64)},
	}
	for name, flags := range tests {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--json", "verify-attestation", missingBundle}, flags...)
			envelope, _, _, exitCode := runAttestationCLI(t, args...)
			if exitCode != 2 || envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("exit=%d envelope=%#v", exitCode, envelope)
			}
		})
	}
}

func TestOfflineTrustPolicyFreshnessPreObservationZeroProbe(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	policyPath, policyDigest := writeCLIOfflineTrustPolicy(t, root, "revoked.json", map[string]string{
		fixture.KeyIDA: "revoked",
	})
	probes := 0
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			FreshnessSnapshot: func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error) {
				probes++
				return domain.SourceSnapshot{}, nil
			},
		},
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), []string{
		"--json", "verify-attestation", fixture.BundleA,
		"--trust-policy", policyPath,
		"--expect-trust-policy-digest", policyDigest,
		"--expect-bundle-digest", cliSHA256Digest(fixture.BundleABytes),
		"--current-manifest", fixture.CurrentSource,
	})
	if exitCode != 7 || probes != 0 {
		t.Fatalf("revoked freshness exit=%d probes=%d stdout=%s stderr=%s", exitCode, probes, stdout.String(), stderr.String())
	}
	envelope := decodeEnvelope(t, stdout.Bytes())
	var report attestation.VerificationReport
	decodeJSON(t, envelope.Data, &report)
	if envelope.Error == nil || envelope.Error.Code != domain.CodeAttestationUntrusted || report.TrustReason != "revoked" {
		t.Fatalf("freshness pre-observation envelope=%#v report=%#v", envelope, report)
	}
}

func newCLITrustFixture(t *testing.T) cliTrustFixture {
	t.Helper()
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	privateA, privatePEMA, _ := writeCLIKeyPair(t, keyRoot, "policy-a")
	privateB, privatePEMB, _ := writeCLIKeyPair(t, keyRoot, "policy-b")
	t.Cleanup(func() {
		clear(privateA)
		clear(privatePEMA)
		clear(privateB)
		clear(privatePEMB)
	})

	build := func(prefix string) (string, []byte, string) {
		bundle := filepath.Join(outputRoot, prefix+".tar")
		envelope, _, stderr, exitCode := runAttestationCLI(
			t,
			"--json", "--data-dir", dataRoot,
			"attest", "--run", runID,
			"--key", filepath.Join(keyRoot, prefix+"-private.pem"),
			"--out", bundle,
		)
		if exitCode != 0 || envelope.Error != nil {
			t.Fatalf("attest %s exit=%d envelope=%#v stderr=%s", prefix, exitCode, envelope, stderr)
		}
		var result struct {
			SignerKeyID string `json:"signerKeyId"`
		}
		decodeJSON(t, envelope.Data, &result)
		return bundle, mustReadFile(t, bundle), result.SignerKeyID
	}
	bundleA, bytesA, keyIDA := build("policy-a")
	bundleB, bytesB, keyIDB := build("policy-b")
	return cliTrustFixture{
		BundleA: bundleA, BundleB: bundleB, BundleABytes: bytesA, BundleBBytes: bytesB,
		PrivateA: privateA, PublicA: filepath.Join(keyRoot, "policy-a-public.pem"),
		KeyIDA: keyIDA, KeyIDB: keyIDB, CurrentSource: healthyNodeManifest(t),
	}
}

func writeCLIOfflineTrustPolicy(
	t *testing.T,
	directory string,
	name string,
	statuses map[string]string,
) (string, string) {
	t.Helper()
	keys := make([]cliOfflineTrustPolicyKey, 0, len(statuses))
	for keyID, status := range statuses {
		keys = append(keys, cliOfflineTrustPolicyKey{KeyID: keyID, Status: status})
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	raw, err := canonicaljson.Marshal(cliOfflineTrustPolicy{
		SchemaVersion: "1", KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256", Keys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cliSHA256Digest(raw)
}

func verifyCLIWithPolicy(
	t *testing.T,
	bundle string,
	policyPath string,
	policyDigest string,
) (attestation.VerificationReport, testEnvelope, int) {
	t.Helper()
	envelope, _, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", bundle,
		"--trust-policy", policyPath,
		"--expect-trust-policy-digest", policyDigest,
	)
	if stderr != "" {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
	var report attestation.VerificationReport
	decodeJSON(t, envelope.Data, &report)
	return report, envelope, exitCode
}
