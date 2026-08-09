package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestSignOfflineTrustPolicyFlagShapeFailsBeforeIO(t *testing.T) {
	valid := []string{
		"--generation", "1", "--trusted-signer-key", "trusted.pem",
		"--revoked-signer-key=revoked.pem", "--key", "authority.pem", "--out-dir", "sidecars",
	}
	options, err := validateSignOfflineTrustPolicyArgs(valid)
	if err != nil || options.Generation != 1 || len(options.SignerKeys) != 2 ||
		options.SignerKeys[0].Decision != attestation.TrustDecisionTrusted || options.SignerKeys[1].Decision != attestation.TrustDecisionRevoked {
		t.Fatalf("valid options=%#v err=%v", options, err)
	}

	tests := map[string][]string{
		"missing generation":   {"--trusted-signer-key", "missing", "--key", "missing", "--out-dir", "missing"},
		"duplicate generation": append(append([]string{}, valid...), "--generation", "2"),
		"no signer":            {"--generation", "1", "--key", "missing", "--out-dir", "missing"},
		"zero":                 {"--generation", "0", "--trusted-signer-key", "missing", "--key", "missing", "--out-dir", "missing"},
		"leading zero":         {"--generation", "01", "--trusted-signer-key", "missing", "--key", "missing", "--out-dir", "missing"},
		"too large":            {"--generation", "9007199254740992", "--trusted-signer-key", "missing", "--key", "missing", "--out-dir", "missing"},
		"unknown":              append(append([]string{}, valid...), "--unknown", "value"),
		"bare argument":        append(append([]string{}, valid...), "bare"),
		"empty inline":         {"--generation=", "--trusted-signer-key", "missing", "--key", "missing", "--out-dir", "missing"},
	}
	tooMany := []string{"--generation", "1", "--key", "missing", "--out-dir", "missing"}
	for index := 0; index < 33; index++ {
		tooMany = append(tooMany, "--trusted-signer-key", "missing")
	}
	tests["too many signers"] = tooMany
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSignOfflineTrustPolicyArgs(args); err == nil || domain.ErrorCodeOf(err) != domain.CodeManifestInvalid {
				t.Fatalf("args=%q err=%v", args, err)
			}
		})
	}

	root := t.TempDir()
	marker := filepath.Join(root, "MUST-NOT-BE-READ")
	output := filepath.Join(root, "MUST-NOT-BE-CREATED")
	var stdout, stderr bytes.Buffer
	app := App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{
		"--json", "sign-offline-trust-policy", "--trusted-signer-key", marker,
		"--key", marker, "--out-dir", output,
	})
	response := decodeEnvelope(t, stdout.Bytes())
	if code != 2 || response.Error == nil || response.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("shape failure exit=%d response=%#v stderr=%s", code, response, stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("shape failure touched output: %v", err)
	}
}

func TestSignOfflineTrustPolicyEndToEndTrustedRevokedNotListed(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := writeReleasePrivateKey(t, root, "authority-private.pem")
	trustedKey := writeReleasePublicKeyForPrivate(t, writeReleasePrivateKey(t, root, "trusted-private.pem"), filepath.Join(root, "trusted-public.pem"))
	revokedKey := writeReleasePublicKeyForPrivate(t, writeReleasePrivateKey(t, root, "revoked-private.pem"), filepath.Join(root, "revoked-public.pem"))
	notListedKey := writeReleasePublicKeyForPrivate(t, writeReleasePrivateKey(t, root, "other-private.pem"), filepath.Join(root, "other-public.pem"))
	output := filepath.Join(root, "sidecars")

	code, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-offline-trust-policy",
		"--generation", "7", "--trusted-signer-key", trustedKey, "--revoked-signer-key", revokedKey,
		"--key", authorityKey, "--out-dir", output,
	)
	response := decodeEnvelope(t, []byte(stdout))
	if code != 0 || response.Error != nil || stderr != "" {
		t.Fatalf("issuance exit=%d response=%#v stdout=%s stderr=%s", code, response, stdout, stderr)
	}
	var data offlineTrustPolicyIssuanceData
	decodeJSON(t, response.Data, &data)
	if data.SchemaVersion != "1" || data.PolicyGeneration != 7 || data.TrustedSignerCount != 1 || data.RevokedSignerCount != 1 || data.TotalSignerCount != 2 ||
		data.PolicyPayloadDigest == "" || data.PolicyEnvelopeDigest == "" || data.AuthorityKeyID == "" || data.SidecarDirectory != output ||
		data.PublisherIdentityAttestation != "none" || data.TimeAttestation != "none" || data.FormalClaim || data.Capability != "incomplete" || data.Overall != "inconclusive" {
		t.Fatalf("issuance data=%#v", data)
	}
	var rawFields map[string]json.RawMessage
	decodeJSON(t, response.Data, &rawFields)
	wantFields := []string{
		"authorityKeyId", "capability", "formalClaim", "overall", "policyEnvelopeDigest", "policyGeneration", "policyPayloadDigest",
		"publisherIdentityAttestation", "revokedSignerCount", "schemaVersion", "sidecarDirectory", "timeAttestation", "totalSignerCount", "trustedSignerCount",
	}
	gotFields := make([]string, 0, len(rawFields))
	for name := range rawFields {
		gotFields = append(gotFields, name)
	}
	sort.Strings(gotFields)
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("JSON data fields=%q want=%q", gotFields, wantFields)
	}

	names, err := os.ReadDir(output)
	if err != nil || len(names) != 2 || names[0].Name() != "offline-trust-policy-authority-public-key.pem" || names[1].Name() != "offline-trust-policy.dsse.json" {
		t.Fatalf("published exact-two=%v err=%v", names, err)
	}
	envelopeRaw := mustReadFile(t, filepath.Join(output, "offline-trust-policy.dsse.json"))
	authoritySPKI := mustReadFile(t, filepath.Join(output, "offline-trust-policy-authority-public-key.pem"))
	policy, err := attestation.ParseSignedOfflineTrustPolicy(envelopeRaw, authoritySPKI)
	if err != nil || policy.Generation() != 7 || policy.PayloadDigest() != data.PolicyPayloadDigest || policy.EnvelopeDigest() != data.PolicyEnvelopeDigest || policy.AuthorityKeyID() != data.AuthorityKeyID {
		t.Fatalf("published policy=%#v err=%v", policy, err)
	}
	for _, test := range []struct {
		path string
		want attestation.TrustDecision
	}{{trustedKey, attestation.TrustDecisionTrusted}, {revokedKey, attestation.TrustDecisionRevoked}, {notListedKey, attestation.TrustDecisionNotListed}} {
		decision, evaluateErr := policy.EvaluateSignerKeyID(testPublicKeyID(t, test.path))
		if evaluateErr != nil || decision != test.want {
			t.Fatalf("key=%s decision=%s want=%s err=%v", filepath.Base(test.path), decision, test.want, evaluateErr)
		}
	}
}

func TestSignOfflineTrustPolicyFullToPortableVerifierParity(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "sidecars")
	code, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-offline-trust-policy", "--generation", "9",
		"--trusted-signer-key", fixture.PublicA, "--key", writeReleasePrivateKey(t, root, "authority.pem"), "--out-dir", output,
	)
	if code != 0 || stderr != "" {
		t.Fatalf("issue exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	args := []string{
		"--json", "verify-attestation", fixture.BundleA,
		"--trust-policy-envelope", filepath.Join(output, "offline-trust-policy.dsse.json"),
		"--trust-policy-authority-key", filepath.Join(output, "offline-trust-policy-authority-public-key.pem"),
		"--minimum-trust-policy-generation", "9",
	}
	fullCode, fullOut, fullErr := runPortableVerifierComparison(t, false, args)
	portableCode, portableOut, portableErr := runPortableVerifierComparison(t, true, args)
	if fullCode != 0 || portableCode != 0 || fullOut != portableOut || fullErr != portableErr {
		t.Fatalf("full=(%d,%q,%q) portable=(%d,%q,%q)", fullCode, fullOut, fullErr, portableCode, portableOut, portableErr)
	}
}

func TestSignOfflineTrustPolicyInputDriftCancellationAndNoPartialOutput(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, signerSPKI := writeCLIKeyPair(t, root, "signer")
	authority := writeReleasePrivateKey(t, root, "authority.pem")

	t.Run("drift", func(t *testing.T) {
		output := filepath.Join(root, "drift-output")
		reads := 0
		var stdout, stderr bytes.Buffer
		app := App{
			Deps: Dependencies{OfflineTrustPolicySignerSnapshot: func(string) ([]byte, error) {
				reads++
				if reads == 1 {
					return append([]byte(nil), signerSPKI...), nil
				}
				return append(append([]byte(nil), signerSPKI...), '\n'), nil
			}},
			Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		}
		code := app.Run(context.Background(), []string{
			"--json", "--data-dir", dataRoot, "sign-offline-trust-policy", "--generation", "1",
			"--trusted-signer-key", "virtual.pem", "--key", authority, "--out-dir", output,
		})
		response := decodeEnvelope(t, stdout.Bytes())
		if code != 1 || reads != 2 || response.Error == nil || response.Error.Code != domain.CodeSigningFailed {
			t.Fatalf("drift exit=%d reads=%d response=%#v stderr=%s", code, reads, response, stderr.String())
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("drift produced output: %v", err)
		}
	})

	t.Run("cancelled before IO", func(t *testing.T) {
		output := filepath.Join(root, "cancel-output")
		reads := 0
		var stdout, stderr bytes.Buffer
		app := App{
			Deps:  Dependencies{OfflineTrustPolicySignerSnapshot: func(string) ([]byte, error) { reads++; return signerSPKI, nil }},
			Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		code := app.Run(ctx, []string{
			"--json", "--data-dir", dataRoot, "sign-offline-trust-policy", "--generation", "1",
			"--trusted-signer-key", "virtual.pem", "--key", authority, "--out-dir", output,
		})
		response := decodeEnvelope(t, stdout.Bytes())
		if code != 1 || reads != 0 || response.Error == nil || response.Error.Code != domain.CodeCancelled {
			t.Fatalf("cancel exit=%d reads=%d response=%#v stderr=%s", code, reads, response, stderr.String())
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("cancel produced output: %v", err)
		}
	})
}

func TestSignOfflineTrustPolicyPrivateKeyAndOutputIsolation(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	authority := writeReleasePrivateKey(t, root, "authority.pem")
	signer := writeReleasePublicKeyForPrivate(t, writeReleasePrivateKey(t, root, "signer.pem"), filepath.Join(root, "signer-public.pem"))
	output := filepath.Join(dataRoot, "forbidden-sidecars")
	code, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-offline-trust-policy", "--generation", "1",
		"--trusted-signer-key", signer, "--key", authority, "--out-dir", output,
	)
	response := decodeEnvelope(t, []byte(stdout))
	if code != 1 || response.Error == nil || response.Error.Code != domain.CodeSigningFailed || stderr != "" {
		t.Fatalf("isolation exit=%d response=%#v stdout=%s stderr=%s", code, response, stdout, stderr)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("isolated output exists: %v", err)
	}
}

func TestPortableVerifierRejectsOfflineTrustPolicyIssuanceBeforeIO(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "MUST-NOT-BE-READ")
	output := filepath.Join(root, "MUST-NOT-BE-CREATED")
	code, stdout, stderr := runReleaseCLI(t, true,
		"--json", "sign-offline-trust-policy", "--generation", "1", "--trusted-signer-key", marker,
		"--key", marker, "--out-dir", output,
	)
	response := decodeEnvelope(t, []byte(stdout))
	if code != 2 || response.Error == nil || response.Error.Code != domain.CodeManifestInvalid || stderr != "" {
		t.Fatalf("portable reject exit=%d response=%#v stdout=%s stderr=%s", code, response, stdout, stderr)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("portable verifier touched output: %v", err)
	}
	if strings.Contains(verifierHelp(), "sign-offline-trust-policy") {
		t.Fatal("portable verifier help exposes issuance command")
	}
}

func testPublicKeyID(t *testing.T, path string) string {
	t.Helper()
	raw := mustReadFile(t, path)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		t.Fatalf("public key %s is not canonical PEM", filepath.Base(path))
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil || !bytes.Equal(canonical, block.Bytes) {
		t.Fatalf("public key %s is not canonical DER: %v", filepath.Base(path), err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}
