package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestSignOfflineTrustPolicyAuthorityTransitionFlagsFailBeforeIO(t *testing.T) {
	valid := []string{
		"--next-authority-key", "next.pem", "--generation=1", "--key", "previous.pem", "--out-dir", "sidecars",
	}
	options, err := validateSignOfflineTrustPolicyAuthorityTransitionArgs(valid)
	if err != nil || options.NextAuthorityKeyPath != "next.pem" || options.Generation != 1 || options.KeyPath != "previous.pem" || options.OutputDirectory != "sidecars" {
		t.Fatalf("valid options=%#v err=%v", options, err)
	}
	tests := map[string][]string{
		"missing next":    {"--generation", "1", "--key", "missing", "--out-dir", "missing"},
		"duplicate next":  append(append([]string{}, valid...), "--next-authority-key", "again.pem"),
		"zero generation": {"--next-authority-key", "missing", "--generation", "0", "--key", "missing", "--out-dir", "missing"},
		"leading zero":    {"--next-authority-key", "missing", "--generation", "01", "--key", "missing", "--out-dir", "missing"},
		"too large":       {"--next-authority-key", "missing", "--generation", "9007199254740992", "--key", "missing", "--out-dir", "missing"},
		"unknown":         append(append([]string{}, valid...), "--unknown", "value"),
		"bare":            append(append([]string{}, valid...), "bare"),
		"single dash":     {"-next-authority-key", "missing", "--generation", "1", "--key", "missing", "--out-dir", "missing"},
		"post separator":  append(append([]string{}, valid...), "--", "value"),
		"empty inline":    {"--next-authority-key=", "--generation", "1", "--key", "missing", "--out-dir", "missing"},
		"flag as value":   {"--next-authority-key", "--generation", "1", "--key", "missing", "--out-dir", "missing"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSignOfflineTrustPolicyAuthorityTransitionArgs(args); err == nil || domain.ErrorCodeOf(err) != domain.CodeManifestInvalid {
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
		"--json", "sign-offline-trust-policy-authority-transition", "--next-authority-key", marker,
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

func TestSignOfflineTrustPolicyAuthorityTransitionEndToEnd(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previousPrivate := writeReleasePrivateKey(t, root, "previous-authority-private.pem")
	nextPrivate := writeReleasePrivateKey(t, root, "next-authority-private.pem")
	nextPublic := writeReleasePublicKeyForPrivate(t, nextPrivate, filepath.Join(root, "next-authority-public.pem"))
	output := filepath.Join(root, "sidecars")

	code, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-offline-trust-policy-authority-transition",
		"--next-authority-key", nextPublic, "--generation", "7", "--key", previousPrivate, "--out-dir", output,
	)
	response := decodeEnvelope(t, []byte(stdout))
	if code != 0 || response.Error != nil || stderr != "" {
		t.Fatalf("producer exit=%d response=%#v stdout=%s stderr=%s", code, response, stdout, stderr)
	}
	var data offlineTrustPolicyAuthorityTransitionData
	decodeJSON(t, response.Data, &data)
	if data.SchemaVersion != "1" || data.Purpose != "offline-trust-policy-authority-rotation" || data.AuthorityTransitionGeneration != 7 ||
		data.PreviousAuthorityKeyID == "" || data.NextAuthorityKeyID == "" || data.PreviousAuthorityKeyID == data.NextAuthorityKeyID ||
		data.AuthorityTransitionPayloadDigest == "" || data.AuthorityTransitionEnvelopeDigest == "" || data.SidecarDirectory != output ||
		data.PublisherIdentityAttestation != "none" || data.TimeAttestation != "none" || data.FormalClaim || data.Capability != "incomplete" || data.Overall != "inconclusive" {
		t.Fatalf("transition data=%#v", data)
	}
	var rawFields map[string]json.RawMessage
	decodeJSON(t, response.Data, &rawFields)
	wantFields := []string{
		"authorityTransitionEnvelopeDigest", "authorityTransitionGeneration", "authorityTransitionPayloadDigest", "capability", "formalClaim",
		"nextAuthorityKeyId", "overall", "previousAuthorityKeyId", "publisherIdentityAttestation", "purpose", "schemaVersion", "sidecarDirectory", "timeAttestation",
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
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"offline-trust-policy-authority-public-key.pem",
		"offline-trust-policy-authority-transition.dsse.json",
		"offline-trust-policy-authority-trust-root-public-key.pem",
	}
	if len(names) != len(wantNames) {
		t.Fatalf("published names=%v", names)
	}
	for index, name := range names {
		if name.Name() != wantNames[index] {
			t.Fatalf("published names=%v want=%v", names, wantNames)
		}
	}
	verified, err := attestation.VerifyOfflineTrustPolicyAuthorityTransition(
		mustReadFile(t, filepath.Join(output, "offline-trust-policy-authority-transition.dsse.json")),
		mustReadFile(t, filepath.Join(output, "offline-trust-policy-authority-trust-root-public-key.pem")),
		mustReadFile(t, filepath.Join(output, "offline-trust-policy-authority-public-key.pem")), 7,
	)
	if err != nil || verified == nil || verified.Generation() != data.AuthorityTransitionGeneration ||
		verified.PreviousAuthorityKeyID() != data.PreviousAuthorityKeyID || verified.NextAuthorityKeyID() != data.NextAuthorityKeyID ||
		verified.PayloadDigest() != data.AuthorityTransitionPayloadDigest || verified.EnvelopeDigest() != data.AuthorityTransitionEnvelopeDigest {
		t.Fatalf("published transition=%#v err=%v", verified, err)
	}
}

func TestSignOfflineTrustPolicyAuthorityTransitionDriftAndPortableRejectBeforeIO(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previousPrivate := writeReleasePrivateKey(t, root, "previous.pem")
	_, _, nextSPKI := writeCLIKeyPair(t, root, "next")

	t.Run("drift", func(t *testing.T) {
		output := filepath.Join(root, "drift-output")
		reads := 0
		var stdout, stderr bytes.Buffer
		app := App{
			Deps: Dependencies{OfflineTrustPolicyAuthoritySnapshot: func(string) ([]byte, error) {
				reads++
				if reads == 1 {
					return append([]byte(nil), nextSPKI...), nil
				}
				return append(append([]byte(nil), nextSPKI...), '\n'), nil
			}},
			Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		}
		code := app.Run(context.Background(), []string{
			"--json", "--data-dir", dataRoot, "sign-offline-trust-policy-authority-transition",
			"--next-authority-key", "virtual-next.pem", "--generation", "1", "--key", previousPrivate, "--out-dir", output,
		})
		response := decodeEnvelope(t, stdout.Bytes())
		if code != 1 || reads != 2 || response.Error == nil || response.Error.Code != domain.CodeSigningFailed || stderr.String() != "" {
			t.Fatalf("drift exit=%d reads=%d response=%#v stderr=%s", code, reads, response, stderr.String())
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("drift produced output: %v", err)
		}
	})

	t.Run("portable producer", func(t *testing.T) {
		marker := filepath.Join(root, "MUST-NOT-BE-READ")
		output := filepath.Join(root, "MUST-NOT-BE-CREATED")
		code, stdout, stderr := runReleaseCLI(t, true,
			"--json", "sign-offline-trust-policy-authority-transition", "--next-authority-key", marker,
			"--generation", "1", "--key", marker, "--out-dir", output,
		)
		response := decodeEnvelope(t, []byte(stdout))
		if code != 2 || response.Error == nil || response.Error.Code != domain.CodeManifestInvalid || stderr != "" {
			t.Fatalf("portable reject exit=%d response=%#v stdout=%s stderr=%s", code, response, stdout, stderr)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("portable verifier touched output: %v", err)
		}
		if strings.Contains(verifierHelp(), "sign-offline-trust-policy-authority-transition") {
			t.Fatal("portable verifier help exposes transition producer")
		}
	})
}

func TestSignOfflineTrustPolicyAuthorityTransitionPrivateKeyAndOutputIsolation(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previousPrivate := writeReleasePrivateKey(t, root, "previous.pem")
	nextPrivate := writeReleasePrivateKey(t, root, "next.pem")
	nextPublic := writeReleasePublicKeyForPrivate(t, nextPrivate, filepath.Join(root, "next-public.pem"))
	output := filepath.Join(dataRoot, "forbidden-sidecars")
	code, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-offline-trust-policy-authority-transition",
		"--next-authority-key", nextPublic, "--generation", "1", "--key", previousPrivate, "--out-dir", output,
	)
	response := decodeEnvelope(t, []byte(stdout))
	if code != 1 || response.Error == nil || response.Error.Code != domain.CodeSigningFailed || stderr != "" {
		t.Fatalf("isolation exit=%d response=%#v stdout=%s stderr=%s", code, response, stdout, stderr)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("isolated output exists: %v", err)
	}
}
