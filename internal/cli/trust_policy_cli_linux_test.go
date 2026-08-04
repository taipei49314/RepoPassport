//go:build linux

package cli

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"golang.org/x/sys/unix"
)

const (
	cliAttestationPath  = "attestation.json"
	cliManifestPath     = "bundle-manifest.json"
	cliVerificationPath = "payload/verification.json"
	cliSignaturePath    = "signature.dsse.json"
	cliPublicKeyPath    = "signer-public-key.pem"
)

func TestOfflineTrustPolicyPrivacyBlockedBeforePolicyFileOpenOrAccess(t *testing.T) {
	fixture := newCLITrustFixture(t)
	blockedBundle := buildCLIPrivacyBlockedResignedBundle(t, fixture.BundleABytes, fixture.PrivateA)
	if _, err := attestation.Verify(blockedBundle, nil); domain.ErrorCodeOf(err) != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("correctly re-signed privacy bundle precondition: %v", err)
	}

	root := t.TempDir()
	bundlePath := filepath.Join(root, "privacy-blocked.tar")
	if err := os.WriteFile(bundlePath, blockedBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath, policyDigest := writeCLIOfflineTrustPolicy(t, root, "watched-policy.json", map[string]string{
		fixture.KeyIDA: "trusted",
	})
	info, err := os.Lstat(policyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("policy positive-control input is not a regular unlinked file: info=%v err=%v", info, err)
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyAddWatch(fd, policyPath, uint32(unix.IN_OPEN|unix.IN_ACCESS))
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = unix.InotifyRmWatch(fd, uint32(watch))
		_ = unix.Close(fd)
	})

	envelope, stdout, stderr, exitCode := runAttestationCLI(
		t,
		"--json", "verify-attestation", bundlePath,
		"--trust-policy", policyPath,
		"--expect-trust-policy-digest", policyDigest,
	)
	if exitCode != 7 || envelope.Error == nil || envelope.Error.Code != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("privacy-before-policy exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
	}
	serialized := stdout + stderr
	for _, forbidden := range []string{
		policyPath,
		"synthetic.user@example.invalid",
		`"trustBasis"`,
		`"trustPolicyDigest"`,
		`"trustReason"`,
	} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("privacy-before-policy output exposed forbidden value %q: %s", forbidden, serialized)
		}
	}

	quiet := collectCLIPolicyInotifyEvents(t, fd, 100*time.Millisecond)
	if quiet.open != 0 || quiet.access != 0 {
		t.Fatalf("privacy failure touched policy: IN_OPEN=%d IN_ACCESS=%d", quiet.open, quiet.access)
	}
	if _, err := os.ReadFile(policyPath); err != nil {
		t.Fatalf("policy positive-control read: %v", err)
	}
	positive := collectCLIPolicyInotifyEvents(t, fd, time.Second)
	if positive.open == 0 || positive.access == 0 {
		t.Fatalf("inotify positive control incomplete: IN_OPEN=%d IN_ACCESS=%d", positive.open, positive.access)
	}
}

type cliPolicyInotifyCounts struct {
	open   int
	access int
}

func collectCLIPolicyInotifyEvents(t *testing.T, fd int, window time.Duration) cliPolicyInotifyCounts {
	t.Helper()
	deadline := time.Now().Add(window)
	counts := cliPolicyInotifyCounts{}
	buffer := make([]byte, 4096)
	for {
		n, err := unix.Read(fd, buffer)
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			t.Fatalf("read inotify events: %v", err)
		}
		if n > 0 {
			for offset := 0; offset < n; {
				if offset+unix.SizeofInotifyEvent > n {
					t.Fatalf("truncated inotify event: offset=%d bytes=%d", offset, n)
				}
				mask := binary.NativeEndian.Uint32(buffer[offset+4 : offset+8])
				nameLength := int(binary.NativeEndian.Uint32(buffer[offset+12 : offset+16]))
				eventLength := unix.SizeofInotifyEvent + nameLength
				if eventLength < unix.SizeofInotifyEvent || offset+eventLength > n {
					t.Fatalf("invalid inotify event length: offset=%d event=%d bytes=%d", offset, eventLength, n)
				}
				if mask&uint32(unix.IN_OPEN) != 0 {
					counts.open++
				}
				if mask&uint32(unix.IN_ACCESS) != 0 {
					counts.access++
				}
				offset += eventLength
			}
		}
		if time.Now().After(deadline) {
			return counts
		}
		if n == 0 || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func buildCLIPrivacyBlockedResignedBundle(
	t *testing.T,
	validBundle []byte,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	files := readCLITestBundle(t, validBundle)
	if len(files) != 5 {
		t.Fatalf("privacy canary requires the legacy five-member bundle, got %d", len(files))
	}
	var base domain.VerificationResult
	if err := json.Unmarshal(files[cliVerificationPath], &base); err != nil {
		t.Fatal(err)
	}
	blocked := rebuildCLIPrivacyRun(t, base, "synthetic.user@example.invalid")
	verificationJSON := mustCanonicalCLIJSON(t, blocked)
	manifestJSON := mustCanonicalCLIJSON(t, attestation.Manifest{
		SchemaVersion:  attestation.BundleVersion,
		BundleFormat:   "repopass.attestation.bundle.v1",
		PrivacyProfile: "minimal-public",
		Files: []attestation.ManifestFile{
			{Path: cliVerificationPath, SHA256: cliSHA256Digest(verificationJSON), Size: int64(len(verificationJSON))},
			{Path: cliPublicKeyPath, SHA256: cliSHA256Digest(files[cliPublicKeyPath]), Size: int64(len(files[cliPublicKeyPath]))},
		},
	})
	statementJSON := mustCanonicalCLIJSON(t, attestation.Statement{
		Type: attestation.StatementType,
		Subject: []attestation.StatementSubject{{
			Name:   cliManifestPath,
			Digest: attestation.SubjectDigest{SHA256: strings.TrimPrefix(cliSHA256Digest(manifestJSON), "sha256:")},
		}},
		PredicateType: attestation.PredicateType,
		Predicate: attestation.Predicate{
			SchemaVersion:              attestation.BundleVersion,
			RunID:                      blocked.RunID,
			VerificationID:             blocked.VerificationID,
			VerificationArtifactDigest: cliSHA256Digest(verificationJSON),
			VerificationDigest:         blocked.Digests.Verification,
			Source:                     blocked.Subject,
			Plan: attestation.PredicatePlan{
				Scenario:                  blocked.Plan.Scenario,
				Environment:               blocked.Plan.Environment,
				PlanDigest:                blocked.Plan.PlanDigest,
				PolicyBundleDigest:        blocked.Plan.PolicyBundleDigest,
				ResolvedPlanSchemaVersion: blocked.Plan.ResolvedPlanSchemaVersion,
				Evidence:                  blocked.Plan.Evidence,
			},
			Runner:          blocked.Runner,
			OriginalResults: blocked.Results,
		},
	})
	var originalEnvelope attestation.Envelope
	if err := json.Unmarshal(files[cliSignaturePath], &originalEnvelope); err != nil || len(originalEnvelope.Signatures) != 1 {
		t.Fatalf("decode original DSSE envelope: %v", err)
	}
	envelopeJSON := mustCanonicalCLIJSON(t, attestation.Envelope{
		PayloadType: attestation.DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statementJSON),
		Signatures: []attestation.DSSESignature{{
			KeyID: originalEnvelope.Signatures[0].KeyID,
			Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(
				privateKey,
				cliDSSEPAE(attestation.DSSEPayloadType, statementJSON),
			)),
		}},
	})
	files[cliVerificationPath] = verificationJSON
	files[cliManifestPath] = manifestJSON
	files[cliAttestationPath] = statementJSON
	files[cliSignaturePath] = envelopeJSON
	return writeCLITestBundle(t, files)
}

func mustCanonicalCLIJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicaljson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cliDSSEPAE(payloadType string, payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len([]byte(payloadType))) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " "
	return append(append([]byte(nil), prefix...), payload...)
}

func readCLITestBundle(t *testing.T, bundle []byte) map[string][]byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(bundle))
	files := make(map[string][]byte, 5)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := files[header.Name]; duplicate {
			t.Fatalf("duplicate bundle member %q", header.Name)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = content
	}
}

func writeCLITestBundle(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	paths := []string{cliAttestationPath, cliManifestPath, cliVerificationPath, cliSignaturePath, cliPublicKeyPath}
	if len(files) != len(paths) {
		t.Fatalf("unexpected bundle member count %d", len(files))
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, path := range paths {
		content, ok := files[path]
		if !ok {
			t.Fatalf("missing bundle member %q", path)
		}
		header := &tar.Header{
			Name:     path,
			Mode:     0o600,
			Uid:      0,
			Gid:      0,
			Size:     int64(len(content)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
