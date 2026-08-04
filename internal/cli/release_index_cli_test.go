package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/releaseindex"
)

type releaseCLIFixture struct {
	DataRoot      string
	ArtifactRoot  string
	IndexPath     string
	SignaturePath string
	SignerKeyPath string
	PolicyPath    string
	AuthorityPath string
	IndexDigest   string
	VerifyArgs    []string
}

func TestVerifyReleaseIndexFlagShapeFailsBeforeIO(t *testing.T) {
	dataRoot := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "must-not-be-read")
	base := []string{
		"--index", sentinel + "-index", "--signature", sentinel + "-signature",
		"--signer-key", sentinel + "-signer", "--artifact-root", sentinel + "-artifacts",
		"--policy-envelope", sentinel + "-policy", "--policy-authority-key", sentinel + "-root",
		"--minimum-policy-generation", "1", "--minimum-release-generation", "1",
		"--product", "repopass", "--channel", "alpha",
		"--expect-release-index-digest", "sha256:" + strings.Repeat("0", 64),
	}
	for name, mutate := range map[string]func([]string) []string{
		"duplicate":              func(args []string) []string { return append(args, "--index", "other") },
		"mixed state modes":      func(args []string) []string { return append(args, "--persist-release-state") },
		"missing freshness mode": func(args []string) []string { return args[:len(args)-2] },
		"noncanonical generation": func(args []string) []string {
			args[13] = "01"
			return args
		},
		"wrong product": func(args []string) []string {
			args[17] = "other"
			return args
		},
		"wrong channel": func(args []string) []string {
			args[19] = "stable"
			return args
		},
		"unknown alias": func(args []string) []string { return append(args, "--Index", "other") },
		"boolean value": func(args []string) []string { return append(args[:len(args)-2], "--persist-release-state=true") },
		"positional":    func(args []string) []string { return append(args, "extra") },
	} {
		t.Run(name, func(t *testing.T) {
			args := mutate(append([]string(nil), base...))
			exitCode, stdout, stderr := runReleaseCLI(t, false, append(
				[]string{"--json", "--data-dir", dataRoot, "verify-release-index"}, args...,
			)...)
			if exitCode != 2 || stderr != "" {
				t.Fatalf("exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
			}
			response := decodeEnvelope(t, []byte(stdout))
			if response.Error == nil || response.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("unexpected response: %#v", response)
			}
			children, err := os.ReadDir(dataRoot)
			if err != nil || len(children) != 0 {
				t.Fatalf("invalid flags caused state I/O: children=%v err=%v", children, err)
			}
		})
	}
}

func TestVerifyReleaseIndexRotationFlagsRequireExactCompleteGroup(t *testing.T) {
	base := []string{
		"--index", "index", "--signature", "signature", "--signer-key", "signer",
		"--artifact-root", "artifacts", "--policy-envelope", "policy", "--policy-authority-key", "authority",
		"--product", "repopass", "--channel", "alpha", "--minimum-policy-generation", "1", "--minimum-release-generation", "1",
		"--expect-release-index-digest", "sha256:" + strings.Repeat("0", 64),
	}
	complete := append(append([]string(nil), base...),
		"--authority-transition", "transition", "--authority-trust-root", "root", "--minimum-authority-generation", "7",
	)
	options, err := validateVerifyReleaseIndexArgs(complete)
	if err != nil || !options.Rotation || options.MinimumAuthorityGeneration != 7 {
		t.Fatalf("complete rotation group = %#v, %v", options, err)
	}
	chainComplete := append(append([]string(nil), base...),
		"--authority-transition-chain", "chain", "--authority-trust-root", "root", "--minimum-authority-generation", "7",
	)
	chainOptions, err := validateVerifyReleaseIndexArgs(chainComplete)
	if err != nil || !chainOptions.Rotation || !chainOptions.Chain || chainOptions.AuthorityTransitionPath != "" || chainOptions.AuthorityTransitionChainPath != "chain" {
		t.Fatalf("complete chain rotation group = %#v, %v", chainOptions, err)
	}
	for name, args := range map[string][]string{
		"transition only":        append(append([]string(nil), base...), "--authority-transition", "transition"),
		"root only":              append(append([]string(nil), base...), "--authority-trust-root", "root"),
		"floor only":             append(append([]string(nil), base...), "--minimum-authority-generation", "7"),
		"noncanonical floor":     append(append([]string(nil), base...), "--authority-transition", "transition", "--authority-trust-root", "root", "--minimum-authority-generation", "07"),
		"duplicate":              append(append([]string(nil), complete...), "--authority-transition", "other"),
		"mixed transition modes": append(append([]string(nil), complete...), "--authority-transition-chain", "chain"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateVerifyReleaseIndexArgs(args); err == nil {
				t.Fatal("invalid rotation group was accepted")
			}
		})
	}
}

func TestAssembleReleaseAuthorityTransitionChainFlagShapeFailsBeforeIO(t *testing.T) {
	valid := []string{
		"--hop-envelope", "first.dsse.json", "--hop-next-authority-key", "first.pem",
		"--hop-envelope", "second.dsse.json", "--hop-next-authority-key", "second.pem",
		"--authority-trust-root", "root.pem", "--product", "repopass", "--channel", "alpha",
		"--minimum-authority-generation", "2", "--out-dir", "published",
	}
	options, err := validateAssembleReleaseAuthorityTransitionChainArgs(valid)
	if err != nil || len(options.HopEnvelopePaths) != 2 || len(options.HopNextAuthorityKeys) != 2 || options.MinimumGeneration != 2 {
		t.Fatalf("valid chain flags = %#v, %v", options, err)
	}
	for name, args := range map[string][]string{
		"one hop":                 valid[:4],
		"nine hops":               append(append([]string(nil), valid...), "--hop-envelope", "third", "--hop-next-authority-key", "third-key", "--hop-envelope", "fourth", "--hop-next-authority-key", "fourth-key", "--hop-envelope", "fifth", "--hop-next-authority-key", "fifth-key", "--hop-envelope", "sixth", "--hop-next-authority-key", "sixth-key", "--hop-envelope", "seventh", "--hop-next-authority-key", "seventh-key", "--hop-envelope", "eighth", "--hop-next-authority-key", "eighth-key", "--hop-envelope", "ninth", "--hop-next-authority-key", "ninth-key"),
		"unpaired":                append(append([]string(nil), valid...), "--hop-envelope", "third"),
		"wrong scope":             append(append([]string(nil), valid...), "--product", "other"),
		"noncanonical generation": append(append([]string(nil), valid[:len(valid)-4]...), "--minimum-authority-generation", "02", "--out-dir", "published"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAssembleReleaseAuthorityTransitionChainArgs(args); err == nil {
				t.Fatal("invalid assembler flags accepted")
			}
		})
	}
}

func TestSignReleaseAuthorityTransitionFlagShape(t *testing.T) {
	valid := []string{
		"--next-authority-key", "next.pem", "--generation", "9", "--product", "repopass", "--channel", "alpha", "--key", "previous.pem", "--out-dir", "new-sidecars",
	}
	options, err := validateSignReleaseAuthorityTransitionArgs(valid)
	if err != nil || options.Generation != 9 || options.NextAuthorityKeyPath != "next.pem" {
		t.Fatalf("valid flags = %#v, %v", options, err)
	}
	for name, args := range map[string][]string{
		"missing":                 valid[:len(valid)-2],
		"wrong scope":             append(append([]string(nil), valid...), "--product", "other"),
		"noncanonical generation": {"--next-authority-key", "next.pem", "--generation", "09", "--product", "repopass", "--channel", "alpha", "--key", "previous.pem", "--out-dir", "new-sidecars"},
		"unknown":                 append(append([]string(nil), valid...), "--nextAuthorityKey", "other.pem"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSignReleaseAuthorityTransitionArgs(args); err == nil {
				t.Fatal("invalid transition signing flags were accepted")
			}
		})
	}
}

func TestReleaseIndexValidationOrderPreventsPrematureTrustArtifactAndStateIO(t *testing.T) {
	dataRoot := t.TempDir()
	inputRoot := t.TempDir()
	malformedIndex := filepath.Join(inputRoot, "malformed.json")
	if err := os.WriteFile(malformedIndex, []byte("{\"not\":\"an-index\"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(inputRoot, "must-not-be-read")
	args := []string{
		"--json", "--data-dir", dataRoot, "verify-release-index",
		"--index", malformedIndex, "--signature", missing + "-signature",
		"--signer-key", missing + "-signer", "--artifact-root", missing + "-artifacts",
		"--policy-envelope", missing + "-policy", "--policy-authority-key", missing + "-root",
		"--minimum-policy-generation", "1", "--minimum-release-generation", "1",
		"--product", "repopass", "--channel", "alpha",
		"--persist-release-state",
	}
	exitCode, stdout, stderr := runReleaseCLI(t, true, args...)
	if exitCode != 7 || stderr != "" {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	response := decodeEnvelope(t, []byte(stdout))
	if response.Error == nil || response.Error.Code != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("unexpected response: %#v", response)
	}
	children, err := os.ReadDir(dataRoot)
	if err != nil || len(children) != 0 {
		t.Fatalf("malformed index caused state I/O: children=%v err=%v", children, err)
	}
}

func TestVerifyReleaseIndexFullAndPortableOutputEquivalence(t *testing.T) {
	fixture := newReleaseCLIFixture(t)
	fullExit, fullStdout, fullStderr := runReleaseCLI(t, false, fixture.VerifyArgs...)
	portableExit, portableStdout, portableStderr := runReleaseCLI(t, true, fixture.VerifyArgs...)
	if fullExit != 0 || portableExit != fullExit || portableStdout != fullStdout || portableStderr != fullStderr {
		t.Fatalf("full=(%d,%q,%q) portable=(%d,%q,%q)", fullExit, fullStdout, fullStderr, portableExit, portableStdout, portableStderr)
	}
	response := decodeEnvelope(t, []byte(fullStdout))
	var report releaseIndexVerificationReport
	decodeJSON(t, response.Data, &report)
	if report.IndexIntegrity != "valid" || report.ArtifactIntegrity != "valid" || report.SignatureValidity != "valid" ||
		report.TrustDecision != "accepted" || report.TrustBasis != "release-key-policy-v1" ||
		report.PublisherIdentityAttestation != "none" || report.TimeAttestation != "none" ||
		report.FormalClaim || report.Capability != "incomplete" || report.Overall != "inconclusive" {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestVerifyReleaseIndexRotatedAuthorityReportsAndPortableParity(t *testing.T) {
	fixture := newReleaseCLIFixture(t)
	oldRoot, nextRoot := t.TempDir(), t.TempDir()
	previousKey := writeReleasePrivateKey(t, oldRoot, "previous-authority.pem")
	nextKey := writeReleasePrivateKey(t, nextRoot, "next-authority.pem")
	nextPublic := writeReleasePublicKeyForPrivate(t, nextKey, filepath.Join(nextRoot, "next-authority-public.pem"))
	transitionDir := filepath.Join(t.TempDir(), "transition")
	if exit, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", fixture.DataRoot, "sign-release-authority-transition",
		"--next-authority-key", nextPublic, "--generation", "1", "--product", "repopass", "--channel", "alpha", "--key", previousKey, "--out-dir", transitionDir,
	); exit != 0 || stderr != "" {
		t.Fatalf("sign transition exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	wantNextSPKI, err := os.ReadFile(nextPublic)
	if err != nil {
		t.Fatal(err)
	}
	publishedNextSPKI, err := os.ReadFile(filepath.Join(transitionDir, "release-authority-public-key.pem"))
	if err != nil || !bytes.Equal(publishedNextSPKI, wantNextSPKI) {
		t.Fatalf("published next authority is not the loader-bound input snapshot: %v", err)
	}
	signerSPKI, err := os.ReadFile(fixture.SignerKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signerID, err := releaseindex.PublicKeyID(signerSPKI)
	if err != nil {
		t.Fatal(err)
	}
	policy := releaseindex.Policy{
		SchemaVersion: releaseindex.SchemaVersion, Product: releaseindex.Product, Channel: releaseindex.Channel,
		Purpose: releaseindex.Purpose, Generation: 1, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		Keys: []releaseindex.PolicyKey{{KeyID: signerID, Status: "trusted"}},
	}
	policyRaw, err := canonicaljson.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyInput := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyInput, policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(t.TempDir(), "rotated-policy")
	if exit, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", fixture.DataRoot, "sign-release-policy", "--policy", policyInput, "--key", nextKey, "--out-dir", policyDir,
	); exit != 0 || stderr != "" {
		t.Fatalf("sign rotated policy exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	args := append([]string{"--json", "--data-dir", fixture.DataRoot}, fixture.VerifyArgs[1:]...)
	for index, value := range args {
		if value == fixture.PolicyPath {
			args[index] = filepath.Join(policyDir, "release-key-policy.dsse.json")
		}
		if value == fixture.AuthorityPath {
			args[index] = filepath.Join(policyDir, "release-authority-public-key.pem")
		}
	}
	args = append(args, "--authority-transition", filepath.Join(transitionDir, "release-authority-transition.dsse.json"),
		"--authority-trust-root", filepath.Join(transitionDir, "release-authority-trust-root-public-key.pem"), "--minimum-authority-generation", "1")
	fullExit, fullStdout, fullStderr := runReleaseCLI(t, false, args...)
	portableExit, portableStdout, portableStderr := runReleaseCLI(t, true, args...)
	if fullExit != 0 || portableExit != 0 || fullStderr != "" || portableStderr != "" || fullStdout != portableStdout {
		t.Fatalf("rotated verifier parity full=(%d,%s,%s) portable=(%d,%s,%s)", fullExit, fullStdout, fullStderr, portableExit, portableStdout, portableStderr)
	}
	response := decodeEnvelope(t, []byte(fullStdout))
	var report map[string]any
	decodeJSON(t, response.Data, &report)
	if report["trustBasis"] != "release-key-policy-v1+authority-transition-v1" ||
		report["authorityTransitionGeneration"] != float64(1) || report["policyAuthorityKeyId"] == "" ||
		report["authorityTransitionPayloadDigest"] == "" || report["trustRootKeyId"] == report["policyAuthorityKeyId"] {
		t.Fatalf("rotated report = %#v", report)
	}
}

func TestAuthorityTransitionChainAssemblerAndVerifierPortableParity(t *testing.T) {
	fixture := newReleaseCLIFixture(t)
	keyRoot, keyMiddle, keyTerminal := t.TempDir(), t.TempDir(), t.TempDir()
	rootPrivate := writeReleasePrivateKey(t, keyRoot, "root-private.pem")
	middlePrivate := writeReleasePrivateKey(t, keyMiddle, "middle-private.pem")
	terminalPrivate := writeReleasePrivateKey(t, keyTerminal, "terminal-private.pem")
	rootPublic := writeReleasePublicKeyForPrivate(t, rootPrivate, filepath.Join(keyRoot, "root-public.pem"))
	middlePublic := writeReleasePublicKeyForPrivate(t, middlePrivate, filepath.Join(keyMiddle, "middle-public.pem"))
	terminalPublic := writeReleasePublicKeyForPrivate(t, terminalPrivate, filepath.Join(keyTerminal, "terminal-public.pem"))
	firstDir, secondDir := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	for _, item := range []struct {
		key, next, out, generation string
	}{
		{rootPrivate, middlePublic, firstDir, "1"},
		{middlePrivate, terminalPublic, secondDir, "2"},
	} {
		if exit, stdout, stderr := runReleaseCLI(t, false, "--json", "--data-dir", fixture.DataRoot,
			"sign-release-authority-transition", "--next-authority-key", item.next, "--generation", item.generation,
			"--product", "repopass", "--channel", "alpha", "--key", item.key, "--out-dir", item.out,
		); exit != 0 || stderr != "" {
			t.Fatalf("sign chain hop exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
		}
	}
	chainDir := filepath.Join(t.TempDir(), "chain")
	if exit, stdout, stderr := runReleaseCLI(t, false, "--json", "--data-dir", fixture.DataRoot,
		"assemble-release-authority-transition-chain",
		"--hop-envelope", filepath.Join(firstDir, "release-authority-transition.dsse.json"), "--hop-next-authority-key", middlePublic,
		"--hop-envelope", filepath.Join(secondDir, "release-authority-transition.dsse.json"), "--hop-next-authority-key", terminalPublic,
		"--authority-trust-root", rootPublic, "--product", "repopass", "--channel", "alpha", "--minimum-authority-generation", "2", "--out-dir", chainDir,
	); exit != 0 || stderr != "" {
		t.Fatalf("assemble chain exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	entries, err := os.ReadDir(chainDir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("chain exact3 entries=%v err=%v", entries, err)
	}
	if entries[0].Name() != "release-authority-public-key.pem" || entries[1].Name() != "release-authority-transition-chain.json" || entries[2].Name() != "release-authority-trust-root-public-key.pem" {
		t.Fatalf("chain sidecars=%v", entries)
	}
	signerSPKI, err := os.ReadFile(fixture.SignerKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signerID, err := releaseindex.PublicKeyID(signerSPKI)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := canonicaljson.Marshal(releaseindex.Policy{
		SchemaVersion: releaseindex.SchemaVersion, Product: releaseindex.Product, Channel: releaseindex.Channel, Purpose: releaseindex.Purpose,
		Generation: 1, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256", Keys: []releaseindex.PolicyKey{{KeyID: signerID, Status: "trusted"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policyInput := filepath.Join(t.TempDir(), "terminal-policy.json")
	if err := os.WriteFile(policyInput, policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(t.TempDir(), "terminal-policy")
	if exit, stdout, stderr := runReleaseCLI(t, false, "--json", "--data-dir", fixture.DataRoot,
		"sign-release-policy", "--policy", policyInput, "--key", terminalPrivate, "--out-dir", policyDir,
	); exit != 0 || stderr != "" {
		t.Fatalf("sign terminal policy exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	args := append([]string{"--json", "--data-dir", fixture.DataRoot}, fixture.VerifyArgs[1:]...)
	for index, value := range args {
		if value == fixture.PolicyPath {
			args[index] = filepath.Join(policyDir, "release-key-policy.dsse.json")
		}
		if value == fixture.AuthorityPath {
			args[index] = filepath.Join(policyDir, "release-authority-public-key.pem")
		}
	}
	args = append(args, "--authority-transition-chain", filepath.Join(chainDir, "release-authority-transition-chain.json"),
		"--authority-trust-root", rootPublic, "--minimum-authority-generation", "2")
	fullExit, fullStdout, fullStderr := runReleaseCLI(t, false, args...)
	portableExit, portableStdout, portableStderr := runReleaseCLI(t, true, args...)
	if fullExit != 0 || portableExit != 0 || fullStderr != "" || portableStderr != "" || fullStdout != portableStdout {
		t.Fatalf("chain verifier parity full=(%d,%s,%s) portable=(%d,%s,%s)", fullExit, fullStdout, fullStderr, portableExit, portableStdout, portableStderr)
	}
	response := decodeEnvelope(t, []byte(fullStdout))
	var report map[string]any
	decodeJSON(t, response.Data, &report)
	if report["trustBasis"] != "release-key-policy-v1+authority-transition-chain-v1" || report["authorityTransitionChainHopCount"] != float64(2) ||
		report["authorityTransitionChainGeneration"] != float64(2) || report["authorityTransitionChainDigest"] == "" ||
		report["trustRootKeyId"] == report["policyAuthorityKeyId"] || report["publisherIdentityAttestation"] != "none" || report["timeAttestation"] != "none" {
		t.Fatalf("chain report = %#v", report)
	}
}

func TestReleaseIndexBuiltBinaryOutsideWorktree(t *testing.T) {
	binary := os.Getenv("REPOPASS_PORTABLE_VERIFIER_BINARY")
	if binary == "" {
		t.Skip("set REPOPASS_PORTABLE_VERIFIER_BINARY for extracted-binary E2E")
	}
	absolute, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("external verifier is not a regular no-link file: %v", err)
	}
	working, _ := os.Getwd()
	if relative, err := filepath.Rel(working, absolute); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("verifier binary must be outside worktree: %s", absolute)
	}
	fixture := newReleaseCLIFixture(t)
	command := exec.Command(absolute, fixture.VerifyArgs...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil || stderr.Len() != 0 {
		t.Fatalf("external verifier failed: %v stderr=%s stdout=%s", err, stderr.String(), stdout.String())
	}
	response := decodeEnvelope(t, stdout.Bytes())
	if response.Status != "ok" || response.Error != nil {
		t.Fatalf("external response: %#v", response)
	}
}

func TestReleaseIndexAtomicPublishNeverOverwritesOrLeaksPartialOutput(t *testing.T) {
	artifactRoot := writeReleaseArtifacts(t)
	indexRaw, err := releaseindex.BuildIndex(artifactRoot, releaseindex.ProductVersion, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	envelopeRaw, signerSPKI, err := releaseindex.SignIndex(indexRaw, private)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	output := filepath.Join(parent, "signed")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := releaseindex.PublishSignedSidecars(output, indexRaw, envelopeRaw, signerSPKI); err == nil {
		t.Fatal("existing destination was overwritten")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "preserve" {
		t.Fatalf("sentinel changed: %q %v", got, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != "signed" {
		t.Fatalf("temporary publication leaked: entries=%v err=%v", entries, err)
	}
}

func newReleaseCLIFixture(t *testing.T) releaseCLIFixture {
	t.Helper()
	dataRoot := t.TempDir()
	artifactRoot := writeReleaseArtifacts(t)
	signerRoot, authorityRoot := t.TempDir(), t.TempDir()
	signerKey := writeReleasePrivateKey(t, signerRoot, "release-signer.pem")
	authorityKey := writeReleasePrivateKey(t, authorityRoot, "release-authority.pem")
	signedIndexDir := filepath.Join(t.TempDir(), "signed-index")
	exitCode, stdout, stderr := runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-release-index",
		"--artifact-root", artifactRoot, "--product-version", releaseindex.ProductVersion,
		"--release-generation", "1", "--key", signerKey, "--out-dir", signedIndexDir,
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("sign index exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	signerSPKIPath := filepath.Join(signedIndexDir, "signer-public-key.pem")
	signerSPKI, err := os.ReadFile(signerSPKIPath)
	if err != nil {
		t.Fatal(err)
	}
	signerKeyID, err := releaseindex.PublicKeyID(signerSPKI)
	if err != nil {
		t.Fatal(err)
	}
	policy := releaseindex.Policy{
		SchemaVersion: releaseindex.SchemaVersion, Product: releaseindex.Product,
		Channel: releaseindex.Channel, Purpose: releaseindex.Purpose, Generation: 1,
		KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		Keys: []releaseindex.PolicyKey{{KeyID: signerKeyID, Status: "trusted"}},
	}
	sort.Slice(policy.Keys, func(i, j int) bool { return policy.Keys[i].KeyID < policy.Keys[j].KeyID })
	policyRaw, err := canonicaljson.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyInputRoot := t.TempDir()
	policyInput := filepath.Join(policyInputRoot, "release-policy.json")
	if err := os.WriteFile(policyInput, policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	signedPolicyDir := filepath.Join(t.TempDir(), "signed-policy")
	exitCode, stdout, stderr = runReleaseCLI(t, false,
		"--json", "--data-dir", dataRoot, "sign-release-policy",
		"--policy", policyInput, "--key", authorityKey, "--out-dir", signedPolicyDir,
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("sign policy exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	indexPath := filepath.Join(signedIndexDir, "release-index.json")
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	indexDigest := sha256.Sum256(indexRaw)
	expected := "sha256:" + hex.EncodeToString(indexDigest[:])
	verifyArgs := []string{
		"--json", "verify-release-index",
		"--index", indexPath, "--signature", filepath.Join(signedIndexDir, "signature.dsse.json"),
		"--signer-key", signerSPKIPath, "--artifact-root", artifactRoot,
		"--policy-envelope", filepath.Join(signedPolicyDir, "release-key-policy.dsse.json"),
		"--policy-authority-key", filepath.Join(signedPolicyDir, "release-authority-public-key.pem"),
		"--minimum-policy-generation", "1", "--minimum-release-generation", "1",
		"--product", "repopass", "--channel", "alpha",
		"--expect-release-index-digest", expected,
	}
	return releaseCLIFixture{
		DataRoot: dataRoot, ArtifactRoot: artifactRoot, IndexPath: indexPath,
		SignaturePath: filepath.Join(signedIndexDir, "signature.dsse.json"), SignerKeyPath: signerSPKIPath,
		PolicyPath:    filepath.Join(signedPolicyDir, "release-key-policy.dsse.json"),
		AuthorityPath: filepath.Join(signedPolicyDir, "release-authority-public-key.pem"),
		IndexDigest:   expected, VerifyArgs: verifyArgs,
	}
}

func writeReleaseArtifacts(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{
		"repopass-linux-amd64":       []byte("synthetic-linux-release\n"),
		"repopass-windows-amd64.exe": []byte("synthetic-windows-release\n"),
	}
	names := make([]string, 0, len(files))
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		digest := sha256.Sum256(files[name])
		sums.WriteString(hex.EncodeToString(digest[:]))
		sums.WriteString("  ")
		sums.WriteString(name)
		sums.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(sums.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeReleasePrivateKey(t *testing.T, root, name string) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	secureCLIPrivateKeyForTest(t, path)
	return path
}

func writeReleasePublicKeyForPrivate(t *testing.T, privatePath, outputPath string) string {
	t.Helper()
	raw, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		t.Fatal("test private key PEM is not canonical")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ed, ok := private.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("test private key is not Ed25519")
	}
	der, err := x509.MarshalPKIXPublicKey(ed.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return outputPath
}

func runReleaseCLI(t *testing.T, verifier bool, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	var exitCode int
	if verifier {
		exitCode = app.RunVerifier(context.Background(), args)
	} else {
		exitCode = app.Run(context.Background(), args)
	}
	return exitCode, stdout.String(), stderr.String()
}
