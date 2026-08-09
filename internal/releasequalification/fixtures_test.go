package releasequalification

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testProductVersion = "0.1.0-alpha.33"
	canonicalModule    = "github.com/taipei49314/RepoPassport"
	legacyModule       = "github.com/repopass/repopass"
)

type qualificationFixture struct {
	root            string
	revision        string
	tree            string
	fullLinux       string
	fullWindows     string
	verifierLinux   string
	verifierWindows string
	helper          string
	legacyRevision  string
	legacyVerifier  string
}

var (
	fixtureOnce  sync.Once
	fixtureValue *qualificationFixture
	fixtureErr   error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureValue != nil {
		_ = os.RemoveAll(fixtureValue.root)
	}
	os.Exit(code)
}

func testQualificationFixture(t *testing.T) *qualificationFixture {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureValue, fixtureErr = buildQualificationFixture()
	})
	if fixtureErr != nil {
		t.Fatalf("build release-qualification fixture: %v", fixtureErr)
	}
	return fixtureValue
}

func buildQualificationFixture() (*qualificationFixture, error) {
	root, err := os.MkdirTemp("", "repopass-releasequalification-test-")
	if err != nil {
		return nil, err
	}
	f := &qualificationFixture{root: root}
	fail := func(err error) (*qualificationFixture, error) {
		_ = os.RemoveAll(root)
		return nil, err
	}

	canonicalRepo := filepath.Join(root, "canonical-source")
	if err := createFixtureModule(canonicalRepo, canonicalModule); err != nil {
		return fail(err)
	}
	if err := gitFixture(canonicalRepo, "init", "-q"); err != nil {
		return fail(err)
	}
	if err := gitFixture(canonicalRepo, "config", "user.name", "RepoPassport qualification test"); err != nil {
		return fail(err)
	}
	if err := gitFixture(canonicalRepo, "config", "user.email", "qualification@example.invalid"); err != nil {
		return fail(err)
	}
	if err := gitFixture(canonicalRepo, "add", "--", "."); err != nil {
		return fail(err)
	}
	if err := gitFixture(canonicalRepo, "commit", "-q", "-m", "fixture"); err != nil {
		return fail(err)
	}
	if f.revision, err = gitFixtureOutput(canonicalRepo, "rev-parse", "HEAD"); err != nil {
		return fail(err)
	}
	if f.tree, err = gitFixtureOutput(canonicalRepo, "rev-parse", "HEAD^{tree}"); err != nil {
		return fail(err)
	}

	outputRoot := filepath.Join(root, "outputs")
	if err := os.Mkdir(outputRoot, 0o700); err != nil {
		return fail(err)
	}
	f.fullLinux = filepath.Join(outputRoot, "repopass-linux-amd64")
	f.fullWindows = filepath.Join(outputRoot, "repopass-windows-amd64.exe")
	f.verifierLinux = filepath.Join(outputRoot, "repopass-verify-linux-amd64")
	f.verifierWindows = filepath.Join(outputRoot, "repopass-verify-windows-amd64.exe")
	f.helper = filepath.Join(outputRoot, "repopass-kit-host.exe")
	builds := []struct {
		pkg, path, goos string
	}{
		{"./cmd/repopass", f.fullLinux, "linux"},
		{"./cmd/repopass", f.fullWindows, "windows"},
		{"./cmd/repopass-verify", f.verifierLinux, "linux"},
		{"./cmd/repopass-verify", f.verifierWindows, "windows"},
		{"./cmd/repopass-kit", f.helper, runtime.GOOS},
	}
	for _, build := range builds {
		if err := goBuildFixture(canonicalRepo, build.pkg, build.path, build.goos); err != nil {
			return fail(err)
		}
	}

	legacyRepo := filepath.Join(root, "legacy-source")
	if err := createFixtureModule(legacyRepo, legacyModule); err != nil {
		return fail(err)
	}
	if err := gitFixture(legacyRepo, "init", "-q"); err != nil {
		return fail(err)
	}
	if err := gitFixture(legacyRepo, "config", "user.name", "RepoPassport qualification test"); err != nil {
		return fail(err)
	}
	if err := gitFixture(legacyRepo, "config", "user.email", "qualification@example.invalid"); err != nil {
		return fail(err)
	}
	if err := gitFixture(legacyRepo, "add", "--", "."); err != nil {
		return fail(err)
	}
	if err := gitFixture(legacyRepo, "commit", "-q", "-m", "fixture"); err != nil {
		return fail(err)
	}
	if f.legacyRevision, err = gitFixtureOutput(legacyRepo, "rev-parse", "HEAD"); err != nil {
		return fail(err)
	}
	f.legacyVerifier = filepath.Join(outputRoot, "legacy-repopass-verify-linux-amd64")
	if err := goBuildFixture(legacyRepo, "./cmd/repopass-verify", f.legacyVerifier, "linux"); err != nil {
		return fail(err)
	}
	return f, nil
}

func createFixtureModule(root, module string) error {
	for _, command := range []string{"repopass", "repopass-verify", "repopass-kit"} {
		dir := filepath.Join(root, "cmd", command)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+module+"\n\ngo 1.24\n"), 0o600)
}

func gitFixture(root string, args ...string) error {
	_, err := runFixtureCommand(root, nil, "git", args...)
	return err
}

func gitFixtureOutput(root string, args ...string) (string, error) {
	out, err := runFixtureCommand(root, nil, "git", args...)
	return strings.TrimSpace(string(out)), err
}

func goBuildFixture(root, pkg, output, goos string) error {
	env := []string{
		"GOWORK=off",
		"CGO_ENABLED=0",
		"GOOS=" + goos,
		"GOARCH=amd64",
	}
	_, err := runFixtureCommand(root, env, "go", "build", "-buildvcs=true", "-trimpath", "-o", output, pkg)
	return err
}

func runFixtureCommand(root string, extraEnv []string, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Dir = root
	command.Env = append(os.Environ(), extraEnv...)
	out, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s fixture command failed", name)
	}
	return out, nil
}

func copyFixtureFile(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func fileDigest(t *testing.T, path string) (int64, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return int64(len(data)), "sha256:" + hex.EncodeToString(digest[:])
}

type testKitOptions struct {
	targetOS         string
	binary           []byte
	order            []string
	manifest         []byte
	verifierType     byte
	verifierLinkname string
	verifierFormat   tar.Format
	verifierPAX      map[string]string
	verifierMode     int64
	extraEntries     []testTarEntry
}

type testTarEntry struct {
	name     string
	data     []byte
	mode     int64
	typeflag byte
	linkname string
	format   tar.Format
	pax      map[string]string
}

func canonicalTestKit(t *testing.T, targetOS, binaryPath string) []byte {
	t.Helper()
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return buildTestKit(t, testKitOptions{targetOS: targetOS, binary: binary})
}

func buildTestKit(t *testing.T, options testKitOptions) []byte {
	t.Helper()
	name := "repopass-verify"
	if options.targetOS == "windows" {
		name += ".exe"
	}
	manifest := options.manifest
	if manifest == nil {
		manifest = testKitManifest(options.targetOS, options.binary, "", -1)
	}
	verifierMode := options.verifierMode
	if verifierMode == 0 {
		verifierMode = 0o755
	}
	verifierType := options.verifierType
	if verifierType == 0 {
		verifierType = tar.TypeReg
	}
	verifierFormat := options.verifierFormat
	if verifierFormat == tar.FormatUnknown {
		verifierFormat = tar.FormatUSTAR
	}
	entries := map[string]testTarEntry{
		"PORTABLE_VERIFIER_MANIFEST.json": {name: "PORTABLE_VERIFIER_MANIFEST.json", data: manifest, mode: 0o644, typeflag: tar.TypeReg, format: tar.FormatUSTAR},
		"TRUST_BOUNDARY.txt":              {name: "TRUST_BOUNDARY.txt", data: []byte(testTrustBoundary()), mode: 0o644, typeflag: tar.TypeReg, format: tar.FormatUSTAR},
		"USAGE.txt":                       {name: "USAGE.txt", data: []byte(testUsage(options.targetOS)), mode: 0o644, typeflag: tar.TypeReg, format: tar.FormatUSTAR},
		name: {name: name, data: options.binary, mode: verifierMode, typeflag: verifierType,
			linkname: options.verifierLinkname, format: verifierFormat, pax: options.verifierPAX},
	}
	order := append([]string(nil), options.order...)
	if len(order) == 0 {
		for entryName := range entries {
			order = append(order, entryName)
		}
		sort.Strings(order)
	}
	var output strings.Builder
	writer := tar.NewWriter(&stringWriter{builder: &output})
	writeEntry := func(entry testTarEntry) {
		t.Helper()
		header := &tar.Header{
			Name: entry.name, Mode: entry.mode, Size: int64(len(entry.data)), Typeflag: entry.typeflag,
			Linkname: entry.linkname, Format: entry.format, ModTime: time.Unix(0, 0).UTC(),
			Uid: 0, Gid: 0, Uname: "", Gname: "", PAXRecords: entry.pax,
		}
		if entry.typeflag != tar.TypeReg && entry.typeflag != tar.TypeRegA {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, entryName := range order {
		entry, ok := entries[entryName]
		if !ok {
			t.Fatalf("unknown test kit entry %q", entryName)
		}
		writeEntry(entry)
	}
	for _, entry := range options.extraEntries {
		writeEntry(entry)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(output.String())
}

// stringWriter is intentionally independent of internal/releasekit and keeps
// test archives byte-addressable without a second production parser/builder.
type stringWriter struct{ builder *strings.Builder }

func (w *stringWriter) Write(data []byte) (int, error) { return w.builder.WriteString(string(data)) }

func testKitManifest(targetOS string, binary []byte, digestOverride string, sizeOverride int64) []byte {
	name := "repopass-verify"
	if targetOS == "windows" {
		name += ".exe"
	}
	digest := sha256.Sum256(binary)
	digestText := "sha256:" + hex.EncodeToString(digest[:])
	if digestOverride != "" {
		digestText = digestOverride
	}
	size := int64(len(binary))
	if sizeOverride >= 0 {
		size = sizeOverride
	}
	text := "{" +
		"\"artifactType\":\"repopass-portable-offline-verifier\"," +
		"\"binary\":{\"path\":" + strconv.Quote(name) + "," +
		"\"sha256\":" + strconv.Quote(digestText) + "," +
		fmt.Sprintf("\"size\":%d},", size) +
		"\"capabilities\":{\"commands\":[\"verify-attestation\",\"verify-release-index\"],\"bundleVersions\":[\"1\",\"2\"]," +
		"\"currentness\":\"optional-current-manifest\",\"historicalReplayRequiresWorktree\":false," +
		"\"networkRequired\":false,\"trustModes\":[\"explicit-spki\",\"offline-policy-v1\",\"signed-offline-policy-v2\",\"signed-offline-policy-v2-explicit-old-root-authority-transition-v1\",\"signed-offline-policy-v2-explicit-root-authority-transition-chain-v1\",\"release-index-explicit-root-policy\",\"release-index-explicit-old-root-authority-transition-v1\",\"release-index-explicit-root-authority-transition-chain-v1\"]}," +
		"\"productVersion\":" + strconv.Quote(testProductVersion) + "," +
		"\"schemaVersion\":\"1\"," +
		"\"target\":{\"goarch\":\"amd64\",\"goos\":" + strconv.Quote(targetOS) + "}," +
		"\"trustBoundary\":{\"capability\":\"incomplete\",\"embeddedKeyIsTrustAnchor\":false,\"formalClaim\":false,\"identityAttestation\":\"none\",\"overall\":\"inconclusive\",\"timeAttestation\":\"none\"}}\n"
	return []byte(text)
}

func testUsage(targetOS string) string {
	return "RepoPassport portable offline verifier (" + targetOS + "/amd64)\n" +
		"Commands: help, version, verify-attestation, verify-release-index\n" +
		"Acceptance is relative to explicit caller-supplied trust roots and policies.\n"
}

func testTrustBoundary() string {
	return "embeddedKeyIsTrustAnchor=false\nformalClaim=false\ncapability=incomplete\noverall=inconclusive\nidentityAttestation=none\ntimeAttestation=none\nofflineTrustPolicySidecarsIncluded=false\nofflineTrustPolicyAuthorityTransitionSidecarsIncluded=false\nofflineTrustPolicyAuthorityTransitionChainSidecarsIncluded=false\nreleaseIndexSidecarsIncluded=false\nauthorityTransitionSidecarsIncluded=false\nevidenceIncluded=false\nprivateKeyIncluded=false\nrootKeyIncluded=false\n"
}
