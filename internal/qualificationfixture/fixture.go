// Package qualificationfixture exports and verifies prebuilt qualification
// test binaries. The expected manifest digest is deliberately supplied out of
// band when a fixture crosses into a contained test process.
package qualificationfixture

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

const (
	SchemaVersion = "1"
	ManifestName  = "qualification-fixture.json"

	ImportRootEnv      = "REPOPASS_RELEASEQUALIFICATION_FIXTURE_IMPORT_ROOT"
	ManifestDigestEnv  = "REPOPASS_RELEASEQUALIFICATION_FIXTURE_MANIFEST_DIGEST"
	maxManifestBytes   = int64(1 << 20)
	maxFixtureFileSize = int64(128 << 20)
)

// BuildInfo is the security-relevant subset of debug/buildinfo bound into the
// fixture manifest.
type BuildInfo struct {
	MainPath            string `json:"mainPath"`
	MainModulePath      string `json:"mainModulePath"`
	VCSRevision         string `json:"vcsRevision"`
	VCSModified         bool   `json:"vcsModified"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	CGOEnabled          bool   `json:"cgoEnabled"`
	Trimpath            bool   `json:"trimpath"`
	FullBuildInfoSHA256 string `json:"fullBuildInfoSha256"`
}

// Binary is one content- and build-identity-bound fixture artifact.
type Binary struct {
	Path           string    `json:"path"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256"`
	SourceRevision string    `json:"sourceRevision"`
	BuildInfo      BuildInfo `json:"buildInfo"`
}

// Manifest binds the source identities and every executable in one fixture.
type Manifest struct {
	SchemaVersion  string   `json:"schemaVersion"`
	Revision       string   `json:"revision"`
	Tree           string   `json:"tree"`
	LegacyRevision string   `json:"legacyRevision"`
	Binaries       []Binary `json:"binaries"`
}

// Envelope keeps the digest beside, but outside, the manifest it hashes.
type Envelope struct {
	Manifest       Manifest `json:"manifest"`
	ManifestDigest string   `json:"manifestDigest"`
}

// BinaryInput describes a host-built binary to copy into an empty export root.
type BinaryInput struct {
	SourcePath             string
	RelativePath           string
	SourceRevision         string
	ExpectedMainPath       string
	ExpectedMainModulePath string
	ExpectedGOOS           string
	ExpectedGOARCH         string
}

// Spec describes the source identities and host-built artifacts to export.
type Spec struct {
	Revision       string
	Tree           string
	LegacyRevision string
	Binaries       []BinaryInput
}

// File is a verified artifact path exposed to a caller that needs to bind
// read-only handles before launching a contained child.
type File struct {
	Path           string
	RelativePath   string
	Size           int64
	SHA256         string
	SourceRevision string
	BuildInfo      BuildInfo
}

// Fixture is a fully verified manifest and its iterable artifact paths.
type Fixture struct {
	Root           string
	Manifest       Manifest
	ManifestDigest string
	Files          []File
}

// Export copies host-built binaries into an existing empty directory, writes
// one canonical manifest envelope, and verifies the completed fixture.
func Export(root string, spec Spec) (*Fixture, error) {
	absolute, err := emptyRoot(root)
	if err != nil {
		return nil, err
	}
	if err := validateSourceIdentities(spec.Revision, spec.Tree, spec.LegacyRevision); err != nil {
		return nil, err
	}
	if len(spec.Binaries) == 0 {
		return nil, fmt.Errorf("qualification fixture has no binaries")
	}

	inputs := append([]BinaryInput(nil), spec.Binaries...)
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].RelativePath < inputs[j].RelativePath })
	manifest := Manifest{
		SchemaVersion:  SchemaVersion,
		Revision:       spec.Revision,
		Tree:           spec.Tree,
		LegacyRevision: spec.LegacyRevision,
		Binaries:       make([]Binary, 0, len(inputs)),
	}
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if err := validateRelativeName(input.RelativePath); err != nil {
			return nil, err
		}
		if _, exists := seen[input.RelativePath]; exists {
			return nil, fmt.Errorf("qualification fixture binary %q is duplicated", input.RelativePath)
		}
		seen[input.RelativePath] = struct{}{}
		if input.SourceRevision != spec.Revision && input.SourceRevision != spec.LegacyRevision {
			return nil, fmt.Errorf("qualification fixture binary %q has an unbound source revision", input.RelativePath)
		}

		data, mode, information, digest, err := inspectBinary(input.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("inspect qualification fixture binary %q: %w", input.RelativePath, err)
		}
		if information.VCSRevision != input.SourceRevision ||
			information.MainPath != input.ExpectedMainPath ||
			information.MainModulePath != input.ExpectedMainModulePath ||
			information.GOOS != input.ExpectedGOOS || information.GOARCH != input.ExpectedGOARCH {
			return nil, fmt.Errorf("qualification fixture binary %q build identity mismatched export spec", input.RelativePath)
		}
		destination := filepath.Join(absolute, input.RelativePath)
		if err := writeExclusive(destination, data, mode.Perm()); err != nil {
			return nil, fmt.Errorf("copy qualification fixture binary %q: %w", input.RelativePath, err)
		}
		manifest.Binaries = append(manifest.Binaries, Binary{
			Path:           input.RelativePath,
			Size:           int64(len(data)),
			SHA256:         digest,
			SourceRevision: input.SourceRevision,
			BuildInfo:      information,
		})
	}

	manifestDigest, err := canonicaljson.Digest(manifest)
	if err != nil {
		return nil, err
	}
	envelope := Envelope{Manifest: manifest, ManifestDigest: manifestDigest}
	raw, err := canonicaljson.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(absolute, ManifestName), raw, 0o600); err != nil {
		return nil, fmt.Errorf("write qualification fixture manifest: %w", err)
	}
	return Load(absolute, manifestDigest)
}

// Load verifies the out-of-band manifest digest, every file's bytes, and the
// debug build information reread from those exact bytes.
func Load(root, expectedDigest string) (*Fixture, error) {
	if !validDigest(expectedDigest) {
		return nil, fmt.Errorf("qualification fixture expected manifest digest is invalid")
	}
	absolute, envelope, err := readEnvelope(root)
	if err != nil {
		return nil, err
	}
	if !sameDigest(envelope.ManifestDigest, expectedDigest) {
		return nil, fmt.Errorf("qualification fixture manifest digest mismatched expected digest")
	}

	files := make([]File, 0, len(envelope.Manifest.Binaries))
	if err := validateExactInventory(absolute, envelope.Manifest); err != nil {
		return nil, err
	}
	for _, binary := range envelope.Manifest.Binaries {
		path := filepath.Join(absolute, binary.Path)
		data, _, information, digest, err := inspectBinary(path)
		if err != nil {
			return nil, fmt.Errorf("verify qualification fixture binary %q: %w", binary.Path, err)
		}
		if int64(len(data)) != binary.Size || !sameDigest(digest, binary.SHA256) {
			return nil, fmt.Errorf("qualification fixture binary %q content drifted", binary.Path)
		}
		if information != binary.BuildInfo {
			return nil, fmt.Errorf("qualification fixture binary %q build information drifted", binary.Path)
		}
		files = append(files, File{
			Path:           path,
			RelativePath:   binary.Path,
			Size:           binary.Size,
			SHA256:         binary.SHA256,
			SourceRevision: binary.SourceRevision,
			BuildInfo:      binary.BuildInfo,
		})
	}
	return &Fixture{
		Root:           absolute,
		Manifest:       envelope.Manifest,
		ManifestDigest: envelope.ManifestDigest,
		Files:          files,
	}, nil
}

func readEnvelope(root string) (string, Envelope, error) {
	absolute, err := existingRoot(root)
	if err != nil {
		return "", Envelope{}, err
	}
	raw, _, err := readRegularFile(filepath.Join(absolute, ManifestName), maxManifestBytes)
	if err != nil {
		return "", Envelope{}, fmt.Errorf("read qualification fixture manifest: %w", err)
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return "", Envelope{}, fmt.Errorf("decode qualification fixture manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return "", Envelope{}, err
	}
	canonical, err := canonicaljson.Marshal(envelope)
	if err != nil {
		return "", Envelope{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return "", Envelope{}, fmt.Errorf("qualification fixture manifest is not canonical JSON")
	}
	if err := validateManifest(envelope.Manifest); err != nil {
		return "", Envelope{}, err
	}
	digest, err := canonicaljson.Digest(envelope.Manifest)
	if err != nil {
		return "", Envelope{}, err
	}
	if !validDigest(envelope.ManifestDigest) || !sameDigest(envelope.ManifestDigest, digest) {
		return "", Envelope{}, fmt.Errorf("qualification fixture embedded manifest digest mismatched content")
	}
	return absolute, envelope, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("qualification fixture schema version is unsupported")
	}
	if err := validateSourceIdentities(manifest.Revision, manifest.Tree, manifest.LegacyRevision); err != nil {
		return err
	}
	if len(manifest.Binaries) == 0 {
		return fmt.Errorf("qualification fixture manifest has no binaries")
	}
	previous := ""
	for _, binary := range manifest.Binaries {
		if err := validateRelativeName(binary.Path); err != nil {
			return err
		}
		if previous != "" && binary.Path <= previous {
			return fmt.Errorf("qualification fixture binary paths are not unique canonical order")
		}
		previous = binary.Path
		if binary.Size < 1 || binary.Size > maxFixtureFileSize || !validDigest(binary.SHA256) {
			return fmt.Errorf("qualification fixture binary %q metadata is invalid", binary.Path)
		}
		if binary.SourceRevision != manifest.Revision && binary.SourceRevision != manifest.LegacyRevision {
			return fmt.Errorf("qualification fixture binary %q source revision is unbound", binary.Path)
		}
		if err := validateBuildInformation(binary.BuildInfo, binary.SourceRevision); err != nil {
			return fmt.Errorf("qualification fixture binary %q manifest build information is invalid: %w", binary.Path, err)
		}
	}
	return nil
}

func validateBuildInformation(information BuildInfo, sourceRevision string) error {
	if information.MainPath == "" || information.MainModulePath == "" ||
		information.VCSRevision != sourceRevision || information.VCSModified ||
		information.GOOS == "" || information.GOARCH == "" || information.CGOEnabled ||
		!information.Trimpath || !validDigest(information.FullBuildInfoSHA256) {
		return fmt.Errorf("required debug build information is absent or inconsistent")
	}
	return nil
}

func inspectBinary(path string) ([]byte, os.FileMode, BuildInfo, string, error) {
	data, mode, err := readRegularFile(path, maxFixtureFileSize)
	if err != nil {
		return nil, 0, BuildInfo{}, "", err
	}
	parsed, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return nil, 0, BuildInfo{}, "", fmt.Errorf("read debug build information: %w", err)
	}
	information, err := selectBuildInformation(parsed)
	if err != nil {
		return nil, 0, BuildInfo{}, "", err
	}
	digest := sha256.Sum256(data)
	return data, mode, information, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func selectBuildInformation(info *debug.BuildInfo) (BuildInfo, error) {
	if info == nil || info.Path == "" || info.Main.Path == "" || info.Main.Replace != nil {
		return BuildInfo{}, fmt.Errorf("main debug build information is invalid")
	}
	revision, err := oneSetting(info.Settings, "vcs.revision")
	if err != nil || !validObjectID(revision) {
		return BuildInfo{}, fmt.Errorf("vcs.revision build setting is invalid")
	}
	modifiedText, err := oneSetting(info.Settings, "vcs.modified")
	if err != nil {
		return BuildInfo{}, err
	}
	modified, err := strconv.ParseBool(modifiedText)
	if err != nil {
		return BuildInfo{}, fmt.Errorf("vcs.modified build setting is invalid")
	}
	goos, err := oneSetting(info.Settings, "GOOS")
	if err != nil || goos == "" {
		return BuildInfo{}, fmt.Errorf("GOOS build setting is invalid")
	}
	goarch, err := oneSetting(info.Settings, "GOARCH")
	if err != nil || goarch == "" {
		return BuildInfo{}, fmt.Errorf("GOARCH build setting is invalid")
	}
	trimpathText, err := oneSetting(info.Settings, "-trimpath")
	if err != nil {
		return BuildInfo{}, err
	}
	trimpath, err := strconv.ParseBool(trimpathText)
	if err != nil {
		return BuildInfo{}, fmt.Errorf("-trimpath build setting is invalid")
	}
	cgoText, err := oneSetting(info.Settings, "CGO_ENABLED")
	if err != nil {
		return BuildInfo{}, err
	}
	cgoEnabled, err := strconv.ParseBool(cgoText)
	if err != nil {
		return BuildInfo{}, fmt.Errorf("CGO_ENABLED build setting is invalid")
	}
	fullDigest := sha256.Sum256([]byte(info.String()))
	result := BuildInfo{
		MainPath:            info.Path,
		MainModulePath:      info.Main.Path,
		VCSRevision:         revision,
		VCSModified:         modified,
		GOOS:                goos,
		GOARCH:              goarch,
		CGOEnabled:          cgoEnabled,
		Trimpath:            trimpath,
		FullBuildInfoSHA256: "sha256:" + hex.EncodeToString(fullDigest[:]),
	}
	if err := validateBuildInformation(result, revision); err != nil {
		return BuildInfo{}, err
	}
	return result, nil
}

func oneSetting(settings []debug.BuildSetting, key string) (string, error) {
	count := 0
	value := ""
	for _, setting := range settings {
		if setting.Key == key {
			count++
			value = setting.Value
		}
	}
	if count != 1 {
		return "", fmt.Errorf("debug build setting %q occurred %d times", key, count)
	}
	return value, nil
}

func emptyRoot(root string) (string, error) {
	absolute, err := existingRoot(root)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(absolute)
	if err != nil {
		return "", fmt.Errorf("read qualification fixture export root: %w", err)
	}
	if len(entries) != 0 {
		return "", fmt.Errorf("qualification fixture export root is not empty")
	}
	return absolute, nil
}

func validateExactInventory(root string, manifest Manifest) error {
	expected := make(map[string]struct{}, len(manifest.Binaries)+1)
	expected[ManifestName] = struct{}{}
	for _, binary := range manifest.Binaries {
		expected[binary.Path] = struct{}{}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read qualification fixture inventory: %w", err)
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("qualification fixture inventory has %d entries, want %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("qualification fixture inventory contains unexpected entry %q", entry.Name())
		}
		information, err := entry.Info()
		if err != nil || !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("qualification fixture inventory entry %q is not a plain regular file", entry.Name())
		}
	}
	return nil
}

func existingRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("qualification fixture root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve qualification fixture root: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect qualification fixture root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("qualification fixture root is not a plain directory")
	}
	return absolute, nil
}

func readRegularFile(path string, maximum int64) ([]byte, os.FileMode, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum {
		return nil, 0, fmt.Errorf("file is not a bounded plain regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || before.Size() != opened.Size() || before.Mode() != opened.Mode() {
		_ = file.Close()
		return nil, 0, fmt.Errorf("file identity changed before read")
	}
	data := make([]byte, before.Size())
	_, readErr := io.ReadFull(file, data)
	pathAfter, pathErr := os.Lstat(path)
	openedAfter, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || pathErr != nil || statErr != nil || closeErr != nil ||
		!os.SameFile(before, pathAfter) || !os.SameFile(before, openedAfter) ||
		before.Size() != pathAfter.Size() || before.Size() != openedAfter.Size() ||
		before.Mode() != pathAfter.Mode() || before.Mode() != openedAfter.Mode() ||
		!before.ModTime().Equal(pathAfter.ModTime()) || !before.ModTime().Equal(openedAfter.ModTime()) {
		return nil, 0, fmt.Errorf("file identity changed during read")
	}
	return data, before.Mode(), nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("qualification fixture manifest has trailing JSON")
		}
		return fmt.Errorf("decode qualification fixture manifest trailer: %w", err)
	}
	return nil
}

func validateSourceIdentities(revision, tree, legacyRevision string) error {
	if !validObjectID(revision) || !validObjectID(tree) || !validObjectID(legacyRevision) {
		return fmt.Errorf("qualification fixture source identities are invalid")
	}
	return nil
}

func validateRelativeName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.IsAbs(name) ||
		filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("qualification fixture binary name %q is not a canonical relative name", name)
	}
	return nil
}

func validObjectID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func sameDigest(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
