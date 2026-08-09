package releasequalification

import (
	"archive/tar"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

var prePublishArtifactContract = []struct {
	id      string
	name    string
	fixture func(*qualificationFixture) string
}{
	{"full-linux-amd64", "repopass-linux-amd64", func(f *qualificationFixture) string { return f.fullLinux }},
	{"full-windows-amd64", "repopass-windows-amd64.exe", func(f *qualificationFixture) string { return f.fullWindows }},
	{"verifier-linux-amd64", "repopass-verify-linux-amd64", func(f *qualificationFixture) string { return f.verifierLinux }},
	{"verifier-windows-amd64", "repopass-verify-windows-amd64.exe", func(f *qualificationFixture) string { return f.verifierWindows }},
}

var prePublishKitContract = []struct {
	id, name, targetOS, verifierName string
}{
	{"kit-linux-amd64", "repopass-verify-linux-amd64.tar", "linux", "repopass-verify-linux-amd64"},
	{"kit-windows-amd64", "repopass-verify-windows-amd64.tar", "windows", "repopass-verify-windows-amd64.exe"},
}

func TestInspectPortableKitUsesIndependentStrictParserAndBindsEmbeddedVerifier(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := t.TempDir()
	standalone := filepath.Join(root, "repopass-verify-linux-amd64")
	kitPath := filepath.Join(root, "repopass-verify-linux-amd64.tar")
	copyFixtureFile(t, fixture.verifierLinux, standalone)
	if err := os.WriteFile(kitPath, canonicalTestKit(t, "linux", standalone), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := InspectPortableKit(KitSpec{
		ID:                     "kit-linux-amd64",
		Path:                   kitPath,
		TargetOS:               "linux",
		StandaloneVerifierPath: standalone,
	}, fixture.revision)
	if err != nil {
		t.Fatalf("canonical kit rejected: %v", err)
	}
	wantKitSize, wantKitDigest := fileDigest(t, kitPath)
	wantBinarySize, wantBinaryDigest := fileDigest(t, standalone)
	if report.ID != "kit-linux-amd64" || report.Size != wantKitSize || report.SHA256 != wantKitDigest {
		t.Fatalf("kit report = %#v, want size %d digest %s", report, wantKitSize, wantKitDigest)
	}
	if embedded := report.EmbeddedVerifier; embedded.Size != wantBinarySize || embedded.SHA256 != wantBinaryDigest || len(embedded.Results) != 0 {
		t.Fatalf("embedded verifier is not the exact standalone identity: %#v", embedded)
	}
}

func TestInspectPortableKitRejectsMutationOrderPAXLinksTrailingAndManifestMismatch(t *testing.T) {
	fixture := testQualificationFixture(t)
	binary, err := os.ReadFile(fixture.verifierLinux)
	if err != nil {
		t.Fatal(err)
	}
	canonical := buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary})
	canonicalOrder := []string{"PORTABLE_VERIFIER_MANIFEST.json", "TRUST_BOUNDARY.txt", "USAGE.txt", "repopass-verify"}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name string
		kit  func(*testing.T) []byte
	}{
		{"header mutation", func(t *testing.T) []byte { value := append([]byte(nil), canonical...); value[100] ^= 1; return value }},
		{"binary mutation", func(t *testing.T) []byte {
			value := append([]byte(nil), canonical...)
			offset := strings.Index(string(value), string(binary[:min(32, len(binary))]))
			if offset < 0 {
				t.Fatal("binary prefix absent from fixture kit")
			}
			value[offset] ^= 1
			return value
		}},
		{"wrong order", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, order: []string{"TRUST_BOUNDARY.txt", "PORTABLE_VERIFIER_MANIFEST.json", "USAGE.txt", "repopass-verify"}})
		}},
		{"PAX verifier", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, verifierFormat: tar.FormatPAX, verifierPAX: map[string]string{"comment": "forbidden"}})
		}},
		{"symlink verifier", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, verifierType: tar.TypeSymlink, verifierLinkname: "outside"})
		}},
		{"hardlink verifier", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, verifierType: tar.TypeLink, verifierLinkname: "USAGE.txt"})
		}},
		{"one trailing zero block", func(t *testing.T) []byte { return append(append([]byte(nil), canonical...), make([]byte, 512)...) }},
		{"trailing nonzero bytes", func(t *testing.T) []byte { return append(append([]byte(nil), canonical...), []byte("trailing")...) }},
		{"truncated", func(t *testing.T) []byte { return append([]byte(nil), canonical[:len(canonical)-1]...) }},
		{"manifest hash mismatch", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, manifest: testKitManifest("linux", binary, zeroDigest, -1)})
		}},
		{"manifest size smaller", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, manifest: testKitManifest("linux", binary, "", int64(len(binary)-1))})
		}},
		{"manifest size larger", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, manifest: testKitManifest("linux", binary, "", int64(len(binary)+1))})
		}},
		{"duplicate member", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, order: canonicalOrder, extraEntries: []testTarEntry{{name: "USAGE.txt", data: []byte(testUsage("linux")), mode: 0o644, typeflag: tar.TypeReg, format: tar.FormatUSTAR}}})
		}},
		{"unexpected member", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, order: canonicalOrder, extraEntries: []testTarEntry{{name: "EXTRA.txt", data: []byte("extra\n"), mode: 0o644, typeflag: tar.TypeReg, format: tar.FormatUSTAR}}})
		}},
		{"noncanonical verifier mode", func(t *testing.T) []byte {
			return buildTestKit(t, testKitOptions{targetOS: "linux", binary: binary, verifierMode: 0o700})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			standalone := filepath.Join(root, "repopass-verify-linux-amd64")
			kitPath := filepath.Join(root, "kit.tar")
			copyFixtureFile(t, fixture.verifierLinux, standalone)
			if err := os.WriteFile(kitPath, test.kit(t), 0o600); err != nil {
				t.Fatal(err)
			}
			if report, err := InspectPortableKit(KitSpec{ID: "kit-linux-amd64", Path: kitPath, TargetOS: "linux", StandaloneVerifierPath: standalone}, fixture.revision); err == nil {
				t.Fatalf("malformed/repacked kit was accepted: %#v", report)
			}
		})
	}
}

func TestInspectPortableKitRejectsCanonicalRepackWithLegacyEmbeddedVerifier(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := t.TempDir()
	standalone := filepath.Join(root, "repopass-verify-linux-amd64")
	kitPath := filepath.Join(root, "repacked-legacy.tar")
	copyFixtureFile(t, fixture.legacyVerifier, standalone)
	if err := os.WriteFile(kitPath, canonicalTestKit(t, "linux", standalone), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := InspectPortableKit(KitSpec{ID: "kit-linux-amd64", Path: kitPath, TargetOS: "linux", StandaloneVerifierPath: standalone}, fixture.legacyRevision)
	if err == nil && len(report.EmbeddedVerifier.Results) == 0 {
		t.Fatalf("legacy binary passed after manifest recompute and canonical repack: %#v", report)
	}
	requireAnyResultCode(t, report.EmbeddedVerifier.Results, buildidentity.CodeLegacyModuleReference)
}

func TestInspectPortableKitRequiresEmbeddedBytesEqualStandaloneVerifier(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := t.TempDir()
	standalone := filepath.Join(root, "repopass-verify-linux-amd64")
	kitPath := filepath.Join(root, "kit.tar")
	copyFixtureFile(t, fixture.verifierLinux, standalone)
	if err := os.WriteFile(kitPath, canonicalTestKit(t, "linux", standalone), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(standalone, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if report, err := InspectPortableKit(KitSpec{ID: "kit-linux-amd64", Path: kitPath, TargetOS: "linux", StandaloneVerifierPath: standalone}, fixture.revision); err == nil {
		t.Fatalf("embedded/standalone byte mismatch accepted: %#v", report)
	}
}

func TestInspectPortableKitLeavesNoExtractionResidueOnSuccessOrFailure(t *testing.T) {
	fixture := testQualificationFixture(t)
	inputRoot := t.TempDir()
	tempRoot := t.TempDir()
	t.Setenv("TMP", tempRoot)
	t.Setenv("TEMP", tempRoot)
	t.Setenv("TMPDIR", tempRoot)
	standalone := filepath.Join(inputRoot, "repopass-verify-linux-amd64")
	kitPath := filepath.Join(inputRoot, "kit.tar")
	copyFixtureFile(t, fixture.verifierLinux, standalone)
	canonical := canonicalTestKit(t, "linux", standalone)
	if err := os.WriteFile(kitPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	wantInput := directoryInventory(t, inputRoot)
	wantTemp := directoryInventory(t, tempRoot)
	spec := KitSpec{ID: "kit-linux-amd64", Path: kitPath, TargetOS: "linux", StandaloneVerifierPath: standalone}
	if _, err := InspectPortableKit(spec, fixture.revision); err != nil {
		t.Fatal(err)
	}
	requireSameInventory(t, inputRoot, wantInput)
	requireSameInventory(t, tempRoot, wantTemp)

	mutated := append(append([]byte(nil), canonical...), []byte("trailing")...)
	if err := os.WriteFile(kitPath, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	wantInput = directoryInventory(t, inputRoot)
	if _, err := InspectPortableKit(spec, fixture.revision); err == nil {
		t.Fatal("invalid kit unexpectedly passed")
	}
	requireSameInventory(t, inputRoot, wantInput)
	requireSameInventory(t, tempRoot, wantTemp)
}

func TestQualifyPrePublishFreezesFourBinariesAndTwoKits(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := stagePrePublish(t, fixture)
	report, err := QualifyPrePublish(root, fixture.revision, fixture.tree)
	if err != nil {
		t.Fatalf("exact pre-publish set rejected: %v (report %#v)", err, report)
	}
	if len(report.Results) != 0 {
		t.Fatalf("exact pre-publish set has identity failures: %#v", report.Results)
	}
	wantArtifactIDs := make([]string, len(prePublishArtifactContract))
	for index, slot := range prePublishArtifactContract {
		wantArtifactIDs[index] = slot.id
	}
	if got := artifactIDs(report.Artifacts); !reflect.DeepEqual(got, wantArtifactIDs) {
		t.Fatalf("pre-publish artifacts = %q, want %q", got, wantArtifactIDs)
	}
	wantKitIDs := make([]string, len(prePublishKitContract))
	for index, slot := range prePublishKitContract {
		wantKitIDs[index] = slot.id
	}
	if got := kitIDs(report.Kits); !reflect.DeepEqual(got, wantKitIDs) {
		t.Fatalf("pre-publish kits = %q, want %q", got, wantKitIDs)
	}
	wantLogIDs := append(append([]string(nil), wantArtifactIDs...), wantKitIDs...)
	requireAllowlistedLog(t, report.Log, wantLogIDs, fixture.revision, fixture.tree, root)
}

func TestReleaseQualificationProductionDoesNotImportReleaseKit(t *testing.T) {
	for name, file := range productionGoFiles(t) {
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if path == canonicalModule+"/internal/releasekit" || strings.HasSuffix(path, "/internal/releasekit") {
				t.Errorf("%s imports %q; qualification must carry an independently reviewed strict USTAR parser", name, path)
			}
		}
	}
}

func stagePrePublish(t *testing.T, fixture *qualificationFixture) string {
	t.Helper()
	root := t.TempDir()
	for _, slot := range prePublishArtifactContract {
		copyFixtureFile(t, slot.fixture(fixture), filepath.Join(root, slot.name))
	}
	for _, slot := range prePublishKitContract {
		binaryPath := filepath.Join(root, slot.verifierName)
		if err := os.WriteFile(filepath.Join(root, slot.name), canonicalTestKit(t, slot.targetOS, binaryPath), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func requireAnyResultCode(t *testing.T, results []buildidentity.Result, code buildidentity.Code) {
	t.Helper()
	for _, result := range results {
		if result.Status == buildidentity.StatusFail && result.Code == code {
			return
		}
	}
	t.Fatalf("results = %#v, want FAIL/%s", results, code)
}

func kitIDs(reports []KitReport) []string {
	ids := make([]string, len(reports))
	for index, report := range reports {
		ids[index] = report.ID
	}
	return ids
}

func directoryInventory(t *testing.T, root string) []string {
	t.Helper()
	var inventory []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		inventory = append(inventory, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(inventory)
	return inventory
}

func requireSameInventory(t *testing.T, root string, want []string) {
	t.Helper()
	if got := directoryInventory(t, root); !reflect.DeepEqual(got, want) {
		t.Fatalf("temporary extraction residue under private root: got %q, want %q", got, want)
	}
}
