package releasequalification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/qualificationfixture"
)

func TestQualificationFixtureManifestBindsEveryBuild(t *testing.T) {
	_, _, loaded := exportQualificationFixtureForTest(t)
	if len(loaded.Files) != 6 {
		t.Fatalf("fixture files = %d, want 6", len(loaded.Files))
	}
	expectedTargets := map[string]string{
		fullLinuxFixtureName:       "linux/amd64",
		fullWindowsFixtureName:     "windows/amd64",
		verifierLinuxFixtureName:   "linux/amd64",
		verifierWindowsFixtureName: "windows/amd64",
		helperFixtureName:          runtimeTarget(),
		legacyVerifierFixtureName:  "linux/amd64",
	}
	for _, file := range loaded.Files {
		information := file.BuildInfo
		if got, ok := expectedTargets[file.RelativePath]; !ok || got != information.GOOS+"/"+information.GOARCH {
			t.Fatalf("fixture target %q = %s/%s", file.RelativePath, information.GOOS, information.GOARCH)
		}
		if information.MainPath == "" || information.MainModulePath == "" ||
			information.VCSRevision != file.SourceRevision || information.VCSModified ||
			information.CGOEnabled || !information.Trimpath || !strings.HasPrefix(information.FullBuildInfoSHA256, "sha256:") {
			t.Fatalf("fixture build information for %q is incomplete: %+v", file.RelativePath, information)
		}
	}
}

func TestQualificationFixtureLoadRejectsMissingManifest(t *testing.T) {
	root, digest, _ := exportQualificationFixtureForTest(t)
	if err := os.Remove(filepath.Join(root, qualificationfixture.ManifestName)); err != nil {
		t.Fatal(err)
	}
	if _, err := qualificationfixture.Load(root, digest); err == nil {
		t.Fatal("fixture load accepted a missing manifest")
	}
}

func TestQualificationFixtureLoadRejectsManifestContentDrift(t *testing.T) {
	root, digest, _ := exportQualificationFixtureForTest(t)
	envelope := readQualificationFixtureEnvelope(t, root)
	envelope.Manifest.Tree = strings.Repeat("0", 40)
	writeQualificationFixtureEnvelope(t, root, envelope)
	if _, err := qualificationfixture.Load(root, digest); err == nil {
		t.Fatal("fixture load accepted manifest content drift")
	}
}

func TestQualificationFixtureLoadRejectsCoherentManifestReplacement(t *testing.T) {
	root, expectedDigest, _ := exportQualificationFixtureForTest(t)
	envelope := readQualificationFixtureEnvelope(t, root)
	envelope.Manifest.Tree = strings.Repeat("0", 40)
	var err error
	envelope.ManifestDigest, err = canonicaljson.Digest(envelope.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeQualificationFixtureEnvelope(t, root, envelope)
	if _, err := qualificationfixture.Load(root, expectedDigest); err == nil {
		t.Fatal("fixture load blessed a coherent replacement instead of retaining the out-of-band digest")
	}
}

func TestQualificationFixtureLoadRejectsBinaryHashDrift(t *testing.T) {
	root, digest, loaded := exportQualificationFixtureForTest(t)
	path := loaded.Files[0].Path
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	position := loaded.Files[0].Size / 2
	value := []byte{0}
	if _, err := file.ReadAt(value, position); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	value[0] ^= 0xff
	if _, err := file.WriteAt(value, position); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := qualificationfixture.Load(root, digest); err == nil {
		t.Fatal("fixture load accepted binary hash drift")
	}
}

func TestQualificationFixtureLoadRejectsBuildInfoDrift(t *testing.T) {
	root, _, _ := exportQualificationFixtureForTest(t)
	envelope := readQualificationFixtureEnvelope(t, root)
	envelope.Manifest.Binaries[0].BuildInfo.MainPath += "/drift"
	var err error
	envelope.ManifestDigest, err = canonicaljson.Digest(envelope.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeQualificationFixtureEnvelope(t, root, envelope)
	if _, err := qualificationfixture.Load(root, envelope.ManifestDigest); err == nil {
		t.Fatal("fixture load accepted debug build-information drift")
	}
}

func TestQualificationFixtureLoadRejectsInventoryDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, *qualificationfixture.Fixture)
	}{
		{
			name: "extra",
			mutate: func(t *testing.T, root string, _ *qualificationfixture.Fixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "extra"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing binary",
			mutate: func(t *testing.T, _ string, loaded *qualificationfixture.Fixture) {
				t.Helper()
				if err := os.Remove(loaded.Files[0].Path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nonregular binary",
			mutate: func(t *testing.T, _ string, loaded *qualificationfixture.Fixture) {
				t.Helper()
				if err := os.Remove(loaded.Files[0].Path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(loaded.Files[0].Path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink binary",
			mutate: func(t *testing.T, _ string, loaded *qualificationfixture.Fixture) {
				t.Helper()
				if err := os.Remove(loaded.Files[0].Path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					filepath.Base(loaded.Files[1].Path),
					loaded.Files[0].Path,
				); err != nil {
					t.Skipf("symlink fixture is unavailable: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, digest, loaded := exportQualificationFixtureForTest(t)
			test.mutate(t, root, loaded)
			if _, err := qualificationfixture.Load(root, digest); err == nil {
				t.Fatal("fixture load accepted inventory drift")
			}
		})
	}
}

func TestQualificationFixtureImportEnvironmentFailsClosed(t *testing.T) {
	tests := []struct {
		name, root, digest string
	}{
		{name: "both missing"},
		{name: "digest missing", root: t.TempDir()},
		{name: "root missing", digest: "sha256:" + strings.Repeat("0", 64)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(qualificationfixture.ImportRootEnv, test.root)
			t.Setenv(qualificationfixture.ManifestDigestEnv, test.digest)
			if _, err := loadQualificationFixtureFromEnvironment(); err == nil {
				t.Fatal("fixture import accepted missing environment input")
			}
		})
	}
}

func exportQualificationFixtureForTest(t *testing.T) (string, string, *qualificationfixture.Fixture) {
	t.Helper()
	root := t.TempDir()
	loaded, err := qualificationfixture.Export(root, fixtureExportSpec(testQualificationFixture(t)))
	if err != nil {
		t.Fatalf("export qualification fixture: %v", err)
	}
	return root, loaded.ManifestDigest, loaded
}

func readQualificationFixtureEnvelope(t *testing.T, root string) qualificationfixture.Envelope {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, qualificationfixture.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var envelope qualificationfixture.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func writeQualificationFixtureEnvelope(t *testing.T, root string, envelope qualificationfixture.Envelope) {
	t.Helper()
	raw, err := canonicaljson.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, qualificationfixture.ManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func runtimeTarget() string {
	return runtime.GOOS + "/amd64"
}
