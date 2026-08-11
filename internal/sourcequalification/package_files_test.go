package sourcequalification

// Production contract under test:
//
//	func assembleQualificationPackage(linuxDir, windowsDir, outputDir string) (packageDigest string, err error)
//
// The operation owns strict lane-directory inspection, cross-lane receipt and
// source binding, and atomic no-replace publication of the four-file package.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	packageFilesArchiveName        = "repopass-source.tar"
	packageFilesManifestName       = "source-archive-manifest-v1.json"
	packageFilesLinuxReceiptName   = "source-qualification-linux-amd64-v1.json"
	packageFilesWindowsReceiptName = "source-qualification-windows-amd64-v1.json"
)

type packageFilesFixture struct {
	root           string
	linuxDir       string
	windowsDir     string
	outputDir      string
	archive        []byte
	manifest       []byte
	linuxReceipt   []byte
	windowsReceipt []byte
}

func TestAssembleQualificationPackagePublishesExactBoundFourFileSet(t *testing.T) {
	fixture := newPackageFilesFixture(t)

	digest, err := assembleQualificationPackage(fixture.linuxDir, fixture.windowsDir, fixture.outputDir)
	if err != nil {
		t.Fatalf("assembleQualificationPackage: %v", err)
	}
	wantDigest := qualificationPackageDigest(
		fixture.archive,
		fixture.manifest,
		fixture.linuxReceipt,
		fixture.windowsReceipt,
	)
	if digest != wantDigest {
		t.Fatalf("package digest = %q, want %q", digest, wantDigest)
	}

	want := map[string][]byte{
		packageFilesArchiveName:        fixture.archive,
		packageFilesManifestName:       fixture.manifest,
		packageFilesLinuxReceiptName:   fixture.linuxReceipt,
		packageFilesWindowsReceiptName: fixture.windowsReceipt,
	}
	entries, err := os.ReadDir(fixture.outputDir)
	if err != nil {
		t.Fatalf("read aggregate directory: %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("aggregate entries = %d, want exact four-file set", len(entries))
	}
	for _, entry := range entries {
		expected, ok := want[entry.Name()]
		if !ok {
			t.Fatalf("aggregate contains unexpected entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("inspect aggregate entry %q: %v", entry.Name(), err)
		}
		if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			t.Fatalf("aggregate entry %q is not a regular file", entry.Name())
		}
		actual, err := os.ReadFile(filepath.Join(fixture.outputDir, entry.Name()))
		if err != nil {
			t.Fatalf("read aggregate entry %q: %v", entry.Name(), err)
		}
		if !bytes.Equal(actual, expected) {
			t.Fatalf("aggregate entry %q differs from the verified lane bytes", entry.Name())
		}
	}
	packageFilesWrite(t, filepath.Join(fixture.linuxDir, packageFilesArchiveName), []byte("mutated lane input\n"))
	packageFilesRequireBytes(
		t,
		filepath.Join(fixture.outputDir, packageFilesArchiveName),
		fixture.archive,
	)
}

func TestAssembleQualificationPackageRejectsNonExactLaneEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *packageFilesFixture)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				packageFilesRemove(t, filepath.Join(fixture.linuxDir, packageFilesManifestName))
			},
		},
		{
			name: "extra",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				packageFilesWrite(t, filepath.Join(fixture.windowsDir, "unexpected.json"), []byte("{}"))
			},
		},
		{
			name: "case collision or wrong case",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				exact := filepath.Join(fixture.linuxDir, packageFilesManifestName)
				collision := filepath.Join(fixture.linuxDir, "SOURCE-ARCHIVE-MANIFEST-V1.JSON")
				if runtime.GOOS == "windows" {
					if err := os.Rename(exact, collision); err != nil {
						t.Fatalf("rename wrong-case fixture: %v", err)
					}
					return
				}
				packageFilesWrite(t, collision, fixture.manifest)
			},
		},
		{
			name: "symbolic link",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				external := filepath.Join(fixture.root, "external-linux-receipt.json")
				packageFilesWrite(t, external, fixture.linuxReceipt)
				input := filepath.Join(fixture.linuxDir, packageFilesLinuxReceiptName)
				packageFilesRemove(t, input)
				if err := os.Symlink(external, input); err != nil {
					t.Skipf("symbolic links unavailable on this runner: %v", err)
				}
			},
		},
		{
			name: "hard link alias",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				external := filepath.Join(fixture.root, "external-windows-receipt.json")
				packageFilesWrite(t, external, fixture.windowsReceipt)
				input := filepath.Join(fixture.windowsDir, packageFilesWindowsReceiptName)
				packageFilesRemove(t, input)
				if err := os.Link(external, input); err != nil {
					t.Skipf("hard links unavailable on this runner: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageFilesFixture(t)
			test.mutate(t, fixture)

			if _, err := assembleQualificationPackage(fixture.linuxDir, fixture.windowsDir, fixture.outputDir); err == nil {
				t.Fatal("assembleQualificationPackage accepted a non-exact lane directory")
			}
			packageFilesRequireAbsent(t, fixture.outputDir)
		})
	}
}

func TestAssembleQualificationPackageRejectsCrossLaneByteSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *packageFilesFixture)
	}{
		{
			name: "self-consistent Windows lane has different source bytes",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				archive, manifest, tree := packageFilesAlternateSource(t)
				windowsReceipt := receiptParserCanonicalWithTree(
					t,
					LaneWindowsAMD64,
					archive,
					manifest,
					tree,
					nil,
				)
				packageFilesWrite(t, filepath.Join(fixture.windowsDir, packageFilesArchiveName), archive)
				packageFilesWrite(t, filepath.Join(fixture.windowsDir, packageFilesManifestName), manifest)
				packageFilesWrite(t, filepath.Join(fixture.windowsDir, packageFilesWindowsReceiptName), windowsReceipt)
			},
		},
		{
			name: "Windows receipt binds different source bytes",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				archive, manifest, tree := packageFilesAlternateSource(t)
				windowsReceipt := receiptParserCanonicalWithTree(
					t,
					LaneWindowsAMD64,
					archive,
					manifest,
					tree,
					nil,
				)
				packageFilesWrite(t, filepath.Join(fixture.windowsDir, packageFilesWindowsReceiptName), windowsReceipt)
			},
		},
		{
			name: "Linux receipt substituted for Windows receipt",
			mutate: func(t *testing.T, fixture *packageFilesFixture) {
				packageFilesWrite(
					t,
					filepath.Join(fixture.windowsDir, packageFilesWindowsReceiptName),
					fixture.linuxReceipt,
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageFilesFixture(t)
			test.mutate(t, fixture)

			if _, err := assembleQualificationPackage(fixture.linuxDir, fixture.windowsDir, fixture.outputDir); err == nil {
				t.Fatal("assembleQualificationPackage accepted cross-lane byte substitution")
			}
			packageFilesRequireAbsent(t, fixture.outputDir)
		})
	}
}

func TestAssembleQualificationPackageNeverReplacesPreexistingOutput(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		fixture := newPackageFilesFixture(t)
		if err := os.Mkdir(fixture.outputDir, 0o700); err != nil {
			t.Fatalf("create preexisting output directory: %v", err)
		}
		sentinel := filepath.Join(fixture.outputDir, "operator-owned.txt")
		packageFilesWrite(t, sentinel, []byte("do not replace\n"))

		if _, err := assembleQualificationPackage(fixture.linuxDir, fixture.windowsDir, fixture.outputDir); err == nil {
			t.Fatal("assembleQualificationPackage replaced a preexisting output directory")
		}
		entries, err := os.ReadDir(fixture.outputDir)
		if err != nil {
			t.Fatalf("read preexisting output directory: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != "operator-owned.txt" {
			t.Fatalf("preexisting output directory changed: %#v", entries)
		}
		packageFilesRequireBytes(t, sentinel, []byte("do not replace\n"))
	})

	t.Run("regular file", func(t *testing.T) {
		fixture := newPackageFilesFixture(t)
		packageFilesWrite(t, fixture.outputDir, []byte("operator-owned\n"))

		if _, err := assembleQualificationPackage(fixture.linuxDir, fixture.windowsDir, fixture.outputDir); err == nil {
			t.Fatal("assembleQualificationPackage replaced a preexisting output file")
		}
		packageFilesRequireBytes(t, fixture.outputDir, []byte("operator-owned\n"))
	})
}

func newPackageFilesFixture(t *testing.T) *packageFilesFixture {
	t.Helper()
	root := t.TempDir()
	archive, manifest, tree := receiptParserValidSourcePackage(t)
	fixture := &packageFilesFixture{
		root:       root,
		linuxDir:   filepath.Join(root, "linux"),
		windowsDir: filepath.Join(root, "windows"),
		outputDir:  filepath.Join(root, "aggregate"),
		archive:    archive,
		manifest:   manifest,
	}
	fixture.linuxReceipt = receiptParserCanonicalWithTree(
		t,
		LaneLinuxAMD64,
		archive,
		manifest,
		tree,
		nil,
	)
	fixture.windowsReceipt = receiptParserCanonicalWithTree(
		t,
		LaneWindowsAMD64,
		archive,
		manifest,
		tree,
		nil,
	)

	for _, directory := range []string{fixture.linuxDir, fixture.windowsDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create lane directory: %v", err)
		}
		packageFilesWrite(t, filepath.Join(directory, packageFilesArchiveName), archive)
		packageFilesWrite(t, filepath.Join(directory, packageFilesManifestName), manifest)
	}
	packageFilesWrite(t, filepath.Join(fixture.linuxDir, packageFilesLinuxReceiptName), fixture.linuxReceipt)
	packageFilesWrite(t, filepath.Join(fixture.windowsDir, packageFilesWindowsReceiptName), fixture.windowsReceipt)
	return fixture
}

func packageFilesAlternateSource(t *testing.T) ([]byte, []byte, string) {
	t.Helper()
	files := []archiveFile{
		{Path: "README.md", GitMode: "100644", Data: []byte("different tracked source\n")},
		{Path: "go.mod", GitMode: "100644", Data: []byte("module github.com/taipei49314/RepoPassport\n")},
	}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatalf("reconstruct alternate source tree: %v", err)
	}
	subject := Subject{
		Repository:      canonicalRepositoryURL,
		ModulePath:      canonicalModulePath,
		ModuleVersion:   canonicalModuleVersion,
		GitObjectFormat: "sha1",
		BaseRevision:    "0123456789abcdef0123456789abcdef01234567",
		TestedRevision:  "89abcdef0123456789abcdef0123456789abcdef",
		TreeSHA:         tree,
	}
	archive, manifest, err := buildSourcePackage(subject, files)
	if err != nil {
		t.Fatalf("build alternate source package: %v", err)
	}
	return archive, manifest, tree
}

func packageFilesWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %q: %v", filepath.Base(path), err)
	}
}

func packageFilesRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove fixture %q: %v", filepath.Base(path), err)
	}
}

func packageFilesRequireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed assembly left output path behind: %v", err)
	}
}

func packageFilesRequireBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retained path %q: %v", filepath.Base(path), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("retained path %q was modified", filepath.Base(path))
	}
}
