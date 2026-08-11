package sourcequalification

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestSourcePackageManifestCanonicalAndTreeBound(t *testing.T) {
	files := []archiveFile{
		{Path: "README.md", GitMode: "100644", Data: []byte("RepoPassport\n")},
		{Path: "go.mod", GitMode: "100644", Data: []byte("module github.com/taipei49314/RepoPassport\n\ngo 1.26.5\n")},
	}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{
		Repository:      "https://github.com/taipei49314/RepoPassport",
		ModulePath:      "github.com/taipei49314/RepoPassport",
		ModuleVersion:   "0.1.0-alpha.33",
		GitObjectFormat: "sha1",
		BaseRevision:    "0123456789abcdef0123456789abcdef01234567",
		TestedRevision:  "89abcdef0123456789abcdef0123456789abcdef",
		TreeSHA:         tree,
		Dirty:           false,
	}

	archive, manifest, err := buildSourcePackage(subject, files)
	if err != nil {
		t.Fatalf("buildSourcePackage: %v", err)
	}
	if len(manifest) == 0 || manifest[len(manifest)-1] == '\n' || bytes.Contains(manifest, []byte("\r")) {
		t.Fatal("manifest is not canonical JSON without a trailing newline")
	}
	var decoded any
	if err := json.Unmarshal(manifest, &decoded); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	canonical, err := canonicaljson.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, manifest) {
		t.Fatalf("manifest bytes are not repository-canonical JSON: %v", err)
	}
	if err := verifySourcePackage(archive, manifest, subject); err != nil {
		t.Fatalf("verifySourcePackage rejected canonical package: %v", err)
	}

	t.Run("archive substitution", func(t *testing.T) {
		changed := bytes.Clone(archive)
		changed[512] ^= 1
		if err := verifySourcePackage(changed, manifest, subject); err == nil {
			t.Fatal("archive byte substitution passed")
		}
	})
	t.Run("manifest alternate bytes", func(t *testing.T) {
		if err := verifySourcePackage(archive, append(bytes.Clone(manifest), '\n'), subject); err == nil {
			t.Fatal("noncanonical manifest bytes passed")
		}
	})
	t.Run("expected subject substitution", func(t *testing.T) {
		changed := subject
		changed.TestedRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := verifySourcePackage(archive, manifest, changed); err == nil {
			t.Fatal("wrong expected subject passed")
		}
	})
}

func TestSourcePackageRejectsModuleAndTreeSubstitution(t *testing.T) {
	base := Subject{
		Repository:      "https://github.com/taipei49314/RepoPassport",
		ModulePath:      "github.com/taipei49314/RepoPassport",
		ModuleVersion:   "0.1.0-alpha.33",
		GitObjectFormat: "sha1",
		BaseRevision:    "0123456789abcdef0123456789abcdef01234567",
		TestedRevision:  "89abcdef0123456789abcdef0123456789abcdef",
		Dirty:           false,
	}
	files := []archiveFile{{Path: "go.mod", GitMode: "100644", Data: []byte("module example.invalid/substitute\n\ngo 1.26.5\n")}}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatal(err)
	}
	base.TreeSHA = tree
	if _, _, err := buildSourcePackage(base, files); err == nil {
		t.Fatal("wrong go.mod module directive was accepted")
	}

	files[0].Data = []byte("module github.com/taipei49314/RepoPassport\n\ngo 1.26.5\n")
	if _, _, err := buildSourcePackage(base, files); err == nil {
		t.Fatal("copied tree SHA survived changed source bytes")
	}
}

func TestSourceArchiveParserReadsMemberBytesInPlace(t *testing.T) {
	files := []archiveFile{
		{Path: "go.mod", GitMode: "100644", Data: []byte("module github.com/taipei49314/RepoPassport\n")},
	}
	archive, err := buildCanonicalArchive(files)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCanonicalArchiveFiles(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || len(parsed[0].Data) == 0 {
		t.Fatalf("parsed archive inventory = %#v", parsed)
	}
	if &parsed[0].Data[0] != &archive[archiveBlockSize] {
		t.Fatal("archive parser copied member bytes instead of hashing the bounded input in place")
	}
}

func TestSourcePackageRejectsEscapedCanonicalNamespaceReplace(t *testing.T) {
	module := []byte("module github.com/taipei49314/RepoPassport\n\nreplace \"github.com/taipei49314/RepoPass\\x70ort\" => ./fork\n")
	files := []archiveFile{{Path: "go.mod", GitMode: "100644", Data: module}}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatal(err)
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
	if _, _, err := buildSourcePackage(subject, files); err == nil {
		t.Fatal("escaped canonical module namespace replacement was accepted")
	}
}
