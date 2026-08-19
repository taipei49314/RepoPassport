package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTrustedControllerRuntimePathAcceptsHardlinkedToolOutsideRepository(t *testing.T) {
	repository := t.TempDir()
	tools := t.TempDir()
	original := writeTrustedRuntimeTestTool(t, tools, trustedRuntimeTestToolName())
	alias := filepath.Join(tools, "hardlinked-"+filepath.Base(original))
	if err := os.Link(original, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	resolved, err := trustedControllerRuntimePath(repository, alias)
	if err != nil {
		t.Fatalf("hardlinked tool outside the repository was rejected: %v", err)
	}
	if !sameCanonicalPath(resolved, alias) && !sameCanonicalPath(resolved, original) {
		t.Fatalf("trusted path = %q, want the hardlinked tool or its original inode path", resolved)
	}
	if pathWithinRepository(repository, resolved) {
		t.Fatal("hardlinked tool outside the repository was classified as inside the repository")
	}
	if !validGateApplication(repository, resolved, []string{filepath.Dir(resolved)}) {
		t.Fatal("hardlinked tool failed gate application binding after trusted resolution")
	}
}

func TestPackageSnapshotStillRejectsHardlinkedRegularFile(t *testing.T) {
	directory := t.TempDir()
	original := filepath.Join(directory, "package-file")
	if err := os.WriteFile(original, []byte("package-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "package-file-alias")
	if err := os.Link(original, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	identity, isDir, err := openPackagePathIdentity(alias)
	if err != nil || isDir || identity == (packageFileIdentity{}) {
		t.Fatalf("containment identity for hardlinked file = (dir=%v err=%v id=%+v), want a file identity",
			isDir, err, identity)
	}

	file, err := openPackageRegularFile(alias)
	if err != nil {
		t.Fatalf("open hardlinked package file: %v", err)
	}
	defer file.Close()
	if _, err := snapshotPackageHandle(file, false); err == nil {
		t.Fatal("package snapshot accepted a hard-linked regular file")
	}
}

func writeTrustedRuntimeTestTool(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("trusted-runtime-tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func trustedRuntimeTestToolName() string {
	if runtime.GOOS == "windows" {
		return "tool.exe"
	}
	return "tool"
}

func requireTrustedRuntimePathError(t *testing.T, repository, path string) {
	t.Helper()
	resolved, err := trustedControllerRuntimePath(repository, path)
	if !errors.Is(err, errGateInvalidInput) || resolved != "" {
		t.Fatalf("trusted path = (%q, %v), want SOURCE_QUAL_INVALID_INPUT", resolved, err)
	}
}
