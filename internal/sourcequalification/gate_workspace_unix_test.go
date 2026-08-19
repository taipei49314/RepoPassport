//go:build !windows

package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCreatePrivateQualificationWorkspaceAppliesExactUnixMetadata(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "private-run")
	if err != nil {
		t.Fatalf("create private qualification workspace: %v", err)
	}
	defer func() { _ = cleanup() }()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("workspace mode = %v, want real 0700 directory", info.Mode())
	}
	var metadata unix.Stat_t
	if err := unix.Lstat(path, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Uid != uint32(unix.Geteuid()) || metadata.Nlink != 2 || metadata.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatalf("workspace metadata = uid:%d nlink:%d mode:%#o", metadata.Uid, metadata.Nlink, metadata.Mode)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		t.Fatalf("workspace resolves to %q, want exact real path %q: %v", resolved, path, err)
	}
}

func TestCreatePrivateQualificationWorkspaceUnixCollisionDoesNotRepairPermissions(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "collision")
	if err := os.Mkdir(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if created, cleanup, err := createPrivateQualificationWorkspace(parent, "collision"); err == nil || created != "" || cleanup != nil {
		t.Fatalf("permissive collision accepted: %q/%v/%v", created, cleanup != nil, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o777 {
		t.Fatalf("collision was repaired or replaced: mode=%v err=%v", info.Mode(), err)
	}
}

func TestCreatePrivateQualificationWorkspaceRejectsSymlinkParent(t *testing.T) {
	realParent := t.TempDir()
	linkRoot := t.TempDir()
	linkParent := filepath.Join(linkRoot, "redirected-parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := createPrivateQualificationWorkspace(linkParent, "private-run")
	if err == nil || path != "" || cleanup != nil {
		t.Fatalf("symlink parent accepted: %q/%v/%v", path, cleanup != nil, err)
	}
	if _, err := os.Lstat(filepath.Join(realParent, "private-run")); !os.IsNotExist(err) {
		t.Fatalf("symlink parent created redirected workspace: %v", err)
	}
}

func TestPrivateQualificationWorkspaceCleanupDoesNotFollowUnixSymlink(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(outsideFile, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "private-run")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup with internal symlink: %v", err)
	}
	if got, err := os.ReadFile(outsideFile); err != nil || string(got) != "keep\n" {
		t.Fatalf("cleanup followed symlink outside workspace: %q, %v", got, err)
	}
}

func TestPrivateQualificationWorkspaceCleanupRemovesReadOnlyUnixTree(t *testing.T) {
	parent := t.TempDir()
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "private-run")
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(path, "module-cache")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	moduleFile := filepath.Join(nested, "module.go")
	if err := os.WriteFile(moduleFile, []byte("package module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(moduleFile, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0o500); err != nil {
		t.Fatal(err)
	}

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup read-only module cache tree: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only workspace remains after cleanup: %v", err)
	}
}
