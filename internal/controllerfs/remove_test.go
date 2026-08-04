package controllerfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveTreeRestoresOwnerAccessBeforeRemoval(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "readonly")
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "fixture.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(nested, "fixture.txt"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}

	if err := RemoveTree(root); err != nil {
		t.Fatalf("RemoveTree returned error: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only tree still exists after cleanup: %v", err)
	}
}

func TestRemoveTreeRejectsFilesystemRoot(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	if err := RemoveTree(root); err == nil {
		t.Fatal("filesystem root cleanup was accepted")
	}
}

func TestRemoveTreeDoesNotFollowNestedSymlink(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o400); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(outside)
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(parent, "readonly")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}

	if err := RemoveTree(root); err != nil {
		t.Fatalf("RemoveTree returned error: %v", err)
	}
	after, err := os.Lstat(outside)
	if err != nil {
		t.Fatalf("external symlink target was removed: %v", err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf(
			"external symlink target mode changed from %o to %o",
			before.Mode().Perm(),
			after.Mode().Perm(),
		)
	}
	contents, err := os.ReadFile(outside)
	if err != nil || string(contents) != "outside" {
		t.Fatalf("external symlink target changed: %q, %v", contents, err)
	}
}

func TestRemoveTreeRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "cleanup-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}

	if err := RemoveTree(link); err == nil {
		t.Fatal("symbolic-link cleanup root was accepted")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("rejected symbolic-link root was removed: %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("symbolic-link target changed: %#v, %v", info, err)
	}
}
