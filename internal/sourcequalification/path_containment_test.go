package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackagePathsOverlapAcceptsDistinctSiblings(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "left")
	right := filepath.Join(root, "right")
	for _, directory := range []string{left, right} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for name, paths := range map[string][2]string{
		"existing directories": {left, right},
		"absent children": {
			filepath.Join(left, "future"),
			filepath.Join(right, "future"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if packagePathsOverlapOrUnsafe(paths[0], paths[1]) {
				t.Fatalf("distinct sibling paths were rejected as overlapping: %q and %q",
					paths[0], paths[1])
			}
		})
	}
}

func TestSecurePackagePathContainmentRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(outside, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	candidate := filepath.Join(link, "child")

	if contains, err := securePackagePathContains(root, candidate); err == nil || contains {
		t.Fatalf("containment through symlink = (%t, %v), want fail-closed error", contains, err)
	}
	if packagePathContains(root, candidate) {
		t.Fatal("boolean containment accepted a symlink ancestor")
	}
	if !pathWithinRepository(root, candidate) {
		t.Fatal("repository rejection boundary did not fail closed for a symlink ancestor")
	}
}
