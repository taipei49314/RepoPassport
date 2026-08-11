package sourcequalification

// Production contract under test:
//
//	func createPrivateQualificationWorkspace(parent, name string) (
//		path string,
//		cleanup func() error,
//		err error,
//	)
//
// The creator owns one exact, absent child of a caller-validated parent. It
// never reuses or repairs a preexisting path, and its cleanup never traverses
// outside that child.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreatePrivateQualificationWorkspaceCreatesAndCleansExactChild(t *testing.T) {
	parent := t.TempDir()
	sibling := filepath.Join(parent, "keep.txt")
	if err := os.WriteFile(sibling, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	path, cleanup, err := createPrivateQualificationWorkspace(parent, "qualification-run")
	if err != nil {
		t.Fatalf("create private qualification workspace: %v", err)
	}
	if want := filepath.Join(parent, "qualification-run"); path != want || cleanup == nil {
		t.Fatalf("workspace = %q/%v, want exact child %q and cleanup", path, cleanup != nil, want)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("new workspace is not an empty directory: entries=%d err=%v", len(entries), err)
	}
	if err := os.Mkdir(filepath.Join(path, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "nested", "private.log"), []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("clean private qualification workspace: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("workspace remains after cleanup: %v", err)
	}
	if got, err := os.ReadFile(sibling); err != nil || !bytes.Equal(got, []byte("keep\n")) {
		t.Fatalf("cleanup changed the parent sibling: %q, %v", got, err)
	}
}

func TestCreatePrivateQualificationWorkspaceRejectsPreexistingPathsWithoutMutation(t *testing.T) {
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "collision")
			var sentinel string
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(path, "sentinel.txt")
			case "file":
				sentinel = path
			}
			if err := os.WriteFile(sentinel, []byte("preexisting\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			created, cleanup, err := createPrivateQualificationWorkspace(parent, "collision")
			if err == nil || created != "" || cleanup != nil {
				t.Fatalf("preexisting %s accepted: path=%q cleanup=%v err=%v", kind, created, cleanup != nil, err)
			}
			if got, readErr := os.ReadFile(sentinel); readErr != nil || !bytes.Equal(got, []byte("preexisting\n")) {
				t.Fatalf("collision handling changed preexisting bytes: %q, %v", got, readErr)
			}
		})
	}
}

func TestCreatePrivateQualificationWorkspaceRejectsNonPortableNames(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{
		"",
		".",
		"..",
		"nested/child",
		`nested\child`,
		"workspace:stream",
		"workspace.",
		"workspace ",
		"CON",
		"nul\x00name",
		strings.Repeat("a", 256),
		parent,
	} {
		t.Run(strings.ReplaceAll(name, "\x00", "NUL"), func(t *testing.T) {
			path, cleanup, err := createPrivateQualificationWorkspace(parent, name)
			if err == nil || path != "" || cleanup != nil {
				t.Fatalf("unsafe workspace name accepted: %q => %q/%v/%v", name, path, cleanup != nil, err)
			}
		})
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid names left parent entries: %d, %v", len(entries), err)
	}
}
