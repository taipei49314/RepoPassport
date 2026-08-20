package sourcequalification

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceQualificationPublishersUseIdentityBoundCleanup(t *testing.T) {
	tests := []struct {
		file     string
		required []string
	}{
		{
			file: "package_files.go",
			required: []string{
				"createPrivateQualificationStaging(",
				"bindPrivateQualificationCleanup(",
			},
		},
		{file: "tool_assembly.go", required: []string{"createPrivateQualificationStaging("}},
		{file: "lane_producer.go", required: []string{"createPrivateQualificationStaging("}},
		{file: "attempt_tombstone.go", required: []string{"createPrivateQualificationStaging("}},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			raw, err := os.ReadFile(test.file)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("os.RemoveAll(")) {
				t.Fatalf("%s retains pathname-only recursive cleanup", test.file)
			}
			for _, fragment := range test.required {
				if !bytes.Contains(raw, []byte(fragment)) {
					t.Errorf("%s does not use identity-bound cleanup primitive %q", test.file, fragment)
				}
			}
		})
	}
}

func TestPrivateQualificationCleanupRejectsReplacementPath(t *testing.T) {
	requireHostFilesystem(t)
	parent := t.TempDir()
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "private-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(parent, "relocated-original")
	if err := os.WriteFile(filepath.Join(path, "original.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	const replacement = "replacement-must-survive"
	replacementPath := filepath.Join(path, "replacement.txt")
	if err := os.WriteFile(replacementPath, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cleanup(); !errors.Is(err, errQualificationWorkspaceCleanup) {
		t.Fatalf("replacement cleanup error = %v, want identity failure", err)
	}
	if raw, err := os.ReadFile(replacementPath); err != nil || string(raw) != replacement {
		t.Fatalf("replacement was altered: bytes=%q err=%v", raw, err)
	}
	if raw, err := os.ReadFile(filepath.Join(original, "original.txt")); err != nil || string(raw) != "original" {
		t.Fatalf("relocated original was altered: bytes=%q err=%v", raw, err)
	}
}

func TestPrivateQualificationCleanupBudgetRejectsEntryAndDepthOverflow(t *testing.T) {
	t.Run("entry cap", func(t *testing.T) {
		budget := qualificationWorkspaceCleanupBudget{
			entries: maximumQualificationWorkspaceCleanupEntries - 1,
		}
		if err := budget.consume(0); err != nil {
			t.Fatalf("last allowed entry: %v", err)
		}
		if err := budget.consume(0); !errors.Is(err, errQualificationWorkspaceCleanup) {
			t.Fatalf("entry cap error = %v, want cleanup failure", err)
		}
	})

	t.Run("depth cap", func(t *testing.T) {
		budget := qualificationWorkspaceCleanupBudget{}
		if err := budget.consume(maximumQualificationWorkspaceCleanupDepth); err != nil {
			t.Fatalf("maximum allowed depth: %v", err)
		}
		if err := budget.consume(maximumQualificationWorkspaceCleanupDepth + 1); !errors.Is(err, errQualificationWorkspaceCleanup) {
			t.Fatalf("depth cap error = %v, want cleanup failure", err)
		}
	})

	t.Run("cache-sized entry cap", func(t *testing.T) {
		if maximumQualificationWorkspaceCleanupEntries < 1_000_000 {
			t.Fatalf("cleanup entry cap = %d, want at least 1_000_000 for GOCACHE and GOMODCACHE",
				maximumQualificationWorkspaceCleanupEntries)
		}
	})
}

func TestPrivateQualificationCleanupTraversalStopsAtDepthCap(t *testing.T) {
	requireHostFilesystem(t)
	parent := t.TempDir()
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "deep-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	current := path
	for depth := 0; depth <= maximumQualificationWorkspaceCleanupDepth+1; depth++ {
		current = filepath.Join(current, "d")
		if err := os.Mkdir(current, 0o700); err != nil {
			t.Fatalf("create depth %d: %v", depth, err)
		}
	}

	if err := cleanup(); !errors.Is(err, errQualificationWorkspaceCleanup) {
		t.Fatalf("deep cleanup error = %v, want bounded cleanup failure", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("bounded cleanup removed root despite incomplete traversal: %v", err)
	}
}
