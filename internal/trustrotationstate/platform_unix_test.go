//go:build unix

package trustrotationstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObserveRejectsUnsafeUnixDirectoriesWithoutRepair(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707} {
		t.Run(mode.String(), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "controller-data")
			if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, mode); err != nil {
				t.Skipf("cannot change directory mode: %v", err)
			}
			result, err := Observe(context.Background(), root, testObservation(2, 2))
			if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
				t.Fatalf("unsafe directory = %#v, %v", result, err)
			}
		})
	}
}

func TestObserveRejectsLinkedUnixStateWithoutOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	t.Run("hard link", func(t *testing.T) {
		linked := filepath.Join(filepath.Dir(path), "linked-state.json")
		if err := os.Link(path, linked); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		result, err := Observe(context.Background(), root, testObservation(2, 2))
		if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
			t.Fatalf("hard linked state = %#v, %v", result, err)
		}
	})
}

func TestObserveRejectsSymlinkedUnixStateAndDirectory(t *testing.T) {
	t.Run("state", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-data")
		if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
			t.Fatal(err)
		}
		path := stateFileForTest(t, root)
		target := filepath.Join(filepath.Dir(path), "actual-state.json")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		result, err := Observe(context.Background(), root, testObservation(2, 2))
		if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
			t.Fatalf("symlinked state = %#v, %v", result, err)
		}
	})
	t.Run("data root", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(base, "controller-data")
		if err := os.Symlink(target, root); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		result, err := Observe(context.Background(), root, testObservation(1, 1))
		if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
			t.Fatalf("symlinked data root = %#v, %v", result, err)
		}
		if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
			t.Fatalf("symlink target changed: %#v, %v", entries, err)
		}
	})
}
