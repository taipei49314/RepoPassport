//go:build unix

package trustchainstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testPlatformSecurityAndAtomicity(t *testing.T) {
	t.Run("unsafe directories", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o770, 0o707} {
			root := filepath.Join(t.TempDir(), "controller-data")
			if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, mode); err != nil {
				t.Skipf("cannot change directory mode: %v", err)
			}
			if result, err := Observe(context.Background(), root, testObservation(2, 2)); !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
				t.Fatalf("unsafe directory = %#v, %v", result, err)
			}
		}
	})
	t.Run("linked state", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-data")
		if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
			t.Fatal(err)
		}
		path := stateFileForTest(t, root)
		if err := os.Link(path, filepath.Join(filepath.Dir(path), "linked-state.json")); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if result, err := Observe(context.Background(), root, testObservation(2, 2)); !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
			t.Fatalf("hard linked state = %#v, %v", result, err)
		}
	})
	t.Run("symlinked state and root", func(t *testing.T) {
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
		if result, err := Observe(context.Background(), root, testObservation(2, 2)); !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
			t.Fatalf("symlinked state = %#v, %v", result, err)
		}
		base := t.TempDir()
		rootTarget := filepath.Join(base, "target")
		if err := os.Mkdir(rootTarget, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(rootTarget, filepath.Join(base, "controller-data")); err != nil {
			t.Skipf("root symlinks unavailable: %v", err)
		}
		if result, err := Observe(context.Background(), filepath.Join(base, "controller-data"), testObservation(1, 1)); !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
			t.Fatalf("symlinked data root = %#v, %v", result, err)
		}
	})
}
