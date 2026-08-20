//go:build windows

package trustrotationstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsObserveRejectsReparseDataRootWithoutWritingTarget(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "controller-data")
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("creating a directory reparse point is unavailable: %v", err)
	}
	result, err := Observe(context.Background(), root, testObservation(1, 1))
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("reparse data root = %#v, %v", result, err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("reparse target changed: %#v, %v", entries, err)
	}
}

func TestWindowsCreatedStateObjectsArePrivateAndNotReparsePoints(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	stateDirectory, err := stateRoot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{root, filepath.Join(root, "trust-policy-state"), filepath.Join(root, "trust-policy-state", "v1"), stateDirectory} {
		if err := validatePrivateStateDirectory(directory); err != nil {
			t.Fatalf("private state directory %q: %v", directory, err)
		}
	}
	for _, path := range []string{
		filepath.Join(stateDirectory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lock"),
		stateFileForTest(t, root),
	} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateOpenedRegularFile(file, path, true); err != nil {
			_ = file.Close()
			t.Fatalf("private regular file %q: %v", path, err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
