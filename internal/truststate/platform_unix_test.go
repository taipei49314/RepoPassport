//go:build unix

package truststate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObserveRejectsWorldWritableDataRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 1, testDigestA); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Skipf("cannot make data root writable: %v", err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 2, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
		t.Fatalf("world-writable data root = %#v, %v", result, err)
	}
}

func TestObserveRejectsWrongOwnerDataRootWhenPermitted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 1, testDigestA); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 1, -1); err != nil {
		t.Skipf("cannot assign a non-current owner: %v", err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 2, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
		t.Fatalf("wrong-owner data root = %#v, %v", result, err)
	}
}
