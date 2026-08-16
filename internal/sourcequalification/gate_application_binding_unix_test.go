//go:build !windows

package sourcequalification

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestBindingVerifyDetectsContentSubstitution(t *testing.T) {
	directory := t.TempDir()
	path := writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes"))
	binding := bindTestApplications(t, map[string]string{"alpha": path})
	defer func() { _ = binding.Release() }()

	if err := binding.Verify(context.Background()); err != nil {
		t.Fatalf("Verify before substitution: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered-bytes"), 0o755); err != nil {
		t.Fatalf("overwrite held application: %v", err)
	}
	if err := binding.Verify(context.Background()); !errors.Is(err, errGateApplicationBindingViolated) {
		t.Fatalf("expected violation after content substitution, got %v", err)
	}
}

func TestBindingVerifyDetectsPathRebinding(t *testing.T) {
	directory := t.TempDir()
	path := writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes"))
	replacement := writeBindingTestApplication(t, directory, "replacement.exe", []byte("alpha-bytes"))
	binding := bindTestApplications(t, map[string]string{"alpha": path})
	defer func() { _ = binding.Release() }()

	// Same bytes, different file: the name→file identity must be what fails.
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("rebind path: %v", err)
	}
	if err := binding.Verify(context.Background()); !errors.Is(err, errGateApplicationBindingViolated) {
		t.Fatalf("expected violation after path rebinding, got %v", err)
	}
}

func TestBindingVerifyDetectsRemovedApplication(t *testing.T) {
	directory := t.TempDir()
	path := writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes"))
	binding := bindTestApplications(t, map[string]string{"alpha": path})
	defer func() { _ = binding.Release() }()

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove held application: %v", err)
	}
	if err := binding.Verify(context.Background()); !errors.Is(err, errGateApplicationBindingViolated) {
		t.Fatalf("expected violation after removal, got %v", err)
	}
}
