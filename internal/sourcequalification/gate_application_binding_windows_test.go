//go:build windows

package sourcequalification

import (
	"context"
	"os"
	"testing"
)

func TestHeldApplicationDeniesWritersWhileHeld(t *testing.T) {
	directory := t.TempDir()
	path := writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes"))
	binding := bindTestApplications(t, map[string]string{"alpha": path})
	defer func() { _ = binding.Release() }()

	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		file.Close()
		t.Fatal("expected write open on a held application to be denied")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("expected delete of a held application to be denied")
	}
	replacement := writeBindingTestApplication(t, directory, "replacement.exe", []byte("other-bytes"))
	if err := os.Rename(replacement, path); err == nil {
		t.Fatal("expected rename over a held application to be denied")
	}
	if err := binding.Verify(context.Background()); err != nil {
		t.Fatalf("Verify after denied mutations: %v", err)
	}
}

func TestReleasedApplicationAcceptsWriters(t *testing.T) {
	directory := t.TempDir()
	path := writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes"))
	binding := bindTestApplications(t, map[string]string{"alpha": path})
	if err := binding.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("expected write open after release, got %v", err)
	}
	file.Close()
}
