package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNewFileAtomicallyPublishesCompleteBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kit.tar")
	want := []byte("complete kit bytes")
	if err := writeNewFileAtomically(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("published content = %q, %v", got, err)
	}
}

func TestWriteNewFileAtomicallyNeverReplacesExistingOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kit.tar")
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFileAtomically(path, []byte("replacement")); err == nil {
		t.Fatal("existing output was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "existing" {
		t.Fatalf("existing output changed to %q, %v", got, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".kit.tar.tmp-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary output remains: %v, %v", leftovers, err)
	}
}

func TestWriteNewFileAtomicallyErrorsWithoutOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "kit.tar")
	err := writeNewFileAtomically(path, []byte("kit"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent error = %v", err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial final output exists: %v", statErr)
	}
}
