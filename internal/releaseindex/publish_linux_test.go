//go:build linux

package releaseindex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixPublicationValidationRejectsOwnerLinkAndIdentitySubstitution(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "staging")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationDirectory(directory); err != nil {
		t.Fatalf("private directory rejected: %v", err)
	}
	identity, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "sidecar")
	if err := os.WriteFile(file, []byte("sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationFile(file); err != nil {
		t.Fatalf("private file rejected: %v", err)
	}
	if err := os.Link(file, filepath.Join(directory, "sidecar-link")); err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationFile(file); err == nil {
		t.Fatal("hardlinked publication file accepted")
	}
	if err := os.Remove(filepath.Join(directory, "sidecar-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, filepath.Join(parent, "original-staging")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateSamePublicationDirectory(directory, identity); err == nil {
		t.Fatal("same-name directory identity substitution accepted")
	}

	if os.Geteuid() == 0 {
		foreign := filepath.Join(parent, "foreign-owner")
		if err := os.Mkdir(foreign, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(foreign, 1, 1); err != nil {
			t.Fatal(err)
		}
		if err := validatePublicationDirectory(foreign); err == nil {
			t.Fatal("foreign-owned private-mode directory accepted")
		}
	}
}
