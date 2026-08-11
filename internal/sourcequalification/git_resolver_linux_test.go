//go:build linux

package sourcequalification

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLinuxTrustedGitCandidatesAreExactMachinePaths(t *testing.T) {
	want := []string{"/usr/bin/git"}
	if got := linuxTrustedGitCandidatePaths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Linux trusted Git candidates = %q, want exact fixed candidates %q", got, want)
	}
}

func TestLinuxTrustedGitResolverRejectsNonRootOwnedTemporaryCandidate(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(path, []byte("temporary fake Git\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if resolved, err := validateLinuxTrustedGitCandidate(repositoryRoot, path); err == nil {
		t.Fatalf("temporary candidate accepted as %q", resolved)
	}
}
