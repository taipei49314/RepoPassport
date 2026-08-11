//go:build windows

package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsTrustedGitResolverAcceptsOnlyMachineProtectedInstall(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	candidates := windowsTrustedGitCandidates()
	if len(candidates) == 0 {
		t.Fatal("machine has no HKLM or fixed Program Files Git candidates")
	}
	resolved, err := resolveTrustedGitExecutable(repositoryRoot)
	if err != nil {
		for index, candidate := range candidates {
			_, candidateErr := validateWindowsTrustedGitCandidate(repositoryRoot, candidate)
			t.Logf("machine Git candidate %d: %v", index, candidateErr)
		}
		t.Fatalf("resolve machine-protected Git: %v", err)
	}
	matched := false
	for _, candidate := range candidates {
		if sameCanonicalPath(candidate.path, resolved) {
			matched = true
			if _, err := validateWindowsTrustedGitCandidate(repositoryRoot, candidate); err != nil {
				t.Fatalf("selected candidate failed fixed-handle machine validation: %v", err)
			}
		}
	}
	if !matched {
		t.Fatalf("resolved Git %q is not one of the fixed HKLM/Program Files candidates", resolved)
	}
}

func TestWindowsTrustedGitResolverRejectsUserControlledCandidate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Git", "cmd", "git.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := windowsTrustedGitCandidate{root: filepath.Join(root, "Git"), path: path}
	if resolved, err := validateWindowsTrustedGitCandidate(t.TempDir(), candidate); err == nil {
		t.Fatalf("user-controlled candidate accepted as %q", resolved)
	}
}
