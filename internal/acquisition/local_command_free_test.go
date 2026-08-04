package acquisition

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func TestMain(m *testing.M) {
	if marker := os.Getenv("REPOPASS_TEST_FAKE_GIT_MARKER"); marker != "" &&
		strings.EqualFold(strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe"), "git") {
		_ = os.WriteFile(marker, []byte("executed"), 0o600)
		fmt.Fprintln(os.Stdout, strings.Repeat("a", 40))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestResolveCommandFreeNeverExecutesGit(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(t.TempDir(), "git-executed")
	fakeName := "git"
	if runtime.GOOS == "windows" {
		fakeName += ".exe"
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fakeGit := filepath.Join(directory, fakeName)
	raw, err := os.ReadFile(testExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeGit, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("PATHEXT", ".EXE")
	t.Setenv("REPOPASS_TEST_FAKE_GIT_MARKER", marker)

	provider := NewLocalProvider()
	resolved, err := provider.ResolveCommandFree(context.Background(), domain.SourceRef{Kind: "local", Value: t.TempDir()})
	if err != nil {
		t.Fatalf("command-free resolve: %v", err)
	}
	if resolved.Commit != "" {
		t.Fatalf("command-free resolve returned commit %q", resolved.Commit)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("command-free resolver executed the fake git binary")
	}
}
