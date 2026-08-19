package sourcequalification

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Git's isolated HOME/config/temp scratch is private controller state. It must
// use the same fixed-handle, identity-bound, bounded workspace implementation
// as gate scratch; a pathname-only recursive delete is not an acceptable
// cleanup boundary.
func TestGitInspectorScratchUsesPrivateWorkspaceAndBoundedCleanup(t *testing.T) {
	repositoryRoot := newGitScratchRepositoryFixture(t)
	entropy := bytes.NewReader(bytes.Repeat([]byte{0xa5}, repositoryScratchEntropyBytes))
	var scratchPath string
	createCalls := 0
	creator := func(parent, name string) (string, func() error, error) {
		createCalls++
		if got, want := parent, wantIsolatedGitScratchParent(t, repositoryRoot); got != want {
			t.Fatalf("scratch parent = %q, want canonical OS temporary directory %q", got, want)
		}
		wantName := repositoryScratchPrefix + strings.Repeat("a5", repositoryScratchEntropyBytes)
		if name != wantName {
			t.Fatalf("scratch name = %q, want deterministic portable name %q", name, wantName)
		}
		path, cleanup, err := createPrivateQualificationWorkspace(parent, name)
		scratchPath = path
		return path, cleanup, err
	}

	inspector, cleanup, err := newRepositoryInspectorWithScratch(repositoryRoot, creator, entropy)
	if err != nil {
		t.Fatalf("create repository inspector scratch: %v", err)
	}
	if inspector == nil || cleanup == nil || createCalls != 1 || scratchPath == "" {
		t.Fatalf("repository scratch creation = inspector:%v cleanup:%v calls:%d path:%q", inspector != nil, cleanup != nil, createCalls, scratchPath)
	}
	for _, name := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "TMPDIR", "TMP", "TEMP"} {
		if got := gitScratchEnvironmentValue(inspector.env, name); got != scratchPath {
			t.Errorf("isolated Git %s = %q, want private scratch %q", name, got, scratchPath)
		}
	}

	nested := filepath.Join(scratchPath, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "private.tmp"), []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("identity-bound repository scratch cleanup: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("idempotent repository scratch cleanup: %v", err)
	}
	if _, err := os.Lstat(scratchPath); !os.IsNotExist(err) {
		t.Fatalf("repository scratch remains after cleanup: %v", err)
	}
}

func TestCanonicalIsolatedGitScratchParentResolvesEvalSymlinksUnstableTemp(t *testing.T) {
	repositoryRoot := t.TempDir()
	raw := filepath.Clean(os.TempDir())
	parent, err := canonicalIsolatedGitScratchParent(repositoryRoot, os.TempDir())
	if err != nil {
		t.Fatalf("canonical isolated Git scratch parent: %v", err)
	}
	if !validGateExternalDirectory(repositoryRoot, parent) {
		t.Fatalf("canonical scratch parent %q is not a valid external directory", parent)
	}
	if pathWithinRepository(repositoryRoot, parent) {
		t.Fatal("canonical scratch parent is inside the repository")
	}

	rawValid := validGateDirectory(raw)
	if rawValid && parent != filepath.Clean(raw) && !sameCanonicalPath(parent, raw) {
		t.Fatalf("EvalSymlinks-stable temp dir %q canonicalized to a different path %q", raw, parent)
	}
	if !rawValid && (parent == raw || !validGateDirectory(parent)) {
		t.Fatalf("EvalSymlinks-unstable temp dir %q was not resolved to a valid parent (got %q)", raw, parent)
	}
}

func TestCanonicalIsolatedGitScratchParentRejectsRepositoryDirectory(t *testing.T) {
	repositoryRoot := t.TempDir()
	resolvedRepo, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		t.Fatalf("repository EvalSymlinks: %v", err)
	}
	resolvedRepo = filepath.Clean(resolvedRepo)
	if _, err := canonicalIsolatedGitScratchParent(resolvedRepo, resolvedRepo); err == nil {
		t.Fatal("repository directory was accepted as an isolated Git scratch parent")
	}
}

func wantIsolatedGitScratchParent(t *testing.T, repositoryRoot string) string {
	t.Helper()
	parent, err := canonicalIsolatedGitScratchParent(repositoryRoot, os.TempDir())
	if err != nil {
		t.Fatalf("canonical isolated Git scratch parent: %v", err)
	}
	return parent
}

func TestInspectRepositoryScratchCleanupFailureIsNeverMasked(t *testing.T) {
	tests := []struct {
		name       string
		inspectErr error
	}{
		{name: "after successful inspection"},
		{name: "after failed inspection", inspectErr: errors.New("synthetic repository inspection failure")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanupCalled := false
			parent := t.TempDir()
			scratchPath, cleanup, err := createPrivateQualificationWorkspace(parent, "git-scratch")
			if err != nil {
				t.Fatalf("create cleanup precedence fixture: %v", err)
			}
			accepted := RepositorySnapshot{Subject: RepositorySubject{TestedRevision: strings.Repeat("2", 40)}}
			snapshot, err := completeRepositoryInspection(
				accepted,
				test.inspectErr,
				func() error {
					cleanupCalled = true
					if err := cleanup(); err != nil {
						return err
					}
					return errors.New("synthetic repository scratch cleanup failure")
				},
			)
			if !cleanupCalled {
				t.Fatal("repository inspection did not invoke scratch cleanup")
			}
			if !errors.Is(err, errRepositoryScratchCleanup) {
				t.Fatalf("repository cleanup failure was masked: %v", err)
			}
			if !reflect.DeepEqual(snapshot, RepositorySnapshot{}) {
				t.Fatalf("cleanup failure returned partial snapshot: %#v", snapshot)
			}
			if _, statErr := os.Lstat(scratchPath); !os.IsNotExist(statErr) {
				t.Fatalf("test scratch remains after injected cleanup failure: %v", statErr)
			}
		})
	}
}

func newGitScratchRepositoryFixture(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	repositoryRoot := filepath.Join(parent, "repository")
	if err := os.MkdirAll(filepath.Join(repositoryRoot, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	toolDirectory := filepath.Join(parent, "tools")
	if err := os.Mkdir(toolDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "git"
	if runtime.GOOS == "windows" {
		name = "git.exe"
	}
	input, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	gitPath := filepath.Join(toolDirectory, name)
	output, err := os.OpenFile(gitPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gitPath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", toolDirectory)
	return repositoryRoot
}

func TestGitScratchProductionHasNoPathOnlyRecursiveCreationOrCleanup(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve git scratch contract test path")
	}
	path := filepath.Join(filepath.Dir(current), "git.go")
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse git.go: %v", err)
	}
	forbidden := map[string]bool{"MkdirTemp": true, "RemoveAll": true}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !forbidden[selector.Sel.Name] {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == "os" {
			t.Errorf("git.go calls forbidden path-only os.%s at %s", selector.Sel.Name, set.Position(call.Pos()))
		}
		return true
	})
}

func gitScratchEnvironmentValue(environment []string, name string) string {
	prefix := strings.ToUpper(name) + "="
	for _, item := range environment {
		if strings.HasPrefix(strings.ToUpper(item), prefix) {
			return item[len(prefix):]
		}
	}
	return ""
}
