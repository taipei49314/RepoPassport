package sourcequalification

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveTrustedGitExecutableNeverUsesAmbientPath(t *testing.T) {
	repositoryRoot := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeDirectory := t.TempDir()
	fakeName := "git"
	if runtime.GOOS == "windows" {
		fakeName = "git.exe"
	}
	fakeGit := filepath.Join(fakeDirectory, fakeName)
	if err := os.WriteFile(fakeGit, []byte("ambient fake Git must never be selected\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fakeGit, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeDirectory)
	ambient, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("test fixture did not control ambient PATH: %v", err)
	}
	ambient, err = filepath.Abs(ambient)
	if err != nil || !sameCanonicalPath(ambient, fakeGit) {
		t.Fatalf("ambient PATH resolved %q, want fake %q: %v", ambient, fakeGit, err)
	}

	resolved, resolveErr := resolveTrustedGitExecutable(repositoryRoot)
	if resolveErr == nil && sameCanonicalPath(resolved, fakeGit) {
		t.Fatalf("trusted Git resolver accepted ambient fake executable %q", resolved)
	}
	if resolveErr == nil {
		if !filepath.IsAbs(resolved) || pathWithinRepository(repositoryRoot, resolved) {
			t.Fatalf("trusted Git resolver returned invalid machine candidate %q", resolved)
		}
	}
}

func TestTrustedGitResolverSourceDoesNotCallAmbientDiscovery(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve trusted Git resolver test path")
	}
	path := filepath.Join(filepath.Dir(current), "git.go")
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse git.go: %v", err)
	}
	foundPlatformResolver := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			if function.Name == "resolveTrustedGitExecutablePlatform" {
				foundPlatformResolver = true
			}
		case *ast.SelectorExpr:
			packageName, ok := function.X.(*ast.Ident)
			if ok && packageName.Name == "exec" && function.Sel.Name == "LookPath" {
				t.Errorf("git.go uses ambient exec.LookPath at %s", set.Position(call.Pos()))
			}
		}
		return true
	})
	if !foundPlatformResolver {
		t.Error("resolveTrustedGitExecutable must delegate only to an OS-specific fixed machine resolver")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `exec.LookPath("git")`) {
		t.Error("git.go retains literal ambient Git discovery")
	}
}
