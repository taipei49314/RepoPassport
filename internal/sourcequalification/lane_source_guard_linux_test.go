//go:build linux

package sourcequalification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQualificationLaneSourceGuardRestoresIsolatedModuleDownload(t *testing.T) {
	goPath, err := trustedControllerRuntimePath(t.TempDir(), requirePATHRuntimeTool(t, "go"))
	if err != nil {
		t.Fatalf("trusted go path: %v", err)
	}
	fixture := newGitRepositoryFixture(t)
	mod := []byte("module " + testCanonicalModule + "\n\ngo 1.26\n\nrequire golang.org/x/sys v0.47.0\n")
	src := []byte("package downloadrestore\n\nimport _ \"golang.org/x/sys/cpu\"\n")
	writeGitFixtureFile(t, filepath.Join(fixture.root, "go.mod"), mod)
	writeGitFixtureFile(t, filepath.Join(fixture.root, "restore.go"), src)

	home, err := os.MkdirTemp("", "repopass-isolated-download-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("sudo", "-n", "chmod", "-R", "u+w", home).Run()
		_ = os.RemoveAll(home)
	})
	modcache := filepath.Join(home, "modcache")
	gocache := filepath.Join(home, "gocache")
	tmpdir := filepath.Join(home, "tmp")
	for _, path := range []string{modcache, gocache, tmpdir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	hostEnv := isolatedGoModuleEnvironment(goPath, home, modcache, gocache, tmpdir, true)
	tidy := exec.Command(goPath, "mod", "tidy")
	tidy.Dir = fixture.root
	tidy.Env = hostEnv
	if output, err := tidy.CombinedOutput(); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("host go mod tidy unavailable: %v\n%s", err, output)
		}
		t.Skipf("host go mod tidy unavailable: %v\n%s", err, output)
	}
	fixture.git(t, "add", "go.mod", "go.sum", "restore.go")
	parent := fixture.tested
	fixture.commit(t, "download restore fixture", "2000-01-04T00:00:00Z")
	fixture.base = parent
	fixture.tested = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))
	fixture.tree = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD^{tree}"))

	sumPath := filepath.Join(fixture.root, "go.sum")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read fixture go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, newOSGateExecutor())
	result, execErr := guard.Execute(context.Background(), gateProcessRequest{
		Application: goPath,
		Args:        []string{"mod", "download", "-modcacherw", "all"},
		Dir:         fixture.root,
		Env:         isolatedGoModuleEnvironment(goPath, home, modcache, gocache, tmpdir, true),
		Network:     NetworkGoModules,
		Timeout:     2 * time.Minute,
		StdoutLimit: 1 << 16,
		StderrLimit: 1 << 16,
	})
	if result.Blocked {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("gate isolation is unavailable")
		}
		t.Skip("gate isolation is unavailable")
	}
	if execErr != nil {
		t.Fatalf("isolated MODULE-DOWNLOAD execution error: %v stderr=%q", execErr, result.Stderr)
	}
	if result.SourceChanged {
		_, inspectErr := InspectRepository(fixture.request())
		t.Fatalf("isolated MODULE-DOWNLOAD was treated as SOURCE_DIRTY; exit=%v stderr=%q inspect=%v", result.ExitCode, result.Stderr, inspectErr)
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || string(restored) != string(original) {
		t.Fatalf("go.sum after isolated MODULE-DOWNLOAD = %q, want %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardRestoresIsolatedCanonicalModuleDownload(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path is unavailable")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	mod, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(moduleRoot, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	goPath, err := trustedControllerRuntimePath(t.TempDir(), requirePATHRuntimeTool(t, "go"))
	if err != nil {
		t.Fatalf("trusted go path: %v", err)
	}
	fixture := newGitRepositoryFixture(t)
	writeGitFixtureFile(t, filepath.Join(fixture.root, "go.mod"), mod)
	writeGitFixtureFile(t, filepath.Join(fixture.root, "go.sum"), sum)
	writeGitFixtureFile(t, filepath.Join(fixture.root, "restore.go"), []byte("package downloadrestore\n"))

	home, err := os.MkdirTemp("", "repopass-isolated-canonical-download-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("sudo", "-n", "chmod", "-R", "u+w", home).Run()
		_ = os.RemoveAll(home)
	})
	modcache := filepath.Join(home, "modcache")
	gocache := filepath.Join(home, "gocache")
	tmpdir := filepath.Join(home, "tmp")
	for _, path := range []string{modcache, gocache, tmpdir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture.git(t, "add", "go.mod", "go.sum", "restore.go")
	parent := fixture.tested
	fixture.commit(t, "canonical download restore fixture", "2000-01-05T00:00:00Z")
	fixture.base = parent
	fixture.tested = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))
	fixture.tree = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD^{tree}"))

	sumPath := filepath.Join(fixture.root, "go.sum")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read fixture go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, newOSGateExecutor())
	result, execErr := guard.Execute(context.Background(), gateProcessRequest{
		Application: goPath,
		Args:        []string{"mod", "download", "-modcacherw", "all"},
		Dir:         fixture.root,
		Env:         isolatedGoModuleEnvironment(goPath, home, modcache, gocache, tmpdir, true),
		Network:     NetworkGoModules,
		Timeout:     2 * time.Minute,
		StdoutLimit: 1 << 16,
		StderrLimit: 1 << 16,
	})
	if result.Blocked {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("gate isolation is unavailable")
		}
		t.Skip("gate isolation is unavailable")
	}
	if execErr != nil {
		t.Fatalf("isolated canonical MODULE-DOWNLOAD execution error: %v stderr=%q", execErr, result.Stderr)
	}
	if result.SourceChanged {
		_, inspectErr := InspectRepository(fixture.request())
		t.Fatalf("isolated canonical MODULE-DOWNLOAD was treated as SOURCE_DIRTY; exit=%v stderr=%q inspect=%v", result.ExitCode, result.Stderr, inspectErr)
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || string(restored) != string(original) {
		t.Fatalf("canonical go.sum after isolated MODULE-DOWNLOAD = %q, want %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardRestoresIsolatedFullModuleDownload(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path is unavailable")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(moduleRoot, "go.mod")); err != nil {
		t.Fatal(err)
	}
	goPath, err := trustedControllerRuntimePath(t.TempDir(), requirePATHRuntimeTool(t, "go"))
	if err != nil {
		t.Fatalf("trusted go path: %v", err)
	}
	fixture := newGitRepositoryFixture(t)
	replaceFixtureWithTrackedModuleTree(t, fixture, moduleRoot)

	home, err := os.MkdirTemp("", "repopass-isolated-full-download-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("sudo", "-n", "chmod", "-R", "u+w", home).Run()
		_ = os.RemoveAll(home)
	})
	modcache := filepath.Join(home, "modcache")
	gocache := filepath.Join(home, "gocache")
	tmpdir := filepath.Join(home, "tmp")
	for _, path := range []string{modcache, gocache, tmpdir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	sumPath := filepath.Join(fixture.root, "go.sum")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read fixture go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, newOSGateExecutor())
	result, execErr := guard.Execute(context.Background(), gateProcessRequest{
		Application: goPath,
		Args:        []string{"mod", "download", "-modcacherw", "all"},
		Dir:         fixture.root,
		Env:         isolatedGoModuleEnvironment(goPath, home, modcache, gocache, tmpdir, true),
		Network:     NetworkGoModules,
		Timeout:     4 * time.Minute,
		StdoutLimit: 1 << 16,
		StderrLimit: 1 << 16,
	})
	if result.Blocked {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("gate isolation is unavailable")
		}
		t.Skip("gate isolation is unavailable")
	}
	if execErr != nil {
		t.Fatalf("isolated full MODULE-DOWNLOAD execution error: %v stderr=%q", execErr, result.Stderr)
	}
	if result.SourceChanged {
		_, inspectErr := InspectRepository(fixture.request())
		status := fixture.git(t, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none")
		t.Fatalf("isolated full MODULE-DOWNLOAD was treated as SOURCE_DIRTY; exit=%v stderr=%q inspect=%v porcelain=%q extras=%q",
			result.ExitCode, result.Stderr, inspectErr, status, unexpectedWorktreePaths(t, fixture.root, guard.expected))
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || string(restored) != string(original) {
		t.Fatalf("full-module go.sum after isolated MODULE-DOWNLOAD = %q, want %q (err=%v)", restored, original, err)
	}
}

func replaceFixtureWithTrackedModuleTree(t *testing.T, fixture *gitRepositoryFixture, moduleRoot string) {
	t.Helper()
	entries, err := os.ReadDir(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(fixture.root, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}

	listed, err := exec.Command("git", "-C", moduleRoot, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, rel := range strings.Split(string(listed), "\x00") {
		if rel == "" {
			continue
		}
		src := filepath.Join(moduleRoot, filepath.FromSlash(rel))
		info, err := os.Lstat(src)
		if err != nil {
			t.Fatalf("stat tracked %s: %v", rel, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read tracked %s: %v", rel, err)
		}
		dst := filepath.Join(fixture.root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		if err := os.WriteFile(dst, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dst, mode); err != nil {
			t.Fatal(err)
		}
	}
	fixture.git(t, "config", "core.filemode", "true")
	fixture.git(t, "add", "-f", "--all")
	parent := fixture.tested
	fixture.commit(t, "full module tree", "2000-01-06T00:00:00Z")
	fixture.base = parent
	fixture.tested = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))
	fixture.tree = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD^{tree}"))
}

func unexpectedWorktreePaths(t *testing.T, root string, snapshot RepositorySnapshot) []string {
	t.Helper()
	expected := make(map[string]struct{}, len(snapshot.Files))
	for _, file := range snapshot.Files {
		expected[file.Path] = struct{}{}
	}
	var extras []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		portable := filepath.ToSlash(relative)
		if portable == "." {
			return nil
		}
		if portable == ".git" || strings.HasPrefix(portable, ".git/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if _, ok := expected[portable]; ok {
			return nil
		}
		extras = append(extras, portable)
		return nil
	})
	if err != nil {
		t.Fatalf("worktree extras walk: %v", err)
	}
	return extras
}

func isolatedGoModuleEnvironment(goPath, home, modcache, gocache, tmpdir string, network bool) []string {
	env := []string{
		"PATH=" + filepath.Dir(goPath),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + home,
		"TMPDIR=" + tmpdir,
		"TMP=" + tmpdir,
		"TEMP=" + tmpdir,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"GOWORK=off",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOFLAGS=",
		"GOCACHEPROG=",
		"GOTELEMETRY=off",
		"CGO_ENABLED=0",
		"GOCACHE=" + gocache,
		"GOMODCACHE=" + modcache,
		"GOPATH=" + filepath.Join(home, "go"),
		"GOBIN=" + filepath.Join(home, "bin"),
		"GOTMPDIR=" + tmpdir,
		"GOAUTH=off",
		"GONOPROXY=none",
		"GOPRIVATE=",
		"GONOSUMDB=",
		"GOINSECURE=",
	}
	if network {
		env = append(env, "GOPROXY=https://proxy.golang.org,direct", "GOSUMDB=sum.golang.org", "GOVULNDB=off")
	} else {
		env = append(env, "GOPROXY=off", "GOSUMDB=off", "GOVULNDB=off")
	}
	return env
}
