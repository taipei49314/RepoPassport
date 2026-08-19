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
