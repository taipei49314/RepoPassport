package sourcequalification

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DebugNetworkNoneGoTest runs `go test` through the production OS gate
// executor. It is a diagnostic helper for source-qualification TEST FAIL
// receipts that omit private logs. Do not merge this file onto main.
func DebugNetworkNoneGoTest(
	ctx context.Context,
	repositoryRoot string,
	testArgs []string,
	timeout time.Duration,
) (string, error) {
	goPath, err := resolveControllerRuntimeApplication(repositoryRoot, "go")
	if err != nil {
		return "", fmt.Errorf("trusted go: %w", err)
	}
	home, err := os.MkdirTemp("", "zz-debug-gotest-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(home)
	for _, name := range []string{"gocache", "modcache", "tmp", "gopath"} {
		if err := os.MkdirAll(filepath.Join(home, name), 0o700); err != nil {
			return "", err
		}
	}
	download := exec.Command(goPath, "mod", "download", "-modcacherw", "all")
	download.Dir = repositoryRoot
	download.Env = debugGateEnvironment(goPath, home, true)
	if output, err := download.CombinedOutput(); err != nil {
		return "", fmt.Errorf("host module download: %w\n%s", err, output)
	}
	_ = exec.Command("git", "-C", repositoryRoot, "checkout", "--", "go.sum", "go.mod").Run()
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	if len(testArgs) == 0 {
		testArgs = []string{"test", "-count=1", "-timeout=8m", "-failfast", "./..."}
	}
	result, execErr := newOSGateExecutor().Execute(ctx, gateProcessRequest{
		Application: goPath,
		Args:        testArgs,
		Dir:         repositoryRoot,
		Env:         debugGateEnvironment(goPath, home, false),
		Network:     NetworkNone,
		Timeout:     timeout,
		StdoutLimit: 1 << 20,
		StderrLimit: 1 << 20,
	})
	return fmt.Sprintf(
		"blocked=%v exit=%v timedOut=%v cancelled=%v cleanupFailed=%v execErr=%v\nstdout:\n%s\nstderr:\n%s\n",
		result.Blocked,
		formatDebugExit(result.ExitCode),
		result.TimedOut,
		result.Cancelled,
		result.CleanupFailed,
		execErr,
		result.Stdout,
		result.Stderr,
	), nil
}

// DebugIsolatedModuleDownload runs production MODULE-DOWNLOAD isolation plus
// tracked restore against a live checkout. Do not merge this file onto main.
func DebugIsolatedModuleDownload(
	ctx context.Context,
	repositoryRoot, baseRevision, testedRevision string,
) (string, error) {
	request := RepositoryRequest{
		Root:                   repositoryRoot,
		ExpectedBaseRevision:   baseRevision,
		ExpectedTestedRevision: testedRevision,
	}
	before, err := InspectRepository(request)
	if err != nil {
		return "", fmt.Errorf("inspect before download: %w extras=%q porcelain=%q",
			err, debugUnexpectedPaths(repositoryRoot, RepositorySnapshot{}), debugPorcelain(repositoryRoot))
	}
	goPath, err := resolveControllerRuntimeApplication(repositoryRoot, "go")
	if err != nil {
		return "", fmt.Errorf("trusted go: %w", err)
	}
	home, err := os.MkdirTemp("", "zz-debug-download-")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = exec.Command("sudo", "-n", "chmod", "-R", "u+w", home).Run()
		_ = os.RemoveAll(home)
	}()
	for _, name := range []string{"gocache", "modcache", "tmp", "gopath"} {
		if err := os.MkdirAll(filepath.Join(home, name), 0o700); err != nil {
			return "", err
		}
	}
	guard := &qualificationLaneSourceGuard{
		inner:     newOSGateExecutor(),
		inspector: productionLaneRepositoryInspector{},
		request:   request,
		expected:  cloneQualificationLaneSnapshot(before),
	}
	result, execErr := guard.Execute(ctx, gateProcessRequest{
		Application: goPath,
		Args:        []string{"mod", "download", "-modcacherw", "all"},
		Dir:         repositoryRoot,
		Env:         debugGateEnvironment(goPath, home, true),
		Network:     NetworkGoModules,
		Timeout:     4 * time.Minute,
		StdoutLimit: 1 << 16,
		StderrLimit: 1 << 16,
	})
	_, afterErr := InspectRepository(request)
	return fmt.Sprintf(
		"blocked=%v exit=%v sourceChanged=%v execErr=%v\ninspectAfter=%v\nporcelain=%q\nextras=%q\nstdout=%q\nstderr=%q\n",
		result.Blocked,
		formatDebugExit(result.ExitCode),
		result.SourceChanged,
		execErr,
		afterErr,
		debugPorcelain(repositoryRoot),
		debugUnexpectedPaths(repositoryRoot, before),
		result.Stdout,
		result.Stderr,
	), nil
}

func debugGateEnvironment(goPath, home string, network bool) []string {
	env := []string{
		"PATH=" + filepath.Dir(goPath),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + home,
		"TMPDIR=" + filepath.Join(home, "tmp"),
		"TMP=" + filepath.Join(home, "tmp"),
		"TEMP=" + filepath.Join(home, "tmp"),
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
		"GOCACHE=" + filepath.Join(home, "gocache"),
		"GOMODCACHE=" + filepath.Join(home, "modcache"),
		"GOPATH=" + filepath.Join(home, "gopath"),
		"GOBIN=" + filepath.Join(home, "bin"),
		"GOTMPDIR=" + filepath.Join(home, "tmp"),
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
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SYSTEMROOT")
		env = append(env, "SYSTEMROOT="+systemRoot, "WINDIR="+systemRoot)
	}
	return env
}

func formatDebugExit(code *int64) string {
	if code == nil {
		return "null"
	}
	return fmt.Sprintf("%d", *code)
}

func debugPorcelain(root string) string {
	git, err := exec.LookPath("git")
	if err != nil {
		return "git-missing"
	}
	command := exec.Command(git, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("status-err:%v:%s", err, output)
	}
	return string(output)
}

func debugUnexpectedPaths(root string, snapshot RepositorySnapshot) string {
	expected := make(map[string]struct{}, len(snapshot.Files))
	for _, file := range snapshot.Files {
		expected[file.Path] = struct{}{}
	}
	var extras []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		portable := filepath.ToSlash(relative)
		if portable == ".git" || strings.HasPrefix(portable, ".git/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if _, ok := expected[portable]; !ok {
			extras = append(extras, portable)
		}
		if len(extras) >= 32 {
			return filepath.SkipAll
		}
		return nil
	})
	return strings.Join(extras, ",")
}
