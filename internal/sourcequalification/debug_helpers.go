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
	home, err := debugPrivateHome(repositoryRoot, "zz-debug-gotest-")
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
	download.Env = debugGateEnvironment(repositoryRoot, goPath, home, true)
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
		Env:         debugGateEnvironment(repositoryRoot, goPath, home, false),
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
	home, err := debugPrivateHome(repositoryRoot, "zz-debug-download-")
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
		Env:         debugGateEnvironment(repositoryRoot, goPath, home, true),
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

// DebugIsolatedRemainingGates runs MODULE-DOWNLOAD then NetworkNone
// verify/tidy/format/vet through the production source guard. Stop at the
// first SourceChanged inspect. Do not merge this file onto main.
func DebugIsolatedRemainingGates(
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
		return "", fmt.Errorf("inspect before remaining gates: %w extras=%q porcelain=%q",
			err, debugUnexpectedPaths(repositoryRoot, RepositorySnapshot{}), debugPorcelain(repositoryRoot))
	}
	goPath, err := resolveControllerRuntimeApplication(repositoryRoot, "go")
	if err != nil {
		return "", fmt.Errorf("trusted go: %w", err)
	}
	gofmtPath, err := resolveControllerRuntimeApplication(repositoryRoot, "gofmt")
	if err != nil {
		return "", fmt.Errorf("trusted gofmt: %w", err)
	}
	home, err := debugPrivateHome(repositoryRoot, "zz-debug-remaining-")
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
	type remainingGate struct {
		name    string
		app     string
		args    []string
		network NetworkMode
		envNet  bool
		limit   time.Duration
	}
	gates := []remainingGate{
		{"MODULE-DOWNLOAD", goPath, []string{"mod", "download", "-modcacherw", "all"}, NetworkGoModules, true, 4 * time.Minute},
		{"MODULE-VERIFY", goPath, []string{"mod", "verify"}, NetworkNone, false, 2 * time.Minute},
		{"TIDY-DIFF", goPath, []string{"mod", "tidy", "-diff"}, NetworkNone, false, 3 * time.Minute},
		{"FORMAT", gofmtPath, []string{"-l", "."}, NetworkNone, false, 2 * time.Minute},
		{"VET", goPath, []string{"vet", "./..."}, NetworkNone, false, 4 * time.Minute},
		{"TEST", goPath, []string{"test", "-count=1", "-timeout=30m", "./..."}, NetworkNone, false, 12 * time.Minute},
	}
	var report strings.Builder
	for _, gate := range gates {
		result, execErr := guard.Execute(ctx, gateProcessRequest{
			Application: gate.app,
			Args:        gate.args,
			Dir:         repositoryRoot,
			Env:         debugGateEnvironment(repositoryRoot, goPath, home, gate.envNet),
			Network:     gate.network,
			Timeout:     gate.limit,
			StdoutLimit: 1 << 16,
			StderrLimit: 1 << 16,
		})
		_, afterErr := InspectRepository(request)
		fmt.Fprintf(
			&report,
			"=== %s ===\nblocked=%v exit=%v sourceChanged=%v execErr=%v inspectAfter=%v porcelain=%q extras=%q stdout=%q stderr=%q\n",
			gate.name,
			result.Blocked,
			formatDebugExit(result.ExitCode),
			result.SourceChanged,
			execErr,
			afterErr,
			debugPorcelain(repositoryRoot),
			debugUnexpectedPaths(repositoryRoot, before),
			result.Stdout,
			result.Stderr,
		)
		if result.Blocked || result.SourceChanged || afterErr != nil {
			return report.String(), nil
		}
	}
	return report.String(), nil
}

func debugPrivateHome(repositoryRoot, prefix string) (string, error) {
	parent := filepath.Dir(repositoryRoot)
	if parent == "" || parent == repositoryRoot {
		parent = os.TempDir()
	}
	return os.MkdirTemp(parent, prefix)
}

func debugToolPATH(repositoryRoot, goPath string) string {
	seen := map[string]struct{}{filepath.Dir(goPath): {}}
	parts := []string{filepath.Dir(goPath)}
	for _, name := range []string{"git", "gofmt", "pwsh"} {
		resolved, err := resolveControllerRuntimeApplication(repositoryRoot, name)
		if err != nil {
			continue
		}
		dir := filepath.Dir(resolved)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		parts = append(parts, dir)
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

func debugGateEnvironment(repositoryRoot, goPath, home string, network bool) []string {
	env := []string{
		"PATH=" + debugToolPATH(repositoryRoot, goPath),
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
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=" + os.DevNull,
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_LITERAL_PATHSPECS=1",
		"GIT_PAGER=",
		"PAGER=",
		"GCM_INTERACTIVE=Never",
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
