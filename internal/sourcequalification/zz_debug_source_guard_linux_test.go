//go:build linux

package sourcequalification

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Debug-only reproduction of the production source-guard sequence.
// Never merge this file onto main. Skip unless SQ_DEBUG_SOURCE_GUARD=1.
func TestDebugSourceGuardReproduction(t *testing.T) {
	if os.Getenv("SQ_DEBUG_SOURCE_GUARD") != "1" {
		t.Skip("debug reproduction disabled")
	}

	root := os.Getenv("SQ_DEBUG_REPO_ROOT")
	base := os.Getenv("SQ_DEBUG_BASE")
	tested := os.Getenv("SQ_DEBUG_TESTED")
	if root == "" || base == "" || tested == "" {
		t.Fatal("SQ_DEBUG_REPO_ROOT/SQ_DEBUG_BASE/SQ_DEBUG_TESTED are required")
	}

	request := RepositoryRequest{
		Root:                   root,
		ExpectedBaseRevision:   base,
		ExpectedTestedRevision: tested,
	}

	probeRootlessIsolation(t)
	logInspect(t, "inspect-before-bind", request)

	goPath := mustTrustedLookPath(t, root, "go")
	gitPath := mustTrustedLookPath(t, root, "git")
	pwshPath := mustTrustedLookPath(t, root, "pwsh")
	gofmtPath := mustTrustedLookPath(t, root, "gofmt")
	unamePath := mustTrustedLookPath(t, root, "uname")
	selfPath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	selfPath, err = trustedControllerRuntimePath(root, selfPath)
	if err != nil {
		t.Fatalf("trusted test executable: %v", err)
	}

	applications := map[string]string{
		"go":                      goPath,
		"gofmt":                   gofmtPath,
		"git":                     gitPath,
		"pwsh":                    pwshPath,
		"uname":                   unamePath,
		"repopass-source-qualify": selfPath,
	}
	t.Logf("applications=%v", applications)

	binding, err := newOSGateApplicationBinding(context.Background(), applications)
	if err != nil {
		t.Fatalf("BindApplications: %v", err)
	}
	defer func() {
		if releaseErr := binding.Release(); releaseErr != nil {
			t.Errorf("Release: %v", releaseErr)
		}
	}()
	logInspect(t, "inspect-while-bound-before-execute", request)

	private := os.Getenv("SQ_DEBUG_PRIVATE")
	if private == "" {
		t.Fatal("SQ_DEBUG_PRIVATE is required")
	}
	environment := gateRunEnvironment{
		ToolPath:                 strings.Join(uniqueDirs(applications), string(os.PathListSeparator)),
		HomeDir:                  filepath.Join(private, "home"),
		GoCacheDir:               filepath.Join(private, "go-cache"),
		GoModCacheDir:            filepath.Join(private, "go-mod-cache"),
		TempDir:                  filepath.Join(private, "tmp"),
		GoProxy:                  "https://proxy.golang.org",
		GoSumDB:                  "sum.golang.org",
		VulnerabilityDatabaseURL: "https://vuln.go.dev",
	}

	result, execErr := osGateExecutor{}.Execute(context.Background(), gateProcessRequest{
		Application: goPath,
		Args:        []string{"version"},
		Dir:         root,
		Env:         gateEnvironment(environment, NetworkNone),
		Network:     NetworkNone,
		Timeout:     30 * time.Second,
		StdoutLimit: maximumGateOutputBytes,
		StderrLimit: maximumGateOutputBytes,
	})
	t.Logf(
		"execute blocked=%t timedOut=%t cancelled=%t cleanupFailed=%t sourceChanged=%t exit=%v execErr=%v stdout=%q stderr=%q",
		result.Blocked,
		result.TimedOut,
		result.Cancelled,
		result.CleanupFailed,
		result.SourceChanged,
		result.ExitCode,
		execErr,
		strings.TrimSpace(string(result.Stdout)),
		strings.TrimSpace(string(result.Stderr)),
	)
	if err := binding.Verify(context.Background()); err != nil {
		t.Logf("binding.Verify after execute: %v", err)
	}
	logInspect(t, "inspect-while-bound-after-execute", request)
}

func probeRootlessIsolation(t *testing.T) {
	t.Helper()
	unshare, ok := trustedLinuxSystemApplication("/usr/bin/unshare")
	truePath, trueOK := trustedLinuxSystemApplication("/usr/bin/true")
	t.Logf("trusted unshare=%t true=%t", ok, trueOK)
	if !ok || !trueOK {
		return
	}
	args := linuxRootlessGateIsolationArguments(NetworkNone, truePath, nil)
	okProbe := linuxIsolationProbe(context.Background(), unshare, args, linuxRootlessProbeEnvironment())
	t.Logf("rootless isolation probe ok=%t argv=%q", okProbe, args)

	sudo, privileged, privilegedOK := linuxPrivilegedGateIsolationCommand(
		NetworkNone,
		os.Getuid(),
		os.Getgid(),
		linuxPrivilegedProbeEnvironment(),
		truePath,
		nil,
	)
	okPrivileged := privilegedOK && linuxIsolationProbe(
		context.Background(),
		sudo,
		privileged,
		linuxPrivilegedLauncherEnvironment(),
	)
	t.Logf("privileged isolation probe ok=%t", okPrivileged)
}

func logInspect(t *testing.T, label string, request RepositoryRequest) {
	t.Helper()
	snapshot, err := InspectRepository(request)
	if err != nil {
		t.Logf("%s INSPECT_ERR=%v", label, err)
		fmt.Printf("%s INSPECT_ERR=%v\n", label, err)
		return
	}
	t.Logf("%s INSPECT_OK files=%d tree=%s", label, len(snapshot.Files), snapshot.Subject.TreeSHA)
	fmt.Printf("%s INSPECT_OK files=%d tree=%s\n", label, len(snapshot.Files), snapshot.Subject.TreeSHA)
}

func mustTrustedLookPath(t *testing.T, repositoryRoot, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("LookPath %s: %v", name, err)
	}
	resolved, err := trustedControllerRuntimePath(repositoryRoot, path)
	if err != nil {
		t.Fatalf("trusted %s: %v", name, err)
	}
	return resolved
}

func uniqueDirs(applications map[string]string) []string {
	seen := map[string]struct{}{}
	var dirs []string
	for _, path := range applications {
		dir := filepath.Dir(path)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		dirs = append(dirs, dir)
	}
	return dirs
}
