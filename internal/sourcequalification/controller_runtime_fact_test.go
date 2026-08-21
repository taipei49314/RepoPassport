package sourcequalification

// Production contract under test:
//
//	func controllerRuntimeFact(context.Context, string, []string, string, []string) (string, error)
//
// Platform facts are controller-local observations of already-resolved trusted
// tools. They MUST remain collectable when NetworkNone gate isolation is
// unavailable, because that isolation is a gate-execution prerequisite and
// Windows network-none gates are required to stay fail-closed until an
// enforceable boundary exists.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
)

func TestControllerRuntimeFactCollectsPinnedGoVersion(t *testing.T) {
	repository := t.TempDir()
	goPath := requirePATHRuntimeTool(t, "go")
	resolved, err := trustedControllerRuntimePath(repository, goPath)
	if err != nil {
		t.Fatalf("trusted go path: %v", err)
	}
	directory := t.TempDir()
	line, err := controllerRuntimeFact(
		context.Background(),
		resolved,
		[]string{"version"},
		directory,
		controllerRuntimeFactEnvironment(gateRunEnvironment{
			ToolPath:   filepath.Dir(resolved),
			HomeDir:    directory,
			TempDir:    directory,
			SystemRoot: windowsFactSystemRoot(t),
		}),
	)
	if err != nil {
		t.Fatalf("controllerRuntimeFact go version: %v", err)
	}
	want := "go version " + receiptGoVersion + " " + runtime.GOOS + "/" + runtime.GOARCH
	if line != want {
		t.Fatalf("go version fact = %q, want %q", line, want)
	}
}

func TestControllerRuntimeFactCollectsGitVersion(t *testing.T) {
	requireHostFilesystem(t)
	repository := t.TempDir()
	gitPath := requirePATHRuntimeTool(t, "git")
	resolved, err := trustedControllerRuntimePath(repository, gitPath)
	if err != nil {
		t.Fatalf("trusted git path: %v", err)
	}
	directory := t.TempDir()
	line, err := controllerRuntimeFact(
		context.Background(),
		resolved,
		[]string{"--version"},
		directory,
		controllerRuntimeFactEnvironment(gateRunEnvironment{
			ToolPath:   filepath.Dir(resolved),
			HomeDir:    directory,
			TempDir:    directory,
			SystemRoot: windowsFactSystemRoot(t),
		}),
	)
	if err != nil {
		t.Fatalf("controllerRuntimeFact git --version: %v", err)
	}
	if !strings.HasPrefix(line, "git version ") {
		t.Fatalf("git version fact = %q, want a git version line", line)
	}
}

func TestControllerRuntimeFactCollectsPowerShellVersion(t *testing.T) {
	repository := t.TempDir()
	pwshPath, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not on PATH")
	}
	pwshPath, err = restrictUnixRuntimeToolWriteBits(pwshPath)
	if err != nil {
		t.Skipf("pwsh write bits could not be restricted: %v", err)
	}
	resolved, err := trustedControllerRuntimePath(repository, pwshPath)
	if err != nil {
		t.Skipf("pwsh is not a trusted runtime file: %v", err)
	}
	directory := t.TempDir()
	line, err := controllerRuntimeFact(
		context.Background(),
		resolved,
		[]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"},
		directory,
		controllerRuntimeFactEnvironment(gateRunEnvironment{
			ToolPath:   filepath.Dir(resolved),
			HomeDir:    directory,
			TempDir:    directory,
			SystemRoot: windowsFactSystemRoot(t),
		}),
	)
	if err != nil {
		t.Fatalf("controllerRuntimeFact pwsh version: %v", err)
	}
	if !validReceiptPlatformVersion(line) {
		t.Fatalf("PowerShell version fact = %q, want a receipt platform version", line)
	}
}

func TestControllerRuntimeFactDoesNotUseNetworkNoneGateIsolation(t *testing.T) {
	repository := t.TempDir()
	goPath := requirePATHRuntimeTool(t, "go")
	resolved, err := trustedControllerRuntimePath(repository, goPath)
	if err != nil {
		t.Fatalf("trusted go path: %v", err)
	}
	directory := t.TempDir()
	environment := controllerRuntimeFactEnvironment(gateRunEnvironment{
		ToolPath:   filepath.Dir(resolved),
		HomeDir:    directory,
		TempDir:    directory,
		SystemRoot: windowsFactSystemRoot(t),
	})
	result, executeErr := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: resolved,
		Args:        []string{"version"},
		Dir:         directory,
		Env:         environment,
		Network:     NetworkNone,
		Timeout:     5 * time.Second,
		StdoutLimit: controllerRuntimeFactLimit,
		StderrLimit: controllerRuntimeFactLimit,
	})
	if result.Blocked {
		if executeErr == nil || result.ExitCode != nil {
			t.Fatalf("blocked NetworkNone gate executor = %#v err=%v", result, executeErr)
		}
	} else if executeErr != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.CleanupFailed || result.TimedOut || result.Cancelled {
		t.Fatalf("isolated NetworkNone fact probe = %#v err=%v", result, executeErr)
	}

	line, err := controllerRuntimeFact(context.Background(), resolved, []string{"version"}, directory, environment)
	if err != nil {
		t.Fatalf("platform fact collection inherited NetworkNone gate blocking: %v", err)
	}
	want := "go version " + receiptGoVersion + " " + runtime.GOOS + "/" + runtime.GOARCH
	if line != want {
		t.Fatalf("go version fact = %q, want %q", line, want)
	}
}

func windowsFactSystemRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return ""
	}
	value := os.Getenv("SystemRoot")
	if value == "" {
		t.Fatal("SystemRoot is required to execute Windows runtime facts")
	}
	return value
}

func requirePATHRuntimeTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	path, err = restrictUnixRuntimeToolWriteBits(path)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return path
}

// restrictUnixRuntimeToolWriteBits drops group/other write bits on a PATH tool
// the test process owns. Ordinary CI on ubuntu-24.04/20260816 extracts setup-go
// with those bits set; the 0o022 trust check itself is unchanged.
func restrictUnixRuntimeToolWriteBits(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return path, nil
	}
	resolved, err := pathsecurity.Resolve(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	perm := info.Mode().Perm()
	if perm&0o022 == 0 {
		return resolved, nil
	}
	if err := os.Chmod(resolved, perm&^0o022); err != nil {
		return "", err
	}
	return resolved, nil
}
