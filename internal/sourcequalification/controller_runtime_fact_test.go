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
)

func TestControllerRuntimeFactCollectsPinnedGoVersion(t *testing.T) {
	repository := t.TempDir()
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
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
	repository := t.TempDir()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
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
	if runtime.GOOS != "windows" {
		t.Skip("Windows is the platform whose NetworkNone gate executor must stay blocked")
	}
	repository := t.TempDir()
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
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
	if !result.Blocked || executeErr == nil || result.ExitCode != nil {
		t.Fatalf("NetworkNone gate executor = %#v err=%v, want fail-closed BLOCKED before invocation",
			result, executeErr)
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
