//go:build !windows

package sourcequalification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const gateExecutorSetsidHelperEnvironment = "REPOPASS_GATE_EXECUTOR_SETSID_HELPER"

func TestOSGateExecutorRejectsDescendantThatEscapesTheProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "setsid-descendant-survived")
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	request := gateProcessRequest{
		Application: executable,
		Args:        []string{"-test.run=^TestOSGateExecutorSetsidHelperProcess$"},
		Dir:         t.TempDir(),
		Network:     NetworkNone,
		Env: []string{
			gateExecutorSetsidHelperEnvironment + "=root",
			"REPOPASS_GATE_DESCENDANT_MARKER=" + marker,
		},
		Timeout:     5 * time.Second,
		StdoutLimit: 1024,
		StderrLimit: 1024,
	}

	result, err := newOSGateExecutor().Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 || result.Blocked || result.TimedOut ||
		result.Cancelled || result.CleanupFailed {
		t.Fatalf("contained descendant result = %#v, want a clean root exit with no residue", result)
	}
	time.Sleep(900 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("setsid descendant escaped process-tree containment: %v", err)
	}
}

func TestOSGateExecutorSetsidHelperProcess(t *testing.T) {
	mode := os.Getenv(gateExecutorSetsidHelperEnvironment)
	if mode == "" {
		return
	}
	marker := os.Getenv("REPOPASS_GATE_DESCENDANT_MARKER")
	switch mode {
	case "root":
		command := exec.Command(os.Args[0], "-test.run=^TestOSGateExecutorSetsidHelperProcess$")
		command.Env = gateExecutorReplaceEnvironment(os.Environ(), map[string]string{
			gateExecutorSetsidHelperEnvironment: "descendant",
			"REPOPASS_GATE_DESCENDANT_MARKER":   marker,
		})
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		command.Stdin = nil
		command.Stdout = nil
		command.Stderr = nil
		if err := command.Start(); err != nil {
			os.Exit(41)
		}
		os.Exit(0)
	case "descendant":
		time.Sleep(500 * time.Millisecond)
		if err := os.WriteFile(marker, []byte("escaped\n"), 0o600); err != nil {
			os.Exit(42)
		}
		os.Exit(0)
	default:
		os.Exit(43)
	}
}
