package sourcequalification

// Production contract under test:
//
//	func newOSGateExecutor() gateExecutor
//
// When its required isolation is available, the executor MUST invoke the
// exact application with independently bound stdout/stderr, terminate the
// complete process tree on timeout or cancellation, and return only structured
// facts. When isolation is unavailable, it MUST block before invocation.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

const gateExecutorHelperEnvironment = "REPOPASS_GATE_EXECUTOR_HELPER"

func TestOSGateExecutorCapturesExitAndIndependentStreams(t *testing.T) {
	executor := newOSGateExecutor()
	request := gateExecutorRequest(t, "streams", time.Second, 1024, 1024)
	result, err := executor.Execute(context.Background(), request)
	if gateExecutorBlockedByUnavailableIsolation(t, request, result, err) {
		return
	}
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.ExitCode == nil || *result.ExitCode != 17 ||
		string(result.Stdout) != "public-test-stdout\n" ||
		string(result.Stderr) != "private-test-stderr\n" ||
		result.Blocked || result.TimedOut || result.Cancelled ||
		result.StdoutOverflow || result.StderrOverflow || result.CleanupFailed {
		t.Fatalf("unexpected process result: %#v", result)
	}
}

func TestOSGateExecutorFailsClosedOnIndependentOutputOverflow(t *testing.T) {
	for _, stream := range []string{"stdout-overflow", "stderr-overflow"} {
		t.Run(stream, func(t *testing.T) {
			executor := newOSGateExecutor()
			request := gateExecutorRequest(t, stream, 5*time.Second, 1024, 1024)
			result, err := executor.Execute(context.Background(), request)
			if gateExecutorBlockedByUnavailableIsolation(t, request, result, err) {
				return
			}
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.ExitCode == nil || *result.ExitCode != 0 {
				t.Fatalf("overflow helper result = %#v", result)
			}
			if len(result.Stdout) > int(request.StdoutLimit) || len(result.Stderr) > int(request.StderrLimit) {
				t.Fatalf("bounded output lengths = %d/%d", len(result.Stdout), len(result.Stderr))
			}
			if stream == "stdout-overflow" && (!result.StdoutOverflow || result.StderrOverflow) {
				t.Fatalf("stdout overflow flags = %#v", result)
			}
			if stream == "stderr-overflow" && (!result.StderrOverflow || result.StdoutOverflow) {
				t.Fatalf("stderr overflow flags = %#v", result)
			}
		})
	}
}

func TestOSGateExecutorTimeoutKillsCompleteProcessTree(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-survived")
	executor := newOSGateExecutor()
	request := gateExecutorRequest(t, "spawn-descendant", 150*time.Millisecond, 1024, 1024)
	request.Env = append(request.Env, "REPOPASS_GATE_DESCENDANT_MARKER="+marker)
	result, err := executor.Execute(context.Background(), request)
	if gateExecutorBlockedByUnavailableIsolation(t, request, result, err) {
		return
	}
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.TimedOut || result.ExitCode != nil || result.CleanupFailed {
		t.Fatalf("timeout result = %#v", result)
	}
	time.Sleep(900 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant escaped process-tree termination: %v", err)
	}
}

func TestOSGateExecutorCancellationKillsProcessTree(t *testing.T) {
	executor := newOSGateExecutor()
	request := gateExecutorRequest(t, "sleep", 10*time.Second, 1024, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	result, err := executor.Execute(ctx, request)
	if gateExecutorBlockedByUnavailableIsolation(t, request, result, err) {
		return
	}
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Cancelled || result.ExitCode != nil || result.CleanupFailed {
		t.Fatalf("cancel result = %#v", result)
	}
}

func TestOSGateExecutorReportsMissingApplicationAsBlocked(t *testing.T) {
	executor := newOSGateExecutor()
	request := gateExecutorRequest(t, "streams", time.Second, 1024, 1024)
	request.Application = filepath.Join(t.TempDir(), "missing-application")
	result, err := executor.Execute(context.Background(), request)
	if err == nil || !result.Blocked || result.ExitCode != nil {
		t.Fatalf("missing application result = %#v, err=%v", result, err)
	}
}

func gateExecutorRequest(t *testing.T, mode string, timeout time.Duration, stdoutLimit, stderrLimit int64) gateProcessRequest {
	t.Helper()
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	environment := []string{
		gateExecutorHelperEnvironment + "=" + mode,
		"REPOPASS_GATE_DESCENDANT_MARKER=",
	}
	if runtime.GOOS == "windows" {
		environment = append(environment,
			"SYSTEMROOT="+os.Getenv("SYSTEMROOT"),
			"WINDIR="+os.Getenv("WINDIR"),
		)
	}
	return gateProcessRequest{
		Application: executable,
		Args:        []string{"-test.run=^TestOSGateExecutorHelperProcess$"},
		Dir:         t.TempDir(),
		Env:         environment,
		Network:     NetworkGoModules,
		Timeout:     timeout,
		StdoutLimit: stdoutLimit,
		StderrLimit: stderrLimit,
	}
}

func gateExecutorBlockedByUnavailableIsolation(
	t *testing.T,
	request gateProcessRequest,
	result gateProcessResult,
	err error,
) bool {
	t.Helper()
	if runtime.GOOS != "linux" || !errors.Is(err, errGateIsolationUnavailable) {
		return false
	}
	if !availableGateApplication(request.Application) || !validGateProcessDirectory(request.Dir) {
		t.Fatal("gate executor fixture is invalid before the isolation capability probe")
	}
	if !result.Blocked || result.ExitCode != nil || len(result.Stdout) != 0 || len(result.Stderr) != 0 ||
		result.TimedOut || result.Cancelled || result.StdoutOverflow || result.StderrOverflow ||
		result.CleanupFailed {
		t.Fatalf("unavailable isolation result = %#v, err=%v", result, err)
	}
	t.Log("verified fail-closed BLOCKED result because rootless gate isolation is unavailable")
	return true
}

func TestOSGateExecutorHelperProcess(t *testing.T) {
	mode := os.Getenv(gateExecutorHelperEnvironment)
	if mode == "" {
		return
	}
	switch mode {
	case "streams":
		_, _ = fmt.Fprintln(os.Stdout, "public-test-stdout")
		_, _ = fmt.Fprintln(os.Stderr, "private-test-stderr")
		os.Exit(17)
	case "stdout-overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 2048))
		os.Exit(0)
	case "stderr-overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'y'}, 2048))
		os.Exit(0)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "spawn-descendant":
		marker := os.Getenv("REPOPASS_GATE_DESCENDANT_MARKER")
		command := exec.Command(os.Args[0], "-test.run=^TestOSGateExecutorHelperProcess$")
		command.Env = gateExecutorReplaceEnvironment(os.Environ(), map[string]string{
			gateExecutorHelperEnvironment:     "descendant",
			"REPOPASS_GATE_DESCENDANT_MARKER": marker,
		})
		if err := command.Start(); err != nil {
			os.Exit(31)
		}
		_, _ = fmt.Fprintln(os.Stdout, "descendant-pid="+strconv.Itoa(command.Process.Pid))
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "descendant":
		time.Sleep(500 * time.Millisecond)
		if err := os.WriteFile(os.Getenv("REPOPASS_GATE_DESCENDANT_MARKER"), []byte("escaped\n"), 0o600); err != nil {
			os.Exit(32)
		}
		os.Exit(0)
	default:
		os.Exit(33)
	}
}

func gateExecutorReplaceEnvironment(environment []string, replacements map[string]string) []string {
	result := make([]string, 0, len(environment)+len(replacements))
	for _, item := range environment {
		name, _, found := bytes.Cut([]byte(item), []byte{'='})
		if !found {
			continue
		}
		if _, replace := replacements[string(name)]; !replace {
			result = append(result, item)
		}
	}
	for name, value := range replacements {
		result = append(result, name+"="+value)
	}
	return result
}
