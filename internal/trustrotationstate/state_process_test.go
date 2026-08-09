package trustrotationstate

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObserveContentionAndCancellationLeaveStateUnchanged(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestTrustRotationStateProcessHelper$")
	command.Env = append(os.Environ(),
		"REPOPASS_TRUST_ROTATION_STATE_HELPER=hold-lock",
		"REPOPASS_TRUST_ROTATION_STATE_ROOT="+root,
	)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "LOCKED" {
		t.Fatalf("lock helper did not signal readiness: %q", scanner.Text())
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	result, observeErr := Observe(cancelled, root, testObservation(2, 2))
	if !errors.Is(observeErr, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("cancelled contention = %#v, %v", result, observeErr)
	}
	previousTimeout := lockTimeout
	lockTimeout = 50 * time.Millisecond
	result, observeErr = Observe(context.Background(), root, testObservation(2, 2))
	lockTimeout = previousTimeout
	if !errors.Is(observeErr, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("lock contention = %#v, %v", result, observeErr)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("contention changed state: got %q, err %v", after, readErr)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("release lock helper: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("lock helper exit = %v", err)
	}
	result, observeErr = Observe(context.Background(), root, testObservation(2, 2))
	if observeErr != nil || result != (Result{Evaluation: EvaluationAdvanced, TransitionGeneration: 2, PolicyGeneration: 2}) {
		t.Fatalf("post-release advance = %#v, %v", result, observeErr)
	}
}

func TestTrustRotationStateProcessHelper(t *testing.T) {
	if os.Getenv("REPOPASS_TRUST_ROTATION_STATE_HELPER") != "hold-lock" {
		return
	}
	root := os.Getenv("REPOPASS_TRUST_ROTATION_STATE_ROOT")
	stateDirectory, err := stateRoot(context.Background(), root)
	if err != nil {
		os.Exit(2)
	}
	lock, err := openLock(filepath.Join(stateDirectory, strings.TrimPrefix(testRootID, "sha256:")+".lock"))
	if err != nil {
		os.Exit(3)
	}
	if _, err := acquireLock(context.Background(), lock, lockTimeout); err != nil {
		_ = lock.Close()
		os.Exit(4)
	}
	_, _ = os.Stdout.WriteString("LOCKED\n")
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		os.Exit(5)
	}
	os.Exit(0) // The process exit must release a lock even without cleanup.
}
