package trustchainstate

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testProcessContention(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestObserveChainStateConcurrencyCancellationAndProcessContention$")
	command.Env = append(os.Environ(), "REPOPASS_TRUST_CHAIN_STATE_HELPER=hold-lock", "REPOPASS_TRUST_CHAIN_STATE_ROOT="+root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
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
	if result, err := Observe(cancelled, root, testObservation(2, 2)); !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("cancelled contention = %#v, %v", result, err)
	}
	previousTimeout := lockTimeout
	lockTimeout = 50 * time.Millisecond
	result, err := Observe(context.Background(), root, testObservation(2, 2))
	lockTimeout = previousTimeout
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("lock contention = %#v, %v", result, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("contention changed state: got %q, err %v", after, err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("lock helper exit = %v", err)
	}
	if result, err := Observe(context.Background(), root, testObservation(2, 2)); err != nil || result != (Result{Evaluation: EvaluationAdvanced, ChainTerminalGeneration: 2, PolicyGeneration: 2}) {
		t.Fatalf("post-release advance = %#v, %v", result, err)
	}
}

func testProcessLockHelper(t *testing.T) bool {
	if os.Getenv("REPOPASS_TRUST_CHAIN_STATE_HELPER") != "hold-lock" {
		return false
	}
	root := os.Getenv("REPOPASS_TRUST_CHAIN_STATE_ROOT")
	stateDirectory, err := stateRoot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := openLock(filepath.Join(stateDirectory, strings.TrimPrefix(testRootID, "sha256:")+".lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := acquireLock(context.Background(), lock, lockTimeout); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("LOCKED\n")
	time.Sleep(250 * time.Millisecond)
	return true
}
