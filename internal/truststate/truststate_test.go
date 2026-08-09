package truststate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAuthority = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestA   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigestB   = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestObserveTransitionContract(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	observe := func(generation uint64, digest string) (Result, error) {
		return Observe(context.Background(), root, testAuthority, generation, digest)
	}

	result, err := observe(7, testDigestA)
	if err != nil || result != (Result{Evaluation: EvaluationInitialized, Generation: 7}) {
		t.Fatalf("initialize = %#v, %v", result, err)
	}
	result, err = observe(7, testDigestA)
	if err != nil || result != (Result{Evaluation: EvaluationMatched, Generation: 7}) {
		t.Fatalf("match = %#v, %v", result, err)
	}
	result, err = observe(9, testDigestB)
	if err != nil || result != (Result{Evaluation: EvaluationAdvanced, Generation: 9}) {
		t.Fatalf("advance = %#v, %v", result, err)
	}
	result, err = observe(8, testDigestA)
	if !errors.Is(err, ErrGenerationRollback) || result != (Result{Evaluation: EvaluationRollbackRejected, Generation: 9}) {
		t.Fatalf("rollback = %#v, %v", result, err)
	}
	result, err = observe(9, testDigestA)
	if !errors.Is(err, ErrGenerationEquivocation) || result != (Result{Evaluation: EvaluationEquivocationRejected, Generation: 9}) {
		t.Fatalf("equivocation = %#v, %v", result, err)
	}
	result, err = observe(9, testDigestB)
	if err != nil || result != (Result{Evaluation: EvaluationMatched, Generation: 9}) {
		t.Fatalf("post-rejection state changed: %#v, %v", result, err)
	}
}

func TestObserveWritesExactCanonicalState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	result, err := Observe(context.Background(), root, testAuthority, 13, testDigestA)
	if err != nil || result.Evaluation != EvaluationInitialized {
		t.Fatalf("Observe = %#v, %v", result, err)
	}
	path := stateFileForTest(t, root)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"authorityKeyId":"` + testAuthority + `","generation":13,"policyDigest":"` + testDigestA + `","schemaVersion":"1"}`
	if string(raw) != want {
		t.Fatalf("state bytes = %q, want %q", raw, want)
	}
}

func TestObserveRejectsCorruptStateWithoutRepair(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 3, testDigestA); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	corrupt := []byte(`{"schemaVersion":"1"}`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 4, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		t.Fatalf("corrupt state = %#v, %v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(corrupt) {
		t.Fatalf("corrupt state was repaired or unreadable: %q, %v", got, err)
	}
}

func TestObserveRejectsNonRegularStateWithoutOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 3, testDigestA); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 4, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable || result.Generation != 0 {
		t.Fatalf("nonregular state = %#v, %v", result, err)
	}
	if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
		t.Fatalf("nonregular state was overwritten: %#v, %v", info, statErr)
	}
}

func TestObserveRejectsOversizeStateWithoutOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 3, testDigestA); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	overflow := []byte(strings.Repeat("x", maxStateBytes+1))
	if err := os.WriteFile(path, overflow, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 4, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		t.Fatalf("oversize state = %#v, %v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(overflow) {
		t.Fatalf("oversize state was repaired or unreadable: %d, %v", len(got), err)
	}
}

func TestObserveRejectsHardLinkedState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 3, testDigestA); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	if err := os.Link(path, filepath.Join(filepath.Dir(path), "linked-state.json")); err != nil {
		t.Skipf("hard link creation is unavailable: %v", err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 4, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		t.Fatalf("hard-linked state = %#v, %v", result, err)
	}
}

func TestObserveRejectsSymlinkState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 3, testDigestA); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	target := filepath.Join(filepath.Dir(path), "real-state.json")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 4, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		t.Fatalf("linked state = %#v, %v", result, err)
	}
}

func TestObserveRejectsInvalidInputsBeforeCreatingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	result, err := Observe(context.Background(), root, "sha256:not-a-key", 1, testDigestA)
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		t.Fatalf("invalid authority = %#v, %v", result, err)
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("invalid input created state root: %v", statErr)
	}
}

func TestObserveAcceptsRelativeDataRoot(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	result, err := Observe(context.Background(), "relative-controller-data", testAuthority, 1, testDigestA)
	if err != nil || result != (Result{Evaluation: EvaluationInitialized, Generation: 1}) {
		t.Fatalf("relative data root = %#v, %v", result, err)
	}
	statePath := filepath.Join(workingDirectory, "relative-controller-data", "trust-policy-state", "v1", strings.TrimPrefix(testAuthority, "sha256:")+".json")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("relative state path was not created: %v", err)
	}
}

func TestObserveRejectsRepositoryLocalDataRoot(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "repo-passport.yml"), []byte("schemaVersion: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(repository, "controller-data")
	result, err := Observe(context.Background(), root, testAuthority, 1, testDigestA)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
		t.Fatalf("repository data root = %#v, %v", result, err)
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("repository-local state was created: %v", statErr)
	}
}

func TestObserveConcurrentGenerationsConvergeAtMaximum(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	var group sync.WaitGroup
	errorsByGeneration := make(chan error, 20)
	for generation := maxGeneration - 19; generation <= maxGeneration; generation++ {
		generation := generation
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := Observe(context.Background(), root, testAuthority, generation, testDigestA)
			errorsByGeneration <- err
		}()
	}
	group.Wait()
	close(errorsByGeneration)
	for err := range errorsByGeneration {
		if errors.Is(err, ErrUnavailable) {
			t.Fatalf("concurrent maximum observation unavailable: %v", err)
		}
	}
	result, err := Observe(context.Background(), root, testAuthority, maxGeneration, testDigestA)
	if err != nil || result != (Result{Evaluation: EvaluationMatched, Generation: maxGeneration}) {
		t.Fatalf("terminal concurrent state = %#v, %v", result, err)
	}
}

func TestObserveConcurrentEqualGenerationEstablishesOneDigest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	type outcome struct {
		digest string
		result Result
		err    error
	}
	results := make(chan outcome, 2)
	for _, digest := range []string{testDigestA, testDigestB} {
		digest := digest
		go func() {
			result, err := Observe(context.Background(), root, testAuthority, 7, digest)
			results <- outcome{digest: digest, result: result, err: err}
		}()
	}
	first, second := <-results, <-results
	all := []outcome{first, second}
	initialized := 0
	equivocated := 0
	for _, item := range all {
		switch {
		case item.err == nil && item.result == (Result{Evaluation: EvaluationInitialized, Generation: 7}):
			initialized++
		case errors.Is(item.err, ErrGenerationEquivocation) && item.result == (Result{Evaluation: EvaluationEquivocationRejected, Generation: 7}):
			equivocated++
		default:
			t.Fatalf("unexpected equal-generation outcome: %#v", item)
		}
	}
	if initialized != 1 || equivocated != 1 {
		t.Fatalf("equal-generation outcomes: initialized=%d equivocated=%d", initialized, equivocated)
	}
}

func TestObserveCrossProcessEqualGenerationEstablishesOneDigest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	outputs := make(chan helperOutput, 2)
	for _, digest := range []string{testDigestA, testDigestB} {
		digest := digest
		go func() {
			output, err := runTruststateHelper("observe", root, digest)
			outputs <- helperOutput{output: output, err: err}
		}()
	}
	first, second := <-outputs, <-outputs
	if first.err != nil || second.err != nil {
		t.Fatalf("cross-process helper errors: first=%v second=%v", first.err, second.err)
	}
	initialized := 0
	equivocated := 0
	for _, output := range []string{first.output, second.output} {
		switch {
		case strings.Contains(output, "RESULT|initialized|7|nil"):
			initialized++
		case strings.Contains(output, "RESULT|equivocation-rejected|7|equivocation"):
			equivocated++
		default:
			t.Fatalf("unexpected helper output: %q", output)
		}
	}
	if initialized != 1 || equivocated != 1 {
		t.Fatalf("cross-process outcomes: initialized=%d equivocated=%d", initialized, equivocated)
	}
}

func TestObserveCrossProcessHigherGenerationsConvergeAtMaximum(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if result, err := Observe(context.Background(), root, testAuthority, 7, testDigestA); err != nil || result != (Result{Evaluation: EvaluationInitialized, Generation: 7}) {
		t.Fatalf("initial state = %#v, %v", result, err)
	}
	type generationOutput struct {
		generation uint64
		helperOutput
	}
	outputs := make(chan generationOutput, 2)
	for _, observation := range []struct {
		generation uint64
		digest     string
	}{{8, testDigestB}, {9, testDigestA}} {
		observation := observation
		go func() {
			output, err := runTruststateGenerationHelper(root, observation.generation, observation.digest)
			outputs <- generationOutput{generation: observation.generation, helperOutput: helperOutput{output: output, err: err}}
		}()
	}
	for range 2 {
		observation := <-outputs
		if observation.err != nil {
			t.Fatalf("higher-generation helper %d: %v", observation.generation, observation.err)
		}
		switch observation.generation {
		case 8:
			if !strings.Contains(observation.output, "RESULT|advanced|8|nil") && !strings.Contains(observation.output, "RESULT|rollback-rejected|9|rollback") {
				t.Fatalf("unexpected generation-8 helper output: %q", observation.output)
			}
		case 9:
			if !strings.Contains(observation.output, "RESULT|advanced|9|nil") {
				t.Fatalf("unexpected generation-9 helper output: %q", observation.output)
			}
		}
	}
	result, err := Observe(context.Background(), root, testAuthority, 9, testDigestA)
	if err != nil || result != (Result{Evaluation: EvaluationMatched, Generation: 9}) {
		t.Fatalf("terminal higher-generation state = %#v, %v", result, err)
	}
	path := stateFileForTest(t, root)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"authorityKeyId":"` + testAuthority + `","generation":9,"policyDigest":"` + testDigestA + `","schemaVersion":"1"}`
	if string(raw) != want {
		t.Fatalf("higher-generation canonical bytes = %q, want %q", raw, want)
	}
}

func TestObserveCrossProcessLockTimeoutAndExitRelease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 1, testDigestA); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestTruststateProcessHelper$")
	command.Env = append(os.Environ(),
		"REPOPASS_TRUSTSTATE_HELPER=hold-lock",
		"REPOPASS_TRUSTSTATE_ROOT="+root,
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
		command.Process.Kill()
		command.Wait()
		t.Fatalf("helper did not acquire lock: %q", scanner.Text())
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledResult, cancelledErr := Observe(cancelled, root, testAuthority, 2, testDigestB)
	if !errors.Is(cancelledErr, ErrUnavailable) || cancelledResult != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		command.Process.Kill()
		command.Wait()
		t.Fatalf("cancelled contention = %#v, %v", cancelledResult, cancelledErr)
	}
	previousTimeout := lockTimeout
	lockTimeout = 100 * time.Millisecond
	defer func() { lockTimeout = previousTimeout }()
	result, observeErr := Observe(context.Background(), root, testAuthority, 2, testDigestB)
	if !errors.Is(observeErr, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable, Generation: 0}) {
		t.Fatalf("lock contention = %#v, %v", result, observeErr)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("release lock helper: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("lock holder exit = %v", err)
	}
	result, observeErr = Observe(context.Background(), root, testAuthority, 2, testDigestB)
	if observeErr != nil || result != (Result{Evaluation: EvaluationAdvanced, Generation: 2}) {
		t.Fatalf("post-exit lock release = %#v, %v", result, observeErr)
	}
}

func TestObserveRejectsGroupWritableStateRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission invariant")
	}
	root := t.TempDir()
	root = filepath.Join(root, "controller-data")
	if _, err := Observe(context.Background(), root, testAuthority, 3, testDigestA); err != nil {
		t.Fatal(err)
	}
	stateRoot, err := stateRoot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateRoot, 0o770); err != nil {
		t.Skipf("cannot change state directory mode: %v", err)
	}
	result, err := Observe(context.Background(), root, testAuthority, 4, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
		t.Fatalf("writable state root = %#v, %v", result, err)
	}
}

func TestObserveCancelledContextFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Observe(ctx, filepath.Join(t.TempDir(), "controller-data"), testAuthority, 1, testDigestA)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable || result.Generation != 0 {
		t.Fatalf("cancelled Observe = %#v, %v", result, err)
	}
}

func TestDecodeRecordRejectsNonCanonicalAndInvalidRecords(t *testing.T) {
	valid := `{"authorityKeyId":"` + testAuthority + `","generation":1,"policyDigest":"` + testDigestA + `","schemaVersion":"1"}`
	cases := []string{
		`{"generation":1,"authorityKeyId":"` + testAuthority + `","policyDigest":"` + testDigestA + `","schemaVersion":"1"}`,
		valid + "\n",
		"\ufeff" + valid,
		strings.Replace(valid, `"generation":1`, `"generation":1.0`, 1),
		strings.Replace(valid, `"schemaVersion":"1"`, `"schemaVersion":"1","extra":true`, 1),
		strings.Replace(valid, `"generation":1`, `"generation":0`, 1),
	}
	for _, raw := range cases {
		t.Run("invalid", func(t *testing.T) {
			if _, err := decodeRecord([]byte(raw)); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("decodeRecord(%q) error = %v", raw, err)
			}
		})
	}
	if value, err := decodeRecord([]byte(valid)); err != nil || value.Generation != 1 {
		t.Fatalf("valid record = %#v, %v", value, err)
	}
}

func stateFileForTest(t *testing.T, dataRoot string) string {
	t.Helper()
	root, err := stateRoot(context.Background(), dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, strings.TrimPrefix(testAuthority, "sha256:")+".json")
}

func TestTruststateProcessHelper(t *testing.T) {
	mode := os.Getenv("REPOPASS_TRUSTSTATE_HELPER")
	if mode == "" {
		return
	}
	root := os.Getenv("REPOPASS_TRUSTSTATE_ROOT")
	switch mode {
	case "observe":
		generation := uint64(7)
		if value := os.Getenv("REPOPASS_TRUSTSTATE_GENERATION"); value != "" {
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil {
				os.Exit(7)
			}
			generation = parsed
		}
		result, err := Observe(context.Background(), root, testAuthority, generation, os.Getenv("REPOPASS_TRUSTSTATE_DIGEST"))
		kind := "nil"
		if errors.Is(err, ErrGenerationEquivocation) {
			kind = "equivocation"
		} else if errors.Is(err, ErrGenerationRollback) {
			kind = "rollback"
		} else if err != nil {
			kind = "other"
		}
		fmt.Printf("RESULT|%s|%d|%s\n", result.Evaluation, result.Generation, kind)
	case "hold-lock":
		if _, err := Observe(context.Background(), root, testAuthority, 1, testDigestA); err != nil {
			os.Exit(2)
		}
		stateDirectory, err := stateRoot(context.Background(), root)
		if err != nil {
			os.Exit(3)
		}
		lock, err := openLock(filepath.Join(stateDirectory, strings.TrimPrefix(testAuthority, "sha256:")+".lock"))
		if err != nil {
			os.Exit(4)
		}
		if _, err := acquireLock(context.Background(), lock, lockTimeout); err != nil {
			os.Exit(5)
		}
		fmt.Println("LOCKED")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(6)
		}
		os.Exit(0) // Deliberately bypasses unlock/close: the OS must release it.
	default:
		os.Exit(7)
	}
}

type helperOutput struct {
	output string
	err    error
}

func runTruststateHelper(mode, root, digest string) (string, error) {
	command := exec.Command(os.Args[0], "-test.run=^TestTruststateProcessHelper$")
	command.Env = append(os.Environ(),
		"REPOPASS_TRUSTSTATE_HELPER="+mode,
		"REPOPASS_TRUSTSTATE_ROOT="+root,
		"REPOPASS_TRUSTSTATE_DIGEST="+digest,
	)
	output, err := command.CombinedOutput()
	return string(output), err
}

func runTruststateGenerationHelper(root string, generation uint64, digest string) (string, error) {
	command := exec.Command(os.Args[0], "-test.run=^TestTruststateProcessHelper$")
	command.Env = append(os.Environ(),
		"REPOPASS_TRUSTSTATE_HELPER=observe",
		"REPOPASS_TRUSTSTATE_ROOT="+root,
		"REPOPASS_TRUSTSTATE_DIGEST="+digest,
		"REPOPASS_TRUSTSTATE_GENERATION="+strconv.FormatUint(generation, 10),
	)
	output, err := command.CombinedOutput()
	return string(output), err
}
