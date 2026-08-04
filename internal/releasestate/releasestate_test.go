package releasestate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAuthorityA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAuthorityB = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testDigestA    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigestB    = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

type observer func(context.Context, string, string, string, string, uint64, string) (Result, error)

func TestObserveTransitionContract(t *testing.T) {
	for name, observe := range map[string]observer{"authority": ObserveAuthority, "policy": ObservePolicy, "index": ObserveIndex} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "controller-data")
			call := func(generation uint64, digest string) (Result, error) {
				return observe(context.Background(), root, testAuthorityA, "repopass", "alpha", generation, digest)
			}
			assertOutcome(t, capture(call(7, testDigestA)), Result{EvaluationInitialized, 7}, nil)
			assertOutcome(t, capture(call(7, testDigestA)), Result{EvaluationMatched, 7}, nil)
			assertOutcome(t, capture(call(9, testDigestB)), Result{EvaluationAdvanced, 9}, nil)
			assertOutcome(t, capture(call(8, testDigestA)), Result{EvaluationRollbackRejected, 9}, ErrGenerationRollback)
			assertOutcome(t, capture(call(9, testDigestA)), Result{EvaluationEquivocationRejected, 9}, ErrGenerationEquivocation)
			assertOutcome(t, capture(call(9, testDigestB)), Result{EvaluationMatched, 9}, nil)
		})
	}
}

func TestObserveAuthorityChainReusesRootAnchoredAuthorityNamespace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	assertOutcome(t, capture(ObserveAuthority(context.Background(), root, testAuthorityA, "repopass", "alpha", 7, testDigestA)), Result{EvaluationInitialized, 7}, nil)
	// A complete chain is deliberately observed only once at its terminal
	// generation, and advances the Alpha.29 one-hop record in the same
	// root-anchored authority namespace.
	assertOutcome(t, capture(ObserveAuthorityChain(context.Background(), root, testAuthorityA, "repopass", "alpha", 9, testDigestB)), Result{EvaluationAdvanced, 9}, nil)
	assertOutcome(t, capture(ObserveAuthority(context.Background(), root, testAuthorityA, "repopass", "alpha", 7, testDigestA)), Result{EvaluationRollbackRejected, 9}, ErrGenerationRollback)
	assertOutcome(t, capture(ObserveAuthorityChain(context.Background(), root, testAuthorityA, "repopass", "alpha", 9, testDigestA)), Result{EvaluationEquivocationRejected, 9}, ErrGenerationEquivocation)
}

func TestReleaseIndexGenerationFloorRollbackEquivocationAndStateFailure(t *testing.T) {
	for name, item := range map[string]struct {
		observe observer
		kind    stateKind
	}{
		"policy":    {ObservePolicy, policyState},
		"index":     {ObserveIndex, indexState},
		"authority": {ObserveAuthority, authorityState},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "controller-data")
			assertOutcome(t, capture(item.observe(context.Background(), root, testAuthorityA, "repopass", "alpha", 11, testDigestA)), Result{EvaluationInitialized, 11}, nil)
			assertOutcome(t, capture(item.observe(context.Background(), root, testAuthorityA, "repopass", "alpha", 10, testDigestA)), Result{EvaluationRollbackRejected, 11}, ErrGenerationRollback)
			assertOutcome(t, capture(item.observe(context.Background(), root, testAuthorityA, "repopass", "alpha", 11, testDigestB)), Result{EvaluationEquivocationRejected, 11}, ErrGenerationEquivocation)
			path := stateFileForTest(t, root, item.kind, testAuthorityA, "repopass", "alpha")
			if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
				t.Fatal(err)
			}
			assertOutcome(t, capture(item.observe(context.Background(), root, testAuthorityA, "repopass", "alpha", 12, testDigestB)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
			raw, err := os.ReadFile(path)
			if err != nil || string(raw) != "corrupt" {
				t.Fatalf("state failure repaired or replaced corrupt state: %q, %v", raw, err)
			}
		})
	}
}

func TestPolicyAndIndexAreDistinctNamespaces(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 5, testDigestA)), Result{EvaluationInitialized, 5}, nil)
	assertOutcome(t, capture(ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)), Result{EvaluationInitialized, 2}, nil)
	assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 5, testDigestA)), Result{EvaluationMatched, 5}, nil)
	assertOutcome(t, capture(ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)), Result{EvaluationMatched, 2}, nil)

	policyRoot, err := stateRoot(context.Background(), root, policyState)
	if err != nil {
		t.Fatal(err)
	}
	indexRoot, err := stateRoot(context.Background(), root, indexState)
	if err != nil {
		t.Fatal(err)
	}
	if samePath(policyRoot, indexRoot) {
		t.Fatal("policy and index state roots are identical")
	}
	key := stateKey(testAuthorityA, "repopass", "alpha")
	for _, item := range []struct {
		root string
		kind stateKind
	}{{policyRoot, policyState}, {indexRoot, indexState}} {
		raw, readErr := os.ReadFile(filepath.Join(item.root, key+".json"))
		if readErr != nil || !strings.Contains(string(raw), `"kind":"`+string(item.kind)+`"`) {
			t.Fatalf("%s state record = %q, %v", item.kind, raw, readErr)
		}
		if _, statErr := os.Stat(filepath.Join(item.root, key+".lock")); statErr != nil {
			t.Fatalf("%s lock is absent: %v", item.kind, statErr)
		}
	}
}

func TestAuthorityPolicyAndIndexAreDistinctNamespaces(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	for name, item := range map[string]struct {
		observe    observer
		kind       stateKind
		generation uint64
		digest     string
	}{
		"authority": {ObserveAuthority, authorityState, 3, testDigestA},
		"policy":    {ObservePolicy, policyState, 4, testDigestB},
		"index":     {ObserveIndex, indexState, 5, testDigestA},
	} {
		t.Run(name, func(t *testing.T) {
			assertOutcome(t, capture(item.observe(context.Background(), root, testAuthorityA, "repopass", "alpha", item.generation, item.digest)), Result{EvaluationInitialized, item.generation}, nil)
			path := stateFileForTest(t, root, item.kind, testAuthorityA, "repopass", "alpha")
			raw, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(raw), `"kind":"`+string(item.kind)+`"`) {
				t.Fatalf("%s state record = %q, %v", item.kind, raw, err)
			}
		})
	}
}

func TestTupleComponentsAreDistinctKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	cases := []struct {
		authority string
		product   string
		channel   string
		digest    string
	}{
		{testAuthorityA, "repopass", "alpha", testDigestA},
		{testAuthorityB, "repopass", "alpha", testDigestB},
		{testAuthorityA, "other-product", "alpha", testDigestB},
		{testAuthorityA, "repopass", "beta", testDigestB},
	}
	seen := map[string]bool{}
	for _, item := range cases {
		key := stateKey(item.authority, item.product, item.channel)
		if seen[key] {
			t.Fatalf("tuple key collision: %q", key)
		}
		seen[key] = true
		result, err := ObservePolicy(context.Background(), root, item.authority, item.product, item.channel, 1, item.digest)
		assertOutcome(t, capture(result, err), Result{EvaluationInitialized, 1}, nil)
	}
}

func TestObserveWritesExactCanonicalState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	assertOutcome(t, capture(ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 13, testDigestA)), Result{EvaluationInitialized, 13}, nil)
	path := stateFileForTest(t, root, indexState, testAuthorityA, "repopass", "alpha")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"authorityKeyId":"` + testAuthorityA + `","channel":"alpha","digest":"` + testDigestA + `","generation":13,"kind":"index","product":"repopass","schemaVersion":"1"}`
	if string(raw) != want {
		t.Fatalf("state bytes = %q, want %q", raw, want)
	}
}

func TestObserveRejectsInvalidInputsBeforeIO(t *testing.T) {
	cases := []struct {
		name       string
		ctx        context.Context
		authority  string
		product    string
		channel    string
		generation uint64
		digest     string
	}{
		{"nil-context", nil, testAuthorityA, "repopass", "alpha", 1, testDigestA},
		{"authority", context.Background(), "sha256:bad", "repopass", "alpha", 1, testDigestA},
		{"product", context.Background(), testAuthorityA, "RepoPass", "alpha", 1, testDigestA},
		{"channel", context.Background(), testAuthorityA, "repopass", "../alpha", 1, testDigestA},
		{"zero-generation", context.Background(), testAuthorityA, "repopass", "alpha", 0, testDigestA},
		{"large-generation", context.Background(), testAuthorityA, "repopass", "alpha", maxGeneration + 1, testDigestA},
		{"digest", context.Background(), testAuthorityA, "repopass", "alpha", 1, "sha256:BAD"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "not-created")
			result, err := ObservePolicy(item.ctx, root, item.authority, item.product, item.channel, item.generation, item.digest)
			assertOutcome(t, capture(result, err), Result{EvaluationUnavailable, 0}, ErrUnavailable)
			if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
				t.Fatalf("invalid input created state: %v", statErr)
			}
		})
	}
}

func TestObserveCancelledContextFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := filepath.Join(t.TempDir(), "controller-data")
	assertOutcome(t, capture(ObserveIndex(ctx, root, testAuthorityA, "repopass", "alpha", 1, testDigestA)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
}

func TestObserveRejectsRepositoryLocalRoot(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "repo-passport.yml"), []byte("schemaVersion: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(repository, "controller-data")
	assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 1, testDigestA)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("repository-local root created: %v", err)
	}
}

func TestObserveRejectsCorruptOversizeAndNonRegularStateWithoutRepair(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*testing.T, string)
		inspect func(*testing.T, string)
	}{
		{
			name: "corrupt",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte(`{"schemaVersion":"1"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			inspect: func(t *testing.T, path string) {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != `{"schemaVersion":"1"}` {
					t.Fatalf("corruption changed: %q, %v", raw, err)
				}
			},
		},
		{
			name: "oversize",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte(strings.Repeat("x", maxStateBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			inspect: func(t *testing.T, path string) {
				raw, err := os.ReadFile(path)
				if err != nil || len(raw) != maxStateBytes+1 {
					t.Fatalf("oversize state changed: %d, %v", len(raw), err)
				}
			},
		},
		{
			name: "directory",
			mutate: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			inspect: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				if err != nil || !info.IsDir() {
					t.Fatalf("directory state changed: %#v, %v", info, err)
				}
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "controller-data")
			assertOutcome(t, capture(ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 3, testDigestA)), Result{EvaluationInitialized, 3}, nil)
			path := stateFileForTest(t, root, indexState, testAuthorityA, "repopass", "alpha")
			item.mutate(t, path)
			assertOutcome(t, capture(ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 4, testDigestB)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
			item.inspect(t, path)
		})
	}
}

func TestObserveRejectsStateLinks(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "controller-data")
			assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 3, testDigestA)), Result{EvaluationInitialized, 3}, nil)
			path := stateFileForTest(t, root, policyState, testAuthorityA, "repopass", "alpha")
			switch kind {
			case "hardlink":
				if err := os.Link(path, filepath.Join(filepath.Dir(path), "linked-state.json")); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			case "symlink":
				target := filepath.Join(filepath.Dir(path), "real-state.json")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 4, testDigestB)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
		})
	}
}

func TestDecodeRecordStrictCanonicalContract(t *testing.T) {
	valid := `{"authorityKeyId":"` + testAuthorityA + `","channel":"alpha","digest":"` + testDigestA + `","generation":1,"kind":"policy","product":"repopass","schemaVersion":"1"}`
	cases := []string{
		`{"generation":1,"authorityKeyId":"` + testAuthorityA + `","channel":"alpha","digest":"` + testDigestA + `","kind":"policy","product":"repopass","schemaVersion":"1"}`,
		valid + "\n",
		"\ufeff" + valid,
		strings.Replace(valid, `"generation":1`, `"generation":1.0`, 1),
		strings.Replace(valid, `"schemaVersion":"1"`, `"schemaVersion":"1","extra":true`, 1),
		strings.Replace(valid, `"kind":"policy"`, `"kind":"other"`, 1),
		strings.Replace(valid, `"product":"repopass"`, `"product":"RepoPass"`, 1),
	}
	for _, raw := range cases {
		if _, err := decodeRecord([]byte(raw)); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("decodeRecord(%q) = %v", raw, err)
		}
	}
	if value, err := decodeRecord([]byte(valid)); err != nil || value.Generation != 1 || value.Kind != "policy" {
		t.Fatalf("valid record = %#v, %v", value, err)
	}
}

func TestObserveConcurrentGenerationsConvergeAtMaximum(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	var group sync.WaitGroup
	errorsByGeneration := make(chan error, 24)
	for generation := maxGeneration - 23; generation <= maxGeneration; generation++ {
		generation := generation
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", generation, testDigestA)
			errorsByGeneration <- err
		}()
	}
	group.Wait()
	close(errorsByGeneration)
	for err := range errorsByGeneration {
		if errors.Is(err, ErrUnavailable) {
			t.Fatalf("concurrent observation unavailable: %v", err)
		}
	}
	assertOutcome(t, capture(ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", maxGeneration, testDigestA)), Result{EvaluationMatched, maxGeneration}, nil)
}

func TestObserveConcurrentEqualGenerationEstablishesOneDigest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	type outcome struct {
		result Result
		err    error
	}
	results := make(chan outcome, 2)
	for _, digest := range []string{testDigestA, testDigestB} {
		digest := digest
		go func() {
			result, err := ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 7, digest)
			results <- outcome{result, err}
		}()
	}
	initialized, equivocated := 0, 0
	for range 2 {
		item := <-results
		switch {
		case item.err == nil && item.result == (Result{EvaluationInitialized, 7}):
			initialized++
		case errors.Is(item.err, ErrGenerationEquivocation) && item.result == (Result{EvaluationEquivocationRejected, 7}):
			equivocated++
		default:
			t.Fatalf("unexpected outcome: %#v", item)
		}
	}
	if initialized != 1 || equivocated != 1 {
		t.Fatalf("initialized=%d equivocated=%d", initialized, equivocated)
	}
}

func TestObserveCrossProcessEqualGeneration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	outputs := make(chan helperOutput, 2)
	for _, digest := range []string{testDigestA, testDigestB} {
		digest := digest
		go func() {
			output, err := runHelper("observe", root, digest)
			outputs <- helperOutput{output, err}
		}()
	}
	initialized, equivocated := 0, 0
	for range 2 {
		item := <-outputs
		if item.err != nil {
			t.Fatalf("helper error: %v, %q", item.err, item.output)
		}
		switch {
		case strings.Contains(item.output, "RESULT|initialized|7|nil"):
			initialized++
		case strings.Contains(item.output, "RESULT|equivocation-rejected|7|equivocation"):
			equivocated++
		default:
			t.Fatalf("unexpected helper output: %q", item.output)
		}
	}
	if initialized != 1 || equivocated != 1 {
		t.Fatalf("initialized=%d equivocated=%d", initialized, equivocated)
	}
}

func TestObserveContextAndTimeoutBoundLockContention(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 1, testDigestA)), Result{EvaluationInitialized, 1}, nil)
	command := exec.Command(os.Args[0], "-test.run=^TestReleaseStateProcessHelper$")
	command.Env = append(os.Environ(), "REPOPASS_RELEASESTATE_HELPER=hold-lock", "REPOPASS_RELEASESTATE_ROOT="+root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "LOCKED" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("helper did not acquire lock: %q", scanner.Text())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	assertOutcome(t, capture(ObservePolicy(ctx, root, testAuthorityA, "repopass", "alpha", 2, testDigestB)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
	previous := lockTimeout
	lockTimeout = 50 * time.Millisecond
	assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
	lockTimeout = previous
	if err := command.Wait(); err != nil {
		t.Fatalf("lock helper exit: %v", err)
	}
	assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)), Result{EvaluationAdvanced, 2}, nil)
}

func TestReleaseStateProcessHelper(t *testing.T) {
	mode := os.Getenv("REPOPASS_RELEASESTATE_HELPER")
	if mode == "" {
		return
	}
	root := os.Getenv("REPOPASS_RELEASESTATE_ROOT")
	switch mode {
	case "observe":
		result, err := ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 7, os.Getenv("REPOPASS_RELEASESTATE_DIGEST"))
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
		stateDirectory, err := stateRoot(context.Background(), root, policyState)
		if err != nil {
			os.Exit(2)
		}
		lock, err := openLock(filepath.Join(stateDirectory, stateKey(testAuthorityA, "repopass", "alpha")+".lock"))
		if err != nil {
			os.Exit(3)
		}
		if _, err := acquireLock(context.Background(), lock, lockTimeout); err != nil {
			os.Exit(4)
		}
		fmt.Println("LOCKED")
		time.Sleep(250 * time.Millisecond)
		os.Exit(0)
	default:
		os.Exit(5)
	}
}

type helperOutput struct {
	output string
	err    error
}

func runHelper(mode, root, digest string) (string, error) {
	command := exec.Command(os.Args[0], "-test.run=^TestReleaseStateProcessHelper$")
	command.Env = append(os.Environ(),
		"REPOPASS_RELEASESTATE_HELPER="+mode,
		"REPOPASS_RELEASESTATE_ROOT="+root,
		"REPOPASS_RELEASESTATE_DIGEST="+digest,
		"REPOPASS_RELEASESTATE_GENERATION="+strconv.FormatUint(7, 10),
	)
	output, err := command.CombinedOutput()
	return string(output), err
}

func stateFileForTest(t *testing.T, dataRoot string, kind stateKind, authority, product, channel string) string {
	t.Helper()
	root, err := stateRoot(context.Background(), dataRoot, kind)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, stateKey(authority, product, channel)+".json")
}

type observedOutcome struct {
	result Result
	err    error
}

func capture(result Result, err error) observedOutcome { return observedOutcome{result, err} }

func assertOutcome(t *testing.T, actual observedOutcome, want Result, wantErr error) {
	t.Helper()
	if actual.result != want || (wantErr == nil && actual.err != nil) || (wantErr != nil && !errors.Is(actual.err, wantErr)) {
		t.Fatalf("outcome = %#v, %v; want %#v, %v", actual.result, actual.err, want, wantErr)
	}
}
