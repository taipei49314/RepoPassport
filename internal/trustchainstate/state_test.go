package trustchainstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testRootID    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testTerminalA = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testTerminalB = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testDigestA   = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testDigestB   = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testDigestC   = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func testObservation(chainTerminalGeneration, policyGeneration uint64) Observation {
	return Observation{
		TrustRootKeyID:          testRootID,
		Purpose:                 Purpose,
		PolicyPayloadType:       PolicyPayloadType,
		ChainTerminalGeneration: chainTerminalGeneration,
		ChainDigest:             testDigestA,
		ChainHopCount:           2,
		TerminalAuthorityKeyID:  testTerminalA,
		PolicyGeneration:        policyGeneration,
		PolicyPayloadDigest:     testDigestC,
	}
}

func stateFileForTest(t *testing.T, dataRoot string) string {
	t.Helper()
	root, err := stateRoot(context.Background(), dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, strings.TrimPrefix(testRootID, "sha256:")+".json")
}

func TestObserveInitializesMatchesAndAdvancesChainAndPolicyAxes(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	stateDirectory, err := stateRoot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	wantDirectory := filepath.Join(root, "trust-policy-state", "v1", "rotation-chain")
	if !samePath(stateDirectory, wantDirectory) {
		t.Fatalf("chain state root = %q, want %q", stateDirectory, wantDirectory)
	}

	observe := func(chain, policy uint64) (Result, error) {
		return Observe(context.Background(), root, testObservation(chain, policy))
	}
	for _, want := range []Result{
		{Evaluation: EvaluationInitialized, ChainTerminalGeneration: 1, PolicyGeneration: 1},
		{Evaluation: EvaluationMatched, ChainTerminalGeneration: 1, PolicyGeneration: 1},
		{Evaluation: EvaluationAdvanced, ChainTerminalGeneration: 1, PolicyGeneration: 2},
		{Evaluation: EvaluationAdvanced, ChainTerminalGeneration: 2, PolicyGeneration: 2},
	} {
		result, observeErr := observe(want.ChainTerminalGeneration, want.PolicyGeneration)
		if observeErr != nil || result != want {
			t.Fatalf("Observe(%d, %d) = %#v, %v", want.ChainTerminalGeneration, want.PolicyGeneration, result, observeErr)
		}
	}

	raw, err := canonicalRecord(recordFromObservation(testObservation(2, 2)))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	wantFields := map[string]struct{}{
		"schemaVersion": {}, "trustRootKeyId": {}, "purpose": {}, "policyPayloadType": {},
		"chainTerminalGeneration": {}, "chainDigest": {}, "chainHopCount": {},
		"terminalAuthorityKeyId": {}, "policyGeneration": {}, "policyPayloadDigest": {},
	}
	if len(fields) != len(wantFields) {
		t.Fatalf("state field count = %d, want %d: %s", len(fields), len(wantFields), raw)
	}
	for field := range wantFields {
		if _, ok := fields[field]; !ok {
			t.Fatalf("missing locked state field %q in %s", field, raw)
		}
	}
}

func TestObserveRejectsChainRollbackAndEquivocationWithoutChangingState(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	current := testObservation(5, 7)
	if _, err := Observe(context.Background(), root, current); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		observation Observation
		want        error
		evaluation  Evaluation
	}{
		{"chain rollback", testObservation(4, 8), ErrGenerationRollback, EvaluationRollbackRejected},
		{"policy rollback", testObservation(6, 6), ErrGenerationRollback, EvaluationRollbackRejected},
		{"chain digest equivocation", withObservation(testObservation(5, 8), func(value *Observation) { value.ChainDigest = testDigestB }), ErrAuthorityEquivocation, EvaluationAuthorityEquivocationRejected},
		{"chain hop count equivocation", withObservation(testObservation(5, 8), func(value *Observation) { value.ChainHopCount = 3 }), ErrAuthorityEquivocation, EvaluationAuthorityEquivocationRejected},
		{"terminal authority equivocation", withObservation(testObservation(5, 8), func(value *Observation) { value.TerminalAuthorityKeyID = testTerminalB }), ErrAuthorityEquivocation, EvaluationAuthorityEquivocationRejected},
		{"policy equivocation", withObservation(testObservation(6, 7), func(value *Observation) { value.PolicyPayloadDigest = testDigestA }), ErrPolicyEquivocation, EvaluationPolicyEquivocationRejected},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			result, err := Observe(context.Background(), root, item.observation)
			want := Result{Evaluation: item.evaluation, ChainTerminalGeneration: 5, PolicyGeneration: 7}
			if !errors.Is(err, item.want) || result != want {
				t.Fatalf("Observe = %#v, %v; want %#v and %v", result, err, want, item.want)
			}
			result, err = Observe(context.Background(), root, current)
			if err != nil || result != (Result{Evaluation: EvaluationMatched, ChainTerminalGeneration: 5, PolicyGeneration: 7}) {
				t.Fatalf("rejection changed durable state: %#v, %v", result, err)
			}
		})
	}
}

func TestObserveRejectsInvalidCorruptAndUnsafeChainStateWithoutRepair(t *testing.T) {
	requireHostFilesystem(t)
	t.Run("invalid observation does not create state", func(t *testing.T) {
		cases := []func(*Observation){
			func(value *Observation) { value.TrustRootKeyID = "sha256:not-a-key" },
			func(value *Observation) { value.Purpose = "release-index-transition" },
			func(value *Observation) { value.PolicyPayloadType = "application/json" },
			func(value *Observation) { value.ChainTerminalGeneration = 0 },
			func(value *Observation) { value.ChainTerminalGeneration = maxGeneration + 1 },
			func(value *Observation) { value.ChainDigest = strings.ToUpper(testDigestA) },
			func(value *Observation) { value.ChainHopCount = 1 },
			func(value *Observation) { value.ChainHopCount = 9 },
			func(value *Observation) { value.TerminalAuthorityKeyID = testRootID },
			func(value *Observation) { value.PolicyGeneration = 0 },
			func(value *Observation) { value.PolicyPayloadDigest = "sha512:" + strings.Repeat("a", 64) },
		}
		for _, mutate := range cases {
			root := filepath.Join(t.TempDir(), "not-created")
			observation := testObservation(1, 1)
			mutate(&observation)
			result, err := Observe(context.Background(), root, observation)
			if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
				t.Fatalf("invalid observation = %#v, %v", result, err)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("invalid observation created data root: %v", err)
			}
		}
	})
	t.Run("canonical corruption and non-regular target are untouched", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-data")
		if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
			t.Fatal(err)
		}
		path := stateFileForTest(t, root)
		for _, corrupt := range [][]byte{[]byte(`{"schemaVersion":"1"}`), []byte(strings.Repeat("x", maxStateBytes+1)), []byte("\xef\xbb\xbf{}"), []byte("{}\n")} {
			if err := os.WriteFile(path, corrupt, 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := Observe(context.Background(), root, testObservation(2, 2))
			if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
				t.Fatalf("corrupt state = %#v, %v", result, err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != string(corrupt) {
				t.Fatalf("corrupt state was altered: got %q, err %v", actual, err)
			}
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if result, err := Observe(context.Background(), root, testObservation(2, 2)); !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
			t.Fatalf("non-regular state = %#v, %v", result, err)
		}
	})
	t.Run("repository-local root is rejected", func(t *testing.T) {
		repository := filepath.Join(t.TempDir(), "repository")
		if err := os.Mkdir(repository, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("gitdir: nowhere\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(repository, "controller-data")
		if result, err := Observe(context.Background(), root, testObservation(1, 1)); !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
			t.Fatalf("repository-local root = %#v, %v", result, err)
		}
	})
}

func TestObserveChainStateConcurrencyCancellationAndProcessContention(t *testing.T) {
	requireHostFilesystem(t)
	if testProcessLockHelper(t) {
		return
	}
	t.Run("concurrent advances converge", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-data")
		const maximum = 24
		errorsByGeneration := make(chan error, maximum)
		var group sync.WaitGroup
		for generation := uint64(1); generation <= maximum; generation++ {
			generation := generation
			group.Add(1)
			go func() {
				defer group.Done()
				_, err := Observe(context.Background(), root, testObservation(generation, generation))
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
		result, err := Observe(context.Background(), root, testObservation(maximum, maximum))
		if err != nil || result != (Result{Evaluation: EvaluationMatched, ChainTerminalGeneration: maximum, PolicyGeneration: maximum}) {
			t.Fatalf("terminal concurrent state = %#v, %v", result, err)
		}
	})
	t.Run("cancelled and process contention leave state unchanged", testProcessContention)
}

func TestObserveChainStatePlatformSecurityAndAtomicity(t *testing.T) {
	requireHostFilesystem(t)
	testPlatformSecurityAndAtomicity(t)
}

func withObservation(value Observation, mutate func(*Observation)) Observation {
	mutate(&value)
	return value
}
