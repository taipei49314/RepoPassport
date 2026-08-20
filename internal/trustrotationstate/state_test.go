package trustrotationstate

import (
	"context"
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

func testObservation(transitionGeneration, policyGeneration uint64) Observation {
	return Observation{
		TrustRootKeyID:           testRootID,
		Purpose:                  Purpose,
		PolicyPayloadType:        PolicyPayloadType,
		TransitionGeneration:     transitionGeneration,
		TransitionPayloadDigest:  testDigestA,
		TransitionEnvelopeDigest: testDigestB,
		TerminalAuthorityKeyID:   testTerminalA,
		PolicyGeneration:         policyGeneration,
		PolicyPayloadDigest:      testDigestC,
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

func TestObserveInitializesMatchesAndAdvancesBothAxes(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	observe := func(transition, policy uint64) (Result, error) {
		return Observe(context.Background(), root, testObservation(transition, policy))
	}

	result, err := observe(1, 1)
	if err != nil || result != (Result{Evaluation: EvaluationInitialized, TransitionGeneration: 1, PolicyGeneration: 1}) {
		t.Fatalf("initialize = %#v, %v", result, err)
	}
	result, err = observe(1, 1)
	if err != nil || result != (Result{Evaluation: EvaluationMatched, TransitionGeneration: 1, PolicyGeneration: 1}) {
		t.Fatalf("match = %#v, %v", result, err)
	}
	result, err = observe(1, 2)
	if err != nil || result != (Result{Evaluation: EvaluationAdvanced, TransitionGeneration: 1, PolicyGeneration: 2}) {
		t.Fatalf("policy advance = %#v, %v", result, err)
	}
	result, err = observe(2, 2)
	if err != nil || result != (Result{Evaluation: EvaluationAdvanced, TransitionGeneration: 2, PolicyGeneration: 2}) {
		t.Fatalf("authority advance = %#v, %v", result, err)
	}
}

func TestObserveRejectsRollbackAndEquivocationWithoutChangingState(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	current := testObservation(5, 7)
	if _, err := Observe(context.Background(), root, current); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name           string
		observation    Observation
		want           error
		wantEvaluation Evaluation
	}{
		{"transition rollback", testObservation(4, 8), ErrGenerationRollback, EvaluationRollbackRejected},
		{"policy rollback", testObservation(6, 6), ErrGenerationRollback, EvaluationRollbackRejected},
		{"authority payload equivocation", func() Observation {
			value := testObservation(5, 8)
			value.TransitionPayloadDigest = testDigestB
			return value
		}(), ErrAuthorityEquivocation, EvaluationAuthorityEquivocationRejected},
		{"authority terminal equivocation", func() Observation {
			value := testObservation(5, 8)
			value.TerminalAuthorityKeyID = testTerminalB
			return value
		}(), ErrAuthorityEquivocation, EvaluationAuthorityEquivocationRejected},
		{"policy equivocation", func() Observation {
			value := testObservation(6, 7)
			value.PolicyPayloadDigest = testDigestA
			return value
		}(), ErrPolicyEquivocation, EvaluationPolicyEquivocationRejected},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			result, err := Observe(context.Background(), root, item.observation)
			if !errors.Is(err, item.want) || result != (Result{Evaluation: item.wantEvaluation, TransitionGeneration: 5, PolicyGeneration: 7}) {
				t.Fatalf("Observe = %#v, %v", result, err)
			}
			result, err = Observe(context.Background(), root, current)
			if err != nil || result != (Result{Evaluation: EvaluationMatched, TransitionGeneration: 5, PolicyGeneration: 7}) {
				t.Fatalf("rejection changed durable state: %#v, %v", result, err)
			}
		})
	}
}

func TestObserveTreatsResignedTransitionPayloadAsMatch(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	first := testObservation(3, 4)
	if result, err := Observe(context.Background(), root, first); err != nil || result.Evaluation != EvaluationInitialized {
		t.Fatalf("first Observe = %#v, %v", result, err)
	}
	resigned := first
	resigned.TransitionEnvelopeDigest = testDigestC
	result, err := Observe(context.Background(), root, resigned)
	if err != nil || result != (Result{Evaluation: EvaluationMatched, TransitionGeneration: 3, PolicyGeneration: 4}) {
		t.Fatalf("re-signed transition = %#v, %v", result, err)
	}
	recorded, exists, err := readRecord(stateFileForTest(t, root))
	if err != nil || !exists || recorded.TransitionEnvelopeDigest != first.TransitionEnvelopeDigest {
		t.Fatalf("match rewrote envelope metadata: %#v, exists=%v, err=%v", recorded, exists, err)
	}
}

func TestObserveRejectsInvalidObservationWithoutCreatingState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Observation)
	}{
		{"bad root", func(value *Observation) { value.TrustRootKeyID = "sha256:not-a-key" }},
		{"wrong purpose", func(value *Observation) { value.Purpose = "release-index-transition" }},
		{"wrong policy type", func(value *Observation) { value.PolicyPayloadType = "application/json" }},
		{"zero transition generation", func(value *Observation) { value.TransitionGeneration = 0 }},
		{"large transition generation", func(value *Observation) { value.TransitionGeneration = maxGeneration + 1 }},
		{"bad transition digest", func(value *Observation) { value.TransitionPayloadDigest = strings.ToUpper(testDigestA) }},
		{"bad envelope digest", func(value *Observation) { value.TransitionEnvelopeDigest = "sha256:" + strings.Repeat("0", 63) }},
		{"root equals terminal", func(value *Observation) { value.TerminalAuthorityKeyID = testRootID }},
		{"zero policy generation", func(value *Observation) { value.PolicyGeneration = 0 }},
		{"bad policy digest", func(value *Observation) { value.PolicyPayloadDigest = "sha512:" + strings.Repeat("a", 64) }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "not-created")
			observation := testObservation(1, 1)
			item.mutate(&observation)
			result, err := Observe(context.Background(), root, observation)
			if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
				t.Fatalf("invalid observation = %#v, %v", result, err)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("invalid observation created data root: %v", err)
			}
		})
	}
}

func TestObserveRejectsCorruptionWithoutRepair(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	for _, corrupt := range [][]byte{
		[]byte(`{"schemaVersion":"1"}`),
		[]byte(strings.Repeat("x", maxStateBytes+1)),
		[]byte("\xef\xbb\xbf{}"),
		[]byte("{}\n"),
	} {
		if err := os.WriteFile(path, corrupt, 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := Observe(context.Background(), root, testObservation(2, 2))
		if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
			t.Fatalf("corrupt state = %#v, %v", result, err)
		}
		actual, readErr := os.ReadFile(path)
		if readErr != nil || string(actual) != string(corrupt) {
			t.Fatalf("corrupt state was altered: got %q, err %v", actual, readErr)
		}
	}
}

func TestObserveRejectsNonRegularStateWithoutOverwrite(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := Observe(context.Background(), root, testObservation(2, 2))
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("non-regular state = %#v, %v", result, err)
	}
	if info, statErr := os.Lstat(path); statErr != nil || !info.IsDir() {
		t.Fatalf("non-regular state was overwritten: %#v, %v", info, statErr)
	}
}

func TestObserveCancelledContextLeavesExistingStateUnchanged(t *testing.T) {
	requireHostFilesystem(t)
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := Observe(context.Background(), root, testObservation(1, 1)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(stateFileForTest(t, root))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Observe(ctx, root, testObservation(2, 2))
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("cancelled Observe = %#v, %v", result, err)
	}
	after, readErr := os.ReadFile(stateFileForTest(t, root))
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("cancelled Observe changed state: got %q, err %v", after, readErr)
	}
}

func TestObserveConcurrentAdvancesConvergeAtTwoDimensionalMaximum(t *testing.T) {
	requireHostFilesystem(t)
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
	if err != nil || result != (Result{Evaluation: EvaluationMatched, TransitionGeneration: maximum, PolicyGeneration: maximum}) {
		t.Fatalf("terminal concurrent state = %#v, %v", result, err)
	}
}

func TestDecodeRecordRequiresExactCanonicalContract(t *testing.T) {
	value := recordFromObservation(testObservation(1, 1))
	canonical, err := canonicalRecord(value)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeRecord(canonical); err != nil || decoded != value {
		t.Fatalf("canonical record = %#v, %v", decoded, err)
	}
	for _, raw := range [][]byte{
		append(append([]byte{}, canonical...), '\n'),
		[]byte(strings.Replace(string(canonical), `"transitionGeneration":1`, `"transitionGeneration":1.0`, 1)),
		[]byte(strings.Replace(string(canonical), `"schemaVersion":"1"`, `"schemaVersion":"1","extra":true`, 1)),
		[]byte(strings.Replace(string(canonical), `"policyGeneration":1`, `"policyGeneration":0`, 1)),
	} {
		if _, err := decodeRecord(raw); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("decodeRecord(%q) = %v, want unavailable", raw, err)
		}
	}
}

func TestObserveRejectsRepositoryLocalDataRoot(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("gitdir: nowhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(repository, "controller-data")
	result, err := Observe(context.Background(), root, testObservation(1, 1))
	if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
		t.Fatalf("repository-local root = %#v, %v", result, err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("repository-local state was created: %v", err)
	}
}
