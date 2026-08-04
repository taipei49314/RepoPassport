package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCommitDockerEngineDiffTreatsTranscriptAsOpaque(t *testing.T) {
	raw := append(
		[]byte("C /real-name\nA /forged-looking-record\nD /invalid-"),
		0xff,
		0xfe,
		'\n',
	)

	first := commitDockerEngineDiff(raw)
	second := commitDockerEngineDiff(bytes.Clone(raw))
	sum := sha256.Sum256(raw)
	wantDigest := fmt.Sprintf("sha256:%x", sum)

	if first != second {
		t.Fatalf(
			"opaque commitment is not deterministic: first=%#v second=%#v",
			first,
			second,
		)
	}
	if first.Digest != wantDigest ||
		first.ByteCount != len(raw) ||
		!first.NonEmpty {
		t.Fatalf(
			"opaque commitment = %#v, want digest=%q bytes=%d nonempty",
			first,
			wantDigest,
			len(raw),
		)
	}
	if strings.Contains(first.Digest, "/real-name") ||
		strings.Contains(first.Digest, "forged-looking-record") {
		t.Fatalf("commitment exposed transcript content: %#v", first)
	}
}

func TestCommitDockerEngineDiffEmptyAndNonEmpty(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		nonEmpty bool
	}{
		{name: "empty", raw: nil, nonEmpty: false},
		{
			name:     "nonempty",
			raw:      []byte("C /opaque-path\n"),
			nonEmpty: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got := commitDockerEngineDiff(test.raw)
			sum := sha256.Sum256(test.raw)
			wantDigest := fmt.Sprintf("sha256:%x", sum)
			if got.Digest != wantDigest ||
				got.ByteCount != len(test.raw) ||
				got.NonEmpty != test.nonEmpty {
				t.Fatalf(
					"commitment = %#v, want digest=%q bytes=%d nonempty=%v",
					got,
					wantDigest,
					len(test.raw),
					test.nonEmpty,
				)
			}
		})
	}
}

func TestCollectDockerEngineDiffUsesExactFullIDTransport(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	transcript := []byte("C /opaque\n")
	fake := &fakeExecutor{}
	fake.handler = func(
		_ context.Context,
		name string,
		args []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if name != "docker" {
			t.Fatalf("backend executable = %q, want docker", name)
		}
		wantArgs := []string{"container", "diff", containerID}
		if !slices.Equal(args, wantArgs) {
			t.Fatalf("engine diff argv = %#v, want %#v", args, wantArgs)
		}
		_, _ = stdout.Write(transcript)
		return 0, nil
	}

	got, err := testRunner(fake).collectDockerEngineDiff(
		context.Background(),
		&PreparedRun{Backend: "docker"},
		containerID,
	)
	if err != nil {
		t.Fatalf("collectDockerEngineDiff: %v", err)
	}
	want := commitDockerEngineDiff(transcript)
	if got != want {
		t.Fatalf("commitment = %#v, want %#v", got, want)
	}
	if calls := fake.snapshotCalls(); len(calls) != 1 {
		t.Fatalf("engine diff calls = %#v, want exactly one", calls)
	}
}

func TestCollectDockerEngineDiffRejectsUntrustedBindingBeforeExecutor(
	t *testing.T,
) {
	tests := []struct {
		name        string
		prepared    *PreparedRun
		containerID string
	}{
		{
			name:        "nil prepared run",
			prepared:    nil,
			containerID: strings.Repeat("a", 64),
		},
		{
			name:        "unsupported backend",
			prepared:    &PreparedRun{Backend: "podman"},
			containerID: strings.Repeat("b", 64),
		},
		{
			name:        "short container id",
			prepared:    &PreparedRun{Backend: "docker"},
			containerID: "container-name",
		},
		{
			name:        "uppercase container id",
			prepared:    &PreparedRun{Backend: "docker"},
			containerID: strings.Repeat("A", 64),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeExecutor{}
			_, err := testRunner(fake).collectDockerEngineDiff(
				context.Background(),
				test.prepared,
				test.containerID,
			)
			if err == nil {
				t.Fatal("untrusted engine diff binding was accepted")
			}
			if calls := fake.snapshotCalls(); len(calls) != 0 {
				t.Fatalf(
					"untrusted binding reached executor: %#v",
					calls,
				)
			}
		})
	}
}

func TestCollectDockerEngineDiffRejectsDirtyOrIncompleteTransport(
	t *testing.T,
) {
	tests := []struct {
		name    string
		handler func(io.Writer, io.Writer) (int, error)
	}{
		{
			name: "dirty stderr",
			handler: func(stdout, stderr io.Writer) (int, error) {
				_, _ = io.WriteString(stdout, "C /opaque\n")
				_, _ = io.WriteString(stderr, "daemon warning")
				return 0, nil
			},
		},
		{
			name: "nonzero exit",
			handler: func(stdout, _ io.Writer) (int, error) {
				_, _ = io.WriteString(stdout, "C /partial\n")
				return 1, nil
			},
		},
		{
			name: "run error",
			handler: func(_ io.Writer, _ io.Writer) (int, error) {
				return -1, errors.New("transport failed")
			},
		},
		{
			name: "stdout truncation",
			handler: func(stdout, _ io.Writer) (int, error) {
				_, _ = stdout.Write(
					bytes.Repeat(
						[]byte{'x'},
						engineDiffControlLimit+1,
					),
				)
				return 0, nil
			},
		},
		{
			name: "stderr truncation",
			handler: func(_ io.Writer, stderr io.Writer) (int, error) {
				_, _ = stderr.Write(
					bytes.Repeat(
						[]byte{'x'},
						engineDiffControlLimit+1,
					),
				)
				return 0, nil
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeExecutor{}
			fake.handler = func(
				_ context.Context,
				_ string,
				_ []string,
				stdout io.Writer,
				stderr io.Writer,
			) (int, error) {
				return test.handler(stdout, stderr)
			}
			got, err := testRunner(fake).collectDockerEngineDiff(
				context.Background(),
				&PreparedRun{Backend: "docker"},
				strings.Repeat("c", 64),
			)
			if err == nil {
				t.Fatalf(
					"dirty or incomplete transport was accepted: %#v",
					got,
				)
			}
			if got != (engineDiffCommitment{}) {
				t.Fatalf(
					"failed transport returned partial commitment: %#v",
					got,
				)
			}
		})
	}
}

func TestSummarizeDockerEngineDiffTruthTable(t *testing.T) {
	final := commitDockerEngineDiff([]byte("C /private-final-path\n"))
	completedAt := time.Date(
		2026,
		time.July,
		30,
		22,
		48,
		0,
		0,
		time.UTC,
	)
	tests := []struct {
		name           string
		state          engineDiffObservationState
		wantCoverage   string
		wantResult     string
		wantConfidence string
		wantEvent      bool
	}{
		{
			name: "not required",
			state: engineDiffObservationState{
				final:                      final,
				finalReady:                 true,
				finalIdentityVerified:      true,
				workloadQuiescenceVerified: true,
			},
			wantCoverage: coverageUnavailable,
			wantEvent:    false,
		},
		{
			name: "final missing",
			state: engineDiffObservationState{
				required:                   true,
				finalIdentityVerified:      true,
				workloadQuiescenceVerified: true,
			},
			wantCoverage:   coverageUnavailable,
			wantResult:     "unavailable",
			wantConfidence: "unknown",
			wantEvent:      true,
		},
		{
			name: "final identity missing",
			state: engineDiffObservationState{
				required:                   true,
				final:                      final,
				finalReady:                 true,
				workloadQuiescenceVerified: true,
			},
			wantCoverage:   coverageUnavailable,
			wantResult:     "unavailable",
			wantConfidence: "unknown",
			wantEvent:      true,
		},
		{
			name: "workload not quiescent",
			state: engineDiffObservationState{
				required:              true,
				final:                 final,
				finalReady:            true,
				finalIdentityVerified: true,
			},
			wantCoverage:   coverageUnavailable,
			wantResult:     "unavailable",
			wantConfidence: "unknown",
			wantEvent:      true,
		},
		{
			name: "complete final boundary",
			state: engineDiffObservationState{
				required:                   true,
				final:                      final,
				finalReady:                 true,
				finalIdentityVerified:      true,
				workloadQuiescenceVerified: true,
				observedAt:                 completedAt.Add(-time.Second),
			},
			wantCoverage:   coverageBestEffort,
			wantResult:     "observed",
			wantConfidence: "high",
			wantEvent:      true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			event, coverage := summarizeDockerEngineDiff(
				test.state,
				"repopass-test1234",
				completedAt,
			)
			if coverage != test.wantCoverage {
				t.Fatalf(
					"coverage = %q, want %q",
					coverage,
					test.wantCoverage,
				)
			}
			if !test.wantEvent {
				if event.Operation != "" || event.Details != nil {
					t.Fatalf(
						"unrequired observer emitted an event: %#v",
						event,
					)
				}
				return
			}
			if event.Operation != "filesystem.engine-diff.summary" ||
				event.Observer != "docker-container-diff" ||
				event.Coverage != test.wantCoverage ||
				event.Result != test.wantResult ||
				event.Confidence != test.wantConfidence {
				t.Fatalf("summary event = %#v", event)
			}
			if test.wantCoverage == coverageBestEffort {
				if event.Details["finalDigest"] != final.Digest ||
					event.Details["finalByteCount"] != final.ByteCount ||
					event.Details["finalNonEmpty"] != final.NonEmpty {
					t.Fatalf(
						"observed final commitment = %#v",
						event.Details,
					)
				}
			} else {
				for _, forbidden := range []string{
					"finalDigest",
					"finalByteCount",
					"finalNonEmpty",
				} {
					if _, present := event.Details[forbidden]; present {
						t.Fatalf(
							"unavailable summary exposed %q: %#v",
							forbidden,
							event.Details,
						)
					}
				}
			}
		})
	}
}

func TestSummarizeDockerEngineDiffNeverPublishesRawTranscript(t *testing.T) {
	const secretPath = "/source/DO_NOT_PUBLISH_RAW_PATH"
	baselineRaw := []byte("C " + secretPath + "-baseline\n")
	finalRaw := []byte("A " + secretPath + "-final\n")
	state := engineDiffObservationState{
		required:                   true,
		baseline:                   commitDockerEngineDiff(baselineRaw),
		baselineReady:              true,
		baselineIdentityVerified:   true,
		final:                      commitDockerEngineDiff(finalRaw),
		finalReady:                 true,
		finalIdentityVerified:      true,
		workloadQuiescenceVerified: true,
	}

	event, coverage := summarizeDockerEngineDiff(
		state,
		"repopass-test1234",
		time.Date(2026, time.July, 30, 22, 48, 0, 0, time.UTC),
	)
	if coverage != coverageBestEffort ||
		event.Details["opaqueTranscript"] != true ||
		event.Details["transcriptParsed"] != false ||
		event.Details["pathsIncluded"] != false ||
		event.Details["pathClassificationAvailable"] != false {
		t.Fatalf("opaque summary contract = %#v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal summary event: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte(secretPath),
		baselineRaw,
		finalRaw,
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf(
				"public event leaked raw transcript %q: %s",
				forbidden,
				encoded,
			)
		}
	}
}

func TestSummarizeDockerEngineDiffBaselineFailureDoesNotBlockFinal(
	t *testing.T,
) {
	final := commitDockerEngineDiff([]byte("C /opaque-final\n"))
	state := engineDiffObservationState{
		required:                   true,
		baselineFailure:            "baseline-engine-diff-failed",
		final:                      final,
		finalReady:                 true,
		finalIdentityVerified:      true,
		workloadQuiescenceVerified: true,
	}

	event, coverage := summarizeDockerEngineDiff(
		state,
		"repopass-test1234",
		time.Date(2026, time.July, 30, 22, 48, 0, 0, time.UTC),
	)
	if coverage != coverageBestEffort ||
		event.Result != "observed" ||
		event.Details["baselineFailure"] !=
			"baseline-engine-diff-failed" ||
		event.Details["finalDigest"] != final.Digest {
		t.Fatalf("baseline failure blocked final evidence: %#v", event)
	}
	for _, absent := range []string{
		"baselineDigest",
		"baselineByteCount",
		"baselineNonEmpty",
		"transcriptChangedFromBaseline",
	} {
		if _, present := event.Details[absent]; present {
			t.Fatalf(
				"missing baseline exposed %q: %#v",
				absent,
				event.Details,
			)
		}
	}
}

func TestCombineFilesystemWriteCoverage(t *testing.T) {
	tests := []struct {
		name     string
		retained string
		engine   string
		want     string
	}{
		{
			name:     "neither observer",
			retained: coverageUnavailable,
			engine:   coverageUnavailable,
			want:     coverageUnavailable,
		},
		{
			name:     "retained observer only",
			retained: coverageBestEffort,
			engine:   coverageUnavailable,
			want:     coverageBestEffort,
		},
		{
			name:     "engine observer only",
			retained: coverageUnavailable,
			engine:   coverageBestEffort,
			want:     coverageBestEffort,
		},
		{
			name:     "both observers",
			retained: coverageBestEffort,
			engine:   coverageBestEffort,
			want:     coverageBestEffort,
		},
		{
			name:     "narrow high is not composite coverage",
			retained: "high",
			engine:   coverageUnavailable,
			want:     coverageUnavailable,
		},
		{
			name:     "unsupported full values do not escalate",
			retained: coverageFull,
			engine:   coverageFull,
			want:     coverageUnavailable,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if got := combineFilesystemWriteCoverage(
				test.retained,
				test.engine,
			); got != test.want {
				t.Fatalf("coverage = %q, want %q", got, test.want)
			}
		})
	}
}
