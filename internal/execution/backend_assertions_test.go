package execution

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestDetectBackendsUsesExplicitUnavailableCoverage(t *testing.T) {
	fake := &fakeExecutor{
		handler: func(
			_ context.Context,
			_ string,
			_ []string,
			_ io.Writer,
			_ io.Writer,
		) (int, error) {
			return -1, errors.New("not installed")
		},
	}
	results := testRunner(fake).DetectBackends(context.Background())
	if len(results) != 2 {
		t.Fatalf("backend results = %d, want 2", len(results))
	}
	for _, result := range results {
		if result.Available {
			t.Fatalf("unavailable backend reported available: %#v", result)
		}
		coverage := []string{
			result.NetworkAttemptObservation,
			result.ProcessExecObservation,
			result.FilesystemWriteObservation,
			result.FilesystemReadObservation,
			result.PortObservation,
			result.ResourceUsage,
		}
		for _, value := range coverage {
			if value != "unavailable" {
				t.Fatalf("unavailable backend coverage = %q in %#v", value, result)
			}
		}
	}
}

func TestDoctorSeparatesWindowsControllerFromLinuxWorkloadWireCoverage(t *testing.T) {
	features, err := testRunner(dockerDoctorFake()).Doctor(context.Background(), "docker")
	if err != nil {
		t.Fatalf("Doctor returned error: %v", err)
	}
	if features.WorkloadOS != "linux" ||
		features.ProcessExecObservation != "best-effort" ||
		features.FilesystemWriteObservation != "unavailable" ||
		features.ResourceUsage != "unavailable" ||
		features.ResourceLimitEnforcement {
		t.Fatalf("unexpected truthful feature report: %#v", features)
	}
}

func TestParseDockerBackendInfoUsesOnlyValidSecurityOptionsForRootless(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "rootful options",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"]}`,
			want: "no",
		},
		{
			name: "empty valid options",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":[]}`,
			want: "no",
		},
		{
			name: "formal rootless option",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":["name=seccomp,profile=builtin","name=rootless"]}`,
			want: "yes",
		},
		{
			name: "rootless substring is not evidence",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":["name=not-rootless"]}`,
			want: "no",
		},
		{
			name: "missing options",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","hostile":{"rootless":false}}`,
			want: "unknown",
		},
		{
			name: "null options",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":null}`,
			want: "unknown",
		},
		{
			name: "wrong options type",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":"name=rootless","hostile":{"rootless":true}}`,
			want: "unknown",
		},
		{
			name: "non-string option",
			raw:  `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":["name=rootless",false]}`,
			want: "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := parseBackendInfo("docker", []byte(test.raw))
			if err != nil {
				t.Fatalf("parseBackendInfo returned error: %v", err)
			}
			if info.rootless != test.want {
				t.Fatalf("rootless = %q, want %q", info.rootless, test.want)
			}
		})
	}
}

func TestParsePodmanBackendInfoStillRequiresBooleanRootlessEvidence(t *testing.T) {
	info, err := parseBackendInfo(
		"podman",
		[]byte(`{"host":{"os":"linux","security":{}},"version":{"Version":"5.0.0"}}`),
	)
	if err != nil {
		t.Fatalf("parseBackendInfo returned error: %v", err)
	}
	if info.rootless != "unknown" {
		t.Fatalf("rootless = %q, want unknown", info.rootless)
	}
}

func TestDoctorReportsRootfulDockerFromValidSecurityOptions(t *testing.T) {
	fake := &fakeExecutor{
		handler: func(
			_ context.Context,
			_ string,
			_ []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			_, _ = io.WriteString(
				stdout,
				`{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"]}`,
			)
			return 0, nil
		},
	}
	features, err := testRunner(fake).Doctor(context.Background(), "docker")
	if err != nil {
		t.Fatalf("Doctor returned error: %v", err)
	}
	if !features.Available || features.Rootless != "no" {
		t.Fatalf("rootful Docker feature report = %#v", features)
	}
}

func TestNegotiateFeaturesRecognizesPinnedLinuxPlatforms(t *testing.T) {
	features := domain.RunnerFeatures{
		Available:  true,
		WorkloadOS: "linux",
	}
	for _, platform := range []string{
		"platform:linux/amd64",
		"platform:linux/arm64",
	} {
		t.Run(platform, func(t *testing.T) {
			if _, err := NegotiateFeatures([]string{platform}, features); err != nil {
				t.Fatalf("NegotiateFeatures(%q): %v", platform, err)
			}
		})
	}

	_, err := NegotiateFeatures(
		[]string{"platform:linux/s390x"},
		features,
	)
	if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf(
			"unsupported platform error code = %q, want %q: %v",
			got,
			domain.CodeRunnerFeatureUnavailable,
			err,
		)
	}
}

func TestNegotiateResourceObservationAcceptsHighButNotBestEffort(
	t *testing.T,
) {
	for _, feature := range []string{
		"resource-usage-observation",
		"observer:resource-usage",
	} {
		high, err := NegotiateFeatures(
			[]string{feature},
			domain.RunnerFeatures{ResourceUsage: "high"},
		)
		if err != nil || len(high.Incomplete) != 0 {
			t.Fatalf(
				"high resource coverage feature=%q result=%#v err=%v",
				feature,
				high,
				err,
			)
		}
		bestEffort, err := NegotiateFeatures(
			[]string{feature},
			domain.RunnerFeatures{ResourceUsage: "best-effort"},
		)
		if err != nil ||
			len(bestEffort.Incomplete) != 1 ||
			bestEffort.Incomplete[0] != feature {
			t.Fatalf(
				"best-effort feature=%q result=%#v err=%v",
				feature,
				bestEffort,
				err,
			)
		}
	}
}

func TestNegotiateFilesystemObservationAcceptsHighButNotBestEffort(
	t *testing.T,
) {
	for _, feature := range []string{
		"filesystem-write-observation",
		"observer:filesystem-write",
	} {
		high, err := NegotiateFeatures(
			[]string{feature},
			domain.RunnerFeatures{
				FilesystemWriteObservation: "high",
			},
		)
		if err != nil || len(high.Incomplete) != 0 {
			t.Fatalf(
				"high filesystem coverage feature=%q result=%#v err=%v",
				feature,
				high,
				err,
			)
		}
		bestEffort, err := NegotiateFeatures(
			[]string{feature},
			domain.RunnerFeatures{
				FilesystemWriteObservation: "best-effort",
			},
		)
		if err != nil ||
			len(bestEffort.Incomplete) != 1 ||
			bestEffort.Incomplete[0] != feature {
			t.Fatalf(
				"best-effort feature=%q result=%#v err=%v",
				feature,
				bestEffort,
				err,
			)
		}
	}
}

func TestLogCaptureUsesOneBoundedBudgetAcrossStreams(t *testing.T) {
	capture := newLogCapture(8)
	if _, err := io.WriteString(capture.stdout, "stdout"); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if _, err := io.WriteString(capture.stderr, "stderr"); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	if got := len(capture.stdout.Bytes()) + len(capture.stderr.Bytes()); got != 8 {
		t.Fatalf("captured bytes = %d, want 8", got)
	}
	if got := capture.budget.Total(); got != 12 {
		t.Fatalf("observed log bytes = %d, want 12", got)
	}
	if !capture.budget.Truncated() {
		t.Fatal("capture did not record truncation")
	}
}

func TestFileExistsAssertionRejectsIntermediateSymlink(t *testing.T) {
	outputs := t.TempDir()
	external := t.TempDir()
	mustWriteFile(t, filepath.Join(external, "secret.txt"), []byte("secret"))
	if err := os.Symlink(external, filepath.Join(outputs, "link")); err != nil {
		t.Skipf("symlink creation is unavailable on this platform: %v", err)
	}
	prepared := sealPreparedRunForTest(&PreparedRun{
		RunID:             "test1234",
		OutputsDir:        outputs,
		WorkspaceDir:      t.TempDir(),
		SourceSnapshotDir: t.TempDir(),
		Plan: domain.ResolvedPlan{
			JourneyAssertions: []domain.PlanAssertion{{
				ID:         "result-created",
				FileExists: "/outputs/link/secret.txt",
			}},
		},
	})
	results := evaluateJourneyAssertions(prepared, []StepResult{{
		ID:       "journey",
		Role:     "journey",
		ExitCode: 0,
	}})
	if len(results) != 1 || results[0].Status != "inconclusive" {
		t.Fatalf("symlink assertion result = %#v, want inconclusive", results)
	}
	if actual, ok := results[0].Actual.(bool); !ok || actual {
		t.Fatalf("symlink assertion actual = %#v, want false", results[0].Actual)
	}
}
