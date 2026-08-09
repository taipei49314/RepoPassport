package execution

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/runtimepolicy"
)

func TestPrepareRejectsUnapprovedRuntimeTupleBeforeBackend(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	plan.BaseImageReference = "docker.io/library/node:22.23.1-bookworm-slim@sha256:" +
		strings.Repeat("f", 64)
	plan.BaseImageDigest = "sha256:" + strings.Repeat("f", 64)
	fake := &fakeExecutor{}

	_, err := testRunner(fake).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got !=
		domain.CodeRunnerFeatureUnavailable {
		t.Fatalf("Prepare error code = %q: %v", got, err)
	}
	if len(fake.snapshotCalls()) != 0 {
		t.Fatalf("backend contacted for unapproved runtime: %#v", fake.snapshotCalls())
	}
}

func TestPrepareRejectsDiskAboveControllerCeilingBeforeBackend(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	runner := testRunner(&fakeExecutor{})
	plan.Resources.DiskBytes = runner.config.MaxDiskBytes + 1

	_, err := runner.Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got !=
		domain.CodeResourceLimitExceeded {
		t.Fatalf("Prepare error code = %q: %v", got, err)
	}
}

func TestRunRejectsUnsealedPreparedRunBeforeBackend(t *testing.T) {
	fake := &fakeExecutor{}
	_, err := testRunner(fake).Run(
		context.Background(),
		&PreparedRun{
			Plan: domain.ResolvedPlan{
				RuntimeAdapter:     "node",
				BaseImageReference: "mutated.invalid/image:latest",
			},
			Runner: domain.RunnerFeatures{
				Available:  true,
				WorkloadOS: "linux",
			},
			Backend: "docker",
			RunID:   "attacker123",
		},
	)
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanUnresolved {
		t.Fatalf(
			"Run unsealed error code = %q, want %q: %v",
			got,
			domain.CodePlanUnresolved,
			err,
		)
	}
	if len(fake.snapshotCalls()) != 0 {
		t.Fatalf("unsealed run reached backend: %#v", fake.snapshotCalls())
	}
}

func TestWorkloadIdentityProbeRejectsAnyPrivilegeInvariantDrift(t *testing.T) {
	valid := `{"uid":65532,"euid":65532,"gid":65532,"egid":65532,` +
		`"capInh":"0000","capPrm":"0000","capEff":"0000","capAmb":"0000",` +
		`"noNewPrivs":1}`
	tests := []struct {
		name string
		json string
	}{
		{"uid", strings.Replace(valid, `"uid":65532`, `"uid":0`, 1)},
		{"euid", strings.Replace(valid, `"euid":65532`, `"euid":0`, 1)},
		{"gid", strings.Replace(valid, `"gid":65532`, `"gid":0`, 1)},
		{"egid", strings.Replace(valid, `"egid":65532`, `"egid":0`, 1)},
		{"CapInh", strings.Replace(valid, `"capInh":"0000"`, `"capInh":"0001"`, 1)},
		{"CapPrm", strings.Replace(valid, `"capPrm":"0000"`, `"capPrm":"0001"`, 1)},
		{"CapEff", strings.Replace(valid, `"capEff":"0000"`, `"capEff":"0001"`, 1)},
		{"CapAmb", strings.Replace(valid, `"capAmb":"0000"`, `"capAmb":"0001"`, 1)},
		{"NoNewPrivs", strings.Replace(valid, `"noNewPrivs":1`, `"noNewPrivs":0`, 1)},
		{"unknown field", strings.TrimSuffix(valid, "}") + `,"extra":true}`},
		{"malformed", `{`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeExecutor{}
			fake.handler = func(
				_ context.Context,
				_ string,
				_ []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				_, _ = io.WriteString(stdout, test.json+"\n")
				return 0, nil
			}
			prepared := sealPreparedRunForTest(&PreparedRun{
				Plan:    domain.ResolvedPlan{RuntimeAdapter: "node"},
				Backend: "docker",
			})
			_, probeErr := testRunner(fake).verifyWorkloadIdentity(
				context.Background(),
				prepared,
				"repopass-test1234",
			)
			if got := domain.ErrorCodeOf(probeErr); got !=
				domain.CodeRunnerFeatureUnavailable {
				t.Fatalf("probe error code = %q: %v", got, probeErr)
			}
		})
	}
}

func TestRunFailsClosedOnPrivilegedIdentityBeforeWorkloadOrExport(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	workloadCalled := false
	tarCalled := false
	removed := false
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		workloadCalled = true
		return 0, nil
	})
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if args[0] == "exec" &&
			containsArgument(args, nodeWorkloadIdentityScript) {
			_, _ = io.WriteString(
				stdout,
				`{"uid":65532,"euid":65532,"gid":65532,"egid":65532,`+
					`"capInh":"0000","capPrm":"0001","capEff":"0000",`+
					`"capAmb":"0000","noNewPrivs":1}`+"\n",
			)
			return 0, nil
		}
		if isTarExportArgs(args) {
			tarCalled = true
		}
		if args[0] == "rm" {
			removed = true
		}
		return base(ctx, name, args, stdout, stderr)
	}

	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got !=
		domain.CodeRunnerFeatureUnavailable {
		t.Fatalf("Execute error code = %q: %v", got, err)
	}
	if workloadCalled || tarCalled || !removed || len(outcome.Steps) != 0 {
		t.Fatalf(
			"privileged identity workload=%v tar=%v removed=%v steps=%#v",
			workloadCalled,
			tarCalled,
			removed,
			outcome.Steps,
		)
	}
	entries, readErr := os.ReadDir(outcome.OutputsDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("privileged identity committed output: %v %#v", readErr, entries)
	}
}

func TestRuntimeVersionProbeRejectsMismatchAndUnreadableOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"mismatch", "v22.23.2\n"},
		{"unreadable", "node version unknown\n"},
		{"multiline", "v22.23.1\nspoof\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeExecutor{}
			fake.handler = func(
				_ context.Context,
				_ string,
				_ []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				_, _ = io.WriteString(stdout, test.output)
				return 0, nil
			}
			prepared := sealPreparedRunForTest(&PreparedRun{
				Plan: domain.ResolvedPlan{
					RuntimeAdapter: "node",
					RuntimeVersion: runtimepolicy.NodeVersion,
				},
				Backend: "docker",
			})
			_, probeErr := testRunner(fake).verifyRuntimeVersion(
				context.Background(),
				prepared,
				"repopass-test1234",
			)
			if got := domain.ErrorCodeOf(probeErr); got !=
				domain.CodeRuntimeVersionUnresolved {
				t.Fatalf("probe error code = %q: %v", got, probeErr)
			}
		})
	}
}

func TestExecuteRejectsDeclared125EvenWithRunningContainer(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	expected := 125
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:       "declared-125",
		ExitCode: &expected,
	}}
	fake := &fakeExecutor{}
	fake.handler = successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		return 125, errors.New("exit status 125")
	})

	_, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got != domain.CodeSandboxStartFailed {
		t.Fatalf("Execute error code = %q: %v", got, err)
	}
	findCall(t, fake.snapshotCalls(), "inspect")
}

func TestExecuteTreats125AsOperationalWhenContainerStopped(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		return 125, errors.New("synthetic engine exec failure")
	})
	tarCalled := false
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if args[0] == "inspect" {
			_, _ = io.WriteString(stdout, "false\n")
			return 0, nil
		}
		if isTarExportArgs(args) {
			tarCalled = true
		}
		return base(ctx, name, args, stdout, stderr)
	}

	_, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got != domain.CodeSandboxStartFailed {
		t.Fatalf("Execute error code = %q: %v", got, err)
	}
	if tarCalled {
		t.Fatal("operational exec failure was exported as a quiescent workload result")
	}
}

func TestExecutePersistsOutputsAcrossSequentialExecs(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	plan.Commands = []domain.PlanCommand{
		{
			Phase:   domain.PhaseSetup,
			ID:      "write",
			Argv:    []string{"node", "/workspace/app.js", "write"},
			Timeout: "10s",
			Role:    "foreground",
		},
		{
			Phase:   domain.PhaseExercise,
			ID:      "read",
			Argv:    []string{"node", "/workspace/app.js", "read"},
			Timeout: "10s",
			Role:    "journey",
		},
	}
	plan.JourneyAssertions = []domain.PlanAssertion{
		{ID: "persisted-log", StdoutContains: "persisted"},
		{ID: "persisted-file", FileExists: "/outputs/state.txt"},
	}
	workloadCalls := 0
	persisted := false
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		workloadCalls++
		switch workloadCalls {
		case 1:
			persisted = true
			return 0, nil
		case 2:
			if !persisted {
				return -1, errors.New("long-lived output state was lost")
			}
			_, _ = io.WriteString(stdout, "persisted\n")
			return 0, nil
		default:
			return -1, errors.New("unexpected workload exec")
		}
	})
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if isTarExportArgs(args) {
			if !persisted {
				return -1, errors.New("output state disappeared before export")
			}
			return writeFixtureTar(stdout, map[string][]byte{
				"state.txt": []byte("persisted\n"),
			})
		}
		return base(ctx, name, args, stdout, stderr)
	}

	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if err != nil {
		t.Fatalf("Execute multi-step: %v", err)
	}
	if workloadCalls != 2 || len(outcome.Steps) != 2 ||
		outcome.Steps[0].ContainerName != outcome.Steps[1].ContainerName {
		t.Fatalf("multi-step outcome = %#v workloadCalls=%d", outcome.Steps, workloadCalls)
	}
	createCount := 0
	for _, call := range fake.snapshotCalls() {
		if len(call.args) > 0 && call.args[0] == "create" {
			createCount++
		}
	}
	if createCount != 1 {
		t.Fatalf("container create count = %d, want 1", createCount)
	}
	for _, assertion := range outcome.Assertions {
		if assertion.Status != "passed" {
			t.Fatalf("multi-step assertion = %#v", assertion)
		}
	}
	if contents, readErr := os.ReadFile(filepath.Join(outcome.OutputsDir, "state.txt")); readErr != nil ||
		string(contents) != "persisted\n" {
		t.Fatalf("persisted output = %q, err %v", contents, readErr)
	}
}

func TestDiskOverflowFailsWithoutOutputLeakage(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	plan.Resources.DiskBytes = 1024
	fake := &fakeExecutor{}
	fake.handler = successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		stderr io.Writer,
	) (int, error) {
		_, _ = io.WriteString(stderr, "ENOSPC: no space left on device\n")
		return 1, errors.New("exit status 1")
	})

	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got !=
		domain.CodeJourneyAssertionFailed {
		t.Fatalf("Execute error code = %q: %v", got, err)
	}
	create := findCall(t, fake.snapshotCalls(), "create")
	if !containsAdjacent(
		create.args,
		"--tmpfs",
		"/outputs:rw,nosuid,nodev,noexec,size=1024,mode=0777",
	) {
		t.Fatalf("disk cap not materialized: %v", create.args)
	}
	entries, readErr := os.ReadDir(outcome.OutputsDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("overflow leaked output: %v %#v", readErr, entries)
	}
}
