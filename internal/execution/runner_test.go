package execution

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/controllerfs"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/runtimepolicy"
	"github.com/taipei49314/RepoPassport/internal/verification"
)

type commandCall struct {
	name string
	args []string
}

type fakeExecutor struct {
	mu      sync.Mutex
	calls   []commandCall
	handler func(context.Context, string, []string, io.Writer, io.Writer) (int, error)
}

func (f *fakeExecutor) Run(
	ctx context.Context,
	name string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, commandCall{name: name, args: cloneStrings(args)})
	f.mu.Unlock()
	if f.handler == nil {
		return 0, nil
	}
	return f.handler(ctx, name, args, stdout, stderr)
}

func (f *fakeExecutor) snapshotCalls() []commandCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]commandCall, len(f.calls))
	copy(result, f.calls)
	return result
}

func TestExecuteUsesExactContainerHardeningAndTrustedAssertions(t *testing.T) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("console.log('ok')\n"))
	mustWriteFile(t, filepath.Join(sourceRoot, "fixtures", "message.txt"), []byte("hello\n"))

	plan := testPlan(t, sourceRoot)
	plan.Inputs = []domain.PlanInput{{
		Name:      "message",
		Type:      "file",
		Fixture:   "fixtures/message.txt",
		MountPath: "/inputs/message.txt",
		ReadOnly:  true,
	}}
	zero := 0
	plan.JourneyAssertions = []domain.PlanAssertion{
		{ID: "process-exited", ExitCode: &zero},
		{ID: "process-reported", StdoutContains: "processed"},
	}

	fake := &fakeExecutor{}
	fake.handler = successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		args []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		_, _ = io.WriteString(stdout, "processed\n")
		return 0, nil
	})
	runner := testRunner(fake)
	outcome, err := runner.Execute(context.Background(), plan, sourceRoot, runRoot, "docker")
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if len(outcome.Assertions) != 2 {
		t.Fatalf("assertions = %d, want 2", len(outcome.Assertions))
	}
	for _, assertion := range outcome.Assertions {
		if assertion.SchemaVersion != "1" ||
			!assertion.Required ||
			assertion.Status != "passed" ||
			len(assertion.EvidenceRefs) == 0 {
			t.Fatalf("invalid trusted assertion wire result: %#v", assertion)
		}
	}
	if outcome.Assertions[0].Type != "exit-code" {
		t.Fatalf("assertion type = %q, want exit-code", outcome.Assertions[0].Type)
	}

	create := findCall(t, fake.snapshotCalls(), "create")
	requiredPairs := [][2]string{
		{"--platform", "linux/amd64"},
		{"--network", "none"},
		{"--ipc", "none"},
		{"--cgroupns", "private"},
		{"--user", "0:0"},
		{"--cap-drop", "ALL"},
		{"--cap-add", "DAC_OVERRIDE"},
		{"--cap-add", "FOWNER"},
		{"--cap-add", "KILL"},
		{"--security-opt", "no-new-privileges=true"},
		{"--pids-limit", "64"},
		{"--memory", "268435456"},
		{"--memory-swap", "268435456"},
		{"--cpus", "1"},
		{"--workdir", trustedHelperWorkdir},
		{"--pull=never", "--entrypoint"},
	}
	for _, pair := range requiredPairs {
		if !containsAdjacent(create.args, pair[0], pair[1]) {
			t.Errorf("create args missing adjacent %q %q: %v", pair[0], pair[1], create.args)
		}
	}
	if !containsArgument(create.args, "--read-only") {
		t.Errorf("create args missing --read-only: %v", create.args)
	}
	if containsArgument(create.args, "--privileged") ||
		containsArgument(create.args, "--device") ||
		containsSubstring(create.args, "relabel=") ||
		containsSubstring(create.args, "docker.sock") ||
		containsSubstring(create.args, "podman.sock") {
		t.Fatalf("unsafe container flag or mount found: %v", create.args)
	}
	if containsSubstring(create.args, sourceRoot) {
		t.Fatalf("live source root was mounted instead of copied snapshot: %v", create.args)
	}

	mounts := flagValues(create.args, "--mount")
	assertMount(t, mounts, "/source", true)
	assertMount(t, mounts, "/workspace", true)
	assertMount(t, mounts, "/inputs/message.txt", true)
	if containsSubstring(mounts, "dst=/outputs") {
		t.Fatalf("/outputs is host-mounted instead of engine tmpfs: %v", mounts)
	}
	tmpfs := flagValues(create.args, "--tmpfs")
	if len(tmpfs) != 1 ||
		tmpfs[0] != "/outputs:rw,nosuid,nodev,noexec,size=1073741824,mode=0777" {
		t.Fatalf("create tmpfs = %v, want one bounded /outputs tmpfs", tmpfs)
	}

	workloadExec := findWorkloadExec(t, fake.snapshotCalls())
	if !containsAdjacent(workloadExec.args, "--user", containerUser) ||
		!containsAdjacent(workloadExec.args, "--workdir", containerWorkspace) {
		t.Fatalf("workload exec lost nonroot identity/workdir: %v", workloadExec.args)
	}

	remove := findCall(t, fake.snapshotCalls(), "rm")
	if len(remove.args) != 3 || remove.args[1] != "-f" {
		t.Fatalf("cleanup command = %v, want rm -f <container>", remove.args)
	}
	if outcome.Runner.ControllerOS != runtime.GOOS ||
		outcome.Runner.WorkloadOS != "linux" {
		t.Fatalf("controller/workload platforms were not separated: %#v", outcome.Runner)
	}
}

func TestSupplementalRetainedStateFailureDoesNotAbortWorkload(t *testing.T) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("console.log('ok')\n"),
	)
	plan := testPlan(t, sourceRoot)
	plan.ObserverSet = []string{"filesystem-write"}
	plan.ObserverVersions = map[string]string{"filesystem-write": "0.4.0"}
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"observer:filesystem-write",
	)
	zero := 0
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:       "journey-exit",
		ExitCode: &zero,
	}}

	workloadRan := false
	fake := &fakeExecutor{}
	fake.handler = successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		workloadRan = true
		return 0, nil
	})
	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if err != nil {
		t.Fatalf(
			"supplemental retained-state failure aborted execution: %v",
			err,
		)
	}
	if !workloadRan {
		t.Fatal("workload did not run after retained-state baseline failure")
	}
	if outcome.Runner.FilesystemWriteObservation != coverageUnavailable {
		t.Fatalf(
			"filesystem write coverage = %q, want unavailable",
			outcome.Runner.FilesystemWriteObservation,
		)
	}
	if !slices.Contains(
		outcome.IncompleteFeatures,
		"observer:filesystem-write",
	) {
		t.Fatalf(
			"required filesystem observer was incorrectly completed: %#v",
			outcome.IncompleteFeatures,
		)
	}
	if len(outcome.Errors) != 0 {
		t.Fatalf(
			"supplemental observer failure became a run finding: %#v",
			outcome.Errors,
		)
	}
	if len(outcome.Assertions) != 1 ||
		outcome.Assertions[0].Status != "passed" ||
		outcome.Cleanup != domain.CleanupClean {
		t.Fatalf("workload outcome was degraded: %#v", outcome)
	}
	foundSummary := false
	for _, observation := range outcome.Observations {
		if observation.Operation !=
			"filesystem.retained-state.summary" {
			continue
		}
		foundSummary = true
		if observation.Result != "unavailable" ||
			observation.Coverage != coverageUnavailable ||
			observation.Details["failure"] !=
				"baseline-snapshot-failed" {
			t.Fatalf(
				"retained-state failure summary = %#v",
				observation,
			)
		}
	}
	if !foundSummary {
		t.Fatal("retained-state failure summary is absent")
	}
}

func TestExecutePublishesBothFilesystemSummariesWithoutCompletingRequiredObserver(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("console.log('ok')\n"),
	)
	plan := testPlan(t, sourceRoot)
	plan.ObserverSet = []string{"filesystem-write"}
	plan.ObserverVersions = map[string]string{"filesystem-write": "0.4.0"}
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"observer:filesystem-write",
	)
	zero := 0
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:       "journey-exit",
		ExitCode: &zero,
	}}

	var order []string
	diffCalls := 0
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		order = append(order, "workload")
		_, _ = io.WriteString(stdout, "ok\n")
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
		if len(args) >= 3 &&
			args[0] == "container" &&
			args[1] == "diff" {
			diffCalls++
			order = append(order, "engine-diff")
			if len(args) != 3 ||
				!fullContainerIDPattern.MatchString(args[2]) {
				t.Fatalf("unsafe engine diff argv: %#v", args)
			}
			_, _ = io.WriteString(stdout, "C /opaque-engine-state\n")
			return 0, nil
		}
		if len(args) > 0 && args[0] == "exec" &&
			containsArgument(args, nodeFilesystemSnapshotScript) {
			_, _ = io.WriteString(
				stdout,
				"{\"ok\":true,\"entries\":[]}\n",
			)
			return 0, nil
		}
		return base(ctx, name, args, stdout, stderr)
	}

	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if diffCalls != 2 ||
		!slices.Equal(
			order,
			[]string{"engine-diff", "workload", "engine-diff"},
		) {
		t.Fatalf(
			"engine diff lifecycle order = %#v; calls=%d",
			order,
			diffCalls,
		)
	}
	if outcome.Runner.FilesystemWriteObservation !=
		coverageBestEffort {
		t.Fatalf(
			"composite filesystem coverage = %q",
			outcome.Runner.FilesystemWriteObservation,
		)
	}
	if !slices.Contains(
		outcome.IncompleteFeatures,
		"observer:filesystem-write",
	) {
		t.Fatalf(
			"required filesystem observer was completed: %#v",
			outcome.IncompleteFeatures,
		)
	}
	foundRetained := false
	foundEngineDiff := false
	for _, observation := range outcome.Observations {
		switch observation.Operation {
		case "filesystem.retained-state.summary":
			foundRetained = observation.Coverage == "high"
		case "filesystem.engine-diff.summary":
			foundEngineDiff =
				observation.Coverage == coverageBestEffort &&
					observation.Details["transcriptChangedFromBaseline"] == false
		}
	}
	if !foundRetained || !foundEngineDiff {
		t.Fatalf(
			"filesystem summaries are incomplete: retained=%v engine=%v",
			foundRetained,
			foundEngineDiff,
		)
	}
}

func TestBindMountUsesPodmanPrivateSELinuxRelabelOnly(t *testing.T) {
	dockerReadOnly := bindMount("docker", "/host/source", "/source", true)
	if strings.Contains(dockerReadOnly, "relabel=") {
		t.Fatalf("Docker mount contains Podman-only relabel option: %q", dockerReadOnly)
	}
	if !strings.Contains(dockerReadOnly, ",readonly") {
		t.Fatalf("Docker source mount lost read-only state: %q", dockerReadOnly)
	}

	podmanReadOnly := bindMount("podman", "/host/source", "/source", true)
	if !strings.Contains(podmanReadOnly, ",readonly") ||
		!strings.Contains(podmanReadOnly, ",relabel=private") {
		t.Fatalf("Podman source mount lacks read-only private relabel: %q", podmanReadOnly)
	}

	podmanWritable := bindMount("PODMAN", "/host/output", "/outputs", false)
	if strings.Contains(podmanWritable, ",readonly") ||
		!strings.Contains(podmanWritable, ",relabel=private") {
		t.Fatalf("Podman writable mount options are incorrect: %q", podmanWritable)
	}
}

func TestLongLivedCreateArgsMaterializeArm64Platform(t *testing.T) {
	runner := testRunner(&fakeExecutor{})
	plan := domain.ResolvedPlan{
		RuntimeAdapter:     "node",
		BaseImageReference: "example.invalid/runtime@sha256:" + strings.Repeat("a", 64),
		Resources: domain.ResourceLimits{
			CPUMillis:   1000,
			MemoryBytes: 256 << 20,
			DiskBytes:   1 << 20,
			PIDs:        64,
		},
	}
	prepared := sealPreparedRunForTest(&PreparedRun{
		Plan:              plan,
		Backend:           "docker",
		Platform:          "linux/arm64",
		RunID:             "test1234",
		SourceSnapshotDir: t.TempDir(),
		WorkspaceDir:      t.TempDir(),
		OutputsDir:        t.TempDir(),
	})
	workloadArgs := runner.buildCreateArgs(
		prepared,
		"repopass-test1234",
	)
	if !containsAdjacent(workloadArgs, "--platform", "linux/arm64") {
		t.Fatalf("workload create omitted arm64 platform: %v", workloadArgs)
	}
	if !containsAdjacent(workloadArgs, "--user", "0:0") ||
		!containsAdjacent(workloadArgs, "--cap-add", "DAC_OVERRIDE") ||
		!containsAdjacent(workloadArgs, "--cap-add", "FOWNER") {
		t.Fatalf("long-lived container lacks restricted repair identity: %v", workloadArgs)
	}
}

func TestLongLivedCreateArgsUseBackendSpecificNoSwapControls(t *testing.T) {
	t.Parallel()
	runner := testRunner(&fakeExecutor{})
	plan := domain.ResolvedPlan{
		RuntimeAdapter:     "node",
		BaseImageReference: "example.invalid/runtime@sha256:" + strings.Repeat("a", 64),
		Resources: domain.ResourceLimits{
			CPUMillis:   1000,
			MemoryBytes: 256 << 20,
			DiskBytes:   1 << 20,
			PIDs:        64,
		},
	}

	createArgs := func(backend string) []string {
		prepared := sealPreparedRunForTest(&PreparedRun{
			Plan:              plan,
			Backend:           backend,
			Platform:          "linux/amd64",
			RunID:             "test1234",
			SourceSnapshotDir: t.TempDir(),
			WorkspaceDir:      t.TempDir(),
			OutputsDir:        t.TempDir(),
		})
		return runner.buildCreateArgs(prepared, "repopass-test1234")
	}

	dockerArgs := createArgs("docker")
	if !containsAdjacent(dockerArgs, "--memory", "268435456") ||
		!containsAdjacent(dockerArgs, "--memory-swap", "268435456") {
		t.Fatalf("Docker create lost exact no-swap controls: %v", dockerArgs)
	}
	if containsArgument(dockerArgs, "--cgroup-conf") ||
		containsArgument(dockerArgs, "memory.swap.max=0") ||
		containsArgument(dockerArgs, "--read-only-tmpfs=false") {
		t.Fatalf("Docker create contains Podman-only cgroup control: %v", dockerArgs)
	}

	podmanArgs := createArgs("podman")
	if !containsAdjacent(podmanArgs, "--memory", "268435456") ||
		!containsAdjacent(podmanArgs, "--cgroup-conf", "memory.swap.max=0") {
		t.Fatalf("Podman create lacks exact cgroup-v2 no-swap controls: %v", podmanArgs)
	}
	if containsArgument(podmanArgs, "--memory-swap") {
		t.Fatalf("Podman create contains incompatible Docker memory-swap flag: %v", podmanArgs)
	}
	if !containsArgument(podmanArgs, "--read-only-tmpfs=false") {
		t.Fatalf("Podman create permits implicit writable system tmpfs mounts: %v", podmanArgs)
	}
}

func TestExecuteQuiescesBackgroundMutatorRepairsAndStreamsOutputs(t *testing.T) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:         "result-exists",
		FileExists: "/outputs/hostile/nested/result.txt",
	}}

	var operations []string
	backgroundMutator := false
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		operations = append(operations, "workload")
		backgroundMutator = true
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
		switch {
		case args[0] == "exec" &&
			containsArgument(args, nodeWorkloadQuiesceScript):
			if !backgroundMutator {
				return -1, errors.New("quiesce ran without simulated mutator")
			}
			operations = append(operations, "quiesce")
			backgroundMutator = false
			return 0, nil
		case args[0] == "exec" &&
			containsArgument(args, nodeOutputRepairScript):
			if backgroundMutator {
				return -1, errors.New("repair raced a simulated mutator")
			}
			operations = append(operations, "repair")
			return 0, nil
		case isTarExportArgs(args):
			if backgroundMutator {
				return -1, errors.New("tar raced a simulated mutator")
			}
			operations = append(operations, "tar")
			return writeFixtureTar(stdout, map[string][]byte{
				"hostile/nested/result.txt": []byte("safe\n"),
			})
		case args[0] == "rm":
			operations = append(operations, "rm")
		}
		return base(ctx, name, args, stdout, stderr)
	}

	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := strings.Join(operations, ","); got !=
		"workload,quiesce,repair,tar,rm" {
		t.Fatalf("lifecycle order = %q", got)
	}
	if outcome.Cleanup != domain.CleanupClean ||
		len(outcome.Steps) != 1 ||
		!outcome.Steps[0].CleanupSucceeded {
		t.Fatalf("streamed cleanup outcome = %#v", outcome)
	}
	result, readErr := os.ReadFile(filepath.Join(
		outcome.OutputsDir,
		"hostile",
		"nested",
		"result.txt",
	))
	if readErr != nil || string(result) != "safe\n" {
		t.Fatalf("committed output = %q, err %v", result, readErr)
	}
	for _, call := range fake.snapshotCalls() {
		if len(call.args) > 0 &&
			(call.args[0] == "cp" || call.args[0] == "pause") {
			t.Fatalf("disproved pause/cp path was invoked: %v", call.args)
		}
	}
	var tarArgs []string
	for _, call := range fake.snapshotCalls() {
		if isTarExportArgs(call.args) {
			tarArgs = call.args
			break
		}
	}
	if len(tarArgs) != 16 {
		t.Fatalf("trusted tar argv length = %d, want 16: %v", len(tarArgs), tarArgs)
	}
	expectedTarArgs := []string{
		"exec",
		"--user", "0:0",
		"--workdir", "/outputs",
		tarArgs[5],
		"/bin/tar",
		"--format=ustar",
		"--blocking-factor=1",
		"--exclude=./.home",
		"--exclude=./.tmp",
		"-C", "/outputs",
		"-cf", "-",
		".",
	}
	if !slices.Equal(tarArgs, expectedTarArgs) {
		t.Fatalf("trusted tar argv = %v, want %v", tarArgs, expectedTarArgs)
	}
	for _, runnerManagedPath := range []string{".home", ".tmp"} {
		if _, statErr := os.Lstat(filepath.Join(outcome.OutputsDir, runnerManagedPath)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf(
				"runner-managed export-excluded path %q was exported: %v",
				runnerManagedPath,
				statErr,
			)
		}
	}
	for _, controllerCopy := range []string{
		outcome.WorkspaceDir,
		filepath.Join(outcome.RunDir, "source-snapshot"),
	} {
		if _, statErr := os.Lstat(controllerCopy); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("read-only controller copy was not removed: %s: %v", controllerCopy, statErr)
		}
	}
}

func TestExecuteFailsClosedWhenQuiesceFailsWithoutTarOrCommit(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	base := successfulNodeSandbox(nil)
	tarCalled := false
	removed := false
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if args[0] == "exec" &&
			containsArgument(args, nodeWorkloadQuiesceScript) {
			return 9, errors.New("synthetic quiescence failure")
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
	if got := domain.ErrorCodeOf(err); got != domain.CodeCleanupFailed {
		t.Fatalf("Execute error code = %q: %v", got, err)
	}
	if tarCalled || !removed || outcome.Cleanup != domain.CleanupInconclusive {
		t.Fatalf(
			"quiescence failure tar=%v removed=%v outcome=%#v",
			tarCalled,
			removed,
			outcome,
		)
	}
	entries, readErr := os.ReadDir(outcome.OutputsDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed export committed outputs: %v %#v", readErr, entries)
	}
}

func TestControllerCopyCleanupErrorUsesFixedPublicScope(t *testing.T) {
	const privateMarker = `C:` + `\Users\synthetic\private-run-root`
	err := controllerCopyCleanupError(errors.New(privateMarker))
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), privateMarker) {
		t.Fatalf("cleanup error echoed private root: %s", encoded)
	}
	if err.Details["scope"] != "controller-source-copies" {
		t.Fatalf("cleanup scope = %#v", err.Details)
	}
}

func TestExecuteRejectsUnsafeTarWithoutCommitAndStillRemoves(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("ok\n"))
	plan := testPlan(t, sourceRoot)
	base := successfulNodeSandbox(nil)
	removed := false
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if isTarExportArgs(args) {
			writer := tar.NewWriter(stdout)
			if err := writer.WriteHeader(&tar.Header{
				Name:     "./leak",
				Typeflag: tar.TypeSymlink,
				Linkname: "/etc/passwd",
			}); err != nil {
				return -1, err
			}
			return 0, writer.Close()
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
		domain.CodeForbiddenFilesystemAccess {
		t.Fatalf("Execute error code = %q: %v", got, err)
	}
	if !removed || outcome.Cleanup != domain.CleanupInconclusive {
		t.Fatalf("unsafe tar cleanup outcome = %#v removed=%v", outcome, removed)
	}
	entries, readErr := os.ReadDir(outcome.OutputsDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("unsafe tar committed outputs: %v %#v", readErr, entries)
	}
}

func TestPrepareRejectsMissingDuplicateAndUnsupportedPlatformFeatures(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*domain.ResolvedPlan)
		wantCode domain.ErrorCode
	}{
		{
			name: "missing",
			mutate: func(plan *domain.ResolvedPlan) {
				plan.RequiredRunnerFeatures = []string{"linux-container"}
			},
			wantCode: domain.CodePlanUnresolved,
		},
		{
			name: "duplicate",
			mutate: func(plan *domain.ResolvedPlan) {
				plan.RequiredRunnerFeatures = append(
					plan.RequiredRunnerFeatures,
					"platform:linux/amd64",
				)
			},
			wantCode: domain.CodePlanUnresolved,
		},
		{
			name: "unsupported",
			mutate: func(plan *domain.ResolvedPlan) {
				for index, feature := range plan.RequiredRunnerFeatures {
					if strings.HasPrefix(feature, "platform:") {
						plan.RequiredRunnerFeatures[index] = "platform:linux/s390x"
					}
				}
			},
			wantCode: domain.CodeRunnerFeatureUnavailable,
		},
		{
			name: "noncanonical",
			mutate: func(plan *domain.ResolvedPlan) {
				for index, feature := range plan.RequiredRunnerFeatures {
					if strings.HasPrefix(feature, "platform:") {
						plan.RequiredRunnerFeatures[index] = "Platform:linux/amd64"
					}
				}
			},
			wantCode: domain.CodeRunnerFeatureUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			mustWriteFile(t, filepath.Join(sourceRoot, "app.js"), []byte("x"))
			plan := testPlan(t, sourceRoot)
			test.mutate(&plan)
			fake := &fakeExecutor{}

			_, err := testRunner(fake).Prepare(
				context.Background(),
				plan,
				sourceRoot,
				t.TempDir(),
				"docker",
			)
			if got := domain.ErrorCodeOf(err); got != test.wantCode {
				t.Fatalf("Prepare error code = %q, want %q: %v", got, test.wantCode, err)
			}
			if len(fake.snapshotCalls()) != 0 {
				t.Fatalf("backend contacted for invalid platform plan: %#v", fake.snapshotCalls())
			}
		})
	}
}

func TestLongLivedContainerCreateFailureForcesBestEffortRemoval(t *testing.T) {
	fake := &fakeExecutor{}
	fake.handler = func(
		_ context.Context,
		_ string,
		args []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		switch args[0] {
		case "create":
			return 125, errors.New("synthetic partial create failure")
		case "rm":
			return 0, nil
		default:
			return -1, errors.New("unexpected command")
		}
	}
	runner := testRunner(fake)
	plan := domain.ResolvedPlan{
		RuntimeAdapter:     "node",
		BaseImageReference: "example.invalid/runtime@sha256:" + strings.Repeat("a", 64),
		Resources: domain.ResourceLimits{
			CPUMillis:   1000,
			MemoryBytes: 256 << 20,
			PIDs:        64,
		},
	}
	prepared := sealPreparedRunForTest(&PreparedRun{
		Plan:              plan,
		Runner:            domain.RunnerFeatures{Available: true, WorkloadOS: "linux"},
		Backend:           "docker",
		Platform:          "linux/amd64",
		RunID:             "test1234",
		RunDir:            t.TempDir(),
		SourceSnapshotDir: t.TempDir(),
		WorkspaceDir:      t.TempDir(),
		OutputsDir:        t.TempDir(),
	})
	_, err := runner.Run(context.Background(), prepared)
	if got := domain.ErrorCodeOf(err); got != domain.CodeSandboxPrepareFailed {
		t.Fatalf("Run error code = %q, want %q: %v", got, domain.CodeSandboxPrepareFailed, err)
	}
	remove := findCall(t, fake.snapshotCalls(), "rm")
	if len(remove.args) != 3 ||
		remove.args[1] != "-f" ||
		remove.args[2] != "repopass-test1234" {
		t.Fatalf("partial create cleanup command = %v", remove.args)
	}
}

func TestSandboxBoundaryFailureEmitsOneCleanupSummaryAndBuildsArtifact(
	t *testing.T,
) {
	tests := []struct {
		name     string
		failCall string
		wantCode domain.ErrorCode
	}{
		{
			name:     "create failure",
			failCall: "create",
			wantCode: domain.CodeSandboxPrepareFailed,
		},
		{
			name:     "start failure",
			failCall: "start",
			wantCode: domain.CodeSandboxStartFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			containerID := strings.Repeat("a", 64)
			fake := &fakeExecutor{}
			fake.handler = func(
				_ context.Context,
				_ string,
				args []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				switch args[0] {
				case "create":
					if test.failCall == "create" {
						return 125, errors.New("synthetic create failure")
					}
					_, _ = io.WriteString(stdout, containerID+"\n")
					return 0, nil
				case "start":
					return 125, errors.New("synthetic start failure")
				case "rm":
					return 0, nil
				default:
					return -1, errors.New("unexpected command")
				}
			}
			plan := domain.ResolvedPlan{
				SchemaVersion: "4",
				Evidence: domain.PlanEvidence{
					Profile: "minimal-public",
					Include: []string{"normalized-observations", "verification-summary"},
					Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
				},
				RuntimeAdapter:   "node",
				RepeatCount:      1,
				SuccessThreshold: 1,
				Cleanup: domain.PlanCleanup{
					ClassifierVersion: cleanupClassifierVersion,
					AllowedResidue:    []string{},
				},
				Resources: domain.ResourceLimits{
					CPUMillis:   1000,
					MemoryBytes: 256 << 20,
					DiskBytes:   1 << 30,
					PIDs:        64,
				},
			}
			prepared := sealPreparedRunForTest(&PreparedRun{
				Plan: plan,
				Runner: domain.RunnerFeatures{
					Available:  true,
					WorkloadOS: "linux",
					Backend:    "docker",
				},
				Backend:           "docker",
				Platform:          "linux/amd64",
				RunID:             "test1234",
				RunDir:            t.TempDir(),
				SourceSnapshotDir: t.TempDir(),
				WorkspaceDir:      t.TempDir(),
				OutputsDir:        t.TempDir(),
			})
			outcome, runErr := testRunner(fake).Run(
				context.Background(),
				prepared,
			)
			if got := domain.ErrorCodeOf(runErr); got != test.wantCode {
				t.Fatalf(
					"Run error code = %q, want %q: %v",
					got,
					test.wantCode,
					runErr,
				)
			}
			if outcome.CompletedAt.IsZero() ||
				outcome.Cleanup != domain.CleanupNotTested {
				t.Fatalf("boundary failure outcome = %#v", outcome)
			}
			var summaries []domain.ObservationEvent
			for _, observation := range outcome.Observations {
				if observation.Operation ==
					"cleanup.residue.summary" {
					summaries = append(summaries, observation)
				}
			}
			if len(summaries) != 1 {
				t.Fatalf(
					"cleanup summaries = %d, want 1: %#v",
					len(summaries),
					outcome.Observations,
				)
			}
			summary := summaries[0]
			if summary.Details["failure"] !=
				"sandbox-boundary-unavailable" ||
				summary.Details["quiescenceConfirmed"] != false ||
				summary.Details["disposableCleanupVerified"] != false ||
				summary.Details["identityVerified"] != false ||
				summary.Details["inventoryComplete"] != false {
				t.Fatalf("boundary cleanup summary = %#v", summary)
			}
			if _, err := verification.Build(verification.Input{
				RunID:            "run_boundary_failure",
				VerificationID:   "vrf_boundary_failure",
				Plan:             plan,
				Runner:           outcome.Runner,
				StartedAt:        outcome.StartedAt,
				CompletedAt:      outcome.CompletedAt,
				Observations:     outcome.Observations,
				Assertions:       outcome.Assertions,
				Errors:           outcome.Errors,
				Requested:        1,
				Completed:        1,
				Matching:         0,
				SuccessThreshold: 1,
				Cleanup:          outcome.Cleanup,
				Resources:        outcome.Resources,
			}); err != nil {
				t.Fatalf("verification.Build boundary failure: %v", err)
			}
		})
	}
}

func TestExecuteReturnsPartialOutcomeAndForcesCleanupOnNonzeroExit(t *testing.T) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.py"), []byte("raise SystemExit(7)\n"))
	plan := testPlan(t, sourceRoot)
	plan.Commands[0].Argv = []string{"python", "/workspace/app.py"}
	zero := 0
	plan.JourneyAssertions = []domain.PlanAssertion{{ID: "process-exited", ExitCode: &zero}}

	fake := &fakeExecutor{}
	fake.handler = successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		stderr io.Writer,
	) (int, error) {
		_, _ = io.WriteString(stderr, "failed\n")
		return 7, errors.New("exit status 7")
	})
	runner := testRunner(fake)
	outcome, err := runner.Execute(context.Background(), plan, sourceRoot, runRoot, "docker")
	if err == nil || domain.ErrorCodeOf(err) != domain.CodeJourneyAssertionFailed {
		t.Fatalf("error = %v, want %s", err, domain.CodeJourneyAssertionFailed)
	}
	if len(outcome.Steps) != 1 || outcome.Steps[0].ExitCode != 7 {
		t.Fatalf("partial step evidence was not retained: %#v", outcome.Steps)
	}
	if outcome.Cleanup != domain.CleanupClean || !outcome.Steps[0].CleanupSucceeded {
		t.Fatalf("forced cleanup was not retained: %#v", outcome)
	}
	if len(outcome.Assertions) != 1 || outcome.Assertions[0].Status != "failed" {
		t.Fatalf("partial assertion evidence = %#v, want failed", outcome.Assertions)
	}
	findCall(t, fake.snapshotCalls(), "rm")
}

func TestExecuteAcceptsDeclaredNonzeroJourneyExit(t *testing.T) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.py"), []byte("raise SystemExit(7)\n"))
	plan := testPlan(t, sourceRoot)
	plan.Commands[0].Argv = []string{"python", "/workspace/app.py"}
	seven := 7
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:       "expected-rejection",
		ExitCode: &seven,
	}}

	fake := &fakeExecutor{}
	fake.handler = successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		return 7, errors.New("exit status 7")
	})

	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if err != nil {
		t.Fatalf("Execute returned error for declared journey exit: %v", err)
	}
	if len(outcome.Assertions) != 1 ||
		outcome.Assertions[0].Status != "passed" ||
		outcome.Assertions[0].Actual != 7 {
		t.Fatalf("declared non-zero assertion = %#v, want passed actual 7", outcome.Assertions)
	}
	for _, observation := range outcome.Observations {
		if observation.Operation == "foreground-process.exit" &&
			observation.Result != "succeeded" {
			t.Fatalf("declared non-zero journey exit observation = %#v", observation)
		}
	}
}

func TestExecuteKeepsForegroundPhaseNonzeroAsFailure(t *testing.T) {
	tests := []struct {
		phase    domain.Phase
		wantCode domain.ErrorCode
	}{
		{phase: domain.PhaseSetup, wantCode: domain.CodeSetupFailed},
		{phase: domain.PhaseBuild, wantCode: domain.CodeBuildFailed},
		{phase: domain.PhaseRun, wantCode: domain.CodeJourneyAssertionFailed},
	}

	for _, test := range tests {
		t.Run(string(test.phase), func(t *testing.T) {
			sourceRoot := t.TempDir()
			mustWriteFile(t, filepath.Join(sourceRoot, "app.py"), []byte("raise SystemExit(7)\n"))
			plan := testPlan(t, sourceRoot)
			plan.Commands[0].Phase = test.phase
			plan.Commands[0].Role = "foreground"
			plan.Commands[0].Argv = []string{"python", "/workspace/app.py"}
			seven := 7
			plan.JourneyAssertions = []domain.PlanAssertion{{
				ID:       "journey-only-exit",
				ExitCode: &seven,
			}}

			fake := &fakeExecutor{}
			fake.handler = successfulNodeSandbox(func(
				_ context.Context,
				_ string,
				_ []string,
				_ io.Writer,
				_ io.Writer,
			) (int, error) {
				return 7, errors.New("exit status 7")
			})

			_, err := testRunner(fake).Execute(
				context.Background(),
				plan,
				sourceRoot,
				t.TempDir(),
				"docker",
			)
			if got := domain.ErrorCodeOf(err); got != test.wantCode {
				t.Fatalf("Execute error code = %q, want %q: %v", got, test.wantCode, err)
			}
		})
	}
}

func TestPrepareRejectsSetupAllowlistWithoutSilentDowngrade(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app"), []byte("x"))
	plan := testPlan(t, sourceRoot)
	plan.Capabilities = map[domain.Phase]domain.CapabilitySet{
		domain.PhaseSetup: {
			Network: domain.NetworkCapability{
				Allow: []domain.NetworkDestination{{Host: "registry.npmjs.org", Port: 443}},
			},
		},
	}
	fake := &fakeExecutor{}
	_, err := testRunner(fake).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if domain.ErrorCodeOf(err) != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf("error = %v, want %s", err, domain.CodeRunnerFeatureUnavailable)
	}
	if len(fake.snapshotCalls()) != 0 {
		t.Fatalf("backend was contacted after unsupported plan was detected: %#v", fake.snapshotCalls())
	}
}

func TestPrepareExcludesSensitiveTreesAndRejectsSourceDrift(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "app.txt"), []byte("expected"))
	mustWriteFile(t, filepath.Join(sourceRoot, ".git", "config"), []byte("credential=secret"))
	mustWriteFile(t, filepath.Join(sourceRoot, ".repopass", "old-evidence.json"), []byte("secret"))
	mustWriteFile(t, filepath.Join(sourceRoot, "passport.lock.json"), []byte("stale"))
	plan := testPlan(t, sourceRoot)

	fake := dockerDoctorFake()
	prepared, err := testRunner(fake).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if err != nil {
		t.Fatalf("Prepare returned error: %v", err)
	}
	t.Cleanup(func() {
		if cleanupErr := controllerfs.RemoveTree(prepared.RunDir); cleanupErr != nil {
			t.Errorf("clean prepared run: %v", cleanupErr)
		}
	})
	for _, relative := range []string{".git", ".repopass", "passport.lock.json"} {
		if _, statErr := os.Stat(filepath.Join(prepared.SourceSnapshotDir, relative)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("sensitive path %q was copied into workload snapshot", relative)
		}
	}

	mustWriteFile(t, filepath.Join(sourceRoot, "app.txt"), []byte("changed"))
	_, err = testRunner(dockerDoctorFake()).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if domain.ErrorCodeOf(err) != domain.CodeSourceDigestMismatch {
		t.Fatalf("drift error = %v, want %s", err, domain.CodeSourceDigestMismatch)
	}
}

func TestPrepareRejectsCommaInFixtureMountSource(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "fixture,option.txt"), []byte("x"))
	plan := testPlan(t, sourceRoot)
	plan.Inputs = []domain.PlanInput{{
		Name:      "fixture",
		Type:      "file",
		Fixture:   "fixture,option.txt",
		MountPath: "/inputs/fixture.txt",
		ReadOnly:  true,
	}}
	_, err := testRunner(dockerDoctorFake()).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if domain.ErrorCodeOf(err) != domain.CodeSandboxPrepareFailed {
		t.Fatalf("error = %v, want %s", err, domain.CodeSandboxPrepareFailed)
	}
}

func TestPrepareRejectsControlCharacterInFixtureMountDestination(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(sourceRoot, "fixture.txt"), []byte("x"))
	plan := testPlan(t, sourceRoot)
	plan.Inputs = []domain.PlanInput{{
		Name:      "fixture",
		Type:      "file",
		Fixture:   "fixture.txt",
		MountPath: "/inputs/fixture\ninjected",
		ReadOnly:  true,
	}}
	_, err := testRunner(dockerDoctorFake()).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if domain.ErrorCodeOf(err) != domain.CodeSourcePathTraversal {
		t.Fatalf("error = %v, want %s", err, domain.CodeSourcePathTraversal)
	}
}

func testRunner(executor CommandExecutor) *Runner {
	config := DefaultConfig()
	config.MaxLogBytes = 1024
	config.DoctorTimeout = time.Second
	config.PrepareTimeout = 5 * time.Second
	config.CreateTimeout = time.Second
	config.CleanupTimeout = time.Second
	runner := NewRunner(executor, config)
	runner.idGenerator = func() (string, error) { return "test1234", nil }
	return runner
}

func testPlan(t *testing.T, sourceRoot string) domain.ResolvedPlan {
	t.Helper()
	provider := acquisition.NewLocalProvider()
	snapshot, err := provider.Fetch(context.Background(), domain.ResolvedSource{
		Kind:      "local",
		LocalPath: sourceRoot,
	})
	if err != nil {
		t.Fatalf("source inventory failed: %v", err)
	}
	return domain.ResolvedPlan{
		SchemaVersion:        "4",
		Source:               domain.PlanSource{Identity: snapshot.Identity, TreeDigest: snapshot.TreeDigest},
		PlanDigest:           "sha256:" + strings.Repeat("b", 64),
		RuntimeAdapter:       "node",
		RuntimeVersion:       runtimepolicy.NodeVersion,
		BaseImageReference:   runtimepolicy.NodeReference,
		BaseImageDigest:      runtimepolicy.NodeDigest,
		JourneyDriver:        "cli",
		JourneyDriverVersion: "0.2.0",
		Cleanup: domain.PlanCleanup{
			ClassifierVersion: "0.1.0",
			AllowedResidue:    []string{},
		},
		Evidence: domain.PlanEvidence{
			Profile: "minimal-public",
			Include: []string{"normalized-observations", "verification-summary"},
			Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
		},
		Resources: domain.ResourceLimits{
			CPUMillis:   1000,
			MemoryBytes: 256 << 20,
			DiskBytes:   1 << 30,
			PIDs:        64,
		},
		Commands: []domain.PlanCommand{{
			Phase:   domain.PhaseExercise,
			ID:      "journey",
			Argv:    []string{"node", "/workspace/app.js"},
			Timeout: "10s",
			Role:    "journey",
		}},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {Network: domain.NetworkCapability{Deny: true}},
		},
		RequiredRunnerFeatures: []string{
			"linux-container",
			"platform:linux/amd64",
			"read-only-source",
			"isolated-workspace",
			"network-deny",
			"bounded-logs",
			"process-cleanup",
			"cleanup-residue-classification",
		},
	}
}

func TestClonePlanDeepCopiesSchema4Evidence(t *testing.T) {
	original := domain.ResolvedPlan{
		SchemaVersion: "4",
		Evidence: domain.PlanEvidence{
			Profile: "minimal-public",
			Include: []string{"normalized-observations", "sbom", "verification-summary"},
			Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
		},
	}
	cloned := clonePlan(original)
	original.Evidence.Include[0] = "mutated-original"
	original.Evidence.Exclude[0] = "mutated-original"
	if cloned.Evidence.Include[0] != "normalized-observations" ||
		cloned.Evidence.Exclude[0] != "raw-stderr" {
		t.Fatalf("clone retained aliased evidence slices: %#v", cloned.Evidence)
	}
}

func dockerDoctorFake() *fakeExecutor {
	fake := &fakeExecutor{}
	fake.handler = func(
		_ context.Context,
		_ string,
		args []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if len(args) > 0 && args[0] == "info" {
			_, _ = io.WriteString(stdout, dockerInfoJSON())
			return 0, nil
		}
		return -1, errors.New("unexpected command")
	}
	return fake
}

func sealPreparedRunForTest(prepared *PreparedRun) *PreparedRun {
	if prepared == nil || prepared.executionPlanSealed {
		return prepared
	}
	prepared.executionPlan = clonePlan(prepared.Plan)
	prepared.executionPlanSealed = true
	return prepared
}

func successfulNodeSandbox(
	workload func(
		context.Context,
		string,
		[]string,
		io.Writer,
		io.Writer,
	) (int, error),
) func(
	context.Context,
	string,
	[]string,
	io.Writer,
	io.Writer,
) (int, error) {
	containerID := strings.Repeat("a", 64)
	runLabel := "test1234"
	memoryBytes := int64(256 << 20)
	diskBytes := int64(1 << 30)
	pids := 64
	cpuMillis := int64(1000)
	resourceSamples := 0
	return func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		switch args[0] {
		case "info":
			_, _ = io.WriteString(stdout, dockerInfoJSON())
			return 0, nil
		case "create":
			for index := 0; index+1 < len(args); index++ {
				switch args[index] {
				case "--memory":
					memoryBytes, _ = strconv.ParseInt(args[index+1], 10, 64)
				case "--pids-limit":
					pids, _ = strconv.Atoi(args[index+1])
				case "--cpus":
					cpus, _ := strconv.ParseFloat(args[index+1], 64)
					cpuMillis = int64(cpus * 1000)
				case "--label":
					if strings.HasPrefix(
						args[index+1],
						runLabelKey+"=",
					) {
						runLabel = strings.TrimPrefix(
							args[index+1],
							runLabelKey+"=",
						)
					}
				case "--tmpfs":
					for _, option := range strings.Split(
						args[index+1],
						",",
					) {
						if strings.HasPrefix(option, "size=") {
							diskBytes, _ = strconv.ParseInt(
								strings.TrimPrefix(option, "size="),
								10,
								64,
							)
						}
					}
				}
			}
			_, _ = io.WriteString(stdout, containerID+"\n")
			return 0, nil
		case "start", "rm":
			return 0, nil
		case "inspect":
			if containsArgument(args, resourceContainerIdentityFormat) {
				_, _ = io.WriteString(
					stdout,
					`{"id":"`+containerID+`","runLabel":"`+
						runLabel+`"}`+"\n",
				)
				return 0, nil
			}
			_, _ = io.WriteString(stdout, "true\n")
			return 0, nil
		case "exec":
			if containsArgument(args, nodeCleanupInventoryScript) {
				_, _ = io.WriteString(
					stdout,
					`{"schemaVersion":"1","ok":true,"scope":"/outputs",`+
						`"count":0,"rootBefore":{"device":"1","inode":"2","mode":511,"ctimeNs":"3","mtimeNs":"4"},`+
						`"rootAfter":{"device":"1","inode":"2","mode":511,"ctimeNs":"3","mtimeNs":"4"},`+
						`"disposableAbsent":true,"entries":[]}`+"\n",
				)
				return 0, nil
			}
			if containsArgument(args, nodeLinuxResourceScript) {
				resourceSamples++
				blockSize := int64(4096)
				writableLimit := ((diskBytes + blockSize - 1) /
					blockSize) * blockSize
				peakMemory := int64(1 << 20)
				if peakMemory > memoryBytes {
					peakMemory = memoryBytes
				}
				maxTasks := 4
				if maxTasks > pids {
					maxTasks = pids
				}
				_, _ = io.WriteString(
					stdout,
					`{"ok":true,"cgroupVersion":2,`+
						`"cpuUsageUsec":`+
						strconv.Itoa(resourceSamples*1000)+
						`,"sandboxPeakMemoryBytes":`+
						strconv.FormatInt(peakMemory, 10)+
						`,"maxTasks":`+strconv.Itoa(maxTasks)+
						`,"pidsLimitEvents":0,`+
						`"memoryOOMEvents":0,`+
						`"memoryOOMKillEvents":0,`+
						`"memoryMaxBytes":`+
						strconv.FormatInt(memoryBytes, 10)+
						`,"memorySwapMaxBytes":0,`+
						`"pidsMax":`+strconv.Itoa(pids)+
						`,"cpuQuotaMicros":`+
						strconv.FormatInt(cpuMillis*100, 10)+
						`,"cpuPeriodMicros":100000,`+
						`"writableBytes":0,`+
						`"writableLimitBytes":`+
						strconv.FormatInt(writableLimit, 10)+
						`,"writableBlockSize":4096}`+"\n",
				)
				return 0, nil
			}
			if containsArgument(args, nodeWorkloadIdentityScript) {
				_, _ = io.WriteString(
					stdout,
					`{"uid":65532,"euid":65532,"gid":65532,"egid":65532,`+
						`"capInh":"0000000000000000","capPrm":"0000000000000000",`+
						`"capEff":"0000000000000000","capAmb":"0000000000000000",`+
						`"noNewPrivs":1}`+"\n",
				)
				return 0, nil
			}
			if len(args) >= 2 &&
				args[len(args)-2] == "node" &&
				args[len(args)-1] == "--version" {
				_, _ = io.WriteString(
					stdout,
					"v"+runtimepolicy.NodeVersion+"\n",
				)
				return 0, nil
			}
			if len(args) >= 2 &&
				args[len(args)-2] == "/bin/tar" &&
				args[len(args)-1] == "--version" {
				_, _ = io.WriteString(stdout, "tar (GNU tar) 1.34\n")
				return 0, nil
			}
			if containsArgument(args, "/bin/tar") &&
				containsArgument(args, "-cf") {
				writer := tar.NewWriter(stdout)
				if err := writer.WriteHeader(&tar.Header{
					Name:     "./",
					Typeflag: tar.TypeDir,
					Mode:     0o755,
				}); err != nil {
					return -1, err
				}
				if err := writer.Close(); err != nil {
					return -1, err
				}
				return 0, nil
			}
			if containsAdjacent(args, "--user", "0:0") ||
				containsArgument(args, nodeOutputInitScript) {
				return 0, nil
			}
			if workload != nil {
				return workload(ctx, name, args, stdout, stderr)
			}
			return 0, nil
		default:
			return -1, errors.New("unexpected command")
		}
	}
}

func isTarExportArgs(args []string) bool {
	return len(args) > 0 &&
		args[0] == "exec" &&
		containsArgument(args, "/bin/tar") &&
		containsArgument(args, "-cf")
}

func writeFixtureTar(
	output io.Writer,
	files map[string][]byte,
) (int, error) {
	writer := tar.NewWriter(output)
	directorySet := map[string]struct{}{}
	fileNames := make([]string, 0, len(files))
	for name := range files {
		fileNames = append(fileNames, name)
		current := path.Dir(name)
		for current != "." && current != "/" {
			directorySet[current] = struct{}{}
			current = path.Dir(current)
		}
	}
	directories := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(i, j int) bool {
		leftDepth := strings.Count(directories[i], "/")
		rightDepth := strings.Count(directories[j], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directories[i] < directories[j]
	})
	for _, directory := range directories {
		if err := writer.WriteHeader(&tar.Header{
			Name:     "./" + directory + "/",
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		}); err != nil {
			return -1, err
		}
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		payload := files[name]
		if err := writer.WriteHeader(&tar.Header{
			Name:     "./" + name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(payload)),
		}); err != nil {
			return -1, err
		}
		if _, err := writer.Write(payload); err != nil {
			return -1, err
		}
	}
	if err := writer.Close(); err != nil {
		return -1, err
	}
	return 0, nil
}

func withDockerInfo(
	next func(context.Context, string, []string, io.Writer, io.Writer) (int, error),
) func(context.Context, string, []string, io.Writer, io.Writer) (int, error) {
	return func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if len(args) > 0 && args[0] == "info" {
			_, _ = io.WriteString(stdout, dockerInfoJSON())
			return 0, nil
		}
		return next(ctx, name, args, stdout, stderr)
	}
}

func dockerInfoJSON() string {
	return `{"OSType":"linux","ServerVersion":"27.0.0","SecurityOptions":["name=rootless"]}`
}

func mustWriteFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func findCall(t *testing.T, calls []commandCall, subcommand string) commandCall {
	t.Helper()
	for _, call := range calls {
		if len(call.args) > 0 && call.args[0] == subcommand {
			return call
		}
	}
	t.Fatalf("backend subcommand %q not found in %#v", subcommand, calls)
	return commandCall{}
}

func findWorkloadExec(t *testing.T, calls []commandCall) commandCall {
	t.Helper()
	for _, call := range calls {
		if len(call.args) == 0 || call.args[0] != "exec" ||
			containsAdjacent(call.args, "--user", "0:0") ||
			containsArgument(call.args, nodeOutputInitScript) ||
			containsArgument(call.args, nodeWorkloadIdentityScript) {
			continue
		}
		if len(call.args) >= 2 &&
			call.args[len(call.args)-2] == "node" &&
			call.args[len(call.args)-1] == "--version" {
			continue
		}
		return call
	}
	t.Fatalf("workload exec not found in %#v", calls)
	return commandCall{}
}

func containsAdjacent(values []string, first, second string) bool {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == first && values[index+1] == second {
			return true
		}
	}
	return false
}

func containsArgument(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsSubstring(values []string, wanted string) bool {
	for _, value := range values {
		if strings.Contains(value, wanted) {
			return true
		}
	}
	return false
}

func flagValues(values []string, flag string) []string {
	var result []string
	for index := 0; index+1 < len(values); index++ {
		if values[index] == flag {
			result = append(result, values[index+1])
		}
	}
	return result
}

func flagValue(values []string, flag string) string {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == flag {
			return values[index+1]
		}
	}
	return ""
}

func mountSource(t *testing.T, args []string, destination string) string {
	t.Helper()
	for _, mount := range flagValues(args, "--mount") {
		parts := strings.Split(mount, ",")
		var source, target string
		for _, part := range parts {
			switch {
			case strings.HasPrefix(part, "src="):
				source = strings.TrimPrefix(part, "src=")
			case strings.HasPrefix(part, "dst="):
				target = strings.TrimPrefix(part, "dst=")
			}
		}
		if target == destination {
			return source
		}
	}
	t.Fatalf("mount destination %q not found in %v", destination, args)
	return ""
}

func assertMount(t *testing.T, mounts []string, destination string, readOnly bool) {
	t.Helper()
	for _, mount := range mounts {
		if !strings.Contains(mount, "dst="+destination) {
			continue
		}
		if strings.Contains(mount, ",readonly") != readOnly {
			t.Fatalf("mount %q readonly=%v, want %v", mount, strings.Contains(mount, ",readonly"), readOnly)
		}
		return
	}
	t.Fatalf("mount destination %q not found in %v", destination, mounts)
}
