package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const validLinuxResourceControl = `{"ok":true,"cgroupVersion":2,` +
	`"cpuUsageUsec":2501,"sandboxPeakMemoryBytes":1048576,` +
	`"maxTasks":4,"pidsLimitEvents":0,"memoryOOMEvents":0,` +
	`"memoryOOMKillEvents":0,"memoryMaxBytes":268435456,` +
	`"memorySwapMaxBytes":0,"pidsMax":64,"cpuQuotaMicros":100000,` +
	`"cpuPeriodMicros":100000,"writableBytes":4096,` +
	`"writableLimitBytes":1073741824,"writableBlockSize":4096}`

func TestDecodeLinuxResourceControlAcceptsExactEnvelope(t *testing.T) {
	snapshot, err := decodeLinuxResourceControl(
		[]byte(validLinuxResourceControl + "\n"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CPUUsageUsec != 2501 ||
		snapshot.SandboxPeakMemoryBytes != 1048576 ||
		snapshot.MaxTasks != 4 ||
		snapshot.MemoryMaxBytes != 268435456 ||
		snapshot.MemorySwapMaxBytes != 0 ||
		snapshot.PIDsMax != 64 ||
		snapshot.WritableLimitBytes != 1073741824 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestDecodeLinuxResourceControlRejectsUntrustedEnvelope(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "top-level array", raw: `[]`},
		{name: "trailing", raw: validLinuxResourceControl + `{}`},
		{
			name: "duplicate ok",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"ok":true`,
				`"ok":true,"ok":true`,
				1,
			),
		},
		{
			name: "duplicate numeric",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"cpuUsageUsec":2501`,
				`"cpuUsageUsec":2501,"cpuUsageUsec":2502`,
				1,
			),
		},
		{
			name: "unknown",
			raw: validLinuxResourceControl[:len(validLinuxResourceControl)-1] +
				`,"extra":0}`,
		},
		{
			name: "missing",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"cpuUsageUsec":2501,`,
				"",
				1,
			),
		},
		{
			name: "numeric null",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"cpuUsageUsec":2501`,
				`"cpuUsageUsec":null`,
				1,
			),
		},
		{
			name: "bool null",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"ok":true`,
				`"ok":null`,
				1,
			),
		},
		{
			name: "numeric string",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"maxTasks":4`,
				`"maxTasks":"4"`,
				1,
			),
		},
		{
			name: "numeric fraction",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"maxTasks":4`,
				`"maxTasks":4.5`,
				1,
			),
		},
		{
			name: "numeric overflow",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"cpuUsageUsec":2501`,
				`"cpuUsageUsec":9223372036854775808`,
				1,
			),
		},
		{
			name: "negative",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"cpuUsageUsec":2501`,
				`"cpuUsageUsec":-1`,
				1,
			),
		},
		{
			name: "wrong cgroup version",
			raw: strings.Replace(
				validLinuxResourceControl,
				`"cgroupVersion":2`,
				`"cgroupVersion":1`,
				1,
			),
		},
		{name: "failure missing error", raw: `{"ok":false}`},
		{
			name: "failure union confusion",
			raw: `{"ok":false,"error":"measurement-unavailable",` +
				`"cpuUsageUsec":0}`,
		},
		{
			name: "failure unknown error",
			raw:  `{"ok":false,"error":"raw-kernel-secret"}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeLinuxResourceControl([]byte(test.raw))
			if err == nil {
				t.Fatal("unsafe resource envelope was accepted")
			}
			if strings.Contains(err.Error(), "raw-kernel-secret") {
				t.Fatalf("raw helper data leaked through error: %v", err)
			}
		})
	}
}

func TestResourcePreflightRequiresExactControllerLimits(t *testing.T) {
	snapshot, err := decodeLinuxResourceControl(
		[]byte(validLinuxResourceControl),
	)
	if err != nil {
		t.Fatal(err)
	}
	limits := domain.ResourceLimits{
		CPUMillis: 1000, MemoryBytes: 268435456,
		DiskBytes: 1073741824, PIDs: 64,
	}
	if err := validateLinuxResourcePreflight(snapshot, limits); err != nil {
		t.Fatalf("valid preflight: %v", err)
	}
	tests := map[string]func(*linuxResourceSnapshot){
		"memory": func(value *linuxResourceSnapshot) {
			value.MemoryMaxBytes--
		},
		"swap": func(value *linuxResourceSnapshot) {
			value.MemorySwapMaxBytes = 1
		},
		"pids": func(value *linuxResourceSnapshot) {
			value.PIDsMax--
		},
		"cpu": func(value *linuxResourceSnapshot) {
			value.CPUQuotaMicros--
		},
		"disk": func(value *linuxResourceSnapshot) {
			value.WritableLimitBytes--
		},
		"oom event": func(value *linuxResourceSnapshot) {
			value.MemoryOOMEvents = 1
		},
		"oom kill event": func(value *linuxResourceSnapshot) {
			value.MemoryOOMKillEvents = 1
		},
		"pids event": func(value *linuxResourceSnapshot) {
			value.PIDsLimitEvents = 1
		},
	}
	for name, mutate := range tests {
		mutated := snapshot
		mutate(&mutated)
		if err := validateLinuxResourcePreflight(mutated, limits); err == nil {
			t.Fatalf("%s mismatch passed preflight", name)
		}
	}
}

func TestResourceHelperUsesPrivateCgroupNamespaceAndExactFiles(t *testing.T) {
	for adapter, script := range map[string]string{
		"node":   nodeLinuxResourceScript,
		"python": pythonLinuxResourceScript,
	} {
		for _, required := range []string{
			`0::/`,
			`cpu.stat`,
			`memory.peak`,
			`memory.events`,
			`memory.swap.max`,
			`pids.peak`,
			`pids.events`,
			`cpu.max`,
		} {
			if !strings.Contains(script, required) {
				t.Fatalf("%s helper omitted %q", adapter, required)
			}
		}
		if strings.Contains(script, `"/sys/fs/cgroup"+`) {
			t.Fatalf("%s helper accepts a host cgroup-relative path", adapter)
		}
	}
}

func TestCollectLinuxResourceSnapshotUsesImmutableIDAndBoundedRootHelper(
	t *testing.T,
) {
	containerID := strings.Repeat("a", 64)
	fake := &fakeExecutor{
		handler: func(
			_ context.Context,
			_ string,
			args []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			if !containsAdjacent(args, "--user", "0:0") ||
				!containsAdjacent(args, "--workdir", trustedHelperWorkdir) ||
				!containsArgument(args, containerID) ||
				!containsArgument(args, nodeLinuxResourceScript) {
				t.Fatalf("unsafe resource helper args: %v", args)
			}
			_, _ = io.WriteString(stdout, validLinuxResourceControl)
			return 0, nil
		},
	}
	snapshot, err := testRunner(fake).collectLinuxResourceSnapshot(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan: domain.ResolvedPlan{
				RuntimeAdapter: "node",
			},
		}),
		containerID,
	)
	if err != nil || snapshot.MaxTasks != 4 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

func TestCollectLinuxResourceSnapshotRejectsOversizedControlWithoutLeak(
	t *testing.T,
) {
	containerID := strings.Repeat("d", 64)
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
				"RAW_RESOURCE_SECRET"+
					strings.Repeat("x", linuxResourceControlLimit),
			)
			return 0, nil
		},
	}
	_, err := testRunner(fake).collectLinuxResourceSnapshot(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan: domain.ResolvedPlan{
				RuntimeAdapter: "node",
			},
		}),
		containerID,
	)
	if err == nil ||
		strings.Contains(err.Error(), "RAW_RESOURCE_SECRET") {
		t.Fatalf("oversized resource control error = %v", err)
	}
}

func TestResourceLimitEventErrorUsesCounterDeltas(t *testing.T) {
	active := linuxResourceSnapshot{}
	final := active
	final.PIDsLimitEvents = 1
	final.MemoryOOMEvents = 2
	final.MemoryOOMKillEvents = 1
	err := resourceLimitEventError(active, final)
	if domain.ErrorCodeOf(err) != domain.CodeResourceLimitExceeded {
		t.Fatalf("error = %v", err)
	}
	if resourceLimitEventError(final, final) != nil {
		t.Fatal("unchanged counters were reported as new limit events")
	}
}

func TestValidateLinuxResourceMonotonicRejectsEveryCounterRollback(
	t *testing.T,
) {
	active, err := decodeLinuxResourceControl(
		[]byte(validLinuxResourceControl),
	)
	if err != nil {
		t.Fatal(err)
	}
	final := active
	final.CPUUsageUsec++
	final.SandboxPeakMemoryBytes++
	final.MaxTasks++
	final.PIDsLimitEvents++
	final.MemoryOOMEvents++
	final.MemoryOOMKillEvents++
	if err := validateLinuxResourceMonotonic(active, final); err != nil {
		t.Fatalf("monotonic final snapshot: %v", err)
	}
	tests := map[string]func(*linuxResourceSnapshot){
		"cpu": func(value *linuxResourceSnapshot) {
			value.CPUUsageUsec = active.CPUUsageUsec - 1
		},
		"memory peak": func(value *linuxResourceSnapshot) {
			value.SandboxPeakMemoryBytes =
				active.SandboxPeakMemoryBytes - 1
		},
		"task peak": func(value *linuxResourceSnapshot) {
			value.MaxTasks = active.MaxTasks - 1
		},
		"pids events": func(value *linuxResourceSnapshot) {
			value.PIDsLimitEvents = active.PIDsLimitEvents - 1
		},
		"oom events": func(value *linuxResourceSnapshot) {
			value.MemoryOOMEvents = active.MemoryOOMEvents - 1
		},
		"oom kill events": func(value *linuxResourceSnapshot) {
			value.MemoryOOMKillEvents =
				active.MemoryOOMKillEvents - 1
		},
	}
	for name, mutate := range tests {
		rolledBack := final
		mutate(&rolledBack)
		if err := validateLinuxResourceMonotonic(
			active,
			rolledBack,
		); err == nil {
			t.Fatalf("%s rollback was accepted", name)
		}
	}
}

func TestParseCreatedContainerIDIsExact(t *testing.T) {
	id := strings.Repeat("b", 64)
	for _, raw := range []string{id, id + "\n", id + "\r\n"} {
		if got, err := parseCreatedContainerID([]byte(raw)); err != nil ||
			got != id {
			t.Fatalf("parse ID %q = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		strings.Repeat("b", 63),
		strings.ToUpper(id),
		id + "\n" + id,
		" " + id,
	} {
		if _, err := parseCreatedContainerID([]byte(raw)); err == nil {
			t.Fatalf("unsafe ID output accepted: %q", raw)
		}
	}
}

func TestDecodeLinuxResourceControlRejectsPlatformIntOverflow(t *testing.T) {
	if int64(math.MaxInt) == math.MaxInt64 {
		t.Skip("platform int is 64-bit")
	}
	raw := strings.Replace(
		validLinuxResourceControl,
		`"maxTasks":4`,
		`"maxTasks":2147483648`,
		1,
	)
	if _, err := decodeLinuxResourceControl([]byte(raw)); err == nil {
		t.Fatal("platform int overflow was accepted")
	}
}

func TestInspectResourceContainerIdentityRejectsMismatch(t *testing.T) {
	containerID := strings.Repeat("c", 64)
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
				`{"id":"`+containerID+`","runLabel":"wrong"}`,
			)
			return 0, nil
		},
	}
	err := testRunner(fake).inspectResourceContainerIdentity(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			RunID:   "test1234",
			Plan:    domain.ResolvedPlan{},
		}),
		containerID,
	)
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestInspectResourceContainerIdentityRejectsDirtyStderr(t *testing.T) {
	containerID := strings.Repeat("c", 64)
	fake := &fakeExecutor{
		handler: func(
			_ context.Context,
			_ string,
			_ []string,
			stdout io.Writer,
			stderr io.Writer,
		) (int, error) {
			_, _ = io.WriteString(
				stdout,
				`{"id":"`+containerID+`","runLabel":"test1234"}`,
			)
			_, _ = io.WriteString(stderr, "untrusted warning")
			return 0, nil
		},
	}
	err := testRunner(fake).inspectResourceContainerIdentity(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			RunID:   "test1234",
			Plan:    domain.ResolvedPlan{},
		}),
		containerID,
	)
	if err == nil {
		t.Fatal("dirty container identity stderr was accepted")
	}
}

func TestInspectResourceContainerIdentityRejectsBindingBeforeExecutor(
	t *testing.T,
) {
	tests := []struct {
		name        string
		prepared    *PreparedRun
		containerID string
	}{
		{
			name:        "nil prepared run",
			containerID: strings.Repeat("c", 64),
		},
		{
			name: "unsafe run id",
			prepared: sealPreparedRunForTest(&PreparedRun{
				Backend: "docker",
				RunID:   "../unsafe",
				Plan:    domain.ResolvedPlan{},
			}),
			containerID: strings.Repeat("c", 64),
		},
		{
			name: "unsafe container id",
			prepared: sealPreparedRunForTest(&PreparedRun{
				Backend: "docker",
				RunID:   "test1234",
				Plan:    domain.ResolvedPlan{},
			}),
			containerID: "--help",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeExecutor{}
			err := testRunner(fake).inspectResourceContainerIdentity(
				context.Background(),
				test.prepared,
				test.containerID,
			)
			if err == nil {
				t.Fatal("untrusted identity binding was accepted")
			}
			if calls := fake.snapshotCalls(); len(calls) != 0 {
				t.Fatalf(
					"untrusted identity binding reached executor: %#v",
					calls,
				)
			}
		})
	}
}

func TestExecutePublishesFrozenHighResourceObservation(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("ok\n"),
	)
	plan := testPlan(t, sourceRoot)
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"resource-usage-observation",
	)
	var operations []string
	resourceCalls := 0
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		operations = append(operations, "workload")
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
		case containsArgument(args, nodeLinuxResourceScript):
			resourceCalls++
			operations = append(
				operations,
				map[bool]string{
					true:  "resource-final",
					false: "resource-active",
				}[resourceCalls == 2],
			)
		case containsArgument(args, nodeWorkloadQuiesceScript):
			operations = append(operations, "quiesce")
		case containsArgument(args, nodeOutputRepairScript):
			operations = append(operations, "repair")
		case isTarExportArgs(args):
			operations = append(operations, "export")
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
		t.Fatal(err)
	}
	if outcome.Runner.ResourceUsage != "high" ||
		!outcome.Runner.ResourceLimitEnforcement ||
		slices.Contains(
			outcome.IncompleteFeatures,
			"resource-usage-observation",
		) {
		t.Fatalf(
			"runner resource coverage = %#v incomplete=%v",
			outcome.Runner,
			outcome.IncompleteFeatures,
		)
	}
	if outcome.Resources.PeakMemoryBytes != 0 ||
		outcome.Resources.CPUTimeMillis != 0 ||
		outcome.Resources.MaxProcesses != 0 ||
		outcome.Resources.SandboxCPUTimeMillis != 2 ||
		outcome.Resources.SandboxPeakMemoryBytes != 1<<20 ||
		outcome.Resources.MaxTasks != 4 ||
		outcome.Resources.WritableBytes != 0 ||
		outcome.Resources.OutputBytes != 0 {
		t.Fatalf("resource summary = %#v", outcome.Resources)
	}
	wantFields := []domain.ResourceObservedField{
		domain.ResourceObservedMaxTasks,
		domain.ResourceObservedOutputBytes,
		domain.ResourceObservedSandboxCPUTimeMillis,
		domain.ResourceObservedSandboxPeakMemoryBytes,
		domain.ResourceObservedWritableBytes,
	}
	if !slices.Equal(outcome.Resources.ObservedFields, wantFields) {
		t.Fatalf(
			"observed fields = %v, want %v",
			outcome.Resources.ObservedFields,
			wantFields,
		)
	}
	if got := strings.Join(operations, ","); got !=
		"resource-active,workload,quiesce,resource-final,repair,export" {
		t.Fatalf("resource freeze ordering = %s", got)
	}
	var observation *domain.ObservationEvent
	var exportObservation *domain.ObservationEvent
	for index := range outcome.Observations {
		if outcome.Observations[index].Operation == "resource.usage" {
			observation = &outcome.Observations[index]
		}
		if outcome.Observations[index].Operation == "sandbox.outputs.export" {
			exportObservation = &outcome.Observations[index]
		}
	}
	if exportObservation == nil || exportObservation.Resource != containerOutputs {
		t.Fatalf("public export observation = %#v", exportObservation)
	}
	if observation == nil ||
		observation.Result != "observed" ||
		observation.Coverage != "high" ||
		observation.Resource != "sandbox" ||
		observation.Details["scope"] != "sandbox-cgroup" ||
		observation.Details["cpuUsageUsec"] != int64(2000) ||
		observation.Details["cgroupVersion"] != 2 ||
		observation.Details["memoryMaxBytes"] != int64(256<<20) ||
		observation.Details["memorySwapMaxBytes"] != int64(0) ||
		observation.Details["pidsMax"] != 64 ||
		observation.Details["cpuQuotaMicros"] != int64(100000) ||
		observation.Details["cpuPeriodMicros"] != int64(100000) ||
		observation.Details["writableLimitBytes"] != int64(1<<30) ||
		observation.Details["writableBlockSize"] != int64(4096) ||
		observation.Details["memoryOOMEvents"] != int64(0) ||
		observation.Details["memoryOOMKillEvents"] != int64(0) ||
		observation.Details["pidsLimitEvents"] != int64(0) {
		t.Fatalf("resource observation = %#v", observation)
	}
	encodedObservation, _ := json.Marshal(observation)
	if bytes.Contains(encodedObservation, []byte(strings.Repeat("a", 64))) {
		t.Fatalf("resource observation leaked immutable container ID: %s", encodedObservation)
	}
}

func TestExecuteBlocksWorkloadOnResourcePreflightMismatch(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("ok\n"),
	)
	workloadCalled := false
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
		if containsArgument(args, nodeLinuxResourceScript) {
			_, _ = io.WriteString(
				stdout,
				strings.Replace(
					validLinuxResourceControl,
					`"memorySwapMaxBytes":0`,
					`"memorySwapMaxBytes":1`,
					1,
				),
			)
			return 0, nil
		}
		return base(ctx, name, args, stdout, stderr)
	}
	plan := testPlan(t, sourceRoot)
	plan.ObserverSet = []string{"resource-usage"}
	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if domain.ErrorCodeOf(err) != domain.CodeObserverStartFailed ||
		workloadCalled ||
		outcome.Runner.ResourceLimitEnforcement ||
		outcome.Runner.ResourceUsage != "unavailable" {
		t.Fatalf(
			"preflight outcome err=%v workload=%v runner=%#v",
			err,
			workloadCalled,
			outcome.Runner,
		)
	}
}

func TestExecuteFinalResourceFailureKeepsCleanupAndExport(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("ok\n"),
	)
	resourceCalls := 0
	exportCalled := false
	base := successfulNodeSandbox(nil)
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if containsArgument(args, nodeLinuxResourceScript) {
			resourceCalls++
			if resourceCalls == 2 {
				_, _ = io.WriteString(stdout, `{"ok":true}`)
				return 0, nil
			}
		}
		if isTarExportArgs(args) {
			exportCalled = true
		}
		return base(ctx, name, args, stdout, stderr)
	}
	plan := testPlan(t, sourceRoot)
	plan.ObserverSet = []string{"resource-usage"}
	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if domain.ErrorCodeOf(err) != domain.CodeObserverIncomplete ||
		outcome.Cleanup != domain.CleanupClean ||
		!exportCalled ||
		outcome.Runner.ResourceUsage != "unavailable" ||
		!outcome.Runner.ResourceLimitEnforcement {
		t.Fatalf(
			"final observer outcome err=%v cleanup=%s export=%v runner=%#v",
			err,
			outcome.Cleanup,
			exportCalled,
			outcome.Runner,
		)
	}
	if _, statErr := os.Stat(outcome.OutputsDir); statErr != nil {
		t.Fatalf("validated outputs were not preserved: %v", statErr)
	}
}
