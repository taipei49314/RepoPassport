package execution

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestTrustedPythonHelpersCannotLoadRepositoryModules(t *testing.T) {
	adversarialWorkspace := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(adversarialWorkspace, "sitecustomize.py"),
		[]byte("raise RuntimeError('executed sitecustomize')\n"),
	)
	mustWriteFile(
		t,
		filepath.Join(adversarialWorkspace, "json.py"),
		[]byte("raise RuntimeError('executed forged json')\n"),
	)
	prepared := sealPreparedRunForTest(&PreparedRun{
		RunID:        "security",
		Backend:      "docker",
		WorkspaceDir: adversarialWorkspace,
		Plan: domain.ResolvedPlan{
			RuntimeAdapter: "python",
		},
	})
	fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
	fake.handler = func(
		_ context.Context,
		_ string,
		args []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		switch {
		case containsArgument(args, pythonOutputInitScript),
			containsArgument(args, pythonOutputRepairScript),
			containsArgument(args, pythonWorkloadQuiesceScript):
			assertIsolatedPythonHelper(t, args)
		case containsArgument(args, pythonWorkloadIdentityScript):
			assertIsolatedPythonHelper(t, args)
			_, _ = io.WriteString(
				stdout,
				`{"uid":65532,"euid":65532,"gid":65532,"egid":65532,`+
					`"capInh":"0","capPrm":"0","capEff":"0","capAmb":"0",`+
					`"noNewPrivs":1}`+"\n",
			)
		case containsArgument(args, pythonServiceSignalScript):
			assertIsolatedPythonHelper(t, args)
			if !containsAdjacent(args, "--user", "0:0") {
				t.Fatalf("signal helper is not root-scoped: %v", args)
			}
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"escalated":false,"remaining":0,`+
					`"initialTargets":1,"sent":1}`+"\n",
			)
		case containsArgument(args, pythonHTTPFileLstatScript):
			assertIsolatedPythonHelper(t, args)
			if !containsAdjacent(args, "--user", "0:0") {
				t.Fatalf("lstat helper is not root-scoped: %v", args)
			}
			_, _ = io.WriteString(stdout, `{"status":"exists"}`+"\n")
		case containsArgument(args, pythonHTTPDriverQuiesceScript):
			assertIsolatedPythonHelper(t, args)
			if !containsAdjacent(args, "--user", "0:0") {
				t.Fatalf("driver cleanup helper is not root-scoped: %v", args)
			}
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"remaining":0,"killed":0}`+"\n",
			)
		default:
			t.Fatalf("unexpected helper command: %v", args)
		}
		return 0, nil
	}
	fake.inputHandler = func(
		_ context.Context,
		_ string,
		args []string,
		_ []byte,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if !containsArgument(args, pythonHTTPHelperScript) {
			t.Fatalf("unexpected stdin helper command: %v", args)
		}
		assertIsolatedPythonHelper(t, args)
		_, _ = io.WriteString(
			stdout,
			`{"ok":true,"status":200,"headers":[],"bodyBase64":"",`+
				`"bodyBytes":0,"bodyTruncated":false,"durationMillis":1}`+"\n",
		)
		return 0, nil
	}
	runner := testRunner(fake)

	if err := runner.initializeOutputDirectories(
		context.Background(),
		prepared,
		"container",
	); err != nil {
		t.Fatal(err)
	}
	if err := runner.repairOutputPermissions(
		context.Background(),
		prepared,
		"container",
	); err != nil {
		t.Fatal(err)
	}
	if err := runner.quiesceWorkloadProcesses(
		context.Background(),
		prepared,
		"container",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.verifyWorkloadIdentity(
		context.Background(),
		prepared,
		"container",
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runner.signalService(
		context.Background(),
		prepared,
		"container",
		domain.PlanCommand{
			ID: "stop", Role: "signal",
			Signal: &domain.PlanSignal{
				Target: "app", Type: "term", GracePeriod: "1ms",
			},
		},
		false,
	); err != nil {
		t.Fatal(err)
	}
	fileResult := runner.inspectHTTPFileAssertion(
		context.Background(),
		prepared,
		"container",
		domain.PlanAssertion{
			ID: "file", FileExists: "/outputs/result.json",
		},
	)
	if fileResult.Status != "passed" {
		t.Fatalf("file helper result = %#v", fileResult)
	}
	if _, err := runner.runTrustedHTTPRequest(
		context.Background(),
		prepared,
		"container",
		trustedHTTPRequest{
			ID: "request", Method: "GET",
			URL:     "http://127.0.0.1:8080/",
			Timeout: time.Second,
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := runner.quiesceHTTPDriverProcesses(
		context.Background(),
		prepared,
		"container",
	); err != nil {
		t.Fatal(err)
	}

	idle := idleRuntimeArgs("python")
	if len(idle) < 4 ||
		idle[0] != "-I" ||
		idle[1] != "-S" ||
		idle[2] != "-c" {
		t.Fatalf("Python supervisor is not isolated: %v", idle)
	}
}

func TestNodeTrustedEnvironmentAndHelperWorkingDirectoryAreFixed(
	t *testing.T,
) {
	prepared := sealPreparedRunForTest(&PreparedRun{
		RunID:             "security",
		Backend:           "docker",
		SourceSnapshotDir: "source",
		WorkspaceDir:      "workspace",
		Plan: domain.ResolvedPlan{
			RuntimeAdapter:     "node",
			BaseImageReference: "image",
			Resources: domain.ResourceLimits{
				CPUMillis: 1000, MemoryBytes: 1 << 20,
				DiskBytes: 1 << 20, PIDs: 8,
			},
		},
	})
	args := testRunner(&fakeExecutor{}).buildCreateArgs(
		prepared,
		"container",
	)
	for _, value := range []string{
		"NODE_OPTIONS=",
		"NODE_PATH=",
		"PYTHONPATH=",
		"PYTHONHOME=",
	} {
		if !containsAdjacent(args, "--env", value) {
			t.Fatalf("container environment omitted %q: %v", value, args)
		}
	}
	if !containsAdjacent(args, "--workdir", trustedHelperWorkdir) {
		t.Fatalf("trusted supervisor workdir is not fixed: %v", args)
	}
	for name, script := range map[string]string{
		"http":   nodeHTTPHelperScript,
		"signal": nodeServiceSignalScript,
		"lstat":  nodeHTTPFileLstatScript,
	} {
		if !strings.Contains(script, `require("node:`) {
			t.Fatalf("%s helper imports a non-builtin module: %s", name, script)
		}
	}
}

func TestHTTPFileLstatScriptsUseHeldDirectoryDescriptors(t *testing.T) {
	for name, checks := range map[string]struct {
		script string
		want   []string
	}{
		"node": {
			script: nodeHTTPFileLstatScript,
			want: []string{
				"O_NOFOLLOW",
				"O_DIRECTORY",
				"/proc/self/fd/",
				"lstatSync",
			},
		},
		"python": {
			script: pythonHTTPFileLstatScript,
			want: []string{
				"O_NOFOLLOW",
				"O_DIRECTORY",
				"dir_fd=parent",
				"follow_symlinks=False",
			},
		},
	} {
		for _, wanted := range checks.want {
			if !strings.Contains(checks.script, wanted) {
				t.Fatalf(
					"%s lstat helper lacks %q dirfd defense",
					name,
					wanted,
				)
			}
		}
	}
}

func TestHTTPHelpersEnforceAbsoluteWallDeadlineAndCleanResidue(
	t *testing.T,
) {
	for name, checks := range map[string]struct {
		script string
		want   []string
	}{
		"node": {
			script: nodeHTTPHelperScript,
			want: []string{
				"const wallTimer=setTimeout",
				"clearTimeout(wallTimer)",
			},
		},
		"python": {
			script: pythonHTTPHelperScript,
			want: []string{
				"signal.setitimer(signal.ITIMER_REAL",
				"signal.SIGALRM",
			},
		},
	} {
		for _, wanted := range checks.want {
			if !strings.Contains(checks.script, wanted) {
				t.Fatalf(
					"%s HTTP helper lacks absolute watchdog %q",
					name,
					wanted,
				)
			}
		}
	}

	t.Run("confirmed clean", func(t *testing.T) {
		cleanupCalled := false
		fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
		fake.inputHandler = func(
			_ context.Context,
			_ string,
			_ []string,
			_ []byte,
			_ io.Writer,
			_ io.Writer,
		) (int, error) {
			return -1, errors.New("slow-drip deadline")
		}
		fake.handler = func(
			_ context.Context,
			_ string,
			args []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			if !containsArgument(args, nodeHTTPDriverQuiesceScript) {
				t.Fatalf("unexpected residue helper: %v", args)
			}
			cleanupCalled = true
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"remaining":0,"killed":1}`+"\n",
			)
			return 0, nil
		}
		_, err := testRunner(fake).runTrustedHTTPRequest(
			context.Background(),
			sealPreparedRunForTest(&PreparedRun{
				Backend: "docker",
				Plan: domain.ResolvedPlan{
					RuntimeAdapter: "node",
				},
			}),
			"container",
			trustedHTTPRequest{
				ID: "slow", Method: "GET",
				URL:     "http://127.0.0.1:8080/slow-drip",
				Timeout: 10 * time.Millisecond,
			},
		)
		if err == nil || !cleanupCalled ||
			errors.Is(err, errHTTPDriverResidue) {
			t.Fatalf(
				"confirmed cleanup err=%v called=%v",
				err,
				cleanupCalled,
			)
		}
	})

	t.Run("uncertain residue", func(t *testing.T) {
		fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
		fake.inputHandler = func(
			_ context.Context,
			_ string,
			_ []string,
			_ []byte,
			_ io.Writer,
			_ io.Writer,
		) (int, error) {
			return -1, errors.New("host exec deadline")
		}
		_, err := testRunner(fake).runTrustedHTTPRequest(
			context.Background(),
			sealPreparedRunForTest(&PreparedRun{
				Backend: "docker",
				Plan: domain.ResolvedPlan{
					RuntimeAdapter: "node",
				},
			}),
			"container",
			trustedHTTPRequest{
				ID: "slow", Method: "GET",
				URL:     "http://127.0.0.1:8080/slow-drip",
				Timeout: 10 * time.Millisecond,
			},
		)
		if !errors.Is(err, errHTTPDriverResidue) {
			t.Fatalf(
				"uncertain driver residue did not fail closed: %v",
				err,
			)
		}
	})
}

func TestUnreachedOrderedHTTPResponseAssertionStaysBlocked(
	t *testing.T,
) {
	expectedFailure := 500
	expectedLater := 200
	prepared := sealPreparedRunForTest(&PreparedRun{
		Backend: "docker",
		Plan: domain.ResolvedPlan{
			RuntimeAdapter: "node",
			HTTPJourney: &domain.PlanHTTPJourney{
				ServiceID: "app",
				Steps: []domain.PlanHTTPDriverStep{
					{Request: &domain.PlanHTTPRequest{
						ID: "a", Method: "get",
						URL:     "http://127.0.0.1:8080/a",
						Timeout: "1s",
					}},
					{AssertionID: "a-fails"},
					{Request: &domain.PlanHTTPRequest{
						ID: "b", Method: "get",
						URL:     "http://127.0.0.1:8080/b",
						Timeout: "1s",
					}},
					{AssertionID: "b-unreached"},
				},
			},
			JourneyAssertions: []domain.PlanAssertion{
				{
					ID: "a-fails",
					Response: &domain.PlanHTTPResponseAssertion{
						RequestID: "a", Status: &expectedFailure,
					},
				},
				{
					ID: "b-unreached",
					Response: &domain.PlanHTTPResponseAssertion{
						RequestID: "b", Status: &expectedLater,
					},
				},
			},
		},
	})
	fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
	fake.inputHandler = func(
		_ context.Context,
		_ string,
		_ []string,
		_ []byte,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		_, _ = io.WriteString(
			stdout,
			`{"ok":true,"status":200,"headers":[],"bodyBase64":"",`+
				`"bodyBytes":0,"bodyTruncated":false,"durationMillis":1}`+"\n",
		)
		return 0, nil
	}
	runner := testRunner(fake)
	service := &runningService{
		command: domain.PlanCommand{ID: "app"},
		cancel:  func() {},
		done:    make(chan stepExecution, 1),
	}
	_, snapshots, _, driverStarted, journeyErr := runner.executeHTTPJourney(
		context.Background(),
		prepared,
		"container",
		service,
	)
	if !driverStarted {
		t.Fatal("invoked trusted HTTP helper was not reported as started")
	}
	if got := domain.ErrorCodeOf(journeyErr); got !=
		domain.CodeJourneyAssertionFailed {
		t.Fatalf("first assertion error = %q: %v", got, journeyErr)
	}
	results := evaluateHTTPJourneyAssertions(prepared, snapshots)
	if len(results) != 2 ||
		results[0].Status != "failed" ||
		results[1].Status != "blocked" {
		t.Fatalf("ordered assertion replay = %#v", results)
	}
}

func TestOrderedHTTPFileSnapshotIgnoresFileCreatedAfterSignal(
	t *testing.T,
) {
	outputs := t.TempDir()
	prepared := sealPreparedRunForTest(&PreparedRun{
		RunID:      "ordered",
		OutputsDir: outputs,
		Plan: domain.ResolvedPlan{
			HTTPJourney: &domain.PlanHTTPJourney{
				Steps: []domain.PlanHTTPDriverStep{
					{AssertionID: "file-at-step"},
				},
			},
			JourneyAssertions: []domain.PlanAssertion{{
				ID: "file-at-step", FileExists: "/outputs/result.json",
			}},
		},
	})
	atStep := domain.AssertionResult{
		SchemaVersion: "1",
		ID:            "file-at-step",
		Type:          "file-exists",
		Required:      true,
		Expected:      true,
		Actual:        false,
		Status:        "failed",
		EvidenceRefs:  []string{"http-assertion:file-at-step:lstat"},
	}
	mustWriteFile(
		t,
		filepath.Join(outputs, "result.json"),
		[]byte(`{"created":"during signal"}`),
	)
	results := evaluateHTTPJourneyAssertions(
		prepared,
		map[string]domain.AssertionResult{"file-at-step": atStep},
	)
	if len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf(
			"post-signal host file changed ordered snapshot: %#v",
			results,
		)
	}
}

func TestSignalServiceQuiescentNoOpContract(t *testing.T) {
	validZero := `{"ok":true,"escalated":false,"remaining":0,` +
		`"initialTargets":0,"sent":0}`
	validObservedRace := `{"ok":true,"escalated":false,"remaining":0,` +
		`"initialTargets":2,"sent":0}`
	tests := []struct {
		name         string
		envelope     string
		stderr       string
		authorized   bool
		exitCode     int
		controlBytes int64
		wantAccepted bool
		wantInitial  int
	}{
		{
			name: "authorized initial zero", envelope: validZero,
			authorized: true, wantAccepted: true,
		},
		{
			name: "authorized observed target race", envelope: validObservedRace,
			authorized: true, wantAccepted: true, wantInitial: 2,
		},
		{name: "unauthorized initial zero", envelope: validZero},
		{name: "unauthorized observed target race", envelope: validObservedRace},
		{
			name: "negative initial", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":0,` +
				`"initialTargets":-1,"sent":0}`,
		},
		{
			name: "negative sent", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":0,` +
				`"initialTargets":1,"sent":-1}`,
		},
		{
			name: "sent exceeds initial", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":0,` +
				`"initialTargets":1,"sent":2}`,
		},
		{
			name: "negative remaining", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":-1,` +
				`"initialTargets":0,"sent":0}`,
		},
		{
			name: "remaining target", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":1,` +
				`"initialTargets":1,"sent":0}`,
		},
		{
			name: "escalated no-op", authorized: true,
			envelope: `{"ok":true,"escalated":true,"remaining":0,` +
				`"initialTargets":1,"sent":0}`,
		},
		{
			name: "false ok", authorized: true,
			envelope: `{"ok":false,"escalated":false,"remaining":0,` +
				`"initialTargets":0,"sent":0}`,
		},
		{
			name: "missing ok", authorized: true,
			envelope: `{"escalated":false,"remaining":0,` +
				`"initialTargets":0,"sent":0}`,
		},
		{
			name: "missing count", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":0,` +
				`"sent":0}`,
		},
		{
			name: "null count", authorized: true,
			envelope: `{"ok":true,"escalated":false,"remaining":0,` +
				`"initialTargets":null,"sent":0}`,
		},
		{
			name: "unknown key", authorized: true,
			envelope: strings.TrimSuffix(validZero, "}") + `,"extra":0}`,
		},
		{
			name: "duplicate key", authorized: true,
			envelope: strings.Replace(validZero, `"ok":true`,
				`"ok":true,"ok":true`, 1),
		},
		{
			name: "trailing object", authorized: true,
			envelope: validZero + `{}`,
		},
		{
			name: "truncated JSON", authorized: true,
			envelope: strings.TrimSuffix(validZero, "}"),
		},
		{
			name: "nonzero helper exit", authorized: true,
			envelope: validZero, exitCode: 9,
		},
		{
			name: "stdout truncation", authorized: true,
			envelope: validZero, controlBytes: 32,
		},
		{
			name: "nonempty stderr", authorized: true,
			envelope: validZero, stderr: "unexpected warning",
		},
		{
			name: "stderr truncation", authorized: true,
			envelope: validZero, stderr: strings.Repeat("x", 64),
			controlBytes: 32,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantAuthorization := "false"
			if test.authorized {
				wantAuthorization = "true"
			}
			fake := &fakeExecutor{
				handler: func(
					_ context.Context,
					_ string,
					args []string,
					stdout io.Writer,
					stderr io.Writer,
				) (int, error) {
					if len(args) == 0 || args[len(args)-1] != wantAuthorization {
						t.Fatalf("authorization argv = %v", args)
					}
					_, _ = io.WriteString(stdout, test.envelope+"\n")
					_, _ = io.WriteString(stderr, test.stderr)
					return test.exitCode, nil
				},
			}
			runner := testRunner(fake)
			if test.controlBytes > 0 {
				runner.config.DoctorOutputBytes = test.controlBytes
			}
			helper, result, err := runner.signalService(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan: domain.ResolvedPlan{
						RuntimeAdapter: "node",
					},
				}),
				"container",
				domain.PlanCommand{
					ID: "stop", Role: "signal",
					Signal: &domain.PlanSignal{
						Target: "app", Type: "term", GracePeriod: "1ms",
					},
				},
				test.authorized,
			)
			if test.wantAccepted {
				if err != nil || !helper.AlreadyExited ||
					helper.InitialTargets != test.wantInitial ||
					helper.Sent != 0 || result.ExitCode != 0 {
					t.Fatalf(
						"accepted no-op helper=%#v result=%#v err=%v",
						helper,
						result,
						err,
					)
				}
			} else if err == nil {
				t.Fatalf("invalid signal response was accepted: %#v", helper)
			}
		})
	}
}

func TestSignalServiceRejectsZeroInitialTargets(t *testing.T) {
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
				`{"ok":true,"escalated":false,"remaining":0,`+
					`"initialTargets":0,"sent":0}`+"\n",
			)
			return 0, nil
		},
	}
	_, _, err := testRunner(fake).signalService(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan: domain.ResolvedPlan{
				RuntimeAdapter: "node",
			},
		}),
		"container",
		domain.PlanCommand{
			ID: "stop", Role: "signal",
			Signal: &domain.PlanSignal{
				Target: "app", Type: "term", GracePeriod: "1ms",
			},
		},
		false,
	)
	if err == nil {
		t.Fatal("unauthorized zero-target signal was accepted")
	}
}

func TestHTTPPlanRequiresFinalSignalAndBoundedGrace(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "server.js"),
		[]byte("server fixture\n"),
	)
	base := testHTTPPlan(t, sourceRoot)

	t.Run("signal is final", func(t *testing.T) {
		plan := clonePlan(base)
		plan.Commands = append(
			plan.Commands,
			domain.PlanCommand{
				Phase: domain.PhaseCleanup,
				ID:    "after-signal",
				Argv:  []string{"node", "-e", "0"},
				Role:  "foreground", Timeout: "1s",
			},
		)
		if err := testRunner(&fakeExecutor{}).
			validateHTTPPlan(plan); err == nil {
			t.Fatal("non-final service signal was accepted")
		}
	})

	t.Run("grace boundary", func(t *testing.T) {
		config := DefaultConfig()
		config.CleanupTimeout = 2 * time.Second
		runner := NewRunner(&fakeExecutor{}, config)
		maximum := config.CleanupTimeout - serviceSignalHelperSlack

		atBoundary := clonePlan(base)
		atBoundary.Commands[len(atBoundary.Commands)-1].
			Signal.GracePeriod = maximum.String()
		if err := runner.validateHTTPPlan(atBoundary); err != nil {
			t.Fatalf("maximum bounded grace was rejected: %v", err)
		}

		overBoundary := clonePlan(base)
		overBoundary.Commands[len(overBoundary.Commands)-1].
			Signal.GracePeriod = (maximum + time.Nanosecond).String()
		if err := runner.validateHTTPPlan(overBoundary); err == nil {
			t.Fatal("grace exceeding cleanup window was accepted")
		}
	})
}

func assertIsolatedPythonHelper(t *testing.T, args []string) {
	t.Helper()
	if !containsAdjacent(args, "--workdir", trustedHelperWorkdir) {
		t.Fatalf("Python helper runs in an untrusted workdir: %v", args)
	}
	index := -1
	for candidate, value := range args {
		if value == "python" {
			index = candidate
			break
		}
	}
	if index < 0 ||
		index+3 >= len(args) ||
		args[index+1] != "-I" ||
		args[index+2] != "-S" ||
		args[index+3] != "-c" {
		t.Fatalf("Python helper lacks -I -S isolation: %v", args)
	}
}
