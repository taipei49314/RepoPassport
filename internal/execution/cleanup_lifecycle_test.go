package execution

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func TestCleanupResidueLifecycleUsesImmutableIdentityInLockedOrder(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("console.log('ok')\n"),
	)
	plan := testPlan(t, sourceRoot)
	plan.Cleanup.AllowedResidue = []string{"/outputs/**"}

	base := successfulNodeSandbox(nil)
	fake := &fakeExecutor{}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if containsArgument(args, nodeCleanupInventoryScript) {
			_, _ = io.WriteString(
				stdout,
				cleanupInventoryControl(
					`{"path":"result.json","type":"file","mode":420}`,
				),
			)
			return 0, nil
		}
		return base(ctx, name, args, stdout, stderr)
	}

	runner := testRunner(fake)
	prepared, err := runner.Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	outcome, err := runner.Run(context.Background(), prepared)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.Cleanup != domain.CleanupAllowedResidue {
		t.Fatalf(
			"cleanup = %q, want %q",
			outcome.Cleanup,
			domain.CleanupAllowedResidue,
		)
	}
	observation := cleanupObservationFromOutcome(t, outcome)
	assertCleanupBoundaryFlags(
		t,
		observation,
		true,
		true,
		true,
		true,
	)
	if observation.Details["allowedProfile"] != "outputs-descendants" ||
		observation.Details["allowedPatternCount"] != 1 {
		t.Fatalf(
			"allowed profile details = %#v",
			observation.Details,
		)
	}

	containerID := strings.Repeat("a", 64)
	calls := fake.snapshotCalls()
	repair := cleanupCallIndex(calls, func(args []string) bool {
		return containsArgument(args, nodeOutputRepairScript)
	})
	disposable := cleanupCallIndex(calls, func(args []string) bool {
		return containsArgument(args, nodeCleanupDisposableScript)
	})
	identity := cleanupCallIndex(calls, func(args []string) bool {
		return len(args) > 0 && args[0] == "inspect" &&
			containsArgument(args, resourceContainerIdentityFormat)
	})
	inventory := cleanupCallIndex(calls, func(args []string) bool {
		return containsArgument(args, nodeCleanupInventoryScript)
	})
	export := cleanupCallIndex(calls, isTarExportArgs)
	remove := cleanupCallIndex(calls, func(args []string) bool {
		return len(args) == 3 &&
			args[0] == "rm" &&
			args[1] == "-f" &&
			args[2] == containerID
	})
	if disposable < 0 || identity <= disposable ||
		inventory <= identity || repair <= inventory ||
		export <= repair || remove <= export {
		t.Fatalf(
			"cleanup order repair=%d disposable=%d identity=%d inventory=%d export=%d remove=%d",
			repair,
			disposable,
			identity,
			inventory,
			export,
			remove,
		)
	}
	for _, index := range []int{repair, disposable, inventory, export} {
		if !containsArgument(calls[index].args, containerID) {
			t.Fatalf(
				"post-quiescence helper did not use immutable ID: %#v",
				calls[index].args,
			)
		}
	}
	quiesce := cleanupCallIndex(calls, func(args []string) bool {
		return containsArgument(args, nodeWorkloadQuiesceScript)
	})
	if quiesce < 0 || !containsArgument(calls[quiesce].args, containerID) {
		t.Fatalf(
			"quiescence did not use immutable ID: %#v",
			calls,
		)
	}
}

func TestCleanupResiduePreconditionFailuresSkipInventoryAndExport(
	t *testing.T,
) {
	tests := []struct {
		name             string
		failRepair       bool
		failDisposable   bool
		failIdentity     bool
		failInventory    bool
		failRandom       bool
		wantDisposable   bool
		wantIdentity     bool
		wantInventory    bool
		wantRepair       bool
		wantFailureClass string
	}{
		{
			name:           "permission repair",
			failRepair:     true,
			wantDisposable: true,
			wantIdentity:   true,
			wantInventory:  true,
			wantRepair:     true,
		},
		{
			name:             "disposable removal",
			failDisposable:   true,
			wantFailureClass: "disposable-removal-failed",
		},
		{
			name:             "identity readback",
			failIdentity:     true,
			wantDisposable:   true,
			wantFailureClass: "container-identity-readback-failed",
		},
		{
			name:             "inventory decode",
			failInventory:    true,
			wantDisposable:   true,
			wantIdentity:     true,
			wantFailureClass: "invalid-control",
		},
		{
			name:             "opaque token randomness",
			failRandom:       true,
			wantDisposable:   true,
			wantIdentity:     true,
			wantInventory:    true,
			wantFailureClass: "random-unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			mustWriteFile(
				t,
				filepath.Join(sourceRoot, "app.js"),
				[]byte("console.log('ok')\n"),
			)
			plan := testPlan(t, sourceRoot)
			plan.Cleanup.AllowedResidue = []string{"/outputs/**"}
			base := successfulNodeSandbox(nil)
			fake := &fakeExecutor{}
			inventoryCalled := false
			repairCalled := false
			exportCalled := false
			fake.handler = func(
				ctx context.Context,
				name string,
				args []string,
				stdout io.Writer,
				stderr io.Writer,
			) (int, error) {
				if containsArgument(args, nodeOutputRepairScript) {
					repairCalled = true
				}
				switch {
				case containsArgument(args, nodeOutputRepairScript) &&
					test.failRepair:
					return 1, errors.New("repair failed")
				case containsArgument(
					args,
					nodeCleanupDisposableScript,
				) && test.failDisposable:
					return 1, errors.New("disposable failed")
				case len(args) > 0 && args[0] == "inspect" &&
					containsArgument(
						args,
						resourceContainerIdentityFormat,
					) && test.failIdentity:
					_, _ = io.WriteString(
						stdout,
						`{"id":"`+
							strings.Repeat("a", 64)+
							`","runLabel":"wrong"}`+"\n",
					)
					return 0, nil
				case containsArgument(
					args,
					nodeCleanupInventoryScript,
				):
					inventoryCalled = true
					if test.failInventory {
						_, _ = io.WriteString(stdout, "{}\n")
						return 0, nil
					}
					_, _ = io.WriteString(
						stdout,
						cleanupInventoryControl(""),
					)
					return 0, nil
				case isTarExportArgs(args):
					exportCalled = true
				}
				return base(ctx, name, args, stdout, stderr)
			}

			runner := testRunner(fake)
			if test.failRandom {
				runner.cleanupTokenKeyReader = strings.NewReader("")
			}
			prepared, err := runner.Prepare(
				context.Background(),
				plan,
				sourceRoot,
				t.TempDir(),
				"docker",
			)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			outcome, runErr := runner.Run(
				context.Background(),
				prepared,
			)
			if domain.ErrorCodeOf(runErr) != domain.CodeCleanupFailed {
				t.Fatalf(
					"Run error = %v, want %s",
					runErr,
					domain.CodeCleanupFailed,
				)
			}
			if outcome.Cleanup != domain.CleanupNotTested {
				t.Fatalf(
					"cleanup = %q, want not-tested",
					outcome.Cleanup,
				)
			}
			wantInventoryCall := test.wantInventory ||
				test.failInventory
			if inventoryCalled != wantInventoryCall ||
				repairCalled != test.wantRepair ||
				exportCalled {
				t.Fatalf(
					"failed boundary continued: inventory=%t wantInventory=%t repair=%t wantRepair=%t export=%t",
					inventoryCalled,
					wantInventoryCall,
					repairCalled,
					test.wantRepair,
					exportCalled,
				)
			}
			observation := cleanupObservationFromOutcome(t, outcome)
			assertCleanupBoundaryFlags(
				t,
				observation,
				true,
				test.wantDisposable,
				test.wantIdentity,
				test.wantInventory,
			)
			if observation.Details["failure"] != test.wantFailureClass &&
				!(test.wantFailureClass == "" &&
					observation.Details["failure"] == nil) {
				t.Fatalf(
					"failure = %#v, want %q",
					observation.Details["failure"],
					test.wantFailureClass,
				)
			}
			containerID := strings.Repeat("a", 64)
			if cleanupCallIndex(
				fake.snapshotCalls(),
				func(args []string) bool {
					return len(args) == 3 &&
						args[0] == "rm" &&
						args[1] == "-f" &&
						args[2] == containerID
				},
			) < 0 {
				t.Fatal("forced immutable-ID removal was not attempted")
			}
		})
	}
}

func TestCleanupUndeclaredResidueSurvivesDestroyFailure(t *testing.T) {
	for _, failDestroy := range []bool{false, true} {
		name := "destroy succeeds"
		if failDestroy {
			name = "destroy fails"
		}
		t.Run(name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			mustWriteFile(
				t,
				filepath.Join(sourceRoot, "app.js"),
				[]byte("console.log('ok')\n"),
			)
			plan := testPlan(t, sourceRoot)
			base := successfulNodeSandbox(nil)
			fake := &fakeExecutor{}
			exportCalled := false
			repairCalled := false
			fake.handler = func(
				ctx context.Context,
				name string,
				args []string,
				stdout io.Writer,
				stderr io.Writer,
			) (int, error) {
				if containsArgument(args, nodeOutputRepairScript) {
					repairCalled = true
				}
				if containsArgument(args, nodeCleanupInventoryScript) {
					_, _ = io.WriteString(
						stdout,
						cleanupInventoryControl(
							`{"path":"escape-link","type":"symlink","mode":511},`+
								`{"path":"leak.json","type":"file","mode":420}`,
						),
					)
					return 0, nil
				}
				if isTarExportArgs(args) {
					exportCalled = true
				}
				if failDestroy && len(args) == 3 &&
					args[0] == "rm" &&
					args[1] == "-f" {
					return 1, errors.New("destroy failed")
				}
				return base(ctx, name, args, stdout, stderr)
			}

			runner := testRunner(fake)
			prepared, err := runner.Prepare(
				context.Background(),
				plan,
				sourceRoot,
				t.TempDir(),
				"docker",
			)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			outcome, runErr := runner.Run(
				context.Background(),
				prepared,
			)
			if outcome.Cleanup != domain.CleanupUndeclaredResidue {
				t.Fatalf(
					"cleanup = %q, want undeclared-residue",
					outcome.Cleanup,
				)
			}
			if repairCalled || exportCalled {
				t.Fatalf(
					"unsafe residue reached repair/export: repair=%t export=%t",
					repairCalled,
					exportCalled,
				)
			}
			if !hasOutcomeError(outcome, domain.CodeCleanupResidue) {
				t.Fatal("CLEANUP_RESIDUE finding is absent")
			}
			if failDestroy {
				if domain.ErrorCodeOf(runErr) !=
					domain.CodeSandboxDestroyFailed ||
					!hasOutcomeError(
						outcome,
						domain.CodeSandboxDestroyFailed,
					) {
					t.Fatalf(
						"destroy failure was not separate: err=%v errors=%#v",
						runErr,
						outcome.Errors,
					)
				}
			} else if runErr != nil {
				t.Fatalf(
					"confirmed undeclared residue became operational error: %v",
					runErr,
				)
			}
			denied := false
			for _, observation := range outcome.Observations {
				if observation.Operation == "sandbox.outputs.export" &&
					observation.Result == "denied" &&
					observation.Details["reason"] ==
						"unsafe-residue" {
					denied = true
				}
			}
			if !denied {
				t.Fatal("unsafe-residue export denial observation is absent")
			}
		})
	}
}

func cleanupInventoryControl(entries string) string {
	count := 0
	if entries != "" {
		count = strings.Count(entries, `"path"`)
	}
	return `{"schemaVersion":"1","ok":true,"scope":"/outputs","count":` +
		strconv.Itoa(count) +
		`,"rootBefore":{"device":"1","inode":"2","mode":511,"ctimeNs":"3","mtimeNs":"4"},` +
		`"rootAfter":{"device":"1","inode":"2","mode":511,"ctimeNs":"3","mtimeNs":"4"},` +
		`"disposableAbsent":true,"entries":[` + entries + "]}\n"
}

func cleanupObservationFromOutcome(
	t *testing.T,
	outcome Outcome,
) domain.ObservationEvent {
	t.Helper()
	for _, observation := range outcome.Observations {
		if observation.Operation == "cleanup.residue.summary" {
			return observation
		}
	}
	t.Fatal("cleanup residue observation is absent")
	return domain.ObservationEvent{}
}

func assertCleanupBoundaryFlags(
	t *testing.T,
	observation domain.ObservationEvent,
	quiescence bool,
	disposable bool,
	identity bool,
	inventory bool,
) {
	t.Helper()
	if observation.Details["boundary"] != cleanupInventoryBoundary ||
		observation.Details["quiescenceConfirmed"] != quiescence ||
		observation.Details["disposableCleanupVerified"] != disposable ||
		observation.Details["identityVerified"] != identity ||
		observation.Details["inventoryComplete"] != inventory ||
		observation.Details["maxControlBytes"] !=
			cleanupInventoryControlBytes {
		t.Fatalf(
			"cleanup boundary details = %#v",
			observation.Details,
		)
	}
}

func cleanupCallIndex(
	calls []commandCall,
	matches func([]string) bool,
) int {
	for index, call := range calls {
		if matches(call.args) {
			return index
		}
	}
	return -1
}

func hasOutcomeError(outcome Outcome, code domain.ErrorCode) bool {
	for _, finding := range outcome.Errors {
		if finding != nil && finding.Code == code {
			return true
		}
	}
	return false
}
