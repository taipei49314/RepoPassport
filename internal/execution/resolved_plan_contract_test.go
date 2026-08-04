package execution

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func TestRunnerRejectsAlpha9ResolvedPlanSchemaVersion(t *testing.T) {
	plan := testPlan(t, t.TempDir())
	plan.SchemaVersion = "2"
	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanUnresolved {
		t.Fatalf(
			"schema v2 error code = %q, want %q: %v",
			got,
			domain.CodePlanUnresolved,
			err,
		)
	}
}

func TestCleanupResidueClassificationFeatureNegotiation(t *testing.T) {
	const feature = "cleanup-residue-classification"
	if _, err := NegotiateFeatures(
		[]string{feature},
		domain.RunnerFeatures{Available: true},
	); err != nil {
		t.Fatalf("available controller-owned cleanup feature rejected: %v", err)
	}
	if _, err := NegotiateFeatures(
		[]string{feature},
		domain.RunnerFeatures{Available: false},
	); domain.ErrorCodeOf(err) != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf(
			"unavailable cleanup feature error = %v, want %s",
			err,
			domain.CodeRunnerFeatureUnavailable,
		)
	}
}

func TestRunnerRejectsResolvedPlanMissingCleanupResidueFeature(t *testing.T) {
	plan := testPlan(t, t.TempDir())
	filtered := make([]string, 0, len(plan.RequiredRunnerFeatures))
	for _, feature := range plan.RequiredRunnerFeatures {
		if feature != "cleanup-residue-classification" {
			filtered = append(filtered, feature)
		}
	}
	plan.RequiredRunnerFeatures = filtered
	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanUnresolved {
		t.Fatalf(
			"missing cleanup feature error code = %q, want %q: %v",
			got,
			domain.CodePlanUnresolved,
			err,
		)
	}
}

func TestRunnerValidatesResolvedCleanupContract(t *testing.T) {
	validOutputs := testPlan(t, t.TempDir())
	validOutputs.Cleanup.AllowedResidue = []string{"/outputs/**"}
	if _, _, err := testRunner(&fakeExecutor{}).validatePlan(
		validOutputs,
	); err != nil {
		t.Fatalf("valid /outputs cleanup contract was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*domain.PlanCleanup)
	}{
		{
			name: "missing classifier",
			mutate: func(cleanup *domain.PlanCleanup) {
				cleanup.ClassifierVersion = ""
			},
		},
		{
			name: "classifier drift",
			mutate: func(cleanup *domain.PlanCleanup) {
				cleanup.ClassifierVersion = "0.1.1"
			},
		},
		{
			name: "null allowed residue",
			mutate: func(cleanup *domain.PlanCleanup) {
				cleanup.AllowedResidue = nil
			},
		},
		{
			name: "custom allowed residue",
			mutate: func(cleanup *domain.PlanCleanup) {
				cleanup.AllowedResidue = []string{"/workspace/**"}
			},
		},
		{
			name: "additional allowed residue",
			mutate: func(cleanup *domain.PlanCleanup) {
				cleanup.AllowedResidue = []string{
					"/outputs/**",
					"/workspace/**",
				}
			},
		},
		{
			name: "duplicate output residue",
			mutate: func(cleanup *domain.PlanCleanup) {
				cleanup.AllowedResidue = []string{
					"/outputs/**",
					"/outputs/**",
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testPlan(t, t.TempDir())
			test.mutate(&plan.Cleanup)
			_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
			if got := domain.ErrorCodeOf(err); got !=
				domain.CodePlanUnresolved {
				t.Fatalf(
					"error code = %q, want %q: %v",
					got,
					domain.CodePlanUnresolved,
					err,
				)
			}
		})
	}
}

func TestClonePlanPreservesAndDeepCopiesCleanupContract(t *testing.T) {
	plan := domain.ResolvedPlan{
		Cleanup: domain.PlanCleanup{
			ClassifierVersion: "0.1.0",
			AllowedResidue:    []string{"/outputs/**"},
		},
	}
	cloned := clonePlan(plan)
	plan.Cleanup.AllowedResidue[0] = "/mutated/**"
	if got := cloned.Cleanup.AllowedResidue; len(got) != 1 ||
		got[0] != "/outputs/**" {
		t.Fatalf("cleanup clone changed with caller-owned plan: %#v", got)
	}

	empty := clonePlan(domain.ResolvedPlan{
		Cleanup: domain.PlanCleanup{
			ClassifierVersion: "0.1.0",
			AllowedResidue:    []string{},
		},
	})
	if empty.Cleanup.AllowedResidue == nil {
		t.Fatal("cleanup clone changed a non-null empty residue set to null")
	}
	null := clonePlan(domain.ResolvedPlan{})
	if null.Cleanup.AllowedResidue != nil {
		t.Fatal("cleanup clone hid a null residue set from validation")
	}
}

func TestPrepareSealsCleanupContractFromCallerMutation(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "app.js"),
		[]byte("ok\n"),
	)
	plan := testPlan(t, sourceRoot)
	plan.Cleanup.AllowedResidue = []string{"/outputs/**"}
	prepared, err := testRunner(dockerDoctorFake()).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if cleanupErr := cleanupPreparedCopies(prepared); cleanupErr != nil {
			t.Errorf(
				"cleanup prepared immutable copies: %v",
				cleanupErr,
			)
		}
	})

	plan.Cleanup.AllowedResidue[0] = "/caller-mutated/**"
	prepared.Plan.Cleanup.AllowedResidue[0] = "/public-mutated/**"
	if got := prepared.executionPlan.Cleanup.AllowedResidue; len(got) != 1 ||
		got[0] != "/outputs/**" {
		t.Fatalf("sealed cleanup contract was mutated: %#v", got)
	}
}
