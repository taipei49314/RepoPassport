package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/planner"
)

func TestCurrentDirectCLIPlanContract(t *testing.T) {
	plan := currentDirectCLIPlan(domain.ResolvedPlan{})
	if plan.SchemaVersion != planner.ResolvedPlanSchemaVersion ||
		plan.JourneyDriver != "cli" ||
		plan.JourneyDriverVersion != planner.CLIJourneyDriverVersion ||
		plan.Cleanup.ClassifierVersion !=
			planner.CleanupClassifierVersion ||
		len(plan.Cleanup.AllowedResidue) != 1 ||
		plan.Cleanup.AllowedResidue[0] != "/outputs/**" ||
		plan.Evidence.Profile != "minimal-public" ||
		len(plan.Evidence.Include) != 2 ||
		plan.Evidence.Include[0] != "normalized-observations" ||
		plan.Evidence.Include[1] != "verification-summary" ||
		len(plan.Evidence.Exclude) != 3 ||
		plan.Evidence.Exclude[0] != "raw-stderr" ||
		plan.Evidence.Exclude[1] != "raw-stdout" ||
		plan.Evidence.Exclude[2] != "raw-syscall-trace" ||
		len(plan.RequiredRunnerFeatures) != 1 ||
		plan.RequiredRunnerFeatures[0] !=
			"cleanup-residue-classification" {
		t.Fatalf("direct CLI plan contract = %#v", plan)
	}
}

func TestDirectIntegrationPlansUseCurrentContractFactory(
	t *testing.T,
) {
	path := filepath.Join("container_integration_test.go")
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(
		fileSet,
		path,
		nil,
		0,
	)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	stack := make([]ast.Node, 0, 32)
	directPlans := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		if literal, ok := node.(*ast.CompositeLit); ok &&
			isResolvedPlanType(literal.Type) {
			directPlans++
			call, wrapped := parent.(*ast.CallExpr)
			if !wrapped ||
				len(call.Args) != 1 ||
				call.Args[0] != literal ||
				!isCurrentDirectCLIPlanCall(call.Fun) {
				t.Errorf(
					"direct ResolvedPlan at %s must use currentDirectCLIPlan",
					fileSet.Position(literal.Pos()),
				)
			}
		}
		stack = append(stack, node)
		return true
	})
	if directPlans != 3 {
		t.Fatalf(
			"direct container integration plan count = %d, want 3",
			directPlans,
		)
	}
}

func currentDirectCLIPlan(plan domain.ResolvedPlan) domain.ResolvedPlan {
	if plan.SchemaVersion != "" ||
		plan.JourneyDriver != "" ||
		plan.JourneyDriverVersion != "" ||
		plan.Cleanup.ClassifierVersion != "" ||
		plan.Cleanup.AllowedResidue != nil ||
		plan.Evidence.Profile != "" ||
		plan.Evidence.Include != nil ||
		plan.Evidence.Exclude != nil {
		panic("direct CLI plan must not override the current plan contract")
	}
	plan.SchemaVersion = planner.ResolvedPlanSchemaVersion
	plan.JourneyDriver = "cli"
	plan.JourneyDriverVersion = planner.CLIJourneyDriverVersion
	plan.Evidence = domain.PlanEvidence{
		Profile: "minimal-public",
		Include: []string{"normalized-observations", "verification-summary"},
		Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
	}
	plan.Cleanup = domain.PlanCleanup{
		ClassifierVersion: planner.CleanupClassifierVersion,
		AllowedResidue:    []string{"/outputs/**"},
	}
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"cleanup-residue-classification",
	)
	return plan
}

func isResolvedPlanType(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ResolvedPlan" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == "domain"
}

func isCurrentDirectCLIPlanCall(expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == "currentDirectCLIPlan"
}
