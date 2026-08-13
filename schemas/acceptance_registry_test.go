package schemas_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/acceptanceregistry"
	schemavalidator "github.com/taipei49314/RepoPassport/schemas"
)

func TestAcceptanceRegistrySchemasArePublishedAndStrict(t *testing.T) {
	root := acceptanceRepositoryRoot(t)
	registryRaw := acceptanceReadFile(t, filepath.Join(root, "acceptance-registry.json"))
	if err := schemavalidator.ValidateAcceptanceRegistryV1JSON(registryRaw); err != nil {
		t.Fatalf("published registry schema validation: %v", err)
	}

	evaluationRaw, err := acceptanceregistry.Evaluate(registryRaw, acceptanceregistry.EvaluationRequest{
		Subject: acceptanceregistry.Subject{
			Repository: "github.com/taipei49314/RepoPassport",
			Revision:   strings.Repeat("a", 40),
			TreeSHA:    strings.Repeat("b", 40),
		},
		Run: acceptanceregistry.Run{
			Attempt:      1,
			Event:        "push",
			ID:           1,
			Ref:          "refs/heads/main",
			WorkflowPath: ".github/workflows/ci.yml",
		},
		Checks: acceptanceregistry.CheckResults{
			Container:  "success",
			Go:         "success",
			SchemaJSON: "success",
			WindowsGo:  "success",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := schemavalidator.ValidateAcceptanceEvaluationV1JSON(evaluationRaw); err != nil {
		t.Fatalf("acceptance evaluation schema validation: %v", err)
	}

	for _, name := range []string{
		"acceptance-registry-v1.schema.json",
		"acceptance-evaluation-v1.schema.json",
	} {
		raw := acceptanceReadFile(t, filepath.Join(root, "schemas", name))
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("%s top-level additionalProperties is not false", name)
		}
	}
}

func TestAcceptanceRegistrySchemasRejectUnknownFieldsAndOversize(t *testing.T) {
	registryRaw := acceptanceReadFile(t, filepath.Join(acceptanceRepositoryRoot(t), "acceptance-registry.json"))
	var registry map[string]any
	if err := json.Unmarshal(registryRaw, &registry); err != nil {
		t.Fatal(err)
	}
	registry["unknown"] = true
	unknownRegistry, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemavalidator.ValidateAcceptanceRegistryV1JSON(unknownRegistry); err == nil {
		t.Fatal("registry schema accepted an unknown top-level field")
	}
	if err := schemavalidator.ValidateAcceptanceRegistryV1JSON(make([]byte, schemavalidator.MaxAcceptanceRegistryV1JSONBytes+1)); err == nil {
		t.Fatal("registry schema accepted oversized input")
	}
	if err := schemavalidator.ValidateAcceptanceEvaluationV1JSON(make([]byte, schemavalidator.MaxAcceptanceEvaluationV1JSONBytes+1)); err == nil {
		t.Fatal("evaluation schema accepted oversized input")
	}
}

func acceptanceRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), ".."))
}

func acceptanceReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
