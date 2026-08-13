package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/acceptanceregistry"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestRunAcceptanceRegistryCommands(t *testing.T) {
	registry := filepath.Join(acceptanceCLIRepositoryRoot(t), "acceptance-registry.json")
	t.Run("validate", func(t *testing.T) {
		stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
		if code := run([]string{"validate", "--registry", registry}, stdout, stderr); code != 0 {
			t.Fatalf("validate exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		assertAcceptanceCLIRecord(t, stdout.Bytes(), "ACCEPTANCE_REGISTRY_VALID", "INCOMPLETE")
		if stderr.Len() != 0 {
			t.Fatalf("validate stderr = %q", stderr.String())
		}
	})

	t.Run("evaluate and require incomplete", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "acceptance-evaluation-v1.json")
		stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
		args := acceptanceEvaluateArgs(registry, output)
		if code := run(args, stdout, stderr); code != 0 {
			t.Fatalf("evaluate exit = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		assertAcceptanceCLIRecord(t, stdout.Bytes(), "ACCEPTANCE_EVALUATION_WRITTEN", "INCOMPLETE")
		if stderr.Len() != 0 {
			t.Fatalf("evaluate stderr = %q", stderr.String())
		}
		registryRaw := acceptanceCLIRead(t, registry)
		evaluationRaw := acceptanceCLIRead(t, output)
		if _, err := acceptanceregistry.ParseEvaluation(registryRaw, evaluationRaw); err != nil {
			t.Fatalf("published evaluation: %v", err)
		}

		stdout.Reset()
		if code := run([]string{"require-complete", "--evaluation", output, "--registry", registry}, stdout, stderr); code == 0 {
			t.Fatal("require-complete accepted the incomplete roadmap")
		}
		assertAcceptanceCLIRecord(t, stdout.Bytes(), "ACCEPTANCE_INCOMPLETE", "INCOMPLETE")
		if stderr.Len() != 0 {
			t.Fatalf("require-complete stderr = %q", stderr.String())
		}
	})
}

func TestRunAcceptanceRegistryRejectsInvalidSyntaxWithoutDisclosure(t *testing.T) {
	registry := filepath.Join(acceptanceCLIRepositoryRoot(t), "acceptance-registry.json")
	marker := "private-path-marker"
	tests := map[string][]string{
		"missing command":           {},
		"unknown command":           {"other"},
		"unknown flag":              {"validate", "--registry", registry, "--other", marker},
		"duplicate flag":            {"validate", "--registry", registry, "--registry", marker},
		"equals flag":               {"validate", "--registry=" + marker},
		"positional":                {"validate", "--registry", registry, marker},
		"missing evaluate identity": {"evaluate", "--registry", registry},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
			if code := run(args, stdout, stderr); code == 0 {
				t.Fatal("invalid CLI syntax returned success")
			}
			assertAcceptanceCLIRecord(t, stdout.Bytes(), "ACCEPTANCE_INVALID_INPUT", "FAIL")
			if stderr.Len() != 0 || bytes.Contains(stdout.Bytes(), []byte(marker)) || bytes.Contains(stdout.Bytes(), []byte("--other")) {
				t.Fatalf("invalid input was disclosed: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunAcceptanceRegistryDoesNotReplaceOutputOrIgnoreWriterFailure(t *testing.T) {
	registry := filepath.Join(acceptanceCLIRepositoryRoot(t), "acceptance-registry.json")
	output := filepath.Join(t.TempDir(), "acceptance-evaluation-v1.json")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := new(bytes.Buffer)
	if code := run(acceptanceEvaluateArgs(registry, output), stdout, io.Discard); code == 0 {
		t.Fatal("evaluate replaced a pre-existing output")
	}
	if got := string(acceptanceCLIRead(t, output)); got != "existing" {
		t.Fatalf("pre-existing output changed to %q", got)
	}

	failing := acceptanceFailWriter{}
	if code := run([]string{"validate", "--registry", registry}, failing, io.Discard); code == 0 {
		t.Fatal("stdout writer failure returned success")
	}
}

func acceptanceEvaluateArgs(registry, output string) []string {
	return []string{
		"evaluate",
		"--registry", registry,
		"--repository", "github.com/taipei49314/RepoPassport",
		"--revision", strings.Repeat("a", 40),
		"--tree-sha", strings.Repeat("b", 40),
		"--event", "push",
		"--ref", "refs/heads/main",
		"--workflow-run-id", "31673266929",
		"--workflow-run-attempt", "1",
		"--go-result", "success",
		"--schema-json-result", "success",
		"--windows-go-result", "success",
		"--container-result", "success",
		"--output", output,
	}
}

func assertAcceptanceCLIRecord(t *testing.T, raw []byte, code, overall string) {
	t.Helper()
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		t.Fatalf("stdout is not one JSON line: %q", raw)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSuffix(raw, []byte{'\n'}), &record); err != nil {
		t.Fatalf("stdout JSON: %v", err)
	}
	if len(record) != 4 || record["code"] != code || record["overallStatus"] != overall || record["status"] == nil || record["sha256"] == nil {
		t.Fatalf("stdout record = %#v", record)
	}
	canonical, err := canonicaljson.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, bytes.TrimSuffix(raw, []byte{'\n'})) {
		t.Fatalf("stdout is not canonical: %q", raw)
	}
	if digest, ok := record["sha256"].(string); !ok || (digest != "NOT_APPLICABLE" && (len(digest) != 71 || !strings.HasPrefix(digest, "sha256:"))) {
		t.Fatalf("stdout sha256 = %v", record["sha256"])
	}
}

func acceptanceCLIRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func acceptanceCLIRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type acceptanceFailWriter struct{}

func (acceptanceFailWriter) Write(p []byte) (int, error) {
	return 0, &strconv.NumError{Func: "write", Num: "redacted", Err: io.ErrClosedPipe}
}
