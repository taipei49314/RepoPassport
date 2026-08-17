package acceptanceregistry

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAcceptanceRegistryRequiredCIContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(acceptanceWorkflowRepositoryRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow acceptanceWorkflowContract
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse CI workflow: %v", err)
	}
	job, ok := workflow.Jobs["acceptance-registry"]
	if !ok {
		t.Fatal("CI workflow has no required acceptance-registry job")
	}
	if job.Name != "Machine-verifiable acceptance registry" || job.RunsOn != "ubuntu-latest" || job.TimeoutMinutes != 10 {
		t.Fatalf("acceptance job identity = %#v", job)
	}
	if job.If != "${{ always() }}" || job.ContinueOnError {
		t.Fatal("acceptance job is not an always-run, required fail-closed gate")
	}
	wantNeeds := []string{"go", "schema-json", "windows-go", "container-integration"}
	if !equalAcceptanceStrings(job.Needs, wantNeeds) {
		t.Fatalf("acceptance job needs = %v, want %v", job.Needs, wantNeeds)
	}
	wantStepIDs := []string{"checkout", "setup-go", "source-binding", "evaluate", "verify-evaluation", "upload-evaluation", "fail-on-upstream"}
	if len(job.Steps) != len(wantStepIDs) {
		t.Fatalf("acceptance steps = %d, want %d", len(job.Steps), len(wantStepIDs))
	}
	steps := make(map[string]acceptanceWorkflowStep, len(job.Steps))
	for index, step := range job.Steps {
		if step.ID != wantStepIDs[index] {
			t.Fatalf("acceptance step %d id = %q, want %q", index, step.ID, wantStepIDs[index])
		}
		if _, duplicate := steps[step.ID]; duplicate {
			t.Fatalf("duplicate acceptance step id %q", step.ID)
		}
		steps[step.ID] = step
	}
	if steps["checkout"].Uses != "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5" || steps["checkout"].With["persist-credentials"] != "false" {
		t.Fatal("acceptance checkout is not pinned and credential-free")
	}
	if steps["setup-go"].Uses != "actions/setup-go@44694675825211faa026b3c33043df3e48a5fa00" || steps["setup-go"].With["go-version"] != "1.26.6" || steps["setup-go"].With["cache"] != "false" {
		t.Fatal("acceptance Go setup is not exact")
	}
	evaluate := steps["evaluate"]
	wantEnv := map[string]string{
		"ACCEPTANCE_OUTPUT":  "${{ runner.temp }}/acceptance-evaluation-v1.json",
		"CONTAINER_RESULT":   "${{ needs.container-integration.result }}",
		"GO_RESULT":          "${{ needs.go.result }}",
		"SCHEMA_JSON_RESULT": "${{ needs.schema-json.result }}",
		"WINDOWS_GO_RESULT":  "${{ needs.windows-go.result }}",
	}
	for key, value := range wantEnv {
		if evaluate.Env[key] != value {
			t.Errorf("evaluate env %s = %q, want %q", key, evaluate.Env[key], value)
		}
	}
	for _, fragment := range []string{
		"go mod download",
		"go mod verify",
		"go run ./cmd/repopass-acceptance-registry evaluate",
		"--registry acceptance-registry.json",
		"--repository github.com/taipei49314/RepoPassport",
		"--revision \"$GITHUB_SHA\"",
		"--tree-sha \"$tree_sha\"",
		"--event \"$GITHUB_EVENT_NAME\"",
		"--ref \"$GITHUB_REF\"",
		"--workflow-run-id \"$GITHUB_RUN_ID\"",
		"--workflow-run-attempt \"$GITHUB_RUN_ATTEMPT\"",
		"--go-result \"$GO_RESULT\"",
		"--schema-json-result \"$SCHEMA_JSON_RESULT\"",
		"--windows-go-result \"$WINDOWS_GO_RESULT\"",
		"--container-result \"$CONTAINER_RESULT\"",
		"--output \"$ACCEPTANCE_OUTPUT\"",
	} {
		if !strings.Contains(evaluate.Run, fragment) {
			t.Errorf("evaluate step is missing %q", fragment)
		}
	}
	if !strings.Contains(steps["source-binding"].Run, "git rev-parse --verify 'HEAD^{tree}'") ||
		!strings.Contains(steps["source-binding"].Run, "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none") {
		t.Fatal("acceptance source binding does not verify the exact clean tree")
	}
	verify := steps["verify-evaluation"]
	for _, fragment := range []string{
		"python3 -", "object_pairs_hook", "read_bounded_regular", "metadata.st_nlink != 1",
		"256 * 1024", "1024 * 1024", "evaluationDigest", "registryDigest",
		"producer-owned-ci", "stableEligible", "expected_ids", "'RP-R-STABLE-SCHEMA'",
		"registry evaluation policy differs", "len(document['rows']) != 37",
		`head_sha="$(git rev-parse --verify HEAD)"`,
		`tree_sha="$(git rev-parse --verify 'HEAD^{tree}')"`,
		`status="$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"`,
		`[[ "$head_sha" == "$GITHUB_SHA" ]]`, `[[ "$tree_sha" == "$EXPECTED_TREE_SHA" ]]`,
		`[[ -z "$status" ]]`,
	} {
		if !strings.Contains(verify.Run, fragment) {
			t.Errorf("independent evaluation verifier is missing %q", fragment)
		}
	}
	upload := steps["upload-evaluation"]
	if upload.Uses != "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" ||
		upload.With["name"] != "repopass-acceptance-evaluation-${{ github.run_id }}-${{ github.run_attempt }}" ||
		upload.With["path"] != "${{ runner.temp }}/acceptance-evaluation-v1.json" ||
		upload.With["retention-days"] != "14" || upload.With["if-no-files-found"] != "error" {
		t.Fatalf("acceptance artifact transport = %#v", upload)
	}
	fail := steps["fail-on-upstream"]
	if fail.If != "${{ always() }}" {
		t.Fatal("upstream result enforcement is not always-run")
	}
	for _, result := range []string{"GO_RESULT", "SCHEMA_JSON_RESULT", "WINDOWS_GO_RESULT", "CONTAINER_RESULT"} {
		if !strings.Contains(fail.Run, `"$`+result+`" != 'success'`) {
			t.Errorf("upstream enforcement omits %s", result)
		}
	}
	if strings.Contains(string(raw), "repopass-acceptance-registry require-complete") {
		t.Fatal("ordinary CI invokes the stable completion gate")
	}
}

type acceptanceWorkflowContract struct {
	Jobs map[string]acceptanceWorkflowJob `yaml:"jobs"`
}

type acceptanceWorkflowJob struct {
	Name            string                   `yaml:"name"`
	Needs           []string                 `yaml:"needs"`
	If              string                   `yaml:"if"`
	RunsOn          string                   `yaml:"runs-on"`
	TimeoutMinutes  int                      `yaml:"timeout-minutes"`
	ContinueOnError bool                     `yaml:"continue-on-error"`
	Steps           []acceptanceWorkflowStep `yaml:"steps"`
}

type acceptanceWorkflowStep struct {
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]string `yaml:"with"`
}

func acceptanceWorkflowRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func equalAcceptanceStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
