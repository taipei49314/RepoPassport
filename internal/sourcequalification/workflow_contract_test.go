package sourcequalification

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSourceQualificationWorkflowContract(t *testing.T) {
	root := workflowRepositoryRoot(t)
	path := filepath.Join(root, ".github", "workflows", "source-qualification.yml")
	raw := readWorkflowContractFile(t, path)
	document := parseWorkflowContractYAML(t, raw)
	workflow := workflowDocumentMapping(t, document)

	requireWorkflowTriggers(t, workflow)

	wantJobs := []string{
		"accept",
		"aggregate",
		"context",
		"linux",
		"replay-linux",
		"replay-windows",
		"windows",
	}
	jobs := workflowRequiredMapping(t, workflow, "jobs")
	if got := workflowMappingKeys(t, jobs); !reflect.DeepEqual(got, wantJobs) {
		t.Fatalf("workflow jobs = %q, want exact source-qualification jobs %q", got, wantJobs)
	}

	wantPermissions := map[string]string{"actions": "read", "contents": "read"}
	if got := workflowScalarMap(t, workflowRequiredMapping(t, workflow, "permissions")); !reflect.DeepEqual(got, wantPermissions) {
		t.Fatalf("workflow permissions = %#v, want exact read-only permissions %#v", got, wantPermissions)
	}
	wantConcurrency := map[string]string{
		"cancel-in-progress": "false",
		"group":              "source-qualification-${{ github.sha }}",
	}
	if got := workflowScalarMap(t, workflowRequiredMapping(t, workflow, "concurrency")); !reflect.DeepEqual(got, wantConcurrency) {
		t.Fatalf("workflow concurrency = %#v, want exact same-subject serialization %#v", got, wantConcurrency)
	}

	wantJobsContract := map[string]struct {
		needs  []string
		runner string
	}{
		"context":        {needs: []string{}, runner: "ubuntu-24.04"},
		"linux":          {needs: []string{"context"}, runner: "ubuntu-24.04"},
		"windows":        {needs: []string{"context"}, runner: "windows-2025"},
		"aggregate":      {needs: []string{"context", "linux", "windows"}, runner: "ubuntu-24.04"},
		"replay-linux":   {needs: []string{"aggregate", "context"}, runner: "ubuntu-24.04"},
		"replay-windows": {needs: []string{"aggregate", "context"}, runner: "windows-2025"},
		"accept":         {needs: []string{"aggregate", "context", "linux", "replay-linux", "replay-windows", "windows"}, runner: "ubuntu-24.04"},
	}
	for name, want := range wantJobsContract {
		job := workflowRequiredMapping(t, jobs, name)
		if got := workflowNeeds(t, job); !reflect.DeepEqual(got, want.needs) {
			t.Errorf("job %s needs = %q, want exact dependencies %q", name, got, want.needs)
		}
		if got := workflowRequiredScalar(t, job, "runs-on"); got != want.runner {
			t.Errorf("job %s runs-on = %q, want %q", name, got, want.runner)
		}
	}

	requireWorkflowContextJob(t, workflowRequiredMapping(t, jobs, "context"))
	requireWorkflowLaneJob(t, "linux", workflowRequiredMapping(t, jobs, "linux"))
	requireWorkflowLaneJob(t, "windows", workflowRequiredMapping(t, jobs, "windows"))
	requireWorkflowAggregateJob(t, workflowRequiredMapping(t, jobs, "aggregate"))
	requireWorkflowReplayJob(t, "linux", workflowRequiredMapping(t, jobs, "replay-linux"))
	requireWorkflowReplayJob(t, "windows", workflowRequiredMapping(t, jobs, "replay-windows"))
	requireWorkflowAcceptJob(t, workflowRequiredMapping(t, jobs, "accept"))
	requireWorkflowSafety(t, workflow)
	requirePinnedWorkflowActions(t, workflow, []string{
		"actions/checkout",
		"actions/download-artifact",
		"actions/setup-go",
		"actions/upload-artifact",
	})
}

func TestSourceQualificationWorkflowHistoryQueriesRetainPageRoot(t *testing.T) {
	t.Parallel()

	root := workflowRepositoryRoot(t)
	path := filepath.Join(root, ".github", "workflows", "source-qualification.yml")
	raw := readWorkflowContractFile(t, path)
	document := parseWorkflowContractYAML(t, raw)
	workflow := workflowDocumentMapping(t, document)
	jobs := workflowRequiredMapping(t, workflow, "jobs")

	for _, test := range []struct {
		job  string
		step string
	}{
		{job: "context", step: "resolve-context"},
		{job: "accept", step: "accept"},
	} {
		t.Run(test.job, func(t *testing.T) {
			step := workflowRequiredStep(t, workflowRequiredMapping(t, jobs, test.job), test.step)
			script := workflowRequiredScalar(t, step, "run")
			if !regexp.MustCompile(`(?s)\.\s+as\s+\$pages\s*\|`).MatchString(script) {
				t.Errorf("%s history query must bind the slurped page root before boolean pipelines", test.job)
			}
			if got := strings.Count(script, "$pages[].workflow_runs[]"); got < 2 {
				t.Errorf("%s history query reads the bound page root %d times, want at least 2", test.job, got)
			}
			if strings.Contains(script, "[.[].workflow_runs[]") {
				t.Errorf("%s history query reuses a pipeline-local dot instead of the bound page root", test.job)
			}
		})
	}
}

func TestPrivateSourceQualificationCLIContract(t *testing.T) {
	root := workflowRepositoryRoot(t)
	directory := filepath.Join(root, "internal", "sourcequalification", "cmd", "repopass-source-qualify")
	mainPath := filepath.Join(directory, "main.go")
	mainSource := readWorkflowContractFile(t, mainPath)
	if !regexp.MustCompile(`(?m)^package main\s*$`).Match(mainSource) {
		t.Fatalf("%s must remain a private package main", filepath.ToSlash(mainPath))
	}

	literals := workflowGoStringLiterals(t, directory)
	for _, value := range []string{
		"produce-lane",
		"assemble",
		"assemble-tools",
		"verify-integrity",
		"verify-subject",
		"validate-schema-json",
		"version",
		"--repo-root",
		"--lane",
		"--event",
		"--expected-ref",
		"--expected-base-revision",
		"--expected-tested-revision",
		"--expected-tree",
		"--expected-qualification-run-id",
		"--workflow-run-id",
		"--workflow-run-attempt",
		"--private-log-root",
		"--out-dir",
		"--linux-dir",
		"--windows-dir",
		"--package-dir",
		"--linux-controller",
		"--windows-controller",
		"--expected-repository",
		"--expected-package-digest",
		"--tool-manifest",
		"--expected-tool-manifest-digest",
		"--expected-executable-digest",
		"--root",
	} {
		if !literals[value] {
			t.Errorf("private source-qualification CLI is missing exact command/flag literal %q", value)
		}
	}

	for _, forbidden := range []string{
		"--command",
		"--registry",
		"--receipt",
		"--status",
		"--platform",
		"--archive-inventory",
	} {
		if literals[forbidden] {
			t.Errorf("private source-qualification CLI exposes forbidden caller-selected input %q", forbidden)
		}
	}
}

func workflowRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(directory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve repository root from %s: %v", directory, err)
	}
	return root
}

func readWorkflowContractFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("required source contract %s: %v", filepath.ToSlash(path), err)
	}
	return raw
}

func parseWorkflowContractYAML(t *testing.T, raw []byte) *yaml.Node {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	document := &yaml.Node{}
	if err := decoder.Decode(document); err != nil {
		t.Fatalf("parse source-qualification workflow YAML: %v", err)
	}
	extra := &yaml.Node{}
	if err := decoder.Decode(extra); err != io.EOF {
		if err == nil {
			t.Fatal("source-qualification workflow must contain exactly one YAML document")
		}
		t.Fatalf("parse trailing source-qualification workflow YAML: %v", err)
	}
	validateWorkflowYAMLNode(t, document, "workflow")
	return document
}

func validateWorkflowYAMLNode(t *testing.T, node *yaml.Node, path string) {
	t.Helper()
	if node == nil {
		t.Fatalf("%s is nil", path)
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		t.Fatalf("%s uses a YAML alias or anchor; workflow contracts must be explicit", path)
	}
	if strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		t.Fatalf("%s uses unsupported YAML tag %q", path, node.Tag)
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			t.Fatalf("%s has an invalid mapping", path)
		}
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" {
				t.Fatalf("%s has a non-string or empty mapping key", path)
			}
			if seen[key.Value] {
				t.Fatalf("%s has duplicate key %q", path, key.Value)
			}
			seen[key.Value] = true
			validateWorkflowYAMLNode(t, node.Content[index+1], path+"."+key.Value)
		}
		return
	}
	for index, child := range node.Content {
		validateWorkflowYAMLNode(t, child, fmt.Sprintf("%s[%d]", path, index))
	}
}

func workflowDocumentMapping(t *testing.T, document *yaml.Node) *yaml.Node {
	t.Helper()
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		t.Fatal("source-qualification workflow must be one YAML mapping document")
	}
	return document.Content[0]
}

func workflowMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func workflowRequiredMapping(t *testing.T, mapping *yaml.Node, key string) *yaml.Node {
	t.Helper()
	value := workflowMappingValue(mapping, key)
	if value == nil || value.Kind != yaml.MappingNode {
		t.Fatalf("workflow %q must be an explicit mapping", key)
	}
	return value
}

func workflowRequiredScalar(t *testing.T, mapping *yaml.Node, key string) string {
	t.Helper()
	value := workflowMappingValue(mapping, key)
	if value == nil || value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
		t.Fatalf("workflow %q must be an explicit scalar", key)
	}
	return strings.TrimSpace(value.Value)
}

func workflowMappingKeys(t *testing.T, mapping *yaml.Node) []string {
	t.Helper()
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		t.Fatal("workflow value must be a mapping")
	}
	keys := make([]string, 0, len(mapping.Content)/2)
	for index := 0; index < len(mapping.Content); index += 2 {
		keys = append(keys, mapping.Content[index].Value)
	}
	sort.Strings(keys)
	return keys
}

func workflowScalarMap(t *testing.T, mapping *yaml.Node) map[string]string {
	t.Helper()
	result := map[string]string{}
	for index := 0; index < len(mapping.Content); index += 2 {
		value := mapping.Content[index+1]
		if value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
			t.Fatalf("workflow mapping value %q must be a scalar", mapping.Content[index].Value)
		}
		result[mapping.Content[index].Value] = strings.TrimSpace(value.Value)
	}
	return result
}

func workflowNeeds(t *testing.T, job *yaml.Node) []string {
	t.Helper()
	node := workflowMappingValue(job, "needs")
	if node == nil {
		return []string{}
	}
	values := []string{}
	switch node.Kind {
	case yaml.ScalarNode:
		values = append(values, strings.TrimSpace(node.Value))
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode {
				t.Fatal("workflow job needs entries must be scalar job identifiers")
			}
			values = append(values, strings.TrimSpace(child.Value))
		}
	default:
		t.Fatal("workflow job needs must be a scalar or sequence")
	}
	sort.Strings(values)
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] == value {
			t.Fatalf("workflow job needs contains an empty or duplicate dependency: %q", values)
		}
	}
	return values
}

func workflowSteps(t *testing.T, job *yaml.Node) []*yaml.Node {
	t.Helper()
	steps := workflowMappingValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode || len(steps.Content) == 0 {
		t.Fatal("workflow job must contain a nonempty steps sequence")
	}
	result := make([]*yaml.Node, 0, len(steps.Content))
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			t.Fatal("workflow steps must be explicit mappings")
		}
		result = append(result, step)
	}
	return result
}

func workflowRequiredStep(t *testing.T, job *yaml.Node, id string) *yaml.Node {
	t.Helper()
	var found *yaml.Node
	for _, step := range workflowSteps(t, job) {
		idNode := workflowMappingValue(step, "id")
		if idNode == nil || idNode.Kind != yaml.ScalarNode || idNode.Value != id {
			continue
		}
		if found != nil {
			t.Fatalf("workflow job contains duplicate step id %q", id)
		}
		found = step
	}
	if found == nil {
		t.Fatalf("workflow job is missing required step id %q", id)
	}
	return found
}

func workflowStepIndex(t *testing.T, job *yaml.Node, id string) int {
	t.Helper()
	for index, step := range workflowSteps(t, job) {
		idNode := workflowMappingValue(step, "id")
		if idNode != nil && idNode.Kind == yaml.ScalarNode && idNode.Value == id {
			return index
		}
	}
	t.Fatalf("workflow job is missing required step id %q", id)
	return -1
}

func workflowAction(t *testing.T, step *yaml.Node) (string, string) {
	t.Helper()
	uses := workflowRequiredScalar(t, step, "uses")
	match := regexp.MustCompile(`^([^@]+)@([0-9a-f]{40})$`).FindStringSubmatch(uses)
	if match == nil {
		t.Fatalf("workflow action is not pinned to one lowercase 40-hex commit: %q", uses)
	}
	return match[1], match[2]

}

func workflowRequiredActionStep(t *testing.T, job *yaml.Node, id, action string) *yaml.Node {
	t.Helper()
	step := workflowRequiredStep(t, job, id)
	got, _ := workflowAction(t, step)
	if got != action {
		t.Fatalf("workflow step %q uses %q, want %q", id, got, action)
	}
	return step
}

func workflowScript(t *testing.T, step *yaml.Node) string {
	t.Helper()
	raw := strings.ReplaceAll(workflowRequiredScalar(t, step, "run"), "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	effective := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		effective = append(effective, line)
	}
	return strings.Join(effective, "\n")
}

func requireWorkflowScriptFragments(t *testing.T, step *yaml.Node, fragments ...string) string {
	t.Helper()
	script := workflowScript(t, step)
	for _, fragment := range fragments {
		if !strings.Contains(script, fragment) {
			t.Errorf("workflow step %q command is missing %q", workflowRequiredScalar(t, step, "id"), fragment)
		}
	}
	return script
}

func requireWorkflowControllerCommand(t *testing.T, step *yaml.Node, command string, flags ...string) string {
	t.Helper()
	script := workflowScript(t, step)
	controller := `(?:"?\$[A-Za-z_][A-Za-z0-9_]*"?|"?\$\{[^\n}]+\}"?|[^\s\n]*(?:repopass-source-qualify|controller)[^\s\n]*)`
	pattern := regexp.MustCompile(`(?m)^\s*(?:&\s+)?` + controller + `\s+` + regexp.QuoteMeta(command) + `(?:\s|$)`)
	if !pattern.MatchString(script) {
		t.Errorf("workflow step %q does not execute the controller command %q", workflowRequiredScalar(t, step, "id"), command)
	}
	for _, flag := range flags {
		if !strings.Contains(script, flag) {
			t.Errorf("workflow controller command %q is missing exact flag %q", command, flag)
		}
	}
	return script
}

func requireAlwaysCondition(t *testing.T, mapping *yaml.Node, label string) string {
	t.Helper()
	condition := workflowRequiredScalar(t, mapping, "if")
	if !regexp.MustCompile(`(?:^|[^A-Za-z0-9_])always\(\)`).MatchString(condition) {
		t.Errorf("%s if condition = %q, want an explicit always() guard", label, condition)
	}
	return condition
}

func requirePinnedWorkflowActions(t *testing.T, workflow *yaml.Node, required []string) {
	t.Helper()
	allowed := map[string]bool{
		"actions/checkout":          true,
		"actions/download-artifact": true,
		"actions/setup-go":          true,
		"actions/upload-artifact":   true,
	}
	found := map[string]bool{}
	jobs := workflowRequiredMapping(t, workflow, "jobs")
	for _, jobName := range workflowMappingKeys(t, jobs) {
		job := workflowRequiredMapping(t, jobs, jobName)
		for _, step := range workflowSteps(t, job) {
			if workflowMappingValue(step, "uses") == nil {
				continue
			}
			action, _ := workflowAction(t, step)
			if !allowed[action] {
				t.Errorf("workflow uses action %q outside the frozen allowlist", action)
			}
			found[action] = true
		}
	}
	for _, action := range required {
		if !found[action] {
			t.Errorf("workflow does not use required pinned action %s", action)
		}
	}
}

func requireWorkflowTriggers(t *testing.T, workflow *yaml.Node) {
	t.Helper()
	triggers := workflowRequiredMapping(t, workflow, "on")
	allowed := map[string]bool{"pull_request": true, "push": true, "workflow_dispatch": true}
	for _, trigger := range workflowMappingKeys(t, triggers) {
		if !allowed[trigger] {
			t.Errorf("source-qualification workflow trigger %q is outside the RFC-0002 allowlist", trigger)
		}
	}
	push := workflowRequiredMapping(t, triggers, "push")
	if got := workflowMappingKeys(t, push); !reflect.DeepEqual(got, []string{"branches"}) {
		t.Errorf("push trigger keys = %q, want only branches", got)
	}
	branches := workflowMappingValue(push, "branches")
	if branches == nil || branches.Kind != yaml.SequenceNode || len(branches.Content) != 1 ||
		branches.Content[0].Kind != yaml.ScalarNode || branches.Content[0].Value != "main" {
		t.Error("source-qualification push trigger must target exactly main")
	}
	if manual := workflowMappingValue(triggers, "workflow_dispatch"); manual != nil {
		if manual.Kind == yaml.MappingNode && len(manual.Content) != 0 ||
			manual.Kind != yaml.MappingNode && !(manual.Kind == yaml.ScalarNode && manual.Tag == "!!null") {
			t.Error("workflow_dispatch, when present, must be input-free and explicitly non-closing")
		}
	}
}

func requireWorkflowContextJob(t *testing.T, job *yaml.Node) {
	t.Helper()
	wantOutputs := []string{
		"base-revision",
		"event",
		"qualification-run-id",
		"ref",
		"repository",
		"tested-revision",
		"tree-sha",
		"workflow-run-attempt",
		"workflow-run-id",
	}
	outputs := workflowRequiredMapping(t, job, "outputs")
	if got := workflowMappingKeys(t, outputs); !reflect.DeepEqual(got, wantOutputs) {
		t.Errorf("context outputs = %q, want exact outputs %q", got, wantOutputs)
	}
	for _, name := range wantOutputs {
		want := "steps.resolve-context.outputs." + name
		if got := workflowRequiredScalar(t, outputs, name); !strings.Contains(got, want) {
			t.Errorf("context output %q = %q, want binding to %q", name, got, want)
		}
	}
	step := workflowRequiredStep(t, job, "resolve-context")
	script := requireWorkflowScriptFragments(t, step,
		"gh api",
		"--paginate",
		"--slurp",
		"/actions/workflows/source-qualification.yml/runs",
		"workflow_runs",
		"run_attempt",
		"length == 0",
		"git ls-remote",
		"github-actions",
		".github/workflows/source-qualification.yml",
		"sha256",
		"GITHUB_OUTPUT",
		"parents",
		"tree",
	)
	operational := script + "\n" + workflowOperationalScalarText(step)
	for _, fragment := range []string{
		"${{ github.repository }}",
		"${{ github.event_name }}",
		"${{ github.ref }}",
		"${{ github.sha }}",
		"${{ github.event.before }}",
		"${{ github.run_id }}",
		"${{ github.run_attempt }}",
		"${{ github.token }}",
		"taipei49314/RepoPassport",
	} {
		if !strings.Contains(operational, fragment) {
			t.Errorf("context resolution is missing trusted input/direct-read binding %q", fragment)
		}
	}
}

func requireWorkflowLaneJob(t *testing.T, lane string, job *yaml.Node) {
	t.Helper()
	binary := "repopass-source-qualify-linux-amd64"
	if lane == "windows" {
		binary = "repopass-source-qualify-windows-amd64.exe"
	}
	requireWorkflowControllerBuild(t, job, binary)

	outputs := workflowRequiredMapping(t, job, "outputs")
	wantOutputs := map[string]string{
		"controller-artifact-id": "${{ steps.upload-controller.outputs.artifact-id }}",
		"lane-artifact-id":       "${{ steps.upload-lane.outputs.artifact-id }}",
	}
	if got := workflowScalarMap(t, outputs); !reflect.DeepEqual(got, wantOutputs) {
		t.Errorf("%s lane outputs = %#v, want exact artifact ID outputs %#v", lane, got, wantOutputs)
	}

	produce := workflowRequiredStep(t, job, "produce-lane")
	if got := workflowRequiredScalar(t, produce, "working-directory"); got != "${{ github.workspace }}/qualification-source" {
		t.Errorf("%s produce-lane working-directory = %q, want the exact clean checkout", lane, got)
	}
	wantProduceEnvironment := map[string]string{
		"SQ_BASE_REVISION":        "${{ needs.context.outputs.base-revision }}",
		"SQ_EVENT":                "${{ needs.context.outputs.event }}",
		"SQ_REF":                  "${{ needs.context.outputs.ref }}",
		"SQ_TESTED_REVISION":      "${{ needs.context.outputs.tested-revision }}",
		"SQ_TREE_SHA":             "${{ needs.context.outputs.tree-sha }}",
		"SQ_WORKFLOW_RUN_ATTEMPT": "${{ needs.context.outputs.workflow-run-attempt }}",
		"SQ_WORKFLOW_RUN_ID":      "${{ needs.context.outputs.workflow-run-id }}",
	}
	if got := workflowScalarMap(t, workflowRequiredMapping(t, produce, "env")); !reflect.DeepEqual(got, wantProduceEnvironment) {
		t.Errorf("%s produce-lane environment = %#v, want exact trusted context bindings %#v",
			lane, got, wantProduceEnvironment)
	}
	script := requireWorkflowControllerCommand(t, produce, "produce-lane",
		"--repo-root",
		"--lane",
		"--event",
		"--expected-ref",
		"--expected-base-revision",
		"--expected-tested-revision",
		"--expected-tree",
		"--workflow-run-id",
		"--workflow-run-attempt",
		"--private-log-root",
		"--out-dir",
	)
	wantLane := lane + "-amd64"
	for _, fragment := range []string{
		"--lane " + wantLane,
		"needs.context.outputs.event",
		"needs.context.outputs.ref",
		"needs.context.outputs.base-revision",
		"needs.context.outputs.tested-revision",
		"needs.context.outputs.tree-sha",
		"needs.context.outputs.workflow-run-id",
		"needs.context.outputs.workflow-run-attempt",
		"SQ_TREE_SHA",
		"GITHUB_OUTPUT",
		"attempt-published=true",
		"attempt-published=false",
		"RUNNER_TEMP",
	} {
		if !strings.Contains(script, fragment) && !strings.Contains(workflowOperationalScalarText(produce), fragment) {
			t.Errorf("%s produce-lane invocation is missing exact binding %q", lane, fragment)
		}
	}
	if !regexp.MustCompile(`(?m)(?:controller_exit|controllerExit)[^\n]*(?:-eq|==)[^\n]*3`).MatchString(script) {
		t.Errorf("%s produce-lane does not reserve exit 3 exclusively for a safely published non-PASS attempt", lane)
	}
	if lane == "linux" {
		if !strings.Contains(script, "env -u GITHUB_OUTPUT") {
			t.Error("linux produce-lane must hide the step-output channel from the candidate controller")
		}
	} else {
		for _, fragment := range []string{"$githubOutput", "Remove-Item Env:GITHUB_OUTPUT"} {
			if !strings.Contains(script, fragment) {
				t.Errorf("windows produce-lane must hide and privately restore the step-output channel: missing %q", fragment)
			}
		}
	}

	testedRevision := "${{ needs.context.outputs.tested-revision }}"
	requireWorkflowUploadStep(t, job, "upload-lane", "source-qualification-"+wantLane+"-"+testedRevision,
		"steps.produce-lane.outcome == 'success'")
	controller := requireWorkflowUploadStep(t, job, "upload-controller", "source-qualification-controller-"+wantLane+"-"+testedRevision,
		"steps.produce-lane.outcome == 'success'")
	controllerPath := strings.ReplaceAll(workflowRequiredScalar(t, workflowRequiredMapping(t, controller, "with"), "path"), "\\", "/")
	if !strings.HasSuffix(controllerPath, "/"+binary) || strings.ContainsAny(controllerPath, "*?[]\n") {
		t.Errorf("%s controller artifact path = %q, want exactly the one named controller file", lane, controllerPath)
	}
	attempt := requireWorkflowUploadStep(t, job, "upload-attempt",
		"source-qualification-attempt-"+wantLane+"-"+testedRevision+"-1",
		"steps.produce-lane.outputs.attempt-published == 'true'")
	attemptCondition := workflowRequiredScalar(t, attempt, "if")
	if strings.Contains(attemptCondition, "steps.produce-lane.outcome != 'success'") {
		t.Errorf("%s attempt upload trusts generic step failure instead of the safe publication signal", lane)
	}
	attemptPath := strings.ReplaceAll(workflowRequiredScalar(t, workflowRequiredMapping(t, attempt, "with"), "path"), "\\", "/")
	if !strings.HasSuffix(attemptPath, "/source-qualification-lane-"+lane) || strings.ContainsAny(attemptPath, "*?[]\n") {
		t.Errorf("%s non-PASS artifact path = %q, want the exact producer output directory", lane, attemptPath)
	}
}

func requireWorkflowControllerBuild(t *testing.T, job *yaml.Node, binary string) {
	t.Helper()
	checkout := workflowRequiredActionStep(t, job, "checkout", "actions/checkout")
	checkoutWith := workflowRequiredMapping(t, checkout, "with")
	for key, want := range map[string]string{
		"fetch-depth":         "0",
		"path":                "qualification-source",
		"persist-credentials": "false",
		"ref":                 "${{ needs.context.outputs.tested-revision }}",
	} {
		if got := workflowRequiredScalar(t, checkoutWith, key); got != want {
			t.Errorf("checkout input %s = %q, want %q", key, got, want)
		}
	}
	setup := workflowRequiredActionStep(t, job, "setup-go", "actions/setup-go")
	if got, want := workflowScalarMap(t, workflowRequiredMapping(t, setup, "with")), map[string]string{
		"cache": "false", "go-version": "1.26.5",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("setup-go inputs = %#v, want exact no-cache Go toolchain %#v", got, want)
	}
	build := workflowRequiredStep(t, job, "build-controller")
	if got := workflowRequiredScalar(t, build, "working-directory"); got != "${{ github.workspace }}/qualification-source" {
		t.Errorf("controller build working-directory = %q, want exact clean checkout", got)
	}
	script := requireWorkflowScriptFragments(t, build,
		"CGO_ENABLED",
		"go build",
		"-trimpath",
		"-buildvcs=true",
		"./internal/sourcequalification/cmd/repopass-source-qualify",
		"RUNNER_TEMP",
		binary,
	)
	if !regexp.MustCompile(`(?m)^\s*(?:&\s+)?go\s+build(?:\s|$)`).MatchString(script) {
		t.Error("build-controller must execute go build, not merely mention it")
	}
}

func requireWorkflowUploadStep(t *testing.T, job *yaml.Node, id, name, outcome string) *yaml.Node {
	t.Helper()
	step := workflowRequiredActionStep(t, job, id, "actions/upload-artifact")
	condition := requireAlwaysCondition(t, step, "upload step "+id)
	if outcome != "" && !strings.Contains(condition, outcome) {
		t.Errorf("upload step %s condition = %q, want %q", id, condition, outcome)
	}
	with := workflowRequiredMapping(t, step, "with")
	wantKeys := []string{"compression-level", "if-no-files-found", "include-hidden-files", "name", "overwrite", "path", "retention-days"}
	if got := workflowMappingKeys(t, with); !reflect.DeepEqual(got, wantKeys) {
		t.Errorf("upload step %s inputs = %q, want exact inputs %q", id, got, wantKeys)
	}
	for key, want := range map[string]string{
		"compression-level":    "0",
		"if-no-files-found":    "error",
		"include-hidden-files": "false",
		"name":                 name,
		"overwrite":            "false",
		"retention-days":       "90",
	} {
		if got := workflowRequiredScalar(t, with, key); got != want {
			t.Errorf("upload step %s input %s = %q, want %q", id, key, got, want)
		}
	}
	if path := workflowRequiredScalar(t, with, "path"); path == "" || strings.ContainsAny(path, "\n\r") {
		t.Errorf("upload step %s has invalid path %q", id, path)
	}
	return step
}

func requireWorkflowAggregateJob(t *testing.T, job *yaml.Node) {
	t.Helper()
	requireAlwaysCondition(t, job, "aggregate job")
	requireWorkflowControllerBuild(t, job, "repopass-source-qualify-aggregate-linux-amd64")

	wantDownloads := []struct {
		id, artifactID, path string
	}{
		{"download-linux-lane", "${{ needs.linux.outputs.lane-artifact-id }}", "${{ runner.temp }}/linux-lane"},
		{"download-linux-controller", "${{ needs.linux.outputs.controller-artifact-id }}", "${{ runner.temp }}/linux-controller"},
		{"download-windows-lane", "${{ needs.windows.outputs.lane-artifact-id }}", "${{ runner.temp }}/windows-lane"},
		{"download-windows-controller", "${{ needs.windows.outputs.controller-artifact-id }}", "${{ runner.temp }}/windows-controller"},
	}
	for _, want := range wantDownloads {
		requireWorkflowDownloadStep(t, job, want.id, want.artifactID, want.path)
	}

	assemble := workflowRequiredStep(t, job, "assemble")
	assembleScript := requireWorkflowControllerCommand(t, assemble, "assemble",
		"--linux-dir", "--windows-dir", "--expected-base-revision", "--expected-tested-revision",
		"--expected-tree", "--expected-qualification-run-id", "--expected-workflow-run-id",
		"--expected-workflow-run-attempt", "--out-dir",
	)
	for _, fragment := range []string{
		"needs.context.outputs.base-revision",
		"needs.context.outputs.tested-revision",
		"needs.context.outputs.tree-sha",
		"needs.context.outputs.qualification-run-id",
		"needs.context.outputs.workflow-run-id",
		"needs.context.outputs.workflow-run-attempt",
	} {
		if !strings.Contains(assembleScript, fragment) && !strings.Contains(workflowOperationalScalarText(assemble), fragment) {
			t.Errorf("assemble invocation is missing exact context binding %q", fragment)
		}
	}
	tools := workflowRequiredStep(t, job, "assemble-tools")
	requireWorkflowControllerCommand(t, tools, "assemble-tools",
		"--package-dir", "--linux-controller", "--windows-controller", "--out-dir",
	)

	testedRevision := "${{ needs.context.outputs.tested-revision }}"
	aggregateUpload := requireWorkflowUploadStep(t, job, "upload-aggregate", "source-qualification-aggregate-"+testedRevision, "steps.assemble.outcome == 'success'")
	toolsUpload := requireWorkflowUploadStep(t, job, "upload-tools", "source-qualification-tools-"+testedRevision, "steps.assemble-tools.outcome == 'success'")
	for id, step := range map[string]*yaml.Node{"upload-aggregate": aggregateUpload, "upload-tools": toolsUpload} {
		condition := workflowRequiredScalar(t, step, "if")
		for _, outcome := range []string{"steps.assemble.outcome == 'success'", "steps.assemble-tools.outcome == 'success'"} {
			if !strings.Contains(condition, outcome) {
				t.Errorf("aggregate publication %s condition = %q, want joint aggregate/tool success %q", id, condition, outcome)
			}
		}
	}

	outputs := workflowRequiredMapping(t, job, "outputs")
	wantOutputs := []string{
		"linux-executable-digest",
		"package-artifact-id",
		"package-digest",
		"tool-artifact-id",
		"tool-manifest-digest",
		"windows-executable-digest",
	}
	if got := workflowMappingKeys(t, outputs); !reflect.DeepEqual(got, wantOutputs) {
		t.Errorf("aggregate outputs = %q, want exact downloader outputs %q", got, wantOutputs)
	}
	for name, fragment := range map[string]string{
		"package-artifact-id": "steps.upload-aggregate.outputs.artifact-id",
		"tool-artifact-id":    "steps.upload-tools.outputs.artifact-id",
	} {
		if got := workflowRequiredScalar(t, outputs, name); !strings.Contains(got, fragment) {
			t.Errorf("aggregate output %s = %q, want binding to %q", name, got, fragment)
		}
	}
	for _, name := range []string{"package-digest", "tool-manifest-digest", "linux-executable-digest", "windows-executable-digest"} {
		if got := workflowRequiredScalar(t, outputs, name); !strings.Contains(got, "steps.") || !strings.Contains(got, ".outputs.") {
			t.Errorf("aggregate digest output %s = %q, want an explicit step output", name, got)
		}
	}
}

func requireWorkflowDownloadStep(t *testing.T, job *yaml.Node, id, artifactID, path string) *yaml.Node {
	t.Helper()
	step := workflowRequiredActionStep(t, job, id, "actions/download-artifact")
	with := workflowRequiredMapping(t, step, "with")
	want := map[string]string{"artifact-ids": artifactID, "path": path}
	if got := workflowScalarMap(t, with); !reflect.DeepEqual(got, want) {
		t.Errorf("download step %s inputs = %#v, want numeric-ID-only inputs %#v", id, got, want)
	}
	if !strings.Contains(artifactID, ".outputs.") || !strings.HasSuffix(strings.TrimSuffix(artifactID, " }}"), "artifact-id") {
		t.Errorf("download step %s artifact ID source = %q, want an upstream numeric artifact-id output", id, artifactID)
	}
	return step
}

func requireWorkflowReplayJob(t *testing.T, platform string, job *yaml.Node) {
	t.Helper()
	for _, step := range workflowSteps(t, job) {
		if workflowMappingValue(step, "uses") == nil {
			continue
		}
		action, _ := workflowAction(t, step)
		if action == "actions/checkout" || action == "actions/setup-go" || action == "actions/upload-artifact" {
			t.Errorf("replay-%s must be a no-checkout offline replay, found %s", platform, action)
		}
	}
	validateIDs := workflowRequiredStep(t, job, "validate-artifact-ids")
	validateScript := requireWorkflowScriptFragments(t, validateIDs, "^[1-9][0-9]{0,19}$")
	validateOperational := validateScript + "\n" + workflowOperationalScalarText(validateIDs)
	for _, expected := range []string{
		"needs.aggregate.outputs.package-artifact-id",
		"needs.aggregate.outputs.tool-artifact-id",
	} {
		if !strings.Contains(validateOperational, expected) {
			t.Errorf("replay-%s artifact-ID validation is missing exact upstream binding %q", platform, expected)
		}
	}

	prepare := workflowRequiredStep(t, job, "prepare-empty-directories")
	packagePath := "${{ runner.temp }}/qualification-package"
	toolPath := "${{ runner.temp }}/qualification-tools"
	prepareFragments := []string{"qualification-package", "qualification-tools"}
	if platform == "linux" {
		prepareFragments = append(prepareFragments, "test ! -e", "mkdir")
	} else {
		prepareFragments = append(prepareFragments, "Test-Path", "New-Item")
	}
	requireWorkflowScriptFragments(t, prepare, prepareFragments...)
	requireWorkflowDownloadStep(t, job, "download-package", "${{ needs.aggregate.outputs.package-artifact-id }}", packagePath)
	requireWorkflowDownloadStep(t, job, "download-tools", "${{ needs.aggregate.outputs.tool-artifact-id }}", toolPath)

	pre := workflowRequiredStep(t, job, "pre-execution-hashes")
	post := workflowRequiredStep(t, job, "post-execution-hashes")
	binary := "repopass-source-qualify-linux-amd64"
	if platform == "windows" {
		binary = "repopass-source-qualify-windows-amd64.exe"
	}
	inventory := []string{
		"repopass-source.tar",
		"source-archive-manifest-v1.json",
		"source-qualification-linux-amd64-v1.json",
		"source-qualification-windows-amd64-v1.json",
		"source-qualification-tool-manifest-v1.json",
		binary,
	}
	if platform == "linux" {
		requireWorkflowScriptFragments(t, pre, append([]string{
			"sha256sum", "actual_tool_manifest_digest", "actual_executable_digest",
			"SQ_TOOL_MANIFEST_DIGEST", "SQ_EXECUTABLE_DIGEST",
			`test "$actual_tool_manifest_digest" = "$SQ_TOOL_MANIFEST_DIGEST"`,
			`test "$actual_executable_digest" = "$SQ_EXECUTABLE_DIGEST"`,
		}, inventory...)...)
		requireWorkflowScriptFragments(t, post, append([]string{"sha256sum", "cmp"}, inventory...)...)
	} else {
		requireWorkflowScriptFragments(t, pre, append([]string{
			"Get-FileHash", "actualToolManifestDigest", "actualExecutableDigest",
			"SQ_TOOL_MANIFEST_DIGEST", "SQ_EXECUTABLE_DIGEST",
			"$actualToolManifestDigest -cne $env:SQ_TOOL_MANIFEST_DIGEST",
			"$actualExecutableDigest -cne $env:SQ_EXECUTABLE_DIGEST",
		}, inventory...)...)
		requireWorkflowScriptFragments(t, post, append([]string{"Get-FileHash", "Compare-Object"}, inventory...)...)
	}
	preText := workflowScript(t, pre) + "\n" + workflowOperationalScalarText(pre)
	for _, fragment := range []string{
		"needs.aggregate.outputs.tool-manifest-digest",
		"needs.aggregate.outputs." + platform + "-executable-digest",
	} {
		if !strings.Contains(preText, fragment) {
			t.Errorf("replay-%s pre-execution hash check is missing independent expected value %q", platform, fragment)
		}
	}

	verify := workflowRequiredStep(t, job, "verify-subject")
	verifyScript := workflowScript(t, verify)
	if platform == "linux" {
		requireWorkflowScriptFragments(t, verify,
			"sudo unshare --net", "--pid", "--mount-proc", "--fork", "--kill-child",
			"setpriv", "--reuid", "--regid", "--clear-groups", "--inh-caps=-all",
			"--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
			"env -i", "HOME=/nonexistent", "TMPDIR=/tmp",
		)
		unshareIndex := strings.Index(verifyScript, "sudo unshare --net")
		setprivIndex := strings.Index(verifyScript, "setpriv")
		verifyIndex := strings.Index(verifyScript, "repopass-source-qualify-linux-amd64\" verify-subject")
		if unshareIndex < 0 || setprivIndex <= unshareIndex || verifyIndex <= setprivIndex {
			t.Error("replay-linux must execute verify-subject inside a fresh network-disabled namespace")
		}
	} else {
		disable := workflowRequiredStep(t, job, "disable-network")
		disableScript := requireWorkflowScriptFragments(t, disable,
			"SOURCE_QUAL_GATE_BLOCKED", "throw",
		)
		if strings.Contains(disableScript, "New-NetFirewallRule") || strings.Contains(disableScript, "-Program") {
			t.Error("replay-windows must fail closed until a non-bypassable network authority exists; per-program firewall rules are insufficient")
		}
		if !regexp.MustCompile(`(?m)^\s*&\s+[^\n]*(?:repopass-source-qualify-windows-amd64\.exe|controller)[^\n]*\s+verify-subject(?:\s|$)`).MatchString(verifyScript) {
			t.Error("replay-windows must execute the downloaded Windows controller verify-subject command")
		}
		restore := workflowRequiredStep(t, job, "restore-network")
		requireAlwaysCondition(t, restore, "replay-windows network restoration")
		requireWorkflowScriptFragments(t, restore, "Remove-NetFirewallRule")
	}
	for _, fragment := range []string{
		"--package-dir",
		"--expected-repository",
		"https://github.com/taipei49314/RepoPassport",
		"--expected-base-revision",
		"--expected-tested-revision",
		"--expected-tree",
		"--expected-qualification-run-id",
		"--expected-workflow-run-id",
		"--expected-workflow-run-attempt",
		"--expected-package-digest",
		"--tool-manifest",
		"--expected-tool-manifest-digest",
		"--expected-executable-digest",
		"needs.context.outputs.base-revision",
		"needs.context.outputs.tested-revision",
		"needs.context.outputs.tree-sha",
		"needs.context.outputs.qualification-run-id",
		"needs.context.outputs.workflow-run-id",
		"needs.context.outputs.workflow-run-attempt",
		"needs.aggregate.outputs.package-digest",
		"needs.aggregate.outputs.tool-manifest-digest",
		"needs.aggregate.outputs." + platform + "-executable-digest",
	} {
		if !strings.Contains(verifyScript, fragment) && !strings.Contains(workflowOperationalScalarText(verify), fragment) {
			t.Errorf("replay-%s verify-subject is missing exact binding %q", platform, fragment)
		}
	}

	wantOrder := []string{
		"validate-artifact-ids",
		"prepare-empty-directories",
		"download-package",
		"download-tools",
		"pre-execution-hashes",
	}
	if platform == "windows" {
		wantOrder = append(wantOrder, "disable-network")
	}
	wantOrder = append(wantOrder, "verify-subject", "post-execution-hashes")
	if platform == "windows" {
		wantOrder = append(wantOrder, "restore-network")
	}
	previous := -1
	for _, id := range wantOrder {
		index := workflowStepIndex(t, job, id)
		if index <= previous {
			t.Errorf("replay-%s step %q is out of required security order %q", platform, id, wantOrder)
		}
		previous = index
	}
}

func requireWorkflowAcceptJob(t *testing.T, job *yaml.Node) {
	t.Helper()
	requireAlwaysCondition(t, job, "accept job")
	step := workflowRequiredStep(t, job, "accept")
	script := requireWorkflowScriptFragments(t, step,
		"gh api",
		"--paginate",
		"--slurp",
		"length == 0",
		"/repos/",
		"/commits/main",
		"/actions/workflows/source-qualification.yml/runs",
		"default_branch",
		"head_sha",
		"run_attempt",
		"conclusion",
		"parents",
		"tree",
		"jq -cS",
	)
	operational := script + "\n" + workflowOperationalScalarText(step)
	for _, fragment := range []string{
		"${{ github.token }}",
		"${{ github.repository }}",
		"${{ github.event_name }}",
		"${{ github.ref }}",
		"${{ github.run_id }}",
		"${{ github.run_attempt }}",
		"${{ needs.context.outputs.base-revision }}",
		"${{ needs.context.outputs.tested-revision }}",
		"${{ needs.context.outputs.tree-sha }}",
		"${{ needs.context.outputs.qualification-run-id }}",
		"${{ needs.context.result }}",
		"${{ needs.aggregate.outputs.package-artifact-id }}",
		"${{ needs.aggregate.outputs.package-digest }}",
		"${{ needs.aggregate.outputs.tool-artifact-id }}",
		"${{ needs.aggregate.outputs.tool-manifest-digest }}",
		"${{ needs.linux.result }}",
		"${{ needs.windows.result }}",
		"${{ needs.aggregate.result }}",
		"${{ needs.replay-linux.result }}",
		"${{ needs.replay-windows.result }}",
		"refs/heads/main",
		"push",
		"failure",
		"cancelled",
		"timed_out",
		"skipped",
	} {
		if !strings.Contains(operational, fragment) {
			t.Errorf("accept step is missing live/currentness/fail-closed binding %q", fragment)
		}
	}
	for label, pattern := range map[string]string{
		"first run attempt": `(?m)(?:RUN_ATTEMPT|run_attempt)[^\n]*(?:==|!=|-eq|-ne)[^\n]*["']?1["']?`,
		"main ref":          `(?m)(?:REF|ref)[^\n]*(?:==|!=|-eq|-ne)[^\n]*refs/heads/main`,
		"push event":        `(?m)(?:EVENT|event)[^\n]*(?:==|!=|-eq|-ne)[^\n]*push`,
	} {
		if !regexp.MustCompile(pattern).MatchString(script) {
			t.Errorf("accept step does not actively enforce %s", label)
		}
	}
	for _, key := range []string{
		"code",
		"packageArtifactId",
		"packageDigest",
		"qualificationRunId",
		"qualificationStatus",
		"testedRevision",
		"toolArtifactId",
		"toolManifestDigest",
		"treeSHA",
		"workflowURL",
	} {
		if !strings.Contains(script, key) {
			t.Errorf("accept canonical JSONL record is missing exact key %q", key)
		}
	}
}

func requireWorkflowSafety(t *testing.T, workflow *yaml.Node) {
	t.Helper()
	var walk func(*yaml.Node, string)
	walk = func(node *yaml.Node, path string) {
		if node.Kind == yaml.MappingNode {
			for index := 0; index < len(node.Content); index += 2 {
				key := node.Content[index].Value
				value := node.Content[index+1]
				switch key {
				case "continue-on-error":
					t.Errorf("%s.%s is forbidden; required failures must remain visible", path, key)
				case "environment":
					t.Errorf("%s.%s is forbidden; source qualification has no deployment environment", path, key)
				case "permissions":
					if path != "workflow" {
						t.Errorf("%s.%s overrides the exact workflow-level read-only permissions", path, key)
					}
				case "id-token":
					t.Errorf("%s.%s is forbidden; source qualification has no OIDC authority", path, key)
				case "cache-dependency-path", "restore-keys":
					t.Errorf("%s.%s is forbidden; source qualification uses no Actions cache", path, key)
				case "cache":
					if value.Kind != yaml.ScalarNode || strings.TrimSpace(value.Value) != "false" {
						t.Errorf("%s.cache must be explicitly false", path)
					}
				case "run":
					if value.Kind != yaml.ScalarNode || strings.Contains(value.Value, "${{") {
						t.Errorf("%s.run must receive workflow expressions through typed environment entries, never direct shell interpolation", path)
					}
				}
				walk(value, path+"."+key)
			}
			return
		}
		if node.Kind == yaml.ScalarNode && strings.Contains(strings.ToLower(node.Value), "secrets.") {
			t.Errorf("%s references repository/environment secrets", path)
		}
		for index, child := range node.Content {
			walk(child, fmt.Sprintf("%s[%d]", path, index))
		}
	}
	walk(workflow, "workflow")

	counts := map[string]int{}
	jobs := workflowRequiredMapping(t, workflow, "jobs")
	for _, jobName := range workflowMappingKeys(t, jobs) {
		job := workflowRequiredMapping(t, jobs, jobName)
		for _, step := range workflowSteps(t, job) {
			if workflowMappingValue(step, "uses") == nil {
				continue
			}
			action, _ := workflowAction(t, step)
			counts[action]++
			switch action {
			case "actions/checkout":
				with := workflowRequiredMapping(t, step, "with")
				for key, want := range map[string]string{
					"fetch-depth": "0", "persist-credentials": "false", "ref": "${{ needs.context.outputs.tested-revision }}",
				} {
					if got := workflowRequiredScalar(t, with, key); got != want {
						t.Errorf("%s checkout %s = %q, want %q", jobName, key, got, want)
					}
				}
				if path := workflowRequiredScalar(t, with, "path"); path == "" || path == "." {
					t.Errorf("%s checkout path must be an explicit distinct clean path", jobName)
				}
			case "actions/setup-go":
				if got, want := workflowScalarMap(t, workflowRequiredMapping(t, step, "with")), map[string]string{
					"cache": "false", "go-version": "1.26.5",
				}; !reflect.DeepEqual(got, want) {
					t.Errorf("%s setup-go inputs = %#v, want %#v", jobName, got, want)
				}
			case "actions/download-artifact":
				if got := workflowMappingKeys(t, workflowRequiredMapping(t, step, "with")); !reflect.DeepEqual(got, []string{"artifact-ids", "path"}) {
					t.Errorf("%s download inputs = %q; name/pattern/run/repository fallback is forbidden", jobName, got)
				}
			case "actions/upload-artifact":
				with := workflowRequiredMapping(t, step, "with")
				for key, want := range map[string]string{
					"compression-level": "0", "if-no-files-found": "error", "include-hidden-files": "false",
					"overwrite": "false", "retention-days": "90",
				} {
					if got := workflowRequiredScalar(t, with, key); got != want {
						t.Errorf("%s upload %s = %q, want %q", jobName, key, got, want)
					}
				}
			}
		}
	}
	wantCounts := map[string]int{
		"actions/checkout":          3,
		"actions/download-artifact": 8,
		"actions/setup-go":          3,
		"actions/upload-artifact":   8,
	}
	if !reflect.DeepEqual(counts, wantCounts) {
		t.Errorf("workflow action counts = %#v, want exact no-cache/no-fallback action surface %#v", counts, wantCounts)
	}
}

func workflowOperationalScalarText(node *yaml.Node) string {
	values := []string{}
	var walk func(*yaml.Node)
	walk = func(current *yaml.Node) {
		switch current.Kind {
		case yaml.MappingNode:
			for index := 0; index < len(current.Content); index += 2 {
				key := current.Content[index].Value
				value := current.Content[index+1]
				if key == "name" {
					continue
				}
				if key == "run" && value.Kind == yaml.ScalarNode {
					lines := strings.Split(strings.ReplaceAll(value.Value, "\r\n", "\n"), "\n")
					for _, line := range lines {
						if !strings.HasPrefix(strings.TrimSpace(line), "#") {
							values = append(values, line)
						}
					}
					continue
				}
				walk(value)
			}
		case yaml.SequenceNode, yaml.DocumentNode:
			for _, child := range current.Content {
				walk(child)
			}
		case yaml.ScalarNode:
			values = append(values, current.Value)
		}
	}
	walk(node)
	return strings.Join(values, "\n")
}

func workflowGoStringLiterals(t *testing.T, directory string) map[string]bool {
	t.Helper()
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, directory, func(info os.FileInfo) bool {
		return strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse private source-qualification CLI: %v", err)
	}
	values := map[string]bool{}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err == nil {
					values[value] = true
				}
				return true
			})
		}
	}
	return values
}
