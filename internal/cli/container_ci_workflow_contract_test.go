package cli

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	containerCINodeImage        = "docker.io/library/node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3"
	containerCINodeAMD64Image   = "sha256:8607a9064d4a571140998ae9e52a3b3fcf9cff361d04642d5971e6cd76d39e27"
	containerCIPythonImage      = "docker.io/library/python:3.12.13-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
	containerCIPythonAMD64Image = "sha256:cab2dbf575e971934a81e4622f5aba17aa7929719bd7e31033a3a83b97fd0464"
)

func TestContainerCIHealthyJourneyRequiredGateContract(t *testing.T) {
	workflow := containerCIWorkflow(t)
	jobs := containerCIRequiredMapping(t, workflow, "jobs")
	job := containerCIRequiredMapping(t, jobs, "container-integration")

	t.Run("required Docker and Podman matrix", func(t *testing.T) {
		if got := containerCIRequiredScalar(t, job, "name"); got != "Container healthy journeys (${{ matrix.backend }})" {
			t.Errorf("container job name = %q, want a distinct required check for each backend", got)
		}
		if got := containerCIRequiredScalar(t, job, "runs-on"); got != "ubuntu-24.04" {
			t.Errorf("container job runs-on = %q, want explicit ubuntu-24.04 runner label", got)
		}
		if got := containerCIStringSequence(t, containerCIRequiredValue(t, job, "needs")); !reflect.DeepEqual(got, []string{"go", "schema-json"}) {
			t.Errorf("container job needs = %q, want exact required prerequisites [go schema-json]", got)
		}

		strategy := containerCIRequiredMapping(t, job, "strategy")
		if got := containerCIRequiredScalar(t, strategy, "fail-fast"); got != "false" {
			t.Errorf("container matrix fail-fast = %q, want false so both first attempts remain visible", got)
		}
		matrix := containerCIRequiredMapping(t, strategy, "matrix")
		if got := containerCIStringSequence(t, containerCIRequiredValue(t, matrix, "backend")); !reflect.DeepEqual(got, []string{"docker", "podman"}) {
			t.Errorf("container backend matrix = %q, want exact [docker podman]", got)
		}
	})

	t.Run("no optional or soft-fail bypass", func(t *testing.T) {
		if node := containerCIMappingValue(job, "if"); node != nil {
			t.Errorf("required container job must not have if guard, got %q", node.Value)
		}
		if containerCIContainsMappingKey(job, "continue-on-error") {
			t.Error("required container job must not use continue-on-error at job or step scope")
		}
		raw := string(containerCIRawWorkflow(t))
		if strings.Contains(raw, "REPOPASS_RUN_CONTAINER_INTEGRATION") || strings.Contains(strings.ToLower(raw), "opt-in") {
			t.Error("required container job still exposes an opt-in path")
		}
	})

	t.Run("current checkout source annotation", func(t *testing.T) {
		step := containerCIRequiredStep(t, job, "source-binding")
		if got := containerCIRequiredScalar(t, containerCIRequiredMapping(t, step, "env"), "EXPECTED_SOURCE_SHA"); got != "${{ github.sha }}" {
			t.Errorf("source-binding EXPECTED_SOURCE_SHA = %q, want exact GitHub event SHA", got)
		}
		script := containerCIRequiredScalar(t, step, "run")
		for _, fragment := range []string{
			"git rev-parse --verify HEAD",
			"git rev-parse --verify HEAD^{tree}",
			"git status --porcelain",
			"EXPECTED_SOURCE_SHA",
			"REPOPASS_M1_JOURNEY_SOURCE",
			`"dirty":false`,
		} {
			if !strings.Contains(script, fragment) {
				t.Errorf("source-binding step is missing %q", fragment)
			}
		}
		if strings.Contains(script, "${{") {
			t.Error("source-binding run script must consume expressions through typed env, not direct shell interpolation")
		}
	})

	t.Run("exact approved images on selected backend", func(t *testing.T) {
		step := containerCIRequiredStep(t, job, "prepare-images")
		if got := containerCIRequiredScalar(t, containerCIRequiredMapping(t, step, "env"), "CONTAINER_BACKEND"); got != "${{ matrix.backend }}" {
			t.Errorf("prepare-images backend = %q, want matrix backend", got)
		}
		script := containerCIRequiredScalar(t, step, "run")
		for _, fragment := range []string{
			containerCINodeImage,
			containerCINodeAMD64Image,
			containerCIPythonImage,
			containerCIPythonAMD64Image,
			"skopeo inspect --raw",
			"sha256sum",
			"pull --platform linux/amd64",
			"image inspect",
		} {
			if !strings.Contains(script, fragment) {
				t.Errorf("prepare-images step is missing %q", fragment)
			}
		}
		if strings.Contains(script, "${{") {
			t.Error("prepare-images run script must consume the selected backend through env")
		}
	})

	t.Run("only named healthy journeys", func(t *testing.T) {
		step := containerCIRequiredStep(t, job, "healthy-journeys")
		if got := containerCIRequiredScalar(t, containerCIRequiredMapping(t, step, "env"), "REPOPASS_INTEGRATION_BACKEND"); got != "${{ matrix.backend }}" {
			t.Errorf("healthy-journeys backend = %q, want matrix backend", got)
		}
		const command = "go test -timeout=25m -tags=integration -count=1 -v ./internal/cli -run '^TestContainerHealthyJourneys$'"
		if got := strings.TrimSpace(containerCIRequiredScalar(t, step, "run")); got != command {
			t.Errorf("healthy journey command = %q, want exact named-only command %q", got, command)
		}
	})

	t.Run("always-run labeled residue check", func(t *testing.T) {
		step := containerCIRequiredStep(t, job, "residue-check")
		if got := containerCIRequiredScalar(t, step, "if"); got != "${{ always() }}" {
			t.Errorf("residue-check if = %q, want always()", got)
		}
		if got := containerCIRequiredScalar(t, containerCIRequiredMapping(t, step, "env"), "CONTAINER_BACKEND"); got != "${{ matrix.backend }}" {
			t.Errorf("residue-check backend = %q, want matrix backend", got)
		}
		script := containerCIRequiredScalar(t, step, "run")
		for _, fragment := range []string{
			"ps -aq",
			"label=dev.repopass.run",
			"container inspect",
		} {
			if !strings.Contains(script, fragment) {
				t.Errorf("residue-check step is missing %q", fragment)
			}
		}
		if strings.Contains(script, " rm ") || strings.Contains(script, "remove") {
			t.Error("residue-check must report and fail, not erase residue")
		}
	})
}

func containerCIWorkflow(t *testing.T) *yaml.Node {
	t.Helper()
	document := &yaml.Node{}
	decoder := yaml.NewDecoder(strings.NewReader(string(containerCIRawWorkflow(t))))
	if err := decoder.Decode(document); err != nil {
		t.Fatalf("parse .github/workflows/ci.yml: %v", err)
	}
	extra := &yaml.Node{}
	if err := decoder.Decode(extra); err != io.EOF {
		if err == nil {
			t.Fatal(".github/workflows/ci.yml must contain exactly one YAML document")
		}
		t.Fatalf("parse trailing .github/workflows/ci.yml content: %v", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		t.Fatalf(".github/workflows/ci.yml root is not a mapping")
	}
	containerCIValidateYAMLNode(t, document.Content[0], "workflow")
	return document.Content[0]
}

func containerCIValidateYAMLNode(t *testing.T, node *yaml.Node, location string) {
	t.Helper()
	if node == nil {
		t.Fatalf("%s is nil", location)
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		t.Fatalf("%s uses a YAML alias or anchor", location)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Value == "" || key.Value == "<<" {
				t.Fatalf("%s has a non-scalar, empty, or merge key", location)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				t.Fatalf("%s has duplicate key %q", location, key.Value)
			}
			seen[key.Value] = struct{}{}
			containerCIValidateYAMLNode(
				t,
				node.Content[index+1],
				location+"."+key.Value,
			)
		}
		return
	}
	for index, child := range node.Content {
		containerCIValidateYAMLNode(
			t,
			child,
			location+"["+strconv.Itoa(index)+"]",
		)
	}
}

func containerCIRawWorkflow(t *testing.T) []byte {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Clean(filepath.Join(directory, "..", "..", ".github", "workflows", "ci.yml"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read required CI workflow %s: %v", filepath.ToSlash(path), err)
	}
	return raw
}

func containerCIMappingValue(mapping *yaml.Node, key string) *yaml.Node {
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

func containerCIRequiredValue(t *testing.T, mapping *yaml.Node, key string) *yaml.Node {
	t.Helper()
	value := containerCIMappingValue(mapping, key)
	if value == nil {
		t.Fatalf("required CI workflow key %q is absent", key)
	}
	return value
}

func containerCIRequiredMapping(t *testing.T, mapping *yaml.Node, key string) *yaml.Node {
	t.Helper()
	value := containerCIRequiredValue(t, mapping, key)
	if value.Kind != yaml.MappingNode {
		t.Fatalf("required CI workflow key %q is not a mapping", key)
	}
	return value
}

func containerCIRequiredScalar(t *testing.T, mapping *yaml.Node, key string) string {
	t.Helper()
	value := containerCIRequiredValue(t, mapping, key)
	if value.Kind != yaml.ScalarNode {
		t.Fatalf("required CI workflow key %q is not a scalar", key)
	}
	return value.Value
}

func containerCIStringSequence(t *testing.T, value *yaml.Node) []string {
	t.Helper()
	if value.Kind == yaml.ScalarNode {
		return []string{value.Value}
	}
	if value.Kind != yaml.SequenceNode {
		t.Fatalf("required CI workflow value is not a string sequence")
	}
	result := make([]string, len(value.Content))
	for index, item := range value.Content {
		if item.Kind != yaml.ScalarNode {
			t.Fatalf("required CI workflow sequence item %d is not a scalar", index)
		}
		result[index] = item.Value
	}
	return result
}

func containerCIRequiredStep(t *testing.T, job *yaml.Node, id string) *yaml.Node {
	t.Helper()
	steps := containerCIRequiredValue(t, job, "steps")
	if steps.Kind != yaml.SequenceNode {
		t.Fatal("container job steps is not a sequence")
	}
	for _, step := range steps.Content {
		if value := containerCIMappingValue(step, "id"); value != nil && value.Value == id {
			return step
		}
	}
	t.Fatalf("container job is missing required step id %q", id)
	return nil
}

func containerCIContainsMappingKey(node *yaml.Node, wanted string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if node.Content[index].Value == wanted {
				return true
			}
		}
	}
	for _, child := range node.Content {
		if containerCIContainsMappingKey(child, wanted) {
			return true
		}
	}
	return false
}
