package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/domain"
	"gopkg.in/yaml.v3"
)

func TestKnownFieldGateCoversPublicSchemaObjects(t *testing.T) {
	type schemaObject struct {
		Properties map[string]json.RawMessage `json:"properties"`
		OneOf      []schemaObject             `json:"oneOf"`
	}
	var publicSchema struct {
		Properties  map[string]json.RawMessage `json:"properties"`
		Definitions map[string]schemaObject    `json:"$defs"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "repo-passport.schema.json"))
	if err != nil {
		t.Fatalf("Read public schema: %v", err)
	}
	if err := json.Unmarshal(data, &publicSchema); err != nil {
		t.Fatalf("Decode public schema: %v", err)
	}

	targets := map[string][]reflect.Type{
		"baseImage":             {reflect.TypeOf(BaseImageSpec{})},
		"capabilitiesByPhase":   {reflect.TypeOf(map[domain.Phase]domain.CapabilitySet{})},
		"capabilitySet":         {reflect.TypeOf(domain.CapabilitySet{})},
		"cliAssertion":          {reflect.TypeOf(DriverAssertion{})},
		"cliDriver":             {reflect.TypeOf(DriverSpec{})},
		"commandSpec":           {reflect.TypeOf(RunAction{})},
		"environment":           {reflect.TypeOf(EnvironmentSpec{})},
		"environmentCapability": {reflect.TypeOf(domain.EnvironmentCapability{})},
		"environmentReference":  {reflect.TypeOf(EnvironmentReference{})},
		"evidence":              {reflect.TypeOf(EvidenceSpec{})},
		"exercisePhase":         {reflect.TypeOf(ExercisePhase{})},
		"filesystemCapability":  {reflect.TypeOf(domain.FilesystemCapability{})},
		"httpAssertion":         {reflect.TypeOf(DriverAssertion{})},
		"httpAssertionStep":     {reflect.TypeOf(DriverStep{})},
		"httpDriver":            {reflect.TypeOf(DriverSpec{})},
		"httpReadiness":         {reflect.TypeOf(HTTPReadiness{})},
		"httpRequest":           {reflect.TypeOf(HTTPRequest{})},
		"httpRequestStep":       {reflect.TypeOf(DriverStep{})},
		"httpResponseAssertion": {reflect.TypeOf(ResponseAssertion{})},
		"httpJSONFileAssertion": {reflect.TypeOf(JSONFileAssertion{})},
		"input":                 {reflect.TypeOf(InputSpec{})},
		"inputMount":            {reflect.TypeOf(MountSpec{})},
		"jsonFileAssertion":     {reflect.TypeOf(JSONFileAssertion{})},
		"listenEndpoint":        {reflect.TypeOf(domain.PortBinding{})},
		"maintainer":            {reflect.TypeOf(Maintainer{})},
		"metadata":              {reflect.TypeOf(Metadata{})},
		"networkCapability":     {reflect.TypeOf(domain.NetworkCapability{})},
		"networkEndpoint":       {reflect.TypeOf(domain.NetworkDestination{})},
		"observerRequirement":   {reflect.TypeOf(ObserverRequirement{})},
		"phases":                {reflect.TypeOf(PhaseSet{})},
		"platform":              {reflect.TypeOf(PlatformSpec{})},
		"policies":              {reflect.TypeOf(PolicySpec{})},
		"portCapability":        {reflect.TypeOf(domain.PortCapability{})},
		"processCapability":     {reflect.TypeOf(domain.ProcessCapability{})},
		"project":               {reflect.TypeOf(ProjectSpec{})},
		"readiness":             {reflect.TypeOf(ReadinessSpec{})},
		"resourceLimits": {
			reflect.TypeOf(ResourceSpec{}),
			reflect.TypeOf(domain.DeclaredResourceLimits{}),
		},
		"runPhase":             {reflect.TypeOf(RunPhase{})},
		"runtime":              {reflect.TypeOf(RuntimeSpec{})},
		"scenario":             {reflect.TypeOf(ScenarioSpec{})},
		"secret":               {reflect.TypeOf(SecretSpec{})},
		"service":              {reflect.TypeOf(ServiceSpec{})},
		"shellCommand":         {reflect.TypeOf(ShellCommand{})},
		"signalSpec":           {reflect.TypeOf(SignalAction{})},
		"spec":                 {reflect.TypeOf(Spec{})},
		"step":                 {reflect.TypeOf(PhaseStep{})},
		"stepPhase":            {reflect.TypeOf(CommandPhase{})},
		"verificationSettings": {reflect.TypeOf(VerificationSpec{})},
	}

	assertGate := func(name string, target reflect.Type, properties map[string]json.RawMessage) {
		t.Helper()
		names := make([]string, 0, len(properties))
		for property := range properties {
			names = append(names, property)
		}
		sort.Strings(names)
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, property := range names {
			node.Content = append(
				node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: property},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"},
			)
		}
		if err := validateKnownFields(node, target, "$."+name); err != nil {
			t.Errorf("%s fields are rejected by the Go known-field gate for %s: %v", name, target, err)
		}
	}
	publicProperties := func(object schemaObject) map[string]json.RawMessage {
		properties := make(map[string]json.RawMessage, len(object.Properties))
		for name, value := range object.Properties {
			properties[name] = value
		}
		for _, variant := range object.OneOf {
			for name, value := range variant.Properties {
				properties[name] = value
			}
		}
		return properties
	}

	assertGate("manifest", reflect.TypeOf(Manifest{}), publicSchema.Properties)
	for name, object := range publicSchema.Definitions {
		properties := publicProperties(object)
		if len(properties) == 0 {
			continue
		}
		objectTargets, ok := targets[name]
		if !ok {
			t.Errorf("public schema object %q has no Go known-field target", name)
			continue
		}
		for _, target := range objectTargets {
			assertGate(name, target, properties)
		}
	}
	for name, contract := range map[string]struct {
		target     reflect.Type
		properties []string
	}{
		"cleanup":      {reflect.TypeOf(CleanupSpec{}), []string{"allowedResidue"}},
		"header":       {reflect.TypeOf(HeaderAssertion{}), []string{"name", "contains"}},
		"jsonPath":     {reflect.TypeOf(JSONPathAssertion{}), []string{"path", "equals"}},
		"secretScope":  {reflect.TypeOf(SecretScope{}), []string{"phases"}},
		"secretExpose": {reflect.TypeOf(SecretExpose{}), []string{"env"}},
	} {
		properties := make(map[string]json.RawMessage, len(contract.properties))
		for _, property := range contract.properties {
			properties[property] = nil
		}
		assertGate(name, contract.target, properties)
	}
}

func TestLoadRejectsUnknownFieldAndAllowsExtension(t *testing.T) {
	tests := []struct {
		name     string
		extra    string
		wantCode domain.ErrorCode
	}{
		{
			name:     "unknown field",
			extra:    "    definitelyUnknown: true",
			wantCode: domain.CodeManifestUnknownField,
		},
		{
			name:  "x extension",
			extra: "    x-test-note: accepted",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeManifest(t, validManifestYAML(test.extra))
			document, err := Load(path)
			if test.wantCode != "" {
				if err == nil {
					t.Fatalf("Load(%s) unexpectedly succeeded", test.name)
				}
				if got := domain.ErrorCodeOf(err); got != test.wantCode {
					t.Fatalf("Load(%s) error code = %q, want %q: %v", test.name, got, test.wantCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load(%s): %v", test.name, err)
			}
			if validationErrors := Validate(document); len(validationErrors) != 0 {
				t.Fatalf("Validate(%s) returned errors: %v", test.name, validationErrors)
			}
		})
	}
}

func TestScenarioLiteralSecretIsRejectedWithStableCode(t *testing.T) {
	path := filepath.Join(
		"..", "..", "testdata", "fixtures", "invalid", "literal-secret", "repo-passport.yml",
	)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load literal-secret fixture unexpectedly succeeded")
	}

	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestLiteralSecret {
		t.Fatalf("literal-secret code = %q, want %q: %v", got, domain.CodeManifestLiteralSecret, err)
	}
	var manifestError *domain.Error
	if !errors.As(err, &manifestError) {
		t.Fatalf("literal-secret error type = %T, want *domain.Error", err)
	}
	if got, want := manifestError.Details["path"], "$.spec.scenarios.quickstart.secrets.api-key.source"; got != want {
		t.Fatalf("literal-secret field = %#v, want %q", got, want)
	}
}

func TestLoadRejectsMultipleYAMLDocuments(t *testing.T) {
	path := writeManifest(t, validManifestYAML("")+"\n---\n{}\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load unexpectedly accepted multiple YAML documents")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("multiple-document code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
}

func TestLoadRejectsOversizeManifestBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo-passport.yml")
	content := bytes.Repeat([]byte{'x'}, maxManifestBytes+1)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write oversize manifest: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load unexpectedly accepted an over-limit manifest")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("oversize error code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
	if !strings.Contains(err.Error(), "4 MiB") || strings.Contains(err.Error(), path) {
		t.Fatalf("oversize error must be fixed and non-echoing: %v", err)
	}
}

func TestLoadRejectsManifestSymlink(t *testing.T) {
	target := writeManifest(t, validManifestYAML(""))
	path := filepath.Join(t.TempDir(), "repo-passport.yml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load unexpectedly followed a manifest symlink")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("symlink error code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("symlink error leaked caller path: %v", err)
	}
}

func TestLoadRejectsHardLinkedManifestWithoutPathLeakage(t *testing.T) {
	original := writeManifest(t, validManifestYAML(""))
	alias := filepath.Join(t.TempDir(), "repo-passport-alias.yml")
	if err := os.Link(original, alias); err != nil {
		t.Skipf("hard-link creation is unavailable: %v", err)
	}

	for _, path := range []string{original, alias} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load unexpectedly accepted a hard-linked manifest")
			}
			if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
				t.Fatalf("hard-link error code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
			}
			serialized, marshalErr := json.Marshal(err)
			if marshalErr != nil {
				t.Fatalf("serialize hard-link error: %v", marshalErr)
			}
			for _, forbidden := range []string{original, alias} {
				if strings.Contains(err.Error(), forbidden) || bytes.Contains(serialized, []byte(forbidden)) {
					t.Fatalf("hard-link rejection leaked a caller path: %v / %s", err, serialized)
				}
			}
		})
	}
}

func TestLoadRejectsMutationAfterFirstRead(t *testing.T) {
	initial := validManifestYAML("")
	mutated := strings.Replace(initial, "manifest-contract-test", "manifest-contract-txst", 1)
	if len(initial) != len(mutated) {
		t.Fatal("test mutation must preserve file size")
	}
	path := writeManifest(t, initial)
	_, err := load(path, func() {
		if writeErr := os.WriteFile(path, []byte(mutated), 0o600); writeErr != nil {
			t.Fatalf("mutate manifest: %v", writeErr)
		}
	})
	if err == nil {
		t.Fatal("Load unexpectedly accepted a manifest mutated between reads")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("mutation error code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
	if !strings.Contains(err.Error(), "changed while") || strings.Contains(err.Error(), path) {
		t.Fatalf("mutation error must be fixed and non-echoing: %v", err)
	}
}

func TestLoadRunsEmbeddedPublicSchema(t *testing.T) {
	oversizedDescription := strings.Repeat("x", 2001)
	content := strings.Replace(
		validManifestYAML(""),
		"  name: manifest-contract-test",
		"  name: manifest-contract-test\n  description: \""+oversizedDescription+"\"",
		1,
	)
	_, err := Load(writeManifest(t, content))
	if err == nil {
		t.Fatal("Load unexpectedly accepted a description beyond the public schema limit")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("schema failure code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
}

func TestLoadAcceptsDeferredPublicSchemaFieldsBeforePlannerFeatureGate(t *testing.T) {
	content := strings.Replace(
		validManifestYAML(""),
		"        pids: 64",
		"        pids: 64\n        time: 1m\n        logBytes: 1024\n      requiredRunnerFeatures: [network-deny]",
		1,
	)
	content = strings.Replace(
		content,
		"        exercise:\n          timeout: 30s",
		"        exercise:\n          timeout: 30s\n          outputs: [/outputs/result.json]",
		1,
	)
	document, err := Load(writeManifest(t, content))
	if err != nil {
		t.Fatalf("Load rejected public-schema fields reserved for a later executable profile: %v", err)
	}
	if validationErrors := Validate(document); len(validationErrors) != 0 {
		t.Fatalf("Validate returned structural errors for schema-valid deferred fields: %v", validationErrors)
	}
}

func TestLoadPreservesChoicePhaseCommandAndHUPSchemaFields(t *testing.T) {
	content := strings.Replace(
		validManifestYAML(""),
		"    quickstart:\n      environment: linux-node\n      phases:",
		`    quickstart:
      environment: linux-node
      inputs:
        mode:
          type: choice
          required: true
          choices: [fast, 2, true]
      phases:
        prepare:
          timeout: 20s
          observerRequirements:
            - observer: process-exec
              minimumCoverage: full
          outputs: [/outputs/prepare.json]
          steps:
            - id: configure
              run:
                shell:
                  executable: /bin/sh
                  command: echo ready
                workingDirectory: /workspace
                environment:
                  MODE:
                    source: input
                    name: mode
                timeout: 5s
                allowedExitCodes: [0, 2]
                outputMode: text
        setup:
          steps:
            - id: reload
              signal:
                target: app
                type: hup
                gracePeriod: 1s`,
		1,
	)
	document, err := Load(writeManifest(t, content))
	if err != nil {
		t.Fatalf("Load rejected fields declared by the public schema: %v", err)
	}
	validationErrors := Validate(document)
	if len(validationErrors) == 0 {
		t.Fatal("Validate unexpectedly approved shell execution")
	}
	if got := validationErrors[0].Code; got != domain.CodeManifestUnsafeShell {
		t.Fatalf("shell error code = %q, want %q: %v", got, domain.CodeManifestUnsafeShell, validationErrors)
	}
	if got, want := validationErrors[0].Details["field"], "spec.scenarios.quickstart.phases.prepare.steps[0].run.shell"; got != want {
		t.Fatalf("shell error field = %#v, want %q", got, want)
	}

	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	input := scenario.Inputs["mode"]
	if !input.Required || len(input.Choices) != 3 {
		t.Fatalf("choice input was not preserved: %#v", input)
	}
	prepare := scenario.Phases.Prepare
	if prepare == nil || len(prepare.ObserverRequirements) != 1 || len(prepare.Outputs) != 1 ||
		len(prepare.Steps) != 1 || prepare.Steps[0].Run == nil {
		t.Fatalf("prepare phase fields were not preserved: %#v", prepare)
	}
	action := prepare.Steps[0].Run
	if action.Shell == nil || action.WorkingDirectory != "/workspace" ||
		len(action.Environment) != 1 || len(action.AllowedExitCodes) != 2 ||
		action.Timeout != "5s" || action.OutputMode != "text" {
		t.Fatalf("command fields were not preserved: %#v", action)
	}
	setup := scenario.Phases.Setup
	if setup == nil || len(setup.Steps) != 1 || setup.Steps[0].Signal == nil ||
		setup.Steps[0].Signal.Type != "hup" {
		t.Fatalf("hup signal was not preserved: %#v", setup)
	}
}

func TestInputRequiredFalseSurvivesYAMLSerialization(t *testing.T) {
	data, err := yaml.Marshal(InputSpec{
		Type:     "choice",
		Required: false,
		Choices:  []any{"fast", "safe"},
	})
	if err != nil {
		t.Fatalf("Marshal input: %v", err)
	}
	if !strings.Contains(string(data), "required: false") {
		t.Fatalf("serialized optional input lost required: false:\n%s", data)
	}
}

func TestInputChoicesDistinguishesAbsentFromExplicitEmptyYAML(t *testing.T) {
	var absent InputSpec
	if err := yaml.Unmarshal(
		[]byte("type: file\nrequired: true\n"),
		&absent,
	); err != nil {
		t.Fatalf("unmarshal absent choices: %v", err)
	}
	if absent.Choices != nil {
		t.Fatalf("absent choices decoded as present: %#v", absent.Choices)
	}

	var explicitEmpty InputSpec
	if err := yaml.Unmarshal(
		[]byte("type: file\nrequired: true\nchoices: []\n"),
		&explicitEmpty,
	); err != nil {
		t.Fatalf("unmarshal explicit empty choices: %v", err)
	}
	if explicitEmpty.Choices == nil || len(explicitEmpty.Choices) != 0 {
		t.Fatalf(
			"explicit empty choices presence was lost: %#v",
			explicitEmpty.Choices,
		)
	}
}

func TestValidateRejectsDanglingProjectEntrypoint(t *testing.T) {
	document, err := Load(writeManifest(t, strings.Replace(
		validManifestYAML(""),
		"entrypoints: [quickstart]",
		"entrypoints: [missing-scenario]",
		1,
	)))
	if err != nil {
		t.Fatalf("Load schema-valid manifest: %v", err)
	}
	validationErrors := Validate(document)
	if len(validationErrors) == 0 {
		t.Fatal("Validate unexpectedly accepted a dangling project entrypoint")
	}
	if got := validationErrors[0].Code; got != domain.CodeManifestInvalid {
		t.Fatalf("entrypoint error code = %q, want %q", got, domain.CodeManifestInvalid)
	}
	if got, want := validationErrors[0].Details["field"], "spec.project.entrypoints[0]"; got != want {
		t.Fatalf("entrypoint error field = %#v, want %q", got, want)
	}
}

func TestValidateRejectsShellBeforeStructuralCommandErrors(t *testing.T) {
	tests := []struct {
		name      string
		wantField string
		mutate    func(*ScenarioSpec)
	}{
		{
			name:      "phase step shell",
			wantField: "spec.scenarios.quickstart.phases.prepare.steps[0].run.shell",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Prepare = &CommandPhase{
					Steps: []PhaseStep{{
						ID: "unsafe-shell",
						Run: &RunAction{
							Command: []string{"node", "--version"},
							Shell: &ShellCommand{
								Executable: "/bin/sh",
								Command:    "echo unsafe",
							},
						},
					}},
				}
			},
		},
		{
			name:      "service shell",
			wantField: "spec.scenarios.quickstart.phases.run.service.shell",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run = &RunPhase{
					Service: &ServiceSpec{
						ID:      "app",
						Command: []string{"node", "server.mjs"},
						Shell: &ShellCommand{
							Executable: "/bin/sh",
							Command:    "node server.mjs",
						},
					},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Load(writeManifest(t, validManifestYAML("")))
			if err != nil {
				t.Fatalf("Load valid manifest: %v", err)
			}
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			test.mutate(&scenario)
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			validationErrors := Validate(document)
			if len(validationErrors) < 2 {
				t.Fatalf("Validate errors = %v, want unsafe-shell plus structural error", validationErrors)
			}
			if got := validationErrors[0].Code; got != domain.CodeManifestUnsafeShell {
				t.Fatalf("first error code = %q, want %q: %v", got, domain.CodeManifestUnsafeShell, validationErrors)
			}
			if got := validationErrors[0].Details["field"]; got != test.wantField {
				t.Fatalf("unsafe-shell field = %#v, want %q", got, test.wantField)
			}
			if got := validationErrors[1].Code; got != domain.CodeManifestInvalid {
				t.Fatalf("second error code = %q, want %q: %v", got, domain.CodeManifestInvalid, validationErrors)
			}
		})
	}
}

func TestValidateRejectsDuplicatePhaseStepIDsAcrossPhases(t *testing.T) {
	document, err := Load(writeManifest(t, validManifestYAML("")))
	if err != nil {
		t.Fatalf("Load valid manifest: %v", err)
	}
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Phases.Prepare = &CommandPhase{
		Steps: []PhaseStep{{
			ID:  "shared-step",
			Run: &RunAction{Command: []string{"node", "--version"}},
		}},
	}
	scenario.Phases.Run = &RunPhase{
		Steps: []PhaseStep{{
			ID:  "shared-step",
			Run: &RunAction{Command: []string{"node", "--version"}},
		}},
	}
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	validationErrors := Validate(document)
	if len(validationErrors) != 1 {
		t.Fatalf("Validate errors = %v, want one duplicate-id error", validationErrors)
	}
	if got := validationErrors[0].Code; got != domain.CodeManifestInvalid {
		t.Fatalf("duplicate step code = %q, want %q", got, domain.CodeManifestInvalid)
	}
	if got, want := validationErrors[0].Details["field"], "spec.scenarios.quickstart.phases.run.steps[0].id"; got != want {
		t.Fatalf("duplicate step field = %#v, want %q", got, want)
	}
}

func TestValidateRejectsDuplicateCLIAssertionIDs(t *testing.T) {
	document, err := Load(writeManifest(t, validManifestYAML("")))
	if err != nil {
		t.Fatalf("Load valid manifest: %v", err)
	}
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	expected := "v22"
	scenario.Phases.Exercise.Driver.Assertions = append(
		scenario.Phases.Exercise.Driver.Assertions,
		DriverAssertion{
			ID:             "version-exited",
			StdoutContains: &expected,
		},
	)
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	validationErrors := Validate(document)
	if len(validationErrors) != 1 {
		t.Fatalf("Validate errors = %v, want one duplicate-id error", validationErrors)
	}
	if got := validationErrors[0].Code; got != domain.CodeManifestInvalid {
		t.Fatalf("duplicate assertion code = %q, want %q", got, domain.CodeManifestInvalid)
	}
	if got, want := validationErrors[0].Details["field"], "spec.scenarios.quickstart.phases.exercise.driver.assertions[1].id"; got != want {
		t.Fatalf("duplicate assertion field = %#v, want %q", got, want)
	}
}

func TestLoadRequiresCLIAssertion(t *testing.T) {
	content := strings.Replace(
		validManifestYAML(""),
		"            assertions:\n              - id: version-exited\n                exitCode: 0",
		"            assertions: []",
		1,
	)
	_, err := Load(writeManifest(t, content))
	if err == nil {
		t.Fatal("Load unexpectedly accepted a CLI journey without assertions")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("missing assertion code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
}

func TestValidateCLIStdoutJSONSchemaPath(t *testing.T) {
	tests := []struct {
		name      string
		schema    string
		wantValid bool
	}{
		{
			name:      "portable repository path",
			schema:    ".repopass/schemas/stdout.schema.json",
			wantValid: true,
		},
		{name: "parent traversal", schema: "../stdout.schema.json"},
		{name: "backslash", schema: `schemas\stdout.schema.json`},
		{name: "absolute", schema: "/schemas/stdout.schema.json"},
		{name: "Windows device", schema: "schemas/CON.json"},
		{name: "trailing dot", schema: "schemas/stdout."},
		{
			name:   "256 byte segment",
			schema: "schemas/" + strings.Repeat("a", 256),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Load(writeManifest(t, validManifestYAML("")))
			if err != nil {
				t.Fatalf("Load valid manifest: %v", err)
			}
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			assertion := &scenario.Phases.Exercise.Driver.Assertions[0]
			assertion.ExitCode = nil
			assertion.StdoutJSONSchema = test.schema
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			findings := Validate(document)
			if test.wantValid {
				if len(findings) != 0 {
					t.Fatalf("Validate rejected portable stdout schema: %v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("Validate findings = %v, want one path finding", findings)
			}
			if findings[0].Code != domain.CodeSourcePathTraversal {
				t.Fatalf(
					"stdout schema code = %q, want %q",
					findings[0].Code,
					domain.CodeSourcePathTraversal,
				)
			}
			wantField := "spec.scenarios.quickstart.phases.exercise.driver.assertions[0].stdoutJsonSchema"
			if got := findings[0].Details["field"]; got != wantField {
				t.Fatalf("stdout schema field = %#v, want %q", got, wantField)
			}
		})
	}
}

func TestValidateAcceptsStrictHTTPServiceProfile(t *testing.T) {
	document, err := Load(writeManifest(t, validManifestYAML("")))
	if err != nil {
		t.Fatalf("Load valid base manifest: %v", err)
	}
	document.Manifest.Spec.Project.Kind = "web-app"
	document.Manifest.Spec.Scenarios["quickstart"] = validHTTPScenario()

	if validationErrors := Validate(document); len(validationErrors) != 0 {
		t.Fatalf("Validate rejected strict HTTP profile: %v", validationErrors)
	}
}

func TestValidateRejectsUnsafeHTTPServiceSemantics(t *testing.T) {
	tests := []struct {
		name      string
		wantField string
		mutate    func(*ScenarioSpec)
	}{
		{
			name:      "missing service",
			wantField: "spec.scenarios.quickstart.phases.run.service",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run.Service = nil
			},
		},
		{
			name:      "missing readiness",
			wantField: "spec.scenarios.quickstart.phases.run.service.readiness",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP = nil
			},
		},
		{
			name:      "missing cleanup signal",
			wantField: "spec.scenarios.quickstart.phases.cleanup.steps",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Cleanup.Steps = nil
			},
		},
		{
			name:      "wrong signal target",
			wantField: "spec.scenarios.quickstart.phases.cleanup.steps[0].signal.target",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].Signal.Target = "other"
			},
		},
		{
			name:      "signal is not final cleanup step",
			wantField: "spec.scenarios.quickstart.phases.cleanup.steps[0].signal",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Cleanup.Steps = append(
					scenario.Phases.Cleanup.Steps,
					PhaseStep{
						ID: "after-signal",
						Run: &RunAction{
							Command: []string{"node", "-e", "0"},
						},
					},
				)
			},
		},
		{
			name:      "signal grace exceeds alpha limit",
			wantField: "spec.scenarios.quickstart.phases.cleanup.steps[0].signal.gracePeriod",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].
					Signal.GracePeriod = "10s1ns"
			},
		},
		{
			name:      "signal outside cleanup",
			wantField: "spec.scenarios.quickstart.phases.setup.steps[0].signal.target",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Setup = &CommandPhase{
					Steps: []PhaseStep{{
						ID: "stop-early",
						Signal: &SignalAction{
							Target:      "app",
							Type:        "term",
							GracePeriod: "1s",
						},
					}},
				}
			},
		},
		{
			name:      "future response reference",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].assert.response.requestId",
			mutate: func(scenario *ScenarioSpec) {
				steps := scenario.Phases.Exercise.Driver.Steps
				steps[0], steps[1] = steps[1], steps[0]
			},
		},
		{
			name:      "request assertion id collision",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.id",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].Assert.ID = "echo"
			},
		},
		{
			name:      "localhost URL",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://localhost:8080/echo"
			},
		},
		{
			name:      "URL userinfo",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://user@127.0.0.1:8080/echo"
			},
		},
		{
			name:      "URL fragment",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://127.0.0.1:8080/echo#fragment"
			},
		},
		{
			name:      "URL port mismatch",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://127.0.0.1:8081/echo"
			},
		},
		{
			name:      "forbidden request header",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.headers.Authorization",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					map[string]string{"Authorization": "synthetic"}
			},
		},
		{
			name:      "literal API key header",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.headers.X-API-Key",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					map[string]string{"X-API-Key": "synthetic"}
			},
		},
		{
			name:      "request header CRLF",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.headers.X-Test",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					map[string]string{"X-Test": "ok\r\nInjected: true"}
			},
		},
		{
			name:      "body and json",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Body = "text"
			},
		},
		{
			name:      "oversized body",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.body",
			mutate: func(scenario *ScenarioSpec) {
				request := scenario.Phases.Exercise.Driver.Steps[0].Request
				request.JSON = nil
				request.Body = strings.Repeat("x", maxHTTPRequestBodyBytes+1)
			},
		},
		{
			name:      "empty body contains assertion",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.bodyContains",
			mutate: func(scenario *ScenarioSpec) {
				empty := ""
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.BodyContains = &empty
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.Status = 0
			},
		},
		{
			name:      "HTTP file assertion outside outputs",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[2].assert.fileExists",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[2].
					Assert.FileExists = "/workspace/late.json"
			},
		},
		{
			name:      "unsupported method",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.method",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Method = "connect"
			},
		},
		{
			name:      "invalid request timeout",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.timeout",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Timeout = "forever"
			},
		},
		{
			name:      "multiple listeners",
			wantField: "spec.scenarios.quickstart.capabilities.run.ports.listen",
			mutate: func(scenario *ScenarioSpec) {
				capability := scenario.Capabilities[domain.PhaseRun]
				capability.Ports.Listen = append(
					capability.Ports.Listen,
					domain.PortBinding{Host: "127.0.0.1", Port: 8081},
				)
				scenario.Capabilities[domain.PhaseRun] = capability
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Load(writeManifest(t, validManifestYAML("")))
			if err != nil {
				t.Fatalf("Load valid base manifest: %v", err)
			}
			scenario := validHTTPScenario()
			test.mutate(&scenario)
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			validationErrors := Validate(document)
			if !containsValidationField(validationErrors, test.wantField) {
				t.Fatalf(
					"Validate errors = %v, want field %q",
					validationErrors,
					test.wantField,
				)
			}
		})
	}
}

func TestHTTPRequestYAMLPreservesExplicitEmptyBodyAndNullJSON(t *testing.T) {
	var nullRequest HTTPRequest
	if err := yaml.Unmarshal([]byte(`
id: null-json
method: post
url: http://127.0.0.1:8080/echo
json: null
`), &nullRequest); err != nil {
		t.Fatalf("decode explicit null JSON request: %v", err)
	}
	if !nullRequest.HasJSON() || nullRequest.HasBody() || nullRequest.JSON != nil {
		t.Fatalf("explicit null JSON presence was lost: %#v", nullRequest)
	}

	var emptyBodyRequest HTTPRequest
	if err := yaml.Unmarshal([]byte(`
id: empty-body
method: post
url: http://127.0.0.1:8080/echo
body: ""
`), &emptyBodyRequest); err != nil {
		t.Fatalf("decode explicit empty body request: %v", err)
	}
	if !emptyBodyRequest.HasBody() ||
		emptyBodyRequest.HasJSON() ||
		emptyBodyRequest.Body != "" {
		t.Fatalf("explicit empty body presence was lost: %#v", emptyBodyRequest)
	}

	var conflicting HTTPRequest
	if err := yaml.Unmarshal([]byte(`
id: conflicting
method: post
url: http://127.0.0.1:8080/echo
body: ""
json: null
`), &conflicting); err != nil {
		t.Fatalf("decode conflicting body request: %v", err)
	}
	scenario := validHTTPScenario()
	scenario.Phases.Exercise.Driver.Steps[0].Request = &conflicting
	findings := validateHTTPScenarioForTest(t, scenario)
	if !containsValidationField(
		findings,
		"spec.scenarios.quickstart.phases.exercise.driver.steps[0].request",
	) {
		t.Fatalf("explicit empty body plus null JSON was not rejected: %v", findings)
	}
}

func TestValidateStructuredHTTPAssertions(t *testing.T) {
	t.Run("accept bounded JSONPath and schema references", func(t *testing.T) {
		scenario := validHTTPScenario()
		response := scenario.Phases.Exercise.Driver.Steps[1].Assert.Response
		response.JSONPath = &JSONPathAssertion{
			Path:   `$["hyphen-name"]['space name'][0]`,
			Equals: nil,
		}
		response.JSONSchema = "schemas/response.schema.json"
		scenario.Phases.Exercise.Driver.Steps[2].Assert.FileExists = ""
		scenario.Phases.Exercise.Driver.Steps[2].Assert.JSONFile =
			&JSONFileAssertion{
				Path:   "/outputs/request.json",
				Schema: "schemas/request.schema.json",
			}

		if findings := validateHTTPScenarioForTest(t, scenario); len(findings) != 0 {
			t.Fatalf("Validate rejected structured HTTP assertions: %v", findings)
		}
	})

	tests := []struct {
		name      string
		wantField string
		mutate    func(*ScenarioSpec)
	}{
		{
			name:      "recursive JSONPath",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.jsonPath.path",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.
					JSONPath = &JSONPathAssertion{
					Path:   "$..secret",
					Equals: true,
				}
			},
		},
		{
			name:      "wildcard JSONPath",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.jsonPath.path",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.
					JSONPath = &JSONPathAssertion{
					Path:   "$[*]",
					Equals: true,
				}
			},
		},
		{
			name:      "oversize JSONPath",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.jsonPath.path",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.
					JSONPath = &JSONPathAssertion{
					Path:   "$." + strings.Repeat("a", domain.AlphaJSONPathMaxBytes),
					Equals: true,
				}
			},
		},
		{
			name:      "nonportable response schema",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.jsonSchema",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.
					JSONSchema = "../response.schema.json"
			},
		},
		{
			name:      "JSON file outside outputs",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[2].assert.jsonFile.path",
			mutate: func(scenario *ScenarioSpec) {
				assertion := scenario.Phases.Exercise.Driver.Steps[2].Assert
				assertion.FileExists = ""
				assertion.JSONFile = &JSONFileAssertion{
					Path:   "/workspace/request.json",
					Schema: "schemas/request.schema.json",
				}
			},
		},
		{
			name:      "nonportable JSON file schema",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[2].assert.jsonFile.schema",
			mutate: func(scenario *ScenarioSpec) {
				assertion := scenario.Phases.Exercise.Driver.Steps[2].Assert
				assertion.FileExists = ""
				assertion.JSONFile = &JSONFileAssertion{
					Path:   "/outputs/request.json",
					Schema: `schemas\request.schema.json`,
				}
			},
		},
	}
	for _, test := range tests {
		t.Run("reject "+test.name, func(t *testing.T) {
			scenario := validHTTPScenario()
			test.mutate(&scenario)
			findings := validateHTTPScenarioForTest(t, scenario)
			if !containsValidationField(findings, test.wantField) {
				t.Fatalf(
					"Validate findings = %v, want field %q",
					findings,
					test.wantField,
				)
			}
		})
	}
}

func TestValidateHTTPAlphaContractBoundaries(t *testing.T) {
	urlPrefix := "http://127.0.0.1:8080/"
	exactURL := urlPrefix + strings.Repeat(
		"a",
		domain.AlphaHTTPMaxURLBytes-len(urlPrefix),
	)
	exactOutput := "/outputs/" + strings.Repeat("界", 1362) + "x"
	exactHeaders := exactHTTPHeaderAggregate()

	accepted := []struct {
		name   string
		mutate func(*ScenarioSpec)
	}{
		{
			name: "2048 byte URL",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL = exactURL
			},
		},
		{
			name: "128 journey steps",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					httpBoundarySteps(1, domain.AlphaHTTPMaxJourneySteps)
			},
		},
		{
			name: "32 request steps",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					httpBoundarySteps(domain.AlphaHTTPMaxRequestSteps, 33)
			},
		},
		{
			name: "64 effective JSON headers",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					httpHeaderSet(63)
			},
		},
		{
			name: "65536 aggregate header bytes",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					exactHeaders
			},
		},
		{
			name: "1 MiB Unicode request body",
			mutate: func(scenario *ScenarioSpec) {
				request := scenario.Phases.Exercise.Driver.Steps[0].Request
				request.JSON = nil
				request.Body = strings.Repeat("界", 349525) + "x"
			},
		},
		{
			name: "1 MiB canonical JSON request",
			mutate: func(scenario *ScenarioSpec) {
				request := scenario.Phases.Exercise.Driver.Steps[0].Request
				request.JSON = map[string]any{
					"value": strings.Repeat(
						"x",
						domain.AlphaHTTPMaxRequestBodyBytes-12,
					),
				}
			},
		},
		{
			name: "response match byte boundaries",
			mutate: func(scenario *ScenarioSpec) {
				response := scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response
				body := strings.Repeat(
					"x",
					domain.AlphaHTTPMaxResponseMatchBytes,
				)
				response.BodyContains = &body
				response.Header = &HeaderAssertion{
					Name: "x-result",
					Contains: strings.Repeat(
						"x",
						domain.AlphaHTTPMaxHeaderValueBytes,
					),
				}
			},
		},
		{
			name: "4096 byte Unicode output path",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[2].
					Assert.FileExists = exactOutput
			},
		},
		{
			name: "1ms HTTP durations and status 200",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Timeout = "1ms"
				scenario.Phases.Run.Service.Readiness.HTTP.Status = 200
				scenario.Phases.Exercise.Driver.Steps[0].Request.Timeout = "1ms"
				scenario.Phases.Cleanup.Steps[0].Signal.GracePeriod = "1ms"
			},
		},
		{
			name: "kill with grace",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].Signal.Type = "kill"
				scenario.Phases.Cleanup.Steps[0].Signal.GracePeriod = "1ms"
			},
		},
	}
	for _, test := range accepted {
		t.Run("accept "+test.name, func(t *testing.T) {
			scenario := validHTTPScenario()
			test.mutate(&scenario)
			if validationErrors := validateHTTPScenarioForTest(t, scenario); len(validationErrors) != 0 {
				t.Fatalf("Validate rejected boundary: %v", validationErrors)
			}
		})
	}

	rejected := []struct {
		name      string
		wantField string
		mutate    func(*ScenarioSpec)
	}{
		{
			name:      "2049 byte URL",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					exactURL + "a"
			},
		},
		{
			name:      "leading zero port",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://127.0.0.1:08080/echo"
			},
		},
		{
			name:      "unsafe query character",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://127.0.0.1:8080/echo?value={x}"
			},
		},
		{
			name:      "malformed query escape",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.url",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://127.0.0.1:8080/echo?value=%zz"
			},
		},
		{
			name:      "129 journey steps",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					httpBoundarySteps(1, domain.AlphaHTTPMaxJourneySteps+1)
			},
		},
		{
			name:      "33 request steps",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					httpBoundarySteps(domain.AlphaHTTPMaxRequestSteps+1, 34)
			},
		},
		{
			name:      "65 effective JSON headers",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.headers",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					httpHeaderSet(64)
			},
		},
		{
			name:      "65537 aggregate header bytes",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.headers",
			mutate: func(scenario *ScenarioSpec) {
				headers := exactHTTPHeaderAggregate()
				headers["h"] += "x"
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					headers
			},
		},
		{
			name:      "non ASCII header value",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.headers",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					map[string]string{"x-test": "界"}
			},
		},
		{
			name:      "Unicode request body exceeds byte limit",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.body",
			mutate: func(scenario *ScenarioSpec) {
				request := scenario.Phases.Exercise.Driver.Steps[0].Request
				request.JSON = nil
				request.Body = strings.Repeat("界", 349525) + "xx"
			},
		},
		{
			name:      "canonical JSON exceeds byte limit",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.json",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.JSON =
					map[string]any{
						"value": strings.Repeat(
							"x",
							domain.AlphaHTTPMaxRequestBodyBytes-11,
						),
					}
			},
		},
		{
			name:      "response body match exceeds byte limit",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.bodyContains",
			mutate: func(scenario *ScenarioSpec) {
				body := strings.Repeat(
					"x",
					domain.AlphaHTTPMaxResponseMatchBytes+1,
				)
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.BodyContains = &body
			},
		},
		{
			name:      "response header match exceeds byte limit",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.header.contains",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.Header = &HeaderAssertion{
					Name: "x-result",
					Contains: strings.Repeat(
						"x",
						domain.AlphaHTTPMaxHeaderValueBytes+1,
					),
				}
			},
		},
		{
			name:      "4097 byte output path",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[2].assert.fileExists",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[2].
					Assert.FileExists = exactOutput + "x"
			},
		},
		{
			name:      "1ns readiness",
			wantField: "spec.scenarios.quickstart.phases.run.service.readiness.http.timeout",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Timeout = "1ns"
			},
		},
		{
			name:      "readiness exceeds 2m",
			wantField: "spec.scenarios.quickstart.phases.run.service.readiness.http.timeout",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Timeout = "2m1ms"
			},
		},
		{
			name:      "fractional millisecond request",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[0].request.timeout",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Timeout = "1.5ms"
			},
		},
		{
			name:      "kill without grace",
			wantField: "spec.scenarios.quickstart.phases.cleanup.steps[0].signal.gracePeriod",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].Signal.Type = "kill"
				scenario.Phases.Cleanup.Steps[0].Signal.GracePeriod = ""
			},
		},
		{
			name:      "readiness status 199",
			wantField: "spec.scenarios.quickstart.phases.run.service.readiness.http.status",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Status = 199
			},
		},
		{
			name:      "response status 199",
			wantField: "spec.scenarios.quickstart.phases.exercise.driver.steps[1].assert.response.status",
			mutate: func(scenario *ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.Status = 199
			},
		},
	}
	for _, test := range rejected {
		t.Run("reject "+test.name, func(t *testing.T) {
			scenario := validHTTPScenario()
			test.mutate(&scenario)
			validationErrors := validateHTTPScenarioForTest(t, scenario)
			if !containsValidationField(validationErrors, test.wantField) {
				t.Fatalf(
					"Validate errors = %v, want field %q",
					validationErrors,
					test.wantField,
				)
			}
		})
	}
}

func validateHTTPScenarioForTest(
	t *testing.T,
	scenario ScenarioSpec,
) []*domain.Error {
	t.Helper()
	document, err := Load(writeManifest(t, validManifestYAML("")))
	if err != nil {
		t.Fatalf("Load valid base manifest: %v", err)
	}
	document.Manifest.Spec.Project.Kind = "web-app"
	document.Manifest.Spec.Scenarios["quickstart"] = scenario
	return Validate(document)
}

func httpBoundarySteps(requestCount, total int) []DriverStep {
	steps := make([]DriverStep, 0, total)
	for index := 0; index < requestCount; index++ {
		steps = append(steps, DriverStep{
			Request: &HTTPRequest{
				ID:      fmt.Sprintf("request-%d", index),
				Method:  "get",
				URL:     fmt.Sprintf("http://127.0.0.1:8080/request/%d", index),
				Timeout: "1ms",
			},
		})
	}
	for index := requestCount; index < total; index++ {
		steps = append(steps, DriverStep{
			Assert: &DriverAssertion{
				ID:         fmt.Sprintf("assertion-%d", index),
				FileExists: "/outputs/request.json",
			},
		})
	}
	return steps
}

func httpHeaderSet(count int) map[string]string {
	headers := make(map[string]string, count)
	for index := 0; index < count; index++ {
		headers[fmt.Sprintf("x-%02d", index)] = "ok"
	}
	return headers
}

func exactHTTPHeaderAggregate() map[string]string {
	headers := map[string]string{
		domain.AlphaHTTPContentTypeName: domain.AlphaHTTPJSONContentType,
	}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		headers[name] = strings.Repeat(
			"x",
			domain.AlphaHTTPMaxHeaderValueBytes,
		)
	}
	headers["h"] = strings.Repeat("x", 8120)
	return headers
}

func TestWriteCandidateRejectsSymlinkedProvenanceDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".repopass")); err != nil {
		t.Skipf("directory symlink creation is unavailable: %v", err)
	}
	_, _, err := WriteCandidate(root, Manifest{APIVersion: APIVersion, Kind: Kind}, nil, false)
	if err == nil {
		t.Fatal("WriteCandidate unexpectedly followed a symlinked .repopass directory")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeSourceSymlinkEscape {
		t.Fatalf("WriteCandidate symlink code = %q, want %q: %v", got, domain.CodeSourceSymlinkEscape, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "init-provenance.json")); !os.IsNotExist(err) {
		t.Fatalf("WriteCandidate wrote outside the source root: %v", err)
	}
}

func validHTTPScenario() ScenarioSpec {
	bodyContains := `"received"`
	return ScenarioSpec{
		Environment: "linux-node",
		Phases: PhaseSet{
			Run: &RunPhase{
				Timeout: "1m",
				Service: &ServiceSpec{
					ID:      "app",
					Command: []string{"node", "/workspace/server.mjs"},
					Readiness: ReadinessSpec{
						HTTP: &HTTPReadiness{
							URL:     "http://127.0.0.1:8080/health",
							Status:  200,
							Timeout: "10s",
						},
					},
				},
			},
			Exercise: &ExercisePhase{
				Timeout: "30s",
				Driver: DriverSpec{
					Type: "http",
					Steps: []DriverStep{
						{
							Request: &HTTPRequest{
								ID:      "echo",
								Method:  "post",
								URL:     "http://127.0.0.1:8080/echo",
								Headers: map[string]string{"X-Trace": "alpha-two"},
								JSON:    map[string]any{"message": "hello"},
								Timeout: "5s",
							},
						},
						{
							Assert: &DriverAssertion{
								ID: "echo-ok",
								Response: &ResponseAssertion{
									RequestID:    "echo",
									Status:       200,
									BodyContains: &bodyContains,
								},
							},
						},
						{
							Assert: &DriverAssertion{
								ID:         "output-created",
								FileExists: "/outputs/request.json",
							},
						},
					},
				},
			},
			Cleanup: &CommandPhase{
				Timeout: "10s",
				Steps: []PhaseStep{{
					ID: "stop-service",
					Signal: &SignalAction{
						Target:      "app",
						Type:        "term",
						GracePeriod: "2s",
					},
				}},
			},
		},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseRun: {
				Network: domain.NetworkCapability{Deny: true},
				Ports: domain.PortCapability{
					Listen: []domain.PortBinding{{
						Host: "127.0.0.1",
						Port: 8080,
					}},
				},
			},
			domain.PhaseExercise: {
				Network: domain.NetworkCapability{Deny: true},
			},
			domain.PhaseCleanup: {
				Network: domain.NetworkCapability{Deny: true},
			},
		},
		Verification: VerificationSpec{
			Repeats:          1,
			SuccessThreshold: 1,
			RequiredObservers: []string{
				"network-enforcement",
				"port-listen",
			},
			Cleanup: CleanupSpec{AllowedResidue: []string{"/outputs/**"}},
		},
	}
}

func containsValidationField(errors []*domain.Error, wanted string) bool {
	for _, validationError := range errors {
		if validationError != nil &&
			validationError.Details["field"] == wanted {
			return true
		}
	}
	return false
}

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repo-passport.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func validManifestYAML(projectExtra string) string {
	return fmt.Sprintf(`apiVersion: repopass.dev/v1alpha1
kind: RepositoryPassport
metadata:
  name: manifest-contract-test
spec:
  project:
    kind: cli
    audiences: [developer]
    entrypoints: [quickstart]
%s
  environments:
    linux-node:
      platform:
        os: linux
        architecture: amd64
      runtime:
        adapter: node
        version: "22.0.0"
      baseImage:
        reference: ghcr.io/repopass/fixtures/node@sha256:8f3c7a2e9b4d1f605a7c8e2b3d9f1406c5a1e7b8d2f4093c6e8a1b5d7f2c9e40
      resources:
        cpu: 1
        memory: 256MiB
        disk: 1GiB
        pids: 64
  scenarios:
    quickstart:
      environment: linux-node
      phases:
        exercise:
          timeout: 30s
          driver:
            type: cli
            command: [node, --version]
            assertions:
              - id: version-exited
                exitCode: 0
      capabilities:
        exercise:
          network:
            deny: true
      verification:
        repeats: 1
        successThreshold: 1
        requiredObservers: [network-enforcement]
        cleanup:
          allowedResidue: []
  policies:
    profile: baseline-v1
  evidence:
    profile: minimal-public
    include: [verification-summary]
    exclude: [raw-stdout]
`, projectExtra)
}
