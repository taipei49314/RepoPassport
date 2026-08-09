package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

func TestStdoutJSONSchemaAssertionPassesWithoutRetainingInstance(t *testing.T) {
	const privateValue = "private-token-123"
	reference, prepared := preparedCLIStdoutSchema(
		t,
		[]byte(`{
			"$schema":"https://json-schema.org/draft/2020-12/schema",
			"type":"object",
			"required":["value"],
			"properties":{"value":{"type":"string"}},
			"additionalProperties":false
		}`),
	)
	result := evaluateJourneyAssertions(
		prepared,
		[]StepResult{{
			ID:       "journey",
			Role:     "journey",
			Stdout:   []byte(`{"value":"` + privateValue + `"}`),
			Duration: 17 * time.Millisecond,
		}},
	)[0]

	if result.Status != "passed" {
		t.Fatalf("stdout schema result = %#v, want passed", result)
	}
	if result.Type != "stdout-json-schema" {
		t.Fatalf("assertion type = %q, want stdout-json-schema", result.Type)
	}
	if result.DurationMillis != 17 {
		t.Fatalf("duration = %d, want 17", result.DurationMillis)
	}
	expected := map[string]any{
		"path":             reference.Path,
		"digest":           reference.Digest,
		"dialect":          reference.Dialect,
		"validatorVersion": reference.ValidatorVersion,
	}
	if !reflect.DeepEqual(result.Expected, expected) {
		t.Fatalf("expected metadata = %#v, want %#v", result.Expected, expected)
	}
	actual := map[string]any{
		"stdoutComplete":    true,
		"strictJSON":        true,
		"jsonSchemaMatched": true,
	}
	if !reflect.DeepEqual(result.Actual, actual) {
		t.Fatalf("actual metadata = %#v, want %#v", result.Actual, actual)
	}
	wantEvidence := []string{"step:001", "json-schema:" + reference.Digest}
	if !reflect.DeepEqual(result.EvidenceRefs, wantEvidence) {
		t.Fatalf("evidence refs = %#v, want %#v", result.EvidenceRefs, wantEvidence)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(wire), privateValue) ||
		strings.Contains(string(wire), `"stdout"`) ||
		strings.Contains(string(wire), `"bytes"`) {
		t.Fatalf("stdout schema evidence retained private instance data: %s", wire)
	}
}

func TestStdoutJSONSchemaAssertionClassifiesStrictJSONFailures(t *testing.T) {
	_, prepared := preparedCLIStdoutSchema(
		t,
		[]byte(`{"type":"object"}`),
	)
	limits := structuredjson.DefaultInstanceDecodeLimits()
	oversized := bytes.Repeat(
		[]byte(" "),
		limits.MaxBytes+1,
	)
	tooDeep := []byte(
		strings.Repeat("[", limits.MaxDepth+1) +
			"0" +
			strings.Repeat("]", limits.MaxDepth+1),
	)
	tooManyNodes := []byte(
		"[" + strings.Repeat("0,", limits.MaxNodes) + "0]",
	)
	tests := []struct {
		name        string
		stdout      []byte
		wantFailure string
	}{
		{name: "empty", stdout: nil, wantFailure: "invalid-json"},
		{name: "malformed", stdout: []byte(`{"value":`), wantFailure: "invalid-json"},
		{name: "duplicate", stdout: []byte(`{"value":1,"value":2}`), wantFailure: "duplicate-key"},
		{name: "trailing value", stdout: []byte(`{"value":1}{"value":2}`), wantFailure: "invalid-json"},
		{name: "invalid UTF-8", stdout: []byte{0xff}, wantFailure: "invalid-utf8"},
		{name: "over one MiB", stdout: oversized, wantFailure: "too-large"},
		{name: "depth limit", stdout: tooDeep, wantFailure: "depth-limit"},
		{name: "node limit", stdout: tooManyNodes, wantFailure: "node-limit"},
		{name: "number exponent limit", stdout: []byte(`1e1001`), wantFailure: "number-exponent-limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateJourneyAssertions(
				prepared,
				[]StepResult{{
					ID:     "journey",
					Role:   "journey",
					Stdout: test.stdout,
				}},
			)[0]
			if result.Status != "failed" {
				t.Fatalf("result = %#v, want failed", result)
			}
			actual, ok := result.Actual.(map[string]any)
			if !ok {
				t.Fatalf("actual = %#v, want map", result.Actual)
			}
			if actual["stdoutComplete"] != true ||
				actual["strictJSON"] != false ||
				actual["failure"] != test.wantFailure {
				t.Fatalf("actual = %#v", actual)
			}
			if _, exists := actual["jsonSchemaMatched"]; exists {
				t.Fatalf("schema match was reported after decode failure: %#v", actual)
			}
		})
	}
}

func TestStdoutJSONSchemaAssertionDistinguishesMismatchAndEvaluationFailure(
	t *testing.T,
) {
	reference, prepared := preparedCLIStdoutSchema(
		t,
		[]byte(`{
			"type":"object",
			"required":["value"],
			"properties":{"value":{"type":"integer"}}
		}`),
	)
	mismatch := evaluateJourneyAssertions(
		prepared,
		[]StepResult{{
			ID:     "journey",
			Role:   "journey",
			Stdout: []byte(`{"value":"not-an-integer"}`),
		}},
	)[0]
	if mismatch.Status != "failed" {
		t.Fatalf("mismatch result = %#v, want failed", mismatch)
	}
	mismatchActual := mismatch.Actual.(map[string]any)
	if mismatchActual["jsonSchemaMatched"] != false ||
		mismatchActual["failure"] != "schema-not-satisfied" {
		t.Fatalf("mismatch actual = %#v", mismatchActual)
	}

	binding, err := structuredJSONSchemaBindingFor(reference)
	if err != nil {
		t.Fatalf("schema binding: %v", err)
	}
	prepared.structuredJSONSchemas[binding] = &structuredjson.Schema{}
	incomplete := evaluateJourneyAssertions(
		prepared,
		[]StepResult{{
			ID:     "journey",
			Role:   "journey",
			Stdout: []byte(`{"value":1}`),
		}},
	)[0]
	if incomplete.Status != "inconclusive" {
		t.Fatalf("evaluation result = %#v, want inconclusive", incomplete)
	}
	incompleteActual := incomplete.Actual.(map[string]any)
	if incompleteActual["jsonSchemaMatched"] != false ||
		incompleteActual["failure"] != "schema-evaluation-incomplete" {
		t.Fatalf("evaluation actual = %#v", incompleteActual)
	}
}

func TestStdoutJSONSchemaAssertionTreatsTruncationBeforeDecode(t *testing.T) {
	_, prepared := preparedCLIStdoutSchema(
		t,
		[]byte(`{"type":"object"}`),
	)
	result := evaluateJourneyAssertions(
		prepared,
		[]StepResult{{
			ID:           "journey",
			Role:         "journey",
			Stdout:       []byte(`{"valid":"prefix"}`),
			LogTruncated: true,
		}},
	)[0]
	if result.Status != "inconclusive" {
		t.Fatalf("truncated result = %#v, want inconclusive", result)
	}
	actual := result.Actual.(map[string]any)
	if actual["stdoutComplete"] != false ||
		actual["failure"] != "log-capture-truncated" {
		t.Fatalf("truncated actual = %#v", actual)
	}
	if _, exists := actual["strictJSON"]; exists {
		t.Fatalf("truncated prefix was decoded: %#v", actual)
	}
}

func TestStdoutJSONSchemaAssertionBlocksWithoutJourneyOrSealedBinding(
	t *testing.T,
) {
	_, prepared := preparedCLIStdoutSchema(
		t,
		[]byte(`{"type":"object"}`),
	)
	missingJourney := evaluateJourneyAssertions(prepared, nil)[0]
	if missingJourney.Status != "blocked" {
		t.Fatalf("missing journey result = %#v, want blocked", missingJourney)
	}
	if missingJourney.Actual.(map[string]any)["failure"] !=
		"journey-unavailable" {
		t.Fatalf("missing journey actual = %#v", missingJourney.Actual)
	}

	prepared.structuredJSONSchemas = nil
	missingBinding := evaluateJourneyAssertions(
		prepared,
		[]StepResult{{
			ID:     "journey",
			Role:   "journey",
			Stdout: []byte(`{"value":1}`),
		}},
	)[0]
	if missingBinding.Status != "blocked" {
		t.Fatalf("missing binding result = %#v, want blocked", missingBinding)
	}
	actual := missingBinding.Actual.(map[string]any)
	if actual["stdoutComplete"] != true ||
		actual["strictJSON"] != true ||
		actual["failure"] != "schema-binding-unavailable" {
		t.Fatalf("missing binding actual = %#v", actual)
	}
}

func TestStdoutJSONSchemaAssertionIgnoresSchemaValidInstanceValues(
	t *testing.T,
) {
	_, prepared := preparedCLIStdoutSchema(
		t,
		[]byte(`{
			"type":"object",
			"required":["nonce"],
			"properties":{"nonce":{"type":"string"}},
			"additionalProperties":false
		}`),
	)
	var results []domain.AssertionResult
	for _, stdout := range [][]byte{
		[]byte(`{"nonce":"first-private-value"}`),
		[]byte(`{"nonce":"second-private-value"}`),
	} {
		result := evaluateJourneyAssertions(
			prepared,
			[]StepResult{{
				ID:     "journey",
				Role:   "journey",
				Stdout: stdout,
			}},
		)[0]
		if result.Status != "passed" {
			t.Fatalf("result = %#v, want passed", result)
		}
		results = append(results, result)
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatalf(
			"schema-valid instance values changed assertion semantics:\n%#v\n%#v",
			results[0],
			results[1],
		)
	}
}

func TestRunnerValidatesAndClonesStdoutJSONSchemaReference(t *testing.T) {
	reference := validCLIStdoutSchemaReference()
	plan := testPlan(t, t.TempDir())
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:               "stdout-schema",
		StdoutJSONSchema: &reference,
	}}
	if _, _, err := testRunner(&fakeExecutor{}).validatePlan(plan); err != nil {
		t.Fatalf("validatePlan rejected stdout schema assertion: %v", err)
	}

	cloned := clonePlan(plan)
	wantReference := reference
	plan.JourneyAssertions[0].StdoutJSONSchema.Path =
		".repopass/schemas/mutated.schema.json"
	if cloned.JourneyAssertions[0].StdoutJSONSchema.Path !=
		wantReference.Path {
		t.Fatalf(
			"clone retained mutable stdout schema pointer: %#v",
			cloned.JourneyAssertions[0].StdoutJSONSchema,
		)
	}
	references := structuredJSONSchemaReferences(cloned)
	if len(references) != 1 || references[0] != wantReference {
		t.Fatalf(
			"structured schema references = %#v, want %#v",
			references,
			wantReference,
		)
	}
}

func TestRunnerRejectsInvalidOrMultipleStdoutSchemaOperations(t *testing.T) {
	reference := validCLIStdoutSchemaReference()
	tests := []struct {
		name      string
		assertion domain.PlanAssertion
	}{
		{
			name: "invalid reference",
			assertion: domain.PlanAssertion{
				ID: "stdout-schema",
				StdoutJSONSchema: &domain.PlanJSONSchemaRef{
					Path:             "../schema.json",
					Digest:           reference.Digest,
					Dialect:          reference.Dialect,
					ValidatorVersion: reference.ValidatorVersion,
				},
			},
		},
		{
			name: "multiple operations",
			assertion: domain.PlanAssertion{
				ID:               "stdout-schema",
				StdoutContains:   "value",
				StdoutJSONSchema: &reference,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := testPlan(t, t.TempDir())
			plan.JourneyAssertions = []domain.PlanAssertion{test.assertion}
			_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
			if domain.ErrorCodeOf(err) != domain.CodePlanUnresolved {
				t.Fatalf("error = %v, want %s", err, domain.CodePlanUnresolved)
			}
		})
	}
}

func TestRunnerRejectsLegacyResolvedPlanSchemaVersion(t *testing.T) {
	plan := testPlan(t, t.TempDir())
	plan.SchemaVersion = "1"
	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if domain.ErrorCodeOf(err) != domain.CodePlanUnresolved {
		t.Fatalf("error = %v, want %s", err, domain.CodePlanUnresolved)
	}
}

func TestRunnerRejectsLegacyCLIJourneyDriverVersion(t *testing.T) {
	plan := testPlan(t, t.TempDir())
	plan.JourneyDriverVersion = "0.1.0"
	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if domain.ErrorCodeOf(err) != domain.CodePlanUnresolved {
		t.Fatalf("error = %v, want %s", err, domain.CodePlanUnresolved)
	}
}

func preparedCLIStdoutSchema(
	t *testing.T,
	schemaBytes []byte,
) (domain.PlanJSONSchemaRef, *PreparedRun) {
	t.Helper()
	schema, err := structuredjson.CompileSchema(schemaBytes)
	if err != nil {
		t.Fatalf("CompileSchema: %v", err)
	}
	sum := sha256.Sum256(schemaBytes)
	reference := validCLIStdoutSchemaReference()
	reference.Digest = "sha256:" + hex.EncodeToString(sum[:])
	binding, err := structuredJSONSchemaBindingFor(reference)
	if err != nil {
		t.Fatalf("schema binding: %v", err)
	}
	plan := domain.ResolvedPlan{
		SchemaVersion: "4",
		Evidence: domain.PlanEvidence{
			Profile: "minimal-public",
			Include: []string{"normalized-observations", "verification-summary"},
			Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
		},
		Cleanup: domain.PlanCleanup{
			ClassifierVersion: "0.1.0",
			AllowedResidue:    []string{},
		},
		JourneyAssertions: []domain.PlanAssertion{{
			ID:               "stdout-schema",
			StdoutJSONSchema: &reference,
		}},
	}
	return reference, &PreparedRun{
		Plan:                clonePlan(plan),
		executionPlan:       clonePlan(plan),
		executionPlanSealed: true,
		structuredJSONSchemas: map[structuredJSONSchemaBinding]*structuredjson.Schema{
			binding: schema,
		},
	}
}

func validCLIStdoutSchemaReference() domain.PlanJSONSchemaRef {
	return domain.PlanJSONSchemaRef{
		Path:             ".repopass/schemas/cli-stdout.schema.json",
		Digest:           "sha256:" + strings.Repeat("a", 64),
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
}
