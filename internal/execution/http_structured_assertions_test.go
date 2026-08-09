package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

func TestHTTPResponseStructuredAssertionsPreservePrecisionAndPrivacy(
	t *testing.T,
) {
	const privateValue = "private-token-123"
	schemaBytes := []byte(`{
		"$schema":"https://json-schema.org/draft/2020-12/schema",
		"type":"object",
		"required":["秘密","large"],
		"properties":{
			"秘密":{"type":"string"},
			"large":{"type":"integer"}
		},
		"additionalProperties":false
	}`)
	schema, err := structuredjson.CompileSchema(schemaBytes)
	if err != nil {
		t.Fatalf("CompileSchema: %v", err)
	}
	schemaDigest := digestBytes(schemaBytes)
	reference := domain.PlanJSONSchemaRef{
		Path:             ".repopass/schemas/response.schema.json",
		Digest:           schemaDigest,
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
	binding, err := structuredJSONSchemaBindingFor(reference)
	if err != nil {
		t.Fatalf("schema binding: %v", err)
	}
	prepared := &PreparedRun{
		executionPlanSealed: true,
		structuredJSONSchemas: map[structuredJSONSchemaBinding]*structuredjson.Schema{
			binding: schema,
		},
	}
	body := []byte(
		`{"秘密":"` + privateValue + `","large":9007199254740993}`,
	)
	result := evaluateHTTPResponseAssertion(
		prepared,
		domain.PlanAssertion{
			ID: "structured",
			Response: &domain.PlanHTTPResponseAssertion{
				RequestID: "request",
				JSONPath: &domain.PlanJSONPathAssertion{
					Path:   `$["large"]`,
					Equals: json.RawMessage(`9007199254740993`),
				},
				JSONSchema: &reference,
			},
		},
		map[string]httpExchange{
			"request": {
				Response: trustedHTTPResponse{
					Status:    200,
					Body:      body,
					BodyBytes: int64(len(body)),
				},
			},
		},
	)
	if result.Status != "passed" {
		t.Fatalf("structured response result = %#v, want passed", result)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(wire), privateValue) ||
		strings.Contains(string(wire), "9007199254740993") {
		t.Fatalf("structured assertion evidence leaked values: %s", wire)
	}
}

func TestHTTPJSONPathDistinguishesNullFromMissing(t *testing.T) {
	assertion := domain.PlanAssertion{
		ID: "nullable",
		Response: &domain.PlanHTTPResponseAssertion{
			RequestID: "request",
			JSONPath: &domain.PlanJSONPathAssertion{
				Path:   "$.value",
				Equals: json.RawMessage(`null`),
			},
		},
	}
	for _, test := range []struct {
		name       string
		body       string
		wantStatus string
	}{
		{name: "present null", body: `{"value":null}`, wantStatus: "passed"},
		{name: "missing", body: `{}`, wantStatus: "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateHTTPResponseAssertion(
				&PreparedRun{},
				assertion,
				map[string]httpExchange{
					"request": {
						Response: trustedHTTPResponse{
							Status:    200,
							Body:      []byte(test.body),
							BodyBytes: int64(len(test.body)),
						},
					},
				},
			)
			if result.Status != test.wantStatus {
				t.Fatalf(
					"result = %#v, want status %q",
					result,
					test.wantStatus,
				)
			}
		})
	}
}

func TestHTTPStructuredResponseFailsClosedForDuplicateOrTruncatedJSON(
	t *testing.T,
) {
	assertion := domain.PlanAssertion{
		ID: "structured",
		Response: &domain.PlanHTTPResponseAssertion{
			RequestID: "request",
			JSONPath: &domain.PlanJSONPathAssertion{
				Path:   "$.value",
				Equals: json.RawMessage(`1`),
			},
		},
	}
	for _, test := range []struct {
		name       string
		body       string
		truncated  bool
		bodyBytes  int64
		wantStatus string
	}{
		{
			name: "duplicate key", body: `{"value":1,"value":1}`,
			bodyBytes: 21, wantStatus: "failed",
		},
		{
			name: "truncated", body: `{"value":1}`,
			truncated: true, bodyBytes: 1025, wantStatus: "inconclusive",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateHTTPResponseAssertion(
				&PreparedRun{},
				assertion,
				map[string]httpExchange{
					"request": {
						Response: trustedHTTPResponse{
							Status:        200,
							Body:          []byte(test.body),
							BodyBytes:     test.bodyBytes,
							BodyTruncated: test.truncated,
						},
					},
				},
			)
			if result.Status != test.wantStatus {
				t.Fatalf(
					"result = %#v, want status %q",
					result,
					test.wantStatus,
				)
			}
		})
	}
}

func TestOrderedHTTPJSONFileAssertionUsesVerifiedSnapshot(t *testing.T) {
	const privateValue = "output-private-token"
	content := []byte(`{"message":"` + privateValue + `"}`)
	schemaBytes := []byte(`{
		"$schema":"https://json-schema.org/draft/2020-12/schema",
		"type":"object",
		"required":["message"],
		"properties":{"message":{"type":"string"}},
		"additionalProperties":false
	}`)
	schema, err := structuredjson.CompileSchema(schemaBytes)
	if err != nil {
		t.Fatalf("CompileSchema: %v", err)
	}
	schemaDigest := digestBytes(schemaBytes)
	reference := domain.PlanJSONSchemaRef{
		Path:             ".repopass/schemas/output.schema.json",
		Digest:           schemaDigest,
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
	binding, err := structuredJSONSchemaBindingFor(reference)
	if err != nil {
		t.Fatalf("schema binding: %v", err)
	}
	fake := &fakeExecutor{
		handler: func(
			_ context.Context,
			_ string,
			args []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			if !containsArgument(args, nodeHTTPJSONFileReadScript) {
				t.Fatalf("fixed JSON file helper absent: %v", args)
			}
			_, _ = io.WriteString(
				stdout,
				validHTTPJSONFileReadControl(content),
			)
			return 0, nil
		},
	}
	prepared := &PreparedRun{
		Plan:                domain.ResolvedPlan{RuntimeAdapter: "node"},
		Backend:             "docker",
		executionPlan:       domain.ResolvedPlan{RuntimeAdapter: "node"},
		executionPlanSealed: true,
		structuredJSONSchemas: map[structuredJSONSchemaBinding]*structuredjson.Schema{
			binding: schema,
		},
	}
	result := testRunner(fake).inspectHTTPJSONFileAssertion(
		context.Background(),
		prepared,
		"repopass-container",
		domain.PlanAssertion{
			ID: "output-schema",
			JSONFile: &domain.PlanJSONFileAssertion{
				Path:   "/outputs/result.json",
				Schema: reference,
			},
		},
	)
	if result.Status != "passed" {
		t.Fatalf("JSON file assertion = %#v, want passed", result)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(wire), privateValue) {
		t.Fatalf("JSON file evidence leaked content: %s", wire)
	}
}

func TestOrderedHTTPJSONFileAssertionClassifiesDefinitiveFailures(
	t *testing.T,
) {
	for _, test := range []struct {
		helperStatus string
		wantStatus   string
	}{
		{helperStatus: "missing", wantStatus: "failed"},
		{helperStatus: "symlink", wantStatus: "failed"},
		{helperStatus: "directory", wantStatus: "failed"},
		{helperStatus: "special", wantStatus: "failed"},
		{helperStatus: "too-large", wantStatus: "failed"},
		{helperStatus: "changed", wantStatus: "inconclusive"},
		{helperStatus: "error", wantStatus: "inconclusive"},
	} {
		t.Run(test.helperStatus, func(t *testing.T) {
			fake := &fakeExecutor{
				handler: func(
					context.Context,
					string,
					[]string,
					io.Writer,
					io.Writer,
				) (int, error) {
					return 0, nil
				},
			}
			fake.handler = func(
				_ context.Context,
				_ string,
				_ []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				_, _ = io.WriteString(
					stdout,
					`{"status":"`+test.helperStatus+`"}`,
				)
				return 0, nil
			}
			result := testRunner(fake).inspectHTTPJSONFileAssertion(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Plan:    domain.ResolvedPlan{RuntimeAdapter: "node"},
					Backend: "docker",
				}),
				"container",
				domain.PlanAssertion{
					ID: "json-file",
					JSONFile: &domain.PlanJSONFileAssertion{
						Path: "/outputs/result.json",
						Schema: domain.PlanJSONSchemaRef{
							Path:             "schema.json",
							Digest:           "sha256:" + strings.Repeat("a", 64),
							Dialect:          domain.AlphaJSONSchemaDialect,
							ValidatorVersion: domain.AlphaJSONValidatorVersion,
						},
					},
				},
			)
			if result.Status != test.wantStatus {
				t.Fatalf(
					"result = %#v, want status %q",
					result,
					test.wantStatus,
				)
			}
		})
	}
}

func TestPreparedStructuredJSONSchemaRequiresExactPreparedBinding(
	t *testing.T,
) {
	schemaBytes := []byte(`{"type":"object"}`)
	schema, err := structuredjson.CompileSchema(schemaBytes)
	if err != nil {
		t.Fatalf("CompileSchema: %v", err)
	}
	reference := domain.PlanJSONSchemaRef{
		Path:             ".repopass/schemas/value.json",
		Digest:           digestBytes(schemaBytes),
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
	binding, err := structuredJSONSchemaBindingFor(reference)
	if err != nil {
		t.Fatalf("schema binding: %v", err)
	}
	prepared := &PreparedRun{
		executionPlanSealed: true,
		structuredJSONSchemas: map[structuredJSONSchemaBinding]*structuredjson.Schema{
			binding: schema,
		},
	}
	if got, ok := prepared.structuredJSONSchema(reference); !ok || got != schema {
		t.Fatal("exact prepared schema binding did not resolve")
	}

	tests := []struct {
		name   string
		mutate func(*domain.PlanJSONSchemaRef)
	}{
		{
			name: "undeclared path with same digest",
			mutate: func(value *domain.PlanJSONSchemaRef) {
				value.Path = ".repopass/schemas/other.json"
			},
		},
		{
			name: "different digest",
			mutate: func(value *domain.PlanJSONSchemaRef) {
				value.Digest = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name: "different dialect",
			mutate: func(value *domain.PlanJSONSchemaRef) {
				value.Dialect = "https://json-schema.org/draft/2019-09/schema"
			},
		},
		{
			name: "different validator",
			mutate: func(value *domain.PlanJSONSchemaRef) {
				value.ValidatorVersion = "different-validator@v1"
			},
		},
		{
			name: "nonportable path",
			mutate: func(value *domain.PlanJSONSchemaRef) {
				value.Path = "../value.json"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := reference
			test.mutate(&mutated)
			if schema, ok := prepared.structuredJSONSchema(mutated); ok ||
				schema != nil {
				t.Fatalf("mutated binding resolved prepared schema: %#v", mutated)
			}
		})
	}

	unsealed := &PreparedRun{
		structuredJSONSchemas: prepared.structuredJSONSchemas,
	}
	if schema, ok := unsealed.structuredJSONSchema(reference); ok ||
		schema != nil {
		t.Fatal("unsealed PreparedRun resolved a schema")
	}
	prepared.structuredJSONSchemas[binding] = nil
	if schema, ok := prepared.structuredJSONSchema(reference); ok ||
		schema != nil {
		t.Fatal("nil prepared schema entry was treated as available")
	}
}

func TestPreparedSchemaBindingsKeepSameDigestPathsDistinct(t *testing.T) {
	root := t.TempDir()
	schemaBytes := []byte(`{"type":"integer"}`)
	references := []domain.PlanJSONSchemaRef{
		{
			Path:             ".repopass/schemas/a.json",
			Digest:           digestBytes(schemaBytes),
			Dialect:          domain.AlphaJSONSchemaDialect,
			ValidatorVersion: domain.AlphaJSONValidatorVersion,
		},
		{
			Path:             ".repopass/schemas/b.json",
			Digest:           digestBytes(schemaBytes),
			Dialect:          domain.AlphaJSONSchemaDialect,
			ValidatorVersion: domain.AlphaJSONValidatorVersion,
		},
	}
	for _, reference := range references {
		absolutePath := filepath.Join(
			root,
			filepath.FromSlash(reference.Path),
		)
		if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
			t.Fatalf("Create schema parent: %v", err)
		}
		if err := os.WriteFile(absolutePath, schemaBytes, 0o600); err != nil {
			t.Fatalf("Write schema: %v", err)
		}
	}
	plan := domain.ResolvedPlan{
		JourneyAssertions: []domain.PlanAssertion{
			{
				ID: "response-schema",
				Response: &domain.PlanHTTPResponseAssertion{
					RequestID:  "request",
					JSONSchema: &references[0],
				},
			},
			{
				ID: "file-schema",
				JSONFile: &domain.PlanJSONFileAssertion{
					Path:   "/outputs/value.json",
					Schema: references[1],
				},
			},
		},
	}
	compiled, err := testRunner(&fakeExecutor{}).
		prepareStructuredJSONSchemas(plan, root, t.TempDir())
	if err != nil {
		t.Fatalf("prepareStructuredJSONSchemas: %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("prepared schema binding count = %d, want 2", len(compiled))
	}
	prepared := &PreparedRun{
		executionPlan:         clonePlan(plan),
		executionPlanSealed:   true,
		structuredJSONSchemas: compiled,
	}
	for _, reference := range references {
		if schema, ok := prepared.structuredJSONSchema(reference); !ok ||
			schema == nil {
			t.Fatalf("prepared binding did not resolve: %#v", reference)
		}
	}
	undeclared := references[0]
	undeclared.Path = ".repopass/schemas/c.json"
	if schema, ok := prepared.structuredJSONSchema(undeclared); ok ||
		schema != nil {
		t.Fatal("unprepared same-digest path resolved a schema")
	}
}

func TestPrepareSealsStructuredBindingAgainstPublicMutation(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "server.js"),
		[]byte("server fixture\n"),
	)
	schemaBytes := []byte(`{"type":"string"}`)
	const schemaPath = ".repopass/schemas/response.json"
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, filepath.FromSlash(schemaPath)),
		schemaBytes,
	)
	plan := testHTTPPlan(t, sourceRoot)
	reference := domain.PlanJSONSchemaRef{
		Path:             schemaPath,
		Digest:           digestBytes(schemaBytes),
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
	plan.JourneyAssertions[0].Response.JSONSchema = &reference

	prepared, err := testRunner(dockerDoctorFake()).Prepare(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if err != nil {
		t.Fatalf("Prepare structured plan: %v", err)
	}
	t.Cleanup(func() {
		if err := cleanupPreparedCopies(prepared); err != nil {
			t.Errorf("cleanup prepared immutable copies: %v", err)
		}
	})
	privateBefore, err := json.Marshal(prepared.executionPlan)
	if err != nil {
		t.Fatalf("Marshal private plan: %v", err)
	}
	if schema, ok := prepared.structuredJSONSchema(reference); !ok ||
		schema == nil {
		t.Fatal("prepared plan-bound schema is unavailable")
	}
	preparedReference := reference

	plan.JourneyAssertions[0].Response.JSONSchema.Path =
		".repopass/schemas/original-mutated.json"
	plan.HTTPJourney.Steps = nil

	publicReference := prepared.Plan.JourneyAssertions[0].
		Response.JSONSchema
	publicReference.Path = ".repopass/schemas/public-mutated.json"
	publicReference.Digest = "sha256:" + strings.Repeat("0", 64)
	publicReference.Dialect =
		"https://json-schema.org/draft/2019-09/schema"
	publicReference.ValidatorVersion = "different-validator@v1"
	prepared.Plan.HTTPJourney.Steps = nil

	privateAfter, err := json.Marshal(prepared.executionPlan)
	if err != nil {
		t.Fatalf("Marshal private plan after mutation: %v", err)
	}
	if string(privateBefore) != string(privateAfter) {
		t.Fatal("source or exported plan mutation changed private execution plan")
	}
	if schema, ok := prepared.structuredJSONSchema(preparedReference); !ok ||
		schema == nil {
		t.Fatal("public mutation displaced original prepared schema binding")
	}
	if schema, ok := prepared.structuredJSONSchema(*publicReference); ok ||
		schema != nil {
		t.Fatal("mutated public schema reference aliased prepared cache")
	}
}

func TestReadPreparedSchemaRequiresPlanBoundDigest(t *testing.T) {
	root := t.TempDir()
	schemaPath := filepath.Join(root, ".repopass", "schemas", "value.json")
	if err := os.MkdirAll(filepath.Dir(schemaPath), 0o700); err != nil {
		t.Fatalf("create schema parent: %v", err)
	}
	raw := []byte(`{"type":"integer"}`)
	if err := os.WriteFile(schemaPath, raw, 0o600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	reference := domain.PlanJSONSchemaRef{
		Path:             ".repopass/schemas/value.json",
		Digest:           digestBytes(raw),
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
	got, err := readPreparedSchema(root, reference)
	if err != nil {
		t.Fatalf("readPreparedSchema: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("schema bytes = %q, want %q", got, raw)
	}
	reference.Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err := readPreparedSchema(root, reference); err == nil ||
		domain.ErrorCodeOf(err) != domain.CodeSourceDigestMismatch {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
