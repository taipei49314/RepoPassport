package structuredjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSchemaValidatesDraft2020Instances(t *testing.T) {
	schema := mustCompileSchema(t, `{
		"$schema":"https://json-schema.org/draft/2020-12/schema",
		"type":"object",
		"required":["name","count"],
		"properties":{
			"name":{"type":"string","pattern":"^[a-z]+$"},
			"count":{"type":"integer","minimum":1}
		},
		"additionalProperties":false
	}`)
	if err := schema.ValidateJSON(
		[]byte(`{"name":"alpha","count":9007199254740993}`),
		DefaultInstanceDecodeLimits(),
	); err != nil {
		t.Fatalf("ValidateJSON healthy: %v", err)
	}

	const secretValue = "RAW-INSTANCE-SECRET"
	err := schema.ValidateJSON(
		[]byte(`{"name":"`+secretValue+`","count":0}`),
		DefaultInstanceDecodeLimits(),
	)
	if KindOf(err) != ErrorSchemaNotSatisfied {
		t.Fatalf("ValidateJSON error = %v (%q)", err, KindOf(err))
	}
	if strings.Contains(err.Error(), secretValue) ||
		strings.Contains(fmt.Sprintf("%+v", err), secretValue) {
		t.Fatalf("validation error leaked raw instance: %#v", err)
	}
	var structuredError *Error
	if !errors.As(err, &structuredError) {
		t.Fatalf("validation error type = %T", err)
	}
	if structuredError.InstanceLocation != "" {
		t.Fatalf("instance location retained untrusted data: %q", structuredError.InstanceLocation)
	}

	const secretKey = "RAW-INSTANCE-KEY"
	closedObject := mustCompileSchema(t, `{
		"type":"object",
		"additionalProperties":false
	}`)
	err = closedObject.Validate(map[string]any{secretKey: true})
	if KindOf(err) != ErrorSchemaNotSatisfied {
		t.Fatalf("additional property error = %v (%q)", err, KindOf(err))
	}
	if strings.Contains(err.Error(), secretKey) ||
		strings.Contains(fmt.Sprintf("%+v", err), secretKey) {
		t.Fatalf("validation error leaked raw instance key: %#v", err)
	}
}

func TestSchemaUsesStrictInstanceDecoder(t *testing.T) {
	schema := mustCompileSchema(t, `{"type":"object"}`)
	err := schema.ValidateJSON(
		[]byte(`{"value":1,"value":2}`),
		DefaultInstanceDecodeLimits(),
	)
	if KindOf(err) != ErrorDuplicateKey {
		t.Fatalf("duplicate instance error = %v (%q)", err, KindOf(err))
	}
}

func TestSchemaNumberExponentLimitFailsClosedBeforeValidator(t *testing.T) {
	schema := mustCompileSchema(
		t,
		`{"type":"number","minimum":0}`,
	)
	for name, validate := range map[string]func() error{
		"strict JSON instance": func() error {
			return schema.ValidateJSON(
				[]byte(`1e1000001`),
				DefaultInstanceDecodeLimits(),
			)
		},
		"native JSON number": func() error {
			return schema.Validate(json.Number(`1e1000001`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := validate()
			if KindOf(err) != ErrorNumberExponentLimit {
				t.Fatalf(
					"validation error = %v (%q), want %q",
					err,
					KindOf(err),
					ErrorNumberExponentLimit,
				)
			}
		})
	}

	for name, raw := range map[string]string{
		"minimum":    `{"minimum":1e1000001}`,
		"maximum":    `{"maximum":1e1000001}`,
		"multipleOf": `{"multipleOf":1e1000001}`,
		"const":      `{"const":1e1000001}`,
		"enum":       `{"enum":[1e1000001]}`,
	} {
		t.Run("schema "+name, func(t *testing.T) {
			_, err := CompileSchema([]byte(raw))
			if KindOf(err) != ErrorNumberExponentLimit {
				t.Fatalf(
					"CompileSchema error = %v (%q), want %q",
					err,
					KindOf(err),
					ErrorNumberExponentLimit,
				)
			}
		})
	}
}

func TestSchemaAcceptsPositiveAndNegativeExponentBoundaries(t *testing.T) {
	positive := mustCompileSchema(
		t,
		`{"type":"number","minimum":1e1000}`,
	)
	if err := positive.ValidateJSON(
		[]byte(`1e1000`),
		DefaultInstanceDecodeLimits(),
	); err != nil {
		t.Fatalf("positive exponent boundary: %v", err)
	}

	negative := mustCompileSchema(
		t,
		`{"type":"number","multipleOf":1e-1000}`,
	)
	if err := negative.ValidateJSON(
		[]byte(`1e-1000`),
		DefaultInstanceDecodeLimits(),
	); err != nil {
		t.Fatalf("negative exponent boundary: %v", err)
	}
}

func TestSchemaSupportsOnlyLocalStaticReferences(t *testing.T) {
	schemas := []string{
		`{
			"$defs":{"positive":{"type":"integer","minimum":1}},
			"$ref":"#/$defs/positive"
		}`,
		`{
			"$id":"https://example.invalid/schema",
			"$defs":{"name":{"type":"string","minLength":1}},
			"$ref":"#/$defs/name"
		}`,
		`{
			"$anchor":"root",
			"type":"string"
		}`,
		`{
			"$defs":{
				"nested":{
					"$id":"https://example.invalid/nested",
					"x-target":{"type":"string","minLength":1},
					"$ref":"#/x-target"
				}
			},
			"$ref":"#/$defs/nested"
		}`,
	}
	instances := []string{"2", `"ok"`, `"value"`, `"nested-value"`}
	for index, raw := range schemas {
		schema := mustCompileSchema(t, raw)
		if err := schema.ValidateJSON(
			[]byte(instances[index]),
			DefaultInstanceDecodeLimits(),
		); err != nil {
			t.Fatalf("schema %d validation: %v", index, err)
		}
	}
	local := mustCompileSchema(t, schemas[0])
	if err := local.ValidateJSON([]byte(`0`), DefaultInstanceDecodeLimits()); KindOf(err) != ErrorSchemaNotSatisfied {
		t.Fatalf("local ref mismatch = %v (%q)", err, KindOf(err))
	}
}

func TestCompileSchemaRejectsUnboundedResolutionFeatures(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		kind ErrorKind
	}{
		{
			name: "remote ref",
			raw:  `{"$ref":"https://example.invalid/schema"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "relative external ref",
			raw:  `{"$ref":"other.json#/$defs/value"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "dynamic ref",
			raw:  `{"$dynamicRef":"#node"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "recursive ref",
			raw:  `{"$recursiveRef":"#"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "custom vocabulary",
			raw:  `{"$vocabulary":{"https://example.invalid/vocab":true}}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "old draft",
			raw:  `{"$schema":"http://json-schema.org/draft-07/schema#"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "custom metaschema",
			raw:  `{"$schema":"https://example.invalid/meta"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "hidden external resolution",
			raw:  `{"x-target":{"$ref":"https://example.invalid/schema"},"$ref":"#/x-target"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "hidden dynamic ref",
			raw:  `{"x-target":{"$dynamicRef":"#node"},"$ref":"#/x-target"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "encoded hidden external resolution",
			raw:  `{"x-target":{"$ref":"https://example.invalid/schema"},"$ref":"#/%78-target"}`,
			kind: ErrorSchemaPolicy,
		},
		{
			name: "nested resource hidden dynamic ref",
			raw: `{
				"x-target":true,
				"$defs":{
					"nested":{
						"$id":"https://example.invalid/nested",
						"$dynamicAnchor":"node",
						"x-target":{"$dynamicRef":"#node"},
						"$ref":"#/x-target"
					}
				}
			}`,
			kind: ErrorSchemaPolicy,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileSchema([]byte(test.raw))
			if KindOf(err) != test.kind {
				t.Fatalf("CompileSchema error = %v (%q), want %q", err, KindOf(err), test.kind)
			}
		})
	}
}

func TestSchemaPolicyIgnoresInstanceDataKeywords(t *testing.T) {
	schema := mustCompileSchema(t, `{
		"const":{
			"$ref":"https://example.invalid/not-a-schema",
			"$dynamicRef":"still-instance-data",
			"pattern":"`+strings.Repeat("x", MaxSchemaPatternBytes+1)+`"
		}
	}`)
	instance := map[string]any{
		"$ref":        "https://example.invalid/not-a-schema",
		"$dynamicRef": "still-instance-data",
		"pattern":     strings.Repeat("x", MaxSchemaPatternBytes+1),
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("Validate const instance data: %v", err)
	}
}

func TestSchemaPolicyFollowsLocalPointerTargets(t *testing.T) {
	branches := make([]any, MaxSchemaBranches+1)
	for index := range branches {
		branches[index] = true
	}
	raw, err := json.Marshal(map[string]any{
		"const": map[string]any{
			"oneOf": branches,
		},
		"$ref": "#/const",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileSchema(raw); KindOf(err) != ErrorSchemaPolicy {
		t.Fatalf("CompileSchema hidden branches = %v (%q)", err, KindOf(err))
	}
}

func TestCompileSchemaEnforcesResourceLimits(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		_, err := CompileSchema(bytes.Repeat([]byte{' '}, MaxSchemaBytes+1))
		if KindOf(err) != ErrorTooLarge {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})

	t.Run("depth", func(t *testing.T) {
		raw := strings.Repeat(`{"not":`, MaxSchemaDepth+1) +
			`true` +
			strings.Repeat(`}`, MaxSchemaDepth+1)
		_, err := CompileSchema([]byte(raw))
		if KindOf(err) != ErrorDepthLimit {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})

	t.Run("nodes", func(t *testing.T) {
		values := make([]any, MaxSchemaNodes)
		raw, err := json.Marshal(map[string]any{"const": values})
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileSchema(raw)
		if KindOf(err) != ErrorNodeLimit {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})

	t.Run("branches", func(t *testing.T) {
		branches := make([]any, MaxSchemaBranches+1)
		for index := range branches {
			branches[index] = true
		}
		raw, err := json.Marshal(map[string]any{"oneOf": branches})
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileSchema(raw)
		if KindOf(err) != ErrorSchemaPolicy {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})

	t.Run("patterns", func(t *testing.T) {
		patterns := make(map[string]any, MaxSchemaPatterns+1)
		for index := 0; index <= MaxSchemaPatterns; index++ {
			patterns[fmt.Sprintf("^value-%03d$", index)] = true
		}
		raw, err := json.Marshal(map[string]any{
			"type":              "object",
			"patternProperties": patterns,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileSchema(raw)
		if KindOf(err) != ErrorSchemaPolicy {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})

	t.Run("pattern bytes", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"type":    "string",
			"pattern": strings.Repeat("a", MaxSchemaPatternBytes+1),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileSchema(raw)
		if KindOf(err) != ErrorSchemaPolicy {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})

	t.Run("references", func(t *testing.T) {
		properties := make(map[string]any, MaxSchemaReferences+1)
		for index := 0; index <= MaxSchemaReferences; index++ {
			properties[fmt.Sprintf("property%03d", index)] =
				map[string]any{"$ref": "#"}
		}
		raw, err := json.Marshal(map[string]any{
			"type":       "object",
			"properties": properties,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileSchema(raw)
		if KindOf(err) != ErrorSchemaPolicy {
			t.Fatalf("CompileSchema error = %v (%q)", err, KindOf(err))
		}
	})
}

func TestCompileSchemaRejectsAmbiguousOrInvalidSchemas(t *testing.T) {
	tests := []struct {
		raw  string
		kind ErrorKind
	}{
		{`{"type":"string","type":"number"}`, ErrorDuplicateKey},
		{`{"type":42}`, ErrorSchemaCompile},
		{`[]`, ErrorSchemaCompile},
		{`{"pattern":"["}`, ErrorSchemaCompile},
	}
	for _, test := range tests {
		_, err := CompileSchema([]byte(test.raw))
		if KindOf(err) != test.kind {
			t.Errorf("CompileSchema(%s) error = %v (%q), want %q", test.raw, err, KindOf(err), test.kind)
		}
	}
}

func TestSchemaValidateFailsClosedOnUnsupportedOrDeepValues(t *testing.T) {
	schema := mustCompileSchema(t, `true`)
	if err := schema.Validate(struct{}{}); KindOf(err) != ErrorUnsupportedValue {
		t.Fatalf("unsupported value error = %v (%q)", err, KindOf(err))
	}
	if err := schema.Validate(string([]byte{0xff})); KindOf(err) != ErrorUnsupportedValue {
		t.Fatalf("invalid UTF-8 value error = %v (%q)", err, KindOf(err))
	}
	if err := schema.Validate(json.Number("01")); KindOf(err) != ErrorUnsupportedValue {
		t.Fatalf("invalid number lexeme error = %v (%q)", err, KindOf(err))
	}

	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if err := schema.Validate(cyclic); KindOf(err) != ErrorDepthLimit {
		t.Fatalf("cyclic value error = %v (%q)", err, KindOf(err))
	}
	var nilSchema *Schema
	if err := nilSchema.Validate(nil); KindOf(err) != ErrorSchemaCompile {
		t.Fatalf("nil schema error = %v (%q)", err, KindOf(err))
	}
}

func TestBooleanSchemas(t *testing.T) {
	if err := mustCompileSchema(t, `true`).Validate(nil); err != nil {
		t.Fatalf("true schema: %v", err)
	}
	if err := mustCompileSchema(t, `false`).Validate(nil); KindOf(err) != ErrorSchemaNotSatisfied {
		t.Fatalf("false schema error = %v (%q)", err, KindOf(err))
	}
}

func mustCompileSchema(t *testing.T, raw string) *Schema {
	t.Helper()
	schema, err := CompileSchema([]byte(raw))
	if err != nil {
		t.Fatalf("CompileSchema: %v", err)
	}
	return schema
}
