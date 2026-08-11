package schemas_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSourceQualificationSchemasArePublishedAndStrict(t *testing.T) {
	tests := []struct {
		name     string
		required []string
	}{
		{
			name: "source-archive-manifest-v1.schema.json",
			required: []string{
				"archive", "artifactType", "files", "schemaVersion", "subject",
			},
		},
		{
			name: "source-qualification-receipt-v1.schema.json",
			required: []string{
				"artifactType", "attempt", "controller", "execution", "gates",
				"limitations", "notApplicable", "platform", "predicateType",
				"productDimensions", "qualificationStatus", "run", "schemaVersion",
				"source", "subject",
			},
		},
		{
			name: "source-qualification-tool-manifest-v1.schema.json",
			required: []string{
				"artifactType", "schemaVersion", "subject", "tools",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(test.name)
			if err != nil {
				t.Fatalf("read required public schema: %v", err)
			}
			var document map[string]any
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				t.Fatalf("decode public schema: %v", err)
			}
			if document["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
				t.Fatalf("$schema = %#v", document["$schema"])
			}
			wantID := "https://schemas.repopass.dev/v1alpha1/" + test.name
			if document["$id"] != wantID {
				t.Fatalf("$id = %#v, want %q", document["$id"], wantID)
			}
			if document["additionalProperties"] != false {
				t.Fatal("source-qualification schema root is not fail-closed")
			}
			gotRequired := jsonStringSlice(t, document["required"])
			sort.Strings(gotRequired)
			wantRequired := append([]string(nil), test.required...)
			sort.Strings(wantRequired)
			if !reflect.DeepEqual(gotRequired, wantRequired) {
				t.Fatalf("required = %q, want exact %q", gotRequired, wantRequired)
			}

			compiler := jsonschema.NewCompiler()
			compiler.DefaultDraft(jsonschema.Draft2020)
			compiler.AssertFormat()
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("decode schema document: %v", err)
			}
			if err := compiler.AddResource(wantID, value); err != nil {
				t.Fatalf("register schema: %v", err)
			}
			if _, err := compiler.Compile(wantID); err != nil {
				t.Fatalf("compile schema: %v", err)
			}
		})
	}
}

func jsonStringSlice(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value is not a JSON array: %#v", value)
	}
	result := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("array item %d is not a string: %#v", index, item)
		}
		result[index] = text
	}
	return result
}
