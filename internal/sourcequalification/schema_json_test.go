package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSchemaJSONAcceptsStrictSchemaAndFixtureDocuments(t *testing.T) {
	root := t.TempDir()
	writeSchemaJSONFixture(t, root, "schemas/example.schema.json", []byte(`{"type":"object"}`))
	writeSchemaJSONFixture(t, root, "testdata/fixtures/example/fixture.json", []byte(`{"status":"healthy"}`))
	if err := ValidateSchemaJSON(root); err != nil {
		t.Fatalf("ValidateSchemaJSON rejected strict fixture tree: %v", err)
	}
}

func TestValidateSchemaJSONRejectsInvalidOrMissingContracts(t *testing.T) {
	tests := []struct {
		name  string
		files map[string][]byte
	}{
		{
			name:  "no schema",
			files: map[string][]byte{"testdata/fixtures/value.json": []byte(`{}`)},
		},
		{
			name:  "duplicate key",
			files: map[string][]byte{"schemas/value.schema.json": []byte(`{"type":"object","type":"array"}`)},
		},
		{
			name:  "trailing value",
			files: map[string][]byte{"schemas/value.schema.json": []byte(`{} {}`)},
		},
		{
			name:  "oversized JSON",
			files: map[string][]byte{"schemas/value.schema.json": append([]byte(`{"value":"`), append(make([]byte, (16<<20)+1), []byte(`"}`)...)...)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for path, raw := range test.files {
				writeSchemaJSONFixture(t, root, path, raw)
			}
			if err := ValidateSchemaJSON(root); err == nil {
				t.Fatal("ValidateSchemaJSON accepted invalid JSON contract tree")
			}
		})
	}
}

func writeSchemaJSONFixture(t *testing.T, root, relative string, raw []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
