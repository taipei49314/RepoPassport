package attestation

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestBuildOutputMatchesPublicAttestationSchemas(t *testing.T) {
	_, privateKey := generateKey(t)
	compiled := compileAttestationSchemas(t)
	withoutSBOM, err := Build(validResult(t, "inconclusive"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	withSBOM, err := BuildWithSPDX(validSBOMResult(t), validSPDXBytes(), privateKey)
	if err != nil {
		t.Fatalf("BuildWithSPDX: %v", err)
	}
	derivedArtifact, derivedResult := derivedAttestationInputs(t)
	derived, err := BuildWithDerivedSPDX(
		derivedResult, derivedArtifact.SPDX, derivedArtifact.ProvenanceCanonical, privateKey,
	)
	if err != nil {
		t.Fatalf("BuildWithDerivedSPDX: %v", err)
	}
	for _, model := range []struct {
		name, manifestSchema, attestationSchema string
		bundle                                  []byte
	}{
		{name: "five-member", bundle: withoutSBOM.Bundle, manifestSchema: "bundle-manifest.schema.json", attestationSchema: "attestation.schema.json"},
		{name: "six-member", bundle: withSBOM.Bundle, manifestSchema: "bundle-manifest.schema.json", attestationSchema: "attestation.schema.json"},
		{name: "seven-member-v2", bundle: derived.Bundle, manifestSchema: "bundle-manifest-v2.schema.json", attestationSchema: "attestation-v2.schema.json"},
	} {
		files := parsedFiles(t, model.bundle)
		for file, schemaName := range map[string]string{
			manifestPath:    model.manifestSchema,
			attestationPath: model.attestationSchema,
			signaturePath:   "dsse-envelope.schema.json",
		} {
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(files[file]))
			if err != nil {
				t.Fatalf("decode generated %s %s: %v", model.name, file, err)
			}
			if err := compiled[schemaName].Validate(instance); err != nil {
				t.Fatalf("generated %s %s does not match %s: %v\n%s", model.name, file, schemaName, err, files[file])
			}
		}
		if model.name == "seven-member-v2" {
			for file, schemaName := range map[string]string{
				sbomPath: "spdx-derived-v1.schema.json", provenancePath: "sbom-provenance-v1.schema.json",
			} {
				instance, decodeErr := jsonschema.UnmarshalJSON(bytes.NewReader(files[file]))
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				if schemaErr := compiled[schemaName].Validate(instance); schemaErr != nil {
					t.Fatalf("generated %s does not match %s: %v", file, schemaName, schemaErr)
				}
			}
		}
	}
}

func compileAttestationSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	const baseURL = "https://schemas.repopass.dev/v1alpha1/"
	names := []string{
		"observation.schema.json",
		"assertion.schema.json",
		"error.schema.json",
		"verification.schema.json",
		"bundle-manifest.schema.json",
		"bundle-manifest-v2.schema.json",
		"attestation.schema.json",
		"attestation-v2.schema.json",
		"spdx-derived-v1.schema.json",
		"sbom-provenance-v1.schema.json",
		"dsse-envelope.schema.json",
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("decode schema %s: %v", name, err)
		}
		if err := compiler.AddResource(baseURL+name, document); err != nil {
			t.Fatalf("register schema %s: %v", name, err)
		}
	}
	result := make(map[string]*jsonschema.Schema)
	for _, name := range []string{
		"bundle-manifest.schema.json",
		"bundle-manifest-v2.schema.json",
		"attestation.schema.json",
		"attestation-v2.schema.json",
		"spdx-derived-v1.schema.json",
		"sbom-provenance-v1.schema.json",
		"dsse-envelope.schema.json",
	} {
		compiled, err := compiler.Compile(baseURL + name)
		if err != nil {
			t.Fatalf("compile schema %s: %v", name, err)
		}
		result[name] = compiled
	}
	return result
}
