package schemas_test

import (
	"testing"

	schemavalidator "github.com/taipei49314/RepoPassport/schemas"
)

func TestSourceQualificationValidatorsRejectEmptyDocuments(t *testing.T) {
	tests := []struct {
		name     string
		validate func([]byte) error
	}{
		{"source archive manifest", schemavalidator.ValidateSourceArchiveManifestV1JSON},
		{"source qualification receipt", schemavalidator.ValidateSourceQualificationReceiptV1JSON},
		{"source qualification tool manifest", schemavalidator.ValidateSourceQualificationToolManifestV1JSON},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.validate([]byte(`{}`)); err == nil {
				t.Fatal("strict source-qualification validator accepted an empty object")
			}
		})
	}
}
