package runtimepolicy

import (
	"testing"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
)

func TestValidateAcceptsOnlyBuiltInRuntimeTuples(t *testing.T) {
	for _, test := range []struct {
		name      string
		adapter   string
		version   string
		reference string
		digest    string
	}{
		{
			name:      "node",
			adapter:   "node",
			version:   NodeVersion,
			reference: NodeReference,
			digest:    NodeDigest,
		},
		{
			name:      "python",
			adapter:   "python",
			version:   PythonVersion,
			reference: PythonReference,
			digest:    PythonDigest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(
				test.adapter,
				test.version,
				test.reference,
				test.digest,
				"linux/amd64",
			); err != nil {
				t.Fatalf("Validate approved tuple: %v", err)
			}
		})
	}
}

func TestValidateRejectsTupleDriftAndUnapprovedPlatform(t *testing.T) {
	tests := []struct {
		name      string
		adapter   string
		version   string
		reference string
		digest    string
		platform  string
	}{
		{"adapter", "python", NodeVersion, NodeReference, NodeDigest, "linux/amd64"},
		{"version", "node", "22.23.2", NodeReference, NodeDigest, "linux/amd64"},
		{"reference", "node", NodeVersion, PythonReference, NodeDigest, "linux/amd64"},
		{"digest", "node", NodeVersion, NodeReference, PythonDigest, "linux/amd64"},
		{"platform", "node", NodeVersion, NodeReference, NodeDigest, "linux/arm64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(
				test.adapter,
				test.version,
				test.reference,
				test.digest,
				test.platform,
			)
			if err == nil ||
				domain.ErrorCodeOf(err) != domain.CodeRunnerFeatureUnavailable {
				t.Fatalf("Validate drift error = %v", err)
			}
		})
	}
}

func TestBindingIsDeterministicAndContainsBothApprovedImages(t *testing.T) {
	first, err := canonicaljson.Digest(Binding())
	if err != nil {
		t.Fatalf("digest first binding: %v", err)
	}
	second, err := canonicaljson.Digest(Binding())
	if err != nil {
		t.Fatalf("digest second binding: %v", err)
	}
	if first != second {
		t.Fatalf("binding digest changed: %q != %q", first, second)
	}
	images, ok := Binding()["images"].([]BindingEntry)
	if !ok || len(images) != 2 {
		t.Fatalf("binding images = %#v, want two entries", Binding()["images"])
	}
}
