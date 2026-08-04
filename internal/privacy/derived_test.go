package privacy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/acquisition"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/spdx"
)

func TestDerivedProjectionFrozenMetadataAndControllerFieldsPass(t *testing.T) {
	if spdx.Digest([]byte(DerivedProjectionDescriptor())) != DerivedProjectionRulesetDigest {
		t.Fatal("derived projection descriptor digest drift")
	}
	if DerivedBasePrivacyRulesetDigest != RulesetDigest {
		t.Fatal("derived projection base ruleset is not locked to the active base scanner")
	}
	if strings.Contains(DerivedProjectionDescriptor(), "controllerGeneratedExcluded") ||
		!strings.Contains(DerivedProjectionDescriptor(), "structuralFieldsExcluded") ||
		!strings.Contains(DerivedProjectionDescriptor(), "validatedLockChecksumExcluded") ||
		!strings.Contains(DerivedProjectionDescriptor(), `"registryArtifactVerified":false`) ||
		!strings.Contains(DerivedProjectionDescriptor(), `"repositoryControlledPossible":true`) {
		t.Fatal("derived projection descriptor does not state the checksum trust boundary")
	}
	artifact := privacyDerivedArtifact(t)
	evaluation, err := EvaluateDerivedPair(artifact.SPDX, artifact.ProvenanceCanonical)
	if err != nil {
		t.Fatalf("safe derived pair: %v", err)
	}
	if evaluation.PrivacyProfile != DerivedProjectionProfile || evaluation.PrivacyPolicy != DerivedProjectionPolicy ||
		evaluation.PrivacyRulesetDigest != DerivedProjectionRulesetDigest || evaluation.PrivacyEvaluation != EvaluationPassed {
		t.Fatalf("unexpected metadata: %#v", evaluation)
	}
}

func TestDerivedProjectionFailsClosedOnBaseRulesetMetadataDrift(t *testing.T) {
	mutated := Passed()
	mutated.PrivacyRulesetDigest = "sha256:" + strings.Repeat("0", 64)
	err := validateDerivedBaseEvaluation(mutated)
	if domain.ErrorCodeOf(err) != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("base ruleset drift error = %v", err)
	}
	if strings.Contains(err.Error(), mutated.PrivacyRulesetDigest) {
		t.Fatal("base ruleset drift error echoed untrusted metadata")
	}
}

func TestDerivedProjectionBlocksRepositoryStringsAndNeverEchoes(t *testing.T) {
	artifact := privacyDerivedArtifact(t)
	cases := map[string]struct {
		name    string
		version string
		code    domain.ErrorCode
	}{
		"provider-token": {
			name: "github_pat_" + strings.Repeat("a", 24), version: "1.0.0",
			code: domain.CodeEvidencePrivacyBlocked,
		},
		"high-entropy-name": {
			name: "a9b8c7d6e5f4g3h2i1j0klmnopqrstuv", version: "1.0.0",
			code: domain.CodeEvidencePrivacyBlocked,
		},
		"high-entropy-version": {
			name: "safe", version: "1.0.0-a9b8c7d6e5f4g3h2i1j0klmnopqrstuv",
			code: domain.CodeEvidencePrivacyBlocked,
		},
		"email-shape":  {name: "person@example.com", version: "1.0.0"},
		"private-path": {name: "/home/" + "person/private", version: "1.0.0"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			document := artifact.Document
			document.Packages = append([]spdx.DerivedPackage(nil), document.Packages...)
			document.Packages[len(document.Packages)-1].Name = test.name
			document.Packages[len(document.Packages)-1].VersionInfo = test.version
			raw, marshalErr := canonicaljson.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, err := EvaluateDerivedPair(raw, artifact.ProvenanceCanonical)
			if err == nil {
				t.Fatal("unsafe repository string accepted")
			}
			if test.code != "" && domain.ErrorCodeOf(err) != test.code {
				t.Fatalf("error code = %q: %v", domain.ErrorCodeOf(err), err)
			}
			if strings.Contains(err.Error(), test.name) || strings.Contains(err.Error(), test.version) {
				t.Fatal("error echoed repository-derived content")
			}
		})
	}
}

func privacyDerivedArtifact(t *testing.T) spdx.DerivedArtifact {
	t.Helper()
	directory := t.TempDir()
	packageJSON := []byte(`{"dependencies":{"safe":"1.0.0"},"name":"root","version":"1.0.0"}`)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))
	lock := map[string]any{
		"name": "root", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "root", "version": "1.0.0", "dependencies": map[string]any{"safe": "1.0.0"}},
			"node_modules/safe": map[string]any{
				"version": "1.0.0", "resolved": "https://registry.npmjs.org/safe/-/safe-1.0.0.tgz", "integrity": integrity,
			},
		},
	}
	lockJSON, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "package.json"), packageJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "package-lock.json"), lockJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.ResolveCommandFree(context.Background(), domain.SourceRef{Kind: "local", Value: directory})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.Fetch(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := spdx.DerivePackageLockV3(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}
