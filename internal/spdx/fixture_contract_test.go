package spdx_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/manifest"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/spdx"
)

func TestRepoOwnedMinimalPublicSPDXFixtureSupportsDerivedProfile(t *testing.T) {
	fixtureRoot, err := filepath.Abs(filepath.Join(
		"..", "..", "testdata", "fixtures", "healthy", "minimal-public-spdx",
	))
	if err != nil {
		t.Fatalf("resolve fixture root: %v", err)
	}

	document, err := manifest.Load(filepath.Join(fixtureRoot, "repo-passport.yml"))
	if err != nil {
		t.Fatalf("load existing SPDX-selected manifest: %v", err)
	}
	if findings := manifest.Validate(document); len(findings) != 0 {
		t.Fatalf("existing SPDX-selected manifest is invalid: %v", findings)
	}
	wantInclude := []string{"normalized-observations", "sbom", "verification-summary"}
	if document.Manifest.Spec.Evidence.Profile != "minimal-public" ||
		!slices.Equal(document.Manifest.Spec.Evidence.Include, wantInclude) {
		t.Fatalf("fixture no longer selects the exact SPDX evidence set: %#v", document.Manifest.Spec.Evidence)
	}

	provider := acquisition.NewLocalProvider()
	resolved, err := provider.ResolveCommandFree(context.Background(), domain.SourceRef{
		Kind: "local", Value: fixtureRoot,
	})
	if err != nil {
		t.Fatalf("command-free fixture resolve: %v", err)
	}
	if resolved.Commit != "" {
		t.Fatalf("command-free fixture resolve returned commit %q", resolved.Commit)
	}
	snapshot, err := provider.Fetch(context.Background(), resolved)
	if err != nil {
		t.Fatalf("fetch complete fixture snapshot: %v", err)
	}

	artifact, err := spdx.DerivePackageLockV3(snapshot)
	if err != nil {
		t.Fatalf("derive fixture SPDX: %v", err)
	}
	derivedDocument, provenance, err := spdx.ValidateDerivedPair(
		artifact.SPDX,
		artifact.ProvenanceCanonical,
	)
	if err != nil {
		t.Fatalf("validate fixture derived pair: %v", err)
	}
	if len(derivedDocument.Packages) != 2 || len(derivedDocument.Relationships) != 1 ||
		provenance.SourceTreeDigest != snapshot.TreeDigest || len(provenance.Inputs) != 2 {
		t.Fatalf("unexpected fixture derivation: document=%#v provenance=%#v", derivedDocument, provenance)
	}

	evaluation, err := privacy.EvaluateDerivedPair(
		artifact.SPDX,
		artifact.ProvenanceCanonical,
	)
	if err != nil {
		t.Fatalf("evaluate fixture derived privacy projection: %v", err)
	}
	if evaluation.PrivacyProfile != privacy.DerivedProjectionProfile ||
		evaluation.PrivacyPolicy != privacy.DerivedProjectionPolicy ||
		evaluation.PrivacyRulesetDigest != privacy.DerivedProjectionRulesetDigest ||
		evaluation.PrivacyEvaluation != privacy.EvaluationPassed {
		t.Fatalf("unexpected fixture privacy metadata: %#v", evaluation)
	}
}
