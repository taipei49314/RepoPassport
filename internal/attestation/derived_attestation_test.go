package attestation

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/spdx"
	"github.com/taipei49314/RepoPassport/internal/verification"
)

func TestDerivedV2BundleDeterministicExactModelReplayAndBindings(t *testing.T) {
	artifact, result := derivedAttestationInputs(t)
	_, privateKey := generateKey(t)
	built, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey)
	if err != nil {
		t.Fatalf("build derived: %v", err)
	}
	repeated, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey)
	if err != nil {
		t.Fatalf("repeat derived: %v", err)
	}
	if !bytes.Equal(built.Bundle, repeated.Bundle) {
		t.Fatal("derived bundle is not deterministic")
	}
	if built.SBOMPrivacyProfile != privacy.DerivedProjectionProfile ||
		built.SBOMPrivacyPolicy != privacy.DerivedProjectionPolicy ||
		built.SBOMPrivacyRulesetDigest != privacy.DerivedProjectionRulesetDigest ||
		built.SBOMPrivacyEvaluation != privacy.EvaluationPassed {
		t.Fatalf("unexpected build privacy binding: %#v", built)
	}
	wantNames := []string{
		attestationPath, manifestPath, provenancePath, sbomPath,
		verificationPath, signaturePath, publicKeyPath,
	}
	if got := tarEntryNames(t, built.Bundle); !equalStrings(got, wantNames) {
		t.Fatalf("member order = %#v, want %#v", got, wantNames)
	}

	report, err := Verify(built.Bundle, built.PublicKeyPEM)
	if err != nil {
		t.Fatalf("verify trusted v2: %v", err)
	}
	if report.SchemaVersion != BundleVersionV2 || report.TrustDecision != "accepted" ||
		report.SBOMOrigin != spdx.DerivedOrigin || report.SBOMProfile != spdx.DerivedProfile ||
		report.SBOMRulesetDigest != spdx.DerivedRulesetDigest ||
		report.SBOMProvenanceDigest != digestBytes(artifact.ProvenanceCanonical) ||
		report.SBOMPrivacyProfile != privacy.DerivedProjectionProfile ||
		report.SBOMPrivacyPolicy != privacy.DerivedProjectionPolicy ||
		report.SBOMPrivacyRulesetDigest != privacy.DerivedProjectionRulesetDigest ||
		report.SBOMPrivacyEvaluation != privacy.EvaluationPassed ||
		report.SBOMCurrentnessEvaluation != SBOMCurrentnessNotEvaluated {
		t.Fatalf("unexpected v2 report: %#v", report)
	}
	acceptedReport, claims, err := VerifyAccepted(built.Bundle, built.PublicKeyPEM)
	if err != nil || acceptedReport.TrustDecision != "accepted" || claims.Derived == nil ||
		claims.Derived.Provenance.DerivationInputDigest != artifact.Provenance.DerivationInputDigest ||
		claims.Derived.SBOMDigest != spdx.Digest(artifact.SPDX) {
		t.Fatalf("accepted claims mismatch: report=%#v claims=%#v err=%v", acceptedReport, claims, err)
	}

	files := parsedFiles(t, built.Bundle)
	var manifest Manifest
	mustJSON(t, files[manifestPath], &manifest)
	if manifest.SchemaVersion != BundleVersionV2 || manifest.BundleFormat != "repopass.attestation.bundle.v2" ||
		manifest.PrivacyProfile != privacy.DerivedProjectionProfile ||
		manifest.PrivacyPolicy != privacy.DerivedProjectionPolicy ||
		manifest.PrivacyRulesetDigest != privacy.DerivedProjectionRulesetDigest ||
		len(manifest.Files) != 4 || manifest.Files[1].SHA256 != spdx.Digest(artifact.SPDX) ||
		manifest.Files[2].SHA256 != digestBytes(artifact.ProvenanceCanonical) {
		t.Fatalf("unexpected v2 manifest: %#v", manifest)
	}
	var statement Statement
	mustJSON(t, files[attestationPath], &statement)
	if statement.PredicateType != PredicateTypeV2 || statement.Predicate.SchemaVersion != BundleVersionV2 ||
		statement.Predicate.SBOM == nil || statement.Predicate.SBOM.Digest != spdx.Digest(artifact.SPDX) ||
		statement.Predicate.SBOM.ProvenancePath != provenancePath ||
		statement.Predicate.SBOM.ProvenanceDigest != digestBytes(artifact.ProvenanceCanonical) ||
		statement.Predicate.SBOM.PrivacyProfile != privacy.DerivedProjectionProfile ||
		statement.Predicate.SBOM.PrivacyPolicy != privacy.DerivedProjectionPolicy ||
		statement.Predicate.SBOM.PrivacyRulesetDigest != privacy.DerivedProjectionRulesetDigest {
		t.Fatalf("unexpected v2 statement: %#v", statement)
	}
}

func TestLegacyV1ModelsOmitDerivedPrivacyBindings(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := BuildWithSPDX(validSBOMResult(t), validSPDXBytes(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	files := parsedFiles(t, built.Bundle)
	var manifest Manifest
	mustJSON(t, files[manifestPath], &manifest)
	if manifest.PrivacyPolicy != "" || manifest.PrivacyRulesetDigest != "" ||
		bytes.Contains(files[manifestPath], []byte(`"privacyPolicy"`)) ||
		bytes.Contains(files[manifestPath], []byte(`"privacyRulesetDigest"`)) {
		t.Fatalf("legacy manifest gained v2 privacy fields: %s", files[manifestPath])
	}
	var statement Statement
	mustJSON(t, files[attestationPath], &statement)
	if statement.Predicate.SBOM == nil || statement.Predicate.SBOM.PrivacyProfile != "" ||
		statement.Predicate.SBOM.PrivacyPolicy != "" || statement.Predicate.SBOM.PrivacyRulesetDigest != "" {
		t.Fatalf("legacy predicate gained v2 privacy fields: %#v", statement.Predicate.SBOM)
	}
}

func TestDerivedV2DirectTamperModelConfusionAndCorrectlyResignedPrivacyBlocked(t *testing.T) {
	artifact, result := derivedAttestationInputs(t)
	_, privateKey := generateKey(t)
	built, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{attestationPath, manifestPath, provenancePath, sbomPath, verificationPath, signaturePath, publicKeyPath} {
		t.Run("tamper-"+strings.ReplaceAll(name, "/", "-"), func(t *testing.T) {
			files := parsedFiles(t, built.Bundle)
			files[name] = append([]byte(nil), files[name]...)
			files[name][0] ^= 1
			mutated, buildErr := buildCanonicalTarV2(files)
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			if _, verifyErr := Verify(mutated, built.PublicKeyPEM); domain.ErrorCodeOf(verifyErr) != domain.CodeAttestationInvalid {
				t.Fatalf("tamper error = %v", verifyErr)
			}
		})
	}

	files := parsedFiles(t, built.Bundle)
	delete(files, provenancePath)
	confused, err := buildCanonicalTar(files, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(confused, built.PublicKeyPEM); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
		t.Fatalf("v2-to-v1 model confusion error = %v", err)
	}

	unsafeDocument := artifact.Document
	unsafeDocument.Packages = append([]spdx.DerivedPackage(nil), unsafeDocument.Packages...)
	unsafeDocument.Packages[len(unsafeDocument.Packages)-1].Name = "github_pat_" + strings.Repeat("a", 24)
	unsafeSBOM := mustCanonical(t, unsafeDocument)
	unsafeProvenanceJSON := artifact.ProvenanceCanonical
	if _, err := BuildWithDerivedSPDX(result, unsafeSBOM, unsafeProvenanceJSON, nil); domain.ErrorCodeOf(err) != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("privacy did not precede invalid key: %v", err)
	}
	attack := correctlyResignedDerivedBundle(t, result, unsafeSBOM, unsafeProvenanceJSON, privateKey)
	if _, err := Verify(attack, built.PublicKeyPEM); domain.ErrorCodeOf(err) != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("correctly re-signed privacy attack error = %v", err)
	}
}

func TestDerivedV2RejectsMissingExtraHybridAndReorderedMembers(t *testing.T) {
	artifact, result := derivedAttestationInputs(t)
	_, privateKey := generateKey(t)
	built, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	original := parsedFiles(t, built.Bundle)

	tests := map[string]func(*testing.T) []byte{
		"missing-sbom": func(t *testing.T) []byte {
			files := cloneDerivedFiles(original)
			delete(files, sbomPath)
			return canonicalTarWithNamesForTest(t, files, []string{
				attestationPath, manifestPath, provenancePath, verificationPath, signaturePath, publicKeyPath,
			})
		},
		"extra-duplicate-member": func(t *testing.T) []byte {
			return canonicalTarWithNamesForTest(t, cloneDerivedFiles(original), append(bundlePathsV2(), verificationPath))
		},
		"hybrid-v2-content-v1-model": func(t *testing.T) []byte {
			files := cloneDerivedFiles(original)
			delete(files, provenancePath)
			return canonicalTarWithNamesForTest(t, files, bundlePaths(true))
		},
		"reordered-members": func(t *testing.T) []byte {
			names := bundlePathsV2()
			names[2], names[3] = names[3], names[2]
			return canonicalTarWithNamesForTest(t, cloneDerivedFiles(original), names)
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(build(t), built.PublicKeyPEM); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
				t.Fatalf("model attack error = %v", err)
			}
		})
	}
}

func TestDerivedV2RejectsReboundAndResignedProvenanceFieldAttacks(t *testing.T) {
	artifact, result := derivedAttestationInputs(t)
	_, privateKey := generateKey(t)
	built, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	tests := map[string]func(*spdx.DerivedProvenance){
		"origin":                  func(value *spdx.DerivedProvenance) { value.Origin = "caller-supplied" },
		"profile":                 func(value *spdx.DerivedProvenance) { value.Profile = "future-profile" },
		"ruleset-digest":          func(value *spdx.DerivedProvenance) { value.RulesetDigest = zeroDigest },
		"source-profile":          func(value *spdx.DerivedProvenance) { value.SourceProfile = "future-source" },
		"source-tree-digest":      func(value *spdx.DerivedProvenance) { value.SourceTreeDigest = zeroDigest },
		"derivation-input-digest": func(value *spdx.DerivedProvenance) { value.DerivationInputDigest = zeroDigest },
		"scope":                   func(value *spdx.DerivedProvenance) { value.Scope = "all-files" },
		"completeness":            func(value *spdx.DerivedProvenance) { value.Completeness = "complete" },
		"inputs-reordered": func(value *spdx.DerivedProvenance) {
			value.Inputs = append([]spdx.DerivedInputRecord(nil), value.Inputs...)
			value.Inputs[0], value.Inputs[1] = value.Inputs[1], value.Inputs[0]
		},
		"input-path": func(value *spdx.DerivedProvenance) {
			value.Inputs = append([]spdx.DerivedInputRecord(nil), value.Inputs...)
			value.Inputs[0].Path = "other-lock.json"
		},
		"input-digest": func(value *spdx.DerivedProvenance) {
			value.Inputs = append([]spdx.DerivedInputRecord(nil), value.Inputs...)
			value.Inputs[0].SHA256 = zeroDigest
		},
		"input-size": func(value *spdx.DerivedProvenance) {
			value.Inputs = append([]spdx.DerivedInputRecord(nil), value.Inputs...)
			value.Inputs[0].Size++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			provenance := artifact.Provenance
			mutate(&provenance)
			provenanceJSON := mustCanonical(t, provenance)
			attack := correctlyResignedDerivedBundle(t, result, artifact.SPDX, provenanceJSON, privateKey)
			if _, err := Verify(attack, built.PublicKeyPEM); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
				t.Fatalf("rebound provenance attack error = %v", err)
			}
		})
	}
}

func TestDerivedV2RejectsCorrectlyResignedPrivacyMetadataSubstitution(t *testing.T) {
	artifact, result := derivedAttestationInputs(t)
	_, privateKey := generateKey(t)
	built, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	tests := map[string]struct {
		manifest  func(*Manifest)
		statement func(*Statement)
	}{
		"policy-consistent-substitution": {
			manifest: func(value *Manifest) { value.PrivacyPolicy = "attacker-policy" },
			statement: func(value *Statement) {
				value.Predicate.SBOM.PrivacyPolicy = "attacker-policy"
			},
		},
		"ruleset-consistent-substitution": {
			manifest: func(value *Manifest) { value.PrivacyRulesetDigest = zeroDigest },
			statement: func(value *Statement) {
				value.Predicate.SBOM.PrivacyRulesetDigest = zeroDigest
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			attack := correctlyResignedDerivedBundleWithMutation(
				t, result, artifact.SPDX, artifact.ProvenanceCanonical, privateKey, test.manifest, test.statement,
			)
			if _, err := Verify(attack, built.PublicKeyPEM); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
				t.Fatalf("privacy metadata substitution error = %v", err)
			}
		})
	}
}

func TestDerivedV2EmbeddedKeyIsNotTrustAndAttackerTrustIsExplicit(t *testing.T) {
	artifact, result := derivedAttestationInputs(t)
	_, originalPrivate := generateKey(t)
	original, err := BuildWithDerivedSPDX(result, artifact.SPDX, artifact.ProvenanceCanonical, originalPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPrivate := generateKey(t)
	attackerPublic := publicKeyPEMForTest(t, attackerPrivate)
	attack := correctlyResignedDerivedBundle(t, result, artifact.SPDX, artifact.ProvenanceCanonical, attackerPrivate)

	report, err := Verify(attack, nil)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || report.SignatureValidity != "valid" || report.TrustDecision != "unknown" {
		t.Fatalf("embedded-only trust = %#v err=%v", report, err)
	}
	report, err = Verify(attack, original.PublicKeyPEM)
	if domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted || report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
		t.Fatalf("original trust against attacker = %#v err=%v", report, err)
	}
	report, err = Verify(attack, attackerPublic)
	if err != nil || report.SignatureValidity != "valid" || report.TrustDecision != "accepted" {
		t.Fatalf("explicit attacker trust = %#v err=%v", report, err)
	}
}

func TestEvaluateSBOMCurrentnessFreshStaleAndUnknown(t *testing.T) {
	artifact, _ := derivedAttestationInputs(t)
	historical := AcceptedDerivedClaims{Provenance: artifact.Provenance, SBOMDigest: spdx.Digest(artifact.SPDX)}
	status, report := EvaluateSBOMCurrentness(historical, &artifact, "")
	if status != SBOMCurrentnessFresh || report.Status != SBOMCurrentnessFresh || report.Reason != SBOMCurrentnessReasonNone {
		t.Fatalf("fresh = %q %#v", status, report)
	}
	changed := artifact
	changed.Provenance.DerivationInputDigest = "sha256:" + strings.Repeat("0", 64)
	status, report = EvaluateSBOMCurrentness(historical, &changed, "")
	if status != SBOMCurrentnessStale || report.Reason != SBOMCurrentnessReasonInputsChanged {
		t.Fatalf("stale = %q %#v", status, report)
	}
	status, report = EvaluateSBOMCurrentness(historical, nil, SBOMCurrentnessReasonSourceUnstable)
	if status != SBOMCurrentnessUnknown || report.Reason != SBOMCurrentnessReasonSourceUnstable {
		t.Fatalf("unknown = %q %#v", status, report)
	}
	status, report = EvaluateSBOMCurrentness(historical, nil, "attacker-controlled-reason")
	if status != SBOMCurrentnessUnknown || report.Reason != SBOMCurrentnessReasonDerivationFailed ||
		strings.Contains(report.Reason, "attacker") {
		t.Fatalf("unknown reason normalization = %q %#v", status, report)
	}
}

func correctlyResignedDerivedBundle(
	t *testing.T,
	result domain.VerificationResult,
	sbomJSON, provenanceJSON []byte,
	privateKey ed25519.PrivateKey,
) []byte {
	return correctlyResignedDerivedBundleWithMutation(
		t, result, sbomJSON, provenanceJSON, privateKey, nil, nil,
	)
}

func correctlyResignedDerivedBundleWithMutation(
	t *testing.T,
	result domain.VerificationResult,
	sbomJSON, provenanceJSON []byte,
	privateKey ed25519.PrivateKey,
	mutateManifest func(*Manifest),
	mutateStatement func(*Statement),
) []byte {
	t.Helper()
	verificationJSON := mustCanonical(t, result)
	publicKeyPEM, publicKeyDER, err := marshalPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	manifest := expectedManifestV2(verificationJSON, sbomJSON, provenanceJSON, publicKeyPEM)
	if mutateManifest != nil {
		mutateManifest(&manifest)
	}
	manifestJSON := mustCanonical(t, manifest)
	statement := expectedStatementV2(result, verificationJSON, sbomJSON, provenanceJSON, manifestJSON)
	if mutateStatement != nil {
		mutateStatement(&statement)
	}
	statementJSON := mustCanonical(t, statement)
	signature := ed25519.Sign(privateKey, pae(DSSEPayloadType, statementJSON))
	envelopeJSON := mustCanonical(t, Envelope{
		PayloadType: DSSEPayloadType, Payload: base64.StdEncoding.EncodeToString(statementJSON),
		Signatures: []DSSESignature{{KeyID: digestBytes(publicKeyDER), Sig: base64.StdEncoding.EncodeToString(signature)}},
	})
	bundle, err := buildCanonicalTarV2(map[string][]byte{
		attestationPath: statementJSON, manifestPath: manifestJSON,
		provenancePath: provenanceJSON, sbomPath: sbomJSON,
		verificationPath: verificationJSON, signaturePath: envelopeJSON,
		publicKeyPath: publicKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func cloneDerivedFiles(files map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(files))
	for name, content := range files {
		clone[name] = append([]byte(nil), content...)
	}
	return clone
}

func canonicalTarWithNamesForTest(t *testing.T, files map[string][]byte, names []string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, name := range names {
		content, ok := files[name]
		if !ok {
			t.Fatalf("test tar content %q missing", name)
		}
		header := &tar.Header{
			Name: name, Mode: 0o600, Uid: 0, Gid: 0, Size: int64(len(content)),
			ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func derivedAttestationInputs(t *testing.T) (spdx.DerivedArtifact, domain.VerificationResult) {
	t.Helper()
	directory := unlinkedTempDir(t)
	packageJSON := []byte(`{"dependencies":{"a":"1.0.0"},"name":"root","version":"1.0.0"}`)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
	lock := map[string]any{
		"name": "root", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "root", "version": "1.0.0", "dependencies": map[string]any{"a": "1.0.0"}},
			"node_modules/a": map[string]any{
				"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": integrity,
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
	return artifact, validDerivedVerificationResult(t, snapshot.TreeDigest)
}

func validDerivedVerificationResult(t *testing.T, treeDigest string) domain.VerificationResult {
	t.Helper()
	base := validResult(t, "inconclusive")
	source := domain.PlanSource{Identity: treeDigest, TreeDigest: treeDigest}
	result, err := verification.Build(verification.Input{
		RunID: base.RunID + "derived", VerificationID: base.VerificationID + "derived",
		Plan: domain.ResolvedPlan{
			SchemaVersion: base.Plan.ResolvedPlanSchemaVersion,
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "sbom", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
			Source: source, Scenario: base.Plan.Scenario, Environment: base.Plan.Environment,
			PlanDigest: base.Plan.PlanDigest, PolicyBundleDigest: base.Plan.PolicyBundleDigest,
			ObserverSet: observerNames(base.ObserverCoverage), RepeatCount: base.Plan.RepeatCount,
			SuccessThreshold: base.Plan.SuccessThreshold,
		},
		Runner: base.Runner, StartedAt: base.StartedAt, CompletedAt: base.CompletedAt,
		Observations: base.Observations, Assertions: base.Assertions, Errors: base.Errors,
		Requested: base.Repeats.Requested, Completed: base.Repeats.Completed,
		Matching: base.Repeats.Matching, SuccessThreshold: base.Plan.SuccessThreshold,
		Cleanup: base.Results.Cleanup, Resources: base.Resources,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustCanonicalDerived(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
