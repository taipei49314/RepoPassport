package attestation

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/spdx"
	"github.com/repopass/repopass/internal/verification"
	"github.com/repopass/repopass/schemas"
)

func TestSchema4OptionalSPDXBundleModelsAreDeterministicAndBound(t *testing.T) {
	_, privateKey := generateKey(t)
	publicKeyPEM := publicKeyPEMForTest(t, privateKey)

	withoutSBOM := validResult(t, "inconclusive")
	legacy, err := Build(withoutSBOM, privateKey)
	if err != nil {
		t.Fatalf("Build without SBOM: %v", err)
	}
	explicitNil, err := BuildWithSPDX(withoutSBOM, nil, privateKey)
	if err != nil {
		t.Fatalf("BuildWithSPDX nil: %v", err)
	}
	if !bytes.Equal(legacy.Bundle, explicitNil.Bundle) {
		t.Fatal("Build and BuildWithSPDX nil differ for the same schema-4 result and key")
	}
	if legacy.SBOMPresent || legacy.SBOMFormat != "" || legacy.SBOMDigest != "" {
		t.Fatalf("no-SBOM build metadata = %#v", legacy)
	}
	if got := tarEntryNames(t, legacy.Bundle); !equalStrings(got, bundlePaths(false)) {
		t.Fatalf("no-SBOM tar order = %#v, want %#v", got, bundlePaths(false))
	}

	withSBOM := validSBOMResult(t)
	raw := validSPDXBytes()
	first, err := BuildWithSPDX(withSBOM, raw, privateKey)
	if err != nil {
		t.Fatalf("BuildWithSPDX: %v", err)
	}
	second, err := BuildWithSPDX(withSBOM, raw, privateKey)
	if err != nil {
		t.Fatalf("second BuildWithSPDX: %v", err)
	}
	if !bytes.Equal(first.Bundle, second.Bundle) || first.BundleDigest != second.BundleDigest {
		t.Fatal("same result, SPDX input, and key produced different six-member bundle bytes")
	}
	if !first.SBOMPresent || first.SBOMFormat != spdx.Format || first.SBOMDigest == "" {
		t.Fatalf("SBOM build metadata = %#v", first)
	}
	if got := tarEntryNames(t, first.Bundle); !equalStrings(got, bundlePaths(true)) {
		t.Fatalf("SBOM tar order = %#v, want %#v", got, bundlePaths(true))
	}

	files := parsedFiles(t, first.Bundle)
	_, canonicalSBOM, canonicalErr := spdx.Canonicalize(raw)
	if canonicalErr != nil || !bytes.Equal(files[sbomPath], canonicalSBOM) {
		t.Fatalf("stored canonical SPDX derivative: %v", canonicalErr)
	}
	if first.SBOMDigest != digestBytes(canonicalSBOM) {
		t.Fatalf("SBOM digest = %q, want %q", first.SBOMDigest, digestBytes(canonicalSBOM))
	}
	var manifest Manifest
	mustJSON(t, files[manifestPath], &manifest)
	if len(manifest.Files) != 3 || manifest.Files[0].Path != verificationPath ||
		manifest.Files[1].Path != sbomPath || manifest.Files[2].Path != publicKeyPath ||
		manifest.Files[1].SHA256 != first.SBOMDigest || manifest.Files[1].Size != int64(len(canonicalSBOM)) {
		t.Fatalf("six-member manifest binding = %#v", manifest.Files)
	}
	var statement Statement
	mustJSON(t, files[attestationPath], &statement)
	if statement.Predicate.SBOM == nil || *statement.Predicate.SBOM != (PredicateSBOM{
		Format: spdx.Format, MediaType: spdx.MediaType, Path: sbomPath, Digest: first.SBOMDigest,
	}) {
		t.Fatalf("statement SBOM binding = %#v", statement.Predicate.SBOM)
	}

	report, verifyErr := Verify(first.Bundle, nil)
	assertErrorCode(t, verifyErr, domain.CodeAttestationUntrusted)
	if !report.SBOMPresent || report.SBOMFormat != spdx.Format || report.SBOMDigest != first.SBOMDigest ||
		report.SignatureValidity != "valid" || report.TrustDecision != "unknown" {
		t.Fatalf("untrusted SBOM report = %#v", report)
	}
	if report.OriginalResults != withSBOM.Results || report.OriginalResults.Evidence != domain.EvidenceUnsigned {
		t.Fatalf("SPDX attachment changed original verdicts: got %#v want %#v", report.OriginalResults, withSBOM.Results)
	}
	report, verifyErr = Verify(first.Bundle, publicKeyPEM)
	if verifyErr != nil || report.TrustDecision != "accepted" || report.SBOMDigest != first.SBOMDigest {
		t.Fatalf("trusted SBOM report = %#v err=%v", report, verifyErr)
	}

	if _, mismatchErr := Build(withSBOM, privateKey); domain.ErrorCodeOf(mismatchErr) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("missing selected SPDX code = %q: %v", domain.ErrorCodeOf(mismatchErr), mismatchErr)
	}
	if _, mismatchErr := BuildWithSPDX(withoutSBOM, raw, privateKey); domain.ErrorCodeOf(mismatchErr) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("unexpected unselected SPDX code = %q: %v", domain.ErrorCodeOf(mismatchErr), mismatchErr)
	}
}

func TestSPDXMemberTamperingAndCorrectlyResignedPrivacyUnsafeAttachment(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := BuildWithSPDX(validSBOMResult(t), validSPDXBytes(), privateKey)
	if err != nil {
		t.Fatalf("BuildWithSPDX: %v", err)
	}
	files := parsedFiles(t, built.Bundle)
	files[sbomPath] = append([]byte(nil), files[sbomPath]...)
	files[sbomPath][len(files[sbomPath])-2] ^= 1
	tampered, err := buildCanonicalTar(files, true)
	if err != nil {
		t.Fatalf("build directly tampered bundle: %v", err)
	}
	if _, verifyErr := Verify(tampered, nil); domain.ErrorCodeOf(verifyErr) != domain.CodeAttestationInvalid {
		t.Fatalf("direct SPDX tamper code = %q: %v", domain.ErrorCodeOf(verifyErr), verifyErr)
	}

	unsafeRaw := bytes.Replace(validSPDXBytes(), []byte("demo-sbom"), []byte("synthetic.user@example.invalid"), 1)
	_, unsafeCanonical, err := spdx.Canonicalize(unsafeRaw)
	if err != nil {
		t.Fatalf("privacy-unsafe document must remain profile-valid: %v", err)
	}
	attack := buildSPDXPrivacyAttackBundle(t, validSBOMResult(t), unsafeCanonical, privateKey)
	report, verifyErr := Verify(attack, []byte("intentionally not a trust key"))
	assertErrorCode(t, verifyErr, domain.CodeEvidencePrivacyBlocked)
	if report.TrustDecision != "" {
		t.Fatalf("privacy-unsafe SPDX reached trust evaluation: %#v", report)
	}
	encoded, _ := json.Marshal(verifyErr)
	if bytes.Contains(encoded, []byte("synthetic.user@example.invalid")) {
		t.Fatalf("privacy error echoed attachment content: %s", encoded)
	}
}

func TestSixMemberBundleRejectsIndependentManifestPredicateDSSEAndModelTampering(t *testing.T) {
	_, privateKey := generateKey(t)
	result := validSBOMResult(t)
	built, err := BuildWithSPDX(result, validSPDXBytes(), privateKey)
	if err != nil {
		t.Fatalf("BuildWithSPDX: %v", err)
	}
	withoutSBOM, err := Build(validResult(t, "inconclusive"), privateKey)
	if err != nil {
		t.Fatalf("Build without SPDX: %v", err)
	}
	fiveFiles := parsedFiles(t, withoutSBOM.Bundle)
	originalSBOM := append([]byte(nil), parsedFiles(t, built.Bundle)[sbomPath]...)

	rebindMutatedSPDX := func(t *testing.T, files map[string][]byte, updateEnvelopePayload bool) {
		t.Helper()
		mutated := bytes.Replace(files[sbomPath], []byte("demo-sbom"), []byte("demo-sbom-2"), 1)
		_, canonical, canonicalErr := spdx.Canonicalize(mutated)
		if canonicalErr != nil || bytes.Equal(canonical, files[sbomPath]) {
			t.Fatalf("prepare valid changed SPDX: %v", canonicalErr)
		}
		files[sbomPath] = canonical
		files[manifestPath] = mustCanonical(t, expectedManifest(
			files[verificationPath], files[sbomPath], files[publicKeyPath],
		))
		files[attestationPath] = mustCanonical(t, expectedStatement(
			result, files[verificationPath], files[sbomPath], files[manifestPath],
		))
		if updateEnvelopePayload {
			var envelope Envelope
			mustJSON(t, files[signaturePath], &envelope)
			envelope.Payload = base64.StdEncoding.EncodeToString(files[attestationPath])
			files[signaturePath] = mustCanonical(t, envelope)
		}
	}

	tests := map[string]func(*testing.T, map[string][]byte){
		"manifest sbom digest": func(t *testing.T, files map[string][]byte) {
			var manifest Manifest
			mustJSON(t, files[manifestPath], &manifest)
			manifest.Files[1].SHA256 = digestOf('0')
			files[manifestPath] = mustCanonical(t, manifest)
		},
		"manifest sbom size": func(t *testing.T, files map[string][]byte) {
			var manifest Manifest
			mustJSON(t, files[manifestPath], &manifest)
			manifest.Files[1].Size++
			files[manifestPath] = mustCanonical(t, manifest)
		},
		"manifest protected order": func(t *testing.T, files map[string][]byte) {
			var manifest Manifest
			mustJSON(t, files[manifestPath], &manifest)
			manifest.Files[0], manifest.Files[1] = manifest.Files[1], manifest.Files[0]
			files[manifestPath] = mustCanonical(t, manifest)
		},
		"predicate sbom format": func(t *testing.T, files map[string][]byte) {
			var statement Statement
			mustJSON(t, files[attestationPath], &statement)
			statement.Predicate.SBOM.Format = "SPDX-2.2"
			files[attestationPath] = mustCanonical(t, statement)
		},
		"predicate sbom media type": func(t *testing.T, files map[string][]byte) {
			var statement Statement
			mustJSON(t, files[attestationPath], &statement)
			statement.Predicate.SBOM.MediaType = "application/json"
			files[attestationPath] = mustCanonical(t, statement)
		},
		"predicate sbom path": func(t *testing.T, files map[string][]byte) {
			var statement Statement
			mustJSON(t, files[attestationPath], &statement)
			statement.Predicate.SBOM.Path = "payload/other.json"
			files[attestationPath] = mustCanonical(t, statement)
		},
		"predicate sbom digest": func(t *testing.T, files map[string][]byte) {
			var statement Statement
			mustJSON(t, files[attestationPath], &statement)
			statement.Predicate.SBOM.Digest = digestOf('0')
			files[attestationPath] = mustCanonical(t, statement)
		},
		"predicate sbom absent": func(t *testing.T, files map[string][]byte) {
			var statement Statement
			mustJSON(t, files[attestationPath], &statement)
			statement.Predicate.SBOM = nil
			files[attestationPath] = mustCanonical(t, statement)
		},
		"predicate sbom null": func(t *testing.T, files map[string][]byte) {
			var statement map[string]any
			mustJSON(t, files[attestationPath], &statement)
			statement["predicate"].(map[string]any)["sbom"] = nil
			files[attestationPath] = mustCanonical(t, statement)
		},
		"stale DSSE payload after rebound SPDX": func(t *testing.T, files map[string][]byte) {
			rebindMutatedSPDX(t, files, false)
		},
		"stale DSSE signature after rebound payload": func(t *testing.T, files map[string][]byte) {
			rebindMutatedSPDX(t, files, true)
		},
		"six member interpreted as five": func(t *testing.T, files map[string][]byte) {
			delete(files, sbomPath)
		},
		"five member interpreted as six": func(t *testing.T, files map[string][]byte) {
			clear(files)
			for name, content := range fiveFiles {
				files[name] = append([]byte(nil), content...)
			}
			files[sbomPath] = append([]byte(nil), originalSBOM...)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			files := parsedFiles(t, built.Bundle)
			mutate(t, files)
			bundle, buildErr := buildCanonicalTar(files)
			if buildErr != nil {
				t.Fatalf("construct canonical tamper model: %v", buildErr)
			}
			if _, verifyErr := Verify(bundle, nil); domain.ErrorCodeOf(verifyErr) != domain.CodeAttestationInvalid {
				t.Fatalf("tamper code = %q, want %q: %v", domain.ErrorCodeOf(verifyErr), domain.CodeAttestationInvalid, verifyErr)
			}
		})
	}
}

func TestRoundTripPreservesThreeOriginalVerdicts(t *testing.T) {
	_, privateKey := generateKey(t)
	for _, test := range []struct {
		name    string
		variant string
	}{
		{name: "verified", variant: "verified"},
		{name: "nonconforming", variant: "nonconforming"},
		{name: "inconclusive", variant: "inconclusive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := validResult(t, test.variant)
			built, err := Build(result, privateKey)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			publicKeyPEM := publicKeyPEMForTest(t, privateKey)
			report, err := Verify(built.Bundle, publicKeyPEM)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if report.ArtifactIntegrity != "valid" ||
				report.SignatureValidity != "valid" ||
				report.TrustDecision != "accepted" ||
				report.FreshnessEvaluation != "not-evaluated" {
				t.Fatalf("unexpected verification report: %#v", report)
			}
			if report.OriginalResults != result.Results {
				t.Fatalf("original results changed: got %#v, want %#v", report.OriginalResults, result.Results)
			}
			if report.OriginalResults.Evidence != domain.EvidenceUnsigned {
				t.Fatalf("evidence = %q, want unsigned", report.OriginalResults.Evidence)
			}
			if built.ManifestDigest == "" || built.BundleDigest == "" || built.SignerKeyID == "" {
				t.Fatalf("build metadata is incomplete: %#v", built)
			}
		})
	}
}

func TestBuildIsDeterministicForSameResultAndKey(t *testing.T) {
	_, privateKey := generateKey(t)
	result := validResult(t, "inconclusive")
	first, err := Build(result, privateKey)
	if err != nil {
		t.Fatalf("first Build: %v", err)
	}
	second, err := Build(result, privateKey)
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if !bytes.Equal(first.Bundle, second.Bundle) {
		t.Fatal("same result and Ed25519 key produced different bundle bytes")
	}
	if first.BundleDigest != second.BundleDigest || first.ManifestDigest != second.ManifestDigest {
		t.Fatal("deterministic build metadata changed")
	}
}

func TestBuildAndVerificationReportCanonicalBundleAndPublicKeyDigests(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "inconclusive"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	wantPublicPEM := publicKeyPEMForTest(t, privateKey)
	if !bytes.Equal(built.PublicKeyPEM, wantPublicPEM) {
		t.Fatal("BuildResult public key is not canonical Ed25519 SPKI PEM")
	}
	_, publicDER, err := parsePublicKey(wantPublicPEM)
	if err != nil {
		t.Fatalf("parse canonical public key: %v", err)
	}
	if built.BundleDigest != digestBytes(built.Bundle) ||
		built.PublicKeyDigest != digestBytes(wantPublicPEM) ||
		built.SignerKeyID != digestBytes(publicDER) {
		t.Fatalf("build digests do not bind their documented byte domains: %#v", built)
	}
	if built.PublicKeyDigest == built.SignerKeyID {
		t.Fatal("PEM companion digest unexpectedly equals the DER signer identity")
	}

	report, err := Verify(built.Bundle, wantPublicPEM)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.BundleDigest != built.BundleDigest ||
		report.PublicKeyDigest != built.PublicKeyDigest ||
		report.SignerKeyID != built.SignerKeyID ||
		report.TrustDecision != "accepted" {
		t.Fatalf("verification report digest/trust fields = %#v", report)
	}
}

func TestExpectedBundleDigestValidationMatchingAndMismatch(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "inconclusive"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := ValidateExpectedBundleDigest(""); domain.ErrorCodeOf(err) != domain.CodeManifestInvalid {
		t.Fatalf("empty explicit digest code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeManifestInvalid, err)
	}
	if err := ValidateExpectedBundleDigest(built.BundleDigest); err != nil {
		t.Fatalf("canonical expected digest: %v", err)
	}
	for _, malformed := range []string{
		"sha256",
		"SHA256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
	} {
		if err := ValidateExpectedBundleDigest(malformed); domain.ErrorCodeOf(err) != domain.CodeManifestInvalid {
			t.Fatalf("malformed %q code = %q, want %q: %v", malformed, domain.ErrorCodeOf(err), domain.CodeManifestInvalid, err)
		}
	}
	if err := CheckExpectedBundleDigest(built.Bundle, built.BundleDigest); err != nil {
		t.Fatalf("matching digest: %v", err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	if wrong == built.BundleDigest {
		wrong = "sha256:" + strings.Repeat("1", 64)
	}
	err = CheckExpectedBundleDigest(built.Bundle, wrong)
	if domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("wrong digest code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceDigestMismatch, err)
	}
	typed, ok := err.(*domain.Error)
	if !ok || typed.Details["expectedBundleDigest"] != wrong ||
		typed.Details["actualBundleDigest"] != built.BundleDigest {
		t.Fatalf("wrong digest details = %#v", err)
	}

	tampered := append([]byte(nil), built.Bundle...)
	tampered[len(tampered)-1] ^= 1
	if err := CheckExpectedBundleDigest(tampered, digestBytes(tampered)); err != nil {
		t.Fatalf("recomputed tampered transport digest: %v", err)
	}
	if _, err := Verify(tampered, built.PublicKeyPEM); domain.ErrorCodeOf(err) != domain.CodeAttestationInvalid {
		t.Fatalf("tamper after matching transport digest code = %q: %v", domain.ErrorCodeOf(err), err)
	}
}

func TestTrustDecisionIsSeparateFromSignatureValidity(t *testing.T) {
	_, privateKey := generateKey(t)
	_, otherPrivateKey := generateKey(t)
	result := validResult(t, "verified")
	built, err := Build(result, privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	report, err := Verify(built.Bundle, nil)
	assertErrorCode(t, err, domain.CodeAttestationUntrusted)
	if report.SignatureValidity != "valid" || report.TrustDecision != "unknown" {
		t.Fatalf("no-trust report = %#v", report)
	}
	assertUntrustedDetails(t, err, "unknown")

	otherPublicKey := publicKeyPEMForTest(t, otherPrivateKey)
	report, err = Verify(built.Bundle, otherPublicKey)
	assertErrorCode(t, err, domain.CodeAttestationUntrusted)
	if report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
		t.Fatalf("mismatch report = %#v", report)
	}
	assertUntrustedDetails(t, err, "rejected")

	publicKey := publicKeyPEMForTest(t, privateKey)
	report, err = Verify(built.Bundle, publicKey)
	if err != nil {
		t.Fatalf("trusted Verify: %v", err)
	}
	if report.TrustDecision != "accepted" {
		t.Fatalf("trusted decision = %q", report.TrustDecision)
	}
}

func TestEmbeddedSelfSignedKeyAndKeyIDTextNeverEstablishTrust(t *testing.T) {
	_, legitimatePrivateKey := generateKey(t)
	_, attackerPrivateKey := generateKey(t)
	attackerBundle, err := Build(validResult(t, "verified"), attackerPrivateKey)
	if err != nil {
		t.Fatalf("build attacker-self-signed bundle: %v", err)
	}

	report, err := Verify(attackerBundle.Bundle, nil)
	assertErrorCode(t, err, domain.CodeAttestationUntrusted)
	if report.SignatureValidity != "valid" || report.TrustDecision != "unknown" {
		t.Fatalf("embedded self-signed key report = %#v", report)
	}

	report, err = Verify(attackerBundle.Bundle, publicKeyPEMForTest(t, legitimatePrivateKey))
	assertErrorCode(t, err, domain.CodeAttestationUntrusted)
	if report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
		t.Fatalf("attacker bundle with legitimate trust report = %#v", report)
	}

	report, err = Verify(attackerBundle.Bundle, []byte(attackerBundle.SignerKeyID))
	assertErrorCode(t, err, domain.CodeAttestationUntrusted)
	if report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
		t.Fatalf("key-id-only trust report = %#v", report)
	}
}

func TestCrossBundleProtectedFileSubstitutionIsInvalid(t *testing.T) {
	_, firstKey := generateKey(t)
	_, secondKey := generateKey(t)
	first, err := Build(validResult(t, "verified"), firstKey)
	if err != nil {
		t.Fatalf("build first bundle: %v", err)
	}
	second, err := Build(validResult(t, "nonconforming"), secondKey)
	if err != nil {
		t.Fatalf("build second bundle: %v", err)
	}
	firstFiles := parsedFiles(t, first.Bundle)
	secondFiles := parsedFiles(t, second.Bundle)
	for _, test := range []struct {
		name  string
		paths []string
	}{
		{name: "attestation", paths: []string{attestationPath}},
		{name: "manifest", paths: []string{manifestPath}},
		{name: "verification", paths: []string{verificationPath}},
		{name: "signature", paths: []string{signaturePath}},
		{name: "public key", paths: []string{publicKeyPath}},
		{name: "attestation and signature", paths: []string{attestationPath, signaturePath}},
		{name: "all protected files except public key", paths: []string{attestationPath, manifestPath, verificationPath, signaturePath}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mixed := make(map[string][]byte, len(firstFiles))
			for name, content := range firstFiles {
				mixed[name] = append([]byte(nil), content...)
			}
			for _, path := range test.paths {
				mixed[path] = append([]byte(nil), secondFiles[path]...)
			}
			bundle, buildErr := buildCanonicalTar(mixed)
			if buildErr != nil {
				t.Fatalf("build substituted bundle: %v", buildErr)
			}
			_, verifyErr := Verify(bundle, nil)
			assertErrorCode(t, verifyErr, domain.CodeAttestationInvalid)
		})
	}

	report, err := Verify(second.Bundle, publicKeyPEMForTest(t, firstKey))
	assertErrorCode(t, err, domain.CodeAttestationUntrusted)
	if report.SignatureValidity != "valid" || report.TrustDecision != "rejected" {
		t.Fatalf("complete bundle substitution trust report = %#v", report)
	}
}

func TestEnvelopeRequiresExactlyOneSignature(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, count := range []int{0, 2} {
		t.Run(fmt.Sprintf("signature count %d", count), func(t *testing.T) {
			files := parsedFiles(t, built.Bundle)
			var envelope Envelope
			mustJSON(t, files[signaturePath], &envelope)
			original := envelope.Signatures[0]
			envelope.Signatures = make([]DSSESignature, count)
			for index := range envelope.Signatures {
				envelope.Signatures[index] = original
			}
			files[signaturePath] = mustCanonical(t, envelope)
			mutated, buildErr := buildCanonicalTar(files)
			if buildErr != nil {
				t.Fatalf("build signature-count bundle: %v", buildErr)
			}
			_, verifyErr := Verify(mutated, nil)
			assertErrorCode(t, verifyErr, domain.CodeAttestationInvalid)
		})
	}
}

func TestBuildRejectsIntegritySchemaAndPrivateHalfFailures(t *testing.T) {
	_, privateKey := generateKey(t)

	tampered := validResult(t, "verified")
	tampered.Subject.TreeDigest = digestOf('9')
	if _, err := Build(tampered, privateKey); domain.ErrorCodeOf(err) != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("tampered integrity code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceDigestMismatch, err)
	}

	schemaInvalid := validResultWithSourceIdentity(t, "sha256:short")
	if _, err := Build(schemaInvalid, privateKey); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("schema-invalid code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
	}

	malformedKey := append(ed25519.PrivateKey(nil), privateKey...)
	malformedKey[len(malformedKey)-1] ^= 0xff
	if _, err := Build(validResult(t, "verified"), malformedKey); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("inconsistent-key code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeSigningFailed, err)
	}
}

func TestBuildPrivacyGatePrecedesSigningAndReportsPassedMetadata(t *testing.T) {
	_, privateKey := generateKey(t)
	valid := validResult(t, "verified")
	built, err := Build(valid, privateKey)
	if err != nil {
		t.Fatalf("Build valid: %v", err)
	}
	if built.PrivacyProfile != "minimal-public" || built.PrivacyPolicy != "minimal-public-v1alpha3" ||
		built.PrivacyRulesetDigest == "" || built.PrivacyEvaluation != "passed" {
		t.Fatalf("privacy build metadata = %#v", built)
	}

	blocked := rebuildResultWithPrivacyMarker(t, valid, "synthetic.user@example.invalid")
	if schemaErr := schemas.ValidateVerificationJSON(mustCanonical(t, blocked)); schemaErr != nil {
		t.Fatalf("blocked schema: %v", schemaErr)
	}
	_, err = Build(blocked, nil)
	assertErrorCode(t, err, domain.CodeEvidencePrivacyBlocked)
	encoded, _ := json.Marshal(err)
	if bytes.Contains(encoded, []byte("synthetic.user@example.invalid")) {
		t.Fatalf("privacy error echoed blocked value: %s", encoded)
	}
}

func TestVerifierRejectsCorrectlyResignedPrivacyBlockedBundleBeforeTrust(t *testing.T) {
	_, privateKey := generateKey(t)
	blocked := rebuildResultWithPrivacyMarker(t, validResult(t, "verified"), "synthetic.user@example.invalid")
	bundle := buildPrivacyAttackBundle(t, blocked, privateKey)
	report, err := Verify(bundle, []byte("not a trust key"))
	assertErrorCode(t, err, domain.CodeEvidencePrivacyBlocked)
	if report.TrustDecision != "" {
		t.Fatalf("privacy-blocked bundle acquired trust decision: %#v", report)
	}

	files := parsedFiles(t, bundle)
	var envelope Envelope
	mustJSON(t, files[signaturePath], &envelope)
	signature, decodeErr := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	signature[0] ^= 1
	envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
	files[signaturePath] = mustCanonical(t, envelope)
	tampered, buildErr := buildCanonicalTar(files)
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	_, err = Verify(tampered, nil)
	assertErrorCode(t, err, domain.CodeAttestationInvalid)
}

func rebuildResultWithPrivacyMarker(t *testing.T, base domain.VerificationResult, marker string) domain.VerificationResult {
	t.Helper()
	errorsList := append([]*domain.Error(nil), base.Errors...)
	errorsList = append(errorsList, domain.NewError(domain.CodeInternal, domain.SeverityHigh, marker))
	observerSet := make([]string, 0, len(base.ObserverCoverage))
	for _, coverage := range base.ObserverCoverage {
		observerSet = append(observerSet, coverage.Observer)
	}
	result, err := verification.Build(verification.Input{
		RunID: base.RunID + "privacy", VerificationID: base.VerificationID + "privacy",
		Plan: domain.ResolvedPlan{SchemaVersion: base.Plan.ResolvedPlanSchemaVersion,
			Evidence: base.Plan.Evidence, Source: base.Subject, Scenario: base.Plan.Scenario,
			Environment: base.Plan.Environment, PlanDigest: base.Plan.PlanDigest,
			PolicyBundleDigest: base.Plan.PolicyBundleDigest, ObserverSet: observerSet,
			RepeatCount: base.Plan.RepeatCount, SuccessThreshold: base.Plan.SuccessThreshold},
		Runner: base.Runner, StartedAt: base.StartedAt, CompletedAt: base.CompletedAt,
		Observations: base.Observations, Assertions: base.Assertions, Errors: errorsList,
		Requested: base.Repeats.Requested, Completed: base.Repeats.Completed,
		Matching: base.Repeats.Matching, SuccessThreshold: base.Plan.SuccessThreshold,
		Cleanup: base.Results.Cleanup, Resources: base.Resources,
	})
	if err != nil {
		t.Fatalf("rebuild privacy result: %v", err)
	}
	return result
}

func buildPrivacyAttackBundle(t *testing.T, result domain.VerificationResult, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	verificationJSON := mustCanonical(t, result)
	publicKeyPEM, publicKeyDER, err := marshalPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON := mustCanonical(t, expectedManifest(verificationJSON, publicKeyPEM))
	statementJSON := mustCanonical(t, expectedStatement(result, verificationJSON, manifestJSON))
	envelopeJSON := mustCanonical(t, Envelope{PayloadType: DSSEPayloadType,
		Payload: base64.StdEncoding.EncodeToString(statementJSON), Signatures: []DSSESignature{{
			KeyID: digestBytes(publicKeyDER), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, pae(DSSEPayloadType, statementJSON))),
		}}})
	bundle, err := buildCanonicalTar(map[string][]byte{attestationPath: statementJSON, manifestPath: manifestJSON,
		verificationPath: verificationJSON, signaturePath: envelopeJSON, publicKeyPath: publicKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func buildSPDXPrivacyAttackBundle(
	t *testing.T,
	result domain.VerificationResult,
	sbomJSON []byte,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	verificationJSON := mustCanonical(t, result)
	publicKeyPEM, publicKeyDER, err := marshalPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON := mustCanonical(t, expectedManifest(verificationJSON, sbomJSON, publicKeyPEM))
	statementJSON := mustCanonical(t, expectedStatement(result, verificationJSON, sbomJSON, manifestJSON))
	envelopeJSON := mustCanonical(t, Envelope{PayloadType: DSSEPayloadType,
		Payload: base64.StdEncoding.EncodeToString(statementJSON), Signatures: []DSSESignature{{
			KeyID: digestBytes(publicKeyDER), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, pae(DSSEPayloadType, statementJSON))),
		}}})
	bundle, err := buildCanonicalTar(map[string][]byte{
		attestationPath: statementJSON, manifestPath: manifestJSON, verificationPath: verificationJSON,
		sbomPath: sbomJSON, signaturePath: envelopeJSON, publicKeyPath: publicKeyPEM,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestProtectedContentAndSignatureTamperingIsInvalid(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*testing.T, map[string][]byte)
	}{
		{
			name: "verification payload",
			mutate: func(t *testing.T, files map[string][]byte) {
				files[verificationPath] = append(files[verificationPath], ' ')
			},
		},
		{
			name: "public key",
			mutate: func(t *testing.T, files map[string][]byte) {
				files[publicKeyPath] = append([]byte(nil), files[publicKeyPath]...)
				files[publicKeyPath][20] ^= 1
			},
		},
		{
			name: "manifest privacy profile",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Manifest
				mustJSON(t, files[manifestPath], &value)
				value.PrivacyProfile = "other"
				files[manifestPath] = mustCanonical(t, value)
			},
		},
		{
			name: "statement subject",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Statement
				mustJSON(t, files[attestationPath], &value)
				value.Subject[0].Digest.SHA256 = strings.Repeat("0", 64)
				files[attestationPath] = mustCanonical(t, value)
			},
		},
		{
			name: "statement predicate",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Statement
				mustJSON(t, files[attestationPath], &value)
				value.Predicate.RunID = "run_substituted"
				files[attestationPath] = mustCanonical(t, value)
			},
		},
		{
			name: "envelope key id",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Envelope
				mustJSON(t, files[signaturePath], &value)
				value.Signatures[0].KeyID = "sha256:" + strings.Repeat("0", 64)
				files[signaturePath] = mustCanonical(t, value)
			},
		},
		{
			name: "signature bytes",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Envelope
				mustJSON(t, files[signaturePath], &value)
				signature, decodeErr := base64.StdEncoding.DecodeString(value.Signatures[0].Sig)
				if decodeErr != nil {
					t.Fatalf("decode signature: %v", decodeErr)
				}
				signature[0] ^= 1
				value.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
				files[signaturePath] = mustCanonical(t, value)
			},
		},
		{
			name: "envelope payload",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Envelope
				mustJSON(t, files[signaturePath], &value)
				value.Payload = base64.StdEncoding.EncodeToString([]byte("{}"))
				files[signaturePath] = mustCanonical(t, value)
			},
		},
		{
			name: "envelope payload type",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value Envelope
				mustJSON(t, files[signaturePath], &value)
				value.PayloadType = "application/json"
				files[signaturePath] = mustCanonical(t, value)
			},
		},
		{
			name: "algorithm confusion field",
			mutate: func(t *testing.T, files map[string][]byte) {
				var value map[string]any
				mustJSON(t, files[signaturePath], &value)
				signatures := value["signatures"].([]any)
				signatures[0].(map[string]any)["alg"] = "EdDSA"
				files[signaturePath] = mustCanonical(t, value)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := parsedFiles(t, built.Bundle)
			test.mutate(t, files)
			mutated, buildErr := buildCanonicalTar(files)
			if buildErr != nil {
				t.Fatalf("rebuild tampered bundle: %v", buildErr)
			}
			_, verifyErr := Verify(mutated, nil)
			assertErrorCode(t, verifyErr, domain.CodeAttestationInvalid)
		})
	}
}

func TestStrictJSONRejectsDuplicateUnknownNonCanonicalAndInvalidUTF8(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "duplicate key",
			mutate: func(raw []byte) []byte {
				return append([]byte(`{"schemaVersion":"1",`), raw[1:]...)
			},
		},
		{
			name: "unknown key",
			mutate: func(raw []byte) []byte {
				var value map[string]any
				if err := json.Unmarshal(raw, &value); err != nil {
					panic(err)
				}
				value["unknown"] = true
				encoded, err := canonicaljson.Marshal(value)
				if err != nil {
					panic(err)
				}
				return encoded
			},
		},
		{
			name:   "noncanonical whitespace",
			mutate: func(raw []byte) []byte { return append(raw, ' ') },
		},
		{
			name: "invalid utf8",
			mutate: func(raw []byte) []byte {
				copyRaw := append([]byte(nil), raw...)
				copyRaw[len(copyRaw)/2] = 0xff
				return copyRaw
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := parsedFiles(t, built.Bundle)
			files[manifestPath] = test.mutate(files[manifestPath])
			mutated, buildErr := buildCanonicalTar(files)
			if buildErr != nil {
				t.Fatalf("rebuild JSON mutation: %v", buildErr)
			}
			_, verifyErr := Verify(mutated, nil)
			assertErrorCode(t, verifyErr, domain.CodeAttestationInvalid)
		})
	}
}

func TestTarAllowlistHeadersPathsLimitsAndCanonicalBytes(t *testing.T) {
	_, privateKey := generateKey(t)
	built, err := Build(validResult(t, "verified"), privateKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	files := parsedFiles(t, built.Bundle)
	base := customEntries(files)
	tests := []struct {
		name   string
		bundle func(*testing.T) []byte
	}{
		{
			name:   "missing entry",
			bundle: func(t *testing.T) []byte { return writeCustomTar(t, base[:4], nil) },
		},
		{
			name: "extra entry",
			bundle: func(t *testing.T) []byte {
				entries := append(cloneEntries(base), testTarEntry{name: "extra.json", content: []byte("{}")})
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name: "duplicate entry",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[1].name = entries[0].name
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name: "casefold collision",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[1].name = "Attestation.json"
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name: "wrong order",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0], entries[1] = entries[1], entries[0]
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name: "noncanonical mode",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0].mode = 0o644
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name: "non-ustar format",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0].format = tar.FormatGNU
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name: "pax format",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0].format = tar.FormatPAX
				entries[0].paxRecords = map[string]string{"REPOPASS.test": "noncanonical"}
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name:   "trailing data",
			bundle: func(t *testing.T) []byte { return append(append([]byte(nil), built.Bundle...), 'x') },
		},
		{
			name:   "trailing zero block",
			bundle: func(t *testing.T) []byte { return append(append([]byte(nil), built.Bundle...), make([]byte, 512)...) },
		},
		{
			name: "concatenated second archive",
			bundle: func(t *testing.T) []byte {
				second := writeCustomTar(t, base, nil)
				return append(append([]byte(nil), built.Bundle...), second...)
			},
		},
		{
			name: "nonzero entry padding",
			bundle: func(t *testing.T) []byte {
				mutated := append([]byte(nil), built.Bundle...)
				paddingOffset := 512 + len(files[attestationPath])
				if paddingOffset%512 == 0 {
					t.Fatal("attestation unexpectedly has no tar padding byte")
				}
				mutated[paddingOffset] = 1
				return mutated
			},
		},
		{
			name: "entry limit",
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0].content = bytes.Repeat([]byte{'x'}, MaxJSONBytes+1)
				return writeCustomTar(t, entries, nil)
			},
		},
		{
			name:   "bundle limit",
			bundle: func(t *testing.T) []byte { return make([]byte, MaxBundleBytes+1) },
		},
	}
	for _, attack := range []string{
		"../attestation.json",
		"/attestation.json",
		"C:/attestation.json",
		"attestation.json:ads",
		`payload\verification.json`,
	} {
		attack := attack
		tests = append(tests, struct {
			name   string
			bundle func(*testing.T) []byte
		}{
			name: "path " + attack,
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0].name = attack
				return writeCustomTar(t, entries, nil)
			},
		})
	}
	for _, special := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeDir} {
		special := special
		tests = append(tests, struct {
			name   string
			bundle func(*testing.T) []byte
		}{
			name: fmt.Sprintf("special type %d", special),
			bundle: func(t *testing.T) []byte {
				entries := cloneEntries(base)
				entries[0].typeflag = special
				if special == tar.TypeSymlink || special == tar.TypeLink {
					entries[0].linkname = "target"
					entries[0].content = nil
				}
				if special == tar.TypeDir || special == tar.TypeChar || special == tar.TypeBlock || special == tar.TypeFifo {
					entries[0].content = nil
				}
				return writeCustomTar(t, entries, nil)
			},
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, verifyErr := Verify(test.bundle(t), nil)
			assertErrorCode(t, verifyErr, domain.CodeAttestationInvalid)
		})
	}
}

type testTarEntry struct {
	name       string
	content    []byte
	mode       int64
	format     tar.Format
	typeflag   byte
	linkname   string
	paxRecords map[string]string
}

func customEntries(files map[string][]byte) []testTarEntry {
	paths := fixedBundlePaths()
	entries := make([]testTarEntry, 0, len(paths))
	for _, name := range paths {
		entries = append(entries, testTarEntry{
			name: name, content: append([]byte(nil), files[name]...), mode: 0o600,
			format: tar.FormatUSTAR, typeflag: tar.TypeReg,
		})
	}
	return entries
}

func cloneEntries(values []testTarEntry) []testTarEntry {
	result := append([]testTarEntry(nil), values...)
	for index := range result {
		result[index].content = append([]byte(nil), result[index].content...)
		if result[index].paxRecords != nil {
			result[index].paxRecords = make(map[string]string, len(result[index].paxRecords))
			for key, value := range values[index].paxRecords {
				result[index].paxRecords[key] = value
			}
		}
	}
	return result
}

func writeCustomTar(t *testing.T, entries []testTarEntry, trailing []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Mode: entry.mode, Size: int64(len(entry.content)),
			Uid: 0, Gid: 0, ModTime: time.Unix(0, 0).UTC(), Typeflag: entry.typeflag,
			Linkname: entry.linkname, Format: entry.format, PAXRecords: entry.paxRecords,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write custom header %q: %v", entry.name, err)
		}
		if len(entry.content) > 0 {
			if _, err := writer.Write(entry.content); err != nil {
				t.Fatalf("write custom content %q: %v", entry.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close custom tar: %v", err)
	}
	output.Write(trailing)
	return output.Bytes()
}

func parsedFiles(t *testing.T, bundle []byte) map[string][]byte {
	t.Helper()
	files, err := parseCanonicalTar(bundle)
	if err != nil {
		t.Fatalf("parse valid bundle: %v", err)
	}
	result := make(map[string][]byte, len(files))
	for name, content := range files {
		result[name] = append([]byte(nil), content...)
	}
	return result
}

func tarEntryNames(t *testing.T, bundle []byte) []string {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(bundle))
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("read tar names: %v", err)
		}
		names = append(names, header.Name)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			t.Fatalf("consume tar member %q: %v", header.Name, err)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(value)
	if err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	return raw
}

func mustJSON(t *testing.T, raw []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return publicKey, privateKey
}

func publicKeyPEMForTest(t *testing.T, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("private key did not produce Ed25519 public key")
	}
	encoded, _, err := marshalPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return encoded
}

func validResult(t *testing.T, variant string) domain.VerificationResult {
	t.Helper()
	return buildResult(t, variant, digestOf('1'))
}

func validSBOMResult(t *testing.T) domain.VerificationResult {
	t.Helper()
	base := validResult(t, "inconclusive")
	result, err := verification.Build(verification.Input{
		RunID: base.RunID + "sbom", VerificationID: base.VerificationID + "sbom",
		Plan: domain.ResolvedPlan{
			SchemaVersion: base.Plan.ResolvedPlanSchemaVersion,
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "sbom", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
			Source: base.Subject, Scenario: base.Plan.Scenario, Environment: base.Plan.Environment,
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
		t.Fatalf("build SBOM-selected verification: %v", err)
	}
	return result
}

func observerNames(coverage []domain.ObserverCoverage) []string {
	result := make([]string, 0, len(coverage))
	for _, item := range coverage {
		result = append(result, item.Observer)
	}
	return result
}

func validSPDXBytes() []byte {
	return []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"demo","licenseDeclared":"NOASSERTION","licenseConcluded":"NOASSERTION","filesAnalyzed":false,"downloadLocation":"NOASSERTION","copyrightText":"NOASSERTION","SPDXID":"SPDXRef-demo"}],"name":"demo-sbom","documentNamespace":"https://example.invalid/spdx/demo","documentDescribes":["SPDXRef-demo"],"dataLicense":"CC0-1.0","creationInfo":{"creators":["Tool: RepoPassport synthetic fixture"],"created":"2026-08-01T00:00:00Z"},"SPDXID":"SPDXRef-DOCUMENT"}`)
}

func validResultWithSourceIdentity(t *testing.T, identity string) domain.VerificationResult {
	t.Helper()
	return buildResult(t, "verified", identity)
}

func buildResult(t *testing.T, variant, identity string) domain.VerificationResult {
	t.Helper()
	started := time.Date(2026, time.July, 31, 1, 2, 3, 0, time.UTC)
	cleanup := domain.CleanupClean
	observerSet := []string{"network-enforcement"}
	runner := domain.RunnerFeatures{
		Backend:       "test",
		Available:     true,
		ControllerOS:  "test-os",
		WorkloadOS:    "linux",
		Rootless:      "yes",
		NetworkDeny:   true,
		EngineVersion: "test-1",
	}
	if variant == "nonconforming" {
		cleanup = domain.CleanupUndeclaredResidue
	}
	if variant == "inconclusive" {
		observerSet = []string{"filesystem-write"}
		runner.FilesystemWriteObservation = "best-effort"
	}
	result, err := verification.Build(verification.Input{
		RunID:          "run_attestation",
		VerificationID: "vrf_attestation",
		Plan: domain.ResolvedPlan{
			SchemaVersion: "4",
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
			Source: domain.PlanSource{
				Identity: identity, Commit: strings.Repeat("a", 40), TreeDigest: digestOf('2'),
			},
			Scenario: "quickstart", Environment: "linux-node",
			PlanDigest: digestOf('3'), PolicyBundleDigest: digestOf('4'),
			ObserverSet: observerSet, RepeatCount: 1, SuccessThreshold: 1,
		},
		Runner:      runner,
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{
			cleanupObservation(started, cleanup),
		},
		Assertions: []domain.AssertionResult{{
			SchemaVersion: "1", ID: "journey", Type: "exit_code", Required: true,
			Expected: 0, Actual: 0, Status: "passed", EvidenceRefs: []string{},
		}},
		Requested: 1, Completed: 1, Matching: 1, SuccessThreshold: 1, Cleanup: cleanup,
	})
	if err != nil {
		t.Fatalf("verification.Build: %v", err)
	}
	return result
}

func cleanupObservation(timestamp time.Time, verdict domain.CleanupVerdict) domain.ObservationEvent {
	entryCount := 0
	symlinkCount := 0
	unmatchedCount := 0
	if verdict == domain.CleanupUndeclaredResidue {
		entryCount = 1
		symlinkCount = 1
		unmatchedCount = 1
	}
	return domain.ObservationEvent{
		SchemaVersion: "1", Sequence: 1, Timestamp: timestamp, Phase: domain.PhaseCleanup,
		Actor: "trusted-runner", Operation: "cleanup.residue.summary", Resource: "/outputs",
		Result: "succeeded", Observer: "controller-cleanup-residue-classifier",
		Coverage: "enforcement-only", Confidence: "high",
		Details: map[string]any{
			"allowedPatternCount": 1, "allowedProfile": "outputs-descendants",
			"boundary":          "post-quiescence-post-final-observers-post-disposable-pre-repair-pre-export-pre-destroy",
			"classifierVersion": "0.1.0", "directoryCount": 0,
			"disposableCleanupVerified": true, "entryCount": entryCount,
			"identityVerified": true, "inventoryComplete": true,
			"maxControlBytes": 512 << 10, "maxDepth": 64, "maxEntries": 2048,
			"maxPathBytes":         1024,
			"opaqueInventoryToken": "hmac-sha256:" + strings.Repeat("ab", 32),
			"quiescenceConfirmed":  true, "regularFileCount": 0, "scope": "/outputs",
			"specialCount": 0, "symlinkCount": symlinkCount,
			"tokenScheme": "ephemeral-keyed-hmac-sha256", "unmatchedCount": unmatchedCount,
			"verdict": string(verdict),
		},
	}
}

func digestOf(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func assertErrorCode(t *testing.T, err error, want domain.ErrorCode) {
	t.Helper()
	if got := domain.ErrorCodeOf(err); got != want {
		t.Fatalf("error code = %q, want %q: %v", got, want, err)
	}
}

func assertUntrustedDetails(t *testing.T, err error, decision string) {
	t.Helper()
	typed, ok := err.(*domain.Error)
	if !ok || typed.Details["signatureValid"] != true || typed.Details["trustDecision"] != decision {
		t.Fatalf("untrusted details = %#v", typed)
	}
}
