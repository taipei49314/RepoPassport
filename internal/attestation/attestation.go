package attestation

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/spdx"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
	"github.com/taipei49314/RepoPassport/internal/verification"
	"github.com/taipei49314/RepoPassport/schemas"
)

const (
	BundleVersion        = "1"
	BundleVersionV2      = "2"
	StatementType        = "https://in-toto.io/Statement/v1"
	PredicateType        = "https://repopass.dev/attestation/verification/v0.1"
	PredicateTypeV2      = "https://repopass.dev/attestation/verification/v0.2"
	DSSEPayloadType      = "application/vnd.in-toto+json"
	MaxBundleBytes       = 20 << 20
	MaxVerificationBytes = 16 << 20
	MaxJSONBytes         = 1 << 20
	MaxPublicKeyBytes    = 16 << 10
)

const (
	attestationPath  = "attestation.json"
	manifestPath     = "bundle-manifest.json"
	verificationPath = "payload/verification.json"
	sbomPath         = spdx.BundlePath
	provenancePath   = spdx.DerivedProvenancePath
	signaturePath    = "signature.dsse.json"
	publicKeyPath    = "signer-public-key.pem"
)

type Manifest struct {
	SchemaVersion        string         `json:"schemaVersion"`
	BundleFormat         string         `json:"bundleFormat"`
	PrivacyProfile       string         `json:"privacyProfile"`
	PrivacyPolicy        string         `json:"privacyPolicy,omitempty"`
	PrivacyRulesetDigest string         `json:"privacyRulesetDigest,omitempty"`
	Files                []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Statement struct {
	Type          string             `json:"_type"`
	Subject       []StatementSubject `json:"subject"`
	PredicateType string             `json:"predicateType"`
	Predicate     Predicate          `json:"predicate"`
}

type StatementSubject struct {
	Name   string        `json:"name"`
	Digest SubjectDigest `json:"digest"`
}

type SubjectDigest struct {
	SHA256 string `json:"sha256"`
}

type Predicate struct {
	SchemaVersion              string                `json:"schemaVersion"`
	RunID                      string                `json:"runId"`
	VerificationID             string                `json:"verificationId"`
	VerificationArtifactDigest string                `json:"verificationArtifactDigest"`
	VerificationDigest         string                `json:"verificationDigest"`
	Source                     domain.PlanSource     `json:"source"`
	Plan                       PredicatePlan         `json:"plan"`
	Runner                     domain.RunnerFeatures `json:"runner"`
	OriginalResults            domain.Verdicts       `json:"originalResults"`
	SBOM                       *PredicateSBOM        `json:"sbom,omitempty"`
}

type PredicatePlan struct {
	Scenario                  string              `json:"scenario"`
	Environment               string              `json:"environment"`
	PlanDigest                string              `json:"planDigest"`
	PolicyBundleDigest        string              `json:"policyBundleDigest"`
	ResolvedPlanSchemaVersion string              `json:"resolvedPlanSchemaVersion"`
	Evidence                  domain.PlanEvidence `json:"evidence"`
}

type PredicateSBOM struct {
	Format               string `json:"format"`
	MediaType            string `json:"mediaType"`
	Path                 string `json:"path"`
	Digest               string `json:"digest"`
	ProvenancePath       string `json:"provenancePath,omitempty"`
	ProvenanceDigest     string `json:"provenanceDigest,omitempty"`
	PrivacyProfile       string `json:"privacyProfile,omitempty"`
	PrivacyPolicy        string `json:"privacyPolicy,omitempty"`
	PrivacyRulesetDigest string `json:"privacyRulesetDigest,omitempty"`
}

type Envelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type BuildResult struct {
	Bundle                   []byte
	PublicKeyPEM             []byte
	RunID                    string
	VerificationID           string
	SignerKeyID              string
	ManifestDigest           string
	BundleDigest             string
	PublicKeyDigest          string
	PrivacyProfile           string
	PrivacyPolicy            string
	PrivacyRulesetDigest     string
	PrivacyEvaluation        string
	SBOMPresent              bool
	SBOMFormat               string
	SBOMDigest               string
	SBOMOrigin               string
	SBOMProfile              string
	SBOMRulesetDigest        string
	SBOMProvenanceDigest     string
	SBOMPrivacyProfile       string
	SBOMPrivacyPolicy        string
	SBOMPrivacyRulesetDigest string
	SBOMPrivacyEvaluation    string
}

type VerificationReport struct {
	SchemaVersion                                            string                 `json:"schemaVersion"`
	ArtifactIntegrity                                        string                 `json:"artifactIntegrity"`
	SignatureValidity                                        string                 `json:"signatureValidity"`
	BundleDigest                                             string                 `json:"bundleDigest"`
	PublicKeyDigest                                          string                 `json:"publicKeyDigest"`
	SignerKeyID                                              string                 `json:"signerKeyId"`
	TrustDecision                                            string                 `json:"trustDecision"`
	TrustBasis                                               string                 `json:"trustBasis,omitempty"`
	TrustPolicyDigest                                        string                 `json:"trustPolicyDigest,omitempty"`
	TrustPolicyEnvelopeDigest                                string                 `json:"trustPolicyEnvelopeDigest,omitempty"`
	TrustPolicyAuthorityKeyID                                string                 `json:"trustPolicyAuthorityKeyId,omitempty"`
	TrustPolicyGeneration                                    uint64                 `json:"trustPolicyGeneration,omitempty"`
	MinimumTrustPolicyGeneration                             uint64                 `json:"minimumTrustPolicyGeneration,omitempty"`
	TrustPolicySignatureValidity                             string                 `json:"trustPolicySignatureValidity,omitempty"`
	TrustPolicyStateEvaluation                               string                 `json:"trustPolicyStateEvaluation,omitempty"`
	TrustPolicyStateGeneration                               uint64                 `json:"trustPolicyStateGeneration,omitempty"`
	TrustPolicyAuthorityTransitionDigest                     string                 `json:"trustPolicyAuthorityTransitionDigest,omitempty"`
	TrustPolicyAuthorityTransitionEnvelopeDigest             string                 `json:"trustPolicyAuthorityTransitionEnvelopeDigest,omitempty"`
	TrustPolicyAuthorityTrustRootKeyID                       string                 `json:"trustPolicyAuthorityTrustRootKeyId,omitempty"`
	TrustPolicyAuthorityTransitionGeneration                 uint64                 `json:"trustPolicyAuthorityTransitionGeneration,omitempty"`
	MinimumTrustPolicyAuthorityGeneration                    uint64                 `json:"minimumTrustPolicyAuthorityGeneration,omitempty"`
	TrustPolicyAuthorityStateEvaluation                      string                 `json:"trustPolicyAuthorityStateEvaluation,omitempty"`
	TrustPolicyAuthorityStateTransitionGeneration            uint64                 `json:"trustPolicyAuthorityStateTransitionGeneration,omitempty"`
	TrustPolicyAuthorityStatePolicyGeneration                uint64                 `json:"trustPolicyAuthorityStatePolicyGeneration,omitempty"`
	TrustPolicyAuthorityTransitionChainDigest                string                 `json:"trustPolicyAuthorityTransitionChainDigest,omitempty"`
	TrustPolicyAuthorityTransitionChainHopCount              uint64                 `json:"trustPolicyAuthorityTransitionChainHopCount,omitempty"`
	TrustPolicyAuthorityTransitionChainGeneration            uint64                 `json:"trustPolicyAuthorityTransitionChainGeneration,omitempty"`
	TrustPolicyAuthorityTransitionChainRootKeyID             string                 `json:"trustPolicyAuthorityTransitionChainRootKeyId,omitempty"`
	TrustPolicyAuthorityTransitionChainTerminalKeyID         string                 `json:"trustPolicyAuthorityTransitionChainTerminalKeyId,omitempty"`
	TrustPolicyAuthorityTransitionChainStateEvaluation       string                 `json:"trustPolicyAuthorityTransitionChainStateEvaluation,omitempty"`
	TrustPolicyAuthorityTransitionChainStateGeneration       uint64                 `json:"trustPolicyAuthorityTransitionChainStateGeneration,omitempty"`
	TrustPolicyAuthorityTransitionChainStatePolicyGeneration uint64                 `json:"trustPolicyAuthorityTransitionChainStatePolicyGeneration,omitempty"`
	TrustReason                                              string                 `json:"trustReason,omitempty"`
	FreshnessEvaluation                                      string                 `json:"freshnessEvaluation"`
	RunID                                                    string                 `json:"runId"`
	VerificationID                                           string                 `json:"verificationId"`
	OriginalResults                                          domain.Verdicts        `json:"originalResults"`
	PrivacyProfile                                           string                 `json:"privacyProfile"`
	PrivacyPolicy                                            string                 `json:"privacyPolicy"`
	PrivacyRulesetDigest                                     string                 `json:"privacyRulesetDigest"`
	PrivacyEvaluation                                        string                 `json:"privacyEvaluation"`
	SBOMPresent                                              bool                   `json:"sbomPresent"`
	SBOMFormat                                               string                 `json:"sbomFormat"`
	SBOMDigest                                               string                 `json:"sbomDigest"`
	SBOMOrigin                                               string                 `json:"sbomOrigin,omitempty"`
	SBOMProfile                                              string                 `json:"sbomProfile,omitempty"`
	SBOMRulesetDigest                                        string                 `json:"sbomRulesetDigest,omitempty"`
	SBOMProvenanceDigest                                     string                 `json:"sbomProvenanceDigest,omitempty"`
	SBOMPrivacyProfile                                       string                 `json:"sbomPrivacyProfile,omitempty"`
	SBOMPrivacyPolicy                                        string                 `json:"sbomPrivacyPolicy,omitempty"`
	SBOMPrivacyRulesetDigest                                 string                 `json:"sbomPrivacyRulesetDigest,omitempty"`
	SBOMPrivacyEvaluation                                    string                 `json:"sbomPrivacyEvaluation,omitempty"`
	SBOMCurrentnessEvaluation                                string                 `json:"sbomCurrentnessEvaluation,omitempty"`
	SBOMCurrentness                                          *SBOMCurrentnessReport `json:"sbomCurrentness,omitempty"`
	Freshness                                                *FreshnessReport       `json:"freshness,omitempty"`
}

// VerifyAccepted returns the exact signed freshness claims only after the
// explicit SPKI trust key has been accepted. Callers must not use claims from
// an untrusted or malformed bundle to drive local source or runner access.
func VerifyAccepted(bundle []byte, trustKeyPEM []byte) (VerificationReport, AcceptedClaims, error) {
	report, err := Verify(bundle, trustKeyPEM)
	if err != nil {
		return report, AcceptedClaims{}, err
	}
	claims, err := acceptedClaimsFromBundle(bundle)
	if err != nil {
		return VerificationReport{}, AcceptedClaims{}, err
	}
	return report, claims, nil
}

// VerifyWithOfflineTrustPolicy preserves the canonical bundle and signature
// verification order, then applies an independently supplied canonical policy
// only to the signer key ID recomputed from the embedded canonical SPKI DER.
func VerifyWithOfflineTrustPolicy(
	bundle []byte,
	policy *OfflineTrustPolicy,
) (VerificationReport, error) {
	report, err := Verify(bundle, nil)
	if err != nil && domain.ErrorCodeOf(err) != domain.CodeAttestationUntrusted {
		return report, err
	}
	report.TrustBasis = "offline-policy-v1"
	report.TrustPolicyDigest = policy.Digest()
	decision, evaluationErr := policy.EvaluateSignerKeyID(report.SignerKeyID)
	if evaluationErr != nil {
		report.TrustDecision = "rejected"
		report.TrustReason = "invalid-or-unavailable"
		return report, untrustedPolicyError("The offline trust policy cannot evaluate the verified signer.", report.TrustReason)
	}
	switch decision {
	case TrustDecisionTrusted:
		report.TrustDecision = "accepted"
		report.TrustReason = "trusted"
		return report, nil
	case TrustDecisionRevoked:
		report.TrustDecision = "rejected"
		report.TrustReason = "revoked"
		return report, untrustedPolicyError("The verified signer is revoked by the offline trust policy.", report.TrustReason)
	default:
		report.TrustDecision = "rejected"
		report.TrustReason = "not-listed"
		return report, untrustedPolicyError("The verified signer is not listed by the offline trust policy.", report.TrustReason)
	}
}

// VerifyAcceptedWithOfflineTrustPolicy releases signed replay claims only
// after the independent policy has accepted the verifier-computed signer ID.
func VerifyAcceptedWithOfflineTrustPolicy(
	bundle []byte,
	policy *OfflineTrustPolicy,
) (VerificationReport, AcceptedClaims, error) {
	report, err := VerifyWithOfflineTrustPolicy(bundle, policy)
	if err != nil {
		return report, AcceptedClaims{}, err
	}
	claims, err := acceptedClaimsFromBundle(bundle)
	if err != nil {
		return VerificationReport{}, AcceptedClaims{}, err
	}
	return report, claims, nil
}

func acceptedClaimsFromBundle(bundle []byte) (AcceptedClaims, error) {
	files, _, err := parseCanonicalTarModel(bundle)
	if err != nil {
		return AcceptedClaims{}, invalidError()
	}
	var statement Statement
	if err := decodeCanonicalJSON(files[attestationPath], MaxJSONBytes, &statement); err != nil {
		return AcceptedClaims{}, invalidError()
	}
	claims := AcceptedClaims{
		Source: statement.Predicate.Source,
		Plan:   statement.Predicate.Plan,
		Runner: statement.Predicate.Runner,
	}
	if provenanceJSON, derived := files[provenancePath]; derived {
		_, provenance, pairErr := spdx.ValidateDerivedPair(files[sbomPath], provenanceJSON)
		if pairErr != nil {
			return AcceptedClaims{}, invalidError()
		}
		claims.Derived = &AcceptedDerivedClaims{Provenance: provenance, SBOMDigest: digestBytes(files[sbomPath])}
	}
	return claims, nil
}

// EvaluatePrivacy validates and evaluates the exact canonical public
// verification representation without touching signing material or paths.
func EvaluatePrivacy(result domain.VerificationResult) (privacy.Evaluation, error) {
	verificationJSON, err := canonicaljson.Marshal(result)
	if err != nil || len(verificationJSON) > MaxVerificationBytes {
		return privacy.Evaluation{}, buildError("The authoritative verification artifact cannot be encoded within the bundle limit.")
	}
	if err := schemas.ValidateVerificationJSON(verificationJSON); err != nil {
		return privacy.Evaluation{}, buildError("The authoritative verification artifact does not satisfy the public schema.")
	}
	return privacy.Evaluate(verificationJSON)
}

func Build(result domain.VerificationResult, privateKey ed25519.PrivateKey) (BuildResult, error) {
	return BuildWithSPDX(result, nil, privateKey)
}

// BuildWithSPDX builds either the exact five-member schema-4 bundle or the
// exact six-member schema-4 bundle selected by the stored verification plan.
// A non-nil attachment is validated and canonicalized before key use.
func BuildWithSPDX(result domain.VerificationResult, attachment []byte, privateKey ed25519.PrivateKey) (BuildResult, error) {
	if err := verification.VerifyIntegrity(result); err != nil {
		return BuildResult{}, err
	}
	verificationJSON, err := canonicaljson.Marshal(result)
	if err != nil || len(verificationJSON) > MaxVerificationBytes {
		return BuildResult{}, buildError("The authoritative verification artifact cannot be encoded within the bundle limit.")
	}
	if err := schemas.ValidateVerificationJSON(verificationJSON); err != nil {
		return BuildResult{}, buildError("The authoritative verification artifact does not satisfy the public schema.")
	}
	privacyEvaluation, err := privacy.Evaluate(verificationJSON)
	if err != nil {
		return BuildResult{}, err
	}
	wantsSBOM := planSelectsSBOM(result.Plan)
	if wantsSBOM != (attachment != nil) {
		return BuildResult{}, buildError("The SPDX attachment does not match the sealed evidence selection.")
	}
	var canonicalSBOM []byte
	sbomMetadata := spdx.Metadata{}
	if wantsSBOM {
		_, canonicalSBOM, err = spdx.Canonicalize(attachment)
		if err != nil {
			return BuildResult{}, buildError("The SPDX attachment does not satisfy the bounded public profile.")
		}
		if _, err := privacy.Evaluate(canonicalSBOM); err != nil {
			return BuildResult{}, err
		}
		sbomMetadata = spdx.MetadataFor(canonicalSBOM)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return BuildResult{}, signingError("The signing key is not a valid Ed25519 private key.")
	}
	seed := privateKey.Seed()
	normalizedPrivateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	privateKeyConsistent := subtle.ConstantTimeCompare(privateKey, normalizedPrivateKey) == 1
	clear(normalizedPrivateKey)
	if !privateKeyConsistent {
		return BuildResult{}, signingError("The Ed25519 private key has inconsistent private and public halves.")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return BuildResult{}, signingError("The signing key cannot produce an Ed25519 public key.")
	}
	publicKeyPEM, publicKeyDER, err := marshalPublicKey(publicKey)
	if err != nil {
		return BuildResult{}, signingError("The signing public key cannot be encoded.")
	}
	keyID := digestBytes(publicKeyDER)

	manifest := expectedManifest(verificationJSON, canonicalSBOM, publicKeyPEM)
	manifestJSON, err := canonicaljson.Marshal(manifest)
	if err != nil {
		return BuildResult{}, buildError("The bundle manifest cannot be encoded.")
	}
	statement := expectedStatement(result, verificationJSON, canonicalSBOM, manifestJSON)
	attestationJSON, err := canonicaljson.Marshal(statement)
	if err != nil {
		return BuildResult{}, buildError("The in-toto statement cannot be encoded.")
	}

	message := pae(DSSEPayloadType, attestationJSON)
	signature := ed25519.Sign(privateKey, message)
	envelopeJSON, err := canonicaljson.Marshal(Envelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(attestationJSON),
		Signatures: []DSSESignature{{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	})
	if err != nil {
		return BuildResult{}, buildError("The DSSE envelope cannot be encoded.")
	}

	files := map[string][]byte{
		attestationPath:  attestationJSON,
		manifestPath:     manifestJSON,
		verificationPath: verificationJSON,
		signaturePath:    envelopeJSON,
		publicKeyPath:    publicKeyPEM,
	}
	if wantsSBOM {
		files[sbomPath] = canonicalSBOM
	}
	bundle, err := buildCanonicalTar(files, wantsSBOM)
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Bundle:               bundle,
		PublicKeyPEM:         append([]byte(nil), publicKeyPEM...),
		RunID:                result.RunID,
		VerificationID:       result.VerificationID,
		SignerKeyID:          keyID,
		ManifestDigest:       digestBytes(manifestJSON),
		BundleDigest:         digestBytes(bundle),
		PublicKeyDigest:      digestBytes(publicKeyPEM),
		PrivacyProfile:       privacyEvaluation.PrivacyProfile,
		PrivacyPolicy:        privacyEvaluation.PrivacyPolicy,
		PrivacyRulesetDigest: privacyEvaluation.PrivacyRulesetDigest,
		PrivacyEvaluation:    privacyEvaluation.PrivacyEvaluation,
		SBOMPresent:          sbomMetadata.Present,
		SBOMFormat:           sbomMetadata.Format,
		SBOMDigest:           sbomMetadata.Digest,
	}, nil
}

// BuildWithDerivedSPDX builds only the exact seven-member v2 model. The two
// canonical derived payloads and their source binding are accepted before any
// private-key operation. The legacy Build and BuildWithSPDX paths are not
// routed through this function.
func BuildWithDerivedSPDX(
	result domain.VerificationResult,
	canonicalSBOM []byte,
	canonicalProvenance []byte,
	privateKey ed25519.PrivateKey,
) (BuildResult, error) {
	if err := verification.VerifyIntegrity(result); err != nil {
		return BuildResult{}, err
	}
	verificationJSON, err := canonicaljson.Marshal(result)
	if err != nil || len(verificationJSON) > MaxVerificationBytes {
		return BuildResult{}, buildError("The authoritative verification artifact cannot be encoded within the bundle limit.")
	}
	if err := schemas.ValidateVerificationJSON(verificationJSON); err != nil {
		return BuildResult{}, buildError("The authoritative verification artifact does not satisfy the public schema.")
	}
	privacyEvaluation, err := privacy.Evaluate(verificationJSON)
	if err != nil {
		return BuildResult{}, err
	}
	if !planSelectsSBOM(result.Plan) {
		return BuildResult{}, buildError("The derived SPDX evidence does not match the sealed evidence selection.")
	}
	_, provenance, err := spdx.ValidateDerivedPair(canonicalSBOM, canonicalProvenance)
	if err != nil {
		return BuildResult{}, buildError("The repository-derived SPDX evidence does not satisfy the frozen public profile.")
	}
	if schemas.ValidateDerivedSPDXJSON(canonicalSBOM) != nil ||
		schemas.ValidateSBOMProvenanceV1JSON(canonicalProvenance) != nil {
		return BuildResult{}, buildError("The repository-derived SPDX evidence does not satisfy the public schema.")
	}
	sbomPrivacy, err := privacy.EvaluateDerivedPair(canonicalSBOM, canonicalProvenance)
	if err != nil {
		return BuildResult{}, err
	}
	if result.Subject.Commit != "" || result.Subject.Identity != result.Subject.TreeDigest ||
		provenance.SourceTreeDigest != result.Subject.TreeDigest {
		return BuildResult{}, buildError("The repository-derived SPDX evidence does not match the authoritative source subject.")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return BuildResult{}, signingError("The signing key is not a valid Ed25519 private key.")
	}
	seed := privateKey.Seed()
	normalizedPrivateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	privateKeyConsistent := subtle.ConstantTimeCompare(privateKey, normalizedPrivateKey) == 1
	clear(normalizedPrivateKey)
	if !privateKeyConsistent {
		return BuildResult{}, signingError("The Ed25519 private key has inconsistent private and public halves.")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return BuildResult{}, signingError("The signing key cannot produce an Ed25519 public key.")
	}
	publicKeyPEM, publicKeyDER, err := marshalPublicKey(publicKey)
	if err != nil {
		return BuildResult{}, signingError("The signing public key cannot be encoded.")
	}
	keyID := digestBytes(publicKeyDER)

	manifest := expectedManifestV2(verificationJSON, canonicalSBOM, canonicalProvenance, publicKeyPEM)
	manifestJSON, err := canonicaljson.Marshal(manifest)
	if err != nil || schemas.ValidateBundleManifestV2JSON(manifestJSON) != nil {
		return BuildResult{}, buildError("The bundle manifest cannot be encoded.")
	}
	statement := expectedStatementV2(result, verificationJSON, canonicalSBOM, canonicalProvenance, manifestJSON)
	attestationJSON, err := canonicaljson.Marshal(statement)
	if err != nil || schemas.ValidateAttestationV2JSON(attestationJSON) != nil {
		return BuildResult{}, buildError("The in-toto statement cannot be encoded.")
	}

	message := pae(DSSEPayloadType, attestationJSON)
	signature := ed25519.Sign(privateKey, message)
	envelopeJSON, err := canonicaljson.Marshal(Envelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(attestationJSON),
		Signatures: []DSSESignature{{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	})
	if err != nil {
		return BuildResult{}, buildError("The DSSE envelope cannot be encoded.")
	}

	files := map[string][]byte{
		attestationPath:  attestationJSON,
		manifestPath:     manifestJSON,
		verificationPath: verificationJSON,
		sbomPath:         canonicalSBOM,
		provenancePath:   canonicalProvenance,
		signaturePath:    envelopeJSON,
		publicKeyPath:    publicKeyPEM,
	}
	bundle, err := buildCanonicalTarV2(files)
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Bundle: bundle, PublicKeyPEM: append([]byte(nil), publicKeyPEM...),
		RunID: result.RunID, VerificationID: result.VerificationID,
		SignerKeyID: keyID, ManifestDigest: digestBytes(manifestJSON),
		BundleDigest: digestBytes(bundle), PublicKeyDigest: digestBytes(publicKeyPEM),
		PrivacyProfile: privacyEvaluation.PrivacyProfile, PrivacyPolicy: privacyEvaluation.PrivacyPolicy,
		PrivacyRulesetDigest: privacyEvaluation.PrivacyRulesetDigest, PrivacyEvaluation: privacyEvaluation.PrivacyEvaluation,
		SBOMPresent: true, SBOMFormat: spdx.Format, SBOMDigest: digestBytes(canonicalSBOM),
		SBOMOrigin: provenance.Origin, SBOMProfile: provenance.Profile,
		SBOMRulesetDigest: provenance.RulesetDigest, SBOMProvenanceDigest: digestBytes(canonicalProvenance),
		SBOMPrivacyProfile: sbomPrivacy.PrivacyProfile, SBOMPrivacyPolicy: sbomPrivacy.PrivacyPolicy,
		SBOMPrivacyRulesetDigest: sbomPrivacy.PrivacyRulesetDigest, SBOMPrivacyEvaluation: sbomPrivacy.PrivacyEvaluation,
	}, nil
}

func Verify(bundle []byte, trustKeyPEM []byte) (VerificationReport, error) {
	files, hasSBOM, err := parseCanonicalTarModel(bundle)
	if err != nil {
		return VerificationReport{}, invalidError()
	}

	var result domain.VerificationResult
	if err := decodeCanonicalJSON(files[verificationPath], MaxVerificationBytes, &result); err != nil {
		return VerificationReport{}, invalidError()
	}
	if err := schemas.ValidateVerificationJSON(files[verificationPath]); err != nil {
		return VerificationReport{}, invalidError()
	}
	if err := verification.VerifyIntegrity(result); err != nil {
		return VerificationReport{}, invalidError()
	}

	var manifest Manifest
	if err := decodeCanonicalJSON(files[manifestPath], MaxJSONBytes, &manifest); err != nil {
		return VerificationReport{}, invalidError()
	}
	publicKey, publicKeyDER, err := parsePublicKey(files[publicKeyPath])
	if err != nil {
		return VerificationReport{}, invalidError()
	}
	keyID := digestBytes(publicKeyDER)
	_, derived := files[provenancePath]
	if derived && schemas.ValidateBundleManifestV2JSON(files[manifestPath]) != nil {
		return VerificationReport{}, invalidError()
	}
	var expectedManifestValue Manifest
	if derived {
		expectedManifestValue = expectedManifestV2(
			files[verificationPath], files[sbomPath], files[provenancePath], files[publicKeyPath],
		)
	} else {
		expectedManifestValue = expectedManifest(files[verificationPath], files[sbomPath], files[publicKeyPath])
	}
	expectedManifestJSON, err := canonicaljson.Marshal(expectedManifestValue)
	if err != nil || !bytes.Equal(files[manifestPath], expectedManifestJSON) {
		return VerificationReport{}, invalidError()
	}

	var statement Statement
	if err := decodeCanonicalJSON(files[attestationPath], MaxJSONBytes, &statement); err != nil {
		return VerificationReport{}, invalidError()
	}
	if derived && schemas.ValidateAttestationV2JSON(files[attestationPath]) != nil {
		return VerificationReport{}, invalidError()
	}
	var expectedStatementValue Statement
	if derived {
		expectedStatementValue = expectedStatementV2(
			result, files[verificationPath], files[sbomPath], files[provenancePath], files[manifestPath],
		)
	} else {
		expectedStatementValue = expectedStatement(result, files[verificationPath], files[sbomPath], files[manifestPath])
	}
	expectedAttestationJSON, err := canonicaljson.Marshal(expectedStatementValue)
	if err != nil || !bytes.Equal(files[attestationPath], expectedAttestationJSON) {
		return VerificationReport{}, invalidError()
	}

	var envelope Envelope
	if err := decodeCanonicalJSON(files[signaturePath], MaxJSONBytes, &envelope); err != nil ||
		envelope.PayloadType != DSSEPayloadType || len(envelope.Signatures) != 1 {
		return VerificationReport{}, invalidError()
	}
	payload, err := decodeBase64Bounded(envelope.Payload, MaxJSONBytes)
	if err != nil || !bytes.Equal(payload, files[attestationPath]) {
		return VerificationReport{}, invalidError()
	}
	if envelope.Signatures[0].KeyID != keyID {
		return VerificationReport{}, invalidError()
	}
	signature, err := decodeBase64Bounded(envelope.Signatures[0].Sig, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, pae(envelope.PayloadType, payload), signature) {
		return VerificationReport{}, invalidError()
	}
	if planSelectsSBOM(result.Plan) != hasSBOM {
		return VerificationReport{}, invalidError()
	}
	sbomMetadata := spdx.Metadata{}
	derivedProvenance := spdx.DerivedProvenance{}
	derivedPrivacy := privacy.DerivedEvaluation{}
	if hasSBOM {
		if derived {
			if schemas.ValidateDerivedSPDXJSON(files[sbomPath]) != nil ||
				schemas.ValidateSBOMProvenanceV1JSON(files[provenancePath]) != nil {
				return VerificationReport{}, invalidError()
			}
			_, derivedProvenance, err = spdx.ValidateDerivedPair(files[sbomPath], files[provenancePath])
			if err != nil || result.Subject.Commit != "" || result.Subject.Identity != result.Subject.TreeDigest ||
				derivedProvenance.SourceTreeDigest != result.Subject.TreeDigest {
				return VerificationReport{}, invalidError()
			}
			derivedPrivacy, err = privacy.EvaluateDerivedPair(files[sbomPath], files[provenancePath])
			if err != nil {
				return VerificationReport{}, err
			}
			sbomMetadata = spdx.MetadataFor(files[sbomPath])
		} else {
			_, canonicalSBOM, spdxErr := spdx.Canonicalize(files[sbomPath])
			if spdxErr != nil || !bytes.Equal(canonicalSBOM, files[sbomPath]) {
				return VerificationReport{}, invalidError()
			}
			sbomMetadata = spdx.MetadataFor(canonicalSBOM)
			if _, err := privacy.Evaluate(canonicalSBOM); err != nil {
				return VerificationReport{}, err
			}
		}
	}
	privacyEvaluation, err := privacy.Evaluate(files[verificationPath])
	if err != nil {
		return VerificationReport{}, err
	}

	report := VerificationReport{
		SchemaVersion:        BundleVersion,
		ArtifactIntegrity:    "valid",
		SignatureValidity:    "valid",
		BundleDigest:         digestBytes(bundle),
		PublicKeyDigest:      digestBytes(files[publicKeyPath]),
		SignerKeyID:          keyID,
		TrustDecision:        "unknown",
		FreshnessEvaluation:  "not-evaluated",
		RunID:                result.RunID,
		VerificationID:       result.VerificationID,
		OriginalResults:      result.Results,
		PrivacyProfile:       privacyEvaluation.PrivacyProfile,
		PrivacyPolicy:        privacyEvaluation.PrivacyPolicy,
		PrivacyRulesetDigest: privacyEvaluation.PrivacyRulesetDigest,
		PrivacyEvaluation:    privacyEvaluation.PrivacyEvaluation,
		SBOMPresent:          sbomMetadata.Present,
		SBOMFormat:           sbomMetadata.Format,
		SBOMDigest:           sbomMetadata.Digest,
	}
	if derived {
		report.SchemaVersion = BundleVersionV2
		report.SBOMOrigin = derivedProvenance.Origin
		report.SBOMProfile = derivedProvenance.Profile
		report.SBOMRulesetDigest = derivedProvenance.RulesetDigest
		report.SBOMProvenanceDigest = digestBytes(files[provenancePath])
		report.SBOMPrivacyProfile = derivedPrivacy.PrivacyProfile
		report.SBOMPrivacyPolicy = derivedPrivacy.PrivacyPolicy
		report.SBOMPrivacyRulesetDigest = derivedPrivacy.PrivacyRulesetDigest
		report.SBOMPrivacyEvaluation = derivedPrivacy.PrivacyEvaluation
		report.SBOMCurrentnessEvaluation = SBOMCurrentnessNotEvaluated
	}
	if len(trustKeyPEM) == 0 {
		return report, untrustedSignatureError(
			"The signature is valid, but no trusted public key was provided.",
			"unknown",
		)
	}
	_, trustedDER, err := parsePublicKey(trustKeyPEM)
	if err != nil {
		report.TrustDecision = "rejected"
		return report, untrustedSignatureError(
			"The trusted public key is not canonical Ed25519 SPKI PEM.",
			"rejected",
		)
	}
	if !bytes.Equal(publicKeyDER, trustedDER) {
		report.TrustDecision = "rejected"
		return report, untrustedSignatureError(
			"The signature is valid, but its signer is not the explicitly trusted key.",
			"rejected",
		)
	}
	report.TrustDecision = "accepted"
	return report, nil
}

// ValidateExpectedBundleDigest accepts only the public canonical digest form.
func ValidateExpectedBundleDigest(value string) error {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return malformedExpectedDigestError()
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return malformedExpectedDigestError()
		}
	}
	return nil
}

// CheckExpectedBundleDigest pins the complete raw bundle before canonical
// parsing or any optional signer-trust decision.
func CheckExpectedBundleDigest(bundle []byte, expected string) error {
	if expected == "" {
		return nil
	}
	if err := ValidateExpectedBundleDigest(expected); err != nil {
		return err
	}
	actual := digestBytes(bundle)
	if actual == expected {
		return nil
	}
	err := domain.NewError(
		domain.CodeEvidenceDigestMismatch,
		domain.SeverityCritical,
		"The complete attestation bundle does not match the expected SHA-256 digest.",
	)
	err.Details = map[string]any{
		"expectedBundleDigest": expected,
		"actualBundleDigest":   actual,
	}
	return err
}

// ValidateExpectedTrustPolicyDigest accepts the same canonical public digest
// syntax as the raw bundle pin, but reports the policy-specific flag contract.
func ValidateExpectedTrustPolicyDigest(value string) error {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return malformedExpectedTrustPolicyDigestError()
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return malformedExpectedTrustPolicyDigestError()
		}
	}
	return nil
}

// CheckExpectedTrustPolicyDigest pins the exact raw policy bytes after the
// evidence bundle has passed cryptographic verification and before policy
// parsing or authorization.
func CheckExpectedTrustPolicyDigest(raw []byte, expected string) error {
	if err := ValidateExpectedTrustPolicyDigest(expected); err != nil {
		return err
	}
	actual := digestBytes(raw)
	if actual == expected {
		return nil
	}
	err := domain.NewError(
		domain.CodeEvidenceDigestMismatch,
		domain.SeverityCritical,
		"The offline trust policy does not match the expected SHA-256 digest.",
	)
	err.Details = map[string]any{
		"expectedTrustPolicyDigest": expected,
		"actualTrustPolicyDigest":   actual,
	}
	return err
}

func malformedExpectedTrustPolicyDigestError() error {
	return domain.NewError(
		domain.CodeManifestInvalid,
		domain.SeverityHigh,
		"--expect-trust-policy-digest must be sha256:<64 lowercase hexadecimal characters>.",
	)
}

func malformedExpectedDigestError() error {
	return domain.NewError(
		domain.CodeManifestInvalid,
		domain.SeverityHigh,
		"--expect-bundle-digest must be sha256:<64 lowercase hexadecimal characters>.",
	)
}

func expectedManifest(verificationJSON []byte, artifacts ...[]byte) Manifest {
	var sbomJSON, publicKeyPEM []byte
	if len(artifacts) == 1 {
		publicKeyPEM = artifacts[0]
	} else if len(artifacts) == 2 {
		sbomJSON, publicKeyPEM = artifacts[0], artifacts[1]
	}
	files := []ManifestFile{
		{
			Path:   verificationPath,
			SHA256: digestBytes(verificationJSON),
			Size:   int64(len(verificationJSON)),
		},
	}
	if sbomJSON != nil {
		files = append(files, ManifestFile{
			Path: sbomPath, SHA256: digestBytes(sbomJSON), Size: int64(len(sbomJSON)),
		})
	}
	files = append(files, ManifestFile{
		Path: publicKeyPath, SHA256: digestBytes(publicKeyPEM), Size: int64(len(publicKeyPEM)),
	})
	return Manifest{
		SchemaVersion:  BundleVersion,
		BundleFormat:   "repopass.attestation.bundle.v1",
		PrivacyProfile: "minimal-public",
		Files:          files,
	}
}

func expectedManifestV2(verificationJSON, sbomJSON, provenanceJSON, publicKeyPEM []byte) Manifest {
	return Manifest{
		SchemaVersion:        BundleVersionV2,
		BundleFormat:         "repopass.attestation.bundle.v2",
		PrivacyProfile:       privacy.DerivedProjectionProfile,
		PrivacyPolicy:        privacy.DerivedProjectionPolicy,
		PrivacyRulesetDigest: privacy.DerivedProjectionRulesetDigest,
		Files: []ManifestFile{
			{Path: verificationPath, SHA256: digestBytes(verificationJSON), Size: int64(len(verificationJSON))},
			{Path: sbomPath, SHA256: digestBytes(sbomJSON), Size: int64(len(sbomJSON))},
			{Path: provenancePath, SHA256: digestBytes(provenanceJSON), Size: int64(len(provenanceJSON))},
			{Path: publicKeyPath, SHA256: digestBytes(publicKeyPEM), Size: int64(len(publicKeyPEM))},
		},
	}
}

func expectedStatement(
	result domain.VerificationResult,
	verificationJSON []byte,
	artifacts ...[]byte,
) Statement {
	var sbomJSON, manifestJSON []byte
	if len(artifacts) == 1 {
		manifestJSON = artifacts[0]
	} else if len(artifacts) == 2 {
		sbomJSON, manifestJSON = artifacts[0], artifacts[1]
	}
	statement := Statement{
		Type: StatementType,
		Subject: []StatementSubject{{
			Name: manifestPath,
			Digest: SubjectDigest{
				SHA256: rawDigestBytes(manifestJSON),
			},
		}},
		PredicateType: PredicateType,
		Predicate: Predicate{
			SchemaVersion:              BundleVersion,
			RunID:                      result.RunID,
			VerificationID:             result.VerificationID,
			VerificationArtifactDigest: digestBytes(verificationJSON),
			VerificationDigest:         result.Digests.Verification,
			Source:                     result.Subject,
			Plan: PredicatePlan{
				Scenario:                  result.Plan.Scenario,
				Environment:               result.Plan.Environment,
				PlanDigest:                result.Plan.PlanDigest,
				PolicyBundleDigest:        result.Plan.PolicyBundleDigest,
				ResolvedPlanSchemaVersion: result.Plan.ResolvedPlanSchemaVersion,
				Evidence: domain.PlanEvidence{
					Profile: result.Plan.Evidence.Profile,
					Include: append([]string{}, result.Plan.Evidence.Include...),
					Exclude: append([]string{}, result.Plan.Evidence.Exclude...),
				},
			},
			Runner:          result.Runner,
			OriginalResults: result.Results,
		},
	}
	if sbomJSON != nil {
		statement.Predicate.SBOM = &PredicateSBOM{
			Format: spdx.Format, MediaType: spdx.MediaType, Path: sbomPath,
			Digest: digestBytes(sbomJSON),
		}
	}
	return statement
}

func expectedStatementV2(
	result domain.VerificationResult,
	verificationJSON, sbomJSON, provenanceJSON, manifestJSON []byte,
) Statement {
	statement := Statement{
		Type: StatementType,
		Subject: []StatementSubject{{
			Name:   manifestPath,
			Digest: SubjectDigest{SHA256: rawDigestBytes(manifestJSON)},
		}},
		PredicateType: PredicateTypeV2,
		Predicate: Predicate{
			SchemaVersion: BundleVersionV2, RunID: result.RunID,
			VerificationID:             result.VerificationID,
			VerificationArtifactDigest: digestBytes(verificationJSON),
			VerificationDigest:         result.Digests.Verification,
			Source:                     result.Subject,
			Plan: PredicatePlan{
				Scenario: result.Plan.Scenario, Environment: result.Plan.Environment,
				PlanDigest: result.Plan.PlanDigest, PolicyBundleDigest: result.Plan.PolicyBundleDigest,
				ResolvedPlanSchemaVersion: result.Plan.ResolvedPlanSchemaVersion,
				Evidence: domain.PlanEvidence{
					Profile: result.Plan.Evidence.Profile,
					Include: append([]string{}, result.Plan.Evidence.Include...),
					Exclude: append([]string{}, result.Plan.Evidence.Exclude...),
				},
			},
			Runner: result.Runner, OriginalResults: result.Results,
			SBOM: &PredicateSBOM{
				Format: spdx.Format, MediaType: spdx.MediaType, Path: sbomPath,
				Digest: digestBytes(sbomJSON), ProvenancePath: provenancePath,
				ProvenanceDigest:     digestBytes(provenanceJSON),
				PrivacyProfile:       privacy.DerivedProjectionProfile,
				PrivacyPolicy:        privacy.DerivedProjectionPolicy,
				PrivacyRulesetDigest: privacy.DerivedProjectionRulesetDigest,
			},
		},
	}
	return statement
}

func buildCanonicalTar(files map[string][]byte, sbomModel ...bool) ([]byte, error) {
	hasSBOM := false
	if len(sbomModel) > 0 {
		hasSBOM = sbomModel[0]
	} else {
		_, hasSBOM = files[sbomPath]
	}
	return buildCanonicalTarPaths(files, bundlePaths(hasSBOM))
}

func buildCanonicalTarV2(files map[string][]byte) ([]byte, error) {
	return buildCanonicalTarPaths(files, bundlePathsV2())
}

func buildCanonicalTarPaths(files map[string][]byte, paths []string) ([]byte, error) {
	if len(files) != len(paths) {
		return nil, buildError("The bundle payload set is incomplete.")
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, name := range paths {
		content, exists := files[name]
		limit, allowed := bundleFileLimit(name)
		if !exists || !allowed || int64(len(content)) > limit {
			_ = writer.Close()
			return nil, buildError("A bundle entry is missing or exceeds its size limit.")
		}
		header := &tar.Header{
			Name:       name,
			Mode:       0o600,
			Uid:        0,
			Gid:        0,
			Size:       int64(len(content)),
			ModTime:    time.Unix(0, 0).UTC(),
			Typeflag:   tar.TypeReg,
			Linkname:   "",
			Uname:      "",
			Gname:      "",
			Devmajor:   0,
			Devminor:   0,
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Format:     tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			_ = writer.Close()
			return nil, buildError("The canonical tar header cannot be written.")
		}
		if _, err := writer.Write(content); err != nil {
			_ = writer.Close()
			return nil, buildError("The canonical tar entry cannot be written.")
		}
	}
	if err := writer.Close(); err != nil {
		return nil, buildError("The canonical tar cannot be finalized.")
	}
	if output.Len() > MaxBundleBytes {
		return nil, buildError("The attestation bundle exceeds the size limit.")
	}
	return output.Bytes(), nil
}

func parseCanonicalTar(bundle []byte) (map[string][]byte, error) {
	files, _, err := parseCanonicalTarModel(bundle)
	return files, err
}

func parseCanonicalTarModel(bundle []byte) (map[string][]byte, bool, error) {
	if len(bundle) == 0 || len(bundle) > MaxBundleBytes {
		return nil, false, fmt.Errorf("bundle size")
	}
	reader := tar.NewReader(bytes.NewReader(bundle))
	files := make(map[string][]byte, 7)
	caseFolded := make(map[string]struct{}, 7)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || len(files) >= 7 || header == nil {
			return nil, false, fmt.Errorf("tar structure")
		}
		if !validBundlePath(header.Name) {
			return nil, false, fmt.Errorf("tar path")
		}
		folded := strings.ToLower(header.Name)
		if _, exists := caseFolded[folded]; exists {
			return nil, false, fmt.Errorf("case-fold path collision")
		}
		caseFolded[folded] = struct{}{}
		limit, allowed := bundleFileLimit(header.Name)
		if !allowed {
			return nil, false, fmt.Errorf("unexpected tar entry")
		}
		if _, duplicate := files[header.Name]; duplicate {
			return nil, false, fmt.Errorf("duplicate tar entry")
		}
		if header.Typeflag != tar.TypeReg ||
			header.Format != tar.FormatUSTAR ||
			header.Mode != 0o600 ||
			header.Uid != 0 || header.Gid != 0 ||
			header.Size < 0 || header.Size > limit ||
			!header.ModTime.Equal(time.Unix(0, 0).UTC()) ||
			!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
			header.Linkname != "" || header.Uname != "" || header.Gname != "" ||
			header.Devmajor != 0 || header.Devminor != 0 ||
			len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			return nil, false, fmt.Errorf("non-canonical tar header")
		}
		content, err := io.ReadAll(io.LimitReader(reader, limit+1))
		if err != nil || int64(len(content)) != header.Size || int64(len(content)) > limit {
			return nil, false, fmt.Errorf("tar entry size")
		}
		files[header.Name] = content
	}
	_, hasSBOM := files[sbomPath]
	_, derived := files[provenancePath]
	paths := bundlePaths(hasSBOM)
	if derived {
		if !hasSBOM {
			return nil, false, fmt.Errorf("derived bundle missing SBOM")
		}
		paths = bundlePathsV2()
	}
	if len(files) != len(paths) {
		return nil, false, fmt.Errorf("missing tar entry")
	}
	for _, name := range paths {
		if _, exists := files[name]; !exists {
			return nil, false, fmt.Errorf("wrong tar model")
		}
	}
	var canonical []byte
	var buildErr error
	if derived {
		canonical, buildErr = buildCanonicalTarV2(files)
	} else {
		canonical, buildErr = buildCanonicalTar(files, hasSBOM)
	}
	if buildErr != nil || !bytes.Equal(bundle, canonical) {
		return nil, false, fmt.Errorf("non-canonical tar bytes")
	}
	return files, hasSBOM, nil
}

func validBundlePath(name string) bool {
	if name == "" || name != path.Clean(name) || path.IsAbs(name) ||
		strings.Contains(name, "\\") || strings.Contains(name, ":") ||
		strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return false
	}
	for _, allowed := range bundlePathsV2() {
		if name == allowed {
			return true
		}
	}
	return false
}

func decodeCanonicalJSON(raw []byte, maximum int, destination any) error {
	if len(raw) == 0 || len(raw) > maximum {
		return fmt.Errorf("JSON size")
	}
	limits := structuredjson.DecodeLimits{
		MaxBytes: maximum,
		MaxDepth: 128,
		MaxNodes: 500_000,
	}
	if _, err := structuredjson.Decode(raw, limits); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("JSON trailing data")
	}
	canonical, err := canonicaljson.Marshal(destination)
	if err != nil || !bytes.Equal(raw, canonical) {
		return fmt.Errorf("non-canonical JSON")
	}
	return nil
}

func marshalPublicKey(publicKey ed25519.PublicKey) ([]byte, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if len(encoded) == 0 || len(encoded) > MaxPublicKeyBytes {
		return nil, nil, fmt.Errorf("public key PEM")
	}
	return encoded, der, nil
}

func parsePublicKey(raw []byte) (ed25519.PublicKey, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxPublicKeyBytes {
		return nil, nil, fmt.Errorf("public key size")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, nil, fmt.Errorf("public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("public key algorithm")
	}
	canonicalPEM, canonicalDER, err := marshalPublicKey(publicKey)
	if err != nil || !bytes.Equal(raw, canonicalPEM) || !bytes.Equal(block.Bytes, canonicalDER) {
		return nil, nil, fmt.Errorf("non-canonical public key")
	}
	return publicKey, canonicalDER, nil
}

func pae(payloadType string, payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len([]byte(payloadType))) + " " + payloadType + " " +
		strconv.Itoa(len(payload)) + " "
	message := make([]byte, 0, len(prefix)+len(payload))
	message = append(message, prefix...)
	return append(message, payload...)
}

func decodeBase64Bounded(value string, maximum int) ([]byte, error) {
	if len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, fmt.Errorf("base64 size")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maximum {
		return nil, fmt.Errorf("base64 encoding")
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("non-canonical base64")
	}
	return decoded, nil
}

func digestBytes(value []byte) string {
	return "sha256:" + rawDigestBytes(value)
}

func rawDigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func invalidError() error {
	return domain.NewError(
		domain.CodeAttestationInvalid,
		domain.SeverityCritical,
		"The attestation bundle is invalid or its protected content does not match.",
	)
}

func untrustedError(message string) error {
	return domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityHigh, message)
}

func untrustedSignatureError(message, decision string) error {
	err := domain.NewError(domain.CodeAttestationUntrusted, domain.SeverityHigh, message)
	err.Details = map[string]any{
		"signatureValid": true,
		"trustDecision":  decision,
	}
	return err
}

func untrustedPolicyError(message, reason string) error {
	err := untrustedSignatureError(message, "rejected")
	typed, ok := err.(*domain.Error)
	if ok {
		typed.Details["trustBasis"] = "offline-policy-v1"
		typed.Details["trustReason"] = reason
	}
	return err
}

func signedOfflineTrustPolicyUnavailableError() error {
	err := untrustedSignatureError("The signed offline trust policy is invalid or unavailable.", "rejected")
	typed := err.(*domain.Error)
	typed.Details["trustBasis"] = "signed-offline-policy-v2"
	typed.Details["trustReason"] = "invalid-or-unavailable"
	return err
}

func signedOfflineTrustPolicyGenerationError() error {
	err := untrustedSignatureError("The signed offline trust policy generation is below the requested minimum.", "rejected")
	typed := err.(*domain.Error)
	typed.Details["trustBasis"] = "signed-offline-policy-v2"
	typed.Details["trustReason"] = "generation-below-minimum"
	return err
}

func signedOfflineTrustPolicyDecisionError(message, reason string) error {
	err := untrustedSignatureError(message, "rejected")
	typed := err.(*domain.Error)
	typed.Details["trustBasis"] = "signed-offline-policy-v2"
	typed.Details["trustReason"] = reason
	return err
}

func signingError(message string) error {
	return domain.NewError(domain.CodeSigningFailed, domain.SeverityHigh, message)
}

func buildError(message string) error {
	return domain.NewError(domain.CodeEvidenceBuildFailed, domain.SeverityHigh, message)
}

func fixedBundlePaths() [5]string {
	return [5]string{
		attestationPath,
		manifestPath,
		verificationPath,
		signaturePath,
		publicKeyPath,
	}
}

func bundlePaths(hasSBOM bool) []string {
	if hasSBOM {
		return []string{attestationPath, manifestPath, verificationPath, sbomPath, signaturePath, publicKeyPath}
	}
	paths := fixedBundlePaths()
	return paths[:]
}

func bundlePathsV2() []string {
	return []string{
		attestationPath, manifestPath, provenancePath, sbomPath,
		verificationPath, signaturePath, publicKeyPath,
	}
}

func bundleFileLimit(name string) (int64, bool) {
	switch name {
	case attestationPath, manifestPath, signaturePath:
		return MaxJSONBytes, true
	case verificationPath:
		return MaxVerificationBytes, true
	case sbomPath:
		return spdx.MaxBytes, true
	case provenancePath:
		return int64(spdx.MaxJSONBytesForDerived()), true
	case publicKeyPath:
		return MaxPublicKeyBytes, true
	default:
		return 0, false
	}
}

func planSelectsSBOM(plan domain.VerificationPlanRef) bool {
	if plan.ResolvedPlanSchemaVersion != "4" || plan.Evidence.Profile != "minimal-public" {
		return false
	}
	for _, item := range plan.Evidence.Include {
		if item == "sbom" {
			return true
		}
	}
	return false
}
