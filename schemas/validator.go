package schemas

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	schemaBaseURL                                          = "https://schemas.repopass.dev/v1alpha1/"
	manifestSchemaURL                                      = schemaBaseURL + "repo-passport.schema.json"
	verificationSchemaURL                                  = schemaBaseURL + "verification.schema.json"
	MaxVerificationJSONBytes                               = 16 << 20
	MaxOfflineTrustPolicyJSONBytes                         = 64 << 10
	MaxReleaseIndexJSONBytes                               = 1 << 20
	MaxReleaseKeyPolicyJSONBytes                           = 64 << 10
	MaxReleaseAuthorityTransitionJSONBytes                 = 16 << 10
	MaxReleaseAuthorityTransitionChainJSONBytes            = 256 << 10
	MaxOfflineTrustPolicyAuthorityTransitionJSONBytes      = 16 << 10
	MaxOfflineTrustPolicyAuthorityTransitionChainJSONBytes = 256 << 10
	MaxSourceArchiveManifestV1JSONBytes                    = 16 << 20
	MaxSourceQualificationReceiptV1JSONBytes               = 1 << 20
	MaxSourceQualificationToolManifestV1JSONBytes          = 64 << 10
	verificationMaxDepth                                   = 128
	verificationMaxNodes                                   = 500_000
)

//go:embed repo-passport.schema.json
var manifestSchemaDocument []byte

//go:embed observation.schema.json
var observationSchemaDocument []byte

//go:embed assertion.schema.json
var assertionSchemaDocument []byte

//go:embed error.schema.json
var errorSchemaDocument []byte

//go:embed verification.schema.json
var verificationSchemaDocument []byte

//go:embed bundle-manifest-v2.schema.json
var bundleManifestV2SchemaDocument []byte

//go:embed attestation-v2.schema.json
var attestationV2SchemaDocument []byte

//go:embed spdx-derived-v1.schema.json
var spdxDerivedV1SchemaDocument []byte

//go:embed sbom-provenance-v1.schema.json
var sbomProvenanceV1SchemaDocument []byte

//go:embed offline-trust-policy-v1.schema.json
var offlineTrustPolicyV1SchemaDocument []byte

//go:embed offline-trust-policy-v2.schema.json
var offlineTrustPolicyV2SchemaDocument []byte

//go:embed offline-trust-policy-v2-envelope.schema.json
var offlineTrustPolicyV2EnvelopeSchemaDocument []byte

//go:embed offline-trust-policy-authority-transition-v1.schema.json
var offlineTrustPolicyAuthorityTransitionV1SchemaDocument []byte

//go:embed offline-trust-policy-authority-transition-envelope-v1.schema.json
var offlineTrustPolicyAuthorityTransitionEnvelopeV1SchemaDocument []byte

//go:embed offline-trust-policy-authority-transition-chain-v1.schema.json
var offlineTrustPolicyAuthorityTransitionChainV1SchemaDocument []byte

//go:embed release-index-v1.schema.json
var releaseIndexV1SchemaDocument []byte

//go:embed release-index-envelope-v1.schema.json
var releaseIndexEnvelopeV1SchemaDocument []byte

//go:embed release-key-policy-v1.schema.json
var releaseKeyPolicyV1SchemaDocument []byte

//go:embed release-key-policy-envelope-v1.schema.json
var releaseKeyPolicyEnvelopeV1SchemaDocument []byte

//go:embed release-authority-transition-v1.schema.json
var releaseAuthorityTransitionV1SchemaDocument []byte

//go:embed release-authority-transition-envelope-v1.schema.json
var releaseAuthorityTransitionEnvelopeV1SchemaDocument []byte

//go:embed release-authority-transition-chain-v1.schema.json
var releaseAuthorityTransitionChainV1SchemaDocument []byte

//go:embed source-archive-manifest-v1.schema.json
var sourceArchiveManifestV1SchemaDocument []byte

//go:embed source-qualification-receipt-v1.schema.json
var sourceQualificationReceiptV1SchemaDocument []byte

//go:embed source-qualification-tool-manifest-v1.schema.json
var sourceQualificationToolManifestV1SchemaDocument []byte

var (
	manifestSchemaOnce sync.Once
	manifestSchema     *jsonschema.Schema
	manifestSchemaErr  error

	verificationSchemaOnce sync.Once
	verificationSchema     *jsonschema.Schema
	verificationSchemaErr  error

	derivedSchemasOnce sync.Once
	derivedSchemas     map[string]*jsonschema.Schema
	derivedSchemasErr  error
)

// ValidateManifest validates a normalized YAML/JSON data model against the
// exact public manifest schema embedded in the CLI.
func ValidateManifest(value any) error {
	manifestSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(manifestSchemaDocument))
		if err != nil {
			manifestSchemaErr = fmt.Errorf("decode embedded manifest schema: %w", err)
			return
		}
		if err := compiler.AddResource(manifestSchemaURL, document); err != nil {
			manifestSchemaErr = fmt.Errorf("register embedded manifest schema: %w", err)
			return
		}
		manifestSchema, manifestSchemaErr = compiler.Compile(manifestSchemaURL)
		if manifestSchemaErr != nil {
			manifestSchemaErr = fmt.Errorf("compile embedded manifest schema: %w", manifestSchemaErr)
		}
	})
	if manifestSchemaErr != nil {
		return manifestSchemaErr
	}
	if err := manifestSchema.Validate(value); err != nil {
		return fmt.Errorf("manifest schema validation: %w", err)
	}
	return nil
}

// ValidateVerificationJSON strictly parses and validates one bounded public
// verification artifact. Duplicate object keys, invalid UTF-8, trailing data,
// excessive depth/node count, unknown fields, and invalid referenced
// observation/assertion/error objects are rejected before the artifact can be
// used as signing input or trusted offline evidence.
func ValidateVerificationJSON(raw []byte) error {
	limits := structuredjson.DecodeLimits{
		MaxBytes: MaxVerificationJSONBytes,
		MaxDepth: verificationMaxDepth,
		MaxNodes: verificationMaxNodes,
	}
	value, err := structuredjson.Decode(raw, limits)
	if err != nil {
		return fmt.Errorf("strict verification JSON decode: %w", err)
	}
	if err := loadVerificationSchema(); err != nil {
		return err
	}
	if err := verificationSchema.Validate(value); err != nil {
		return fmt.Errorf("verification schema validation: %w", err)
	}
	return nil
}

func loadVerificationSchema() error {
	verificationSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		for _, item := range []struct {
			name string
			raw  []byte
		}{
			{"observation.schema.json", observationSchemaDocument},
			{"assertion.schema.json", assertionSchemaDocument},
			{"error.schema.json", errorSchemaDocument},
			{"verification.schema.json", verificationSchemaDocument},
		} {
			document, err := jsonschema.UnmarshalJSON(bytes.NewReader(item.raw))
			if err != nil {
				verificationSchemaErr = fmt.Errorf(
					"decode embedded %s: %w",
					item.name,
					err,
				)
				return
			}
			if err := compiler.AddResource(schemaBaseURL+item.name, document); err != nil {
				verificationSchemaErr = fmt.Errorf(
					"register embedded %s: %w",
					item.name,
					err,
				)
				return
			}
		}
		verificationSchema, verificationSchemaErr = compiler.Compile(
			verificationSchemaURL,
		)
		if verificationSchemaErr != nil {
			verificationSchemaErr = fmt.Errorf(
				"compile embedded verification schema: %w",
				verificationSchemaErr,
			)
		}
	})
	return verificationSchemaErr
}

func ValidateBundleManifestV2JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 1<<20, 64, 65_536, "bundle-manifest-v2.schema.json")
}

func ValidateAttestationV2JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 1<<20, 128, 500_000, "attestation-v2.schema.json")
}

func ValidateDerivedSPDXJSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 1<<20, 64, 65_536, "spdx-derived-v1.schema.json")
}

func ValidateSBOMProvenanceV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 16<<10, 16, 128, "sbom-provenance-v1.schema.json")
}

// ValidateOfflineTrustPolicyV1JSON strictly decodes and validates the bounded
// public policy shape. Canonical-byte equality and ordinal key ordering are
// additionally enforced by attestation.ParseOfflineTrustPolicy.
func ValidateOfflineTrustPolicyV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxOfflineTrustPolicyJSONBytes, 8, 256, "offline-trust-policy-v1.schema.json")
}

// ValidateOfflineTrustPolicyV2JSON strictly validates the authenticated v2
// payload shape. Canonical-byte equality and ordinal key ordering remain an
// attestation concern, after DSSE authentication has succeeded.
func ValidateOfflineTrustPolicyV2JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxOfflineTrustPolicyJSONBytes, 8, 256, "offline-trust-policy-v2.schema.json")
}

// ValidateOfflineTrustPolicyV2EnvelopeJSON validates the bounded dedicated
// single-signature DSSE envelope before it is decoded by the verifier.
func ValidateOfflineTrustPolicyV2EnvelopeJSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 96<<10, 8, 64, "offline-trust-policy-v2-envelope.schema.json")
}

// ValidateOfflineTrustPolicyAuthorityTransitionV1JSON strictly validates the
// bounded old-root-authorized offline policy-authority transition payload.
func ValidateOfflineTrustPolicyAuthorityTransitionV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxOfflineTrustPolicyAuthorityTransitionJSONBytes, 8, 64, "offline-trust-policy-authority-transition-v1.schema.json")
}

// ValidateOfflineTrustPolicyAuthorityTransitionEnvelopeV1JSON validates the
// dedicated single-signature DSSE transition envelope before authentication.
func ValidateOfflineTrustPolicyAuthorityTransitionEnvelopeV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 32<<10, 8, 64, "offline-trust-policy-authority-transition-envelope-v1.schema.json")
}

// ValidateOfflineTrustPolicyAuthorityTransitionChainV1JSON strictly validates
// the bounded unsigned chain transport before any embedded key or envelope is
// used.
func ValidateOfflineTrustPolicyAuthorityTransitionChainV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxOfflineTrustPolicyAuthorityTransitionChainJSONBytes, 8, 64, "offline-trust-policy-authority-transition-chain-v1.schema.json")
}

// ValidateReleaseIndexV1JSON strictly validates the bounded external release
// index payload. Canonical-byte equality, ordinal/case-fold ordering, and the
// exact artifact-root inventory are enforced by the release verifier.
func ValidateReleaseIndexV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxReleaseIndexJSONBytes, 16, 1_024, "release-index-v1.schema.json")
}

// ValidateReleaseIndexEnvelopeV1JSON validates the bounded dedicated
// single-signature DSSE envelope before release-index authentication.
func ValidateReleaseIndexEnvelopeV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 1400<<10, 8, 64, "release-index-envelope-v1.schema.json")
}

// ValidateReleaseKeyPolicyV1JSON strictly validates the authenticated bounded
// release-index signer authorization policy shape.
func ValidateReleaseKeyPolicyV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxReleaseKeyPolicyJSONBytes, 8, 256, "release-key-policy-v1.schema.json")
}

// ValidateReleaseKeyPolicyEnvelopeV1JSON validates the bounded dedicated
// single-signature DSSE envelope before release-key-policy authentication.
func ValidateReleaseKeyPolicyEnvelopeV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 96<<10, 8, 64, "release-key-policy-envelope-v1.schema.json")
}

// ValidateReleaseAuthorityTransitionV1JSON strictly validates the bounded
// old-root-authorized policy-authority transition payload shape.
func ValidateReleaseAuthorityTransitionV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxReleaseAuthorityTransitionJSONBytes, 8, 64, "release-authority-transition-v1.schema.json")
}

// ValidateReleaseAuthorityTransitionEnvelopeV1JSON validates the bounded
// dedicated single-signature DSSE transition envelope before authentication.
func ValidateReleaseAuthorityTransitionEnvelopeV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, 32<<10, 8, 64, "release-authority-transition-envelope-v1.schema.json")
}

// ValidateReleaseAuthorityTransitionChainV1JSON strictly validates the
// bounded unsigned chain transport before any embedded key or envelope is used.
func ValidateReleaseAuthorityTransitionChainV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxReleaseAuthorityTransitionChainJSONBytes, 8, 64, "release-authority-transition-chain-v1.schema.json")
}

// ValidateSourceArchiveManifestV1JSON validates the bounded public source
// archive manifest transport. Canonical bytes and Git-tree reconstruction are
// enforced by the source-qualification controller.
func ValidateSourceArchiveManifestV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxSourceArchiveManifestV1JSONBytes, 16, 200_000, "source-archive-manifest-v1.schema.json")
}

// ValidateSourceQualificationReceiptV1JSON validates one bounded public
// platform receipt before semantic run, gate, privacy, and cross-lane checks.
func ValidateSourceQualificationReceiptV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxSourceQualificationReceiptV1JSONBytes, 16, 32_768, "source-qualification-receipt-v1.schema.json")
}

// ValidateSourceQualificationToolManifestV1JSON validates the bounded
// producer-owned offline controller tool manifest transport.
func ValidateSourceQualificationToolManifestV1JSON(raw []byte) error {
	return validateDerivedSchemaJSON(raw, MaxSourceQualificationToolManifestV1JSONBytes, 8, 256, "source-qualification-tool-manifest-v1.schema.json")
}

func validateDerivedSchemaJSON(raw []byte, maxBytes, maxDepth, maxNodes int, name string) error {
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: maxBytes, MaxDepth: maxDepth, MaxNodes: maxNodes,
	})
	if err != nil {
		return fmt.Errorf("strict derived JSON decode: %w", err)
	}
	if err := loadDerivedSchemas(); err != nil {
		return err
	}
	schema, ok := derivedSchemas[name]
	if !ok {
		return fmt.Errorf("derived schema %s is unavailable", name)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("%s validation: %w", name, err)
	}
	return nil
}

func loadDerivedSchemas() error {
	derivedSchemasOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		documents := []struct {
			name string
			raw  []byte
		}{
			{"observation.schema.json", observationSchemaDocument},
			{"assertion.schema.json", assertionSchemaDocument},
			{"error.schema.json", errorSchemaDocument},
			{"verification.schema.json", verificationSchemaDocument},
			{"bundle-manifest-v2.schema.json", bundleManifestV2SchemaDocument},
			{"attestation-v2.schema.json", attestationV2SchemaDocument},
			{"spdx-derived-v1.schema.json", spdxDerivedV1SchemaDocument},
			{"sbom-provenance-v1.schema.json", sbomProvenanceV1SchemaDocument},
			{"offline-trust-policy-v1.schema.json", offlineTrustPolicyV1SchemaDocument},
			{"offline-trust-policy-v2.schema.json", offlineTrustPolicyV2SchemaDocument},
			{"offline-trust-policy-v2-envelope.schema.json", offlineTrustPolicyV2EnvelopeSchemaDocument},
			{"offline-trust-policy-authority-transition-v1.schema.json", offlineTrustPolicyAuthorityTransitionV1SchemaDocument},
			{"offline-trust-policy-authority-transition-envelope-v1.schema.json", offlineTrustPolicyAuthorityTransitionEnvelopeV1SchemaDocument},
			{"offline-trust-policy-authority-transition-chain-v1.schema.json", offlineTrustPolicyAuthorityTransitionChainV1SchemaDocument},
			{"release-index-v1.schema.json", releaseIndexV1SchemaDocument},
			{"release-index-envelope-v1.schema.json", releaseIndexEnvelopeV1SchemaDocument},
			{"release-key-policy-v1.schema.json", releaseKeyPolicyV1SchemaDocument},
			{"release-key-policy-envelope-v1.schema.json", releaseKeyPolicyEnvelopeV1SchemaDocument},
			{"release-authority-transition-v1.schema.json", releaseAuthorityTransitionV1SchemaDocument},
			{"release-authority-transition-envelope-v1.schema.json", releaseAuthorityTransitionEnvelopeV1SchemaDocument},
			{"release-authority-transition-chain-v1.schema.json", releaseAuthorityTransitionChainV1SchemaDocument},
			{"source-archive-manifest-v1.schema.json", sourceArchiveManifestV1SchemaDocument},
			{"source-qualification-receipt-v1.schema.json", sourceQualificationReceiptV1SchemaDocument},
			{"source-qualification-tool-manifest-v1.schema.json", sourceQualificationToolManifestV1SchemaDocument},
		}
		for _, item := range documents {
			document, err := jsonschema.UnmarshalJSON(bytes.NewReader(item.raw))
			if err != nil {
				derivedSchemasErr = fmt.Errorf("decode embedded %s: %w", item.name, err)
				return
			}
			if err := compiler.AddResource(schemaBaseURL+item.name, document); err != nil {
				derivedSchemasErr = fmt.Errorf("register embedded %s: %w", item.name, err)
				return
			}
		}
		derivedSchemas = make(map[string]*jsonschema.Schema, 16)
		for _, name := range []string{
			"bundle-manifest-v2.schema.json", "attestation-v2.schema.json",
			"spdx-derived-v1.schema.json", "sbom-provenance-v1.schema.json",
			"offline-trust-policy-v1.schema.json",
			"offline-trust-policy-v2.schema.json", "offline-trust-policy-v2-envelope.schema.json",
			"offline-trust-policy-authority-transition-v1.schema.json", "offline-trust-policy-authority-transition-envelope-v1.schema.json",
			"offline-trust-policy-authority-transition-chain-v1.schema.json",
			"release-index-v1.schema.json", "release-index-envelope-v1.schema.json",
			"release-key-policy-v1.schema.json", "release-key-policy-envelope-v1.schema.json",
			"release-authority-transition-v1.schema.json", "release-authority-transition-envelope-v1.schema.json",
			"release-authority-transition-chain-v1.schema.json",
			"source-archive-manifest-v1.schema.json",
			"source-qualification-receipt-v1.schema.json",
			"source-qualification-tool-manifest-v1.schema.json",
		} {
			compiled, err := compiler.Compile(schemaBaseURL + name)
			if err != nil {
				derivedSchemasErr = fmt.Errorf("compile embedded %s: %w", name, err)
				return
			}
			derivedSchemas[name] = compiled
		}
	})
	return derivedSchemasErr
}
