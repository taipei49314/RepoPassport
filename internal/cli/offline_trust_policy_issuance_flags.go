package cli

import (
	"strings"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
)

const maxOfflineTrustPolicyCLIKeys = 32

type offlineTrustPolicySignerInput struct {
	Path     string
	Decision attestation.TrustDecision
}

type signOfflineTrustPolicyCLIOptions struct {
	Generation      uint64
	SignerKeys      []offlineTrustPolicySignerInput
	KeyPath         string
	OutputDirectory string
}

func validateSignOfflineTrustPolicyArgs(args []string) (signOfflineTrustPolicyCLIOptions, error) {
	var options signOfflineTrustPolicyCLIOptions
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") || argument == "--" || len(argument) <= 2 {
			return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, inline, hasInline := strings.Cut(nameValue, "=")
		if name != "generation" && name != "trusted-signer-key" && name != "revoked-signer-key" && name != "key" && name != "out-dir" {
			return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
		}
		value := inline
		if !hasInline {
			index++
			if index >= len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") {
				return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
			}
			value = args[index]
		}
		if value == "" {
			return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
		}
		switch name {
		case "trusted-signer-key", "revoked-signer-key":
			decision := attestation.TrustDecisionTrusted
			if name == "revoked-signer-key" {
				decision = attestation.TrustDecisionRevoked
			}
			options.SignerKeys = append(options.SignerKeys, offlineTrustPolicySignerInput{Path: value, Decision: decision})
			if len(options.SignerKeys) > maxOfflineTrustPolicyCLIKeys {
				return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
			}
		case "generation":
			if seen[name] {
				return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
			}
			generation, ok := parseCanonicalReleaseGeneration(value)
			if !ok || generation > attestation.MaxTrustPolicyGeneration {
				return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
			}
			options.Generation = generation
		case "key":
			if seen[name] {
				return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
			}
			options.KeyPath = value
		case "out-dir":
			if seen[name] {
				return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
			}
			options.OutputDirectory = value
		}
		seen[name] = true
	}
	if options.Generation == 0 || options.KeyPath == "" || options.OutputDirectory == "" || len(options.SignerKeys) == 0 {
		return signOfflineTrustPolicyCLIOptions{}, invalidSignOfflineTrustPolicyFlags()
	}
	return options, nil
}

func invalidSignOfflineTrustPolicyFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"sign-offline-trust-policy requires exactly one non-empty canonical --generation, --key, and --out-dir, plus 1 through 32 combined --trusted-signer-key or --revoked-signer-key values.")
}
