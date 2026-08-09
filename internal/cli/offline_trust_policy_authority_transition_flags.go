package cli

import (
	"strings"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

type signOfflineTrustPolicyAuthorityTransitionCLIOptions struct {
	NextAuthorityKeyPath string
	Generation           uint64
	KeyPath              string
	OutputDirectory      string
}

// validateSignOfflineTrustPolicyAuthorityTransitionArgs owns the complete
// command shape before any caller-controlled path is opened. This producer is
// intentionally single-hop: repeated flags are never an implicit chain.
func validateSignOfflineTrustPolicyAuthorityTransitionArgs(args []string) (signOfflineTrustPolicyAuthorityTransitionCLIOptions, error) {
	var options signOfflineTrustPolicyAuthorityTransitionCLIOptions
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") || argument == "--" || len(argument) <= 2 {
			return signOfflineTrustPolicyAuthorityTransitionCLIOptions{}, invalidSignOfflineTrustPolicyAuthorityTransitionFlags()
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, inline, hasInline := strings.Cut(nameValue, "=")
		if name != "next-authority-key" && name != "generation" && name != "key" && name != "out-dir" || seen[name] {
			return signOfflineTrustPolicyAuthorityTransitionCLIOptions{}, invalidSignOfflineTrustPolicyAuthorityTransitionFlags()
		}
		value := inline
		if !hasInline {
			index++
			if index >= len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") {
				return signOfflineTrustPolicyAuthorityTransitionCLIOptions{}, invalidSignOfflineTrustPolicyAuthorityTransitionFlags()
			}
			value = args[index]
		}
		if value == "" {
			return signOfflineTrustPolicyAuthorityTransitionCLIOptions{}, invalidSignOfflineTrustPolicyAuthorityTransitionFlags()
		}
		switch name {
		case "next-authority-key":
			options.NextAuthorityKeyPath = value
		case "generation":
			generation, ok := parseCanonicalReleaseGeneration(value)
			if !ok || generation > attestation.MaxTrustPolicyGeneration {
				return signOfflineTrustPolicyAuthorityTransitionCLIOptions{}, invalidSignOfflineTrustPolicyAuthorityTransitionFlags()
			}
			options.Generation = generation
		case "key":
			options.KeyPath = value
		case "out-dir":
			options.OutputDirectory = value
		}
		seen[name] = true
	}
	if options.NextAuthorityKeyPath == "" || options.Generation == 0 || options.KeyPath == "" || options.OutputDirectory == "" {
		return signOfflineTrustPolicyAuthorityTransitionCLIOptions{}, invalidSignOfflineTrustPolicyAuthorityTransitionFlags()
	}
	return options, nil
}

func invalidSignOfflineTrustPolicyAuthorityTransitionFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"sign-offline-trust-policy-authority-transition requires exactly one non-empty --next-authority-key, canonical --generation, --key, and --out-dir.")
}
