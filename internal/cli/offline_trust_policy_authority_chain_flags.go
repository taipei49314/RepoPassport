package cli

import (
	"strings"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
)

type assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions struct {
	HopEnvelopePaths     []string
	HopNextAuthorityKeys []string
	AuthorityTrustRoot   string
	MinimumGeneration    uint64
	OutputDirectory      string
}

// validateAssembleOfflineTrustPolicyAuthorityTransitionChainArgs owns the
// complete repeated-pair producer shape before any caller-controlled path is
// opened. Ordered envelope and next-key occurrences are paired by index.
func validateAssembleOfflineTrustPolicyAuthorityTransitionChainArgs(args []string) (assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions, error) {
	var options assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") || argument == "--" || len(argument) <= 2 {
			return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, inline, hasInline := strings.Cut(nameValue, "=")
		if name != "hop-envelope" && name != "hop-next-authority-key" &&
			name != "trust-policy-authority-trust-root" &&
			name != "minimum-trust-policy-authority-generation" && name != "out-dir" {
			return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
		}
		value := inline
		if !hasInline {
			index++
			if index >= len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") {
				return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
			}
			value = args[index]
		}
		if value == "" {
			return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
		}
		switch name {
		case "hop-envelope":
			options.HopEnvelopePaths = append(options.HopEnvelopePaths, value)
		case "hop-next-authority-key":
			options.HopNextAuthorityKeys = append(options.HopNextAuthorityKeys, value)
		case "trust-policy-authority-trust-root":
			if seen[name] {
				return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
			}
			options.AuthorityTrustRoot = value
		case "minimum-trust-policy-authority-generation":
			if seen[name] || !canonicalTrustPolicyGeneration(value) {
				return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
			}
			generation, ok := parseCanonicalReleaseGeneration(value)
			if !ok || generation > attestation.MaxTrustPolicyGeneration {
				return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
			}
			options.MinimumGeneration = generation
		case "out-dir":
			if seen[name] {
				return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
			}
			options.OutputDirectory = value
		}
		seen[name] = true
	}
	if len(options.HopEnvelopePaths) < 2 || len(options.HopEnvelopePaths) > 8 ||
		len(options.HopEnvelopePaths) != len(options.HopNextAuthorityKeys) ||
		options.AuthorityTrustRoot == "" || options.MinimumGeneration == 0 || options.OutputDirectory == "" {
		return assembleOfflineTrustPolicyAuthorityTransitionChainCLIOptions{}, invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags()
	}
	return options, nil
}

func invalidAssembleOfflineTrustPolicyAuthorityTransitionChainFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"assemble-offline-trust-policy-authority-transition-chain requires 2 through 8 ordered --hop-envelope values, the same count of --hop-next-authority-key values, and exactly one non-empty --trust-policy-authority-trust-root, canonical --minimum-trust-policy-authority-generation, and --out-dir.")
}
