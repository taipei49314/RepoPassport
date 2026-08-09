package cli

import (
	"strconv"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

type signedTrustPolicyAuthorityRotationCLIOptions struct {
	Enabled             bool
	TransitionPath      string
	TransitionChainPath string
	TrustRootPath       string
	MinimumGeneration   uint64
	Chain               bool
}

// validateSignedTrustPolicyAuthorityRotationArgs resolves the optional
// one-hop authority-rotation group before any bundle or trust-input I/O. The
// group is valid only as an extension of the complete signed-policy mode.
func validateSignedTrustPolicyAuthorityRotationArgs(args []string, signedPolicyEnabled bool) (signedTrustPolicyAuthorityRotationCLIOptions, error) {
	if trustPolicyAuthorityRotationFlagAfterSeparator(args) {
		return signedTrustPolicyAuthorityRotationCLIOptions{}, invalidSignedTrustPolicyAuthorityRotationFlags()
	}
	transitionCount, transitionPath, transitionOK := strictValueFlag(args, "trust-policy-authority-transition")
	chainCount, chainPath, chainOK := strictValueFlag(args, "trust-policy-authority-transition-chain")
	rootCount, rootPath, rootOK := strictValueFlag(args, "trust-policy-authority-trust-root")
	minimumCount, minimumRaw, minimumOK := strictValueFlag(args, "minimum-trust-policy-authority-generation")
	if !transitionOK || !chainOK || !rootOK || !minimumOK {
		return signedTrustPolicyAuthorityRotationCLIOptions{}, invalidSignedTrustPolicyAuthorityRotationFlags()
	}
	if transitionCount == 0 && chainCount == 0 && rootCount == 0 && minimumCount == 0 {
		return signedTrustPolicyAuthorityRotationCLIOptions{}, nil
	}
	if !signedPolicyEnabled || (transitionCount == chainCount) || transitionCount > 1 || chainCount > 1 ||
		rootCount != 1 || minimumCount != 1 || rootPath == "" ||
		(transitionCount == 1 && transitionPath == "") || (chainCount == 1 && chainPath == "") ||
		!canonicalTrustPolicyGeneration(minimumRaw) {
		return signedTrustPolicyAuthorityRotationCLIOptions{}, invalidSignedTrustPolicyAuthorityRotationFlags()
	}
	minimum, err := strconv.ParseUint(minimumRaw, 10, 64)
	if err != nil || minimum == 0 || minimum > attestation.MaxTrustPolicyGeneration {
		return signedTrustPolicyAuthorityRotationCLIOptions{}, invalidSignedTrustPolicyAuthorityRotationFlags()
	}
	return signedTrustPolicyAuthorityRotationCLIOptions{
		Enabled:             true,
		TransitionPath:      transitionPath,
		TransitionChainPath: chainPath,
		TrustRootPath:       rootPath,
		MinimumGeneration:   minimum,
		Chain:               chainCount == 1,
	}, nil
}

func trustPolicyAuthorityRotationFlagAfterSeparator(args []string) bool {
	afterSeparator := false
	for _, argument := range args {
		if argument == "--" {
			afterSeparator = true
			continue
		}
		if !afterSeparator || !strings.HasPrefix(argument, "-") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		if strings.HasPrefix(strings.ToLower(name), "trust-policy-authority-") || strings.HasPrefix(strings.ToLower(name), "minimum-trust-policy-authority-") {
			return true
		}
	}
	return false
}

func canonicalTrustPolicyGeneration(raw string) bool {
	if raw == "" || strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") || strings.TrimSpace(raw) != raw || (len(raw) > 1 && raw[0] == '0') {
		return false
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	return err == nil && value > 0 && value <= attestation.MaxTrustPolicyGeneration && strconv.FormatUint(value, 10) == raw
}

func invalidSignedTrustPolicyAuthorityRotationFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"Signed offline trust-policy authority rotation requires exactly one of --trust-policy-authority-transition or --trust-policy-authority-transition-chain, plus exactly one non-empty --trust-policy-authority-trust-root and canonical --minimum-trust-policy-authority-generation in complete signed-policy mode.")
}
