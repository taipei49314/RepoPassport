package cli

import (
	"strconv"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/releaseindex"
)

type signReleaseIndexCLIOptions struct {
	ArtifactRoot      string
	ProductVersion    string
	ReleaseGeneration uint64
	KeyPath           string
	OutputDirectory   string
}

type signReleasePolicyCLIOptions struct {
	PolicyPath      string
	KeyPath         string
	OutputDirectory string
}

type signReleaseAuthorityTransitionCLIOptions struct {
	NextAuthorityKeyPath string
	Generation           uint64
	Product              string
	Channel              string
	KeyPath              string
	OutputDirectory      string
}

type assembleReleaseAuthorityTransitionChainCLIOptions struct {
	HopEnvelopePaths     []string
	HopNextAuthorityKeys []string
	AuthorityTrustRoot   string
	Product              string
	Channel              string
	MinimumGeneration    uint64
	OutputDirectory      string
}

type verifyReleaseIndexCLIOptions struct {
	IndexPath                    string
	SignaturePath                string
	SignerKeyPath                string
	ArtifactRoot                 string
	PolicyEnvelopePath           string
	PolicyAuthorityKeyPath       string
	Product                      string
	Channel                      string
	MinimumPolicyGeneration      uint64
	MinimumReleaseGeneration     uint64
	PersistState                 bool
	ExpectedIndexDigest          string
	AuthorityTransitionPath      string
	AuthorityTransitionChainPath string
	AuthorityTrustRootPath       string
	MinimumAuthorityGeneration   uint64
	Rotation                     bool
	Chain                        bool
}

func validateAssembleReleaseAuthorityTransitionChainArgs(args []string) (assembleReleaseAuthorityTransitionChainCLIOptions, error) {
	// This command deliberately has a dedicated parser: repeated ordered hop
	// flags are part of the signed transport and must be shape-checked before
	// any caller-controlled path is read.
	var options assembleReleaseAuthorityTransitionChainCLIOptions
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") || argument == "--" || len(argument) <= 2 {
			return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, inline, hasInline := strings.Cut(nameValue, "=")
		if name != "hop-envelope" && name != "hop-next-authority-key" && name != "authority-trust-root" && name != "product" && name != "channel" && name != "minimum-authority-generation" && name != "out-dir" {
			return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
		}
		value := inline
		if !hasInline {
			index++
			if index >= len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			value = args[index]
		}
		if value == "" {
			return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
		}
		switch name {
		case "hop-envelope":
			options.HopEnvelopePaths = append(options.HopEnvelopePaths, value)
		case "hop-next-authority-key":
			options.HopNextAuthorityKeys = append(options.HopNextAuthorityKeys, value)
		case "authority-trust-root":
			if seen[name] {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			options.AuthorityTrustRoot = value
		case "product":
			if seen[name] {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			options.Product = value
		case "channel":
			if seen[name] {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			options.Channel = value
		case "minimum-authority-generation":
			if seen[name] {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			generation, ok := parseCanonicalReleaseGeneration(value)
			if !ok {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			options.MinimumGeneration = generation
		case "out-dir":
			if seen[name] {
				return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
			}
			options.OutputDirectory = value
		}
		seen[name] = true
	}
	if len(options.HopEnvelopePaths) < 2 || len(options.HopEnvelopePaths) > 8 || len(options.HopEnvelopePaths) != len(options.HopNextAuthorityKeys) ||
		options.AuthorityTrustRoot == "" || options.Product != releaseindex.Product || options.Channel != releaseindex.Channel || options.MinimumGeneration == 0 || options.OutputDirectory == "" {
		return assembleReleaseAuthorityTransitionChainCLIOptions{}, invalidAssembleReleaseAuthorityTransitionChainFlags()
	}
	return options, nil
}

func validateSignReleaseAuthorityTransitionArgs(args []string) (signReleaseAuthorityTransitionCLIOptions, error) {
	values, _, err := parseExactReleaseFlags(args, []string{
		"next-authority-key", "generation", "product", "channel", "key", "out-dir",
	}, nil)
	if err != nil || len(values) != 6 {
		return signReleaseAuthorityTransitionCLIOptions{}, invalidSignReleaseAuthorityTransitionFlags()
	}
	generation, ok := parseCanonicalReleaseGeneration(values["generation"])
	if !ok || values["product"] != releaseindex.Product || values["channel"] != releaseindex.Channel {
		return signReleaseAuthorityTransitionCLIOptions{}, invalidSignReleaseAuthorityTransitionFlags()
	}
	return signReleaseAuthorityTransitionCLIOptions{
		NextAuthorityKeyPath: values["next-authority-key"], Generation: generation,
		Product: values["product"], Channel: values["channel"], KeyPath: values["key"], OutputDirectory: values["out-dir"],
	}, nil
}

func validateSignReleaseIndexArgs(args []string) (signReleaseIndexCLIOptions, error) {
	values, _, err := parseExactReleaseFlags(args, []string{
		"artifact-root", "product-version", "release-generation", "key", "out-dir",
	}, nil)
	if err != nil || len(values) != 5 {
		return signReleaseIndexCLIOptions{}, invalidSignReleaseIndexFlags()
	}
	generation, ok := parseCanonicalReleaseGeneration(values["release-generation"])
	if !ok || values["product-version"] != releaseindex.ProductVersion {
		return signReleaseIndexCLIOptions{}, invalidSignReleaseIndexFlags()
	}
	return signReleaseIndexCLIOptions{
		ArtifactRoot: values["artifact-root"], ProductVersion: values["product-version"],
		ReleaseGeneration: generation, KeyPath: values["key"], OutputDirectory: values["out-dir"],
	}, nil
}

func validateSignReleasePolicyArgs(args []string) (signReleasePolicyCLIOptions, error) {
	values, _, err := parseExactReleaseFlags(args, []string{"policy", "key", "out-dir"}, nil)
	if err != nil || len(values) != 3 {
		return signReleasePolicyCLIOptions{}, invalidSignReleasePolicyFlags()
	}
	return signReleasePolicyCLIOptions{
		PolicyPath: values["policy"], KeyPath: values["key"], OutputDirectory: values["out-dir"],
	}, nil
}

func validateVerifyReleaseIndexArgs(args []string) (verifyReleaseIndexCLIOptions, error) {
	values, booleans, err := parseExactReleaseFlags(args, []string{
		"index", "signature", "signer-key", "artifact-root", "policy-envelope",
		"policy-authority-key", "product", "channel", "minimum-policy-generation", "minimum-release-generation",
		"expect-release-index-digest", "authority-transition", "authority-trust-root", "minimum-authority-generation",
		"authority-transition-chain",
	}, []string{"persist-release-state"})
	if err != nil {
		return verifyReleaseIndexCLIOptions{}, invalidVerifyReleaseIndexFlags()
	}
	for _, required := range []string{
		"index", "signature", "signer-key", "artifact-root", "policy-envelope",
		"policy-authority-key", "product", "channel", "minimum-policy-generation", "minimum-release-generation",
	} {
		if values[required] == "" {
			return verifyReleaseIndexCLIOptions{}, invalidVerifyReleaseIndexFlags()
		}
	}
	policyGeneration, policyOK := parseCanonicalReleaseGeneration(values["minimum-policy-generation"])
	releaseGeneration, releaseOK := parseCanonicalReleaseGeneration(values["minimum-release-generation"])
	persist := booleans["persist-release-state"]
	digest, pinned := values["expect-release-index-digest"]
	transition, hasTransition := values["authority-transition"]
	chain, hasChain := values["authority-transition-chain"]
	trustRoot, hasTrustRoot := values["authority-trust-root"]
	minimumAuthority, hasMinimumAuthority := values["minimum-authority-generation"]
	rotation := hasTransition || hasChain || hasTrustRoot || hasMinimumAuthority
	authorityGeneration, authorityOK := parseCanonicalReleaseGeneration(minimumAuthority)
	if !policyOK || !releaseOK || values["product"] != releaseindex.Product || values["channel"] != releaseindex.Channel ||
		persist == pinned || (pinned && releaseindex.ValidateExpectedIndexDigest(digest) != nil) ||
		(rotation && ((hasTransition == hasChain) || !hasTrustRoot || !hasMinimumAuthority || !authorityOK)) {
		return verifyReleaseIndexCLIOptions{}, invalidVerifyReleaseIndexFlags()
	}
	return verifyReleaseIndexCLIOptions{
		IndexPath: values["index"], SignaturePath: values["signature"],
		SignerKeyPath: values["signer-key"], ArtifactRoot: values["artifact-root"],
		PolicyEnvelopePath: values["policy-envelope"], PolicyAuthorityKeyPath: values["policy-authority-key"],
		Product: values["product"], Channel: values["channel"],
		MinimumPolicyGeneration: policyGeneration, MinimumReleaseGeneration: releaseGeneration,
		PersistState: persist, ExpectedIndexDigest: digest, Rotation: rotation,
		AuthorityTransitionPath: transition, AuthorityTransitionChainPath: chain, AuthorityTrustRootPath: trustRoot, MinimumAuthorityGeneration: authorityGeneration, Chain: hasChain,
	}, nil
}

func parseExactReleaseFlags(args, valueNames, booleanNames []string) (map[string]string, map[string]bool, error) {
	valueAllowed := make(map[string]struct{}, len(valueNames))
	for _, name := range valueNames {
		valueAllowed[name] = struct{}{}
	}
	booleanAllowed := make(map[string]struct{}, len(booleanNames))
	for _, name := range booleanNames {
		booleanAllowed[name] = struct{}{}
	}
	values := make(map[string]string, len(valueNames))
	booleans := make(map[string]bool, len(booleanNames))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") || argument == "--" || len(argument) <= 2 {
			return nil, nil, invalidVerifyReleaseIndexFlags()
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, inline, hasInline := strings.Cut(nameValue, "=")
		if _, ok := booleanAllowed[name]; ok {
			if hasInline || booleans[name] {
				return nil, nil, invalidVerifyReleaseIndexFlags()
			}
			booleans[name] = true
			continue
		}
		if _, ok := valueAllowed[name]; !ok {
			return nil, nil, invalidVerifyReleaseIndexFlags()
		}
		if _, duplicate := values[name]; duplicate {
			return nil, nil, invalidVerifyReleaseIndexFlags()
		}
		value := inline
		if !hasInline {
			index++
			if index >= len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") {
				return nil, nil, invalidVerifyReleaseIndexFlags()
			}
			value = args[index]
		}
		if value == "" {
			return nil, nil, invalidVerifyReleaseIndexFlags()
		}
		values[name] = value
	}
	return values, booleans, nil
}

func parseCanonicalReleaseGeneration(raw string) (uint64, bool) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.HasPrefix(raw, "+") ||
		strings.HasPrefix(raw, "-") || (len(raw) > 1 && raw[0] == '0') {
		return 0, false
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	return value, err == nil && value > 0 && value <= releaseindex.MaxGeneration &&
		strconv.FormatUint(value, 10) == raw
}

func invalidSignReleaseIndexFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"sign-release-index requires exactly one non-empty --artifact-root, --product-version, --release-generation, --key, and --out-dir.")
}

func invalidSignReleasePolicyFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"sign-release-policy requires exactly one non-empty --policy, --key, and --out-dir.")
}

func invalidSignReleaseAuthorityTransitionFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"sign-release-authority-transition requires exactly one non-empty --next-authority-key, --generation, --product, --channel, --key, and --out-dir.")
}

func invalidAssembleReleaseAuthorityTransitionChainFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"assemble-release-authority-transition-chain requires 2 through 8 ordered --hop-envelope values, the same count of --hop-next-authority-key values, and exactly one non-empty --authority-trust-root, --product, --channel, --minimum-authority-generation, and --out-dir.")
}

func invalidVerifyReleaseIndexFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"verify-release-index requires each release sidecar, artifact root, explicit product/channel, canonical policy and release floors, plus exactly one of --persist-release-state or --expect-release-index-digest. Rotation requires exactly one of --authority-transition or --authority-transition-chain, plus --authority-trust-root and --minimum-authority-generation.")
}
