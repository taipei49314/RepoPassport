package cli

import (
	"strconv"
	"testing"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
)

func TestAlpha32AuthorityRotationFlagsAreExactAndPreIO(t *testing.T) {
	valid := []string{
		"--trust-policy-authority-transition", "transition.dsse.json",
		"--trust-policy-authority-trust-root", "root.pem",
		"--minimum-trust-policy-authority-generation", "7",
	}
	options, err := validateSignedTrustPolicyAuthorityRotationArgs(valid, true)
	if err != nil || !options.Enabled || options.TransitionPath != "transition.dsse.json" || options.TrustRootPath != "root.pem" || options.MinimumGeneration != 7 {
		t.Fatalf("valid rotation flags: options=%+v err=%v", options, err)
	}
	if disabled, err := validateSignedTrustPolicyAuthorityRotationArgs(nil, true); err != nil || disabled.Enabled {
		t.Fatalf("absent rotation group: options=%+v err=%v", disabled, err)
	}

	maximum := strconv.FormatUint(attestation.MaxTrustPolicyGeneration, 10)
	if options, err := validateSignedTrustPolicyAuthorityRotationArgs([]string{
		"--trust-policy-authority-transition=transition.dsse.json",
		"--trust-policy-authority-trust-root=root.pem",
		"--minimum-trust-policy-authority-generation=" + maximum,
	}, true); err != nil || options.MinimumGeneration != attestation.MaxTrustPolicyGeneration {
		t.Fatalf("maximum generation rejected: options=%+v err=%v", options, err)
	}

	invalid := map[string][]string{
		"without signed policy":       valid,
		"transition only":             valid[:2],
		"root only":                   valid[2:4],
		"floor only":                  valid[4:],
		"duplicate transition":        append(append([]string{}, valid...), "--trust-policy-authority-transition", "other"),
		"empty root":                  {"--trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root=", "--minimum-trust-policy-authority-generation", "1"},
		"zero":                        {"--trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "0"},
		"leading zero":                {"--trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "01"},
		"plus":                        {"--trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "+1"},
		"over maximum":                {"--trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", strconv.FormatUint(attestation.MaxTrustPolicyGeneration+1, 10)},
		"single dash":                 {"-trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "1"},
		"extra dash":                  {"---trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "1"},
		"case alias":                  {"--Trust-Policy-Authority-Transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "1"},
		"near prefix":                 {"--trust-policy-authority-transition-file", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "1"},
		"post separator is not group": {"--", "--trust-policy-authority-transition", "transition", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "1"},
	}
	for name, args := range invalid {
		t.Run(name, func(t *testing.T) {
			signedEnabled := name != "without signed policy"
			options, err := validateSignedTrustPolicyAuthorityRotationArgs(args, signedEnabled)
			if err == nil || options.Enabled || domain.ErrorCodeOf(err) != domain.CodeManifestInvalid {
				t.Fatalf("invalid rotation flags accepted: options=%+v err=%v", options, err)
			}
		})
	}
}
