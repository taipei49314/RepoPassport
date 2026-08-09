//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestPersistentSignedTrustPolicyPrivacyBlockedStopsBeforeAuthorityEnvelopeAndState(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	blockedBundle := buildCLIPrivacyBlockedResignedBundle(t, fixture.BundleABytes, fixture.PrivateA)
	if _, err := attestation.Verify(blockedBundle, nil); err == nil || domain.ErrorCodeOf(err) != domain.CodeEvidencePrivacyBlocked {
		t.Fatalf("privacy-blocked fixture precondition failed: %v", err)
	}
	bundlePath := filepath.Join(root, "privacy-blocked.tar")
	if err := os.WriteFile(bundlePath, blockedBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(root, "must-not-exist")
	missingAuthority := filepath.Join(root, "must-not-read-authority.pem")
	missingEnvelope := filepath.Join(root, "must-not-read-envelope.dsse")

	response, _, stderr, code := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "verify-attestation", bundlePath,
		"--trust-policy-envelope", missingEnvelope,
		"--trust-policy-authority-key", missingAuthority,
		"--minimum-trust-policy-generation", "1",
		"--persist-trust-policy-state",
	)
	if code != 7 || response.Error == nil || response.Error.Code != domain.CodeEvidencePrivacyBlocked || stderr != "" {
		t.Fatalf("privacy rejection exit=%d response=%#v stderr=%q", code, response, stderr)
	}
	if _, err := os.Stat(dataRoot); !os.IsNotExist(err) {
		t.Fatalf("privacy-blocked input touched persistent state root: %v", err)
	}
}
