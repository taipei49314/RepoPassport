//go:build windows

package releaseindex

import (
	"path/filepath"
	"testing"
)

func TestPublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecarsRetainsPrivateWindowsDACL(t *testing.T) {
	requireHostFilesystem(t)
	rootSPKI, terminalSPKI, chainRaw := makeOfflineTrustPolicyAuthorityTransitionChainPublication(t)
	output := filepath.Join(t.TempDir(), "private-chain-sidecars")
	if err := PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars(output, terminalSPKI, chainRaw, rootSPKI); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := validatePublicationDirectory(output); err != nil {
		t.Fatalf("final directory DACL: %v", err)
	}
	for _, name := range []string{
		"offline-trust-policy-authority-public-key.pem",
		"offline-trust-policy-authority-transition-chain.json",
		"offline-trust-policy-authority-trust-root-public-key.pem",
	} {
		if err := validatePublicationFile(filepath.Join(output, name)); err != nil {
			t.Fatalf("%s DACL: %v", name, err)
		}
	}
}
