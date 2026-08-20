//go:build windows

package releaseindex

import (
	"path/filepath"
	"testing"
)

func TestPublishSignedOfflineTrustPolicySidecarsRetainsPrivateWindowsDACL(t *testing.T) {
	requireHostFilesystem(t)
	authority, authoritySPKI := keyPair(t)
	_, signerSPKI := keyPair(t)
	envelopeRaw, authoritySPKI := makeOfflineTrustPolicyPublication(t, authority, authoritySPKI, []offlineTrustPolicyPublicationKey{{KeyID: keyIDFromSPKI(t, signerSPKI), Status: "trusted"}})
	output := filepath.Join(t.TempDir(), "private-policy-sidecars")
	if err := PublishSignedOfflineTrustPolicySidecars(output, envelopeRaw, authoritySPKI); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := validatePublicationDirectory(output); err != nil {
		t.Fatalf("final directory DACL: %v", err)
	}
	for _, name := range []string{"offline-trust-policy-authority-public-key.pem", "offline-trust-policy.dsse.json"} {
		if err := validatePublicationFile(filepath.Join(output, name)); err != nil {
			t.Fatalf("%s DACL: %v", name, err)
		}
	}
}
