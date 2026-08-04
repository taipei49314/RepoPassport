package releaseindex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/repopass/repopass/internal/attestation"
)

func PublishSignedSidecars(outputDir string, index, envelopeRaw, signerSPKI []byte) error {
	if _, err := ParseIndex(index); err != nil {
		return ErrPublishFailed
	}
	if _, _, err := parseCanonicalSPKI(signerSPKI); err != nil {
		return ErrPublishFailed
	}
	// Verify the envelope's shape and byte binding cryptographically before any
	// output is materialized. Publication itself does not confer trust.
	public, der, _ := parseCanonicalSPKI(signerSPKI)
	payload, _, err := authenticateEnvelope(envelopeRaw, IndexPayloadType, public, digest(der), MaxEnvelopeBytes, MaxIndexBytes)
	if err != nil || !bytes.Equal(payload, index) {
		return ErrPublishFailed
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "release-index.json", data: index},
		{name: "signature.dsse.json", data: envelopeRaw},
		{name: "signer-public-key.pem", data: signerSPKI},
	})
}

func PublishSignedPolicySidecars(outputDir string, envelopeRaw, authoritySPKI []byte) error {
	public, der, err := parseCanonicalSPKI(authoritySPKI)
	if err != nil {
		return ErrPublishFailed
	}
	payload, _, err := authenticateEnvelope(envelopeRaw, PolicyPayloadType, public, digest(der), MaxPolicyEnvelopeBytes, MaxPolicyBytes)
	if err != nil {
		return ErrPublishFailed
	}
	policy, err := ParsePolicyPayload(payload)
	if err != nil {
		return ErrPublishFailed
	}
	for _, key := range policy.Keys {
		if key.KeyID == digest(der) {
			return ErrPublishFailed
		}
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "release-authority-public-key.pem", data: authoritySPKI},
		{name: "release-key-policy.dsse.json", data: envelopeRaw},
	})
}

// PublishSignedOfflineTrustPolicySidecars authenticates an exact canonical
// signed offline-trust-policy-v2 envelope before atomically publishing its
// authority companion. The companion is not a trust anchor: a verifier must
// still receive it through an independently trusted input. The authority key
// cannot also be a policy signer, including as a revoked signer.
func PublishSignedOfflineTrustPolicySidecars(outputDir string, envelopeRaw, authoritySPKI []byte) error {
	policy, err := attestation.ParseSignedOfflineTrustPolicy(envelopeRaw, authoritySPKI)
	if err != nil {
		return ErrPublishFailed
	}
	decision, err := policy.EvaluateSignerKeyID(policy.AuthorityKeyID())
	if err != nil || decision != attestation.TrustDecisionNotListed {
		return ErrPublishFailed
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "offline-trust-policy-authority-public-key.pem", data: authoritySPKI},
		{name: "offline-trust-policy.dsse.json", data: envelopeRaw},
	})
}

// PublishSignedOfflineTrustPolicyAuthorityTransitionSidecars authenticates an
// exact canonical one-hop transition before atomically publishing its three
// companions. Neither public key is a trust anchor; both must be supplied
// independently by a verifier selecting this opt-in rotation mode.
func PublishSignedOfflineTrustPolicyAuthorityTransitionSidecars(outputDir string, nextAuthoritySPKI, envelopeRaw, previousAuthoritySPKI []byte) error {
	if _, err := attestation.VerifyOfflineTrustPolicyAuthorityTransition(
		envelopeRaw, previousAuthoritySPKI, nextAuthoritySPKI, 1,
	); err != nil {
		return ErrPublishFailed
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "offline-trust-policy-authority-public-key.pem", data: nextAuthoritySPKI},
		{name: "offline-trust-policy-authority-transition.dsse.json", data: envelopeRaw},
		{name: "offline-trust-policy-authority-trust-root-public-key.pem", data: previousAuthoritySPKI},
	})
}

// PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars
// authenticates the complete bounded chain before atomically materializing
// its exact three companions. Neither key companion is promoted to a trust
// anchor; a verifier must receive the explicit root independently.
func PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars(outputDir string, terminalSPKI, chainRaw, rootSPKI []byte) error {
	if _, err := attestation.VerifyOfflineTrustPolicyAuthorityTransitionChain(
		chainRaw, rootSPKI, terminalSPKI, 1,
	); err != nil {
		return ErrPublishFailed
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "offline-trust-policy-authority-public-key.pem", data: terminalSPKI},
		{name: "offline-trust-policy-authority-transition-chain.json", data: chainRaw},
		{name: "offline-trust-policy-authority-trust-root-public-key.pem", data: rootSPKI},
	})
}

// PublishAuthorityTransitionSidecars atomically publishes the exact three
// canonical transition companions. The previous-root companion is verified as
// the signer but is never promoted to trust without the caller's explicit
// verification input.
func PublishAuthorityTransitionSidecars(outputDir string, nextAuthoritySPKI, envelopeRaw, previousAuthoritySPKI []byte) error {
	if _, err := VerifyAuthorityTransition(
		envelopeRaw, previousAuthoritySPKI, nextAuthoritySPKI,
		DefaultAuthorityTransitionScope(), 1,
	); err != nil {
		return ErrPublishFailed
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "release-authority-public-key.pem", data: nextAuthoritySPKI},
		{name: "release-authority-transition.dsse.json", data: envelopeRaw},
		{name: "release-authority-trust-root-public-key.pem", data: previousAuthoritySPKI},
	})
}

// PublishAuthorityTransitionChainSidecars authenticates the complete chain
// before atomically materializing its exact three companions. Neither key
// companion is a trust anchor unless supplied independently by the caller.
func PublishAuthorityTransitionChainSidecars(outputDir string, chainRaw, explicitRootSPKI, explicitTerminalSPKI []byte) error {
	if _, err := VerifyAuthorityTransitionChain(
		chainRaw, explicitRootSPKI, explicitTerminalSPKI,
		DefaultAuthorityTransitionChainScope(), 1,
	); err != nil {
		return ErrPublishFailed
	}
	return publishNewDirectory(outputDir, []publicationFile{
		{name: "release-authority-public-key.pem", data: explicitTerminalSPKI},
		{name: "release-authority-transition-chain.json", data: chainRaw},
		{name: "release-authority-trust-root-public-key.pem", data: explicitRootSPKI},
	})
}

type publicationFile struct {
	name string
	data []byte
}

func publishNewDirectory(outputDir string, files []publicationFile) error {
	if !safeNativePath(outputDir) {
		return ErrPublishFailed
	}
	destination, err := filepath.Abs(outputDir)
	if err != nil {
		return ErrPublishFailed
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return ErrPublishFailed
	}
	parent, err := safeExistingDirectory(filepath.Dir(destination))
	if err != nil || !samePath(filepath.Dir(destination), parent) {
		return ErrPublishFailed
	}
	temporary, err := os.MkdirTemp(parent, ".release-index-publish-")
	if err != nil {
		return ErrPublishFailed
	}
	published := false
	defer func() {
		if !published {
			cleanupPublicationTemp(parent, temporary)
		}
	}()
	if err := securePublicationDirectory(temporary); err != nil || validatePublicationDirectory(temporary) != nil {
		return ErrPublishFailed
	}
	stagingIdentity, err := os.Lstat(temporary)
	if err != nil || !stagingIdentity.IsDir() {
		return ErrPublishFailed
	}
	for _, item := range files {
		if err := validateSamePublicationDirectory(temporary, stagingIdentity); err != nil {
			return ErrPublishFailed
		}
		if !portableBaseName(item.name) || len(item.data) == 0 {
			return ErrPublishFailed
		}
		path := filepath.Join(temporary, item.name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return ErrPublishFailed
		}
		_, writeErr := file.Write(item.data)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return ErrPublishFailed
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return ErrPublishFailed
		}
		if err := validatePublicationFile(path); err != nil {
			return ErrPublishFailed
		}
	}
	if err := validateSamePublicationDirectory(temporary, stagingIdentity); err != nil {
		return ErrPublishFailed
	}
	if err := syncDirectory(temporary); err != nil {
		return ErrPublishFailed
	}
	if err := atomicPublishDirectory(temporary, destination); err != nil {
		return ErrPublishFailed
	}
	published = true
	if err := validateSamePublicationDirectory(destination, stagingIdentity); err != nil {
		cleanupPublishedDirectory(destination, files)
		return ErrPublishFailed
	}
	if err := syncDirectory(parent); err != nil {
		cleanupPublishedDirectory(destination, files)
		return ErrPublishFailed
	}
	if err := verifyPublishedDirectory(destination, files, stagingIdentity); err != nil {
		cleanupPublishedDirectory(destination, files)
		_ = syncDirectory(parent)
		return ErrPublishFailed
	}
	return nil
}

func cleanupPublishedDirectory(destination string, files []publicationFile) {
	if validatePublicationDirectory(destination) != nil {
		return
	}
	names, err := directoryNames(destination)
	if err != nil || len(names) != len(files) {
		return
	}
	expected := make(map[string]struct{}, len(files))
	for _, item := range files {
		expected[item.name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := expected[name]; !ok {
			return
		}
		path := filepath.Join(destination, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) || validatePublicationFile(path) != nil {
			return
		}
	}
	for _, name := range names {
		if os.Remove(filepath.Join(destination, name)) != nil {
			return
		}
	}
	_ = os.Remove(destination)
}

func verifyPublishedDirectory(destination string, files []publicationFile, identity os.FileInfo) error {
	if err := validateSamePublicationDirectory(destination, identity); err != nil {
		return err
	}
	names, err := directoryNames(destination)
	if err != nil || len(names) != len(files) {
		return ErrPublishFailed
	}
	expected := make(map[string][]byte, len(files))
	for _, item := range files {
		expected[item.name] = item.data
	}
	for _, name := range names {
		want, ok := expected[name]
		if !ok {
			return ErrPublishFailed
		}
		raw, _, err := stableFile(filepath.Join(destination, name), int64(len(want)), true)
		if err != nil || validatePublicationFile(filepath.Join(destination, name)) != nil || !bytes.Equal(raw, want) {
			return ErrPublishFailed
		}
	}
	return nil
}

func validateSamePublicationDirectory(path string, identity os.FileInfo) error {
	if identity == nil || validatePublicationDirectory(path) != nil {
		return ErrPublishFailed
	}
	current, err := os.Lstat(path)
	if err != nil || !current.IsDir() || !os.SameFile(identity, current) {
		return ErrPublishFailed
	}
	return nil
}

func cleanupPublicationTemp(parent, temporary string) {
	absolute, err := filepath.Abs(temporary)
	if err != nil || !pathWithin(parent, absolute) || !strings.HasPrefix(filepath.Base(absolute), ".release-index-publish-") {
		return
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(absolute) {
		return
	}
	_ = os.RemoveAll(absolute)
}
