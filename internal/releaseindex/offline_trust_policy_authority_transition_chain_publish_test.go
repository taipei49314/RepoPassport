package releaseindex

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
)

func makeOfflineTrustPolicyAuthorityTransitionChainPublication(t *testing.T) (root, terminal, chain []byte) {
	t.Helper()
	rootPrivate, rootSPKI := keyPair(t)
	middlePrivate, middleSPKI := keyPair(t)
	_, terminalSPKI := keyPair(t)
	first, _, _, err := attestation.SignOfflineTrustPolicyAuthorityTransition(middleSPKI, 1, rootPrivate)
	if err != nil {
		t.Fatalf("sign first transition: %v", err)
	}
	second, _, _, err := attestation.SignOfflineTrustPolicyAuthorityTransition(terminalSPKI, 2, middlePrivate)
	if err != nil {
		t.Fatalf("sign second transition: %v", err)
	}
	chainRaw, err := attestation.BuildOfflineTrustPolicyAuthorityTransitionChain(
		[][]byte{first, second}, [][]byte{middleSPKI, terminalSPKI}, rootSPKI,
	)
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	return rootSPKI, terminalSPKI, chainRaw
}

func TestPublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecarsExactAtomicNoOverwrite(t *testing.T) {
	requireHostFilesystem(t)
	rootSPKI, terminalSPKI, chainRaw := makeOfflineTrustPolicyAuthorityTransitionChainPublication(t)
	output := filepath.Join(t.TempDir(), "published")
	if err := PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars(output, terminalSPKI, chainRaw, rootSPKI); err != nil {
		t.Fatalf("publish: %v", err)
	}
	want := map[string][]byte{
		"offline-trust-policy-authority-public-key.pem":            terminalSPKI,
		"offline-trust-policy-authority-transition-chain.json":     chainRaw,
		"offline-trust-policy-authority-trust-root-public-key.pem": rootSPKI,
	}
	names, err := directoryNames(output)
	if err != nil || len(names) != len(want) {
		t.Fatalf("published inventory=%v err=%v", names, err)
	}
	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(output, name))
		if readErr != nil || !bytes.Equal(raw, want[name]) {
			t.Fatalf("published %s mismatch: %v", name, readErr)
		}
	}
	if err := PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars(output, terminalSPKI, chainRaw, rootSPKI); !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("existing output accepted: %v", err)
	}
}

func TestPublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecarsRejectsInvalidWithoutOutput(t *testing.T) {
	rootSPKI, terminalSPKI, chainRaw := makeOfflineTrustPolicyAuthorityTransitionChainPublication(t)
	_, wrongTerminal := keyPair(t)
	for name, values := range map[string]struct {
		terminal []byte
		chain    []byte
		root     []byte
	}{
		"wrong terminal": {terminal: wrongTerminal, chain: chainRaw, root: rootSPKI},
		"wrong root":     {terminal: terminalSPKI, chain: chainRaw, root: wrongTerminal},
		"tampered chain": {terminal: terminalSPKI, chain: append(append([]byte(nil), chainRaw...), 'x'), root: rootSPKI},
	} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "invalid")
			if err := PublishSignedOfflineTrustPolicyAuthorityTransitionChainSidecars(output, values.terminal, values.chain, values.root); !errors.Is(err, ErrPublishFailed) {
				t.Fatalf("invalid chain accepted: %v", err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("invalid publication materialized output: %v", err)
			}
		})
	}
}
