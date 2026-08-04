//go:build !windows

package cli

import (
	"os"
	"testing"
)

func secureCLIPrivateKeyForTest(*testing.T, string) {}

func makeCLITrustKeyUnreadableForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("unreadable trust fixture\n"), 0o600); err != nil {
		t.Fatalf("write unreadable trust fixture: %v", err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("make trust fixture unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
}
