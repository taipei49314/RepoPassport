//go:build !windows

package releaseindex

import (
	"os"
	"testing"
)

func secureTransitionPrivateKeyForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
