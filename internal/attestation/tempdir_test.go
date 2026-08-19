package attestation

import "testing"

func unlinkedTempDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := requireUnlinkedDirectory(parent); err != nil {
		t.Skipf("unlinked output parent is unavailable in this process: %v", err)
	}
	return parent
}
