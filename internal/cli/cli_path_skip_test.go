package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/manifest"
)

func healthyNodeManifestPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(
		"..", "..", "testdata", "fixtures", "healthy", "healthy-node-cli", "repo-passport.yml",
	))
	if err != nil {
		t.Fatalf("resolve healthy-node-cli manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("healthy-node-cli manifest: %v", err)
	}
	return path
}

func skipIfCLIFailClosedPathUnavailable(t *testing.T, path string) {
	t.Helper()
	if _, err := manifest.Load(path); err != nil {
		t.Skipf("CLI fail-closed path checks are unavailable in this process: %v", err)
	}
}

func skipIfCLIFailClosedTempUnavailable(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(healthyNodeManifestPath(t))
	if err != nil {
		t.Fatalf("read healthy-node-cli manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), "repo-passport.yml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write CLI path probe: %v", err)
	}
	skipIfCLIFailClosedPathUnavailable(t, path)
}
