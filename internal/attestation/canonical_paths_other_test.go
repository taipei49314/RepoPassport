//go:build !windows

package attestation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func TestCanonicalDataAndRepositoryBoundariesRejectSymlinkAliases(t *testing.T) {
	base := t.TempDir()
	realData := filepath.Join(base, "real-data")
	realRepository := filepath.Join(base, "real-repository")
	exports := filepath.Join(base, "exports")
	keys := filepath.Join(base, "keys")
	for _, directory := range []string{realData, realRepository, exports, keys} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
	}
	dataAlias := filepath.Join(base, "data-alias")
	repositoryAlias := filepath.Join(base, "repository-alias")
	if err := os.Symlink(realData, dataAlias); err != nil {
		t.Fatalf("create data alias: %v", err)
	}
	if err := os.Symlink(realRepository, repositoryAlias); err != nil {
		t.Fatalf("create repository alias: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realRepository, "repo-passport.yml"), []byte("apiVersion: repopass.dev/v1alpha1\n"), 0o600); err != nil {
		t.Fatalf("write repository marker: %v", err)
	}
	_, privatePEM := generatedPrivatePEM(t)
	externalKey := filepath.Join(keys, "external.pem")
	dataKey := filepath.Join(realData, "data.pem")
	repositoryKey := filepath.Join(realRepository, "repository.pem")
	for _, path := range []string{externalKey, dataKey, repositoryKey} {
		writePrivateFile(t, path, privatePEM, 0o600)
	}

	if _, err := LoadPrivateKey(dataKey, dataAlias, filepath.Join(exports, "data-key.tar"), base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("aliased data-root key code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKey(externalKey, dataAlias, filepath.Join(realData, "data-output.tar"), base); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("aliased data-root output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKey(repositoryKey, realData, filepath.Join(exports, "repository-key.tar"), repositoryAlias); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("aliased repository key code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if _, err := LoadPrivateKey(externalKey, realData, filepath.Join(realRepository, "repository-output.tar"), repositoryAlias); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("aliased repository output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
}
