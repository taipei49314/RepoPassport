//go:build !windows

package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectRepositoryRejectsExecutableModeDrift(t *testing.T) {
	tests := []struct {
		name string
		path string
		mode os.FileMode
	}{
		{name: "100755_without_execute", path: "scripts/run.sh", mode: 0o600},
		{name: "100644_with_execute", path: "README.md", mode: 0o700},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitRepositoryFixture(t)
			path := filepath.Join(fixture.root, filepath.FromSlash(test.path))
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatalf("create executable-mode drift fixture: %v", err)
			}
			requireRepositoryInspectionRejected(t, fixture.request())
		})
	}
}
