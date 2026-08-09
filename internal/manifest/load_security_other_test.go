//go:build unix

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestLoadRejectsSpecialManifestFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo-passport.yml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("named pipe creation is unavailable: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load unexpectedly accepted a named pipe")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("special-file error code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("special-file error leaked caller path: %v", err)
	}
	if info, statErr := os.Lstat(path); statErr != nil || info.Mode().IsRegular() {
		t.Fatalf("test fixture changed unexpectedly: info=%v err=%v", info, statErr)
	}
}
