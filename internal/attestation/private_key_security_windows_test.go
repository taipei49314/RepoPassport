//go:build windows

package attestation

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/repopass/repopass/internal/domain"
	"golang.org/x/sys/windows"
)

func TestWindowsPrivateKeyRejectsHardlinksAndPermissiveDACL(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	outputRoot := filepath.Join(base, "output")
	keyRoot := filepath.Join(base, "keys")
	for _, directory := range []string{dataRoot, outputRoot, keyRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
	}
	_, privatePEM := generatedPrivatePEM(t)
	output := filepath.Join(outputRoot, "bundle.tar")

	hardlinkedKey := filepath.Join(keyRoot, "hardlinked.pem")
	writePrivateFile(t, hardlinkedKey, privatePEM, 0o600)
	if err := os.Link(hardlinkedKey, filepath.Join(keyRoot, "second-link.pem")); err != nil {
		t.Fatalf("create hardlink fixture: %v", err)
	}
	if _, err := LoadPrivateKey(hardlinkedKey, dataRoot, output, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("hardlinked private-key code = %q: %v", domain.ErrorCodeOf(err), err)
	}

	permissiveKey := filepath.Join(keyRoot, "permissive.pem")
	writePrivateFile(t, permissiveKey, privatePEM, 0o600)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	setPrivateDACLForTest(t, permissiveKey, fmt.Sprintf(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)(A;;GR;;;WD)",
		user.User.Sid.String(),
	))
	if _, err := LoadPrivateKey(permissiveKey, dataRoot, output, base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("permissive private-key code = %q: %v", domain.ErrorCodeOf(err), err)
	}
}

func TestWindowsCanonicalBoundaryAndFinalPathRejectDirectoryAliasWhenAvailable(t *testing.T) {
	base := t.TempDir()
	realData := filepath.Join(base, "real-data")
	otherData := filepath.Join(base, "other-data")
	outputRoot := filepath.Join(base, "output")
	for _, directory := range []string{realData, otherData, outputRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
	}
	dataAlias := filepath.Join(base, "data-alias")
	if err := os.Symlink(realData, dataAlias); err != nil {
		return
	}
	_, privatePEM := generatedPrivatePEM(t)
	dataKey := filepath.Join(realData, "private.pem")
	writePrivateFile(t, dataKey, privatePEM, 0o600)
	if _, err := LoadPrivateKey(dataKey, dataAlias, filepath.Join(outputRoot, "bundle.tar"), base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("aliased data-root key code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	aliasKeyPath := filepath.Join(dataAlias, "private.pem")
	if _, err := LoadPrivateKey(aliasKeyPath, otherData, filepath.Join(outputRoot, "alias-key.tar"), base); domain.ErrorCodeOf(err) != domain.CodeSigningFailed {
		t.Fatalf("aliased final private-key path code = %q: %v", domain.ErrorCodeOf(err), err)
	}
}
