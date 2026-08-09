//go:build windows

package releasequalification

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSealedSnapshotPathsConvergeToCurrentOwnerProtectedACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sealed")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "artifact")
	if err := os.WriteFile(file, []byte("bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureQualificationSnapshotPath(root, true); err != nil {
		t.Fatal(err)
	}
	if err := secureQualificationSnapshotPath(file, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, file} {
		descriptor, err := windows.GetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil || descriptor == nil || !descriptor.IsValid() {
			t.Fatalf("private descriptor unavailable: %v", err)
		}
		owner, _, err := descriptor.Owner()
		current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || currentErr != nil || owner == nil || current == nil ||
			current.User.Sid == nil || !owner.Equals(current.User.Sid) {
			t.Fatal("sealed snapshot owner is not the current token user")
		}
		control, _, err := descriptor.Control()
		if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("sealed snapshot DACL is not present and protected")
		}
		dacl, _, err := descriptor.DACL()
		if err != nil || dacl == nil || dacl.AceCount != 2 {
			t.Fatal("sealed snapshot DACL is not the exact two-principal contract")
		}
	}
}
