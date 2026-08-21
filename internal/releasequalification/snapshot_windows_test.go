//go:build windows

package releasequalification

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/testsupport"

	"golang.org/x/sys/windows"
)

func TestSealedSnapshotPathsConvergeToCurrentOwnerProtectedACL(t *testing.T) {
	testsupport.RequireHostFilesystem(t)
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

func TestQualificationSnapshotDACLRejectsWrongACEContracts(t *testing.T) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatal("current token SID is unavailable")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	owner := current.User.Sid.String()
	exact := snapshotTestDescriptor(t, fmt.Sprintf(
		"O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)", owner, owner,
	))
	if !validQualificationSnapshotDACL(exact, current.User.Sid, system, nil, false) {
		t.Fatal("exact snapshot file DACL was rejected")
	}
	for name, sddl := range map[string]string{
		"wrong mask":      fmt.Sprintf("O:%sD:P(A;;FR;;;%s)(A;;FA;;;SY)", owner, owner),
		"wrong flags":     fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)", owner, owner),
		"extra principal": fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", owner, owner),
		"duplicate owner": fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FA;;;%s)", owner, owner, owner),
	} {
		t.Run(name, func(t *testing.T) {
			if validQualificationSnapshotDACL(
				snapshotTestDescriptor(t, sddl), current.User.Sid, system, nil, false,
			) {
				t.Fatalf("invalid snapshot DACL was accepted: %s", sddl)
			}
		})
	}

	appContainer, err := windows.StringToSid("S-1-15-2-111-222-333-444-555-666-777")
	if err != nil {
		t.Fatal(err)
	}
	withAppContainer := snapshotTestDescriptor(t, fmt.Sprintf(
		"O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;%s)", owner, owner, appContainer.String(),
	))
	if !validQualificationSnapshotDACL(
		withAppContainer, current.User.Sid, system, appContainer, false,
	) {
		t.Fatal("exact AppContainer snapshot DACL was rejected")
	}
	systemOwner := snapshotTestDescriptor(t, "O:SYD:P(A;;FA;;;SY)(A;;FA;;;SY)")
	if !validQualificationSnapshotDACL(systemOwner, system, system, nil, false) {
		t.Fatal("legacy SYSTEM-owner two-ACE snapshot DACL was rejected")
	}
	systemOwnerSingle := snapshotTestDescriptor(t, "O:SYD:P(A;;FA;;;SY)")
	if validQualificationSnapshotDACL(systemOwnerSingle, system, system, nil, false) {
		t.Fatal("SYSTEM-owner snapshot DACL accepted a changed one-ACE profile")
	}
}

func snapshotTestDescriptor(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || descriptor == nil {
		t.Fatalf("parse security descriptor: %v", err)
	}
	return descriptor
}
