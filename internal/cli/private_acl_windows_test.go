//go:build windows

package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/testsupport"
	"golang.org/x/sys/windows"
)

func secureCLIPrivateKeyForTest(t *testing.T, path string) {
	t.Helper()
	testsupport.RequireHostFilesystem(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	setCLIFileDACLForTest(t, path, fmt.Sprintf(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)",
		user.User.Sid.String(),
	))
}

func makeCLITrustKeyUnreadableForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("unreadable trust fixture\n"), 0o600); err != nil {
		t.Fatalf("write unreadable trust fixture: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	setCLIFileDACLForTest(t, path, fmt.Sprintf(
		"D:P(D;;GR;;;%s)(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)",
		user.User.Sid.String(),
		user.User.Sid.String(),
	))
}

func setCLIFileDACLForTest(t *testing.T, path, sddl string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse test DACL: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("extract test DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("apply test DACL: %v", err)
	}
}
