//go:build windows

package releaseindex

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func secureTransitionPrivateKeyForTest(t *testing.T, path string) {
	t.Helper()
	requireHostFilesystem(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)", user.User.Sid.String(),
	))
	if err != nil {
		t.Fatalf("parse private DACL: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("extract private DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		user.User.Sid, nil, dacl, nil,
	); err != nil {
		t.Fatalf("apply private DACL: %v", err)
	}
}
