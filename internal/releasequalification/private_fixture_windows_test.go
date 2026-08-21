//go:build windows

package releasequalification

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

func privateQualificationFixtureDir(t *testing.T) string {
	t.Helper()
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatalf("read current token user: %v", err)
	}
	owner := current.User.Sid.String()
	principal, err := windowssecurity.CurrentAppContainerPrincipal()
	if err != nil {
		t.Fatalf("read current AppContainer principal: %v", err)
	}
	entries := []string{fmt.Sprintf("(A;OICI;FA;;;%s)", owner), "(A;OICI;FA;;;SY)"}
	if principal != "" && principal != owner && principal != "S-1-5-18" {
		entries = append(entries, fmt.Sprintf("(A;OICI;FA;;;%s)", principal))
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + owner + "D:P" + strings.Join(entries, ""),
	)
	if err != nil || descriptor == nil {
		t.Fatalf("build private fixture security descriptor: %v", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	path := filepath.Join(t.TempDir(), "private")
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("encode private fixture path: %v", err)
	}
	if err := windows.CreateDirectory(pointer, attributes); err != nil {
		t.Fatalf("create private fixture directory: %v", err)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatalf("parse SYSTEM SID: %v", err)
	}
	var appContainer *windows.SID
	if principal != "" {
		appContainer, err = windows.StringToSid(principal)
		if err != nil {
			t.Fatalf("parse AppContainer SID: %v", err)
		}
	}
	actual, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || !validQualificationSnapshotDACL(
		actual, current.User.Sid, system, appContainer, true,
	) {
		t.Fatalf("private fixture directory DACL is not exact: %v", err)
	}
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(current)
	return path
}
