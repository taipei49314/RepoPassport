//go:build windows

package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCreatePrivateQualificationWorkspaceAppliesExactWindowsMetadata(t *testing.T) {
	parent := t.TempDir()
	workspaceSetPermissiveWindowsDACL(t, parent)
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "private-run")
	if err != nil {
		t.Fatalf("create private qualification workspace: %v", err)
	}
	defer func() { _ = cleanup() }()

	workspaceAssertExactPrivateWindowsDirectory(t, path)
	workspaceAssertPermissiveWindowsDACL(t, parent)
}

func TestCreatePrivateQualificationWorkspaceWindowsCollisionDoesNotRepairDACL(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "collision")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	workspaceSetPermissiveWindowsDACL(t, path)
	if created, cleanup, err := createPrivateQualificationWorkspace(parent, "collision"); err == nil || created != "" || cleanup != nil {
		t.Fatalf("permissive collision accepted: %q/%v/%v", created, cleanup != nil, err)
	}
	workspaceAssertPermissiveWindowsDACL(t, path)
}

func workspaceSetPermissiveWindowsDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("extract permissive DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("apply permissive DACL: %v", err)
	}
}

func workspaceAssertExactPrivateWindowsDirectory(t *testing.T, path string) {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatalf("workspace attributes = %#x, want real directory: %v", attributes, err)
	}

	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("read workspace security descriptor: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) !=
		windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		t.Fatalf("workspace DACL is not present and protected: %#x, %v", control, err)
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentErr != nil || ownerDefaulted || owner == nil || current == nil ||
		current.User.Sid == nil || !owner.Equals(current.User.Sid) {
		t.Fatalf("workspace owner is not current token user: %v / %v", err, currentErr)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	wantACECount := uint16(2)
	if owner.Equals(system) {
		wantACECount = 1
	}
	if err != nil || daclDefaulted || dacl == nil || dacl.AceCount != wantACECount {
		t.Fatalf("workspace DACL is not exact: count=%v want=%d err=%v", dacl, wantACECount, err)
	}
	seen := make(map[string]struct{}, wantACECount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) ||
			ace.Mask != 0x1f01ff {
			t.Fatalf("workspace ACE %d is invalid: %#v, %v", index, ace, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() || !sid.Equals(owner) && !sid.Equals(system) {
			t.Fatalf("workspace ACE %d grants unexpected SID", index)
		}
		if _, duplicate := seen[sid.String()]; duplicate {
			t.Fatalf("workspace DACL duplicates SID %q", sid.String())
		}
		seen[sid.String()] = struct{}{}
	}
	if _, ok := seen[owner.String()]; !ok {
		t.Fatal("workspace DACL lacks owner")
	}
	if _, ok := seen[system.String()]; !ok {
		t.Fatal("workspace DACL lacks SYSTEM")
	}

	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open workspace without following reparse: %v", err)
	}
	defer windows.CloseHandle(handle)
	if err := validatePackageWindowsStreams(handle, false); err != nil {
		t.Fatalf("new workspace contains an alternate data stream: %v", err)
	}
}

func workspaceAssertPermissiveWindowsDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		t.Fatalf("read permissive DACL: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("permissive DACL changed: %#v, %v", dacl, err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil || ace.Mask != 0x1f01ff {
		t.Fatalf("permissive ACE changed: %#v, %v", ace, err)
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if sid == nil || !sid.IsValid() || !sid.Equals(everyone) {
		t.Fatal("permissive Everyone ACE changed")
	}
}
