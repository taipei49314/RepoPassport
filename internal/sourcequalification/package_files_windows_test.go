//go:build windows

package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSecurePrivatePackagePathAppliesExactProtectedOwnerAndSystemDACL(t *testing.T) {
	root := t.TempDir()
	packageFilesSetPermissiveWindowsDACL(t, root)
	directory := filepath.Join(root, "staging")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "artifact.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := securePrivatePackagePath(directory, true); err != nil {
		t.Fatalf("secure staging directory: %v", err)
	}
	if err := securePrivatePackagePath(file, false); err != nil {
		t.Fatalf("secure staging file: %v", err)
	}
	packageFilesAssertExactWindowsDACL(t, directory)
	packageFilesAssertExactWindowsDACL(t, file)
}

func TestAssembleQualificationPackagePublishesExactPrivateWindowsDACL(t *testing.T) {
	fixture := newPackageFilesFixture(t)
	packageFilesSetPermissiveWindowsDACL(t, fixture.root)
	if _, err := assembleQualificationPackage(fixture.linuxDir, fixture.windowsDir, fixture.outputDir); err != nil {
		t.Fatalf("assembleQualificationPackage: %v", err)
	}
	packageFilesAssertExactWindowsDACL(t, fixture.outputDir)
	for _, name := range []string{
		packageFilesArchiveName,
		packageFilesManifestName,
		packageFilesLinuxReceiptName,
		packageFilesWindowsReceiptName,
	} {
		packageFilesAssertExactWindowsDACL(t, filepath.Join(fixture.outputDir, name))
	}
}

func packageFilesSetPermissiveWindowsDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatalf("parse permissive DACL: %v", err)
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

func packageFilesAssertExactWindowsDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("read private DACL: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) !=
		windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		t.Fatalf("DACL is not present and protected: %#x, %v", control, err)
	}
	owner, _, err := descriptor.Owner()
	current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentErr != nil || owner == nil || current == nil ||
		current.User.Sid == nil || !owner.Equals(current.User.Sid) {
		t.Fatalf("owner is not the current token user: %v / %v", err, currentErr)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("DACL is not the exact two-ACE contract: %v", err)
	}
	seenOwner, seenSystem := false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) ||
			ace.Mask != 0x1f01ff {
			t.Fatalf("DACL ACE %d is not exact FILE_ALL_ACCESS: %#v, %v", index, ace, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			t.Fatalf("DACL ACE %d has an invalid SID", index)
		}
		switch {
		case sid.Equals(owner):
			if seenOwner {
				t.Fatal("owner ACE is duplicated")
			}
			seenOwner = true
		case sid.Equals(system):
			if seenSystem {
				t.Fatal("SYSTEM ACE is duplicated")
			}
			seenSystem = true
		default:
			t.Fatalf("DACL grants FILE_ALL_ACCESS to unexpected principal %q", sid.String())
		}
	}
	if !seenOwner || !seenSystem {
		t.Fatal("DACL does not contain exactly current owner and SYSTEM")
	}
}
