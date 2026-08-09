//go:build windows

package releasequalification

import (
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

func secureQualificationSnapshotPath(path string, directory bool) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return os.ErrPermission
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	inheritance := uint32(0)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	var pinner runtime.Pinner
	pinner.Pin(current.User.Sid)
	pinner.Pin(system)
	defer pinner.Unpin()
	entries := []windows.EXPLICIT_ACCESS{
		{AccessPermissions: 0x1f01ff, AccessMode: windows.GRANT_ACCESS, Inheritance: inheritance, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid)}},
		{AccessPermissions: 0x1f01ff, AccessMode: windows.GRANT_ACCESS, Inheritance: inheritance, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(system)}},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		current.User.Sid,
		nil,
		acl,
		nil,
	); err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return os.ErrPermission
	}
	owner, _, ownerErr := descriptor.Owner()
	control, _, controlErr := descriptor.Control()
	dacl, _, daclErr := descriptor.DACL()
	if ownerErr != nil || controlErr != nil || daclErr != nil || owner == nil || !owner.Equals(current.User.Sid) ||
		control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 ||
		dacl == nil || dacl.AceCount != 2 {
		return os.ErrPermission
	}
	runtime.KeepAlive(entries)
	runtime.KeepAlive(current)
	return nil
}
