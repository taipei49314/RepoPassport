//go:build windows

package releasequalification

import (
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	qualificationSnapshotAppContainerPrincipal = func() (string, error) { return "", nil }
	qualificationSnapshotTestAdapterOnce       sync.Once
)

func installQualificationSnapshotAppContainerTestAdapter(principal func() (string, error)) {
	if principal == nil {
		return
	}
	qualificationSnapshotTestAdapterOnce.Do(func() {
		qualificationSnapshotAppContainerPrincipal = principal
	})
}

func secureQualificationSnapshotPath(path string, directory bool) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return os.ErrPermission
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	appContainerPrincipal, err := qualificationSnapshotAppContainerPrincipal()
	if err != nil {
		return os.ErrPermission
	}
	var appContainerSID *windows.SID
	if appContainerPrincipal != "" {
		appContainerSID, err = windows.StringToSid(appContainerPrincipal)
		if err != nil || appContainerSID == nil || !appContainerSID.IsValid() {
			return os.ErrPermission
		}
	}
	inheritance := uint32(0)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	var pinner runtime.Pinner
	pinner.Pin(current.User.Sid)
	pinner.Pin(system)
	if appContainerSID != nil {
		pinner.Pin(appContainerSID)
	}
	defer pinner.Unpin()
	entries := []windows.EXPLICIT_ACCESS{
		{AccessPermissions: 0x1f01ff, AccessMode: windows.GRANT_ACCESS, Inheritance: inheritance, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid)}},
		{
			AccessPermissions: 0x1f01ff,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
	}
	if appContainerSID != nil && !appContainerSID.Equals(current.User.Sid) && !appContainerSID.Equals(system) {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: 0x1f01ff,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(appContainerSID),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	securityInformation := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	var owner *windows.SID
	if appContainerSID == nil {
		securityInformation |= windows.OWNER_SECURITY_INFORMATION
		owner = current.User.Sid
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		securityInformation,
		owner,
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
	if !validQualificationSnapshotDACL(
		descriptor, current.User.Sid, system, appContainerSID, directory,
	) {
		return os.ErrPermission
	}
	runtime.KeepAlive(entries)
	runtime.KeepAlive(current)
	return nil
}

func validQualificationSnapshotDACL(
	descriptor *windows.SECURITY_DESCRIPTOR,
	owner, system, appContainer *windows.SID,
	directory bool,
) bool {
	if descriptor == nil || owner == nil || system == nil || !descriptor.IsValid() {
		return false
	}
	actualOwner, ownerDefaulted, ownerErr := descriptor.Owner()
	control, _, controlErr := descriptor.Control()
	dacl, daclDefaulted, daclErr := descriptor.DACL()
	expectedCount := uint16(2)
	if appContainer != nil && !appContainer.Equals(owner) && !appContainer.Equals(system) {
		expectedCount++
	}
	if ownerErr != nil || ownerDefaulted || controlErr != nil || daclErr != nil || daclDefaulted ||
		actualOwner == nil || !actualOwner.Equals(owner) ||
		control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) !=
			windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED ||
		dacl == nil || dacl.AceCount != expectedCount {
		return false
	}
	expectedFlags := uint8(0)
	if directory {
		expectedFlags = uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	seenOwner, seenSystem, seenAppContainer := false, false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != expectedFlags ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) ||
			ace.Mask != 0x1f01ff {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return false
		}
		switch {
		case sid.Equals(owner):
			if !seenOwner {
				seenOwner = true
			} else if owner.Equals(system) && !seenSystem {
				seenSystem = true
			} else {
				return false
			}
		case sid.Equals(system):
			if seenSystem {
				return false
			}
			seenSystem = true
		case appContainer != nil && sid.Equals(appContainer):
			if seenAppContainer {
				return false
			}
			seenAppContainer = true
		default:
			return false
		}
	}
	return seenOwner && seenSystem && (appContainer == nil || seenAppContainer ||
		appContainer.Equals(owner) || appContainer.Equals(system))
}
