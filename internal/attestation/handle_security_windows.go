//go:build windows

package attestation

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
	"golang.org/x/sys/windows"
)

var (
	privateKeyAppContainerPrincipal = func() (string, error) { return "", nil }
	privateKeyTestAdapterOnce       sync.Once
)

func installPrivateKeyAppContainerTestAdapter(principal func() (string, error)) {
	if principal == nil {
		return
	}
	privateKeyTestAdapterOnce.Do(func() {
		privateKeyAppContainerPrincipal = principal
	})
}

func validatePrivateKeyHandle(file *os.File, expectedPath string) error {
	handle := windows.Handle(file.Fd())
	if err := validateWindowsFinalHandlePath(handle, expectedPath); err != nil {
		return err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("private key link state is not exclusive")
	}
	return validateWindowsPrivateDACL(handle)
}

func validateDirectoryHandle(file *os.File, expectedPath string) error {
	return validateWindowsFinalHandlePath(windows.Handle(file.Fd()), expectedPath)
}

func validateStableInputHandle(file *os.File, expectedPath string) error {
	handle := windows.Handle(file.Fd())
	if err := validateWindowsFinalHandlePath(handle, expectedPath); err != nil {
		return err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("stable input link state is not exclusive")
	}
	return nil
}

func validateWindowsFinalHandlePath(handle windows.Handle, expectedPath string) error {
	if pathsecurity.ValidateFinalPath(handle, expectedPath) != nil {
		return fmt.Errorf("final handle path does not match requested path")
	}
	return nil
}

func validateWindowsPrivateDACL(handle windows.Handle) error {
	securityDescriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || securityDescriptor == nil || !securityDescriptor.IsValid() {
		return fmt.Errorf("private key security descriptor is unavailable")
	}
	defer runtime.KeepAlive(securityDescriptor)
	owner, ownerDefaulted, err := securityDescriptor.Owner()
	if err != nil || owner == nil || ownerDefaulted || !owner.IsValid() {
		return fmt.Errorf("private key owner is not explicit")
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil ||
		!owner.Equals(currentUser.User.Sid) {
		return fmt.Errorf("private key owner is not the current user")
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("private key DACL is absent or empty")
	}
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	administratorsSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	appContainerPrincipal, err := privateKeyAppContainerPrincipal()
	if err != nil {
		return fmt.Errorf("private key AppContainer identity is unavailable")
	}
	var appContainerSID *windows.SID
	if appContainerPrincipal != "" {
		appContainerSID, err = windows.StringToSid(appContainerPrincipal)
		if err != nil || appContainerSID == nil || !appContainerSID.IsValid() {
			return fmt.Errorf("private key AppContainer identity is invalid")
		}
	}
	ownerAllowed := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) {
			return fmt.Errorf("private key DACL contains an invalid ACE")
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("private key DACL contains an unsupported ACE type")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("private key DACL contains an invalid SID")
		}
		if sid.Equals(owner) {
			if ace.Mask&(windows.FILE_READ_DATA|windows.GENERIC_READ|windows.GENERIC_ALL) == 0 {
				return fmt.Errorf("private key owner ACE does not grant read access")
			}
			ownerAllowed = true
			continue
		}
		if sid.Equals(systemSID) || sid.Equals(administratorsSID) {
			continue
		}
		if appContainerSID != nil && sid.Equals(appContainerSID) {
			if ace.Mask&(windows.FILE_READ_DATA|windows.GENERIC_READ|windows.GENERIC_ALL) == 0 {
				return fmt.Errorf("private key AppContainer ACE does not grant read access")
			}
			continue
		}
		return fmt.Errorf("private key DACL grants access to another identity")
	}
	if !ownerAllowed {
		return fmt.Errorf("private key DACL does not grant its owner access")
	}
	return nil
}
