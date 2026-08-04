//go:build windows

package releaseindex

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isReparsePoint(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func hardlinkCount(file *os.File) uint64 {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return 0
	}
	return uint64(info.NumberOfLinks)
}

func validateOpenedPath(file *os.File, expectedPath string) error {
	handle := windows.Handle(file.Fd())
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return os.ErrInvalid
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return os.ErrInvalid
	}
	finalPath := windows.UTF16ToString(buffer[:length])
	if strings.HasPrefix(strings.ToUpper(finalPath), `\\?\UNC\`) {
		return os.ErrInvalid
	}
	if strings.HasPrefix(strings.ToUpper(finalPath), `\\?\`) {
		finalPath = finalPath[len(`\\?\`):]
	}
	expectedAbsolute, err := filepath.Abs(expectedPath)
	if err != nil || !strings.EqualFold(filepath.Clean(finalPath), filepath.Clean(expectedAbsolute)) {
		return os.ErrInvalid
	}
	return nil
}

func validateNoAlternateDataStreams(path string) error {
	if !onlyDefaultDataStream(path) {
		return os.ErrInvalid
	}
	return nil
}

func securePublicationDirectory(path string) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return os.ErrPermission
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	var pinner runtime.Pinner
	pinner.Pin(current.User.Sid)
	pinner.Pin(system)
	defer pinner.Unpin()
	entries := []windows.EXPLICIT_ACCESS{
		{AccessPermissions: 0x1f01ff, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid)}},
		{AccessPermissions: 0x1f01ff, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(system)}},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	runtime.KeepAlive(entries)
	return validatePublicationDirectory(path)
}

func validatePublicationDirectory(path string) error {
	return validatePublicationACL(path, true)
}

func validatePublicationACL(path string, requireProtected bool) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := validateFinalWindowsHandlePath(handle, path); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return os.ErrPermission
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return os.ErrPermission
	}
	owner, _, err := descriptor.Owner()
	current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentErr != nil || owner == nil || current == nil || current.User.Sid == nil || !owner.Equals(current.User.Sid) {
		return os.ErrPermission
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return os.ErrPermission
	}
	seenOwner, seenSystem := false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) || ace.Mask != 0x1f01ff {
			return os.ErrPermission
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return os.ErrPermission
		}
		switch {
		case sid.Equals(owner):
			seenOwner = true
		case sid.Equals(system):
			seenSystem = true
		default:
			return os.ErrPermission
		}
	}
	if !seenOwner || !seenSystem {
		return os.ErrPermission
	}
	return nil
}

func validatePublicationFile(path string) error { return validatePublicationACL(path, false) }

func validateFinalWindowsHandlePath(handle windows.Handle, expectedPath string) error {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return os.ErrInvalid
	}
	finalPath := windows.UTF16ToString(buffer[:length])
	if strings.HasPrefix(strings.ToUpper(finalPath), `\\?\UNC\`) {
		return os.ErrInvalid
	}
	if strings.HasPrefix(strings.ToUpper(finalPath), `\\?\`) {
		finalPath = finalPath[len(`\\?\`):]
	}
	absolute, err := filepath.Abs(expectedPath)
	if err != nil || !strings.EqualFold(filepath.Clean(finalPath), filepath.Clean(absolute)) {
		return os.ErrInvalid
	}
	return nil
}

var (
	kernel32Streams  = windows.NewLazySystemDLL("kernel32.dll")
	findFirstStreamW = kernel32Streams.NewProc("FindFirstStreamW")
	findNextStreamW  = kernel32Streams.NewProc("FindNextStreamW")
)

type findStreamData struct {
	size int64
	name [windows.MAX_PATH + 36]uint16
}

func onlyDefaultDataStream(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var data findStreamData
	handle, _, _ := findFirstStreamW.Call(uintptr(unsafe.Pointer(pointer)), 0, uintptr(unsafe.Pointer(&data)), 0)
	if handle == ^uintptr(0) {
		return false
	}
	defer windows.FindClose(windows.Handle(handle))
	if windows.UTF16ToString(data.name[:]) != "::$DATA" {
		return false
	}
	var next findStreamData
	result, _, callErr := findNextStreamW.Call(handle, uintptr(unsafe.Pointer(&next)))
	return result == 0 && errors.Is(callErr, windows.ERROR_HANDLE_EOF)
}

func atomicPublishDirectory(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// No MOVEFILE_REPLACE_EXISTING: an existing destination fails closed.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func syncDirectory(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := windows.FlushFileBuffers(handle); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	return nil
}
