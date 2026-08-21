//go:build windows

package sourcequalification

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	packageWindowsMaximumStreamInfoBytes = 1 << 20
	packageWindowsMaximumStreams         = 256
	packageWindowsStreamInfoHeaderSize   = 24
)

var (
	privatePackageAppContainerPrincipal = func() (string, error) { return "", nil }
	privatePackageTestAdapterOnce       sync.Once
)

func installPrivatePackageAppContainerTestAdapter(principal func() (string, error)) {
	if principal == nil {
		return
	}
	privatePackageTestAdapterOnce.Do(func() {
		privatePackageAppContainerPrincipal = principal
	})
}

func currentPrivatePackageAppContainerSID() (*windows.SID, error) {
	principal, err := privatePackageAppContainerPrincipal()
	if err != nil {
		return nil, errors.New("source qualification AppContainer identity is unavailable")
	}
	if principal == "" {
		return nil, nil
	}
	sid, err := windows.StringToSid(principal)
	if err != nil || sid == nil || !sid.IsValid() {
		return nil, errors.New("source qualification AppContainer identity is invalid")
	}
	return sid, nil
}

func openPackageDirectory(path string) (*os.File, error) {
	return openWindowsPackagePath(
		path,
		windows.GENERIC_READ,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
}

func openPackageAncestorDirectory(path string) (*os.File, error) {
	return openWindowsPackagePath(
		path,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
}

func validatePackageAncestorDirectoryMetadata(file *os.File, info os.FileInfo) error {
	var metadata windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &metadata); err != nil {
		return errors.New("source qualification Windows directory metadata could not be read")
	}
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || !info.IsDir() {
		return errors.New("source qualification Windows directory chain contains a reparse point")
	}
	return nil
}

func validatePrivatePackagePermissions(file *os.File, _ os.FileInfo, directory bool) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("source qualification Windows private security descriptor is unavailable")
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) !=
		windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		return errors.New("source qualification Windows private DACL is not protected")
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentErr != nil || ownerDefaulted || owner == nil ||
		current == nil || current.User.Sid == nil || !owner.Equals(current.User.Sid) {
		return errors.New("source qualification Windows private owner is invalid")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return errors.New("source qualification Windows SYSTEM identity is unavailable")
	}
	appContainerSID, err := currentPrivatePackageAppContainerSID()
	if err != nil {
		return err
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	expectedCount := uint16(2)
	if appContainerSID != nil {
		expectedCount++
	}
	if err != nil || daclDefaulted || dacl == nil || dacl.AceCount != expectedCount {
		return errors.New("source qualification Windows private DACL is not exact")
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
			return errors.New("source qualification Windows private DACL contains an invalid ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return errors.New("source qualification Windows private DACL contains an invalid SID")
		}
		switch {
		case sid.Equals(owner):
			if seenOwner {
				return errors.New("source qualification Windows private owner ACE is duplicated")
			}
			seenOwner = true
		case sid.Equals(system):
			if seenSystem {
				return errors.New("source qualification Windows private SYSTEM ACE is duplicated")
			}
			seenSystem = true
		case appContainerSID != nil && sid.Equals(appContainerSID):
			if seenAppContainer {
				return errors.New("source qualification Windows private AppContainer ACE is duplicated")
			}
			seenAppContainer = true
		default:
			return errors.New("source qualification Windows private DACL grants another identity")
		}
	}
	if !seenOwner || !seenSystem || appContainerSID != nil && !seenAppContainer {
		return errors.New("source qualification Windows private DACL is incomplete")
	}
	return nil
}

func securePrivatePackagePath(path string, directory bool) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return errors.New("source qualification Windows private owner is unavailable")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return errors.New("source qualification Windows SYSTEM identity is unavailable")
	}
	appContainerSID, err := currentPrivatePackageAppContainerSID()
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
	if appContainerSID != nil {
		pinner.Pin(appContainerSID)
	}
	defer pinner.Unpin()
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: 0x1f01ff,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid),
			},
		},
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
	if appContainerSID != nil {
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
		return errors.New("source qualification Windows private DACL could not be created")
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
		return errors.New("source qualification Windows private DACL could not be applied")
	}
	runtime.KeepAlive(entries)
	runtime.KeepAlive(current)
	return nil
}

func openPackageRegularFile(path string) (*os.File, error) {
	return openWindowsPackagePath(
		path,
		windows.GENERIC_READ,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
}

func openWindowsPackagePath(path string, access, flags uint32) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("source qualification filesystem handle is invalid")
	}
	return file, nil
}

func validatePackageHandleMetadata(
	file *os.File,
	info os.FileInfo,
	directory bool,
) (packageFileIdentity, error) {
	var metadata windows.ByHandleFileInformation
	handle := windows.Handle(file.Fd())
	if err := windows.GetFileInformationByHandle(handle, &metadata); err != nil {
		return packageFileIdentity{}, errors.New("source qualification Windows metadata could not be read")
	}
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return packageFileIdentity{}, errors.New("source qualification Windows entry is a reparse point")
	}
	isDirectory := metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if directory {
		if !isDirectory || !info.IsDir() {
			return packageFileIdentity{}, errors.New("source qualification Windows directory metadata is invalid")
		}
	} else if isDirectory || !info.Mode().IsRegular() || metadata.NumberOfLinks != 1 {
		return packageFileIdentity{}, errors.New("source qualification Windows file is non-regular or hard-linked")
	}
	if err := validatePackageWindowsStreams(handle, !directory); err != nil {
		return packageFileIdentity{}, err
	}
	return packageFileIdentity{
		first:  uint64(metadata.VolumeSerialNumber),
		second: uint64(metadata.FileIndexHigh)<<32 | uint64(metadata.FileIndexLow),
	}, nil
}

func validatePackageWindowsStreams(handle windows.Handle, regular bool) error {
	bufferSize := 4096
	var buffer []byte
	for {
		buffer = make([]byte, bufferSize)
		err := windows.GetFileInformationByHandleEx(
			handle,
			windows.FileStreamInfo,
			&buffer[0],
			uint32(len(buffer)),
		)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) &&
			!errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return errors.New("source qualification Windows streams could not be inspected")
		}
		if bufferSize >= packageWindowsMaximumStreamInfoBytes {
			return errors.New("source qualification Windows streams exceed the metadata bound")
		}
		bufferSize *= 2
	}

	offset := 0
	for streamCount := 0; ; streamCount++ {
		if streamCount >= packageWindowsMaximumStreams ||
			len(buffer)-offset < packageWindowsStreamInfoHeaderSize {
			return errors.New("source qualification Windows stream metadata is invalid")
		}
		nextOffset := binary.LittleEndian.Uint32(buffer[offset : offset+4])
		nameLength := binary.LittleEndian.Uint32(buffer[offset+4 : offset+8])
		if nameLength == 0 || nameLength%2 != 0 ||
			uint64(nameLength) > uint64(len(buffer)-offset-packageWindowsStreamInfoHeaderSize) {
			return errors.New("source qualification Windows stream name is invalid")
		}
		nameStart := offset + packageWindowsStreamInfoHeaderSize
		nameEnd := nameStart + int(nameLength)
		nameBytes := buffer[nameStart:nameEnd]
		name := decodePackageWindowsStreamName(nameBytes)
		if !allowedPackageWindowsStream(name, regular) {
			return errors.New("source qualification Windows entry contains an alternate data stream")
		}
		if nextOffset == 0 {
			return nil
		}
		minimumNext := uint64(packageWindowsStreamInfoHeaderSize) + uint64(nameLength)
		if uint64(nextOffset) < minimumNext || nextOffset%8 != 0 ||
			uint64(nextOffset) > uint64(len(buffer)-offset) {
			return errors.New("source qualification Windows stream metadata is invalid")
		}
		offset += int(nextOffset)
	}
}

func decodePackageWindowsStreamName(data []byte) string {
	codeUnits := make([]uint16, len(data)/2)
	for index := range codeUnits {
		codeUnits[index] = binary.LittleEndian.Uint16(data[index*2 : index*2+2])
	}
	return string(utf16.Decode(codeUnits))
}

func allowedPackageWindowsStream(name string, regular bool) bool {
	if name == "::$DATA" || name == ":$DATA" {
		return true
	}
	if regular {
		return false
	}
	return !strings.HasSuffix(strings.ToUpper(name), ":$DATA")
}

func publishPackageDirectoryNoReplace(stagingPath, outputPath string) error {
	from, err := windows.UTF16PtrFromString(stagingPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(outputPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func syncPackageDirectory(_ *os.File) error {
	return nil
}

func validatePackagePlatformPath(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("source qualification Windows path is not a local absolute path")
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || strings.Contains(path[len(volume):], ":") {
		return errors.New("source qualification Windows path uses a device or alternate stream")
	}
	return nil
}
