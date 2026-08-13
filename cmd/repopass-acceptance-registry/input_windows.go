//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	acceptanceMaximumStreamInfoBytes = 1 << 20
	acceptanceMaximumStreams         = 256
	acceptanceStreamInfoHeaderSize   = 24
)

func openAcceptanceInput(path string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("input handle is invalid")
	}
	return file, nil
}

func validateAcceptanceInputMetadata(file *os.File, info os.FileInfo) error {
	var metadata windows.ByHandleFileInformation
	handle := windows.Handle(file.Fd())
	if err := windows.GetFileInformationByHandle(handle, &metadata); err != nil {
		return errors.New("input metadata is unavailable")
	}
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		!info.Mode().IsRegular() || metadata.NumberOfLinks != 1 {
		return errors.New("input metadata is invalid")
	}
	return validateAcceptanceStreams(handle)
}

func validateAcceptanceStreams(handle windows.Handle) error {
	bufferSize := 4096
	var buffer []byte
	for {
		buffer = make([]byte, bufferSize)
		err := windows.GetFileInformationByHandleEx(handle, windows.FileStreamInfo, &buffer[0], uint32(len(buffer)))
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil
		}
		if (!errors.Is(err, windows.ERROR_MORE_DATA) && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER)) || bufferSize >= acceptanceMaximumStreamInfoBytes {
			return errors.New("input streams are unavailable")
		}
		bufferSize *= 2
	}
	offset := 0
	for count := 0; ; count++ {
		if count >= acceptanceMaximumStreams || len(buffer)-offset < acceptanceStreamInfoHeaderSize {
			return errors.New("input stream metadata is invalid")
		}
		nextOffset := binary.LittleEndian.Uint32(buffer[offset : offset+4])
		nameLength := binary.LittleEndian.Uint32(buffer[offset+4 : offset+8])
		if nameLength == 0 || nameLength%2 != 0 || uint64(nameLength) > uint64(len(buffer)-offset-acceptanceStreamInfoHeaderSize) {
			return errors.New("input stream metadata is invalid")
		}
		nameStart := offset + acceptanceStreamInfoHeaderSize
		name := decodeAcceptanceStreamName(buffer[nameStart : nameStart+int(nameLength)])
		if name != "::$DATA" && name != ":$DATA" {
			return errors.New("input contains an alternate stream")
		}
		if nextOffset == 0 {
			return nil
		}
		minimumNext := uint64(acceptanceStreamInfoHeaderSize) + uint64(nameLength)
		if uint64(nextOffset) < minimumNext || nextOffset%8 != 0 || uint64(nextOffset) > uint64(len(buffer)-offset) {
			return errors.New("input stream metadata is invalid")
		}
		offset += int(nextOffset)
	}
}

func decodeAcceptanceStreamName(data []byte) string {
	codeUnits := make([]uint16, len(data)/2)
	for index := range codeUnits {
		codeUnits[index] = binary.LittleEndian.Uint16(data[index*2 : index*2+2])
	}
	return string(utf16.Decode(codeUnits))
}

func secureAcceptanceOutput(path string, file *os.File) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return errors.New("output owner is unavailable")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return errors.New("SYSTEM identity is unavailable")
	}
	var pinner runtime.Pinner
	pinner.Pin(current.User.Sid)
	pinner.Pin(system)
	defer pinner.Unpin()
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: 0x1f01ff,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid),
			},
		},
		{
			AccessPermissions: 0x1f01ff,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return errors.New("output DACL is unavailable")
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
		return errors.New("output DACL could not be applied")
	}
	runtime.KeepAlive(entries)
	runtime.KeepAlive(current)
	info, err := file.Stat()
	if err != nil {
		return errors.New("output metadata is unavailable")
	}
	return validateAcceptanceOutputSecurity(file, info)
}

func validateAcceptanceOutputSecurity(file *os.File, info os.FileInfo) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("output security descriptor is unavailable")
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		return errors.New("output DACL is not protected")
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentErr != nil || ownerDefaulted || owner == nil || current == nil || current.User.Sid == nil || !owner.Equals(current.User.Sid) {
		return errors.New("output owner is invalid")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return errors.New("SYSTEM identity is unavailable")
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || daclDefaulted || dacl == nil || dacl.AceCount != 2 {
		return errors.New("output DACL is not exact")
	}
	seenOwner, seenSystem := false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) || ace.Mask != 0x1f01ff {
			return errors.New("output DACL contains an invalid ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return errors.New("output DACL contains an invalid SID")
		}
		switch {
		case sid.Equals(owner):
			if seenOwner {
				return errors.New("output owner ACE is duplicated")
			}
			seenOwner = true
		case sid.Equals(system):
			if seenSystem {
				return errors.New("output SYSTEM ACE is duplicated")
			}
			seenSystem = true
		default:
			return errors.New("output DACL grants another identity")
		}
	}
	if !seenOwner || !seenSystem {
		return errors.New("output DACL is incomplete")
	}
	return validateAcceptanceInputMetadata(file, info)
}
