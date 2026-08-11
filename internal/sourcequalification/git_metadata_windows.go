//go:build windows

package sourcequalification

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	maximumWindowsStreamInfoBytes = 1 << 20
	maximumWindowsStreams         = 256
	windowsStreamInfoHeaderSize   = 24
)

func validateNoLinkMetadata(path string, info os.FileInfo) error {
	return validateWindowsPathMetadata(path, info.Mode().IsRegular())
}

func validateWorktreeEntryMetadata(path string, info os.FileInfo, gitMode string) error {
	if gitMode != "" && gitMode != "100644" && gitMode != "100755" {
		return errors.New("tracked file has an unsupported Git mode")
	}
	return validateWindowsPathMetadata(path, info.Mode().IsRegular())
}

func validateOpenedWorktreeFileMetadata(file *os.File, info os.FileInfo, gitMode string) error {
	if gitMode != "100644" && gitMode != "100755" {
		return errors.New("tracked file has an unsupported Git mode")
	}
	return validateWindowsHandleMetadata(windows.Handle(file.Fd()), info.Mode().IsRegular())
}

func validateWindowsPathMetadata(path string, regular bool) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("Windows filesystem path metadata is invalid")
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.New("Windows filesystem metadata could not be opened")
	}
	defer windows.CloseHandle(handle)
	return validateWindowsHandleMetadata(handle, regular)
}

func validateWindowsHandleMetadata(handle windows.Handle, regular bool) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return errors.New("Windows filesystem metadata could not be read")
	}
	links := uint32(1)
	if regular {
		links = information.NumberOfLinks
	}
	if err := validateWindowsFileMetadata(information.FileAttributes, 0, links); err != nil {
		return err
	}
	return validateWindowsStreams(handle, regular)
}

func validateWindowsFileMetadata(fileAttributes uint32, reparseTag uint32, numberOfLinks uint32) error {
	if fileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || reparseTag != 0 {
		return errors.New("Windows filesystem entry is a reparse point")
	}
	if numberOfLinks != 1 {
		return errors.New("Windows regular file has a hard-link alias")
	}
	return nil
}

func validateWindowsStreams(handle windows.Handle, regular bool) error {
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
		if !errors.Is(err, windows.ERROR_MORE_DATA) && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return errors.New("Windows file streams could not be inspected")
		}
		if bufferSize >= maximumWindowsStreamInfoBytes {
			return errors.New("Windows file streams exceed the metadata bound")
		}
		bufferSize *= 2
	}

	offset := 0
	for streamCount := 0; ; streamCount++ {
		if streamCount >= maximumWindowsStreams || len(buffer)-offset < windowsStreamInfoHeaderSize {
			return errors.New("Windows file stream metadata is invalid")
		}
		nextOffset := binary.LittleEndian.Uint32(buffer[offset : offset+4])
		nameLength := binary.LittleEndian.Uint32(buffer[offset+4 : offset+8])
		if nameLength == 0 || nameLength%2 != 0 || uint64(nameLength) > uint64(len(buffer)-offset-windowsStreamInfoHeaderSize) {
			return errors.New("Windows file stream name is invalid")
		}
		nameBytes := buffer[offset+windowsStreamInfoHeaderSize : offset+windowsStreamInfoHeaderSize+int(nameLength)]
		name := decodeWindowsStreamName(nameBytes)
		if !allowedWindowsStream(name, regular) {
			return errors.New("Windows filesystem entry contains an alternate data stream")
		}
		if nextOffset == 0 {
			return nil
		}
		minimumNext := uint64(windowsStreamInfoHeaderSize) + uint64(nameLength)
		if uint64(nextOffset) < minimumNext || nextOffset%8 != 0 || uint64(nextOffset) > uint64(len(buffer)-offset) {
			return errors.New("Windows file stream metadata is invalid")
		}
		offset += int(nextOffset)
	}
}

func decodeWindowsStreamName(data []byte) string {
	codeUnits := make([]uint16, len(data)/2)
	for index := range codeUnits {
		codeUnits[index] = binary.LittleEndian.Uint16(data[index*2 : index*2+2])
	}
	return string(utf16.Decode(codeUnits))
}

func allowedWindowsStream(name string, regular bool) bool {
	if name == "::$DATA" {
		return true
	}
	if regular {
		return false
	}
	return !strings.HasSuffix(strings.ToUpper(name), ":$DATA")
}
