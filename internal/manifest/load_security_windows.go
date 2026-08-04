//go:build windows

package manifest

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func isManifestReparsePoint(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func validateManifestOpenedHandle(file *os.File, expectedPath string) error {
	handle := windows.Handle(file.Fd())
	buffer := make([]uint16, 32_768)
	count, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || count == 0 || count >= uint32(len(buffer)) {
		return os.ErrInvalid
	}
	actual := strings.TrimPrefix(windows.UTF16ToString(buffer[:count]), `\\?\`)
	expected, err := filepath.Abs(expectedPath)
	if err != nil || !strings.EqualFold(filepath.Clean(actual), filepath.Clean(expected)) {
		return os.ErrInvalid
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.NumberOfLinks != 1 {
		return os.ErrInvalid
	}
	return nil
}
