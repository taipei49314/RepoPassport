//go:build windows

package sourcequalification

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func canonicalTrustedRuntimePathPlatform(path string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", errGateInvalidInput
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return "", errGateInvalidInput
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", errGateInvalidInput
	}
	actual := windows.UTF16ToString(buffer[:length])
	upper := strings.ToUpper(actual)
	if strings.HasPrefix(upper, `\\?\UNC\`) {
		return "", errGateInvalidInput
	}
	if strings.HasPrefix(upper, `\\?\`) {
		actual = actual[len(`\\?\`):]
	}
	actual = filepath.Clean(actual)
	if err := validatePackagePlatformPath(actual); err != nil {
		return "", errGateInvalidInput
	}
	return actual, nil
}
