//go:build windows

package windowssecurity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const finalPathVolumeNameNone uint32 = 4

var errAppContainerPathInvalid = errors.New("Windows AppContainer path information is invalid")

// AppContainerFinalPath verifies that handle is the exact clean DOS path
// expectedPath without requiring a DOS-volume final-name lookup.
func AppContainerFinalPath(handle windows.Handle, expectedPath string) error {
	contained, err := CurrentProcessIsAppContainer()
	if err != nil || !contained {
		return errAppContainerPathInvalid
	}
	expected, expectedWithoutVolume, ok := cleanAbsoluteDOSPath(expectedPath)
	if !ok {
		return errAppContainerPathInvalid
	}
	actual, err := finalPathWithoutVolume(handle)
	if err != nil || !strings.EqualFold(filepath.Clean(actual), expectedWithoutVolume) {
		return errAppContainerPathInvalid
	}

	pointer, err := windows.UTF16PtrFromString(expected)
	if err != nil {
		return errAppContainerPathInvalid
	}
	reopened, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errAppContainerPathInvalid
	}
	defer windows.CloseHandle(reopened)

	var actualInformation, expectedInformation windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &actualInformation); err != nil {
		return errAppContainerPathInvalid
	}
	if err := windows.GetFileInformationByHandle(reopened, &expectedInformation); err != nil {
		return errAppContainerPathInvalid
	}
	if actualInformation.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		expectedInformation.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		actualInformation.VolumeSerialNumber != expectedInformation.VolumeSerialNumber ||
		actualInformation.FileIndexHigh != expectedInformation.FileIndexHigh ||
		actualInformation.FileIndexLow != expectedInformation.FileIndexLow {
		return errAppContainerPathInvalid
	}
	return nil
}

// ResolveAppContainerPath preserves filepath.EvalSymlinks on a host token and
// uses exact handle identity only inside the qualification AppContainer.
func ResolveAppContainerPath(path string) (string, error) {
	contained, err := CurrentProcessIsAppContainer()
	if err != nil {
		return "", err
	}
	if !contained {
		return filepath.EvalSymlinks(path)
	}
	expected, _, ok := cleanAbsoluteDOSPath(path)
	if !ok {
		return "", errAppContainerPathInvalid
	}
	pointer, err := windows.UTF16PtrFromString(expected)
	if err != nil {
		return "", errAppContainerPathInvalid
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", errAppContainerPathInvalid
	}
	defer windows.CloseHandle(handle)
	if err := AppContainerFinalPath(handle, expected); err != nil {
		return "", err
	}
	return expected, nil
}

// CurrentAppContainerPathBoundary freezes the bootstrap-controlled temporary
// directory used by a qualification test binary. Host test binaries have no
// boundary and retain their normal filesystem behavior.
func CurrentAppContainerPathBoundary() (string, error) {
	contained, err := CurrentProcessIsAppContainer()
	if err != nil {
		return "", err
	}
	if !contained {
		return "", nil
	}
	boundary := os.Getenv("GOTMPDIR")
	resolved, err := ResolveAppContainerPath(boundary)
	if err != nil || !strings.EqualFold(resolved, boundary) {
		return "", errAppContainerPathInvalid
	}
	return resolved, nil
}

// AppContainerPathBoundary returns the frozen boundary only for exact child
// paths. Any escape or malformed path fails closed.
func AppContainerPathBoundary(path, boundary string) (string, error) {
	if boundary == "" {
		return "", nil
	}
	cleanPath, _, pathOK := cleanAbsoluteDOSPath(path)
	cleanBoundary, _, boundaryOK := cleanAbsoluteDOSPath(boundary)
	if !pathOK || !boundaryOK {
		return "", errAppContainerPathInvalid
	}
	relative, err := filepath.Rel(cleanBoundary, cleanPath)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return "", errAppContainerPathInvalid
	}
	return cleanBoundary, nil
}

func finalPathWithoutVolume(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(
		handle,
		&buffer[0],
		uint32(len(buffer)),
		finalPathVolumeNameNone,
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", errAppContainerPathInvalid
	}
	path := windows.UTF16ToString(buffer[:length])
	if path == "" || strings.HasPrefix(path, `\\`) || !strings.HasPrefix(path, `\`) ||
		strings.IndexByte(path, 0) >= 0 || strings.Contains(path, ":") || filepath.Clean(path) != path {
		return "", errAppContainerPathInvalid
	}
	return path, nil
}

func cleanAbsoluteDOSPath(path string) (string, string, bool) {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", false
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' ||
		!((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
		return "", "", false
	}
	withoutVolume := strings.TrimPrefix(path, volume)
	if !strings.HasPrefix(withoutVolume, `\`) || strings.HasPrefix(withoutVolume, `\\`) ||
		strings.Contains(withoutVolume, ":") || filepath.Clean(withoutVolume) != withoutVolume {
		return "", "", false
	}
	return path, withoutVolume, true
}
