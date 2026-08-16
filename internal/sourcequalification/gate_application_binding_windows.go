//go:build windows

package sourcequalification

import (
	"os"

	"golang.org/x/sys/windows"
)

// gateFileIdentity is the NTFS name→file binding: volume serial and file index.
type gateFileIdentity struct {
	volumeSerial uint32
	indexHigh    uint32
	indexLow     uint32
}

// openHeldGateApplicationFile holds the resolved file with read access and
// FILE_SHARE_READ only: while the handle is open the OS denies every writer,
// deleter, and rename over the file, but CreateProcess can still execute it.
func openHeldGateApplicationFile(path string) (*os.File, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func heldGateFileIdentity(file *os.File) (gateFileIdentity, error) {
	return windowsGateFileIdentity(windows.Handle(file.Fd()))
}

// currentGateFileIdentity re-opens the path with a compatible read-only,
// share-read request and reads the identity of whatever file the name resolves
// to now. A held file admits this open; a swapped name fails the identity
// comparison.
func currentGateFileIdentity(path string) (gateFileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return gateFileIdentity{}, errGateApplicationBindingViolated
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return gateFileIdentity{}, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return gateFileIdentity{}, err
	}
	defer windows.CloseHandle(handle)
	return windowsGateFileIdentity(handle)
}

func windowsGateFileIdentity(handle windows.Handle) (gateFileIdentity, error) {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return gateFileIdentity{}, err
	}
	return gateFileIdentity{
		volumeSerial: information.VolumeSerialNumber,
		indexHigh:    information.FileIndexHigh,
		indexLow:     information.FileIndexLow,
	}, nil
}

func sameGateFileIdentity(left, right gateFileIdentity) bool {
	return left == right
}
