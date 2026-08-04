//go:build windows

package attestation

import "golang.org/x/sys/windows"

func publishBundleNoReplace(source, destination string) (bool, error) {
	sourcePointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return false, err
	}
	destinationPointer, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return false, err
	}
	if err := windows.MoveFileEx(
		sourcePointer,
		destinationPointer,
		windows.MOVEFILE_WRITE_THROUGH,
	); err != nil {
		return false, err
	}
	return true, nil
}

func syncBundleDirectory(string) error {
	// MOVEFILE_WRITE_THROUGH flushes the no-replace publication before return.
	return nil
}
