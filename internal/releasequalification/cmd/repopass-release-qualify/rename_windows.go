//go:build windows

package main

import "golang.org/x/sys/windows"

func atomicPublishDirectoryNoReplace(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// Deliberately omit MOVEFILE_REPLACE_EXISTING. A destination created after
	// the last Lstat remains an error rather than being overwritten.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
