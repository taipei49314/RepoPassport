//go:build windows

package attestation

import "syscall"

func isReparsePoint(path string) bool {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := syscall.GetFileAttributes(pointer)
	if err != nil {
		return true
	}
	const fileAttributeReparsePoint = 0x400
	return attributes&fileAttributeReparsePoint != 0
}
