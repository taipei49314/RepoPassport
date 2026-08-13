//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openAcceptanceInput(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("input handle is invalid")
	}
	return file, nil
}

func validateAcceptanceInputMetadata(file *os.File, info os.FileInfo) error {
	var metadata unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &metadata); err != nil {
		return errors.New("input metadata is unavailable")
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG || !info.Mode().IsRegular() || metadata.Nlink != 1 {
		return errors.New("input metadata is invalid")
	}
	return nil
}

func secureAcceptanceOutput(path string, file *os.File) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return errors.New("output permissions are unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		return errors.New("output metadata is unavailable")
	}
	return validateAcceptanceOutputSecurity(file, info)
}

func validateAcceptanceOutputSecurity(file *os.File, info os.FileInfo) error {
	var metadata unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &metadata); err != nil {
		return errors.New("output metadata is unavailable")
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG || metadata.Nlink != 1 ||
		int(metadata.Uid) != os.Geteuid() || info.Mode().Perm() != 0o600 {
		return errors.New("output metadata is not private")
	}
	return nil
}
