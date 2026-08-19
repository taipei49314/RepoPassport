//go:build windows

package sourcequalification

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func packageContainmentFileIdentity(
	file *os.File,
	info os.FileInfo,
) (packageFileIdentity, error) {
	var metadata windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&metadata,
	); err != nil {
		return packageFileIdentity{}, errors.New("source qualification path identity is unavailable")
	}
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || !info.Mode().IsRegular() {
		return packageFileIdentity{}, errors.New("source qualification path is unsafe")
	}
	return packageFileIdentity{
		first:  uint64(metadata.VolumeSerialNumber),
		second: uint64(metadata.FileIndexHigh)<<32 | uint64(metadata.FileIndexLow),
	}, nil
}

func packageContainmentDirectoryIdentity(
	file *os.File,
	info os.FileInfo,
) (packageFileIdentity, error) {
	var metadata windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&metadata,
	); err != nil {
		return packageFileIdentity{}, errors.New("source qualification path identity is unavailable")
	}
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || !info.IsDir() {
		return packageFileIdentity{}, errors.New("source qualification path ancestor is unsafe")
	}
	return packageFileIdentity{
		first:  uint64(metadata.VolumeSerialNumber),
		second: uint64(metadata.FileIndexHigh)<<32 | uint64(metadata.FileIndexLow),
	}, nil
}

func equalPackageMissingPathComponent(left, right string) bool {
	return strings.EqualFold(left, right)
}
