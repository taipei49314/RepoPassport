//go:build !windows

package sourcequalification

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func packageContainmentFileIdentity(
	file *os.File,
	info os.FileInfo,
) (packageFileIdentity, error) {
	var metadata unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &metadata); err != nil {
		return packageFileIdentity{}, errors.New("source qualification path identity is unavailable")
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG || !info.Mode().IsRegular() {
		return packageFileIdentity{}, errors.New("source qualification path is unsafe")
	}
	return packageFileIdentity{
		first:  uint64(metadata.Dev),
		second: metadata.Ino,
	}, nil
}

func packageContainmentDirectoryIdentity(
	file *os.File,
	info os.FileInfo,
) (packageFileIdentity, error) {
	return validatePackageHandleMetadata(file, info, true)
}

func equalPackageMissingPathComponent(left, right string) bool {
	return left == right
}
