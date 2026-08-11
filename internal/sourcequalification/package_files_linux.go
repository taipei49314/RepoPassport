//go:build linux

package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openPackageDirectory(path string) (*os.File, error) {
	return openLinuxPackagePath(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW)
}

func openPackageRegularFile(path string) (*os.File, error) {
	return openLinuxPackagePath(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
}

func openLinuxPackagePath(path string, flags int) (*os.File, error) {
	descriptor, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("source qualification filesystem handle is invalid")
	}
	return file, nil
}

func validatePackageHandleMetadata(
	file *os.File,
	info os.FileInfo,
	directory bool,
) (packageFileIdentity, error) {
	var metadata unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &metadata); err != nil {
		return packageFileIdentity{}, errors.New("source qualification filesystem metadata could not be read")
	}
	kind := metadata.Mode & unix.S_IFMT
	if directory {
		if kind != unix.S_IFDIR || !info.IsDir() {
			return packageFileIdentity{}, errors.New("source qualification directory metadata is invalid")
		}
	} else if kind != unix.S_IFREG || !info.Mode().IsRegular() || metadata.Nlink != 1 {
		return packageFileIdentity{}, errors.New("source qualification file metadata contains a link or non-regular entry")
	}
	return packageFileIdentity{
		first:  uint64(metadata.Dev),
		second: metadata.Ino,
	}, nil
}

func validatePackageAncestorDirectoryMetadata(file *os.File, info os.FileInfo) error {
	_, err := validatePackageHandleMetadata(file, info, true)
	return err
}

func validatePrivatePackagePermissions(_ *os.File, info os.FileInfo, directory bool) error {
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if info.Mode().Perm() != want ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("source qualification staging permissions are not private")
	}
	return nil
}

func securePrivatePackagePath(path string, directory bool) error {
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if err := os.Chmod(path, want); err != nil {
		return errors.New("source qualification staging permissions could not be restricted")
	}
	return nil
}

func publishPackageDirectoryNoReplace(stagingPath, outputPath string) error {
	return unix.Renameat2(
		unix.AT_FDCWD,
		stagingPath,
		unix.AT_FDCWD,
		outputPath,
		unix.RENAME_NOREPLACE,
	)
}

func syncPackageDirectory(directory *os.File) error {
	return directory.Sync()
}

func validatePackagePlatformPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("source qualification filesystem path is not absolute")
	}
	return nil
}
