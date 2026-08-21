//go:build !linux && !windows

package sourcequalification

import (
	"errors"
	"os"
)

func openPackageDirectory(path string) (*os.File, error) {
	return os.Open(path)
}

func openPackageAncestorDirectory(path string) (*os.File, error) {
	return openPackageDirectory(path)
}

func openPackageRegularFile(path string) (*os.File, error) {
	return os.Open(path)
}

func validatePackageHandleMetadata(
	_ *os.File,
	_ os.FileInfo,
	_ bool,
) (packageFileIdentity, error) {
	return packageFileIdentity{}, errors.New("source qualification package assembly is unsupported on this platform")
}

func validatePackageAncestorDirectoryMetadata(_ *os.File, _ os.FileInfo) error {
	return errors.New("source qualification package assembly is unsupported on this platform")
}

func validatePrivatePackagePermissions(_ *os.File, _ os.FileInfo, _ bool) error {
	return errors.New("source qualification package assembly is unsupported on this platform")
}

func securePrivatePackagePath(_ string, _ bool) error {
	return errors.New("source qualification package assembly is unsupported on this platform")
}

func publishPackageDirectoryNoReplace(_, _ string) error {
	return errors.New("source qualification package assembly is unsupported on this platform")
}

func syncPackageDirectory(_ *os.File) error {
	return errors.New("source qualification package assembly is unsupported on this platform")
}

func validatePackagePlatformPath(_ string) error {
	return errors.New("source qualification package assembly is unsupported on this platform")
}
