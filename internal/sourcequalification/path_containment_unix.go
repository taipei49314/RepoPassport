//go:build !windows

package sourcequalification

import "os"

func packageContainmentDirectoryIdentity(
	file *os.File,
	info os.FileInfo,
) (packageFileIdentity, error) {
	return validatePackageHandleMetadata(file, info, true)
}

func equalPackageMissingPathComponent(left, right string) bool {
	return left == right
}
