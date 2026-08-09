//go:build !windows

package releasequalification

import "os"

func secureQualificationSnapshotPath(path string, directory bool) error {
	if directory {
		return os.Chmod(path, 0o700)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return os.ErrPermission
	}
	mode := info.Mode().Perm() & 0o700
	if mode&0o600 != 0o600 {
		return os.ErrPermission
	}
	return os.Chmod(path, mode)
}
