//go:build unix

package releasestate

import (
	"os"
	"path/filepath"
	"syscall"
)

func safeNativePath(value string) bool  { return safeNativeInput(value) }
func safeNativeInput(value string) bool { return value != "" && !containsNUL(value) }
func isReparsePoint(string) bool        { return false }

func createPrivateDirectory(path string) (bool, error) {
	err := os.Mkdir(path, 0o700)
	if err == nil {
		return true, nil
	}
	if os.IsExist(err) {
		return false, nil
	}
	return false, err
}

func createPrivateLock(path string) (*os.File, bool, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return file, true, nil
	}
	if os.IsExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func openExistingPrivateLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}

func validateDirectoryPlatform(_ string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnavailable
	}
	return nil
}

func validatePrivateStateDirectoryPlatform(_ string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return ErrUnavailable
	}
	return nil
}

func convergePrivateFile(*os.File, string) error { return nil }

func validateOpenedRegularFile(file *os.File, expectedPath string, singleLink bool) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ErrUnavailable
	}
	pathInfo, err := os.Lstat(expectedPath)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return ErrUnavailable
	}
	if singleLink {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
			return ErrUnavailable
		}
	}
	actual, err := filepath.EvalSymlinks(expectedPath)
	if err != nil || !samePath(expectedPath, actual) {
		return ErrUnavailable
	}
	return nil
}

func atomicReplace(source, destination string) error { return os.Rename(source, destination) }

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func samePathPlatform(left, right string) bool { return left == right }
