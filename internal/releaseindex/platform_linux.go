//go:build linux

package releaseindex

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func isReparsePoint(string) bool { return false }

func hardlinkCount(file *os.File) uint64 {
	info, err := file.Stat()
	if err != nil {
		return 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func validateOpenedPath(*os.File, string) error    { return nil }
func validateNoAlternateDataStreams(string) error  { return nil }
func securePublicationDirectory(path string) error { return os.Chmod(path, 0o700) }
func securePublicationFile(path string) error      { return os.Chmod(path, 0o600) }
func validatePublicationDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return os.ErrPermission
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink < 1 {
		return os.ErrPermission
	}
	directory, err := os.Open(path)
	if err != nil {
		return os.ErrPermission
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		return os.ErrPermission
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != uint32(os.Geteuid()) || openedStat.Nlink < 1 {
		return os.ErrPermission
	}
	return nil
}
func validatePublicationFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return os.ErrPermission
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return os.ErrPermission
	}
	file, err := os.Open(path)
	if err != nil {
		return os.ErrPermission
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return os.ErrPermission
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != uint32(os.Geteuid()) || openedStat.Nlink != 1 {
		return os.ErrPermission
	}
	return nil
}

func atomicPublishDirectory(source, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
