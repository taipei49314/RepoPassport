//go:build unix

package manifest

import (
	"os"
	"syscall"
)

func isManifestReparsePoint(string) bool { return false }

func validateManifestOpenedHandle(file *os.File, _ string) error {
	info, err := file.Stat()
	if err != nil {
		return os.ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return os.ErrInvalid
	}
	return nil
}
