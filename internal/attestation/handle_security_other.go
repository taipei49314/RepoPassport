//go:build !windows

package attestation

import (
	"fmt"
	"os"
	"syscall"
)

func validatePrivateKeyHandle(file *os.File, _ string) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key handle permissions allow group or other access")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("private key hardlink count is not one")
	}
	return nil
}

func validateDirectoryHandle(*os.File, string) error { return nil }

func validateStableInputHandle(file *os.File, _ string) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("stable input hardlink count is not one")
	}
	return nil
}
