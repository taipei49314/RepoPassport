//go:build !windows

package spdx

import (
	"os"
	"syscall"
)

func isReparsePoint(string) bool                  { return false }
func validateOpenedHandle(*os.File, string) error { return nil }

func validateExclusiveLink(file *os.File) error {
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
