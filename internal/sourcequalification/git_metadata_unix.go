//go:build !windows

package sourcequalification

import (
	"errors"
	"os"
	"syscall"
)

func validateNoLinkMetadata(_ string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("filesystem metadata contains a link or redirected entry")
	}
	if info.Mode().IsRegular() {
		return validateUnixRegularFileMetadata(info, "")
	}
	return nil
}

func validateWorktreeEntryMetadata(_ string, info os.FileInfo, gitMode string) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("worktree contains a link or redirected entry")
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	return validateUnixRegularFileMetadata(info, gitMode)
}

func validateOpenedWorktreeFileMetadata(_ *os.File, info os.FileInfo, gitMode string) error {
	return validateUnixRegularFileMetadata(info, gitMode)
}

func validateUnixRegularFileMetadata(info os.FileInfo, gitMode string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("regular file has a hard-link alias")
	}
	if gitMode == "" {
		return nil
	}
	if gitMode != "100644" && gitMode != "100755" {
		return errors.New("tracked file has an unsupported Git mode")
	}
	wantExecutable := gitMode == "100755"
	isExecutable := info.Mode().Perm()&0o111 != 0
	if wantExecutable != isExecutable {
		return errors.New("tracked worktree executable mode differs from the Git tree")
	}
	return nil
}
