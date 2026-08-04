package controllerfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// RemoveTree removes a controller-owned directory after restoring the owner
// permissions needed to traverse and unlink a deliberately read-only tree.
// WalkDir does not follow symbolic links, so cleanup cannot chmod a target
// outside the tree through a workload-controlled link.
func RemoveTree(root string) error {
	absolute, err := validatedTreeRoot(root)
	if err != nil {
		return err
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("controller cleanup root is not a physical directory: %s", absolute)
	}

	restoreErr := restoreOwnerAccess(absolute)
	removeErr := os.RemoveAll(absolute)
	if removeErr != nil {
		return errors.Join(restoreErr, removeErr)
	}
	if _, statErr := os.Lstat(absolute); statErr == nil {
		return errors.Join(restoreErr, errors.New("controller cleanup directory still exists"))
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.Join(restoreErr, statErr)
	}
	return nil
}

func restoreOwnerAccess(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return os.Chmod(path, info.Mode().Perm()|0o700)
		case info.Mode().IsRegular():
			return os.Chmod(path, info.Mode().Perm()|0o600)
		default:
			return nil
		}
	})
}

func validatedTreeRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("controller cleanup root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	volumeRoot := filepath.VolumeName(absolute) + string(filepath.Separator)
	if samePath(absolute, volumeRoot) {
		return "", errors.New("refusing to remove a filesystem root")
	}
	return absolute, nil
}

func samePath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(first, second)
	}
	return first == second
}
