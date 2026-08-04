package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data only after a same-directory temporary file has
// been written, flushed, and closed.
func Write(path string, data []byte, mode os.FileMode) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".repopass-atomic-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replace(tempPath, absolute); err != nil {
		return fmt.Errorf("atomically replace %s: %w", absolute, err)
	}
	return syncDirectory(directory)
}
