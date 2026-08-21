//go:build !windows

package attestation

import "os"

func writePrivateFileForTest(path string, content []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, content, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
