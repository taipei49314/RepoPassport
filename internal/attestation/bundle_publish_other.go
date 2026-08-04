//go:build !windows

package attestation

import "os"

func publishBundleNoReplace(source, destination string) (bool, error) {
	if err := os.Link(source, destination); err != nil {
		return false, err
	}
	if err := os.Remove(source); err != nil {
		return true, err
	}
	return true, nil
}

func syncBundleDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
