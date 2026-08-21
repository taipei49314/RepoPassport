//go:build !windows

package sourcequalification

import "os"

func toolAssemblyCreatePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	if err := securePrivatePackagePath(path, true); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func toolAssemblyCreatePrivateFile(path string, raw []byte) error {
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	if err := securePrivatePackagePath(path, false); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
