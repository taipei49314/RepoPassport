//go:build !windows

package sourcequalification

import "os"

func controllerRuntimeToolPathEntries(directory string) ([]os.DirEntry, error) {
	return os.ReadDir(directory)
}
