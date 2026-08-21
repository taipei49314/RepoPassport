//go:build !windows

package pathsecurity

import "path/filepath"

func Resolve(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func QualificationTestDescriptor() (string, bool) {
	return "", false
}

func QualificationPathContains(string, string) (bool, bool, error) {
	return false, false, nil
}

func QualificationPathBoundary(string, string) (string, bool, error) {
	return "", false, nil
}
