//go:build !windows

package testsupport

func currentProcessIsAppContainer() (bool, error) {
	return false, nil
}
