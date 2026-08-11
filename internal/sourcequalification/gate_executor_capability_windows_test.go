//go:build windows

package sourcequalification

func gateExecutorIsolationUnavailableForTest(NetworkMode) bool {
	return false
}
