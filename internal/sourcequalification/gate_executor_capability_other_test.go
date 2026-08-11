//go:build !linux && !windows

package sourcequalification

func gateExecutorIsolationUnavailableForTest(NetworkMode) bool {
	return false
}
