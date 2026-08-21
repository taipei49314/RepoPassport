//go:build !windows

package sourcequalification

import "io"

func RunWindowsAppContainerGateBootstrap(
	[]string,
	io.Reader,
	io.Writer,
	io.Writer,
) (int, bool) {
	return 0, false
}
