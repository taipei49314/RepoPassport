//go:build !unix && !windows

package trustchainstate

import "testing"

func testPlatformSecurityAndAtomicity(t *testing.T) {
	t.Skip("durable state is unavailable on this platform")
}
