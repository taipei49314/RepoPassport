//go:build !windows

package attestation

import "testing"

func securePrivatePermissionsForTest(*testing.T, string) {}
