//go:build !windows

package attestation

func isReparsePoint(string) bool { return false }
