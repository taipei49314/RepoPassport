//go:build !windows

package acquisition

func isReparsePoint(string) bool { return false }
