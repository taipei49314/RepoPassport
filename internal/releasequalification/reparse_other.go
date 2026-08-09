//go:build !windows

package releasequalification

func qualificationPathHasReparsePoint(string) bool { return false }
