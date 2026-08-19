//go:build !windows && !linux

package sourcequalification

import "os"

func reapUnixQualificationWorkspaceHolders(string, *os.File) {}
