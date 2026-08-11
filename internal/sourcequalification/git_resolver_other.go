//go:build !linux && !windows

package sourcequalification

import "errors"

func resolveTrustedGitExecutablePlatform(string) (string, error) {
	return "", errors.New("fixed machine Git application is unsupported on this platform")
}
