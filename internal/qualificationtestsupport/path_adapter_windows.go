//go:build windows

// Package qualificationtestsupport installs qualification-only test seams.
package qualificationtestsupport

import "github.com/taipei49314/RepoPassport/internal/pathsecurity"

func init() {
	if err := pathsecurity.InstallQualificationTestAdapter(); err != nil {
		panic(err.Error())
	}
}
