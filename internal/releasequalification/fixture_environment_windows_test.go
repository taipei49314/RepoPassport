//go:build windows

package releasequalification

import "github.com/taipei49314/RepoPassport/internal/windowssecurity"

func qualificationFixtureImportRequired() (bool, error) {
	return windowssecurity.CurrentProcessIsAppContainer()
}
