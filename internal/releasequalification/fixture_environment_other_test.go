//go:build !windows

package releasequalification

func qualificationFixtureImportRequired() (bool, error) {
	return false, nil
}
