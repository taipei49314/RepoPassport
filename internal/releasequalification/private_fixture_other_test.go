//go:build !windows

package releasequalification

import "testing"

func privateQualificationFixtureDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
