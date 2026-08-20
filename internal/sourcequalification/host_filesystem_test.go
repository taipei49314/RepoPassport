package sourcequalification

import (
	"testing"

	"github.com/taipei49314/RepoPassport/internal/testsupport"
)

func requireHostFilesystem(t testing.TB) {
	t.Helper()
	testsupport.RequireHostFilesystem(t)
}

func inAppContainer(t testing.TB) bool {
	t.Helper()
	return testsupport.IsAppContainer(t)
}
