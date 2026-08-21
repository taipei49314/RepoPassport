//go:build windows

package releasequalification

import (
	_ "github.com/taipei49314/RepoPassport/internal/qualificationtestsupport"
	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
)

func init() {
	installQualificationSnapshotAppContainerTestAdapter(windowssecurity.CurrentAppContainerPrincipal)
}
