//go:build windows

package sourcequalification

import (
	_ "github.com/taipei49314/RepoPassport/internal/qualificationtestsupport"
	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
)

func init() {
	installPrivatePackageAppContainerTestAdapter(windowssecurity.CurrentAppContainerPrincipal)
}
