//go:build windows

package attestation

import (
	_ "github.com/taipei49314/RepoPassport/internal/qualificationtestsupport"
	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
)

func init() {
	installPrivateKeyAppContainerTestAdapter(windowssecurity.CurrentAppContainerPrincipal)
}
