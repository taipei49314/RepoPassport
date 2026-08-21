//go:build windows

package trustchainstate

import "github.com/taipei49314/RepoPassport/internal/windowssecurity"

func init() {
	boundary, boundaryErr := windowssecurity.CurrentAppContainerPathBoundary()
	installPrivateAppContainerTestAdapter(
		windowssecurity.CurrentAppContainerPrincipal,
		windowssecurity.ResolveAppContainerPath,
		func(path string) (string, error) {
			if boundaryErr != nil {
				return "", boundaryErr
			}
			return windowssecurity.AppContainerPathBoundary(path, boundary)
		},
		windowssecurity.AppContainerFinalPath,
	)
}
