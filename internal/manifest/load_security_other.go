//go:build !windows && !unix

package manifest

import "os"

func isManifestReparsePoint(string) bool { return false }

// Unknown platform-specific handle metadata fails closed: this fallback cannot
// prove the required single-link invariant.
func validateManifestOpenedHandle(*os.File, string) error { return os.ErrInvalid }
