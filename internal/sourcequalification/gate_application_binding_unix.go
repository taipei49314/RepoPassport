//go:build !windows

package sourcequalification

import (
	"os"
	"syscall"
)

// gateFileIdentity is the POSIX name→file binding: device and inode.
type gateFileIdentity struct {
	device uint64
	inode  uint64
}

// openHeldGateApplicationFile holds a read handle on the resolved file. POSIX
// has no mandatory deny-write sharing, so mutation is detected by the per-gate
// identity and digest re-verification rather than prevented by the hold.
func openHeldGateApplicationFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

func heldGateFileIdentity(file *os.File) (gateFileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return gateFileIdentity{}, err
	}
	return unixGateFileIdentity(info.Sys())
}

func currentGateFileIdentity(path string) (gateFileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return gateFileIdentity{}, errGateApplicationBindingViolated
	}
	return unixGateFileIdentity(info.Sys())
}

func unixGateFileIdentity(sys any) (gateFileIdentity, error) {
	stat, ok := sys.(*syscall.Stat_t)
	if !ok || stat == nil {
		return gateFileIdentity{}, errGateApplicationBindingViolated
	}
	return gateFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func sameGateFileIdentity(left, right gateFileIdentity) bool {
	return left == right
}
