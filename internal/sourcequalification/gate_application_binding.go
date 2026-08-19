package sourcequalification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
)

var errGateApplicationBindingViolated = errors.New("gate application binding was violated")

// heldGateApplication pins one logical gate application: an open handle on the
// resolved file, the name→file identity observed at bind time, and the content
// digest every later gate must re-match before it may run.
type heldGateApplication struct {
	logicalName string
	path        string
	file        *os.File
	identity    gateFileIdentity
	digest      [sha256.Size]byte
	size        int64
}

// osGateApplicationBinding holds every resolved gate application for the lane
// lifetime. Verify re-checks the name→file identity and re-hashes the held
// bytes before each gate, so a rewritten, re-pointed, or removed tool fails
// closed instead of executing. Where the platform supports it (Windows
// read-only sharing) the hold also denies writers outright for the lane
// lifetime.
type osGateApplicationBinding struct {
	mutex        sync.Mutex
	applications []heldGateApplication
	released     bool
}

func newOSGateApplicationBinding(
	ctx context.Context,
	applications map[string]string,
) (gateApplicationBinding, error) {
	if ctx == nil || nilGateDependency(ctx) || ctx.Err() != nil || len(applications) == 0 {
		return nil, errGateApplicationBindingUnavailable
	}
	logicalNames := make([]string, 0, len(applications))
	for logicalName := range applications {
		logicalNames = append(logicalNames, logicalName)
	}
	sort.Strings(logicalNames)

	binding := &osGateApplicationBinding{}
	for _, logicalName := range logicalNames {
		path := applications[logicalName]
		if logicalName == "" || !cleanAbsoluteGatePath(path) || !availableGateApplication(path) {
			_ = binding.closeHeldApplications()
			return nil, errGateApplicationBindingUnavailable
		}
		held, err := holdGateApplication(logicalName, path)
		if err != nil {
			_ = binding.closeHeldApplications()
			return nil, errGateApplicationBindingUnavailable
		}
		binding.applications = append(binding.applications, held)
	}
	return binding, nil
}

func holdGateApplication(logicalName, path string) (heldGateApplication, error) {
	file, err := openHeldGateApplicationFile(path)
	if err != nil {
		return heldGateApplication{}, err
	}
	identity, err := heldGateFileIdentity(file)
	if err != nil {
		_ = file.Close()
		return heldGateApplication{}, err
	}
	digest, size, err := digestHeldGateApplication(file)
	if err != nil {
		_ = file.Close()
		return heldGateApplication{}, err
	}
	return heldGateApplication{
		logicalName: logicalName,
		path:        path,
		file:        file,
		identity:    identity,
		digest:      digest,
		size:        size,
	}, nil
}

func digestHeldGateApplication(file *os.File) ([sha256.Size]byte, int64, error) {
	var digest [sha256.Size]byte
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return digest, 0, err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return digest, 0, err
	}
	copy(digest[:], hash.Sum(nil))
	return digest, size, nil
}

func (binding *osGateApplicationBinding) Verify(ctx context.Context) error {
	if ctx == nil || nilGateDependency(ctx) || ctx.Err() != nil {
		return errGateApplicationBindingViolated
	}
	binding.mutex.Lock()
	defer binding.mutex.Unlock()
	if binding.released {
		return errGateApplicationBindingViolated
	}
	for index := range binding.applications {
		if err := binding.applications[index].verify(); err != nil {
			return err
		}
	}
	return nil
}

func (held *heldGateApplication) verify() error {
	current, err := currentGateFileIdentity(held.path)
	if err != nil || !sameGateFileIdentity(current, held.identity) {
		return errGateApplicationBindingViolated
	}
	digest, size, err := digestHeldGateApplication(held.file)
	if err != nil || size != held.size || !bytes.Equal(digest[:], held.digest[:]) {
		return errGateApplicationBindingViolated
	}
	return nil
}

func (binding *osGateApplicationBinding) Release() error {
	binding.mutex.Lock()
	defer binding.mutex.Unlock()
	if binding.released {
		return errGateApplicationBindingViolated
	}
	binding.released = true
	return binding.closeHeldApplicationsLocked()
}

func (binding *osGateApplicationBinding) closeHeldApplications() error {
	binding.mutex.Lock()
	defer binding.mutex.Unlock()
	return binding.closeHeldApplicationsLocked()
}

func (binding *osGateApplicationBinding) closeHeldApplicationsLocked() error {
	var firstErr error
	for index := range binding.applications {
		if file := binding.applications[index].file; file != nil {
			if err := file.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
			binding.applications[index].file = nil
		}
	}
	return firstErr
}
