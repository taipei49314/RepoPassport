package sourcequalification

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	maximumQualificationWorkspaceCleanupDepth   = 64
	maximumQualificationWorkspaceCleanupEntries = 2_000_000
)

var (
	errQualificationWorkspaceInvalid = errors.New("SOURCE_QUAL_PRIVATE_WORKSPACE_INVALID")
	errQualificationWorkspaceCreate  = errors.New("SOURCE_QUAL_PRIVATE_WORKSPACE_CREATE_FAILED")
	errQualificationWorkspaceCleanup = errors.New("SOURCE_QUAL_PRIVATE_WORKSPACE_CLEANUP_FAILED")
)

type qualificationWorkspacePlatform interface {
	cleanup() error
	release() error
}

type qualificationWorkspaceCleanupBudget struct {
	entries int
}

func (budget *qualificationWorkspaceCleanupBudget) consume(depth int) error {
	if depth > maximumQualificationWorkspaceCleanupDepth ||
		budget.entries >= maximumQualificationWorkspaceCleanupEntries {
		return errQualificationWorkspaceCleanup
	}
	budget.entries++
	return nil
}

func createPrivateQualificationWorkspace(parent, name string) (
	path string,
	cleanup func() error,
	err error,
) {
	path, workspace, err := createPrivateQualificationWorkspaceAuthority(parent, name)
	if err != nil {
		return "", nil, err
	}
	cleanup, _ = qualificationWorkspaceLifecycle(workspace)
	return path, cleanup, nil
}

func createPrivateQualificationStaging(parent, prefix string) (
	path string,
	cleanup func() error,
	release func() error,
	err error,
) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nil, nil, errQualificationWorkspaceCreate
	}
	name := prefix + hex.EncodeToString(nonce[:])
	if !validQualificationWorkspaceName(name) {
		return "", nil, nil, errQualificationWorkspaceInvalid
	}
	path, workspace, err := createPrivateQualificationWorkspaceAuthority(parent, name)
	if err != nil {
		return "", nil, nil, err
	}
	cleanup, release = qualificationWorkspaceLifecycle(workspace)
	return path, cleanup, release, nil
}

func createPrivateQualificationWorkspaceAuthority(parent, name string) (
	path string,
	workspace qualificationWorkspacePlatform,
	err error,
) {
	if !validGateDirectory(parent) || !validQualificationWorkspaceName(name) {
		return "", nil, errQualificationWorkspaceInvalid
	}

	path = filepath.Join(parent, name)
	if filepath.Clean(path) != path || !sameCanonicalPath(filepath.Dir(path), parent) {
		return "", nil, errQualificationWorkspaceInvalid
	}

	parentDirectory, parentSnapshot, err := openValidatedPackageDirectory(parent)
	if err != nil {
		return "", nil, errQualificationWorkspaceInvalid
	}
	workspace, err = createQualificationWorkspacePlatform(
		parentDirectory,
		parentSnapshot.identity,
		parent,
		name,
		path,
	)
	if err != nil {
		_ = parentDirectory.Close()
		return "", nil, errQualificationWorkspaceCreate
	}
	return path, workspace, nil
}

func bindPrivateQualificationCleanup(
	path string,
	expected packageFileIdentity,
	expectedParent packageFileIdentity,
) (func() error, error) {
	canonical, err := canonicalPackageFilesystemPath(path)
	if err != nil || canonical != path || !filepath.IsAbs(path) {
		return nil, errQualificationWorkspaceInvalid
	}
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if parentPath == path || !validGateDirectory(parentPath) ||
		!validQualificationWorkspaceName(name) {
		return nil, errQualificationWorkspaceInvalid
	}
	parent, parentSnapshot, err := openValidatedPackageDirectory(parentPath)
	if err != nil || parentSnapshot.identity != expectedParent {
		if parent != nil {
			_ = parent.Close()
		}
		return nil, errQualificationWorkspaceInvalid
	}
	workspace, err := bindQualificationWorkspacePlatform(
		parent,
		parentSnapshot.identity,
		parentPath,
		name,
		path,
		expected,
	)
	if err != nil {
		_ = parent.Close()
		return nil, errQualificationWorkspaceInvalid
	}
	cleanup, _ := qualificationWorkspaceLifecycle(workspace)
	return cleanup, nil
}

func qualificationWorkspaceLifecycle(
	workspace qualificationWorkspacePlatform,
) (cleanup func() error, release func() error) {
	var once sync.Once
	var cleanupErr error
	finish := func(remove bool) error {
		once.Do(func() {
			var err error
			if remove {
				err = workspace.cleanup()
			} else {
				err = workspace.release()
			}
			if err != nil {
				cleanupErr = errQualificationWorkspaceCleanup
			}
		})
		return cleanupErr
	}
	return func() error { return finish(true) }, func() error { return finish(false) }
}

func validQualificationWorkspaceName(name string) bool {
	return name != "" && !strings.ContainsRune(name, '/') &&
		validateRepositoryPath(name) == nil
}

func qualificationWorkspacePathHasIdentity(path string, expected packageFileIdentity) bool {
	directory, snapshot, err := openValidatedPackageDirectory(path)
	if err != nil {
		return false
	}
	return directory.Close() == nil && snapshot.identity == expected
}

func qualificationWorkspaceHandleHasIdentity(
	file *os.File,
	expected packageFileIdentity,
) bool {
	if file == nil {
		return false
	}
	snapshot, err := snapshotPackageHandle(file, true)
	return err == nil && snapshot.identity == expected
}
