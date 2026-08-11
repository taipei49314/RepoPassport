package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	maximumQualificationWorkspaceCleanupDepth   = 64
	maximumQualificationWorkspaceCleanupEntries = 100_000
)

var (
	errQualificationWorkspaceInvalid = errors.New("SOURCE_QUAL_PRIVATE_WORKSPACE_INVALID")
	errQualificationWorkspaceCreate  = errors.New("SOURCE_QUAL_PRIVATE_WORKSPACE_CREATE_FAILED")
	errQualificationWorkspaceCleanup = errors.New("SOURCE_QUAL_PRIVATE_WORKSPACE_CLEANUP_FAILED")
)

type qualificationWorkspacePlatform interface {
	cleanup() error
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
	workspace, err := createQualificationWorkspacePlatform(
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

	var once sync.Once
	var cleanupErr error
	cleanup = func() error {
		once.Do(func() {
			if err := workspace.cleanup(); err != nil {
				cleanupErr = errQualificationWorkspaceCleanup
			}
		})
		return cleanupErr
	}
	return path, cleanup, nil
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
