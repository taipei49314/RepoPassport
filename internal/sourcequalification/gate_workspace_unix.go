//go:build !windows

package sourcequalification

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type unixQualificationWorkspace struct {
	parent         *os.File
	root           *os.File
	parentPath     string
	path           string
	name           string
	parentIdentity packageFileIdentity
	rootIdentity   packageFileIdentity
}

func createQualificationWorkspacePlatform(
	parent *os.File,
	parentIdentity packageFileIdentity,
	parentPath string,
	name string,
	path string,
) (qualificationWorkspacePlatform, error) {
	if !qualificationWorkspaceHandleHasIdentity(parent, parentIdentity) {
		return nil, errQualificationWorkspaceCreate
	}
	parentDescriptor := int(parent.Fd())
	if err := unix.Mkdirat(parentDescriptor, name, 0o700); err != nil {
		return nil, errQualificationWorkspaceCreate
	}

	descriptor, err := unix.Openat(
		parentDescriptor,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		rollbackCreatedUnixQualificationWorkspace(parentDescriptor, name, -1, nil)
		return nil, errQualificationWorkspaceCreate
	}
	if err := unix.Fchmod(descriptor, 0o700); err != nil {
		rollbackCreatedUnixQualificationWorkspace(parentDescriptor, name, descriptor, nil)
		return nil, errQualificationWorkspaceCreate
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		rollbackCreatedUnixQualificationWorkspace(parentDescriptor, name, descriptor, nil)
		return nil, errQualificationWorkspaceCreate
	}
	rootIdentity := unixQualificationWorkspaceIdentity(&metadata)
	if !validUnixQualificationWorkspaceMetadata(&metadata, rootIdentity, true) {
		rollbackCreatedUnixQualificationWorkspace(parentDescriptor, name, descriptor, &rootIdentity)
		return nil, errQualificationWorkspaceCreate
	}
	root := os.NewFile(uintptr(descriptor), path)
	if root == nil {
		rollbackCreatedUnixQualificationWorkspace(parentDescriptor, name, descriptor, &rootIdentity)
		return nil, errQualificationWorkspaceCreate
	}
	workspace := &unixQualificationWorkspace{
		parent:         parent,
		root:           root,
		parentPath:     parentPath,
		path:           path,
		name:           name,
		parentIdentity: parentIdentity,
		rootIdentity:   rootIdentity,
	}
	if !qualificationWorkspaceHandleHasIdentity(parent, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(parentPath, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(path, rootIdentity) {
		_ = workspace.cleanupWithoutPathVerification()
		return nil, errQualificationWorkspaceCreate
	}
	return workspace, nil
}

func bindQualificationWorkspacePlatform(
	parent *os.File,
	parentIdentity packageFileIdentity,
	parentPath string,
	name string,
	path string,
	expected packageFileIdentity,
) (qualificationWorkspacePlatform, error) {
	if !qualificationWorkspaceHandleHasIdentity(parent, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(parentPath, parentIdentity) {
		return nil, errQualificationWorkspaceCreate
	}
	descriptor, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errQualificationWorkspaceCreate
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil ||
		!validUnixQualificationWorkspaceMetadata(&metadata, expected, false) {
		_ = unix.Close(descriptor)
		return nil, errQualificationWorkspaceCreate
	}
	root := os.NewFile(uintptr(descriptor), path)
	if root == nil {
		_ = unix.Close(descriptor)
		return nil, errQualificationWorkspaceCreate
	}
	workspace := &unixQualificationWorkspace{
		parent:         parent,
		root:           root,
		parentPath:     parentPath,
		path:           path,
		name:           name,
		parentIdentity: parentIdentity,
		rootIdentity:   expected,
	}
	if !qualificationWorkspaceHandleHasIdentity(parent, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(parentPath, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(path, expected) {
		_ = workspace.release()
		return nil, errQualificationWorkspaceCreate
	}
	return workspace, nil
}

func rollbackCreatedUnixQualificationWorkspace(
	parentDescriptor int,
	name string,
	descriptor int,
	expected *packageFileIdentity,
) {
	var opened unix.Stat_t
	openedValid := descriptor >= 0 && unix.Fstat(descriptor, &opened) == nil
	var current unix.Stat_t
	currentValid := unix.Fstatat(
		parentDescriptor,
		name,
		&current,
		unix.AT_SYMLINK_NOFOLLOW,
	) == nil && current.Mode&unix.S_IFMT == unix.S_IFDIR &&
		current.Uid == uint32(unix.Geteuid()) && current.Mode&0o077 == 0 &&
		current.Mode&0o7000 == 0 && uint64(current.Nlink) == 2
	if currentValid && openedValid {
		currentValid = opened.Mode&unix.S_IFMT == unix.S_IFDIR &&
			sameUnixQualificationWorkspaceIdentity(&current, unixQualificationWorkspaceIdentity(&opened))
	}
	if currentValid && expected != nil {
		currentValid = sameUnixQualificationWorkspaceIdentity(&current, *expected)
	}
	if currentValid {
		_ = unix.Unlinkat(parentDescriptor, name, unix.AT_REMOVEDIR)
	}
	if descriptor >= 0 {
		_ = unix.Close(descriptor)
	}
}

func (workspace *unixQualificationWorkspace) cleanup() error {
	return workspace.cleanupInternal(true)
}

func (workspace *unixQualificationWorkspace) release() error {
	if workspace == nil || workspace.parent == nil || workspace.root == nil {
		return errQualificationWorkspaceCleanup
	}
	rootErr := workspace.root.Close()
	parentErr := workspace.parent.Close()
	workspace.root = nil
	workspace.parent = nil
	if rootErr != nil || parentErr != nil {
		return errQualificationWorkspaceCleanup
	}
	return nil
}

func (workspace *unixQualificationWorkspace) cleanupWithoutPathVerification() error {
	return workspace.cleanupInternal(false)
}

func (workspace *unixQualificationWorkspace) cleanupInternal(verifyPaths bool) (returnErr error) {
	if workspace == nil || workspace.parent == nil || workspace.root == nil {
		return errQualificationWorkspaceCleanup
	}
	defer func() {
		if err := workspace.release(); err != nil {
			returnErr = errQualificationWorkspaceCleanup
		}
	}()

	if verifyPaths && (!qualificationWorkspacePathHasIdentity(
		workspace.parentPath,
		workspace.parentIdentity,
	) || !qualificationWorkspacePathHasIdentity(workspace.path, workspace.rootIdentity)) {
		return errQualificationWorkspaceCleanup
	}
	if !qualificationWorkspaceHandleHasIdentity(workspace.parent, workspace.parentIdentity) {
		return errQualificationWorkspaceCleanup
	}
	var rootMetadata unix.Stat_t
	if err := unix.Fstat(int(workspace.root.Fd()), &rootMetadata); err != nil ||
		!validUnixQualificationWorkspaceMetadata(&rootMetadata, workspace.rootIdentity, false) {
		return errQualificationWorkspaceCleanup
	}

	budget := &qualificationWorkspaceCleanupBudget{}
	if err := removeUnixQualificationWorkspaceContents(
		workspace.root,
		workspace.rootIdentity.first,
		0,
		budget,
	); err != nil {
		return errQualificationWorkspaceCleanup
	}
	if err := unix.Fstat(int(workspace.root.Fd()), &rootMetadata); err != nil ||
		!validUnixQualificationWorkspaceMetadata(&rootMetadata, workspace.rootIdentity, true) {
		return errQualificationWorkspaceCleanup
	}

	var pathMetadata unix.Stat_t
	if err := unix.Fstatat(
		int(workspace.parent.Fd()),
		workspace.name,
		&pathMetadata,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil || !sameUnixQualificationWorkspaceIdentity(&pathMetadata, workspace.rootIdentity) ||
		pathMetadata.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errQualificationWorkspaceCleanup
	}
	if err := unix.Unlinkat(int(workspace.parent.Fd()), workspace.name, unix.AT_REMOVEDIR); err != nil {
		return errQualificationWorkspaceCleanup
	}
	return nil
}

func removeUnixQualificationWorkspaceContents(
	directory *os.File,
	rootDevice uint64,
	depth int,
	budget *qualificationWorkspaceCleanupBudget,
) error {
	if depth > maximumQualificationWorkspaceCleanupDepth {
		return errQualificationWorkspaceCleanup
	}
	for {
		names, err := directory.Readdirnames(128)
		if err != nil && err != io.EOF {
			return errQualificationWorkspaceCleanup
		}
		for _, name := range names {
			if name == "" || name == "." || name == ".." ||
				budget.consume(depth) != nil {
				return errQualificationWorkspaceCleanup
			}
			if err := removeUnixQualificationWorkspaceEntry(
				directory,
				name,
				rootDevice,
				depth,
				budget,
			); err != nil {
				return errQualificationWorkspaceCleanup
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func removeUnixQualificationWorkspaceEntry(
	parent *os.File,
	name string,
	rootDevice uint64,
	depth int,
	budget *qualificationWorkspaceCleanupBudget,
) error {
	parentDescriptor := int(parent.Fd())
	var before unix.Stat_t
	if err := unix.Fstatat(parentDescriptor, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errQualificationWorkspaceCleanup
	}
	identity := unixQualificationWorkspaceIdentity(&before)
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		var current unix.Stat_t
		if err := unix.Fstatat(parentDescriptor, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			!sameUnixQualificationWorkspaceIdentity(&current, identity) ||
			current.Mode&unix.S_IFMT == unix.S_IFDIR {
			return errQualificationWorkspaceCleanup
		}
		if err := unix.Unlinkat(parentDescriptor, name, 0); err != nil {
			return errQualificationWorkspaceCleanup
		}
		return nil
	}
	if identity.first != rootDevice {
		return errQualificationWorkspaceCleanup
	}

	descriptor, err := unix.Openat(
		parentDescriptor,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return errQualificationWorkspaceCleanup
	}
	child := os.NewFile(uintptr(descriptor), name)
	if child == nil {
		_ = unix.Close(descriptor)
		return errQualificationWorkspaceCleanup
	}
	var opened unix.Stat_t
	if err := unix.Fstat(descriptor, &opened); err != nil ||
		!sameUnixQualificationWorkspaceIdentity(&opened, identity) ||
		opened.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = child.Close()
		return errQualificationWorkspaceCleanup
	}
	if err := removeUnixQualificationWorkspaceContents(
		child,
		rootDevice,
		depth+1,
		budget,
	); err != nil {
		_ = child.Close()
		return errQualificationWorkspaceCleanup
	}
	if err := child.Close(); err != nil {
		return errQualificationWorkspaceCleanup
	}

	var current unix.Stat_t
	if err := unix.Fstatat(parentDescriptor, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		!sameUnixQualificationWorkspaceIdentity(&current, identity) ||
		current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errQualificationWorkspaceCleanup
	}
	if err := unix.Unlinkat(parentDescriptor, name, unix.AT_REMOVEDIR); err != nil {
		return errQualificationWorkspaceCleanup
	}
	return nil
}

func unixQualificationWorkspaceIdentity(metadata *unix.Stat_t) packageFileIdentity {
	return packageFileIdentity{
		first:  uint64(metadata.Dev),
		second: uint64(metadata.Ino),
	}
}

func sameUnixQualificationWorkspaceIdentity(
	metadata *unix.Stat_t,
	expected packageFileIdentity,
) bool {
	return unixQualificationWorkspaceIdentity(metadata) == expected
}

func validUnixQualificationWorkspaceMetadata(
	metadata *unix.Stat_t,
	expected packageFileIdentity,
	exactLinkCount bool,
) bool {
	if metadata == nil || !sameUnixQualificationWorkspaceIdentity(metadata, expected) ||
		metadata.Mode&unix.S_IFMT != unix.S_IFDIR ||
		metadata.Uid != uint32(unix.Geteuid()) || metadata.Mode&0o7777 != 0o700 {
		return false
	}
	return !exactLinkCount || uint64(metadata.Nlink) == 2
}
