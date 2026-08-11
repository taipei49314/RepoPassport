//go:build windows

package sourcequalification

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsQualificationWorkspace struct {
	parent         *os.File
	root           *os.File
	parentPath     string
	path           string
	parentIdentity packageFileIdentity
	rootIdentity   packageFileIdentity
}

type windowsQualificationWorkspaceMetadata struct {
	identity   packageFileIdentity
	attributes uint32
	links      uint32
}

func createQualificationWorkspacePlatform(
	parent *os.File,
	parentIdentity packageFileIdentity,
	parentPath string,
	_ string,
	path string,
) (qualificationWorkspacePlatform, error) {
	if !qualificationWorkspaceHandleHasIdentity(parent, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(parentPath, parentIdentity) {
		return nil, errQualificationWorkspaceCreate
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errQualificationWorkspaceCreate
	}
	attributes, descriptor, err := qualificationWorkspaceSecurityAttributes()
	if err != nil {
		return nil, errQualificationWorkspaceCreate
	}
	createErr := windows.CreateDirectory(pointer, attributes)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(descriptor)
	if createErr != nil {
		return nil, errQualificationWorkspaceCreate
	}

	root, err := openWindowsQualificationWorkspaceEntry(path)
	if err != nil {
		_ = windows.RemoveDirectory(pointer)
		return nil, errQualificationWorkspaceCreate
	}
	metadata, err := readWindowsQualificationWorkspaceMetadata(root)
	if err != nil {
		_ = root.Close()
		_ = windows.RemoveDirectory(pointer)
		return nil, errQualificationWorkspaceCreate
	}
	workspace := &windowsQualificationWorkspace{
		parent:         parent,
		root:           root,
		parentPath:     parentPath,
		path:           path,
		parentIdentity: parentIdentity,
		rootIdentity:   metadata.identity,
	}
	if !validWindowsQualificationWorkspaceDirectory(root, metadata.identity, true, true) ||
		!qualificationWorkspaceHandleHasIdentity(parent, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(parentPath, parentIdentity) ||
		!qualificationWorkspacePathHasIdentity(path, metadata.identity) {
		_ = workspace.cleanupInternal(false, false)
		return nil, errQualificationWorkspaceCreate
	}
	return workspace, nil
}

func (workspace *windowsQualificationWorkspace) cleanup() error {
	return workspace.cleanupInternal(true, true)
}

func (workspace *windowsQualificationWorkspace) cleanupInternal(
	verifyPaths bool,
	requirePrivate bool,
) (returnErr error) {
	if workspace == nil || workspace.parent == nil || workspace.root == nil {
		return errQualificationWorkspaceCleanup
	}
	defer func() {
		rootErr := workspace.root.Close()
		parentErr := workspace.parent.Close()
		workspace.root = nil
		workspace.parent = nil
		if rootErr != nil || parentErr != nil {
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
	if requirePrivate {
		if !validWindowsQualificationWorkspaceDirectory(
			workspace.root,
			workspace.rootIdentity,
			false,
			false,
		) {
			return errQualificationWorkspaceCleanup
		}
	} else {
		metadata, err := readWindowsQualificationWorkspaceMetadata(workspace.root)
		if err != nil || metadata.identity != workspace.rootIdentity ||
			metadata.attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			metadata.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errQualificationWorkspaceCleanup
		}
	}

	budget := &qualificationWorkspaceCleanupBudget{}
	if err := removeWindowsQualificationWorkspaceContents(
		workspace.root,
		workspace.path,
		workspace.rootIdentity.first,
		0,
		budget,
	); err != nil {
		return errQualificationWorkspaceCleanup
	}
	if err := removeWindowsQualificationWorkspaceEntry(
		workspace.path,
		workspace.rootIdentity,
		true,
		false,
	); err != nil {
		return errQualificationWorkspaceCleanup
	}
	return nil
}

func qualificationWorkspaceSecurityAttributes() (
	*windows.SecurityAttributes,
	*windows.SECURITY_DESCRIPTOR,
	error,
) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil || !current.User.Sid.IsValid() {
		return nil, nil, errQualificationWorkspaceCreate
	}
	owner := current.User.Sid.String()
	if owner == "" {
		return nil, nil, errQualificationWorkspaceCreate
	}
	sddl := "O:" + owner + "D:P(A;OICI;FA;;;" + owner + ")"
	if owner != "S-1-5-18" {
		sddl += "(A;OICI;FA;;;SY)"
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || descriptor == nil {
		return nil, nil, errQualificationWorkspaceCreate
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      0,
	}, descriptor, nil
}

func openWindowsQualificationWorkspaceEntry(path string) (*os.File, error) {
	return openWindowsPackagePath(
		path,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
}

func readWindowsQualificationWorkspaceMetadata(
	file *os.File,
) (windowsQualificationWorkspaceMetadata, error) {
	if file == nil {
		return windowsQualificationWorkspaceMetadata{}, errQualificationWorkspaceCleanup
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&information,
	); err != nil {
		return windowsQualificationWorkspaceMetadata{}, errQualificationWorkspaceCleanup
	}
	return windowsQualificationWorkspaceMetadata{
		identity: packageFileIdentity{
			first:  uint64(information.VolumeSerialNumber),
			second: uint64(information.FileIndexHigh)<<32 | uint64(information.FileIndexLow),
		},
		attributes: information.FileAttributes,
		links:      information.NumberOfLinks,
	}, nil
}

func validWindowsQualificationWorkspaceDirectory(
	file *os.File,
	expected packageFileIdentity,
	exactLinkCount bool,
	checkStreams bool,
) bool {
	metadata, err := readWindowsQualificationWorkspaceMetadata(file)
	if err != nil || metadata.identity != expected ||
		metadata.attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		metadata.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		exactLinkCount && metadata.links != 1 ||
		!validWindowsQualificationWorkspaceDACL(file) {
		return false
	}
	if checkStreams && validatePackageWindowsStreams(windows.Handle(file.Fd()), false) != nil {
		return false
	}
	return true
}

func validWindowsQualificationWorkspaceDACL(file *os.File) bool {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return false
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) !=
		windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		return false
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	current, currentErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentErr != nil || ownerDefaulted || owner == nil ||
		current == nil || current.User.Sid == nil || !owner.Equals(current.User.Sid) {
		return false
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil || system == nil {
		return false
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	expectedCount := uint16(2)
	if owner.Equals(system) {
		expectedCount = 1
	}
	if err != nil || daclDefaulted || dacl == nil || dacl.AceCount != expectedCount {
		return false
	}
	seenOwner := false
	seenSystem := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) ||
			ace.Mask != 0x1f01ff {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return false
		}
		switch {
		case sid.Equals(owner):
			if seenOwner {
				return false
			}
			seenOwner = true
			if owner.Equals(system) {
				seenSystem = true
			}
		case sid.Equals(system):
			if seenSystem {
				return false
			}
			seenSystem = true
		default:
			return false
		}
	}
	runtime.KeepAlive(current)
	runtime.KeepAlive(system)
	return seenOwner && seenSystem
}

func removeWindowsQualificationWorkspaceContents(
	directory *os.File,
	path string,
	rootVolume uint64,
	depth int,
	budget *qualificationWorkspaceCleanupBudget,
) error {
	if depth > maximumQualificationWorkspaceCleanupDepth {
		return errQualificationWorkspaceCleanup
	}
	for {
		entries, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return errQualificationWorkspaceCleanup
		}
		for _, entry := range entries {
			name := entry.Name()
			if name == "" || name == "." || name == ".." ||
				budget.consume(depth) != nil {
				return errQualificationWorkspaceCleanup
			}
			childPath := filepath.Join(path, name)
			child, openErr := openWindowsQualificationWorkspaceEntry(childPath)
			if openErr != nil {
				return errQualificationWorkspaceCleanup
			}
			metadata, metadataErr := readWindowsQualificationWorkspaceMetadata(child)
			if metadataErr != nil || metadata.identity.first != rootVolume {
				_ = child.Close()
				return errQualificationWorkspaceCleanup
			}
			isDirectory := metadata.attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
			isReparse := metadata.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
			if isDirectory && !isReparse {
				if err := removeWindowsQualificationWorkspaceContents(
					child,
					childPath,
					rootVolume,
					depth+1,
					budget,
				); err != nil {
					_ = child.Close()
					return errQualificationWorkspaceCleanup
				}
			}
			if err := child.Close(); err != nil {
				return errQualificationWorkspaceCleanup
			}
			if err := removeWindowsQualificationWorkspaceEntry(
				childPath,
				metadata.identity,
				isDirectory,
				isReparse,
			); err != nil {
				return errQualificationWorkspaceCleanup
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func removeWindowsQualificationWorkspaceEntry(
	path string,
	expected packageFileIdentity,
	wantDirectory bool,
	wantReparse bool,
) error {
	file, err := openWindowsQualificationWorkspaceEntry(path)
	if err != nil {
		return errQualificationWorkspaceCleanup
	}
	metadata, metadataErr := readWindowsQualificationWorkspaceMetadata(file)
	isDirectory := metadata.attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	isReparse := metadata.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	if metadataErr != nil || metadata.identity != expected ||
		isDirectory != wantDirectory || isReparse != wantReparse {
		_ = file.Close()
		return errQualificationWorkspaceCleanup
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = file.Close()
		return errQualificationWorkspaceCleanup
	}
	if metadata.attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		// SetFileAttributes follows a reparse point, so a read-only reparse
		// entry is deliberately left untouched. Real entries are kept open,
		// identity-checked, restricted to clearing READONLY, and checked again
		// before deletion.
		if wantReparse || windows.SetFileAttributes(
			pointer,
			metadata.attributes&^windows.FILE_ATTRIBUTE_READONLY,
		) != nil {
			_ = file.Close()
			return errQualificationWorkspaceCleanup
		}
		current, currentErr := readWindowsQualificationWorkspaceMetadata(file)
		if currentErr != nil || current.identity != expected ||
			current.attributes&windows.FILE_ATTRIBUTE_DIRECTORY != metadata.attributes&windows.FILE_ATTRIBUTE_DIRECTORY ||
			current.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != metadata.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT ||
			current.attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
			_ = file.Close()
			return errQualificationWorkspaceCleanup
		}
		verification, verificationErr := openWindowsQualificationWorkspaceEntry(path)
		if verificationErr != nil {
			_ = file.Close()
			return errQualificationWorkspaceCleanup
		}
		verified, verifiedErr := readWindowsQualificationWorkspaceMetadata(verification)
		verificationCloseErr := verification.Close()
		if verifiedErr != nil || verificationCloseErr != nil || verified.identity != expected ||
			verified.attributes&windows.FILE_ATTRIBUTE_DIRECTORY != current.attributes&windows.FILE_ATTRIBUTE_DIRECTORY ||
			verified.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != current.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT ||
			verified.attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
			_ = file.Close()
			return errQualificationWorkspaceCleanup
		}
	}
	if wantDirectory {
		err = windows.RemoveDirectory(pointer)
	} else {
		err = windows.DeleteFile(pointer)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errQualificationWorkspaceCleanup
	}
	return nil
}
