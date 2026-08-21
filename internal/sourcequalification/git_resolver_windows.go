//go:build windows

package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	windowsTrustedInstallerSID                       = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	windowsMaximumGitDACLACEs                        = 256
	windowsGitUntrustedWriteMask windows.ACCESS_MASK = windows.FILE_WRITE_DATA |
		windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES |
		0x00000040 | // FILE_DELETE_CHILD for directories.
		windows.DELETE |
		windows.WRITE_DAC |
		windows.WRITE_OWNER |
		windows.GENERIC_WRITE |
		windows.GENERIC_ALL
)

type windowsTrustedGitCandidate struct {
	root string
	path string
}

type windowsTrustedGitSnapshot struct {
	identity   packageFileIdentity
	attributes uint32
}

func resolveTrustedGitExecutablePlatform(repositoryRoot string) (string, error) {
	contained, err := windowssecurity.CurrentProcessIsAppContainer()
	if err != nil || contained {
		return "", errors.New("fixed machine Git application is unavailable in AppContainer")
	}
	for _, candidate := range windowsTrustedGitCandidates() {
		resolved, err := validateWindowsTrustedGitCandidate(repositoryRoot, candidate)
		if err == nil {
			return resolved, nil
		}
	}
	return "", errors.New("fixed machine Git application is unavailable")
}

func windowsTrustedGitCandidates() []windowsTrustedGitCandidate {
	result := []windowsTrustedGitCandidate{}
	seen := map[string]bool{}
	appendCandidate := func(root, path string) {
		root = filepath.Clean(root)
		path = filepath.Clean(path)
		if !filepath.IsAbs(root) || !filepath.IsAbs(path) ||
			strings.ContainsAny(root, "%\x00\r\n") || strings.ContainsAny(path, "%\x00\r\n") ||
			!windowsTrustedGitCandidateContains(root, path) {
			return
		}
		key := strings.ToLower(root) + "\x00" + strings.ToLower(path)
		if seen[key] {
			return
		}
		seen[key] = true
		result = append(result, windowsTrustedGitCandidate{root: root, path: path})
	}

	for _, root := range windowsGitForWindowsInstallRoots() {
		appendCandidate(root, filepath.Join(root, "cmd", "git.exe"))
		appendCandidate(root, filepath.Join(root, "bin", "git.exe"))
	}
	for _, folderID := range []*windows.KNOWNFOLDERID{
		windows.FOLDERID_ProgramFiles,
		windows.FOLDERID_ProgramFilesX64,
		windows.FOLDERID_ProgramFilesX86,
	} {
		root, err := windows.KnownFolderPath(folderID, windows.KF_FLAG_DEFAULT)
		if err != nil || root == "" {
			continue
		}
		appendCandidate(root, filepath.Join(root, "Git", "cmd", "git.exe"))
		appendCandidate(root, filepath.Join(root, "Git", "bin", "git.exe"))
	}
	return result
}

func windowsGitForWindowsInstallRoots() []string {
	result := []string{}
	seen := map[string]bool{}
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		key, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SOFTWARE\GitForWindows`,
			registry.QUERY_VALUE|view,
		)
		if err != nil {
			continue
		}
		root, _, valueErr := key.GetStringValue("InstallPath")
		closeErr := key.Close()
		root = filepath.Clean(root)
		if valueErr != nil || closeErr != nil || !filepath.IsAbs(root) ||
			strings.ContainsAny(root, "%\x00\r\n") {
			continue
		}
		folded := strings.ToLower(root)
		if !seen[folded] {
			seen[folded] = true
			result = append(result, root)
		}
	}
	return result
}

func validateWindowsTrustedGitCandidate(
	repositoryRoot string,
	candidate windowsTrustedGitCandidate,
) (string, error) {
	root := filepath.Clean(candidate.root)
	path := filepath.Clean(candidate.path)
	qualificationBoundary, qualification, qualificationErr := windowsTrustedGitQualificationBoundary(root, path)
	if root != candidate.root || path != candidate.path || !filepath.IsAbs(root) ||
		!filepath.IsAbs(path) || qualificationErr != nil || !windowsTrustedGitCandidateContains(root, path) ||
		(!qualification && pathWithinRepository(repositoryRoot, root)) || pathWithinRepository(repositoryRoot, path) {
		return "", errors.New("Windows Git candidate is not a fixed external machine path")
	}
	if qualification {
		resolvedBoundary, boundaryErr := pathsecurity.Resolve(qualificationBoundary)
		resolvedPath, pathErr := pathsecurity.Resolve(path)
		if boundaryErr != nil || pathErr != nil ||
			!sameCanonicalPath(qualificationBoundary, resolvedBoundary) || !sameCanonicalPath(path, resolvedPath) {
			return "", errors.New("Windows Git candidate traverses a reparse point")
		}
		return validateWindowsTrustedGitPaths(path, []string{qualificationBoundary, path})
	}
	resolvedRoot, rootErr := pathsecurity.Resolve(root)
	resolvedPath, pathErr := pathsecurity.Resolve(path)
	if rootErr != nil || pathErr != nil || !sameCanonicalPath(root, resolvedRoot) ||
		!sameCanonicalPath(path, resolvedPath) || validatePackageDirectoryChain(root) != nil {
		return "", errors.New("Windows Git candidate traverses a reparse point")
	}

	relative, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(relative) || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("Windows Git candidate is outside its machine root")
	}
	paths := []string{root}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return "", errors.New("Windows Git candidate path is invalid")
		}
		current = filepath.Join(current, component)
		paths = append(paths, current)
	}
	return validateWindowsTrustedGitPaths(path, paths)
}

func windowsTrustedGitCandidateContains(root, path string) bool {
	_, handled, err := windowsTrustedGitQualificationBoundary(root, path)
	if handled {
		return err == nil
	}
	return packagePathContains(root, path)
}

func windowsTrustedGitQualificationBoundary(root, path string) (string, bool, error) {
	boundary, handled, err := pathsecurity.QualificationPathBoundary(path, "tool")
	if !handled {
		return "", false, nil
	}
	if err != nil || !sameCanonicalPath(filepath.Dir(path), boundary) ||
		!sameCanonicalPath(filepath.Dir(boundary), root) {
		return "", true, errors.New("Windows Git qualification boundary is invalid")
	}
	return boundary, true, nil
}

func validateWindowsTrustedGitPaths(path string, paths []string) (string, error) {
	for index, currentPath := range paths {
		directory := index != len(paths)-1
		opened, openedSnapshot, err := openWindowsTrustedGitPath(currentPath, directory)
		if err != nil {
			return "", errors.New("Windows Git candidate could not be opened safely")
		}
		if !validWindowsMachineProtectedGitDACL(opened) {
			_ = opened.Close()
			return "", errors.New("Windows Git candidate DACL is not machine protected")
		}
		if !directory {
			var magic [2]byte
			if count, readErr := opened.ReadAt(magic[:], 0); readErr != nil || count != len(magic) || string(magic[:]) != "MZ" {
				_ = opened.Close()
				return "", errors.New("Windows Git candidate is not a PE executable")
			}
		}
		verified, verifiedSnapshot, verifyErr := openWindowsTrustedGitPath(currentPath, directory)
		verifyCloseErr := error(nil)
		if verified != nil {
			verifyCloseErr = verified.Close()
		}
		openedCloseErr := opened.Close()
		if verifyErr != nil || verifyCloseErr != nil || openedSnapshot != verifiedSnapshot {
			return "", errors.New("Windows Git candidate identity changed during validation")
		}
		if openedCloseErr != nil {
			return "", errors.New("Windows Git candidate handle could not be closed")
		}
	}
	return path, nil
}

func openWindowsTrustedGitPath(
	path string,
	directory bool,
) (*os.File, windowsTrustedGitSnapshot, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, windowsTrustedGitSnapshot{}, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, windowsTrustedGitSnapshot{}, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, windowsTrustedGitSnapshot{}, errors.New("Windows Git handle is invalid")
	}
	var metadata windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &metadata); err != nil {
		_ = file.Close()
		return nil, windowsTrustedGitSnapshot{}, err
	}
	isDirectory := metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory {
		_ = file.Close()
		return nil, windowsTrustedGitSnapshot{}, errors.New("Windows Git path type is invalid")
	}
	return file, windowsTrustedGitSnapshot{
		identity: packageFileIdentity{
			first:  uint64(metadata.VolumeSerialNumber),
			second: uint64(metadata.FileIndexHigh)<<32 | uint64(metadata.FileIndexLow),
		},
		attributes: metadata.FileAttributes,
	}, nil
}

func validWindowsMachineProtectedGitDACL(file *os.File) bool {
	if file == nil {
		return false
	}
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
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return false
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	administrators, adminErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	system, systemErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	creatorOwner, creatorErr := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	trustedInstaller, trustedInstallerErr := windows.StringToSid(windowsTrustedInstallerSID)
	if err != nil || adminErr != nil || systemErr != nil || creatorErr != nil ||
		trustedInstallerErr != nil || ownerDefaulted || owner == nil ||
		!windowsTrustedGitPrivilegedSID(owner, administrators, system, trustedInstaller) {
		return false
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || daclDefaulted || dacl == nil || dacl.AceCount == 0 ||
		dacl.AceCount > windowsMaximumGitDACLACEs {
		return false
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) {
			return false
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return false
		}
		if ace.Mask&windowsGitUntrustedWriteMask == 0 ||
			windowsTrustedGitPrivilegedSID(sid, administrators, system, trustedInstaller) {
			continue
		}
		if sid.Equals(creatorOwner) && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		return false
	}
	runtime.KeepAlive(administrators)
	runtime.KeepAlive(system)
	runtime.KeepAlive(creatorOwner)
	runtime.KeepAlive(trustedInstaller)
	return true
}

func windowsTrustedGitPrivilegedSID(
	sid, administrators, system, trustedInstaller *windows.SID,
) bool {
	return sid != nil && (sid.Equals(administrators) || sid.Equals(system) || sid.Equals(trustedInstaller))
}
