//go:build windows

package sourcequalification

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsProcThreadAttributeSecurityCapabilities = 0x00020009
	windowsHRESULTAlreadyExists                    = 0x800700B7
)

type windowsSecurityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    uintptr
	CapabilityCount uint32
	Reserved        uint32
}

type windowsAppContainerSession struct {
	name         string
	sid          *windows.SID
	capabilities windowsSecurityCapabilities
}

var (
	windowsUserenv                                   = windows.NewLazySystemDLL("userenv.dll")
	windowsAdvapi32                                  = windows.NewLazySystemDLL("advapi32.dll")
	windowsCreateAppContainerProfile                 = windowsUserenv.NewProc("CreateAppContainerProfile")
	windowsDeleteAppContainerProfile                 = windowsUserenv.NewProc("DeleteAppContainerProfile")
	windowsDeriveAppContainerSidFromAppContainerName = windowsUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	windowsTreeResetNamedSecurityInfo                = windowsAdvapi32.NewProc("TreeResetNamedSecurityInfoW")
)

func windowsPrepareNetworkNoneAppContainer(request gateProcessRequest) (*windowsAppContainerSession, error) {
	name, err := windowsNewAppContainerName()
	if err != nil {
		return nil, err
	}
	sid, err := windowsCreateOrDeriveAppContainerSID(name)
	if err != nil {
		return nil, err
	}
	session := &windowsAppContainerSession{name: name, sid: sid}
	session.capabilities.AppContainerSid = sid
	if err := windowsGrantAppContainerGatePaths(request, sid); err != nil {
		session.release()
		return nil, err
	}
	return session, nil
}

func (session *windowsAppContainerSession) release() {
	if session == nil || session.name == "" {
		return
	}
	name, err := windows.UTF16PtrFromString(session.name)
	if err == nil {
		_, _, _ = windowsDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(name)))
	}
	session.name = ""
	session.sid = nil
	session.capabilities = windowsSecurityCapabilities{}
}

func windowsNewAppContainerName() (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "RepoPass.sq." + hex.EncodeToString(nonce[:]), nil
}

func windowsCreateOrDeriveAppContainerSID(name string) (*windows.SID, error) {
	if err := windowsCreateAppContainerProfile.Find(); err != nil {
		return nil, err
	}
	if err := windowsDeriveAppContainerSidFromAppContainerName.Find(); err != nil {
		return nil, err
	}
	if err := windowsDeleteAppContainerProfile.Find(); err != nil {
		return nil, err
	}
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, callErr := windowsCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		0,
		uintptr(unsafe.Pointer(&sid)),
	)
	if hr == 0 && sid != nil {
		copied, copyErr := sid.Copy()
		_ = windows.FreeSid(sid)
		if copyErr != nil {
			return nil, copyErr
		}
		return copied, nil
	}
	if hr != 0 && uint32(hr) != windowsHRESULTAlreadyExists {
		if callErr != windows.ERROR_SUCCESS {
			return nil, callErr
		}
		return nil, windows.ERROR_ACCESS_DENIED
	}
	hr, _, callErr = windowsDeriveAppContainerSidFromAppContainerName.Call(
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&sid)),
	)
	if hr != 0 || sid == nil {
		if callErr != windows.ERROR_SUCCESS {
			return nil, callErr
		}
		return nil, windows.ERROR_ACCESS_DENIED
	}
	copied, copyErr := sid.Copy()
	_ = windows.FreeSid(sid)
	if copyErr != nil {
		return nil, copyErr
	}
	return copied, nil
}

func windowsGrantAppContainerGatePaths(request gateProcessRequest, sid *windows.SID) error {
	required, writable, readable := windowsNetworkNoneAccessPaths(request)
	for _, path := range required {
		if err := windowsGrantAppContainerPath(path, sid, false, false); err != nil {
			return err
		}
		windowsGrantAppContainerExistingTree(path, sid)
	}
	for _, path := range writable {
		if err := windowsGrantAppContainerPath(path, sid, true, true); err != nil {
			return err
		}
	}
	for _, path := range readable {
		_ = windowsGrantAppContainerPath(path, sid, false, false)
		base := filepath.Base(path)
		if strings.EqualFold(base, "bin") || strings.EqualFold(base, "tool") {
			windowsGrantAppContainerExistingTree(path, sid)
		}
	}
	// AppContainer lacks SeChangeNotifyPrivilege. Schema JSON opens Dir and
	// every ancestor except the volume root. Grant path-only traverse on Dir's
	// ancestors. Do not grant Application/GOROOT ancestors: SetNamedSecurityInfo
	// on C:\hostedtoolcache hangs CI. Do not inherit or TreeReset.
	windowsGrantAppContainerAncestorChain(request.Dir, sid)
	return nil
}

func windowsAppContainerAncestorPaths(path string) []string {
	path = filepath.Clean(path)
	if path == "" {
		return nil
	}
	ancestors := make([]string, 0, 8)
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return ancestors
		}
		path = parent
		ancestors = append(ancestors, path)
	}
}

func windowsGrantAppContainerAncestorChain(path string, sid *windows.SID) {
	for _, ancestor := range windowsAppContainerAncestorPaths(path) {
		if windowsAppContainerAncestorGrantForbidden(ancestor) {
			continue
		}
		_ = windowsGrantAppContainerAncestorPath(ancestor, sid)
	}
}

func windowsAppContainerAncestorGrantForbidden(path string) bool {
	if windowsAppContainerTreeMutationForbidden(path) {
		return true
	}
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" {
		return true
	}
	relative := strings.TrimPrefix(path, volume)
	relative = strings.Trim(relative, `\`)
	if relative == "" {
		return true
	}
	first, _, _ := strings.Cut(strings.ToLower(relative), `\`)
	switch first {
	case "users", "program files", "program files (x86)", "programdata", "windows", "documents and settings":
		return true
	default:
		return false
	}
}

func windowsGrantAppContainerAncestorPath(path string, sid *windows.SID) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	_, err = windowsSetAppContainerPathAccess(
		path,
		sid,
		windows.GENERIC_READ|windows.GENERIC_EXECUTE,
		uint32(windows.NO_INHERITANCE),
	)
	return err
}

func windowsNetworkNoneAccessPaths(request gateProcessRequest) (required, writable, readable []string) {
	required = uniqueExistingWindowsPaths([]string{request.Application, request.Dir})
	var writePaths, readPaths []string
	readPaths = append(readPaths, windowsExecutableTree(request.Application)...)
	for _, entry := range request.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" {
			continue
		}
		switch strings.ToUpper(key) {
		case "HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP", "GOCACHE", "GOMODCACHE", "GOTMPDIR":
			writePaths = append(writePaths, value)
		case "GOROOT":
			readPaths = append(readPaths, value)
		case "PATH":
			readPaths = append(readPaths, filepath.SplitList(value)...)
		}
	}
	writable = uniqueExistingWindowsPaths(writePaths)
	readable = uniqueExistingWindowsPaths(readPaths)
	return required, writable, readable
}

func windowsExecutableTree(application string) []string {
	if application == "" {
		return nil
	}
	directory := filepath.Dir(application)
	paths := []string{application, directory}
	base := filepath.Base(application)
	if (strings.EqualFold(base, "go.exe") || strings.EqualFold(base, "gofmt.exe")) &&
		strings.EqualFold(filepath.Base(directory), "bin") {
		root := filepath.Dir(directory)
		paths = append(paths, root, filepath.Join(root, "pkg", "tool"))
	}
	if strings.EqualFold(base, "git.exe") && strings.EqualFold(filepath.Base(directory), "cmd") {
		paths = append(paths, filepath.Dir(directory))
	}
	return paths
}

func uniqueExistingWindowsPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) {
			continue
		}
		clean := filepath.Clean(path)
		if _, err := os.Lstat(clean); err != nil {
			continue
		}
		key := strings.ToLower(clean)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, clean)
	}
	return result
}

func windowsCreateGatePipe(session *windowsAppContainerSession) (*os.File, *os.File, error) {
	if session == nil || session.sid == nil {
		return os.Pipe()
	}
	return windowsCreateAppContainerPipe(session.sid)
}

func windowsCreateAppContainerPipe(sid *windows.SID) (*os.File, *os.File, error) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return nil, nil, err
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(sid)
	pinner.Pin(current.User.Sid)
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       uint32(windows.NO_INHERITANCE),
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ | windows.GENERIC_WRITE | windows.SYNCHRONIZE,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       uint32(windows.NO_INHERITANCE),
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, nil, err
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, nil, err
	}
	if err := descriptor.SetDACL(acl, true, false); err != nil {
		return nil, nil, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      1,
	}
	var readerHandle, writerHandle windows.Handle
	if err := windows.CreatePipe(&readerHandle, &writerHandle, &attributes, 0); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(acl)
	reader := os.NewFile(uintptr(readerHandle), "appcontainer-pipe-reader")
	writer := os.NewFile(uintptr(writerHandle), "appcontainer-pipe-writer")
	if reader == nil || writer == nil {
		_ = windows.CloseHandle(readerHandle)
		_ = windows.CloseHandle(writerHandle)
		return nil, nil, windows.ERROR_INVALID_HANDLE
	}
	return reader, writer, nil
}

func windowsGrantAppContainerPath(path string, sid *windows.SID, writable, propagate bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	access := windows.ACCESS_MASK(windows.GENERIC_READ | windows.GENERIC_EXECUTE)
	if writable {
		access = windows.GENERIC_ALL
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if info.IsDir() {
		inheritance = uint32(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	}
	acl, err := windowsSetAppContainerPathAccess(path, sid, access, inheritance)
	if err != nil {
		return err
	}
	if !propagate || !info.IsDir() || windowsAppContainerTreeMutationForbidden(path) {
		return nil
	}
	if err := windowsPropagateAppContainerDACL(path, acl); err != nil && writable {
		return err
	}
	return nil
}

func windowsGrantAppContainerExistingTree(root string, sid *windows.SID) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		windowsAppContainerTreeMutationForbidden(root) {
		return
	}
	budget := 500_000
	windowsGrantAppContainerExistingTreeLimited(root, sid, 0, &budget)
}

func windowsGrantAppContainerExistingTreeLimited(root string, sid *windows.SID, depth int, budget *int) {
	if depth > maximumQualificationWorkspaceCleanupDepth || budget == nil || *budget <= 0 {
		return
	}
	directory, err := os.Open(root)
	if err != nil {
		return
	}
	defer directory.Close()
	for {
		entries, err := directory.ReadDir(128)
		if err != nil && (err != io.EOF || len(entries) == 0) {
			return
		}
		for _, entry := range entries {
			*budget--
			if *budget <= 0 {
				return
			}
			name := entry.Name()
			if name == "" || name == "." || name == ".." {
				continue
			}
			child := filepath.Join(root, name)
			info, err := os.Lstat(child)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			_ = windowsGrantAppContainerPath(child, sid, false, false)
			if info.IsDir() {
				windowsGrantAppContainerExistingTreeLimited(child, sid, depth+1, budget)
			}
		}
		if err == io.EOF || len(entries) < 128 {
			return
		}
	}
}

func windowsSetAppContainerPathAccess(
	path string,
	sid *windows.SID,
	access windows.ACCESS_MASK,
	inheritance uint32,
) (*windows.ACL, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(sid)
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	var merged *windows.ACL
	if descriptor != nil {
		merged, _, err = descriptor.DACL()
		if err != nil {
			merged = nil
		}
	}
	acl, err := windows.ACLFromEntries(entries, merged)
	if err != nil {
		return nil, err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return nil, err
	}
	return acl, nil
}

func windowsAppContainerTreeMutationForbidden(path string) bool {
	path = filepath.Clean(path)
	for _, root := range windowsSystemRootCandidates() {
		if root == "" {
			continue
		}
		if strings.EqualFold(path, root) {
			return true
		}
		prefix := root
		if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
			prefix += string(os.PathSeparator)
		}
		if len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func windowsSystemRootCandidates() []string {
	seen := make(map[string]struct{}, 2)
	var roots []string
	for _, key := range []string{"SYSTEMROOT", "WINDIR"} {
		value := os.Getenv(key)
		if value == "" || !filepath.IsAbs(value) {
			continue
		}
		clean := filepath.Clean(value)
		key = strings.ToLower(clean)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, clean)
	}
	return roots
}

func windowsPropagateAppContainerDACL(path string, acl *windows.ACL) error {
	if windowsAppContainerTreeMutationForbidden(path) {
		return nil
	}
	if err := windowsTreeResetNamedSecurityInfo.Find(); err != nil {
		return nil
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	status, _, _ := windowsTreeResetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(windows.SE_FILE_OBJECT),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		0,
		0,
		uintptr(unsafe.Pointer(acl)),
		0,
		1,
		0,
		1,
		0,
	)
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}
