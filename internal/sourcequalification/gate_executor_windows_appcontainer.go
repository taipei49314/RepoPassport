//go:build windows

package sourcequalification

import (
	"crypto/rand"
	"encoding/hex"
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
		if err := windowsGrantAppContainerPath(path, sid, false); err != nil {
			return err
		}
	}
	for _, path := range writable {
		if err := windowsGrantAppContainerPath(path, sid, true); err != nil {
			return err
		}
	}
	for _, path := range readable {
		_ = windowsGrantAppContainerPath(path, sid, false)
	}
	return nil
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
		case "SYSTEMROOT", "WINDIR", "GOROOT":
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
		paths = append(paths, filepath.Dir(directory))
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

func windowsGrantAppContainerPath(path string, sid *windows.SID, writable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	access := windows.GENERIC_READ | windows.GENERIC_EXECUTE
	if writable {
		access = windows.GENERIC_ALL
	}
	inheritance := windows.NO_INHERITANCE
	if info.IsDir() {
		inheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(sid)
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(access),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       uint32(inheritance),
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
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
		return err
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
		return err
	}
	if !info.IsDir() {
		return nil
	}
	return windowsPropagateAppContainerDACL(path, acl)
}

func windowsPropagateAppContainerDACL(path string, acl *windows.ACL) error {
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
