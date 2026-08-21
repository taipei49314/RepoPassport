//go:build windows

package sourcequalification

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	windowsProcThreadAttributeSecurityCapabilities = 0x00020009
	windowsHRESULTAlreadyExists                    = 0x800700B7
	windowsAppContainerNullMutexName               = `Global\RepoPass.SourceQualification.AppContainer.NullDACL.v1`
	windowsAppContainerWorkspacePrefix             = "w-"
	windowsFileDeleteChild                         = 0x00000040
	windowsAppContainerWritableRootAccess          = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE |
		windows.FILE_GENERIC_EXECUTE | windowsFileDeleteChild
	windowsAppContainerWritableChildAccess = windowsAppContainerWritableRootAccess | windows.DELETE
)

var windowsAppContainerWritableEnvironmentKeys = [...]string{
	"HOME",
	"USERPROFILE",
	"XDG_CONFIG_HOME",
	"GOCACHE",
	"GOPATH",
	"GOBIN",
	"GOTMPDIR",
	"TMPDIR",
	"TMP",
	"TEMP",
}

var (
	errWindowsAppContainerPrepareCleanup  = errors.New("Windows AppContainer preparation cleanup failed")
	errWindowsAppContainerPrivateGrant    = errors.New("Windows AppContainer private-boundary grant failed")
	errWindowsAppContainerRequiredGrant   = errors.New("Windows AppContainer required-path grant failed")
	errWindowsAppContainerWritableGrant   = errors.New("Windows AppContainer writable-path grant failed")
	errWindowsAppContainerReadableGrant   = errors.New("Windows AppContainer readable-path grant failed")
	errWindowsAppContainerNullGrant       = errors.New("Windows AppContainer null-device grant failed")
	errWindowsAppContainerNullLease       = errors.New("Windows AppContainer null-device lease failed")
	errWindowsAppContainerGrantNotApplied = errors.New("Windows AppContainer supplemental grant was not applied")
	errWindowsAppContainerAncestorGrant   = errors.New("Windows AppContainer ancestor grant failed")
	errWindowsAppContainerDACLRestore     = errors.New("Windows AppContainer DACL restore failed")
	errWindowsAppContainerDACLSet         = errors.New("Windows AppContainer DACL set failed")
	errWindowsAppContainerDACLRead        = errors.New("Windows AppContainer DACL readback failed")
	errWindowsAppContainerDACLMismatch    = errors.New("Windows AppContainer DACL readback mismatched")
	errWindowsAppContainerDACLIdentity    = errors.New("Windows AppContainer DACL object identity changed")
	errWindowsAppContainerDACLOrphan      = errors.New("Windows AppContainer DACL contains an orphan package principal")
	errWindowsAppContainerProfileCleanup  = errors.New("Windows AppContainer profile cleanup failed")
	errWindowsAppContainerWorkspace       = errors.New("Windows AppContainer writable workspace failed")
)

type windowsSecurityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    uintptr
	CapabilityCount uint32
	Reserved        uint32
}

type windowsAppContainerSession struct {
	name                     string
	sid                      *windows.SID
	baselinePackageSID       *windows.SID
	capabilities             windowsSecurityCapabilities
	daclRestores             []*windowsAppContainerDACLRestore
	writableWorkspacePath    string
	cleanupWritableWorkspace func() error
}

type windowsAppContainerDACLRestore struct {
	file              *os.File
	descriptor        *windows.SECURITY_DESCRIPTOR
	dacl              *windows.ACL
	identity          windowsAppContainerObjectIdentity
	daclBytes         []byte
	daclIdentity      windowsACLSemanticIdentity
	control           windows.SECURITY_DESCRIPTOR_CONTROL
	revision          uint32
	lease             windows.Handle
	leaseThreadLocked bool
}

type windowsACLSemanticIdentity struct {
	revision uint8
	aces     [][]byte
}

type windowsAppContainerObjectIdentity struct {
	fileType      uint32
	hasFileID     bool
	volumeSerial  uint32
	fileIndexHigh uint32
	fileIndexLow  uint32
}

type windowsAppContainerDACLTarget uint8

const (
	windowsAppContainerDACLFilesystem windowsAppContainerDACLTarget = iota
	windowsAppContainerDACLNullDevice
)

type windowsACLHeader struct {
	revision  uint8
	reserved  uint8
	size      uint16
	count     uint16
	reserved2 uint16
}

var (
	windowsUserenv                                   = windows.NewLazySystemDLL("userenv.dll")
	windowsCreateAppContainerProfile                 = windowsUserenv.NewProc("CreateAppContainerProfile")
	windowsDeleteAppContainerProfile                 = windowsUserenv.NewProc("DeleteAppContainerProfile")
	windowsDeriveAppContainerSidFromAppContainerName = windowsUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

func windowsPrepareNetworkNoneAppContainer(request *gateProcessRequest) (*windowsAppContainerSession, error) {
	if request == nil {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	baselinePrincipal, err := windowssecurity.CurrentAppContainerPrincipal()
	if err != nil {
		return nil, err
	}
	var baselinePackageSID *windows.SID
	if baselinePrincipal != "" {
		baselinePackageSID, err = windows.StringToSid(baselinePrincipal)
		if err != nil || baselinePackageSID == nil || !baselinePackageSID.IsValid() {
			return nil, windows.ERROR_INVALID_SID
		}
	}
	name, err := windowsNewAppContainerName()
	if err != nil {
		return nil, err
	}
	sid, err := windowsCreateOrDeriveAppContainerSID(name)
	if err != nil {
		return nil, err
	}
	session := &windowsAppContainerSession{
		name:               name,
		sid:                sid,
		baselinePackageSID: baselinePackageSID,
	}
	session.capabilities.AppContainerSid = sid
	if err := session.prepareWritableWorkspace(request); err != nil {
		if cleanupErr := session.release(); cleanupErr != nil {
			return nil, errors.Join(err, errWindowsAppContainerPrepareCleanup, cleanupErr)
		}
		return nil, err
	}
	if err := windowsGrantAppContainerGatePaths(*request, session); err != nil {
		if cleanupErr := session.release(); cleanupErr != nil {
			return nil, errors.Join(err, errWindowsAppContainerPrepareCleanup, cleanupErr)
		}
		return nil, err
	}
	return session, nil
}

func (session *windowsAppContainerSession) release() error {
	if session == nil {
		return nil
	}
	cleanupErr := session.restoreDACLs()
	if session.cleanupWritableWorkspace != nil {
		cleanupErr = errors.Join(cleanupErr, session.cleanupWritableWorkspace())
		session.cleanupWritableWorkspace = nil
		session.writableWorkspacePath = ""
	}
	if session.name == "" {
		session.sid = nil
		session.baselinePackageSID = nil
		session.capabilities = windowsSecurityCapabilities{}
		return cleanupErr
	}

	cleanupErr = errors.Join(cleanupErr, windowsDeleteAppContainerProfileByName(session.name))
	session.name = ""
	session.sid = nil
	session.baselinePackageSID = nil
	session.capabilities = windowsSecurityCapabilities{}
	return cleanupErr
}

func (session *windowsAppContainerSession) restoreDACLs() error {
	if session == nil {
		return nil
	}
	var cleanupErr error
	for index := len(session.daclRestores) - 1; index >= 0; index-- {
		cleanupErr = errors.Join(cleanupErr, session.daclRestores[index].restore())
	}
	session.daclRestores = nil
	return cleanupErr
}

func windowsAppContainerProfileDeletionError(hresult uintptr, callErr error) error {
	if hresult == 0 {
		return nil
	}
	if callErr == nil || callErr == windows.ERROR_SUCCESS {
		callErr = windows.ERROR_ACCESS_DENIED
	}
	return errors.Join(errWindowsAppContainerProfileCleanup, callErr)
}

func windowsDeleteAppContainerProfileByName(name string) error {
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return errors.Join(errWindowsAppContainerProfileCleanup, err)
	}
	hresult, _, callErr := windowsDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(nameUTF16)))
	return windowsAppContainerProfileDeletionError(hresult, callErr)
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
	if hr == 0 {
		var copied *windows.SID
		copyErr := error(windows.ERROR_INVALID_SID)
		freeErr := error(nil)
		if sid != nil {
			copied, copyErr = sid.Copy()
			freeErr = windows.FreeSid(sid)
		}
		if copyErr == nil && freeErr == nil && copied != nil {
			return copied, nil
		}
		operationErr := errors.Join(copyErr, freeErr)
		if copied == nil {
			operationErr = errors.Join(operationErr, windows.ERROR_INVALID_SID)
		}
		cleanupErr := windowsDeleteAppContainerProfileByName(name)
		if cleanupErr != nil {
			return nil, errors.Join(operationErr, errWindowsAppContainerPrepareCleanup, cleanupErr)
		}
		return nil, operationErr
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
	freeErr := windows.FreeSid(sid)
	if copyErr != nil || freeErr != nil || copied == nil {
		operationErr := errors.Join(copyErr, freeErr)
		if copied == nil {
			operationErr = errors.Join(operationErr, windows.ERROR_INVALID_SID)
		}
		return nil, operationErr
	}
	return copied, nil
}

func (session *windowsAppContainerSession) prepareWritableWorkspace(request *gateProcessRequest) error {
	if session == nil || session.sid == nil || request == nil {
		return errors.Join(errWindowsAppContainerWorkspace, windows.ERROR_INVALID_PARAMETER)
	}
	privateRoot := windowsQualificationPrivateRoot(request.Env)
	moduleCache := windowsEnvironmentLookup(request.Env, "GOMODCACHE")
	if privateRoot == "" || !cleanAbsoluteGatePath(moduleCache) ||
		strings.EqualFold(privateRoot, moduleCache) ||
		!windowsPathWithin(privateRoot, moduleCache) ||
		windowsPathsOverlap(privateRoot, request.Dir) ||
		!validGateDirectory(moduleCache) {
		return errors.Join(errWindowsAppContainerWorkspace, windows.ERROR_INVALID_PARAMETER)
	}

	workspace, cleanup, _, err := createPrivateQualificationStaging(
		privateRoot, windowsAppContainerWorkspacePrefix,
	)
	if err != nil || cleanup == nil {
		return errors.Join(errWindowsAppContainerWorkspace, err)
	}
	session.writableWorkspacePath = workspace
	session.cleanupWritableWorkspace = cleanup
	if windowsPathsOverlap(workspace, moduleCache) || windowsPathsOverlap(workspace, request.Dir) {
		return errors.Join(errWindowsAppContainerWorkspace, windows.ERROR_INVALID_PARAMETER)
	}
	if err := session.grantWritableWorkspaceRoot(workspace); err != nil {
		return errors.Join(errWindowsAppContainerWritableGrant, err)
	}

	environment, ok := windowsRehomeAppContainerWritableEnvironment(request.Env, workspace)
	if !ok {
		return errors.Join(errWindowsAppContainerWorkspace, windows.ERROR_INVALID_PARAMETER)
	}
	request.Env = environment
	if !validWindowsAppContainerEnvironmentBounds(request.Env) ||
		windowsQualificationPrivateRoot(request.Env) != privateRoot ||
		!strings.EqualFold(windowsEnvironmentLookup(request.Env, "GOMODCACHE"), moduleCache) {
		return errors.Join(errWindowsAppContainerWorkspace, windows.ERROR_INVALID_PARAMETER)
	}
	return nil
}

func validWindowsAppContainerEnvironmentBounds(environment []string) bool {
	if len(environment) == 0 || len(environment) > maximumGateEnvironment {
		return false
	}
	total := 0
	for _, entry := range environment {
		total += len(entry)
		if total > maximumGateProcessTextBytes {
			return false
		}
	}
	return true
}

func (session *windowsAppContainerSession) grantWritableWorkspaceRoot(path string) error {
	file, information, err := windowsOpenAppContainerGrantPath(path)
	if err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = file.Close()
		return windows.ERROR_DIRECTORY
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsAppContainerAccessEntry(
			session.sid,
			windowsAppContainerWritableRootAccess,
			uint32(windows.NO_INHERITANCE),
		),
		windowsAppContainerAccessEntry(
			session.sid,
			windowsAppContainerWritableChildAccess,
			uint32(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERIT_ONLY_ACE),
		),
	}
	return session.grantOpenHandleEntries(file, entries, 0)
}

func windowsRehomeAppContainerWritableEnvironment(environment []string, workspace string) ([]string, bool) {
	if !cleanAbsoluteGatePath(workspace) {
		return nil, false
	}
	targets := make(map[string]struct{}, len(windowsAppContainerWritableEnvironmentKeys))
	for _, name := range windowsAppContainerWritableEnvironmentKeys {
		targets[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(targets))
	result := make([]string, 0, len(environment)+len(targets))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		canonical := strings.ToUpper(name)
		if !ok || name == "" {
			return nil, false
		}
		if _, rewrite := targets[canonical]; !rewrite {
			result = append(result, entry)
			continue
		}
		if _, duplicate := seen[canonical]; duplicate {
			return nil, false
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical+"="+workspace)
	}
	for _, name := range windowsAppContainerWritableEnvironmentKeys {
		if _, ok := seen[name]; ok {
			continue
		}
		result = append(result, name+"="+workspace)
	}
	if !validWindowsAppContainerEnvironmentBounds(result) {
		return nil, false
	}
	return result, true
}

func windowsPathsOverlap(left, right string) bool {
	if !cleanAbsoluteGatePath(left) || !cleanAbsoluteGatePath(right) ||
		!strings.EqualFold(filepath.VolumeName(left), filepath.VolumeName(right)) {
		return false
	}
	return windowsPathWithin(left, right) || windowsPathWithin(right, left)
}

func windowsGrantAppContainerGatePaths(request gateProcessRequest, session *windowsAppContainerSession) error {
	if session == nil || session.sid == nil {
		return windows.ERROR_INVALID_SID
	}
	required, moduleCache, readable := windowsNetworkNoneAccessPaths(request)
	if privateRoot := windowsQualificationPrivateRoot(request.Env); privateRoot != "" {
		if err := session.grantPath(
			privateRoot,
			windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|
				windows.READ_CONTROL|windows.SYNCHRONIZE,
			false,
		); err != nil {
			return errors.Join(errWindowsAppContainerPrivateGrant, err)
		}
	}
	for _, path := range required {
		if err := session.grantPath(
			path, windows.GENERIC_READ|windows.GENERIC_EXECUTE,
			strings.EqualFold(path, request.Dir),
		); err != nil {
			return errors.Join(errWindowsAppContainerRequiredGrant, err)
		}
	}
	// go.exe launches vet.exe -flags with stdout attached to NUL. AppContainer
	// cannot open the Null device unless this SID is on that device DACL.
	// NUL is supplemental for gates that do not launch go or Git. A failure
	// before any mutation is safe to skip; once mutated, every failure blocks
	// preparation so release can restore the journaled device DACL.
	if err := session.grantNullDevice(); err != nil &&
		!errors.Is(err, errWindowsAppContainerGrantNotApplied) {
		return errors.Join(errWindowsAppContainerNullGrant, err)
	}
	for _, path := range moduleCache {
		if err := session.grantPath(path, windows.GENERIC_READ|windows.GENERIC_EXECUTE, true); err != nil {
			return errors.Join(errWindowsAppContainerRequiredGrant, err)
		}
	}
	for _, path := range readable {
		propagate := windowsAppContainerReadableTree(path) &&
			!strings.EqualFold(path, request.ContainmentApplication) &&
			!strings.EqualFold(path, filepath.Dir(request.ContainmentApplication))
		// External runtime trees can already be readable by AppContainer tokens.
		// Skip a supplemental path only if it fails before the first mutation.
		if err := session.grantPath(path, windows.GENERIC_READ|windows.GENERIC_EXECUTE, propagate); err != nil &&
			!errors.Is(err, errWindowsAppContainerGrantNotApplied) {
			return errors.Join(errWindowsAppContainerReadableGrant, err)
		}
	}
	// AppContainer lacks SeChangeNotifyPrivilege. Schema JSON opens Dir and
	// every ancestor except the volume root. Grant path-only traverse on Dir's
	// ancestors. Do not grant Application/GOROOT ancestors: SetNamedSecurityInfo
	// on C:\hostedtoolcache hangs CI. Do not inherit or TreeReset.
	if err := session.grantAncestorChain(request.Dir); err != nil {
		return errors.Join(errWindowsAppContainerAncestorGrant, err)
	}
	return nil
}

func windowsAppContainerReadableTree(path string) bool {
	base := filepath.Base(path)
	if strings.EqualFold(base, "bin") || strings.EqualFold(base, "tool") {
		return true
	}
	if !strings.EqualFold(base, "src") && !strings.EqualFold(base, "pkg") &&
		!strings.EqualFold(base, "lib") {
		return false
	}
	_, err := os.Lstat(filepath.Join(filepath.Dir(path), "bin", "go.exe"))
	return err == nil
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

func (session *windowsAppContainerSession) grantAncestorChain(path string) error {
	for _, ancestor := range windowsAppContainerAncestorPaths(path) {
		if windowsAppContainerAncestorGrantForbidden(ancestor) {
			continue
		}
		if err := session.grantAncestorPath(ancestor); err != nil {
			return err
		}
	}
	return nil
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

func (session *windowsAppContainerSession) grantAncestorPath(path string) error {
	file, information, err := windowsOpenAppContainerGrantPath(path)
	if err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = file.Close()
		return windows.ERROR_DIRECTORY
	}
	return session.grantOpenHandle(
		file,
		windows.GENERIC_READ|windows.GENERIC_EXECUTE,
		uint32(windows.NO_INHERITANCE),
		0,
	)
}

func (session *windowsAppContainerSession) grantNullDevice() (resultErr error) {
	journalStart := 0
	if session != nil {
		journalStart = len(session.daclRestores)
	}
	defer func() {
		journalEnd := journalStart
		if session != nil {
			journalEnd = len(session.daclRestores)
		}
		resultErr = windowsClassifyAppContainerGrantFailure(
			resultErr, journalStart, journalEnd,
		)
	}()
	if session == nil || session.sid == nil {
		return windows.ERROR_INVALID_SID
	}
	access := windows.ACCESS_MASK(
		windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.SYNCHRONIZE,
	)
	lease, err := windowsAcquireAppContainerNullLease()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(`\\.\NUL`)
	if err != nil {
		return windowsAppContainerPreMutationFailure(
			err, windowsReleaseAppContainerNullLease(lease, true),
		)
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return windowsAppContainerPreMutationFailure(
			err, windowsReleaseAppContainerNullLease(lease, true),
		)
	}
	file := os.NewFile(uintptr(handle), "appcontainer-null-device-grant")
	if file == nil {
		return windowsAppContainerPreMutationFailure(
			windows.ERROR_INVALID_HANDLE,
			windows.CloseHandle(handle),
			windowsReleaseAppContainerNullLease(lease, true),
		)
	}
	return session.grantOpenHandle(file, access, uint32(windows.NO_INHERITANCE), lease)
}

func windowsAcquireAppContainerNullLease() (windows.Handle, error) {
	return windowsAcquireNamedAppContainerNullLease(
		windowsAppContainerNullMutexName,
		gateProcessCleanupTimeout,
	)
}

func windowsAcquireNamedAppContainerNullLease(
	mutexName string,
	timeout time.Duration,
) (windows.Handle, error) {
	milliseconds := timeout.Milliseconds()
	if timeout%time.Millisecond != 0 {
		milliseconds++
	}
	if milliseconds <= 0 || milliseconds >= int64(windows.INFINITE) {
		return 0, errors.Join(errWindowsAppContainerNullLease, windows.ERROR_INVALID_PARAMETER)
	}
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return 0, errors.Join(errWindowsAppContainerNullLease, err)
	}
	runtime.LockOSThread()
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		runtime.UnlockOSThread()
		return 0, errors.Join(errWindowsAppContainerNullLease, err)
	}
	event, waitErr := windows.WaitForSingleObject(handle, uint32(milliseconds))
	if waitErr != nil || event != windows.WAIT_OBJECT_0 {
		var releaseErr error
		var abandonedErr error
		if event == windows.WAIT_ABANDONED {
			abandonedErr = errors.Join(
				errWindowsAppContainerPrepareCleanup,
				windows.ERROR_ABANDONED_WAIT_0,
			)
			releaseErr = windows.ReleaseMutex(handle)
		}
		closeErr := windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		return 0, errors.Join(
			errWindowsAppContainerNullLease,
			waitErr,
			abandonedErr,
			releaseErr,
			closeErr,
		)
	}
	return handle, nil
}

func windowsReleaseAppContainerNullLease(handle windows.Handle, threadLocked bool) error {
	if handle == 0 {
		if threadLocked {
			runtime.UnlockOSThread()
		}
		return errWindowsAppContainerNullLease
	}
	releaseErr := windows.ReleaseMutex(handle)
	closeErr := windows.CloseHandle(handle)
	if threadLocked {
		runtime.UnlockOSThread()
	}
	if releaseErr != nil || closeErr != nil {
		return errors.Join(errWindowsAppContainerNullLease, releaseErr, closeErr)
	}
	return nil
}

func windowsNetworkNoneAccessPaths(request gateProcessRequest) (required, moduleCache, readable []string) {
	required = uniqueExistingWindowsPaths([]string{
		request.Application,
		request.ContainmentApplication,
		request.Dir,
	})
	var modulePaths, readPaths []string
	readPaths = append(readPaths, windowsExecutableTree(request.Application)...)
	readPaths = append(readPaths, windowsExecutableTree(request.ContainmentApplication)...)
	for _, entry := range request.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" {
			continue
		}
		switch strings.ToUpper(key) {
		case "GOMODCACHE":
			modulePaths = append(modulePaths, value)
		case "GOROOT":
			readPaths = append(readPaths, value)
		case "PATH":
			readPaths = append(readPaths, filepath.SplitList(value)...)
		}
	}
	moduleCache = uniqueExistingWindowsPaths(modulePaths)
	readable = excludeExistingWindowsPaths(
		uniqueExistingWindowsPaths(readPaths),
		append(append([]string(nil), required...), moduleCache...),
	)
	return required, moduleCache, readable
}

func excludeExistingWindowsPaths(paths, excluded []string) []string {
	keys := make(map[string]struct{}, len(excluded))
	for _, path := range excluded {
		keys[strings.ToLower(filepath.Clean(path))] = struct{}{}
	}
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, skip := keys[strings.ToLower(filepath.Clean(path))]; skip {
			continue
		}
		result = append(result, path)
	}
	return result
}

func windowsQualificationPrivateRoot(environment []string) string {
	values := make(map[string]string, 4)
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		name = strings.ToUpper(name)
		if !ok || (name != "HOME" && name != "GOCACHE" && name != "GOMODCACHE" && name != "GOTMPDIR") {
			continue
		}
		if value == "" || values[name] != "" {
			return ""
		}
		values[name] = filepath.Clean(value)
	}
	root := values["HOME"]
	if root == "" || !filepath.IsAbs(root) {
		return ""
	}
	for _, name := range []string{"GOCACHE", "GOMODCACHE", "GOTMPDIR"} {
		path := values[name]
		if path == "" || !filepath.IsAbs(path) ||
			!strings.EqualFold(filepath.VolumeName(root), filepath.VolumeName(path)) {
			return ""
		}
		for !windowsPathWithin(root, path) {
			parent := filepath.Dir(root)
			if parent == root {
				return ""
			}
			root = parent
		}
	}
	if filepath.Dir(root) == root {
		return ""
	}
	return root
}

func windowsPathWithin(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
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
		paths = append(paths, root, filepath.Join(root, "pkg", "tool"),
			filepath.Join(root, "pkg"), filepath.Join(root, "src"),
			filepath.Join(root, "lib"))
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

func (session *windowsAppContainerSession) grantPath(
	path string,
	access windows.ACCESS_MASK,
	propagate bool,
) (resultErr error) {
	journalStart := 0
	if session != nil {
		journalStart = len(session.daclRestores)
	}
	defer func() {
		journalEnd := journalStart
		if session != nil {
			journalEnd = len(session.daclRestores)
		}
		resultErr = windowsClassifyAppContainerGrantFailure(
			resultErr, journalStart, journalEnd,
		)
	}()
	budget := 500_000
	return session.grantPathLimited(path, access, propagate, 0, &budget)
}

func windowsClassifyAppContainerGrantFailure(err error, journalStart, journalEnd int) error {
	if err == nil || journalEnd != journalStart ||
		errors.Is(err, errWindowsAppContainerPrepareCleanup) ||
		errors.Is(err, errWindowsAppContainerDACLOrphan) {
		return err
	}
	return errors.Join(errWindowsAppContainerGrantNotApplied, err)
}

func (restore *windowsAppContainerDACLRestore) restore() error {
	if restore == nil {
		return errWindowsAppContainerDACLRestore
	}
	if restore.file == nil || restore.dacl == nil || restore.descriptor == nil {
		leaseErr := windowsReleaseAppContainerNullLease(restore.lease, restore.leaseThreadLocked)
		restore.lease = 0
		restore.leaseThreadLocked = false
		return errors.Join(errWindowsAppContainerDACLRestore, leaseErr)
	}
	handle := windows.Handle(restore.file.Fd())
	restoreErr := windowsVerifyAppContainerObjectIdentity(handle, restore.identity)
	if restoreErr != nil {
		restoreErr = errors.Join(errWindowsAppContainerDACLIdentity, restoreErr)
	} else {
		restoreErr = windowsRestoreAppContainerDACL(handle, restore)
		if restoreErr != nil {
			restoreErr = errors.Join(errWindowsAppContainerDACLSet, restoreErr)
		}
	}
	if restoreErr == nil {
		restoreErr = windowsVerifyAppContainerObjectIdentity(handle, restore.identity)
		if restoreErr != nil {
			restoreErr = errors.Join(errWindowsAppContainerDACLIdentity, restoreErr)
		}
	}
	if restoreErr == nil {
		current, readErr := windows.GetSecurityInfo(
			handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		)
		if readErr != nil {
			restoreErr = errors.Join(errWindowsAppContainerDACLRead, readErr)
		} else if current == nil || !current.IsValid() {
			restoreErr = errWindowsAppContainerDACLMismatch
		} else {
			control, revision, controlErr := current.Control()
			currentDACL, defaulted, daclErr := current.DACL()
			currentBytes, aclOK := windowsACLBytes(currentDACL)
			currentIdentity, identityOK := windowsACLSemantic(currentDACL)
			if controlErr != nil || daclErr != nil || defaulted || !aclOK ||
				!identityOK ||
				control != restore.control || revision != restore.revision ||
				(!bytes.Equal(currentBytes, restore.daclBytes) &&
					!sameWindowsACLSemantic(currentIdentity, restore.daclIdentity)) {
				restoreErr = errWindowsAppContainerDACLMismatch
			}
		}
		runtime.KeepAlive(current)
	}
	runtime.KeepAlive(restore.descriptor)
	closeErr := restore.file.Close()
	restore.file = nil
	var leaseErr error
	if restore.lease != 0 || restore.leaseThreadLocked {
		leaseErr = windowsReleaseAppContainerNullLease(restore.lease, restore.leaseThreadLocked)
		restore.lease = 0
		restore.leaseThreadLocked = false
	}
	if restoreErr != nil || closeErr != nil || leaseErr != nil {
		return errors.Join(errWindowsAppContainerDACLRestore, restoreErr, closeErr, leaseErr)
	}
	return nil
}

func windowsRestoreAppContainerDACL(
	handle windows.Handle,
	restore *windowsAppContainerDACLRestore,
) error {
	if restore == nil || restore.dacl == nil || restore.descriptor == nil {
		return windows.ERROR_INVALID_SECURITY_DESCR
	}
	if restore.control&windows.SE_DACL_AUTO_INHERITED == 0 {
		return windows.SetKernelObjectSecurity(
			handle,
			windows.DACL_SECURITY_INFORMATION,
			restore.descriptor,
		)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if restore.control&windows.SE_DACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		securityInformation,
		nil,
		nil,
		restore.dacl,
		nil,
	)
}

func windowsACLBytes(acl *windows.ACL) ([]byte, bool) {
	if acl == nil {
		return nil, false
	}
	header := (*windowsACLHeader)(unsafe.Pointer(acl))
	if header.size < uint16(unsafe.Sizeof(windowsACLHeader{})) {
		return nil, false
	}
	for index := uint32(0); index < uint32(header.count); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
			return nil, false
		}
	}
	value := make([]byte, int(header.size))
	copy(value, unsafe.Slice((*byte)(unsafe.Pointer(acl)), int(header.size)))
	return value, true
}

func windowsACLSemantic(acl *windows.ACL) (windowsACLSemanticIdentity, bool) {
	if acl == nil {
		return windowsACLSemanticIdentity{}, false
	}
	header := (*windowsACLHeader)(unsafe.Pointer(acl))
	if header.size < uint16(unsafe.Sizeof(windowsACLHeader{})) {
		return windowsACLSemanticIdentity{}, false
	}
	identity := windowsACLSemanticIdentity{
		revision: header.revision,
		aces:     make([][]byte, 0, header.count),
	}
	for index := uint32(0); index < uint32(header.count); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
			return windowsACLSemanticIdentity{}, false
		}
		value := make([]byte, int(ace.Header.AceSize))
		copy(value, unsafe.Slice((*byte)(unsafe.Pointer(ace)), len(value)))
		identity.aces = append(identity.aces, value)
	}
	return identity, true
}

func sameWindowsACLSemantic(left, right windowsACLSemanticIdentity) bool {
	if left.revision != right.revision || len(left.aces) != len(right.aces) {
		return false
	}
	for index := range left.aces {
		if !bytes.Equal(left.aces[index], right.aces[index]) {
			return false
		}
	}
	return true
}

func (session *windowsAppContainerSession) grantPathLimited(
	path string,
	access windows.ACCESS_MASK,
	propagate bool,
	depth int,
	budget *int,
) error {
	if session == nil || session.sid == nil || budget == nil ||
		depth > maximumQualificationWorkspaceCleanupDepth || *budget <= 0 ||
		windowsAppContainerTreeMutationForbidden(path) {
		return windows.ERROR_ACCESS_DENIED
	}
	*budget--
	file, information, err := windowsOpenAppContainerGrantPath(path)
	if err != nil {
		return err
	}
	if !propagate || information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return session.grantOpenHandle(file, access, uint32(windows.NO_INHERITANCE), 0)
	}

	for {
		entries, readErr := file.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return windowsAppContainerPreMutationFailure(readErr, file.Close())
		}
		for _, entry := range entries {
			name := entry.Name()
			if name == "" || name == "." || name == ".." {
				return windowsAppContainerPreMutationFailure(windows.ERROR_INVALID_NAME, file.Close())
			}
			if err := session.grantPathLimited(
				filepath.Join(path, name), access, true, depth+1, budget,
			); err != nil {
				return windowsAppContainerPreMutationFailure(err, file.Close())
			}
		}
		if readErr == io.EOF || len(entries) < 128 {
			break
		}
	}
	// SetSecurityInfo can re-propagate a directory's inheritable baseline ACEs
	// even though the added package ACE is non-inheriting. Snapshot descendants
	// first so reverse journal restoration runs parent before child and returns
	// every object to its pre-session state.
	return session.grantOpenHandle(file, access, uint32(windows.NO_INHERITANCE), 0)
}

func (session *windowsAppContainerSession) grantOpenHandle(
	file *os.File,
	access windows.ACCESS_MASK,
	inheritance uint32,
	lease windows.Handle,
) error {
	if session == nil || session.sid == nil || file == nil || inheritance != uint32(windows.NO_INHERITANCE) {
		var closeErr error
		if file != nil {
			closeErr = file.Close()
		}
		return windowsAppContainerPreMutationFailure(
			windows.ERROR_INVALID_PARAMETER,
			closeErr,
			windowsReleaseOptionalAppContainerNullLease(lease),
		)
	}
	return session.grantOpenHandleEntries(
		file,
		[]windows.EXPLICIT_ACCESS{windowsAppContainerAccessEntry(session.sid, access, inheritance)},
		lease,
	)
}

func windowsAppContainerAccessEntry(
	sid *windows.SID,
	access windows.ACCESS_MASK,
	inheritance uint32,
) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func (session *windowsAppContainerSession) grantOpenHandleEntries(
	file *os.File,
	entries []windows.EXPLICIT_ACCESS,
	lease windows.Handle,
) error {
	if session == nil || session.sid == nil || file == nil || len(entries) == 0 {
		var closeErr error
		if file != nil {
			closeErr = file.Close()
		}
		return windowsAppContainerPreMutationFailure(
			windows.ERROR_INVALID_PARAMETER,
			closeErr,
			windowsReleaseOptionalAppContainerNullLease(lease),
		)
	}
	restore, err := windowsSnapshotAppContainerDACL(file)
	if err != nil {
		return windowsAppContainerPreMutationFailure(
			err, file.Close(), windowsReleaseOptionalAppContainerNullLease(lease),
		)
	}
	target := windowsAppContainerDACLFilesystem
	if lease != 0 {
		if restore.identity.fileType != windows.FILE_TYPE_CHAR {
			return windowsAppContainerPreMutationFailure(
				windows.ERROR_INVALID_HANDLE,
				file.Close(),
				windowsReleaseOptionalAppContainerNullLease(lease),
			)
		}
		target = windowsAppContainerDACLNullDevice
	}
	if err := windowsValidateAppContainerDACLPackageBaselineForTarget(
		restore.dacl,
		target,
		session.baselinePackageSID,
		session.sid,
	); err != nil {
		return windowsAppContainerPreMutationFailure(
			err, file.Close(), windowsReleaseOptionalAppContainerNullLease(lease),
		)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(session.sid)
	acl, err := windows.ACLFromEntries(entries, restore.dacl)
	if err != nil {
		return windowsAppContainerPreMutationFailure(
			err, file.Close(), windowsReleaseOptionalAppContainerNullLease(lease),
		)
	}
	handle := windows.Handle(file.Fd())
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		runtime.KeepAlive(acl)
		return windowsAppContainerPreMutationFailure(
			errors.Join(errWindowsAppContainerDACLSet, err),
			file.Close(),
			windowsReleaseOptionalAppContainerNullLease(lease),
		)
	}
	runtime.KeepAlive(acl)
	restore.lease = lease
	restore.leaseThreadLocked = lease != 0
	session.daclRestores = append(session.daclRestores, restore)
	if err := windowsVerifyAppContainerObjectIdentity(handle, restore.identity); err != nil {
		return errors.Join(errWindowsAppContainerDACLIdentity, err)
	}
	return nil
}

func windowsValidateAppContainerDACLPackageBaseline(dacl *windows.ACL, allowed ...*windows.SID) error {
	return windowsValidateAppContainerDACLPackageBaselineForTarget(
		dacl, windowsAppContainerDACLFilesystem, allowed...,
	)
}

func windowsValidateAppContainerDACLPackageBaselineForTarget(
	dacl *windows.ACL,
	target windowsAppContainerDACLTarget,
	allowed ...*windows.SID,
) error {
	if dacl == nil {
		return errWindowsAppContainerDACLOrphan
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			(ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
				ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE) ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) {
			return errWindowsAppContainerDACLOrphan
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() || uintptr(sid.Len()) >
			uintptr(ace.Header.AceSize)-unsafe.Offsetof(ace.SidStart) {
			return errWindowsAppContainerDACLOrphan
		}
		sidText := sid.String()
		if sidText == "" {
			return errWindowsAppContainerDACLOrphan
		}
		if windowsWellKnownAppContainerReadPrincipal(sidText) {
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
				!windowsValidWellKnownAppContainerACE(ace, target) {
				return errWindowsAppContainerDACLOrphan
			}
			continue
		}
		subAuthorities, appContainerAuthority := windowsCanonicalAppContainerSIDParts(sidText)
		if !appContainerAuthority || len(subAuthorities) == 0 || subAuthorities[0] != 2 {
			continue
		}
		if len(subAuthorities) != 8 {
			return errWindowsAppContainerDACLOrphan
		}
		matched := false
		for _, candidate := range allowed {
			if validWindowsAppContainerPackageSID(candidate) && sidText == candidate.String() {
				matched = true
				break
			}
		}
		if !matched {
			return errWindowsAppContainerDACLOrphan
		}
	}
	return nil
}

func windowsValidWellKnownAppContainerACE(
	ace *windows.ACCESS_ALLOWED_ACE,
	target windowsAppContainerDACLTarget,
) bool {
	if ace == nil {
		return false
	}
	switch target {
	case windowsAppContainerDACLFilesystem:
		const genericReadExecute windows.ACCESS_MASK = windows.GENERIC_READ | windows.GENERIC_EXECUTE
		const fileReadExecute windows.ACCESS_MASK = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
		const inherited = uint8(windows.INHERITED_ACE)
		const inheritOnly = uint8(
			windows.OBJECT_INHERIT_ACE |
				windows.CONTAINER_INHERIT_ACE |
				windows.INHERIT_ONLY_ACE,
		)
		return (ace.Mask == fileReadExecute &&
			(ace.Header.AceFlags == uint8(windows.NO_INHERITANCE) || ace.Header.AceFlags == inherited)) ||
			(ace.Mask == genericReadExecute &&
				(ace.Header.AceFlags == inheritOnly || ace.Header.AceFlags == inheritOnly|inherited))
	case windowsAppContainerDACLNullDevice:
		return ace.Mask == windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.FILE_GENERIC_EXECUTE &&
			ace.Header.AceFlags == uint8(windows.NO_INHERITANCE)
	default:
		return false
	}
}

func windowsWellKnownAppContainerReadPrincipal(value string) bool {
	return value == "S-1-15-2-1" || value == "S-1-15-2-2"
}

func validWindowsAppContainerPackageSID(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	subAuthorities, ok := windowsCanonicalAppContainerSIDParts(sid.String())
	return ok && len(subAuthorities) == 8 && subAuthorities[0] == 2
}

func windowsCanonicalAppContainerSIDParts(value string) ([]uint32, bool) {
	parts := strings.Split(value, "-")
	if len(parts) < 4 || parts[0] != "S" || parts[1] != "1" || parts[2] != "15" {
		return nil, false
	}
	subAuthorities := make([]uint32, len(parts)-3)
	for index, part := range parts[3:] {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, false
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(parsed, 10) != part {
			return nil, false
		}
		subAuthorities[index] = uint32(parsed)
	}
	return subAuthorities, true
}

func windowsAppContainerPreMutationFailure(operationErr error, cleanupErrs ...error) error {
	cleanupErr := errors.Join(cleanupErrs...)
	if cleanupErr != nil {
		return errors.Join(operationErr, errWindowsAppContainerPrepareCleanup, cleanupErr)
	}
	return operationErr
}

func windowsReleaseOptionalAppContainerNullLease(handle windows.Handle) error {
	if handle == 0 {
		return nil
	}
	return windowsReleaseAppContainerNullLease(handle, true)
}

func windowsSnapshotAppContainerDACL(file *os.File) (*windowsAppContainerDACLRestore, error) {
	if file == nil {
		return nil, windows.ERROR_INVALID_HANDLE
	}
	handle := windows.Handle(file.Fd())
	identity, err := windowsReadAppContainerObjectIdentity(handle)
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		if err != nil {
			return nil, err
		}
		return nil, windows.ERROR_INVALID_SECURITY_DESCR
	}
	control, revision, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return nil, windows.ERROR_INVALID_ACL
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || defaulted || dacl == nil {
		return nil, windows.ERROR_INVALID_ACL
	}
	daclBytes, ok := windowsACLBytes(dacl)
	if !ok {
		return nil, windows.ERROR_INVALID_ACL
	}
	daclIdentity, ok := windowsACLSemantic(dacl)
	if !ok {
		return nil, windows.ERROR_INVALID_ACL
	}
	return &windowsAppContainerDACLRestore{
		file:         file,
		descriptor:   descriptor,
		dacl:         dacl,
		identity:     identity,
		daclBytes:    daclBytes,
		daclIdentity: daclIdentity,
		control:      control,
		revision:     revision,
	}, nil
}

func windowsReadAppContainerObjectIdentity(handle windows.Handle) (windowsAppContainerObjectIdentity, error) {
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return windowsAppContainerObjectIdentity{}, err
	}
	identity := windowsAppContainerObjectIdentity{fileType: fileType}
	switch fileType {
	case windows.FILE_TYPE_DISK:
		var information windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
			return windowsAppContainerObjectIdentity{}, err
		}
		identity.hasFileID = true
		identity.volumeSerial = information.VolumeSerialNumber
		identity.fileIndexHigh = information.FileIndexHigh
		identity.fileIndexLow = information.FileIndexLow
	case windows.FILE_TYPE_CHAR:
		// A retained character-device handle is the stable identity boundary;
		// character devices do not expose a filesystem file ID.
	default:
		return windowsAppContainerObjectIdentity{}, windows.ERROR_INVALID_HANDLE
	}
	return identity, nil
}

func windowsVerifyAppContainerObjectIdentity(
	handle windows.Handle,
	want windowsAppContainerObjectIdentity,
) error {
	got, err := windowsReadAppContainerObjectIdentity(handle)
	if err != nil {
		return err
	}
	if got != want {
		return windows.ERROR_FILE_INVALID
	}
	return nil
}

func windowsOpenAppContainerGrantPath(path string) (*os.File, windows.ByHandleFileInformation, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, windows.ByHandleFileInformation{}, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, windows.ByHandleFileInformation{}, err
	}
	file := os.NewFile(uintptr(handle), "appcontainer-grant")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, windows.ByHandleFileInformation{}, windows.ERROR_INVALID_HANDLE
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = file.Close()
		if err != nil {
			return nil, windows.ByHandleFileInformation{}, err
		}
		return nil, windows.ByHandleFileInformation{}, windows.ERROR_CANT_ACCESS_FILE
	}
	return file, information, nil
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
