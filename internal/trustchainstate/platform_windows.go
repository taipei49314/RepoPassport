//go:build windows

package trustchainstate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32                         = syscall.NewLazyDLL("kernel32.dll")
	moveFileExProc                   = kernel32.NewProc("MoveFileExW")
	afterPrivateCreate               = func(string) {}
	privateDACLAppContainerPrincipal = func() (string, error) { return "", nil }
	privateAppContainerFinalPath     func(windows.Handle, string) error
	installPrivateTestAdapterOnce    sync.Once
)

func installPrivateAppContainerTestAdapter(
	principal func() (string, error),
	resolver func(string) (string, error),
	boundary func(string) (string, error),
	finalPath func(windows.Handle, string) error,
) {
	if principal == nil || resolver == nil || boundary == nil || finalPath == nil {
		return
	}
	installPrivateTestAdapterOnce.Do(func() {
		privateDACLAppContainerPrincipal = principal
		privateStatePathResolver = resolver
		privateStatePathBoundaryResolver = boundary
		privateAppContainerFinalPath = finalPath
	})
}

func safeNativePath(value string) bool {
	if !safeNativeInput(value) {
		return false
	}
	volume := filepath.VolumeName(value)
	return volume != "" && strings.HasSuffix(volume, `:`)
}

func safeNativeInput(value string) bool {
	if value == "" || containsNUL(value) {
		return false
	}
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, `\\?\`) || strings.HasPrefix(upper, `\\.\`) || strings.HasPrefix(value, `\\`) {
		return false
	}
	volume := filepath.VolumeName(value)
	rest := value
	if volume != "" {
		rest = value[len(volume):]
	}
	if strings.Contains(rest, `:`) {
		return false
	}
	for _, component := range strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' }) {
		if component == "" || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return false
		}
	}
	return true
}

func isReparsePoint(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func createPrivateDirectory(path string) (bool, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, descriptor, err := privateSecurityAttributes()
	if err != nil {
		return false, err
	}
	err = windows.CreateDirectory(pointer, attributes)
	if err == nil {
		afterPrivateCreate(path)
	}
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(descriptor)
	if err == nil {
		return true, nil
	}
	if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_FILE_EXISTS {
		return false, nil
	}
	return false, err
}

func createPrivateLock(path string) (*os.File, bool, error) {
	file, created, err := createPrivateFile(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	return file, created, err
}

func openExistingPrivateLock(path string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	return file, nil
}

func createPrivateTemporaryFile(directory, prefix string) (*os.File, error) {
	for attempt := 0; attempt < 100; attempt++ {
		name, err := randomTemporaryName(prefix)
		if err != nil {
			return nil, ErrUnavailable
		}
		path := filepath.Join(directory, name)
		file, created, err := createPrivateFile(path, 0)
		if err != nil {
			return nil, err
		}
		if created {
			return file, nil
		}
	}
	return nil, ErrUnavailable
}

func createPrivateFile(path string, shareMode uint32) (*os.File, bool, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	attributes, descriptor, err := privateSecurityAttributes()
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		shareMode, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err == nil {
		afterPrivateCreate(path)
	}
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(descriptor)
	if err == nil {
		file := os.NewFile(uintptr(handle), path)
		if file == nil {
			_ = windows.CloseHandle(handle)
			return nil, false, ErrUnavailable
		}
		return file, true, nil
	}
	if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_FILE_EXISTS {
		return nil, false, nil
	}
	return nil, false, err
}

func privateSecurityAttributes() (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || token == nil || token.User.Sid == nil {
		return nil, nil, ErrUnavailable
	}
	owner := token.User.Sid.String()
	if owner == "" {
		return nil, nil, ErrUnavailable
	}
	sddl, err := currentPrivateDACLSDDL(owner)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || descriptor == nil {
		return nil, nil, ErrUnavailable
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, descriptor, nil
}

func privateDACLSDDL(owner string) string {
	sddl, _ := windowssecurity.PrivateDACLSDDL(owner, "")
	return sddl
}

func currentPrivateDACLSDDL(owner string) (string, error) {
	principal, err := privateDACLAppContainerPrincipal()
	if err != nil {
		return "", err
	}
	sddl, ok := windowssecurity.PrivateDACLSDDL(owner, principal)
	if !ok {
		return "", ErrUnavailable
	}
	return sddl, nil
}

func validateDirectoryPlatform(path string, info os.FileInfo) error {
	if !info.IsDir() || isReparsePoint(path) {
		return ErrUnavailable
	}
	return nil
}

func validatePrivateStateDirectoryPlatform(path string, info os.FileInfo) error {
	if err := validateDirectoryPlatform(path, info); err != nil {
		return err
	}
	handle, err := openDirectoryHandle(path, windows.READ_CONTROL)
	if err != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(handle)
	if err := validateFinalHandlePath(handle, path); err != nil {
		return ErrUnavailable
	}
	return validatePrivateDACL(handle)
}

func openDirectoryHandle(path string, access uint32) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func validateOpenedRegularFile(file *os.File, expectedPath string, singleLink bool) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrUnavailable
	}
	pathInfo, err := os.Lstat(expectedPath)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		isReparsePoint(expectedPath) || !os.SameFile(info, pathInfo) {
		return ErrUnavailable
	}
	handle := windows.Handle(file.Fd())
	if err := validateFinalHandlePath(handle, expectedPath); err != nil {
		return ErrUnavailable
	}
	if singleLink {
		var information windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &information); err != nil || information.NumberOfLinks != 1 ||
			information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrUnavailable
		}
	}
	return validatePrivateDACL(handle)
}

func validatePrivateDACL(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return ErrUnavailable
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		return ErrUnavailable
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return ErrUnavailable
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil || !owner.Equals(currentUser.User.Sid) {
		return ErrUnavailable
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return ErrUnavailable
	}
	principals := make([]string, 0, dacl.AceCount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 || ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) || ace.Mask != 0x1f01ff {
			return ErrUnavailable
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.String() == "" {
			return ErrUnavailable
		}
		principals = append(principals, sid.String())
	}
	principal, principalErr := privateDACLAppContainerPrincipal()
	valid := windowssecurity.ValidPrivateDACLPrincipals(owner.String(), principals, principal)
	if principalErr != nil || !valid {
		return ErrUnavailable
	}
	return nil
}

func validPrivateDACLPrincipals(owner string, principals []string) bool {
	return windowssecurity.ValidPrivateDACLPrincipals(owner, principals, "")
}

func hasPrincipal(principals map[string]struct{}, principal string) bool {
	_, present := principals[principal]
	return present
}

func validateFinalHandlePath(handle windows.Handle, expectedPath string) error {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED && privateAppContainerFinalPath != nil &&
			privateAppContainerFinalPath(handle, expectedPath) == nil {
			return nil
		}
		return ErrUnavailable
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return ErrUnavailable
	}
	actual := windows.UTF16ToString(buffer[:length])
	upper := strings.ToUpper(actual)
	if strings.HasPrefix(upper, `\\?\UNC\`) {
		return ErrUnavailable
	}
	if strings.HasPrefix(upper, `\\?\`) {
		actual = actual[len(`\\?\`):]
	}
	expected, err := filepath.Abs(expectedPath)
	if err != nil || !strings.EqualFold(filepath.Clean(actual), filepath.Clean(expected)) {
		return ErrUnavailable
	}
	return nil
}

func atomicReplace(source, destination string) error {
	sourcePointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileExProc.Call(uintptr(unsafe.Pointer(sourcePointer)), uintptr(unsafe.Pointer(destinationPointer)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough))
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return syscall.EINVAL
	}
	return nil
}

func syncDirectory(string) error { return nil }

func samePathPlatform(left, right string) bool { return strings.EqualFold(left, right) }
