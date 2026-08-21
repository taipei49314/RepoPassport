//go:build windows

package attestation

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func writePrivateFileForTest(path string, content []byte, _ os.FileMode) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("resolve current user SID: %w", err)
	}
	return createPrivateFileWithDACLForTest(path, content, fmt.Sprintf(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)",
		user.User.Sid.String(),
	))
}

func createPrivateFileWithDACLForTest(path string, content []byte, sddl string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("resolve current user SID: %w", err)
	}
	if !strings.HasPrefix(sddl, "D:") {
		return fmt.Errorf("test DACL is not canonical")
	}
	sddl = "O:" + user.User.Sid.String() + sddl

	appContainerPrincipal, err := windowssecurity.CurrentAppContainerPrincipal()
	if err != nil {
		return fmt.Errorf("resolve test AppContainer SID: %w", err)
	}
	if appContainerPrincipal != "" {
		sddl += fmt.Sprintf("(A;;GA;;;%s)", appContainerPrincipal)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse test DACL: %w", err)
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode private file path: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_WRITE,
		0,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create private file: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("wrap private file handle")
	}
	written, writeErr := file.Write(content)
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write private file: %w", writeErr)
	}
	if written != len(content) {
		_ = os.Remove(path)
		return io.ErrShortWrite
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close private file: %w", closeErr)
	}
	return nil
}
