//go:build windows

package sourcequalification

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func toolAssemblyCreatePrivateDirectory(path string) error {
	attributes, descriptor, err := toolAssemblyPrivateSecurityAttributes(true)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(pointer, attributes)
	runtime.KeepAlive(descriptor)
	return err
}

func toolAssemblyCreatePrivateFile(path string, raw []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	attributes, descriptor, err := toolAssemblyPrivateSecurityAttributes(false)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return errors.New("private tool assembly file handle is invalid")
	}
	written, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr == nil && written != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}

func toolAssemblyPrivateSecurityAttributes(
	directory bool,
) (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return nil, nil, errors.New("private tool assembly owner is unavailable")
	}
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	principals := []string{current.User.Sid.String(), "SY"}
	appContainer, err := currentPrivatePackageAppContainerSID()
	if err != nil {
		return nil, nil, err
	}
	if appContainer != nil {
		principals = append(principals, appContainer.String())
	}
	entries := make([]string, 0, len(principals))
	for _, principal := range principals {
		entries = append(entries, fmt.Sprintf("(A;%s;FA;;;%s)", inheritance, principal))
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + current.User.Sid.String() + "D:P" + strings.Join(entries, ""),
	)
	if err != nil {
		return nil, nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, descriptor, nil
}
