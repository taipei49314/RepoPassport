//go:build windows

package windowssecurity

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenIsAppContainer  uint32 = 29
	tokenAppContainerSID uint32 = 31
)

var errAppContainerTokenInvalid = errors.New("Windows AppContainer token information is invalid")

type tokenAppContainerInformation struct {
	SID *windows.SID
}

// CurrentProcessIsAppContainer reports whether the effective process token is
// an AppContainer token. Query failures are returned so callers can fail closed.
func CurrentProcessIsAppContainer() (bool, error) {
	var value uint32
	var returned uint32
	if err := windows.GetTokenInformation(
		windows.GetCurrentProcessToken(),
		tokenIsAppContainer,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
		&returned,
	); err != nil {
		return false, err
	}
	if returned != uint32(unsafe.Sizeof(value)) {
		return false, errAppContainerTokenInvalid
	}
	return value != 0, nil
}

// CurrentAppContainerPrincipal returns the exact package SID for the current
// AppContainer, or an empty string for a normal host token.
func CurrentAppContainerPrincipal() (string, error) {
	appContainer, err := CurrentProcessIsAppContainer()
	if err != nil || !appContainer {
		return "", err
	}

	token := windows.GetCurrentProcessToken()
	var required uint32
	err = windows.GetTokenInformation(token, tokenAppContainerSID, nil, 0, &required)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || required < uint32(unsafe.Sizeof(tokenAppContainerInformation{})) {
		return "", errAppContainerTokenInvalid
	}
	buffer := make([]byte, required)
	var returned uint32
	if err := windows.GetTokenInformation(token, tokenAppContainerSID, &buffer[0], uint32(len(buffer)), &returned); err != nil {
		return "", err
	}
	if returned < uint32(unsafe.Sizeof(tokenAppContainerInformation{})) || returned > uint32(len(buffer)) {
		return "", errAppContainerTokenInvalid
	}
	information := (*tokenAppContainerInformation)(unsafe.Pointer(&buffer[0]))
	base := uintptr(unsafe.Pointer(&buffer[0]))
	end := base + uintptr(returned)
	sidPointer := uintptr(unsafe.Pointer(information.SID))
	if information.SID == nil || sidPointer < base || sidPointer >= end || !information.SID.IsValid() {
		return "", errAppContainerTokenInvalid
	}
	sidLength := uintptr(information.SID.Len())
	if sidLength == 0 || sidLength > end-sidPointer {
		return "", errAppContainerTokenInvalid
	}
	principal := information.SID.String()
	runtime.KeepAlive(buffer)
	if !validAppContainerPackagePrincipal(principal) {
		return "", errAppContainerTokenInvalid
	}
	return principal, nil
}
