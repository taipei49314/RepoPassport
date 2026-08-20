//go:build windows

package testsupport

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tokenIsAppContainer uint32 = 29

func currentProcessIsAppContainer() (bool, error) {
	var value uint32
	var returned uint32
	if err := windows.GetTokenInformation(
		windows.GetCurrentProcessToken(),
		tokenIsAppContainer,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
		&returned,
	); err != nil {
		return false, fmt.Errorf("query TokenIsAppContainer: %w", err)
	}
	if returned != uint32(unsafe.Sizeof(value)) {
		return false, fmt.Errorf("TokenIsAppContainer returned %d bytes, want %d", returned, unsafe.Sizeof(value))
	}
	return value != 0, nil
}
