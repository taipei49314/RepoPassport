//go:build windows

package releasequalification

import (
	"path/filepath"
	"strings"
	"syscall"
)

// qualificationPathHasReparsePoint is fail-closed: an unreadable path is not
// eligible for release qualification, and every Windows reparse point is
// rejected rather than relying on tag-specific symlink interpretation.
func qualificationPathHasReparsePoint(path string) bool {
	return qualificationPathHasReparsePointWith(path, func(component string) (uint32, error) {
		name, err := syscall.UTF16PtrFromString(component)
		if err != nil {
			return 0, err
		}
		return syscall.GetFileAttributes(name)
	})
}

func qualificationPathHasReparsePointWith(path string, attributes func(string) (uint32, error)) bool {
	absolute, err := filepath.Abs(path)
	if err != nil || attributes == nil {
		return true
	}
	clean := filepath.Clean(absolute)
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return true
	}
	current := volume + string(filepath.Separator)
	components := strings.FieldsFunc(strings.TrimPrefix(clean, volume), func(character rune) bool {
		return character == '\\' || character == '/'
	})
	for index := -1; index < len(components); index++ {
		if index >= 0 {
			current = filepath.Join(current, components[index])
		}
		value, err := attributes(current)
		if err != nil || value == syscall.INVALID_FILE_ATTRIBUTES ||
			value&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
	}
	return false
}
