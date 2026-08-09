//go:build windows

package releasequalification

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestQualificationPathRejectsAnyAncestorReparsePoint(t *testing.T) {
	path := `C:\safe\junction\child\artifact.exe`
	visited := make([]string, 0, 5)
	got := qualificationPathHasReparsePointWith(path, func(component string) (uint32, error) {
		visited = append(visited, component)
		if strings.EqualFold(component, `C:\safe\junction`) {
			return syscall.FILE_ATTRIBUTE_DIRECTORY | syscall.FILE_ATTRIBUTE_REPARSE_POINT, nil
		}
		return syscall.FILE_ATTRIBUTE_DIRECTORY, nil
	})
	if !got {
		t.Fatal("ancestor reparse point was accepted")
	}
	foundAncestor := false
	for _, component := range visited {
		if strings.EqualFold(component, `C:\safe\junction`) {
			foundAncestor = true
		}
	}
	if !foundAncestor {
		t.Fatalf("ancestor components were not inspected: %q", visited)
	}
}

func TestQualificationPathComponentInspectionFailsClosed(t *testing.T) {
	if !qualificationPathHasReparsePointWith(`C:\safe\artifact.exe`, func(string) (uint32, error) {
		return 0, errors.New("access denied")
	}) {
		t.Fatal("attribute lookup error was accepted")
	}
	if qualificationPathHasReparsePointWith(`C:\safe\artifact.exe`, func(string) (uint32, error) {
		return syscall.FILE_ATTRIBUTE_DIRECTORY, nil
	}) {
		t.Fatal("ordinary path components were rejected")
	}
}
