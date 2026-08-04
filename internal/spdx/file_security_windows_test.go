//go:build windows

package spdx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsUnsafeNativePathsAndReparseFailClosed(t *testing.T) {
	for _, value := range []string{
		`\\server\share\sbom.json`,
		`\\?\C:\fixture\sbom.json`,
		`\\.\C:\fixture\sbom.json`,
		`C:\fixture\sbom.json:alternate`,
	} {
		t.Run(value, func(t *testing.T) {
			if safeNativePath(value) {
				t.Fatalf("unsafe Windows path accepted by shape gate: %q", value)
			}
			if _, err := ReadFile(value); err == nil {
				t.Fatalf("unsafe Windows path reached attachment read: %q", value)
			}
		})
	}

	root := t.TempDir()
	target := filepath.Join(root, "regular.json")
	if err := os.WriteFile(target, []byte(`{"synthetic":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "reparse.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink/reparse creation unavailable: %v", err)
	}
	if !isReparsePoint(link) {
		t.Fatal("Windows symlink did not expose reparse-point attributes")
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("Windows final reparse point accepted")
	}
}
