//go:build !windows

package sourcequalification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedControllerRuntimePathRejectsGroupOrWorldWritableUnixTool(t *testing.T) {
	repository := t.TempDir()
	path := writeTrustedRuntimeTestTool(t, t.TempDir(), "writable-tool")
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	requireTrustedRuntimePathError(t, repository, path)
	if validGateApplication(repository, path, []string{filepath.Dir(path)}) {
		t.Fatal("gate application binding accepted a group/world-writable Unix tool")
	}

	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := trustedControllerRuntimePath(repository, path)
	if err != nil {
		t.Fatalf("0755 tool was rejected after write bits were cleared: %v", err)
	}
	if !validGateApplication(repository, resolved, []string{filepath.Dir(resolved)}) {
		t.Fatal("0755 tool failed gate application binding")
	}
}
