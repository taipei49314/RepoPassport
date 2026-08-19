//go:build !windows

package sourcequalification

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictUnixRuntimeToolWriteBitsClearsGroupAndOtherWrite(t *testing.T) {
	path := writeTrustedRuntimeTestTool(t, t.TempDir(), "group-writable-go")
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	cleared, err := restrictUnixRuntimeToolWriteBits(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(cleared)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("restricted tool mode = %o, want no group/other write bits", info.Mode().Perm())
	}
	if _, err := trustedControllerRuntimePath(t.TempDir(), cleared); err != nil {
		t.Fatalf("restricted 0775 tool remained untrusted: %v", err)
	}
}

func TestControllerRuntimeFactRejectsGroupOrWorldWritableUnixTool(t *testing.T) {
	repository := t.TempDir()
	path := writeTrustedRuntimeTestTool(t, t.TempDir(), "writable-fact-tool")
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	line, err := controllerRuntimeFact(
		context.Background(),
		path,
		[]string{"version"},
		directory,
		controllerRuntimeFactEnvironment(gateRunEnvironment{
			ToolPath: filepath.Dir(path),
			HomeDir:  directory,
			TempDir:  directory,
		}),
	)
	if err == nil || line != "" {
		t.Fatalf("writable Unix tool fact = (%q, %v), want SOURCE_QUAL_INVALID_INPUT", line, err)
	}
	if validGateApplication(repository, path, []string{filepath.Dir(path)}) {
		t.Fatal("gate application binding accepted a group/world-writable Unix tool used as a fact source")
	}
}
