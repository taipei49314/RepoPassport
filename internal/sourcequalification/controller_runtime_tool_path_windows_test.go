//go:build windows

package sourcequalification

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustedControllerRuntimePathAcceptsToolBehindWindowsJunction(t *testing.T) {
	repository := t.TempDir()
	realDir := t.TempDir()
	realTool := writeTrustedRuntimeTestTool(t, realDir, "go.exe")
	junctionRoot := t.TempDir()
	junction := filepath.Join(junctionRoot, "hostedtoolcache")
	if !createWindowsDirectoryJunction(t, junction, realDir) {
		t.Skip("Windows junction fixture unavailable")
	}
	toolThroughJunction := filepath.Join(junction, "go.exe")

	resolved, err := trustedControllerRuntimePath(repository, toolThroughJunction)
	if err != nil {
		t.Fatalf("tool behind a directory junction was rejected: %v", err)
	}
	if sameCanonicalPath(resolved, toolThroughJunction) {
		t.Fatalf("trusted path kept the junction spelling %q", resolved)
	}
	if !sameCanonicalPath(resolved, realTool) {
		t.Fatalf("trusted path = %q, want the junction target %q", resolved, realTool)
	}
	if pathWithinRepository(repository, resolved) {
		t.Fatal("junction target was classified as inside the repository")
	}
	if _, evalErr := filepath.EvalSymlinks(resolved); evalErr != nil {
		t.Fatalf("resolved path %q is still not EvalSymlinks-stable: %v", resolved, evalErr)
	}
	if !validGateApplication(repository, resolved, []string{filepath.Dir(resolved)}) {
		t.Fatal("junction-resolved tool failed gate application binding")
	}
}

func createWindowsDirectoryJunction(t *testing.T, path, target string) bool {
	t.Helper()
	command := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", path, target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Logf("Windows junction fixture unavailable: %v (%s)", err, strings.TrimSpace(string(output)))
		return false
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return true
}
