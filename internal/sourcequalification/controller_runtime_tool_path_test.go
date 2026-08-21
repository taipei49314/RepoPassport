package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTrustedControllerRuntimePathAcceptsHardlinkedToolOutsideRepository(t *testing.T) {
	repository := t.TempDir()
	tools := t.TempDir()
	original := writeTrustedRuntimeTestTool(t, tools, trustedRuntimeTestToolName())
	alias := filepath.Join(tools, "hardlinked-"+filepath.Base(original))
	if err := os.Link(original, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	resolved, err := trustedControllerRuntimePath(repository, alias)
	if err != nil {
		t.Fatalf("hardlinked tool outside the repository was rejected: %v", err)
	}
	if !sameCanonicalPath(resolved, alias) && !sameCanonicalPath(resolved, original) {
		t.Fatalf("trusted path = %q, want the hardlinked tool or its original inode path", resolved)
	}
	if pathWithinRepository(repository, resolved) {
		t.Fatal("hardlinked tool outside the repository was classified as inside the repository")
	}
	if !validGateApplication(repository, resolved, []string{filepath.Dir(resolved)}) {
		t.Fatal("hardlinked tool failed gate application binding after trusted resolution")
	}
}

func TestPackageSnapshotStillRejectsHardlinkedRegularFile(t *testing.T) {
	directory := t.TempDir()
	original := filepath.Join(directory, "package-file")
	if err := os.WriteFile(original, []byte("package-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "package-file-alias")
	if err := os.Link(original, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	identity, isDir, err := openPackagePathIdentity(alias)
	if err != nil || isDir || identity == (packageFileIdentity{}) {
		t.Fatalf("containment identity for hardlinked file = (dir=%v err=%v id=%+v), want a file identity",
			isDir, err, identity)
	}

	file, err := openPackageRegularFile(alias)
	if err != nil {
		t.Fatalf("open hardlinked package file: %v", err)
	}
	defer file.Close()
	if _, err := snapshotPackageHandle(file, false); err == nil {
		t.Fatal("package snapshot accepted a hard-linked regular file")
	}
}

func TestControllerRuntimeToolPathSeparatesFactOnlyApplications(t *testing.T) {
	root := t.TempDir()
	requiredDirectory := filepath.Join(root, "required")
	secondRequiredDirectory := filepath.Join(root, "required-second")
	factOnlyDirectory := filepath.Join(root, "fact-only")
	hostOnlyDirectory := filepath.Join(root, "host-only")
	for _, directory := range []string{
		requiredDirectory,
		secondRequiredDirectory,
		factOnlyDirectory,
		hostOnlyDirectory,
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	required := map[string]string{
		"go":                      filepath.Join(requiredDirectory, trustedRuntimeTestToolName()),
		"gofmt":                   filepath.Join(requiredDirectory, "gofmt"),
		"repopass-source-qualify": filepath.Join(secondRequiredDirectory, "controller"),
		"pwsh":                    filepath.Join(hostOnlyDirectory, "pwsh"),
	}
	all := map[string]string{
		"go":                      required["go"],
		"gofmt":                   required["gofmt"],
		"repopass-source-qualify": required["repopass-source-qualify"],
		"pwsh":                    required["pwsh"],
		"git":                     filepath.Join(factOnlyDirectory, "git"),
	}

	registry := []GateSpec{
		newGateSpec("go", 1, NetworkNone, "go", "version"),
		newGateSpec("format", 1, NetworkNone, "gofmt", "-l", "."),
		newGateSpec("schema", 1, NetworkNone, "repopass-source-qualify", "validate-schema-json"),
		newGateSpec("release", 1, NetworkGoModules, "pwsh", "build.ps1"),
	}
	windowsNetworkNoneToolPath := controllerRuntimeNetworkNoneToolPath(registry, required)
	hostToolPath := controllerRuntimeToolPath(all)
	for logicalName, application := range required {
		if logicalName != "pwsh" &&
			!controllerRuntimeToolPathContainsApplication(windowsNetworkNoneToolPath, application) {
			t.Fatalf("Windows NetworkNone PATH omitted required application %q", logicalName)
		}
		if !controllerRuntimeToolPathContainsApplication(hostToolPath, application) {
			t.Fatalf("host PATH omitted required application %q", logicalName)
		}
	}
	if controllerRuntimeToolPathContainsApplication(windowsNetworkNoneToolPath, all["git"]) {
		t.Fatal("Windows NetworkNone PATH contains the fact-only Git directory")
	}
	if controllerRuntimeToolPathContainsApplication(windowsNetworkNoneToolPath, required["pwsh"]) {
		t.Fatal("Windows NetworkNone PATH contains the host-only release application directory")
	}
	if !controllerRuntimeToolPathContainsApplication(hostToolPath, all["git"]) {
		t.Fatal("host PATH omitted the fact-only Git directory")
	}
	if got := len(filepath.SplitList(windowsNetworkNoneToolPath)); got != 2 {
		t.Fatalf("Windows NetworkNone PATH directory count = %d, want deduplicated 2", got)
	}
}

func TestControllerRuntimeNetworkNoneToolPathRejectsAnyGitCandidate(t *testing.T) {
	directory := t.TempDir()
	toolPath := controllerRuntimeToolPath(map[string]string{
		"go": filepath.Join(directory, trustedRuntimeTestToolName()),
	})
	contains, err := controllerRuntimeToolPathContainsGit(toolPath)
	if err != nil || contains {
		t.Fatalf("empty tool directory Git scan = (%t, %v), want (false, nil)", contains, err)
	}
	for _, name := range []string{"git", "GIT.EXE", "git.custom-extension"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, []byte("not executable\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(path) })
			contains, err := controllerRuntimeToolPathContainsGit(toolPath)
			if err != nil || !contains {
				t.Fatalf("Git candidate %q scan = (%t, %v), want (true, nil)", name, contains, err)
			}
		})
	}
}

func writeTrustedRuntimeTestTool(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("trusted-runtime-tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func trustedRuntimeTestToolName() string {
	if runtime.GOOS == "windows" {
		return "tool.exe"
	}
	return "tool"
}

func requireTrustedRuntimePathError(t *testing.T, repository, path string) {
	t.Helper()
	resolved, err := trustedControllerRuntimePath(repository, path)
	if !errors.Is(err, errGateInvalidInput) || resolved != "" {
		t.Fatalf("trusted path = (%q, %v), want SOURCE_QUAL_INVALID_INPUT", resolved, err)
	}
}
