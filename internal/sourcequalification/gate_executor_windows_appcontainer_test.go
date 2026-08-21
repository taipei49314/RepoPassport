//go:build windows

package sourcequalification

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/qualificationfixture"
	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const windowsAppContainerBootstrapHelperEnvironment = "REPOPASS_WINDOWS_APPCONTAINER_BOOTSTRAP_HELPER"

func TestWindowsExecutableTreeIncludesGoRoot(t *testing.T) {
	t.Parallel()
	application := `C:\hostedtoolcache\windows\go\1.26.6\x64\bin\go.exe`
	tree := windowsExecutableTree(application)
	want := []string{
		application,
		`C:\hostedtoolcache\windows\go\1.26.6\x64\bin`,
		`C:\hostedtoolcache\windows\go\1.26.6\x64`,
		`C:\hostedtoolcache\windows\go\1.26.6\x64\pkg\tool`,
		`C:\hostedtoolcache\windows\go\1.26.6\x64\pkg`,
		`C:\hostedtoolcache\windows\go\1.26.6\x64\src`,
		`C:\hostedtoolcache\windows\go\1.26.6\x64\lib`,
	}
	for _, path := range want {
		found := false
		for _, got := range tree {
			if filepath.Clean(got) == filepath.Clean(path) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("windowsExecutableTree(%q) = %q, missing %q", application, tree, path)
		}
	}
}

func TestWindowsNewAppContainerNameFormat(t *testing.T) {
	t.Parallel()
	name, err := windowsNewAppContainerName()
	if err != nil {
		t.Fatal(err)
	}
	if len(name) < 12 || len(name) > 64 || name[:12] != "RepoPass.sq." {
		t.Fatalf("app container name = %q", name)
	}
	for _, r := range name {
		if r != '.' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			t.Fatalf("app container name %q has invalid rune %q", name, r)
		}
	}
}

func TestWindowsGateEnvironmentBlockIncludesSystemRootAndTerminator(t *testing.T) {
	t.Parallel()
	block, ok := windowsGateEnvironmentBlock([]string{
		"PATH=C:\\go\\bin",
		"SYSTEMROOT=C:\\Windows",
		"GOFLAGS=",
	})
	if !ok {
		t.Fatal("environment block was rejected")
	}
	decoded := windowsDecodeEnvironmentBlock(block)
	if decoded["SystemRoot"] != `C:\Windows` || decoded["SystemDrive"] != "C:" ||
		decoded["SYSTEMROOT"] != `C:\Windows` || decoded["GOFLAGS"] != "" {
		t.Fatalf("environment block = %#v", decoded)
	}
	if decoded["LOCALAPPDATA"] == "" && os.Getenv("LOCALAPPDATA") != "" {
		t.Fatal("AppContainer environment omitted host LOCALAPPDATA")
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("environment block is not double-NUL terminated: %v", block[max(0, len(block)-4):])
	}
}

func windowsDecodeEnvironmentBlock(block []uint16) map[string]string {
	result := make(map[string]string)
	start := 0
	for i, unit := range block {
		if unit != 0 {
			continue
		}
		if i == start {
			break
		}
		entry := string(utf16.Decode(block[start:i]))
		key, value, _ := strings.Cut(entry, "=")
		result[key] = value
		start = i + 1
	}
	return result
}

func TestWindowsAppContainerAncestorPathsIncludeVolumeRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	leaf := filepath.Join(dir, "bin", "repopass-source-qualify.exe")
	ancestors := windowsAppContainerAncestorPaths(leaf)
	if len(ancestors) == 0 {
		t.Fatal("AppContainer ancestor chain is empty")
	}
	foundVolume := false
	foundParent := false
	for _, ancestor := range ancestors {
		if filepath.Dir(ancestor) == ancestor {
			foundVolume = true
		}
		if filepath.Clean(ancestor) == filepath.Clean(dir) {
			foundParent = true
		}
	}
	if !foundVolume || !foundParent {
		t.Fatalf("windowsAppContainerAncestorPaths(%q) = %q, want volume root and %q", leaf, ancestors, dir)
	}
}

func TestWindowsAppContainerAncestorGrantSkipsHostProfileRoot(t *testing.T) {
	t.Parallel()
	if !windowsAppContainerAncestorGrantForbidden(`C:\Users`) ||
		!windowsAppContainerAncestorGrantForbidden(`C:\Users\runner`) ||
		!windowsAppContainerAncestorGrantForbidden(`C:\Program Files`) ||
		windowsAppContainerAncestorGrantForbidden(`C:\hostedtoolcache`) ||
		windowsAppContainerAncestorGrantForbidden(`D:\a`) {
		t.Fatal("ancestor grant skip list must exclude Users/Program Files trees and keep CI volume paths")
	}
	if os.Getenv("SystemDrive") == "C:" && !windowsAppContainerAncestorGrantForbidden(`C:\`) {
		t.Fatal("volume roots must not receive AppContainer ancestor grants")
	}
	if !windowsAppContainerAncestorGrantForbidden(`D:\`) {
		t.Fatal("volume roots must not receive AppContainer ancestor grants")
	}
}

func TestWindowsOpenAppContainerGrantPathRejectsVolumeRootBeforeOpen(t *testing.T) {
	for _, root := range []string{`C:\`, `D:\`} {
		for _, open := range []func(string) (*os.File, windows.ByHandleFileInformation, error){
			windowsOpenAppContainerGrantPath,
			windowsOpenAppContainerAncestorGrantPath,
		} {
			file, _, err := open(root)
			if file != nil {
				_ = file.Close()
			}
			if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("grant-path open for volume root %q = file:%v err:%v, want access denied", root, file != nil, err)
			}
		}
	}
}

func TestWindowsAppContainerBootstrapRestoresTempAndKeepsContainment(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	fixtureRoot := requireSchemaJSONAppContainerFixtureRoot(t)
	dir := filepath.Join(fixtureRoot, "repo")
	toolRoot := filepath.Join(fixtureRoot, "tools")
	privateBoundary, cleanupPrivateBoundary, _, err := createPrivateQualificationStaging(
		filepath.Dir(fixtureRoot), "private-parent-",
	)
	if err != nil || cleanupPrivateBoundary == nil {
		t.Fatalf("create private AppContainer ancestor: %v", err)
	}
	privateBoundaryDACL := windowsPathDACLState(t, privateBoundary)
	t.Cleanup(func() {
		if err := cleanupPrivateBoundary(); err != nil {
			t.Errorf("cleanup private AppContainer ancestor: %v", err)
		}
	})
	privateRoot, cleanupPrivateRoot, _, err := createPrivateQualificationStaging(
		privateBoundary, "private-",
	)
	if err != nil || cleanupPrivateRoot == nil {
		t.Fatalf("create private AppContainer fixture root: %v", err)
	}
	t.Cleanup(func() {
		if err := cleanupPrivateRoot(); err != nil {
			t.Errorf("cleanup private AppContainer fixture root: %v", err)
		}
	})
	directories, err := createControllerRuntimeDirectories(privateRoot)
	if err != nil {
		t.Fatalf("create private AppContainer runtime directories: %v", err)
	}
	home := directories["home"]
	gocache := directories["go-cache"]
	gomodcache := directories["go-mod-cache"]
	tmpdir := directories["tmp"]
	for _, path := range []string{dir, toolRoot, filepath.Join(home, "go"), filepath.Join(home, "bin")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(home, "go"), filepath.Join(home, "bin")} {
		if err := securePrivatePackagePath(path, true); err != nil {
			t.Fatalf("secure private AppContainer fixture %q: %v", filepath.Base(path), err)
		}
	}
	sentinel := filepath.Join(privateRoot, "private-log-sentinel")
	if err := os.WriteFile(sentinel, []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	moduleSentinel := filepath.Join(gomodcache, "module-sentinel.txt")
	if err := os.WriteFile(moduleSentinel, []byte("module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateRootDACL := windowsPathDACLString(t, privateRoot)
	repositoryDACL := windowsPathDACLState(t, dir)
	moduleCacheDACL := windowsPathDACLState(t, gomodcache)
	moduleSentinelDACL := windowsPathDACLState(t, moduleSentinel)
	containment := buildSourceQualifyApplicationAt(t, filepath.Join(toolRoot, "repopass-source-qualify.exe"))
	helper := filepath.Join(dir, "sourcequalification-bootstrap-helper.test.exe")
	copyWindowsAppContainerTestExecutable(t, helper)

	environment := windowsNetworkNoneGoVersionEnvironment(t, containment, privateRoot)
	for index, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "HOME", "USERPROFILE":
			environment[index] = name + "=" + home
		case "GOCACHE":
			environment[index] = name + "=" + gocache
		case "GOMODCACHE":
			environment[index] = name + "=" + gomodcache
		case "GOPATH":
			environment[index] = name + "=" + filepath.Join(home, "go")
		case "GOBIN":
			environment[index] = name + "=" + filepath.Join(home, "bin")
		case "GOTMPDIR", "TMPDIR", "TMP", "TEMP":
			environment[index] = name + "=" + tmpdir
		}
	}
	environment = append(environment,
		windowsAppContainerBootstrapHelperEnvironment+"=1",
		"REPOPASS_WINDOWS_APPCONTAINER_PRIVATE_ROOT="+privateRoot,
		"REPOPASS_WINDOWS_APPCONTAINER_MODULE_CACHE="+gomodcache,
		"REPOPASS_WINDOWS_APPCONTAINER_MODULE_SENTINEL="+moduleSentinel,
		"REPOPASS_WINDOWS_APPCONTAINER_PRIVATE_SENTINEL="+sentinel,
	)
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application:            helper,
		ContainmentApplication: containment,
		Args:                   []string{"-test.run=^TestWindowsAppContainerBootstrapHelperProcess$"},
		Dir:                    dir,
		Env:                    environment,
		Network:                NetworkNone,
		Timeout:                30 * time.Second,
		StdoutLimit:            4096,
		StderrLimit:            4096,
	})
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed ||
		string(result.Stdout) != "BOOTSTRAP_OK\n" || len(result.Stderr) != 0 {
		exitCode := int64(-1)
		if result.ExitCode != nil {
			exitCode = *result.ExitCode
		}
		t.Fatalf("AppContainer bootstrap exit=%d result=%#v err=%v stdout=%q stderr=%q",
			exitCode, result, err, result.Stdout, result.Stderr)
	}
	if got := windowsPathDACLString(t, privateRoot); got != privateRootDACL {
		t.Fatalf("private root DACL was not restored: got %q, want %q", got, privateRootDACL)
	}
	if got := windowsPathDACLState(t, privateBoundary); !sameWindowsTestDACLState(got, privateBoundaryDACL) {
		t.Fatal("private ancestor DACL/control was not restored exactly")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "private\n" {
		t.Fatalf("private sibling changed: bytes=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(moduleSentinel); err != nil || string(got) != "module\n" {
		t.Fatalf("module cache sentinel changed: bytes=%q err=%v", got, err)
	}
	if got := windowsPathDACLState(t, dir); !sameWindowsTestDACLState(got, repositoryDACL) {
		t.Fatal("repository DACL/control was not restored exactly")
	}
	if got := windowsPathDACLState(t, gomodcache); !sameWindowsTestDACLState(got, moduleCacheDACL) {
		t.Fatal("module cache DACL/control was not restored exactly")
	}
	if got := windowsPathDACLState(t, moduleSentinel); !sameWindowsTestDACLState(got, moduleSentinelDACL) {
		t.Fatal("module cache entry DACL/control was not restored exactly")
	}
	entries, err := os.ReadDir(privateRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), windowsAppContainerWorkspacePrefix) {
			t.Fatalf("writable AppContainer workspace remained after release: %q", entry.Name())
		}
	}
}

func TestWindowsAppContainerBootstrapHelperProcess(t *testing.T) {
	if os.Getenv(windowsAppContainerBootstrapHelperEnvironment) != "1" {
		return
	}
	privateRoot := os.Getenv("REPOPASS_WINDOWS_APPCONTAINER_PRIVATE_ROOT")
	moduleCache := os.Getenv("REPOPASS_WINDOWS_APPCONTAINER_MODULE_CACHE")
	moduleSentinel := os.Getenv("REPOPASS_WINDOWS_APPCONTAINER_MODULE_SENTINEL")
	contained, err := windowssecurity.CurrentProcessIsAppContainer()
	if err != nil || !contained {
		os.Exit(91)
	}
	principal, err := windowssecurity.CurrentAppContainerPrincipal()
	if err != nil || !strings.HasPrefix(principal, "S-1-15-2-") {
		os.Exit(92)
	}
	workspace := os.Getenv("HOME")
	if privateRoot == "" || moduleCache == "" || moduleSentinel == "" || workspace == "" ||
		filepath.Dir(workspace) != privateRoot ||
		!strings.HasPrefix(filepath.Base(workspace), windowsAppContainerWorkspacePrefix) ||
		os.Getenv("GOMODCACHE") != moduleCache || filepath.Clean(os.TempDir()) != filepath.Clean(workspace) {
		os.Exit(93)
	}
	for _, name := range windowsAppContainerWritableEnvironmentKeys {
		if os.Getenv(name) != workspace {
			os.Exit(101)
		}
	}
	sentinel := os.Getenv("REPOPASS_WINDOWS_APPCONTAINER_PRIVATE_SENTINEL")
	if sentinel == "" {
		os.Exit(94)
	}
	if _, err := os.ReadFile(sentinel); err == nil {
		os.Exit(95)
	}
	if err := os.WriteFile(sentinel, []byte("changed\n"), 0o600); err == nil {
		os.Exit(96)
	}
	moduleBytes, err := os.ReadFile(moduleSentinel)
	if err != nil || string(moduleBytes) != "module\n" {
		os.Exit(97)
	}
	if err := os.WriteFile(filepath.Join(moduleCache, "new.txt"), []byte("changed\n"), 0o600); err == nil {
		os.Exit(98)
	}
	if err := os.WriteFile(moduleSentinel, []byte("changed\n"), 0o600); err == nil {
		os.Exit(99)
	}
	if err := os.Rename(moduleSentinel, filepath.Join(moduleCache, "renamed.txt")); err == nil {
		os.Exit(100)
	}
	if err := os.Remove(moduleSentinel); err == nil {
		os.Exit(102)
	}
	if err := os.WriteFile(filepath.Join(".", "appcontainer-write.txt"), []byte("changed\n"), 0o600); err == nil {
		os.Exit(103)
	}
	if err := os.Remove(workspace); err == nil {
		os.Exit(104)
	}
	workspacePointer, err := windows.UTF16PtrFromString(workspace)
	if err != nil {
		os.Exit(105)
	}
	if handle, openErr := windows.CreateFile(
		workspacePointer,
		windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	); openErr == nil {
		_ = windows.CloseHandle(handle)
		os.Exit(106)
	}
	filePath := filepath.Join(workspace, "runtime.txt")
	if err := os.WriteFile(filePath, []byte("one\n"), 0o600); err != nil {
		os.Exit(107)
	}
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		os.Exit(108)
	}
	if _, err := file.WriteAt([]byte("two"), 0); err != nil || file.Close() != nil {
		os.Exit(109)
	}
	renamed := filepath.Join(workspace, "renamed.txt")
	if err := os.Rename(filePath, renamed); err != nil {
		os.Exit(110)
	}
	if got, err := os.ReadFile(renamed); err != nil || string(got) != "two\n" {
		os.Exit(111)
	}
	nested := filepath.Join(workspace, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil ||
		os.WriteFile(filepath.Join(nested, "value.txt"), []byte("nested\n"), 0o600) != nil {
		os.Exit(112)
	}
	if !strings.Contains(windowsPathDACLString(t, renamed), principal) {
		os.Exit(113)
	}
	if err := os.RemoveAll(nested); err != nil || os.Remove(renamed) != nil {
		os.Exit(114)
	}
	if _, err := exec.LookPath("git"); err == nil {
		os.Exit(115)
	}
	if _, err := resolveTrustedGitExecutable(privateRoot); err == nil {
		os.Exit(116)
	}
	_, _ = os.Stdout.WriteString("BOOTSTRAP_OK\n")
	os.Exit(0)
}

func windowsPathDACLString(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("read Windows path DACL: %v", err)
	}
	value := descriptor.String()
	if value == "" {
		t.Fatal("Windows path DACL string is unavailable")
	}
	return value
}

func TestWindowsAppContainerBootstrapMarkerIsPrivate(t *testing.T) {
	contained, err := windowssecurity.CurrentProcessIsAppContainer()
	if err != nil {
		t.Fatal(err)
	}
	exitCode, handled := RunWindowsAppContainerGateBootstrap(
		[]string{windowsAppContainerBootstrapArgv0},
		strings.NewReader(""),
		io.Discard,
		io.Discard,
	)
	if contained {
		if !handled || exitCode != windowsAppContainerBootstrapError {
			t.Fatalf("contained malformed bootstrap = %d/%v", exitCode, handled)
		}
		return
	}
	if handled || exitCode != 0 {
		t.Fatalf("host bootstrap marker bypassed public command handling: %d/%v", exitCode, handled)
	}
}

func TestWindowsAppContainerBootstrapPATHExcludesGitFailsClosed(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("PATH", directory)
	t.Setenv("PATHEXT", ".EXE")
	if !windowsAppContainerBootstrapPATHExcludesGit() {
		t.Fatal("empty AppContainer bootstrap PATH was rejected")
	}
	if err := os.WriteFile(filepath.Join(directory, "git.exe"), []byte("not an executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if windowsAppContainerBootstrapPATHExcludesGit() {
		t.Fatal("AppContainer bootstrap PATH accepted git.exe")
	}
}

func TestOSGateExecutorIsolatesSchemaJSONWithNetworkNone(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	privateRoot := t.TempDir()
	application := requireBuiltSourceQualifyApplication(t)
	goApplication := requireTrustedWindowsGoApplication(t)
	writeSchemaJSONFixture(t, dir, "schemas/example.schema.json", []byte(`{"type":"object"}`))
	writeSchemaJSONFixture(t, dir, "testdata/fixtures/example/fixture.json", []byte(`{"status":"healthy"}`))

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application:            application,
		ContainmentApplication: application,
		Args:                   []string{"validate-schema-json", "--root", "."},
		Dir:                    dir,
		Env:                    windowsNetworkNoneGoVersionEnvironment(t, goApplication, privateRoot),
		Network:                NetworkNone,
		Timeout:                30 * time.Second,
		StdoutLimit:            4096,
		StderrLimit:            4096,
	})
	if time.Since(started) > 20*time.Second {
		t.Fatal("NetworkNone schema JSON AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("NetworkNone validate-schema-json result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesSchemaJSONThroughJunctionAncestor(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	parent := requireSchemaJSONAppContainerFixtureRoot(t)
	real := filepath.Join(parent, "real")
	writeSchemaJSONFixture(t, real, "schemas/example.schema.json", []byte(`{"type":"object"}`))
	writeSchemaJSONFixture(t, real, "testdata/fixtures/example/fixture.json", []byte(`{"status":"healthy"}`))
	alias := filepath.Join(parent, "junc")
	if !createSchemaJSONDirectoryRedirect(t, alias, parent) {
		t.Skip("directory junction fixture is unavailable")
	}
	dir := filepath.Join(alias, "real")
	if !validGateProcessDirectory(dir) {
		t.Skip("junction spelling is not a valid gate directory")
	}
	application := requireBuiltSourceQualifyApplication(t)
	privateRoot := t.TempDir()

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"validate-schema-json", "--root", "."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(t, requireTrustedWindowsGoApplication(t), privateRoot),
		Network:     NetworkNone,
		Timeout:     30 * time.Second,
		StdoutLimit: 4096,
		StderrLimit: 4096,
	})
	if time.Since(started) > 20*time.Second {
		t.Fatal("junction-ancestor schema JSON AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("junction-ancestor validate-schema-json result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoVetWithNetworkNone(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.invalid/vetprobe\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.go"), []byte("package vetprobe\n\nfunc Ready() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	application := requireTrustedWindowsGoApplication(t)
	privateRoot := t.TempDir()

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"vet", "./..."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot),
		Network:     NetworkNone,
		Timeout:     45 * time.Second,
		StdoutLimit: 4096,
		StderrLimit: 4096,
	})
	if time.Since(started) > 90*time.Second {
		t.Fatal("NetworkNone go vet AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("NetworkNone go vet result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoTestWithNetworkNone(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.invalid/testprobe\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe_test.go"), []byte("package testprobe\n\nimport \"testing\"\n\nfunc TestReady(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	application := requireTrustedWindowsGoApplication(t)
	privateRoot := t.TempDir()

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"test", "-count=1", "."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot),
		Network:     NetworkNone,
		Timeout:     60 * time.Second,
		StdoutLimit: 8192,
		StderrLimit: 8192,
	})
	if time.Since(started) > 90*time.Second {
		t.Fatal("NetworkNone go test AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("NetworkNone go test result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoVetWithFilledModuleCache(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	fixtureRoot := requireSchemaJSONAppContainerFixtureRoot(t)
	dir := filepath.Join(fixtureRoot, "repo")
	privateRoot := filepath.Join(fixtureRoot, "private")
	modcache := filepath.Join(privateRoot, "go-mod-cache")
	gocache := filepath.Join(privateRoot, "go-cache")
	gopath := filepath.Join(privateRoot, "gopath")
	for _, path := range []string{dir, modcache, gocache, gopath} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.invalid/vetmod\n\ngo 1.26\n\nrequire golang.org/x/sys v0.47.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mod.go"), []byte("package vetmod\n\nimport _ \"golang.org/x/sys/cpu\"\n\nfunc Ready() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	application := requireTrustedWindowsGoApplication(t)
	download := exec.Command(application, "mod", "download", "-modcacherw", "all")
	download.Dir = dir
	download.Env = []string{
		"PATH=" + filepath.Dir(application),
		"HOME=" + privateRoot,
		"USERPROFILE=" + privateRoot,
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOENV=off",
		"GOFLAGS=",
		"GOPROXY=https://proxy.golang.org,direct",
		"GOSUMDB=sum.golang.org",
		"GOMODCACHE=" + modcache,
		"GOCACHE=" + gocache,
		"GOPATH=" + gopath,
		"GOTMPDIR=" + privateRoot,
		"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
		"WINDIR=" + os.Getenv("WINDIR"),
	}
	if output, err := download.CombinedOutput(); err != nil {
		t.Skipf("host module download unavailable: %v\n%s", err, output)
	}

	env := windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot)
	for index, item := range env {
		name, _, _ := strings.Cut(item, "=")
		switch strings.ToUpper(name) {
		case "GOMODCACHE":
			env[index] = "GOMODCACHE=" + modcache
		case "GOCACHE":
			env[index] = "GOCACHE=" + gocache
		case "GOPATH":
			env[index] = "GOPATH=" + gopath
		}
	}

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"vet", "./..."},
		Dir:         dir,
		Env:         env,
		Network:     NetworkNone,
		Timeout:     60 * time.Second,
		StdoutLimit: 8192,
		StderrLimit: 8192,
	})
	if time.Since(started) > 90*time.Second {
		t.Fatal("module-cache go vet AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("module-cache go vet result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoVetOfModuleRootWithFilledCache(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path is unavailable")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(moduleRoot, "go.mod")); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("module root %q is missing go.mod", moduleRoot)
		}
		t.Skip("module root is unavailable")
	}
	fixtureRoot := requireSchemaJSONAppContainerFixtureRoot(t)
	src := filepath.Join(fixtureRoot, "module")
	privateRoot := filepath.Join(fixtureRoot, "private")
	modcache := filepath.Join(privateRoot, "go-mod-cache")
	gocache := filepath.Join(privateRoot, "go-cache")
	gopath := filepath.Join(privateRoot, "gopath")
	tmpdir := filepath.Join(privateRoot, "tmp")
	for _, path := range []string{src, privateRoot, modcache, gocache, gopath, tmpdir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	copyGrantableModuleTree(t, moduleRoot, src)
	application := requireTrustedWindowsGoApplication(t)
	download := exec.Command(application, "mod", "download", "-modcacherw", "all")
	download.Dir = src
	download.Env = []string{
		"PATH=" + filepath.Dir(application),
		"HOME=" + privateRoot,
		"USERPROFILE=" + privateRoot,
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOENV=off",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
		"GOPROXY=https://proxy.golang.org,direct",
		"GOSUMDB=sum.golang.org",
		"GOMODCACHE=" + modcache,
		"GOCACHE=" + gocache,
		"GOPATH=" + gopath,
		"GOTMPDIR=" + tmpdir,
		"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
		"WINDIR=" + os.Getenv("WINDIR"),
	}
	if output, err := download.CombinedOutput(); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("host readonly module download unavailable: %v\n%s", err, output)
		}
		t.Skipf("host readonly module download unavailable: %v\n%s", err, output)
	}

	env := windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot)
	for index, item := range env {
		name, _, _ := strings.Cut(item, "=")
		switch strings.ToUpper(name) {
		case "GOMODCACHE":
			env[index] = "GOMODCACHE=" + modcache
		case "GOCACHE":
			env[index] = "GOCACHE=" + gocache
		case "GOPATH":
			env[index] = "GOPATH=" + gopath
		case "GOTMPDIR", "TMPDIR", "TMP", "TEMP":
			env[index] = name + "=" + tmpdir
		}
	}

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"vet", "./..."},
		Dir:         src,
		Env:         env,
		Network:     NetworkNone,
		Timeout:     5 * time.Minute,
		StdoutLimit: 1 << 16,
		StderrLimit: 1 << 16,
	})
	if time.Since(started) > 4*time.Minute {
		t.Fatal("module-root go vet AppContainer grant or vet walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("module-root go vet result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestWindowsNetworkNoneAccessPathsOmitSystemRoots(t *testing.T) {
	t.Parallel()
	application := `C:\hostedtoolcache\windows\go\1.26.6\x64\bin\go.exe`
	dir := t.TempDir()
	systemRoot := `C:\Windows`
	required, moduleCache, readable := windowsNetworkNoneAccessPaths(gateProcessRequest{
		Application: application,
		Dir:         dir,
		Env: []string{
			"PATH=" + filepath.Dir(application),
			"HOME=" + dir,
			"USERPROFILE=" + dir,
			"TMPDIR=" + dir,
			"GOCACHE=" + dir,
			"GOMODCACHE=" + dir,
			"GOTMPDIR=" + dir,
			"SYSTEMROOT=" + systemRoot,
			"WINDIR=" + systemRoot,
		},
	})
	for _, path := range concatWindowsPaths(required, moduleCache, readable) {
		if windowsAppContainerTreeMutationForbidden(path) {
			t.Fatalf("NetworkNone grant list included system path %q", path)
		}
	}
}

func TestWindowsNetworkNoneAccessPathsIncludeContainmentApplication(t *testing.T) {
	dir := t.TempDir()
	application := filepath.Join(dir, "go.exe")
	containment := filepath.Join(dir, "repopass-source-qualify.exe")
	for _, path := range []string{application, containment} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	required, _, readable := windowsNetworkNoneAccessPaths(gateProcessRequest{
		Application:            application,
		ContainmentApplication: containment,
		Dir:                    dir,
	})
	for _, want := range []string{application, containment} {
		if !containsWindowsPath(required, want) || containsWindowsPath(readable, want) {
			t.Fatalf("containment access paths required=%q readable=%q, want one required grant for %q", required, readable, want)
		}
	}
}

func TestWindowsNetworkNoneAccessPathsIncludeReleaseFixtureTree(t *testing.T) {
	root := t.TempDir()
	fixtureRoot := filepath.Join(root, "release-fixture")
	if err := os.Mkdir(fixtureRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, readable := windowsNetworkNoneAccessPaths(gateProcessRequest{
		Env: []string{qualificationfixture.ImportRootEnv + "=" + fixtureRoot},
	})
	found := false
	for _, path := range readable {
		if strings.EqualFold(path, fixtureRoot) {
			found = true
		}
	}
	if !found {
		t.Fatalf("release fixture root %q missing from read-only grant paths: %q", fixtureRoot, readable)
	}
}

func newWindowsAppContainerTestSession(t *testing.T, sid *windows.SID) *windowsAppContainerSession {
	t.Helper()
	session := &windowsAppContainerSession{sid: sid}
	principal, err := windowssecurity.CurrentAppContainerPrincipal()
	if err != nil {
		t.Fatalf("read current AppContainer principal: %v", err)
	}
	if principal == "" {
		return session
	}
	session.baselinePackageSID, err = windows.StringToSid(principal)
	if err != nil || !validWindowsAppContainerPackageSID(session.baselinePackageSID) {
		t.Fatalf("parse current AppContainer principal %q: %v", principal, err)
	}
	return session
}

func TestWindowsAppContainerGrantRejectsJunctionBeforeMutation(t *testing.T) {
	parent := t.TempDir()
	target := t.TempDir()
	junction := filepath.Join(parent, "redirect")
	if !createSchemaJSONDirectoryRedirect(t, junction, target) {
		t.Skip("directory junction fixture is unavailable")
	}
	parentBefore := windowsPathDACLState(t, parent)
	before := windowsPathDACLString(t, target)
	session := newWindowsAppContainerTestSession(t, testWindowsAppContainerSID(t))
	if err := session.grantPath(parent, windows.GENERIC_ALL, true); err == nil {
		t.Fatal("tree containing a junction was accepted")
	}
	if err := session.release(); err != nil {
		t.Fatalf("restore rejected junction grant cleanup: %v", err)
	}
	if after := windowsPathDACLString(t, target); after != before {
		t.Fatalf("junction target DACL changed: got %q, want %q", after, before)
	}
	if after := windowsPathDACLState(t, parent); !sameWindowsTestDACLState(after, parentBefore) {
		t.Fatal("junction rejection changed its parent DACL")
	}
}

func TestWindowsAppContainerDACLJournalRestoresTreeByHandleIdentity(t *testing.T) {
	requireHostFilesystem(t)
	root := t.TempDir()
	directory := filepath.Join(root, "existing")
	originalFile := filepath.Join(directory, "source.txt")
	renamedFile := filepath.Join(directory, "renamed.txt")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(originalFile, []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baselines := map[string]windowsTestDACLState{
		root:         windowsPathDACLState(t, root),
		directory:    windowsPathDACLState(t, directory),
		originalFile: windowsPathDACLState(t, originalFile),
	}
	identities := map[string]windowsAppContainerObjectIdentity{
		root:         windowsPathObjectIdentity(t, root),
		directory:    windowsPathObjectIdentity(t, directory),
		originalFile: windowsPathObjectIdentity(t, originalFile),
	}
	sid := testWindowsAppContainerSID(t)
	session := newWindowsAppContainerTestSession(t, sid)
	if err := session.grantPath(root, windows.GENERIC_READ|windows.GENERIC_EXECUTE, true); err != nil {
		t.Fatalf("grant read-only tree: %v", err)
	}
	if len(session.daclRestores) != len(baselines) {
		t.Fatalf("journal entries = %d, want %d", len(session.daclRestores), len(baselines))
	}
	wantJournalOrder := []windowsAppContainerObjectIdentity{
		identities[originalFile], identities[directory], identities[root],
	}
	for index, want := range wantJournalOrder {
		if got := session.daclRestores[index].identity; got != want {
			t.Fatalf("journal identity %d = %#v, want postorder %#v", index, got, want)
		}
	}
	for path := range baselines {
		if !strings.Contains(windowsPathDACLString(t, path), sid.String()) {
			t.Fatalf("journaled path %q omitted the package SID", path)
		}
	}

	newChild := filepath.Join(root, "new-child.txt")
	if err := os.WriteFile(newChild, []byte("new\n"), 0o600); err != nil {
		t.Fatalf("create child while journal handles are retained: %v", err)
	}
	if strings.Contains(windowsPathDACLString(t, newChild), sid.String()) {
		t.Fatal("NO_INHERITANCE grant leaked the package SID into a new child")
	}
	if err := os.Rename(originalFile, renamedFile); err != nil {
		t.Fatalf("rename while journal identity is retained: %v", err)
	}
	if _, err := os.Lstat(originalFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("renamed source path still resolves: %v", err)
	}
	if got := windowsPathObjectIdentity(t, renamedFile); got != identities[originalFile] {
		t.Fatalf("renamed file identity = %#v, want retained %#v", got, identities[originalFile])
	}
	if err := session.release(); err != nil {
		t.Fatalf("restore journal: %v", err)
	}
	if got := windowsPathDACLState(t, root); !sameWindowsTestDACLState(got, baselines[root]) {
		t.Fatal("root DACL/control was not restored exactly")
	}
	if got := windowsPathDACLState(t, directory); !sameWindowsTestDACLState(got, baselines[directory]) {
		t.Fatal("directory DACL/control was not restored exactly")
	}
	if got := windowsPathDACLState(t, renamedFile); !sameWindowsTestDACLState(got, baselines[originalFile]) {
		t.Fatal("renamed file DACL/control was not restored through its retained identity")
	}
	for _, path := range []string{root, directory, renamedFile, newChild} {
		if strings.Contains(windowsPathDACLString(t, path), sid.String()) {
			t.Fatalf("release left package SID residue on %q", path)
		}
	}
}

func TestWindowsAppContainerDACLPackageBaselineRejectsOrphans(t *testing.T) {
	foreign := testWindowsAppContainerSID(t)
	other, err := windows.StringToSid(
		"S-1-15-2-27011983-37021984-47031985-57041986-67051987-77061988-87071989",
	)
	if err != nil || other == nil || !other.IsValid() {
		t.Fatalf("create second package SID fixture: %v", err)
	}
	allApplications, err := windows.StringToSid("S-1-15-2-1")
	if err != nil || allApplications == nil || !allApplications.IsValid() {
		t.Fatalf("create broad AppContainer SID fixture: %v", err)
	}
	allRestrictedApplications, err := windows.StringToSid("S-1-15-2-2")
	if err != nil || allRestrictedApplications == nil || !allRestrictedApplications.IsValid() {
		t.Fatalf("create restricted AppContainer SID fixture: %v", err)
	}
	unknownPackageNamespace, err := windows.StringToSid("S-1-15-2-99")
	if err != nil || unknownPackageNamespace == nil || !unknownPackageNamespace.IsValid() {
		t.Fatalf("create unknown AppContainer SID fixture: %v", err)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatalf("read current user SID: %v", err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	for _, sid := range []*windows.SID{
		foreign, other, allApplications, allRestrictedApplications, unknownPackageNamespace, current.User.Sid,
	} {
		pinner.Pin(sid)
	}
	build := func(packageSID *windows.SID) *windows.ACL {
		t.Helper()
		acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
			windowsAppContainerAccessEntry(
				current.User.Sid, windows.GENERIC_ALL, uint32(windows.NO_INHERITANCE),
			),
			windowsAppContainerAccessEntry(
				packageSID,
				windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE,
				uint32(windows.NO_INHERITANCE),
			),
		}, nil)
		if err != nil || acl == nil {
			t.Fatalf("create package baseline ACL: %v", err)
		}
		return acl
	}
	foreignACL := build(foreign)
	if err := windowsValidateAppContainerDACLPackageBaseline(foreignACL, nil); !errors.Is(
		err, errWindowsAppContainerDACLOrphan,
	) {
		t.Fatalf("host baseline accepted a package SID: %v", err)
	}
	if err := windowsValidateAppContainerDACLPackageBaseline(foreignACL, other); !errors.Is(
		err, errWindowsAppContainerDACLOrphan,
	) {
		t.Fatalf("nested baseline accepted a foreign package SID: %v", err)
	}
	if err := windowsValidateAppContainerDACLPackageBaseline(foreignACL, foreign); err != nil {
		t.Fatalf("nested baseline rejected its exact current token SID: %v", err)
	}
	if err := windowsValidateAppContainerDACLPackageBaseline(foreignACL, other, foreign); err != nil {
		t.Fatalf("session baseline rejected its exact active package SID: %v", err)
	}
	if err := windowsValidateAppContainerDACLPackageBaseline(
		build(unknownPackageNamespace), nil,
	); !errors.Is(err, errWindowsAppContainerDACLOrphan) {
		t.Fatalf("baseline accepted an unknown package-namespace SID: %v", err)
	}
	for _, wellKnown := range []*windows.SID{allApplications, allRestrictedApplications} {
		if err := windowsValidateAppContainerDACLPackageBaseline(build(wellKnown), nil); err != nil {
			t.Fatalf("baseline rejected well-known AppContainer read principal %s: %v", wellKnown, err)
		}
		for _, profile := range []struct {
			mask  windows.ACCESS_MASK
			flags uint32
		}{
			{windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE, uint32(windows.INHERITED_ACE)},
			{
				windows.GENERIC_READ | windows.GENERIC_EXECUTE,
				uint32(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.INHERIT_ONLY_ACE),
			},
			{
				windows.GENERIC_READ | windows.GENERIC_EXECUTE,
				uint32(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE |
					windows.INHERIT_ONLY_ACE | windows.INHERITED_ACE),
			},
		} {
			readACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
				windowsAppContainerAccessEntry(wellKnown, profile.mask, profile.flags),
			}, nil)
			if err != nil {
				t.Fatalf("create canonical broad read ACL: %v", err)
			}
			if err := windowsValidateAppContainerDACLPackageBaseline(readACL, nil); err != nil {
				t.Fatalf("baseline rejected canonical broad read principal %s mask=%#x flags=%#x: %v",
					wellKnown, profile.mask, profile.flags, err)
			}
		}
		writeACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
			windowsAppContainerAccessEntry(
				wellKnown,
				windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE|windows.FILE_GENERIC_WRITE,
				uint32(windows.NO_INHERITANCE),
			),
		}, nil)
		if err != nil {
			t.Fatalf("create broad write ACL: %v", err)
		}
		if err := windowsValidateAppContainerDACLPackageBaseline(writeACL, nil); !errors.Is(
			err, errWindowsAppContainerDACLOrphan,
		) {
			t.Fatalf("baseline accepted broad AppContainer write principal %s: %v", wellKnown, err)
		}
		if err := windowsValidateAppContainerDACLPackageBaselineForTarget(
			writeACL, windowsAppContainerDACLNullDevice, nil,
		); err != nil {
			t.Fatalf("null-device baseline rejected exact broad read/write principal %s: %v", wellKnown, err)
		}
		deny := windowsAppContainerAccessEntry(
			wellKnown,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE,
			uint32(windows.NO_INHERITANCE),
		)
		deny.AccessMode = windows.DENY_ACCESS
		denyACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{deny}, nil)
		if err != nil {
			t.Fatalf("create broad deny ACL: %v", err)
		}
		if err := windowsValidateAppContainerDACLPackageBaseline(denyACL, nil); !errors.Is(
			err, errWindowsAppContainerDACLOrphan,
		) {
			t.Fatalf("baseline accepted broad AppContainer deny principal %s: %v", wellKnown, err)
		}
	}
	objectACL := build(allApplications)
	var objectACE *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(objectACL, 1, &objectACE); err != nil || objectACE == nil {
		t.Fatalf("read broad object ACE fixture: %v", err)
	}
	objectACE.Header.AceType = 5 // ACCESS_ALLOWED_OBJECT_ACE_TYPE
	if err := windowsValidateAppContainerDACLPackageBaseline(objectACL, nil); !errors.Is(
		err, errWindowsAppContainerDACLOrphan,
	) {
		t.Fatalf("baseline accepted a broad object ACE: %v", err)
	}
	invalidInheritanceACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAppContainerAccessEntry(
			allApplications,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE,
			uint32(windows.INHERIT_ONLY_ACE),
		),
	}, nil)
	if err != nil {
		t.Fatalf("create invalid broad inheritance ACL: %v", err)
	}
	if err := windowsValidateAppContainerDACLPackageBaseline(invalidInheritanceACL, nil); !errors.Is(
		err, errWindowsAppContainerDACLOrphan,
	) {
		t.Fatalf("baseline accepted invalid broad inheritance flags: %v", err)
	}
	for name, invalid := range map[string]windows.EXPLICIT_ACCESS{
		"read subset": windowsAppContainerAccessEntry(
			allApplications, windows.FILE_READ_DATA, uint32(windows.NO_INHERITANCE),
		),
		"object-inherit only": windowsAppContainerAccessEntry(
			allApplications,
			windows.GENERIC_READ|windows.GENERIC_EXECUTE,
			uint32(windows.OBJECT_INHERIT_ACE),
		),
	} {
		acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{invalid}, nil)
		if err != nil {
			t.Fatalf("create invalid broad %s ACL: %v", name, err)
		}
		if err := windowsValidateAppContainerDACLPackageBaseline(acl, nil); !errors.Is(
			err, errWindowsAppContainerDACLOrphan,
		) {
			t.Fatalf("baseline accepted invalid broad %s profile: %v", name, err)
		}
	}
}

func TestWindowsCanonicalAppContainerSIDParts(t *testing.T) {
	t.Parallel()
	valid := map[string][]uint32{
		"S-1-15-2-1":                      {2, 1},
		"S-1-15-3-4":                      {3, 4},
		"S-1-15-2-1-2-3-4-5-6-4294967295": {2, 1, 2, 3, 4, 5, 6, 4294967295},
	}
	for value, want := range valid {
		got, ok := windowsCanonicalAppContainerSIDParts(value)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("parse %q = %v, %v; want %v, true", value, got, ok, want)
		}
	}
	for _, value := range []string{
		"", "S-1-15", "s-1-15-2-1", "S-2-15-2-1", "S-1-16-2-1",
		"S-1-15-02-1", "S-1-15-2-01", "S-1-15-2-+1", "S-1-15-2--1",
		"S-1-15-2-4294967296", "S-1-15-2-one", "S-1-15-2-1-",
	} {
		if got, ok := windowsCanonicalAppContainerSIDParts(value); ok || got != nil {
			t.Errorf("parse %q = %v, %v; want nil, false", value, got, ok)
		}
	}
}

func FuzzWindowsCanonicalAppContainerSIDParts(f *testing.F) {
	for _, value := range []string{
		"S-1-15-2-1",
		"S-1-15-2-1-2-3-4-5-6-7",
		"S-1-15-2-4294967296",
		"S-1-15-02-1",
		"not-a-sid",
	} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		parts, ok := windowsCanonicalAppContainerSIDParts(value)
		if !ok {
			return
		}
		var rebuilt strings.Builder
		rebuilt.WriteString("S-1-15")
		for _, part := range parts {
			rebuilt.WriteByte('-')
			rebuilt.WriteString(strconv.FormatUint(uint64(part), 10))
		}
		if rebuilt.String() != value {
			t.Fatalf("accepted noncanonical SID %q as %q", value, rebuilt.String())
		}
	})
}

func TestWindowsAppContainerOrphanGrantCannotBecomeSupplemental(t *testing.T) {
	classified := windowsClassifyAppContainerGrantFailure(errWindowsAppContainerDACLOrphan, 7, 7)
	if !errors.Is(classified, errWindowsAppContainerDACLOrphan) ||
		errors.Is(classified, errWindowsAppContainerGrantNotApplied) {
		t.Fatalf("orphan grant classification = %v, want hard failure", classified)
	}
}

func TestWindowsAppContainerRepeatedGrantDoesNotDuplicateACE(t *testing.T) {
	requireHostFilesystem(t)
	root, cleanup, _, err := createPrivateQualificationStaging(t.TempDir(), "repeat-")
	if err != nil || cleanup == nil {
		t.Fatalf("create repeated-grant fixture: path=%q cleanup=%v err=%v", root, cleanup != nil, err)
	}
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = cleanup()
		}
	})
	baseline := windowsPathDACLState(t, root)
	sid := testWindowsAppContainerSID(t)
	session := newWindowsAppContainerTestSession(t, sid)
	released := false
	t.Cleanup(func() {
		if !released {
			_ = session.release()
		}
	})
	for attempt := 1; attempt <= 2; attempt++ {
		if err := session.grantPath(root, windows.GENERIC_READ|windows.GENERIC_EXECUTE, false); err != nil {
			t.Fatalf("grant attempt %d: %v", attempt, err)
		}
		profiles := windowsPathACEProfilesForSID(t, root, sid)
		want := map[windowsTestACEProfile]int{
			{
				mask:  windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE,
				flags: uint8(windows.NO_INHERITANCE),
			}: 1,
		}
		if !reflect.DeepEqual(profiles, want) {
			t.Fatalf("grant attempt %d package ACEs = %#v, want %#v", attempt, profiles, want)
		}
	}
	if len(session.daclRestores) != 2 {
		t.Fatalf("repeated grant journal entries = %d, want 2", len(session.daclRestores))
	}
	if err := session.release(); err != nil {
		t.Fatalf("release repeated grant session: %v", err)
	}
	released = true
	if got := windowsPathDACLState(t, root); !sameWindowsTestDACLState(got, baseline) {
		t.Fatal("repeated grant release did not restore the exact baseline DACL/control")
	}
	if profiles := windowsPathACEProfilesForSID(t, root, sid); len(profiles) != 0 {
		t.Fatalf("repeated grant release left active package ACEs: %#v", profiles)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup repeated-grant fixture: %v", err)
	}
	cleaned = true
}

func TestWindowsAppContainerNonPropagatingDirectoryGrantPreservesExistingChild(t *testing.T) {
	requireHostFilesystem(t)
	root := t.TempDir()
	existingChild := filepath.Join(root, "existing-child")
	if err := os.Mkdir(existingChild, 0o700); err != nil {
		t.Fatal(err)
	}
	rootBaseline := windowsPathDACLState(t, root)
	childBaseline := windowsPathDACLState(t, existingChild)
	sid := testWindowsAppContainerSID(t)
	session := newWindowsAppContainerTestSession(t, sid)
	released := false
	t.Cleanup(func() {
		if !released {
			_ = session.release()
		}
	})
	access := windows.ACCESS_MASK(windows.GENERIC_READ | windows.GENERIC_EXECUTE)
	if err := session.grantPath(root, access, false); err != nil {
		t.Fatalf("grant non-propagating directory: %v", err)
	}
	want := map[windowsTestACEProfile]int{
		{
			mask:  windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE,
			flags: uint8(windows.NO_INHERITANCE),
		}: 1,
	}
	if got := windowsPathACEProfilesForSID(t, root, sid); !reflect.DeepEqual(got, want) {
		t.Fatalf("non-propagating directory package ACEs = %#v, want %#v", got, want)
	}
	if got := windowsPathDACLState(t, existingChild); !sameWindowsTestDACLState(got, childBaseline) {
		t.Fatal("non-propagating directory grant changed the pre-existing child DACL/control")
	}
	if got := windowsPathACEProfilesForSID(t, existingChild, sid); len(got) != 0 {
		t.Fatalf("non-propagating directory grant reached pre-existing child: %#v", got)
	}
	if err := session.release(); err != nil {
		t.Fatalf("release non-propagating directory grant: %v", err)
	}
	released = true
	if got := windowsPathDACLState(t, root); !sameWindowsTestDACLState(got, rootBaseline) {
		t.Fatal("non-propagating directory DACL/control was not restored exactly")
	}
	if got := windowsPathDACLState(t, existingChild); !sameWindowsTestDACLState(got, childBaseline) {
		t.Fatal("non-propagating directory release changed the pre-existing child DACL/control")
	}
}

func TestWindowsAppContainerPrivateAncestorGrantIsMinimalAndNonInheriting(t *testing.T) {
	requireHostFilesystem(t)
	if windowsAppContainerAncestorGrantHandleAccess != windows.MAXIMUM_ALLOWED {
		t.Fatal("DACL mutation handle can propagate existing inheritable ACEs into unjournaled children")
	}
	ancestor := t.TempDir()
	existingChild := filepath.Join(ancestor, "existing-child")
	if err := os.Mkdir(existingChild, 0o700); err != nil {
		t.Fatal(err)
	}
	baseline := windowsPathDACLState(t, ancestor)
	existingChildBaseline := windowsPathDACLState(t, existingChild)
	sid := testWindowsAppContainerSID(t)
	session := newWindowsAppContainerTestSession(t, sid)
	released := false
	t.Cleanup(func() {
		if !released {
			_ = session.release()
		}
	})
	access := windowsAppContainerAncestorAccess
	if err := session.grantAncestorPathWithAccess(ancestor, access); err != nil {
		t.Fatalf("grant minimal private ancestor access: %v", err)
	}
	want := map[windowsTestACEProfile]int{
		{mask: access, flags: uint8(windows.NO_INHERITANCE)}: 1,
	}
	if got := windowsPathACEProfilesForSID(t, ancestor, sid); !reflect.DeepEqual(got, want) {
		t.Fatalf("private ancestor package ACEs = %#v, want %#v", got, want)
	}
	if got := windowsPathDACLState(t, existingChild); !sameWindowsTestDACLState(got, existingChildBaseline) {
		t.Fatal("private ancestor grant propagated its existing inheritable ACEs into a pre-existing child")
	}
	if got := windowsPathACEProfilesForSID(t, existingChild, sid); len(got) != 0 {
		t.Fatalf("private ancestor grant reached a pre-existing child: %#v", got)
	}
	child := filepath.Join(ancestor, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := windowsPathACEProfilesForSID(t, child, sid); len(got) != 0 {
		t.Fatalf("private ancestor grant inherited into child: %#v", got)
	}
	if err := session.release(); err != nil {
		t.Fatalf("restore private ancestor grant: %v", err)
	}
	released = true
	if got := windowsPathDACLState(t, ancestor); !sameWindowsTestDACLState(got, baseline) {
		t.Fatal("private ancestor DACL/control was not restored exactly")
	}
	if got := windowsPathDACLState(t, existingChild); !sameWindowsTestDACLState(got, existingChildBaseline) {
		t.Fatal("private ancestor release did not preserve the pre-existing child DACL/control")
	}
}

func TestWindowsAppContainerRehomesWritableEnvironmentExactly(t *testing.T) {
	application := requireTrustedWindowsGoApplication(t)
	privateRoot := t.TempDir()
	environment := windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot)
	moduleCache := windowsEnvironmentLookup(environment, "GOMODCACHE")
	withoutXDG := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "XDG_CONFIG_HOME") {
			continue
		}
		withoutXDG = append(withoutXDG, entry)
	}
	original := append([]string(nil), withoutXDG...)
	workspace := filepath.Join(privateRoot, windowsAppContainerWorkspacePrefix+"fixture")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	rewritten, ok := windowsRehomeAppContainerWritableEnvironment(withoutXDG, workspace)
	if !ok || !reflect.DeepEqual(withoutXDG, original) {
		t.Fatalf("writable environment rewrite = %v, input changed=%v", ok, !reflect.DeepEqual(withoutXDG, original))
	}
	counts := make(map[string]int, len(windowsAppContainerWritableEnvironmentKeys))
	for _, entry := range rewritten {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("rewritten environment entry is malformed: %q", entry)
		}
		for _, writableName := range windowsAppContainerWritableEnvironmentKeys {
			if strings.EqualFold(name, writableName) {
				counts[writableName]++
				if value != workspace {
					t.Fatalf("%s = %q, want workspace %q", writableName, value, workspace)
				}
			}
		}
	}
	for _, name := range windowsAppContainerWritableEnvironmentKeys {
		if counts[name] != 1 {
			t.Fatalf("writable environment %s count = %d, want 1", name, counts[name])
		}
	}
	if got := windowsEnvironmentLookup(rewritten, "GOMODCACHE"); got != moduleCache {
		t.Fatalf("GOMODCACHE = %q, want preserved %q", got, moduleCache)
	}
	if got := windowsQualificationPrivateRoot(rewritten); !strings.EqualFold(got, privateRoot) {
		t.Fatalf("rewritten private root = %q, want %q", got, privateRoot)
	}
	duplicate := append(append([]string(nil), withoutXDG...), "HOME="+workspace)
	if got, ok := windowsRehomeAppContainerWritableEnvironment(duplicate, workspace); ok || got != nil {
		t.Fatal("duplicate writable environment key was accepted")
	}
	oversize := append(append([]string(nil), withoutXDG...), "OVERSIZE="+strings.Repeat("x", maximumGateProcessTextBytes))
	if got, ok := windowsRehomeAppContainerWritableEnvironment(oversize, workspace); ok || got != nil {
		t.Fatal("oversize writable environment was accepted")
	}
}

func TestWindowsAppContainerWorkspaceLeavesLegacyGitPathHeadroom(t *testing.T) {
	const legacySafePathUnits = 240
	workspaceName := windowsAppContainerWorkspacePrefix + strings.Repeat("0", 32)
	if len(workspaceName) != len(windowsAppContainerWorkspacePrefix)+32 {
		t.Fatal("AppContainer workspace name does not retain the 128-bit hex nonce")
	}
	longestGitFixture := filepath.Join(
		`D:\a\_temp`,
		"rpq",
		workspaceName,
		"TestInspectRepositoryRejectsShallowAndInjectedGitStatereplace_o9999999999",
		"001",
		"repository",
		".git",
		"refs",
		"replace",
		strings.Repeat("f", 40)+".lock",
	)
	encoded, err := windows.UTF16FromString(longestGitFixture)
	if err != nil {
		t.Fatalf("encode longest Git fixture path: %v", err)
	}
	if units := len(encoded) - 1; units >= legacySafePathUnits {
		t.Fatalf("longest Git fixture path uses %d UTF-16 units, want less than %d: %q",
			units, legacySafePathUnits, longestGitFixture)
	}
}

func TestWindowsQualificationPrivateRootStaysOutsideCleanRepository(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	privateRoot := filepath.Join(filepath.Dir(fixture.root), "rpq")
	if windowsPathsOverlap(fixture.root, privateRoot) {
		t.Fatalf("private root %q overlaps repository %q", privateRoot, fixture.root)
	}
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		t.Fatalf("create disjoint private root: %v", err)
	}
	for _, phase := range []string{"present", "removed"} {
		snapshot, err := InspectRepository(fixture.request())
		if err != nil || snapshot.Subject.Dirty {
			t.Fatalf("repository inspection while private root is %s: dirty=%v err=%v",
				phase, snapshot.Subject.Dirty, err)
		}
		if phase == "present" {
			if err := os.Remove(privateRoot); err != nil {
				t.Fatalf("remove disjoint private root: %v", err)
			}
		}
	}
}

func TestWindowsAppContainerWritableWorkspaceACLAndCleanup(t *testing.T) {
	requireHostFilesystem(t)
	parent := t.TempDir()
	parentBefore := windowsPathDACLState(t, parent)
	workspace, cleanup, _, err := createPrivateQualificationStaging(parent, windowsAppContainerWorkspacePrefix)
	if err != nil || cleanup == nil {
		t.Fatalf("create writable workspace: path=%q cleanup=%v err=%v", workspace, cleanup != nil, err)
	}
	workspaceBefore := windowsPathDACLState(t, workspace)
	sid := testWindowsAppContainerSID(t)
	session := newWindowsAppContainerTestSession(t, sid)
	session.writableWorkspacePath = workspace
	session.cleanupWritableWorkspace = cleanup
	if err := session.grantWritableWorkspaceRoot(workspace); err != nil {
		t.Fatalf("grant writable workspace: %v", err)
	}
	profiles := windowsPathACEProfilesForSID(t, workspace, sid)
	wantProfiles := map[windowsTestACEProfile]int{
		{mask: windowsAppContainerWritableRootAccess, flags: uint8(windows.NO_INHERITANCE)}: 1,
		{
			mask:  windowsAppContainerWritableChildAccess,
			flags: uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.INHERIT_ONLY_ACE),
		}: 1,
	}
	if !reflect.DeepEqual(profiles, wantProfiles) {
		t.Fatalf("writable workspace package ACEs = %#v, want %#v", profiles, wantProfiles)
	}
	if windowsAppContainerWritableRootAccess&(windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER) != 0 ||
		windowsAppContainerWritableChildAccess&(windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
		t.Fatal("writable workspace grants delete/DACL/owner authority outside the descendant contract")
	}
	directory := filepath.Join(workspace, "nested")
	file := filepath.Join(directory, "value.txt")
	if err := os.Mkdir(directory, 0o700); err != nil || os.WriteFile(file, []byte("value\n"), 0o600) != nil {
		t.Fatal("create inherited writable workspace entries")
	}
	for _, path := range []string{directory, file} {
		inherited := windowsPathACEProfilesForSID(t, path, sid)
		found := false
		for profile := range inherited {
			if profile.mask == windowsAppContainerWritableChildAccess &&
				profile.flags&uint8(windows.INHERITED_ACE) != 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("new workspace entry %q did not inherit the exact package access", path)
		}
	}
	if err := session.restoreDACLs(); err != nil {
		t.Fatalf("restore writable workspace: %v", err)
	}
	if got := windowsPathDACLState(t, workspace); !sameWindowsTestDACLState(got, workspaceBefore) {
		t.Fatal("writable workspace DACL/control was not restored exactly")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup writable workspace: %v", err)
	}
	session.cleanupWritableWorkspace = nil
	if _, err := os.Lstat(workspace); !os.IsNotExist(err) {
		t.Fatalf("writable workspace survived release: %v", err)
	}
	if got := windowsPathDACLState(t, parent); !sameWindowsTestDACLState(got, parentBefore) {
		t.Fatal("writable workspace changed its parent DACL/control")
	}
}

type windowsTestACEProfile struct {
	mask  windows.ACCESS_MASK
	flags uint8
}

func windowsPathACEProfilesForSID(t *testing.T, path string, sid *windows.SID) map[windowsTestACEProfile]int {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("read Windows path DACL profiles: %v", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || defaulted || dacl == nil {
		t.Fatalf("read Windows path DACL profiles: defaulted=%v err=%v", defaulted, err)
	}
	profiles := make(map[windowsTestACEProfile]int)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if principal != nil && principal.IsValid() && principal.Equals(sid) {
			profiles[windowsTestACEProfile{mask: ace.Mask, flags: ace.Header.AceFlags}]++
		}
	}
	return profiles
}

func TestWindowsAppContainerNullDeviceLeaseRoundTrip(t *testing.T) {
	lease, err := windowsAcquireAppContainerNullLease()
	if err != nil {
		t.Fatalf("acquire NUL DACL lease: %v", err)
	}
	if err := windowsReleaseAppContainerNullLease(lease, true); err != nil {
		t.Fatalf("release NUL DACL lease: %v", err)
	}
}

func TestWindowsAppContainerNullDeviceLeaseWaitIsBounded(t *testing.T) {
	name := windowsAppContainerNullMutexName + ".test." + strconv.Itoa(os.Getpid()) + "." +
		strconv.FormatInt(time.Now().UnixNano(), 10)
	holderReady := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		lease, err := windowsAcquireNamedAppContainerNullLease(name, time.Second)
		if err != nil {
			holderDone <- err
			return
		}
		close(holderReady)
		<-releaseHolder
		holderDone <- windowsReleaseAppContainerNullLease(lease, true)
	}()
	select {
	case <-holderReady:
	case err := <-holderDone:
		t.Fatalf("acquire holder lease: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("holder lease did not become ready")
	}

	started := time.Now()
	lease, err := windowsAcquireNamedAppContainerNullLease(name, 25*time.Millisecond)
	elapsed := time.Since(started)
	close(releaseHolder)
	if holderErr := <-holderDone; holderErr != nil {
		t.Fatalf("release holder lease: %v", holderErr)
	}
	if lease != 0 || !errors.Is(err, errWindowsAppContainerNullLease) {
		t.Fatalf("contended lease = %v, %v; want zero fail-closed lease", lease, err)
	}
	if elapsed < 20*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("bounded lease wait took %s", elapsed)
	}
}

type windowsTestDACLState struct {
	control  windows.SECURITY_DESCRIPTOR_CONTROL
	revision uint32
	dacl     windowsACLSemanticIdentity
}

func windowsPathDACLState(t *testing.T, path string) windowsTestDACLState {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("read Windows path DACL state: %v", err)
	}
	control, revision, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read Windows path DACL control: %v", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || defaulted || dacl == nil {
		t.Fatalf("read Windows path DACL: defaulted=%v err=%v", defaulted, err)
	}
	daclIdentity, ok := windowsACLSemantic(dacl)
	if !ok {
		t.Fatal("read Windows path DACL semantics")
	}
	return windowsTestDACLState{
		control:  control,
		revision: revision,
		dacl:     daclIdentity,
	}
}

func windowsPathObjectIdentity(t *testing.T, path string) windowsAppContainerObjectIdentity {
	t.Helper()
	file, _, err := windowsOpenAppContainerGrantPath(path)
	if err != nil {
		t.Fatalf("open Windows path identity: %v", err)
	}
	identity, identityErr := windowsReadAppContainerObjectIdentity(windows.Handle(file.Fd()))
	closeErr := file.Close()
	if identityErr != nil || closeErr != nil {
		t.Fatalf("read Windows path identity: identity=%v close=%v", identityErr, closeErr)
	}
	return identity
}

func sameWindowsTestDACLState(left, right windowsTestDACLState) bool {
	return left.control == right.control && left.revision == right.revision &&
		sameWindowsACLSemantic(left.dacl, right.dacl)
}

func TestWindowsTestDACLStateComparisonUsesOrderedACESemantics(t *testing.T) {
	baseline := windowsTestDACLState{
		control:  windows.SE_DACL_PRESENT | windows.SE_DACL_PROTECTED,
		revision: 1,
		dacl: windowsACLSemanticIdentity{
			revision: 2,
			aces:     [][]byte{{0, 1, 2}, {3, 4, 5}},
		},
	}
	equivalent := windowsTestDACLState{
		control:  baseline.control,
		revision: baseline.revision,
		dacl: windowsACLSemanticIdentity{
			revision: baseline.dacl.revision,
			aces:     [][]byte{{0, 1, 2}, {3, 4, 5}},
		},
	}
	if !sameWindowsTestDACLState(baseline, equivalent) {
		t.Fatal("identical ordered ACE semantics were rejected")
	}

	changed := equivalent
	changed.dacl = windowsACLSemanticIdentity{
		revision: equivalent.dacl.revision,
		aces:     [][]byte{{3, 4, 5}, {0, 1, 2}},
	}
	if sameWindowsTestDACLState(baseline, changed) {
		t.Fatal("reordered ACE semantics were accepted")
	}
	changed = equivalent
	changed.dacl = windowsACLSemanticIdentity{
		revision: equivalent.dacl.revision + 1,
		aces:     [][]byte{{0, 1, 2}, {3, 4, 5}},
	}
	if sameWindowsTestDACLState(baseline, changed) {
		t.Fatal("changed ACL revision was accepted")
	}
	changed = equivalent
	changed.dacl = windowsACLSemanticIdentity{
		revision: equivalent.dacl.revision,
		aces:     [][]byte{{0, 1, 9}, {3, 4, 5}},
	}
	if sameWindowsTestDACLState(baseline, changed) {
		t.Fatal("changed ACE bytes were accepted")
	}
	changed = equivalent
	changed.control ^= windows.SE_DACL_PROTECTED
	if sameWindowsTestDACLState(baseline, changed) {
		t.Fatal("changed security-descriptor control was accepted")
	}
	changed = equivalent
	changed.revision++
	if sameWindowsTestDACLState(baseline, changed) {
		t.Fatal("changed security-descriptor revision was accepted")
	}
}

func testWindowsAppContainerSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid("S-1-15-2-17011983-27021984-37031985-47041986-57051987-67061988-77071989")
	if err != nil || sid == nil || !sid.IsValid() {
		t.Fatalf("create package SID fixture: %v", err)
	}
	return sid
}

func TestWindowsPrepareNetworkNoneAppContainerIgnoresUnwritableSourceTreeReset(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	application := requireTrustedWindowsGoApplication(t)
	dir := t.TempDir()
	privateRoot := t.TempDir()
	locked := filepath.Join(dir, "locked-pack")
	file, err := os.OpenFile(locked, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("pack"); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	request := gateProcessRequest{
		Application: application,
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot),
	}
	session, err := windowsPrepareNetworkNoneAppContainer(&request)
	if err != nil || session == nil {
		t.Fatalf("prepare with a held source file: session=%v err=%v", session != nil, err)
	}
	defer session.release()
	if time.Since(started) > 90*time.Second {
		t.Fatal("source-tree AppContainer grant walked too long")
	}
}

func TestOSGateExecutorIsolatesGoVersionWithNetworkNone(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	application := requireTrustedWindowsGoApplication(t)
	dir := t.TempDir()
	privateRoot := t.TempDir()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"version"},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot),
		Network:     NetworkNone,
		Timeout:     20 * time.Second,
		StdoutLimit: 4096,
		StderrLimit: 4096,
	})
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("NetworkNone go version result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
	want := "go version " + receiptGoVersion + " windows/amd64\n"
	if string(result.Stdout) != want {
		t.Fatalf("NetworkNone go version stdout = %q, want %q", result.Stdout, want)
	}
}

func TestWindowsAppContainerCreateProcessWithPipesAndEnvironment(t *testing.T) {
	skipIfHostLoopbackUnavailable(t)
	application := requireTrustedWindowsGoApplication(t)
	dir := t.TempDir()
	privateRoot := t.TempDir()
	request := gateProcessRequest{
		Application: application,
		Args:        []string{"version"},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot),
		Network:     NetworkNone,
	}
	session, err := windowsPrepareNetworkNoneAppContainer(&request)
	if err != nil || session == nil {
		t.Fatalf("prepare: %v", err)
	}
	defer session.release()

	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdoutReader, stdoutWriter, err := windowsCreateAppContainerPipe(session.sid)
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	defer stdoutReader.Close()
	defer stdoutWriter.Close()
	stderrReader, stderrWriter, err := windowsCreateAppContainerPipe(session.sid)
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	defer stderrReader.Close()
	defer stderrWriter.Close()
	childHandles := []windows.Handle{
		windows.Handle(stdin.Fd()),
		windows.Handle(stdoutWriter.Fd()),
		windows.Handle(stderrWriter.Fd()),
	}
	for _, handle := range childHandles {
		if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			t.Fatalf("inherit: %v", err)
		}
	}

	attributeList, err := windows.NewProcThreadAttributeList(windowsAppContainerProcessAttributeSlots)
	if err != nil {
		t.Fatal(err)
	}
	defer attributeList.Delete()
	if err := attributeList.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&childHandles[0]),
		uintptr(len(childHandles))*unsafe.Sizeof(childHandles[0]),
	); err != nil {
		t.Fatalf("handle list: %v", err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	if err := windowsUpdateAppContainerProcessAttributes(attributeList, session, &pinner); err != nil {
		t.Fatalf("AppContainer attributes: %v", err)
	}

	applicationUTF16, err := windows.UTF16PtrFromString(application)
	if err != nil {
		t.Fatal(err)
	}
	commandLine, err := windows.UTF16FromString(windows.ComposeCommandLine([]string{application, "version"}))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	environment, ok := windowsGateEnvironmentBlock(request.Env)
	if !ok {
		t.Fatal("environment block was rejected")
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  childHandles[0],
			StdOutput: childHandles[1],
			StdErr:    childHandles[2],
		},
		ProcThreadAttributeList: attributeList.List(),
	}
	process := windows.ProcessInformation{}
	err = windows.CreateProcess(
		applicationUTF16,
		&commandLine[0],
		nil,
		nil,
		true,
		windows.CREATE_SUSPENDED|windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_DEFAULT_ERROR_MODE|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		&environment[0],
		directory,
		&startup.StartupInfo,
		&process,
	)
	if err != nil {
		t.Fatalf("CreateProcess: %v", err)
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	if err := windows.TerminateProcess(process.Process, 1); err != nil {
		t.Fatal(err)
	}
}

func windowsNetworkNoneGoVersionEnvironment(t *testing.T, application, privateRoot string) []string {
	t.Helper()
	home := filepath.Join(privateRoot, "home")
	goCache := filepath.Join(privateRoot, "go-cache")
	goModCache := filepath.Join(privateRoot, "go-mod-cache")
	temporary := filepath.Join(privateRoot, "tmp")
	for _, path := range []string{home, goCache, goModCache, temporary} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	systemRoot := os.Getenv("SYSTEMROOT")
	return []string{
		"PATH=" + filepath.Dir(application),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + home,
		"TMPDIR=" + temporary,
		"TMP=" + temporary,
		"TEMP=" + temporary,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"GOWORK=off",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOFLAGS=",
		"GOCACHEPROG=",
		"GOTELEMETRY=off",
		"CGO_ENABLED=0",
		"GOCACHE=" + goCache,
		"GOMODCACHE=" + goModCache,
		"GOPATH=" + filepath.Join(home, "go"),
		"GOBIN=" + filepath.Join(home, "bin"),
		"GOTMPDIR=" + temporary,
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOVULNDB=off",
		"SYSTEMROOT=" + systemRoot,
		"WINDIR=" + systemRoot,
	}
}

func concatWindowsPaths(sets ...[]string) []string {
	var result []string
	for _, set := range sets {
		result = append(result, set...)
	}
	return result
}

func requireTrustedWindowsGoApplication(t *testing.T) string {
	t.Helper()
	path := requirePATHRuntimeTool(t, "go")
	resolved, err := trustedControllerRuntimePath(t.TempDir(), path)
	if err != nil {
		t.Fatalf("trusted go path: %v", err)
	}
	return resolved
}

func requireBuiltSourceQualifyApplication(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "repopass-source-qualify.exe")
	command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-o", out,
		"github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build source-qualify controller: %v\n%s", err, output)
	}
	resolved, err := trustedControllerRuntimePath(t.TempDir(), out)
	if err != nil {
		t.Fatalf("trusted source-qualify path: %v", err)
	}
	return resolved
}

func buildSourceQualifyApplicationAt(t *testing.T, out string) string {
	t.Helper()
	command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-o", out,
		"github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build source-qualify controller: %v\n%s", err, output)
	}
	return out
}

func copyWindowsAppContainerTestExecutable(t *testing.T, destination string) {
	t.Helper()
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func containsWindowsPath(paths []string, want string) bool {
	for _, path := range paths {
		if strings.EqualFold(filepath.Clean(path), filepath.Clean(want)) {
			return true
		}
	}
	return false
}

func requireSchemaJSONAppContainerFixtureRoot(t *testing.T) string {
	t.Helper()
	candidates := []string{t.TempDir()}
	if runnerTemp := os.Getenv("RUNNER_TEMP"); runnerTemp != "" {
		candidates = append([]string{filepath.Join(runnerTemp, "sq-schema-json-"+filepath.Base(t.TempDir()))}, candidates...)
	}
	for _, dir := range candidates {
		if !schemaJSONAppContainerRootGrantable(dir) {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	t.Skip("schema JSON AppContainer ancestor chain crosses a host profile root")
	return ""
}

func copyGrantableModuleTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		portable := filepath.ToSlash(rel)
		if portable == ".git" || strings.HasPrefix(portable, ".git/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy module tree: %v", err)
	}
}

func schemaJSONAppContainerRootGrantable(dir string) bool {
	if dir == "" {
		return false
	}
	for _, ancestor := range windowsAppContainerAncestorPaths(dir) {
		if !windowsAppContainerAncestorGrantForbidden(ancestor) {
			continue
		}
		volume := filepath.VolumeName(ancestor)
		relative := strings.Trim(strings.TrimPrefix(filepath.Clean(ancestor), volume), `\`)
		if relative == "" {
			continue
		}
		return false
	}
	return true
}
