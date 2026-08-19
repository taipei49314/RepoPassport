//go:build windows

package sourcequalification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	block := windowsGateEnvironmentBlock([]string{
		"PATH=C:\\go\\bin",
		"SYSTEMROOT=C:\\Windows",
		"GOFLAGS=",
	})
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

func TestOSGateExecutorIsolatesSchemaJSONWithNetworkNone(t *testing.T) {
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	application := requireBuiltSourceQualifyApplication(t)
	writeSchemaJSONFixture(t, dir, "schemas/example.schema.json", []byte(`{"type":"object"}`))
	writeSchemaJSONFixture(t, dir, "testdata/fixtures/example/fixture.json", []byte(`{"status":"healthy"}`))

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"validate-schema-json", "--root", "."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(requireTrustedWindowsGoApplication(t), dir),
		Network:     NetworkNone,
		Timeout:     30 * time.Second,
		StdoutLimit: 4096,
		StderrLimit: 4096,
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

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"validate-schema-json", "--root", "."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(requireTrustedWindowsGoApplication(t), dir),
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
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.invalid/vetprobe\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.go"), []byte("package vetprobe\n\nfunc Ready() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	application := requireTrustedWindowsGoApplication(t)

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"vet", "./..."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(application, dir),
		Network:     NetworkNone,
		Timeout:     45 * time.Second,
		StdoutLimit: 4096,
		StderrLimit: 4096,
	})
	if time.Since(started) > 40*time.Second {
		t.Fatal("NetworkNone go vet AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("NetworkNone go vet result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoTestWithNetworkNone(t *testing.T) {
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.invalid/testprobe\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe_test.go"), []byte("package testprobe\n\nimport \"testing\"\n\nfunc TestReady(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	application := requireTrustedWindowsGoApplication(t)

	started := time.Now()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"test", "-count=1", "."},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(application, dir),
		Network:     NetworkNone,
		Timeout:     60 * time.Second,
		StdoutLimit: 8192,
		StderrLimit: 8192,
	})
	if time.Since(started) > 50*time.Second {
		t.Fatal("NetworkNone go test AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("NetworkNone go test result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoVetWithFilledModuleCache(t *testing.T) {
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	modcache := filepath.Join(dir, "modcache")
	gocache := filepath.Join(dir, "gocache")
	gopath := filepath.Join(dir, "gopath")
	for _, path := range []string{modcache, gocache, gopath} {
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
		"HOME=" + dir,
		"USERPROFILE=" + dir,
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOENV=off",
		"GOFLAGS=",
		"GOPROXY=https://proxy.golang.org,direct",
		"GOSUMDB=sum.golang.org",
		"GOMODCACHE=" + modcache,
		"GOCACHE=" + gocache,
		"GOPATH=" + gopath,
		"GOTMPDIR=" + dir,
		"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
		"WINDIR=" + os.Getenv("WINDIR"),
	}
	if output, err := download.CombinedOutput(); err != nil {
		t.Skipf("host module download unavailable: %v\n%s", err, output)
	}

	env := windowsNetworkNoneGoVersionEnvironment(application, dir)
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
	if time.Since(started) > 50*time.Second {
		t.Fatal("module-cache go vet AppContainer grant walked too long")
	}
	if result.Blocked || err != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
		result.TimedOut || result.Cancelled || result.CleanupFailed {
		t.Fatalf("module-cache go vet result = %#v err=%v stdout=%q stderr=%q",
			result, err, result.Stdout, result.Stderr)
	}
}

func TestOSGateExecutorIsolatesGoVetOfModuleRootWithFilledCache(t *testing.T) {
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
	dir := requireSchemaJSONAppContainerFixtureRoot(t)
	src := filepath.Join(dir, "module")
	modcache := filepath.Join(dir, "modcache")
	gocache := filepath.Join(dir, "gocache")
	gopath := filepath.Join(dir, "gopath")
	tmpdir := filepath.Join(dir, "tmp")
	for _, path := range []string{src, modcache, gocache, gopath, tmpdir} {
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
		"HOME=" + dir,
		"USERPROFILE=" + dir,
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

	env := windowsNetworkNoneGoVersionEnvironment(application, dir)
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
	required, writable, readable := windowsNetworkNoneAccessPaths(gateProcessRequest{
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
	for _, path := range concatWindowsPaths(required, writable, readable) {
		if windowsAppContainerTreeMutationForbidden(path) {
			t.Fatalf("NetworkNone grant list included system path %q", path)
		}
	}
}

func TestWindowsPrepareNetworkNoneAppContainerIgnoresUnwritableSourceTreeReset(t *testing.T) {
	application := requireTrustedWindowsGoApplication(t)
	dir := t.TempDir()
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
	session, err := windowsPrepareNetworkNoneAppContainer(gateProcessRequest{
		Application: application,
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(application, dir),
	})
	if err != nil || session == nil {
		t.Fatalf("prepare with a held source file: session=%v err=%v", session != nil, err)
	}
	defer session.release()
	if time.Since(started) > 45*time.Second {
		t.Fatal("source-tree AppContainer grant walked too long")
	}
}

func TestOSGateExecutorIsolatesGoVersionWithNetworkNone(t *testing.T) {
	application := requireTrustedWindowsGoApplication(t)
	dir := t.TempDir()
	result, err := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: application,
		Args:        []string{"version"},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(application, dir),
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
	application := requireTrustedWindowsGoApplication(t)
	dir := t.TempDir()
	request := gateProcessRequest{
		Application: application,
		Args:        []string{"version"},
		Dir:         dir,
		Env:         windowsNetworkNoneGoVersionEnvironment(application, dir),
		Network:     NetworkNone,
	}
	session, err := windowsPrepareNetworkNoneAppContainer(request)
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

	attributeList, err := windows.NewProcThreadAttributeList(2)
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
	pinner.Pin(session.sid)
	pinner.Pin(&session.capabilities)
	if err := attributeList.Update(
		windowsProcThreadAttributeSecurityCapabilities,
		unsafe.Pointer(&session.capabilities),
		unsafe.Sizeof(session.capabilities),
	); err != nil {
		t.Fatalf("capabilities: %v", err)
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
	environment := windowsGateEnvironmentBlock(request.Env)
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

func windowsNetworkNoneGoVersionEnvironment(application, dir string) []string {
	systemRoot := os.Getenv("SYSTEMROOT")
	return []string{
		"PATH=" + filepath.Dir(application),
		"HOME=" + dir,
		"USERPROFILE=" + dir,
		"TMPDIR=" + dir,
		"TMP=" + dir,
		"TEMP=" + dir,
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
		"GOCACHE=" + dir,
		"GOMODCACHE=" + dir,
		"GOPATH=" + filepath.Join(dir, "go"),
		"GOBIN=" + filepath.Join(dir, "bin"),
		"GOTMPDIR=" + dir,
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
	command := exec.Command("go", "build", "-trimpath", "-o", out,
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
