package sourcequalification

// Temporary CI diagnostic for issue #6 — removed before any qualification
// change merges.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestZZDebugPlatformConfigurationCI(t *testing.T) {
	repoRoot := os.Getenv("SQ_DEBUG_REPO_ROOT")
	if repoRoot == "" {
		t.Skip("diagnostic probe requires SQ_DEBUG_REPO_ROOT")
	}
	absolute, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	absolute = filepath.Clean(absolute)
	lane := LaneLinuxAMD64
	if runtime.GOOS == "windows" {
		lane = LaneWindowsAMD64
	}

	fmt.Printf("debug workspace=%q runnerTemp=%q goos=%s cwd=%q\n",
		absolute, os.Getenv("RUNNER_TEMP"), runtime.GOOS, evalOrErr("."))
	dumpEnv("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "SystemRoot")
	if self, err := os.Executable(); err != nil {
		fmt.Printf("debug testSelf err=%v\n", err)
	} else {
		dumpResolved(absolute, "test-self", self)
	}
	if controllerDir := os.Getenv("SQ_DEBUG_CONTROLLER"); controllerDir != "" {
		pattern := filepath.Join(filepath.Clean(controllerDir), "repopass-source-qualify*")
		matches, globErr := filepath.Glob(pattern)
		fmt.Printf("debug controllerGlob pattern=%q err=%v matches=%q\n", pattern, globErr, matches)
		for _, path := range matches {
			info, statErr := os.Lstat(path)
			fmt.Printf("debug controllerFile path=%q lstatErr=%v mode=%v perm=%#o size=%d\n",
				path, statErr, fileMode(info), filePerm(info), fileSize(info))
			dumpResolved(absolute, "controller", path)
		}
	}

	temp := os.Getenv("RUNNER_TEMP")
	if temp == "" {
		t.Fatal("RUNNER_TEMP is required")
	}
	temp = filepath.Clean(temp)
	workspace, cleanup, err := createPrivateQualificationWorkspace(temp, "sq-debug-private")
	fmt.Printf("debug privateWorkspace path=%q err=%v validDir=%v eval=%q\n",
		workspace, err, validGateProcessDirectory(workspace), evalOrErr(workspace))
	if err != nil {
		return
	}
	defer func() { _ = cleanup() }()
	fmt.Printf("debug requirePrivate=%v\n", requirePrivatePackageDirectory(workspace))
	directories, dirErr := createControllerRuntimeDirectories(workspace)
	fmt.Printf("debug runtimeDirs err=%v dirs=%v\n", dirErr, directories)
	if dirErr != nil {
		return
	}

	applications, all, toolPath, selfPath, resolveErr := resolveControllerRuntimeApplications(absolute, lane)
	fmt.Printf("debug resolve err=%v self=%q toolPath=%q count=%d/%d\n",
		resolveErr, selfPath, toolPath, len(applications), len(all))
	for name, path := range all {
		fmt.Printf("debug resolved %s=%q available=%v validGate=%v\n",
			name, path, availableGateApplication(path),
			validGateApplication(absolute, path, []string{filepath.Dir(path)}))
	}
	if resolveErr != nil {
		return
	}

	systemRoot := ""
	if runtime.GOOS == "windows" {
		systemRoot, err = controllerRuntimeSystemRoot(absolute)
		fmt.Printf("debug systemRoot=%q err=%v\n", systemRoot, err)
		if err != nil {
			return
		}
	}
	environment := gateRunEnvironment{
		ToolPath:   toolPath,
		HomeDir:    directories["home"],
		GoCacheDir: directories["go-cache"],
		TempDir:    directories["tmp"],
		SystemRoot: systemRoot,
	}

	dumpFact(t, all, "go", []string{"version"}, workspace, environment)
	dumpFact(t, all, "git", []string{"--version"}, workspace, environment)
	dumpFact(t, all, "pwsh", []string{
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
		"$PSVersionTable.PSVersion.ToString()",
	}, workspace, environment)
	if runtime.GOOS == "windows" {
		dumpFact(t, all, "pwsh-kernel", []string{
			"-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
			"[Environment]::OSVersion.Version.ToString()",
		}, workspace, environment)
	} else {
		dumpFact(t, all, "uname", []string{"-r"}, workspace, environment)
	}

	request := ProduceLaneRequest{Lane: lane, PrivateLogRoot: workspace}
	platform, platformErr := collectControllerRuntimePlatform(context.Background(), request, all, environment)
	fmt.Printf("debug collectPlatform err=%v platform=%+v\n", platformErr, platform)
	if platformErr == nil {
		fmt.Printf("debug validatePlatform err=%v privacyErr=%v runnerImageOK=%v\n",
			validateReceiptPlatform(platform, lane),
			validateReceiptPrivacy(platform),
			validReceiptRunnerImage(platform.RunnerImage, lane))
	}

	_, logsErr := newProductionGateLogSink(workspace, lane)
	fmt.Printf("debug logSink err=%v\n", logsErr)
}

func dumpEnv(names ...string) {
	for _, name := range names {
		value, ok := os.LookupEnv(name)
		fmt.Printf("debug env %s set=%v value=%q\n", name, ok, value)
	}
}

func dumpFact(t *testing.T, applications map[string]string, label string, args []string, directory string, environment gateRunEnvironment) {
	t.Helper()
	name := label
	if label == "pwsh-kernel" {
		name = "pwsh"
	}
	application := applications[name]
	fmt.Printf("debug factpre %s app=%q dir=%q available=%v validDir=%v\n",
		label, application, directory, availableGateApplication(application), validGateProcessDirectory(directory))
	if application == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	line, err := controllerRuntimeFact(ctx, application, args, directory, controllerRuntimeFactEnvironment(environment))
	fmt.Printf("debug fact %s line=%q err=%v\n", label, line, err)
}

func dumpResolved(repository, name, path string) {
	info, statErr := os.Lstat(path)
	resolved, evalErr := filepath.EvalSymlinks(path)
	trusted, trustedErr := trustedControllerRuntimePath(repository, path)
	fmt.Printf("debug tool %s path=%q lstatErr=%v mode=%v perm=%#o writeBits=%#o eval=%q evalErr=%v trusted=%q trustedErr=%v inside=%v available=%v validGate=%v\n",
		name, path, statErr, fileMode(info), filePerm(info), filePerm(info)&0o022, resolved, evalErr, trusted, trustedErr,
		pathWithinRepository(repository, path),
		availableGateApplication(path),
		trustedErr == nil && validGateApplication(repository, trusted, []string{filepath.Dir(trusted)}))
}

func fileMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func filePerm(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}

func fileSize(info os.FileInfo) int64 {
	if info == nil {
		return 0
	}
	return info.Size()
}

func evalOrErr(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "err:" + err.Error()
	}
	return resolved
}
