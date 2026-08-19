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

	fmt.Printf("debug workspace=%q runnerTemp=%q goos=%s\n", absolute, os.Getenv("RUNNER_TEMP"), runtime.GOOS)
	dumpEnv("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "SystemRoot")

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

func evalOrErr(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "err:" + err.Error()
	}
	return resolved
}
