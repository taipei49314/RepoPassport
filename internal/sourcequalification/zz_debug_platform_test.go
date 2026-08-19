package sourcequalification

// Temporary CI diagnostic for issue #6 — removed before any qualification
// change merges.

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
			dumpInspectController(path)
		}
	}
	dumpLookPath(absolute, "go", "gofmt", "pwsh", "git", "uname")
	gitPath, gitErr := resolveTrustedGitExecutable(absolute)
	fmt.Printf("debug trustedGit path=%q err=%v\n", gitPath, gitErr)
	dumpInspectRepository(absolute)

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

func dumpLookPath(repository string, names ...string) {
	for _, name := range names {
		if name == "uname" && runtime.GOOS == "windows" {
			continue
		}
		path, err := exec.LookPath(name)
		fmt.Printf("debug lookPath %s path=%q err=%v\n", name, path, err)
		if err != nil {
			continue
		}
		dumpResolved(repository, "lookpath-"+name, path)
	}
}

func dumpInspectController(path string) {
	revision, revErr := exec.Command("git", "rev-parse", "HEAD").Output()
	if revErr != nil {
		fmt.Printf("debug inspectController gitRev err=%v\n", revErr)
		return
	}
	identity, _, err := inspectQualificationController(path, runtime.GOOS, strings.TrimSpace(string(revision)))
	fmt.Printf("debug inspectController path=%q err=%v identity=%+v\n", path, err, identity)
}

func dumpInspectRepository(repository string) {
	gitDir := filepath.Join(repository, ".git")
	info, statErr := os.Lstat(gitDir)
	resolvedRoot := evalOrErr(repository)
	fmt.Printf("debug gitDir path=%q lstatErr=%v mode=%v eval=%q rootEval=%q sameRoot=%v\n",
		gitDir, statErr, fileMode(info), evalOrErr(gitDir), resolvedRoot,
		sameCanonicalPath(repository, resolvedRoot))
	rawTemp := filepath.Clean(os.TempDir())
	parent, parentErr := canonicalIsolatedGitScratchParent(repository, os.TempDir())
	fmt.Printf("debug scratchParent raw=%q validRaw=%v canonical=%q err=%v\n",
		rawTemp, validGateDirectory(rawTemp), parent, parentErr)

	inspector, cleanup, err := newRepositoryInspectorWithScratch(
		repository,
		createPrivateQualificationWorkspace,
		rand.Reader,
	)
	gitPath := ""
	if inspector != nil {
		gitPath = inspector.gitPath
	}
	fmt.Printf("debug inspector err=%v gitPath=%q\n", err, gitPath)
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	if err != nil {
		return
	}

	head := debugGitLine(repository, "rev-parse", "HEAD")
	base := debugGitLine(repository, "rev-parse", "HEAD^")
	fmt.Printf("debug inspectSHAs head=%q base=%q\n", head, base)
	if head == "" || base == "" {
		return
	}
	snapshot, inspectErr := InspectRepository(RepositoryRequest{
		Root:                   repository,
		ExpectedBaseRevision:   base,
		ExpectedTestedRevision: head,
	})
	fmt.Printf("debug inspectRepository err=%v tree=%q files=%d\n",
		inspectErr, snapshot.Subject.TreeSHA, len(snapshot.Files))
}

func debugGitLine(repository string, args ...string) string {
	output, err := exec.Command("git", append([]string{"-C", repository}, args...)...).Output()
	if err != nil {
		fmt.Printf("debug git %v err=%v\n", args, err)
		return ""
	}
	return strings.TrimSpace(string(output))
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
	contains, containErr := securePackagePathContains(repository, path)
	fmt.Printf("debug contain %s contains=%v err=%v\n", name, contains, containErr)
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
