package qualificationfixture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ErrHostBuildCleanup identifies a failure to remove the private host-build
// scratch directory. A cleanup failure always suppresses the returned fixture.
var ErrHostBuildCleanup = errors.New("qualification fixture host-build cleanup failed")

// HostBuildRequest is the complete input to the trusted synthetic fixture
// builder. Environment must be an explicit, duplicate-free environment whose
// PATH starts with the directory containing GitExecutable.
type HostBuildRequest struct {
	Root          string
	GoExecutable  string
	GitExecutable string
	Environment   []string
}

const (
	hostBuildScratchPrefix = ".repopass-qualification-host-build-"
	hostBuildOutputLimit   = 4096

	hostCanonicalModule = "github.com/taipei49314/RepoPassport"
	hostLegacyModule    = "github.com/repopass/repopass"

	hostFullLinuxName       = "repopass-linux-amd64"
	hostFullWindowsName     = "repopass-windows-amd64.exe"
	hostVerifierLinuxName   = "repopass-verify-linux-amd64"
	hostVerifierWindowsName = "repopass-verify-windows-amd64.exe"
	hostHelperName          = "repopass-kit-host.exe"
	hostLegacyVerifierName  = "legacy-repopass-verify-linux-amd64"
)

type hostBuildTool struct {
	path string
	info os.FileInfo
}

type hostBuildBinary struct {
	packagePath  string
	outputName   string
	goos         string
	source       string
	revision     string
	mainPath     string
	mainModule   string
	expectedArch string
}

type hostBuildEnvironmentValue struct {
	name  string
	value string
}

// BuildHost creates fixed synthetic canonical and legacy repositories beside
// Root, commits them with the pinned Git executable, builds the six fixture
// binaries with the pinned Go executable, and exports the verified fixture.
// It never loads or executes a package from the repository under qualification.
func BuildHost(
	ctx context.Context,
	request HostBuildRequest,
) (fixture *Fixture, resultErr error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("qualification fixture host-build context is invalid")
	}
	root, err := emptyRoot(request.Root)
	if err != nil {
		return nil, fmt.Errorf("qualification fixture host-build root is invalid: %w", err)
	}
	goTool, err := newHostBuildTool(request.GoExecutable, "go")
	if err != nil {
		return nil, err
	}
	gitTool, err := newHostBuildTool(request.GitExecutable, "git")
	if err != nil {
		return nil, err
	}
	baseEnvironment, err := hostBuildBaseEnvironment(request.Environment, gitTool.path)
	if err != nil {
		return nil, err
	}

	parent := filepath.Dir(root)
	scratch, err := os.MkdirTemp(parent, hostBuildScratchPrefix)
	if err != nil {
		return nil, errors.New("qualification fixture host-build scratch creation failed")
	}
	defer func() {
		if cleanupErr := os.RemoveAll(scratch); cleanupErr != nil {
			fixture = nil
			resultErr = errors.Join(resultErr, ErrHostBuildCleanup, cleanupErr)
		}
	}()
	if filepath.Dir(scratch) != parent {
		return nil, errors.New("qualification fixture host-build scratch is invalid")
	}
	scratchInfo, err := os.Lstat(scratch)
	if err != nil || !scratchInfo.IsDir() || scratchInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("qualification fixture host-build scratch is invalid")
	}

	canonicalRoot := filepath.Join(scratch, "canonical-source")
	legacyRoot := filepath.Join(scratch, "legacy-source")
	outputRoot := filepath.Join(scratch, "outputs")
	emptyHooks := filepath.Join(scratch, "empty-hooks")
	for _, directory := range []string{outputRoot, emptyHooks} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, errors.New("qualification fixture host-build directory creation failed")
		}
	}
	if err := createHostBuildModule(canonicalRoot, hostCanonicalModule); err != nil {
		return nil, errors.New("qualification fixture canonical source creation failed")
	}
	if err := createHostBuildModule(legacyRoot, hostLegacyModule); err != nil {
		return nil, errors.New("qualification fixture legacy source creation failed")
	}

	canonicalRevision, canonicalTree, err := initializeHostBuildRepository(
		ctx, gitTool, baseEnvironment, canonicalRoot, emptyHooks,
	)
	if err != nil {
		return nil, err
	}
	legacyRevision, _, err := initializeHostBuildRepository(
		ctx, gitTool, baseEnvironment, legacyRoot, emptyHooks,
	)
	if err != nil {
		return nil, err
	}

	builds := []hostBuildBinary{
		{
			packagePath: "./cmd/repopass",
			outputName:  hostFullLinuxName, goos: "linux", source: canonicalRoot,
			revision: canonicalRevision, mainPath: hostCanonicalModule + "/cmd/repopass",
			mainModule: hostCanonicalModule, expectedArch: "amd64",
		},
		{
			packagePath: "./cmd/repopass",
			outputName:  hostFullWindowsName, goos: "windows", source: canonicalRoot,
			revision: canonicalRevision, mainPath: hostCanonicalModule + "/cmd/repopass",
			mainModule: hostCanonicalModule, expectedArch: "amd64",
		},
		{
			packagePath: "./cmd/repopass-verify",
			outputName:  hostVerifierLinuxName, goos: "linux", source: canonicalRoot,
			revision: canonicalRevision, mainPath: hostCanonicalModule + "/cmd/repopass-verify",
			mainModule: hostCanonicalModule, expectedArch: "amd64",
		},
		{
			packagePath: "./cmd/repopass-verify",
			outputName:  hostVerifierWindowsName, goos: "windows", source: canonicalRoot,
			revision: canonicalRevision, mainPath: hostCanonicalModule + "/cmd/repopass-verify",
			mainModule: hostCanonicalModule, expectedArch: "amd64",
		},
		{
			packagePath: "./cmd/repopass-kit",
			outputName:  hostHelperName, goos: runtime.GOOS, source: canonicalRoot,
			revision: canonicalRevision, mainPath: hostCanonicalModule + "/cmd/repopass-kit",
			mainModule: hostCanonicalModule, expectedArch: "amd64",
		},
		{
			packagePath: "./cmd/repopass-verify",
			outputName:  hostLegacyVerifierName, goos: "linux", source: legacyRoot,
			revision: legacyRevision, mainPath: hostLegacyModule + "/cmd/repopass-verify",
			mainModule: hostLegacyModule, expectedArch: "amd64",
		},
	}
	inputs := make([]BinaryInput, 0, len(builds))
	for _, build := range builds {
		if ctx.Err() != nil || !goTool.verify() || !gitTool.verify() {
			return nil, errors.New("qualification fixture host-build tool binding changed")
		}
		output := filepath.Join(outputRoot, build.outputName)
		environment := hostBuildEnvironmentWithOverrides(baseEnvironment, map[string]string{
			"CGO_ENABLED": "0",
			"GOARCH":      build.expectedArch,
			"GOOS":        build.goos,
			"GOWORK":      "off",
		})
		if err := runHostBuildCommand(
			ctx,
			goTool.path,
			build.source,
			environment,
			"go-build",
			"build", "-buildvcs=true", "-trimpath", "-o", output, build.packagePath,
		); err != nil {
			return nil, err
		}
		inputs = append(inputs, BinaryInput{
			SourcePath:             output,
			RelativePath:           build.outputName,
			SourceRevision:         build.revision,
			ExpectedMainPath:       build.mainPath,
			ExpectedMainModulePath: build.mainModule,
			ExpectedGOOS:           build.goos,
			ExpectedGOARCH:         build.expectedArch,
		})
	}
	if ctx.Err() != nil || !goTool.verify() || !gitTool.verify() {
		return nil, errors.New("qualification fixture host-build tool binding changed")
	}

	fixture, err = Export(root, Spec{
		Revision:       canonicalRevision,
		Tree:           canonicalTree,
		LegacyRevision: legacyRevision,
		Binaries:       inputs,
	})
	if err != nil {
		return nil, fmt.Errorf("qualification fixture host export failed: %w", err)
	}
	return fixture, nil
}

func newHostBuildTool(path, logicalName string) (hostBuildTool, error) {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".exe")
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.ContainsAny(path, "\x00\r\n") || base != logicalName {
		return hostBuildTool{}, fmt.Errorf("qualification fixture host %s executable is invalid", logicalName)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 {
		return hostBuildTool{}, fmt.Errorf("qualification fixture host %s executable is invalid", logicalName)
	}
	return hostBuildTool{path: path, info: info}, nil
}

func (tool hostBuildTool) verify() bool {
	if tool.path == "" || tool.info == nil {
		return false
	}
	current, err := os.Lstat(tool.path)
	return err == nil && current.Mode().IsRegular() && current.Mode()&os.ModeSymlink == 0 &&
		current.Size() == tool.info.Size() && current.Mode() == tool.info.Mode() &&
		current.ModTime().Equal(tool.info.ModTime()) && os.SameFile(tool.info, current)
}

func hostBuildBaseEnvironment(environment []string, gitPath string) ([]string, error) {
	values, err := parseHostBuildEnvironment(environment)
	if err != nil {
		return nil, err
	}
	pathEntry, ok := values["PATH"]
	if !ok || pathEntry.value == "" {
		return nil, errors.New("qualification fixture host-build PATH is invalid")
	}
	parts := filepath.SplitList(pathEntry.value)
	gitDirectory := filepath.Dir(gitPath)
	if len(parts) == 0 || !sameHostBuildPath(parts[0], gitDirectory) {
		return nil, errors.New("qualification fixture host-build PATH is invalid")
	}
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" || !filepath.IsAbs(part) || filepath.Clean(part) != part ||
			strings.ContainsAny(part, "\x00\r\n") {
			return nil, errors.New("qualification fixture host-build PATH is invalid")
		}
		key := part
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("qualification fixture host-build PATH is invalid")
		}
		seen[key] = struct{}{}
	}

	for _, name := range []string{
		"GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_COMMON_DIR",
		"GIT_CONFIG",
		"GIT_CONFIG_PARAMETERS",
		"GIT_DIR",
		"GIT_EXEC_PATH",
		"GIT_INDEX_FILE",
		"GIT_NAMESPACE",
		"GIT_OBJECT_DIRECTORY",
		"GIT_TEMPLATE_DIR",
		"GIT_WORK_TREE",
	} {
		delete(values, name)
	}
	overrides := map[string]string{
		"CGO_ENABLED":            "0",
		"GIT_ATTR_NOSYSTEM":      "1",
		"GIT_CONFIG_COUNT":       "0",
		"GIT_CONFIG_GLOBAL":      os.DevNull,
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_CONFIG_SYSTEM":      os.DevNull,
		"GIT_LITERAL_PATHSPECS":  "1",
		"GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_OPTIONAL_LOCKS":     "0",
		"GIT_PAGER":              "",
		"GIT_TERMINAL_PROMPT":    "0",
		"GCM_INTERACTIVE":        "Never",
		"GOENV":                  "off",
		"GOFLAGS":                "",
		"GOPROXY":                "off",
		"GOSUMDB":                "off",
		"GOTOOLCHAIN":            "local",
		"GOVULNDB":               "off",
		"GOWORK":                 "off",
		"LANG":                   "C",
		"LC_ALL":                 "C",
		"PAGER":                  "",
		"PATH":                   strings.Join(parts, string(os.PathListSeparator)),
		"TZ":                     "UTC",
	}
	if runtime.GOOS == "windows" {
		overrides["PATHEXT"] = ".EXE"
	}
	for name, value := range overrides {
		values[name] = hostBuildEnvironmentValue{name: name, value: value}
	}
	return renderHostBuildEnvironment(values), nil
}

func parseHostBuildEnvironment(environment []string) (map[string]hostBuildEnvironmentValue, error) {
	if len(environment) == 0 {
		return nil, errors.New("qualification fixture host-build environment is invalid")
	}
	values := make(map[string]hostBuildEnvironmentValue, len(environment))
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		canonical := strings.ToUpper(name)
		if !ok || name == "" || strings.ContainsAny(name, "\x00\r\n") ||
			strings.ContainsAny(value, "\x00\r\n") {
			return nil, errors.New("qualification fixture host-build environment is invalid")
		}
		if _, duplicate := values[canonical]; duplicate {
			return nil, errors.New("qualification fixture host-build environment is invalid")
		}
		values[canonical] = hostBuildEnvironmentValue{name: name, value: value}
	}
	return values, nil
}

func hostBuildEnvironmentWithOverrides(environment []string, overrides map[string]string) []string {
	values, err := parseHostBuildEnvironment(environment)
	if err != nil {
		return nil
	}
	for name, value := range overrides {
		canonical := strings.ToUpper(name)
		values[canonical] = hostBuildEnvironmentValue{name: canonical, value: value}
	}
	return renderHostBuildEnvironment(values)
}

func renderHostBuildEnvironment(values map[string]hostBuildEnvironmentValue) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		value := values[name]
		result = append(result, value.name+"="+value.value)
	}
	return result
}

func sameHostBuildPath(left, right string) bool {
	if !filepath.IsAbs(left) || !filepath.IsAbs(right) || filepath.Clean(left) != left || filepath.Clean(right) != right {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func createHostBuildModule(root, module string) error {
	if err := os.Mkdir(root, 0o700); err != nil {
		return err
	}
	for _, command := range []string{"repopass", "repopass-verify", "repopass-kit"} {
		directory := filepath.Join(root, "cmd", command)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := writeExclusive(
			filepath.Join(directory, "main.go"),
			[]byte("package main\nfunc main() {}\n"),
			0o600,
		); err != nil {
			return err
		}
	}
	return writeExclusive(
		filepath.Join(root, "go.mod"),
		[]byte("module "+module+"\n\ngo 1.24\n"),
		0o600,
	)
}

func initializeHostBuildRepository(
	ctx context.Context,
	git hostBuildTool,
	environment []string,
	root string,
	emptyHooks string,
) (string, string, error) {
	commands := []struct {
		label string
		args  []string
	}{
		{label: "git-init", args: []string{"init", "-q", "--template="}},
		{label: "git-config-name", args: []string{"config", "--local", "user.name", "RepoPassport qualification test"}},
		{label: "git-config-email", args: []string{"config", "--local", "user.email", "qualification@example.invalid"}},
		{label: "git-add", args: []string{"add", "--", "."}},
		{
			label: "git-commit",
			args: []string{
				"-c", "core.hooksPath=" + emptyHooks,
				"commit", "-q", "--no-gpg-sign", "--no-verify", "-m", "fixture",
			},
		},
	}
	for _, command := range commands {
		if ctx.Err() != nil || !git.verify() {
			return "", "", errors.New("qualification fixture host-build tool binding changed")
		}
		if err := runHostBuildCommand(
			ctx, git.path, root, environment, command.label, command.args...,
		); err != nil {
			return "", "", err
		}
	}
	revision, err := runHostBuildIdentityCommand(
		ctx, git.path, root, environment, "git-revision", "rev-parse", "HEAD",
	)
	if err != nil {
		return "", "", err
	}
	tree, err := runHostBuildIdentityCommand(
		ctx, git.path, root, environment, "git-tree", "rev-parse", "HEAD^{tree}",
	)
	if err != nil {
		return "", "", err
	}
	return revision, tree, nil
}

func runHostBuildCommand(
	ctx context.Context,
	application string,
	directory string,
	environment []string,
	label string,
	args ...string,
) error {
	command := exec.CommandContext(ctx, application, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("qualification fixture host %s command failed", label)
	}
	return nil
}

func runHostBuildIdentityCommand(
	ctx context.Context,
	application string,
	directory string,
	environment []string,
	label string,
	args ...string,
) (string, error) {
	output := &hostBuildOutput{}
	command := exec.CommandContext(ctx, application, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.overflow {
		return "", fmt.Errorf("qualification fixture host %s command failed", label)
	}
	identity := strings.TrimSpace(string(output.data))
	if !validObjectID(identity) {
		return "", fmt.Errorf("qualification fixture host %s output is invalid", label)
	}
	return identity, nil
}

type hostBuildOutput struct {
	data     []byte
	overflow bool
}

func (output *hostBuildOutput) Write(value []byte) (int, error) {
	length := len(value)
	remaining := hostBuildOutputLimit - len(output.data)
	if remaining < len(value) {
		output.overflow = true
		if remaining > 0 {
			output.data = append(output.data, value[:remaining]...)
		}
		return length, nil
	}
	output.data = append(output.data, value...)
	return length, nil
}
