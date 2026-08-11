package sourcequalification

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const controllerRuntimeFactLimit int64 = 4096

var errAuthenticatedLaneAttemptHistoryUnavailable = errors.New(
	"authenticated source qualification attempt history is unavailable",
)

// unavailableLaneAttemptHistoryProvider is the only production provider until
// an authenticated GitHub history adapter is added. It deliberately reads no
// token or environment value and can never authorize an ordinal-1 attempt.
type unavailableLaneAttemptHistoryProvider struct{}

func (unavailableLaneAttemptHistoryProvider) HasPriorExecution(
	context.Context,
	laneAttemptHistoryScope,
) (bool, error) {
	return false, errAuthenticatedLaneAttemptHistoryUnavailable
}

// verifiedLaneAttemptHistoryProvider carries one complete authenticated
// answer across the production preflight into the lane producer without a
// second external query. A scope mismatch fails closed.
type verifiedLaneAttemptHistoryProvider struct {
	scope laneAttemptHistoryScope
	prior bool
}

func (provider verifiedLaneAttemptHistoryProvider) HasPriorExecution(
	ctx context.Context,
	scope laneAttemptHistoryScope,
) (bool, error) {
	if ctx == nil || ctx.Err() != nil || scope != provider.scope {
		return false, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	return provider.prior, nil
}

type productionLaneRepositoryInspector struct{}

func (productionLaneRepositoryInspector) InspectRepository(
	request RepositoryRequest,
) (RepositorySnapshot, error) {
	return InspectRepository(request)
}

type productionLaneClock struct{}

func (productionLaneClock) Now() time.Time { return time.Now() }

type productionLaneSelfController struct {
	path           string
	expectedGOOS   string
	testedRevision string
}

func (inspector productionLaneSelfController) InspectSelfController() (receiptController, error) {
	identity, _, err := inspectQualificationController(
		inspector.path,
		inspector.expectedGOOS,
		inspector.testedRevision,
	)
	return identity, err
}

type productionGateLogSink struct {
	root    string
	gateIDs []string
	written int
}

func newProductionGateLogSink(root string, lane Lane) (*productionGateLogSink, error) {
	if err := requirePrivatePackageDirectory(root); err != nil {
		return nil, err
	}
	registry := RequiredGates(lane)
	if len(registry) == 0 {
		return nil, errGateInvalidInput
	}
	result := &productionGateLogSink{root: root, gateIDs: make([]string, len(registry))}
	for index, gate := range registry {
		result.gateIDs[index] = gate.ID
	}
	return result, nil
}

func (sink *productionGateLogSink) WriteGateLog(id string, stdout, stderr []byte) error {
	if sink == nil || sink.written >= len(sink.gateIDs) || sink.gateIDs[sink.written] != id ||
		int64(len(stdout)) > maximumGateOutputBytes || int64(len(stderr)) > maximumGateOutputBytes ||
		requirePrivatePackageDirectory(sink.root) != nil {
		return errGateFailed
	}
	ordinal := sink.written + 1
	prefix := "gate-" + strconv.Itoa(ordinal)
	if ordinal < 10 {
		prefix = "gate-0" + strconv.Itoa(ordinal)
	}
	if err := writeControllerPrivateFile(filepath.Join(sink.root, prefix+"-stdout.log"), stdout); err != nil {
		return errGateFailed
	}
	if err := writeControllerPrivateFile(filepath.Join(sink.root, prefix+"-stderr.log"), stderr); err != nil {
		return errGateFailed
	}
	sink.written++
	return nil
}

func writeControllerPrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errGateFailed
	}
	if err := securePrivatePackagePath(path, false); err != nil {
		_ = file.Close()
		return errGateFailed
	}
	info, statErr := file.Stat()
	permissionsErr := error(nil)
	if statErr == nil {
		permissionsErr = validatePrivatePackagePermissions(file, info, false)
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if statErr != nil || permissionsErr != nil || writeErr != nil || written != len(data) ||
		syncErr != nil || closeErr != nil {
		return errGateFailed
	}
	return nil
}

type productionLaneConfiguration struct {
	laneRequest  qualificationLaneRequest
	dependencies qualificationLaneDependencies
}

func produceControllerLaneStage(
	ctx context.Context,
	request ProduceLaneRequest,
) (produceLaneStageOutcome, *qualificationReceipt, error) {
	historyScope := productionLaneAttemptHistoryScope(request)
	prior, historyErr := (unavailableLaneAttemptHistoryProvider{}).HasPriorExecution(
		ctx,
		historyScope,
	)
	if historyErr != nil {
		return produceLaneStageOutcome{
			QualificationStatus: StatusBlocked,
			Code:                controllerCodeGateBlocked,
		}, nil, errGateBlocked
	}
	if prior {
		return produceLaneStageOutcome{
			QualificationStatus: StatusFail,
			Code:                controllerCodeGateFailed,
		}, nil, errGateFailed
	}
	configuration, err := buildProductionLaneConfiguration(
		ctx,
		request,
		verifiedLaneAttemptHistoryProvider{scope: historyScope, prior: prior},
	)
	if err != nil {
		return produceLaneStageOutcome{
			QualificationStatus: StatusFail,
			Code:                controllerCodeInvalidInput,
		}, nil, errQualificationLaneInvalidInput
	}

	status, laneErr := produceQualificationLane(
		ctx,
		configuration.laneRequest,
		configuration.dependencies,
	)
	code := ""
	if laneErr != nil {
		code = qualificationLaneErrorCode(laneErr, status)
	}
	outcome := produceLaneStageOutcome{
		QualificationStatus: status,
		Code:                code,
	}

	read, readErr := readQualificationLaneDirectory(request.OutputDir, request.Lane, nil, nil)
	if readErr != nil {
		if laneErr == nil {
			return produceLaneStageOutcome{
				QualificationStatus: StatusFail,
				Code:                controllerCodeReceiptInvalid,
			}, nil, errQualificationLaneReceiptInvalid
		}
		return outcome, nil, laneErr
	}
	receiptName, ok := qualificationLaneReceiptName(request.Lane)
	if !ok {
		return produceLaneStageOutcome{
			QualificationStatus: StatusFail,
			Code:                controllerCodeReceiptInvalid,
		}, nil, errQualificationLaneReceiptInvalid
	}
	receipt, parseErr := parseCanonicalReceipt(read.files[receiptName], request.Lane)
	if parseErr != nil || receipt.QualificationStatus != status ||
		receipt.Subject.BaseRevision != request.ExpectedBaseRevision ||
		receipt.Subject.TestedRevision != request.ExpectedTestedRevision ||
		receipt.Run.WorkflowRunID != request.WorkflowRunID ||
		receipt.Run.WorkflowRunAttempt != request.WorkflowRunAttempt {
		return produceLaneStageOutcome{
			QualificationStatus: StatusFail,
			Code:                controllerCodeReceiptInvalid,
		}, nil, errQualificationLaneReceiptInvalid
	}
	outcome.StageReady = true
	outcome.TestedRevision = receipt.Subject.TestedRevision
	outcome.TreeSHA = receipt.Subject.TreeSHA
	return outcome, &receipt, laneErr
}

func buildProductionLaneConfiguration(
	ctx context.Context,
	request ProduceLaneRequest,
	history laneAttemptHistoryProvider,
) (productionLaneConfiguration, error) {
	if ctx == nil || ctx.Err() != nil ||
		history == nil || nilGateDependency(history) ||
		(request.Lane == LaneLinuxAMD64 && runtime.GOOS != "linux") ||
		(request.Lane == LaneWindowsAMD64 && runtime.GOOS != "windows") ||
		runtime.GOARCH != "amd64" {
		return productionLaneConfiguration{}, errQualificationLaneInvalidInput
	}

	workspace := request.PrivateLogRoot
	if err := requirePrivatePackageDirectory(workspace); err != nil {
		return productionLaneConfiguration{}, errQualificationLaneInvalidInput
	}
	directories, err := createControllerRuntimeDirectories(workspace)
	if err != nil {
		return productionLaneConfiguration{}, errQualificationLaneInvalidInput
	}
	applications, factApplications, toolPath, selfPath, err := resolveControllerRuntimeApplications(
		request.RepoRoot,
		request.Lane,
	)
	if err != nil {
		return productionLaneConfiguration{}, errQualificationLaneInvalidInput
	}
	systemRoot := ""
	if runtime.GOOS == "windows" {
		systemRoot, err = controllerRuntimeSystemRoot(request.RepoRoot)
		if err != nil {
			return productionLaneConfiguration{}, errQualificationLaneInvalidInput
		}
	}
	environment := gateRunEnvironment{
		ToolPath:                 toolPath,
		HomeDir:                  directories["home"],
		GoCacheDir:               directories["go-cache"],
		GoModCacheDir:            directories["go-mod-cache"],
		TempDir:                  directories["tmp"],
		GoProxy:                  "https://proxy.golang.org",
		GoSumDB:                  "sum.golang.org",
		VulnerabilityDatabaseURL: "https://vuln.go.dev",
		SystemRoot:               systemRoot,
	}
	platform, err := collectControllerRuntimePlatform(
		ctx,
		request,
		factApplications,
		environment,
	)
	if err != nil {
		return productionLaneConfiguration{}, errQualificationLaneInvalidInput
	}
	logs, err := newProductionGateLogSink(workspace, request.Lane)
	if err != nil {
		return productionLaneConfiguration{}, errQualificationLaneInvalidInput
	}

	laneRequest := qualificationLaneRequest{
		Repository: RepositoryRequest{
			Root:                   request.RepoRoot,
			ExpectedBaseRevision:   request.ExpectedBaseRevision,
			ExpectedTestedRevision: request.ExpectedTestedRevision,
		},
		Gate: gateRunRequest{
			Lane:           request.Lane,
			TestedRevision: request.ExpectedTestedRevision,
			RepositoryRoot: request.RepoRoot,
			GOOS:           runtime.GOOS,
			GOARCH:         runtime.GOARCH,
			Applications:   applications,
			Environment:    environment,
		},
		Run: RunIdentity{
			WorkflowRepository: canonicalWorkflowRepository,
			WorkflowPath:       canonicalWorkflowPath,
			Event:              request.Event,
			Ref:                request.ExpectedRef,
			WorkflowRunID:      request.WorkflowRunID,
			WorkflowRunAttempt: int(request.WorkflowRunAttempt),
			TestedRevision:     request.ExpectedTestedRevision,
		},
		Platform:  platform,
		OutputDir: request.OutputDir,
	}
	return productionLaneConfiguration{
		laneRequest: laneRequest,
		dependencies: qualificationLaneDependencies{
			Repository: productionLaneRepositoryInspector{},
			Executor:   newOSGateExecutor(),
			Clock:      productionLaneClock{},
			SelfController: productionLaneSelfController{
				path:           selfPath,
				expectedGOOS:   runtime.GOOS,
				testedRevision: request.ExpectedTestedRevision,
			},
			PrivateLogs:    logs,
			AttemptHistory: history,
		},
	}, nil
}

func productionLaneAttemptHistoryScope(request ProduceLaneRequest) laneAttemptHistoryScope {
	return laneAttemptHistoryScope{
		WorkflowRepository:     canonicalWorkflowRepository,
		WorkflowPath:           canonicalWorkflowPath,
		TestedRevision:         request.ExpectedTestedRevision,
		Lane:                   request.Lane,
		CurrentWorkflowRunID:   request.WorkflowRunID,
		CurrentWorkflowAttempt: request.WorkflowRunAttempt,
	}
}

func createControllerRuntimeDirectories(root string) (map[string]string, error) {
	names := []string{"go-cache", "go-mod-cache", "home", "tmp"}
	result := make(map[string]string, len(names))
	for _, name := range names {
		path := filepath.Join(root, name)
		if filepath.Dir(path) != root || os.Mkdir(path, 0o700) != nil ||
			securePrivatePackagePath(path, true) != nil || requirePrivatePackageDirectory(path) != nil {
			return nil, errQualificationWorkspaceCreate
		}
		result[name] = path
	}
	return result, nil
}

func resolveControllerRuntimeApplications(
	repositoryRoot string,
	lane Lane,
) (map[string]string, map[string]string, string, string, error) {
	registry := RequiredGates(lane)
	if len(registry) == 0 {
		return nil, nil, "", "", errGateInvalidInput
	}
	selfPath, err := os.Executable()
	if err != nil {
		return nil, nil, "", "", errGateInvalidInput
	}
	selfPath, err = trustedControllerRuntimePath(repositoryRoot, selfPath)
	if err != nil {
		return nil, nil, "", "", errGateInvalidInput
	}

	required := make(map[string]struct{})
	for _, gate := range registry {
		if len(gate.Argv) == 0 {
			return nil, nil, "", "", errGateInvalidInput
		}
		required[gate.Argv[0]] = struct{}{}
	}
	applications := make(map[string]string, len(required))
	all := make(map[string]string, len(required)+2)
	for name := range required {
		path := selfPath
		if name != "repopass-source-qualify" {
			path, err = resolveControllerRuntimeApplication(repositoryRoot, name)
			if err != nil {
				return nil, nil, "", "", errGateInvalidInput
			}
		}
		applications[name] = path
		all[name] = path
	}
	for _, name := range []string{"git", "uname"} {
		if name == "uname" && runtime.GOOS == "windows" {
			continue
		}
		path, err := resolveControllerRuntimeApplication(repositoryRoot, name)
		if err != nil {
			return nil, nil, "", "", errGateInvalidInput
		}
		all[name] = path
	}

	directorySet := make(map[string]struct{}, len(all))
	for _, path := range all {
		directorySet[filepath.Dir(path)] = struct{}{}
	}
	directories := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool {
		return strings.ToLower(directories[left]) < strings.ToLower(directories[right])
	})
	return applications, all, strings.Join(directories, string(os.PathListSeparator)), selfPath, nil
}

func resolveControllerRuntimeApplication(repositoryRoot, name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", errGateInvalidInput
	}
	return trustedControllerRuntimePath(repositoryRoot, path)
}

func trustedControllerRuntimePath(repositoryRoot, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errGateInvalidInput
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || !filepath.IsAbs(resolved) || pathWithinRepository(repositoryRoot, resolved) {
		return "", errGateInvalidInput
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && (info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0)) {
		return "", errGateInvalidInput
	}
	return filepath.Clean(resolved), nil
}

func controllerRuntimeSystemRoot(repositoryRoot string) (string, error) {
	value, ok := os.LookupEnv("SystemRoot")
	if !ok || value == "" {
		return "", errGateInvalidInput
	}
	path, err := filepath.Abs(value)
	if err != nil {
		return "", errGateInvalidInput
	}
	path = filepath.Clean(path)
	if !validGateExternalDirectory(repositoryRoot, path) {
		return "", errGateInvalidInput
	}
	return path, nil
}

func collectControllerRuntimePlatform(
	ctx context.Context,
	request ProduceLaneRequest,
	applications map[string]string,
	environment gateRunEnvironment,
) (receiptPlatform, error) {
	goLine, err := controllerRuntimeFact(
		ctx,
		applications["go"],
		[]string{"version"},
		request.PrivateLogRoot,
		controllerRuntimeFactEnvironment(environment),
	)
	wantGoLine := "go version " + receiptGoVersion + " " + runtime.GOOS + "/" + runtime.GOARCH
	if err != nil || goLine != wantGoLine {
		return receiptPlatform{}, errGateInvalidInput
	}
	gitVersion, err := controllerRuntimeFact(
		ctx,
		applications["git"],
		[]string{"--version"},
		request.PrivateLogRoot,
		controllerRuntimeFactEnvironment(environment),
	)
	if err != nil || !strings.HasPrefix(gitVersion, "git version ") {
		return receiptPlatform{}, errGateInvalidInput
	}
	powerShellVersion, err := controllerRuntimeFact(
		ctx,
		applications["pwsh"],
		[]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"},
		request.PrivateLogRoot,
		controllerRuntimeFactEnvironment(environment),
	)
	if err != nil {
		return receiptPlatform{}, errGateInvalidInput
	}

	kernelApplication := applications["uname"]
	kernelArguments := []string{"-r"}
	if runtime.GOOS == "windows" {
		kernelApplication = applications["pwsh"]
		kernelArguments = []string{
			"-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
			"[Environment]::OSVersion.Version.ToString()",
		}
	}
	kernelVersion, err := controllerRuntimeFact(
		ctx,
		kernelApplication,
		kernelArguments,
		request.PrivateLogRoot,
		controllerRuntimeFactEnvironment(environment),
	)
	if err != nil {
		return receiptPlatform{}, errGateInvalidInput
	}

	runnerImage, imageOK := os.LookupEnv("ImageOS")
	runnerImageVersion, versionOK := os.LookupEnv("ImageVersion")
	runnerOS, osOK := os.LookupEnv("RUNNER_OS")
	runnerArch, archOK := os.LookupEnv("RUNNER_ARCH")
	if !imageOK || !versionOK || !osOK || !archOK {
		return receiptPlatform{}, errGateInvalidInput
	}
	platform := receiptPlatform{
		GitVersion:         gitVersion,
		GoVersion:          receiptGoVersion,
		GOARCH:             runtime.GOARCH,
		GOOS:               runtime.GOOS,
		KernelVersion:      kernelVersion,
		PowerShellVersion:  powerShellVersion,
		RunnerArch:         runnerArch,
		RunnerImage:        runnerImage,
		RunnerImageVersion: runnerImageVersion,
		RunnerOS:           runnerOS,
	}
	if validateReceiptPlatform(platform, request.Lane) != nil || validateReceiptPrivacy(platform) != nil {
		return receiptPlatform{}, errGateInvalidInput
	}
	return platform, nil
}

func controllerRuntimeFactEnvironment(configuration gateRunEnvironment) []string {
	result := []string{
		"PATH=" + configuration.ToolPath,
		"HOME=" + configuration.HomeDir,
		"USERPROFILE=" + configuration.HomeDir,
		"TMPDIR=" + configuration.TempDir,
		"TMP=" + configuration.TempDir,
		"TEMP=" + configuration.TempDir,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"GOWORK=off",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOFLAGS=",
		"GOTELEMETRY=off",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=" + os.DevNull,
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
	}
	if configuration.SystemRoot != "" {
		result = append(result,
			"SYSTEMROOT="+configuration.SystemRoot,
			"WINDIR="+configuration.SystemRoot,
		)
	}
	return result
}

func controllerRuntimeFact(
	ctx context.Context,
	application string,
	args []string,
	directory string,
	environment []string,
) (string, error) {
	if application == "" {
		return "", errGateInvalidInput
	}
	result, err := newOSGateExecutor().Execute(ctx, gateProcessRequest{
		Application: application,
		Args:        append([]string(nil), args...),
		Dir:         directory,
		Env:         append([]string(nil), environment...),
		Network:     NetworkNone,
		Timeout:     30 * time.Second,
		StdoutLimit: controllerRuntimeFactLimit,
		StderrLimit: controllerRuntimeFactLimit,
	})
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 || result.Blocked ||
		result.TimedOut || result.Cancelled || result.StdoutOverflow || result.StderrOverflow ||
		result.CleanupFailed || len(result.Stderr) != 0 {
		return "", errGateInvalidInput
	}
	line := string(result.Stdout)
	switch {
	case strings.HasSuffix(line, "\r\n"):
		line = strings.TrimSuffix(line, "\r\n")
	case strings.HasSuffix(line, "\n"):
		line = strings.TrimSuffix(line, "\n")
	default:
		return "", errGateInvalidInput
	}
	if !validReceiptPrintableASCII(line, receiptMaxPlatformBytes) || strings.ContainsAny(line, "\r\n") {
		return "", errGateInvalidInput
	}
	return line, nil
}
