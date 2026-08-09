package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/taipei49314/RepoPassport/internal/controllerfs"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/runtimepolicy"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	containerUser       = "65532:65532"
	containerDriverUser = "65533:65533"
	containerSource     = "/source"
	containerWorkspace  = "/workspace"
	containerOutputs    = "/outputs"
	runLabelKey         = "dev.repopass.run"
	phaseLabelKey       = "dev.repopass.phase"
)

var exactRuntimeVersionPattern = regexp.MustCompile(
	`^[0-9]+\.[0-9]+\.[0-9]+$`,
)

type Config struct {
	DoctorTimeout        time.Duration
	DoctorOutputBytes    int64
	PrepareTimeout       time.Duration
	CreateTimeout        time.Duration
	CleanupTimeout       time.Duration
	ExportTimeout        time.Duration
	DefaultStepTimeout   time.Duration
	MaxStepTimeout       time.Duration
	MaxLogBytes          int64
	MaxHTTPControlBytes  int64
	MaxHTTPRequestBytes  int64
	MaxHTTPResponseBytes int64
	MaxHTTPHeaderBytes   int64
	MaxSourceFiles       int
	MaxSourceBytes       int64
	MaxDiskBytes         int64
	MaxPIDs              int
	MaxMemoryBytes       int64
	MaxCPUMillis         int64
	TemporaryBytes       int64
}

func DefaultConfig() Config {
	return Config{
		DoctorTimeout:        15 * time.Second,
		DoctorOutputBytes:    1 << 20,
		PrepareTimeout:       2 * time.Minute,
		CreateTimeout:        30 * time.Second,
		CleanupTimeout:       15 * time.Second,
		ExportTimeout:        2 * time.Minute,
		DefaultStepTimeout:   5 * time.Minute,
		MaxStepTimeout:       30 * time.Minute,
		MaxLogBytes:          4 << 20,
		MaxHTTPControlBytes:  2 << 20,
		MaxHTTPRequestBytes:  1 << 20,
		MaxHTTPResponseBytes: 1 << 20,
		MaxHTTPHeaderBytes:   64 << 10,
		MaxSourceFiles:       100_000,
		MaxSourceBytes:       2 << 30,
		MaxDiskBytes:         2 << 30,
		MaxPIDs:              4096,
		MaxMemoryBytes:       64 << 30,
		MaxCPUMillis:         64_000,
		TemporaryBytes:       64 << 20,
	}
}

type Runner struct {
	executor              CommandExecutor
	config                Config
	idGenerator           func() (string, error)
	cleanupTokenKeyReader io.Reader
	now                   func() time.Time
}

func NewRunner(executor CommandExecutor, config Config) *Runner {
	if executor == nil {
		executor = OSCommandExecutor{}
	}
	return &Runner{
		executor:              executor,
		config:                normalizedConfig(config),
		idGenerator:           secureRunID,
		cleanupTokenKeyReader: rand.Reader,
		now:                   time.Now,
	}
}

func normalizedConfig(config Config) Config {
	defaults := DefaultConfig()
	if config.DoctorTimeout <= 0 {
		config.DoctorTimeout = defaults.DoctorTimeout
	}
	if config.DoctorOutputBytes <= 0 {
		config.DoctorOutputBytes = defaults.DoctorOutputBytes
	}
	if config.PrepareTimeout <= 0 {
		config.PrepareTimeout = defaults.PrepareTimeout
	}
	if config.CreateTimeout <= 0 {
		config.CreateTimeout = defaults.CreateTimeout
	}
	if config.CleanupTimeout <= 0 {
		config.CleanupTimeout = defaults.CleanupTimeout
	}
	if config.ExportTimeout <= 0 {
		config.ExportTimeout = defaults.ExportTimeout
	}
	if config.DefaultStepTimeout <= 0 {
		config.DefaultStepTimeout = defaults.DefaultStepTimeout
	}
	if config.MaxStepTimeout <= 0 {
		config.MaxStepTimeout = defaults.MaxStepTimeout
	}
	if config.MaxLogBytes <= 0 {
		config.MaxLogBytes = defaults.MaxLogBytes
	}
	if config.MaxHTTPControlBytes <= 0 {
		config.MaxHTTPControlBytes = defaults.MaxHTTPControlBytes
	}
	if config.MaxHTTPRequestBytes <= 0 {
		config.MaxHTTPRequestBytes = defaults.MaxHTTPRequestBytes
	}
	if config.MaxHTTPResponseBytes <= 0 {
		config.MaxHTTPResponseBytes = defaults.MaxHTTPResponseBytes
	}
	if config.MaxHTTPHeaderBytes <= 0 {
		config.MaxHTTPHeaderBytes = defaults.MaxHTTPHeaderBytes
	}
	if config.MaxSourceFiles <= 0 {
		config.MaxSourceFiles = defaults.MaxSourceFiles
	}
	if config.MaxSourceBytes <= 0 {
		config.MaxSourceBytes = defaults.MaxSourceBytes
	}
	if config.MaxDiskBytes <= 0 {
		config.MaxDiskBytes = defaults.MaxDiskBytes
	}
	if config.MaxPIDs <= 0 {
		config.MaxPIDs = defaults.MaxPIDs
	}
	if config.MaxMemoryBytes <= 0 {
		config.MaxMemoryBytes = defaults.MaxMemoryBytes
	}
	if config.MaxCPUMillis <= 0 {
		config.MaxCPUMillis = defaults.MaxCPUMillis
	}
	if config.TemporaryBytes <= 0 {
		config.TemporaryBytes = defaults.TemporaryBytes
	}
	return config
}

type InputMount struct {
	Name          string `json:"name"`
	SourcePath    string `json:"-"`
	ContainerPath string `json:"containerPath"`
	Type          string `json:"type"`
	ReadOnly      bool   `json:"readOnly"`
}

type PreparedRun struct {
	Plan                  domain.ResolvedPlan   `json:"plan"`
	Runner                domain.RunnerFeatures `json:"runner"`
	Backend               string                `json:"backend"`
	Platform              string                `json:"platform"`
	RunID                 string                `json:"runId"`
	RunDir                string                `json:"runDir"`
	SourceSnapshotDir     string                `json:"sourceSnapshotDir"`
	WorkspaceDir          string                `json:"workspaceDir"`
	OutputsDir            string                `json:"outputsDir"`
	Inputs                []InputMount          `json:"inputs,omitempty"`
	IncompleteFeatures    []string              `json:"incompleteFeatures,omitempty"`
	executionPlan         domain.ResolvedPlan
	executionPlanSealed   bool
	structuredJSONSchemas map[structuredJSONSchemaBinding]*structuredjson.Schema
	steps                 []preparedStep
}

type preparedStep struct {
	command  domain.PlanCommand
	timeout  time.Duration
	position int
}

type StepResult struct {
	ID               string           `json:"id"`
	Phase            domain.Phase     `json:"phase"`
	Role             string           `json:"role"`
	ExitCode         int              `json:"exitCode"`
	Stdout           []byte           `json:"stdout,omitempty"`
	Stderr           []byte           `json:"stderr,omitempty"`
	Duration         time.Duration    `json:"duration"`
	LogBytes         int64            `json:"logBytes"`
	LogTruncated     bool             `json:"logTruncated"`
	TimedOut         bool             `json:"timedOut"`
	ContainerName    string           `json:"containerName"`
	CleanupAttempted bool             `json:"cleanupAttempted"`
	CleanupSucceeded bool             `json:"cleanupSucceeded"`
	ErrorCode        domain.ErrorCode `json:"errorCode,omitempty"`
}

type Outcome struct {
	RunID              string                    `json:"runId"`
	RunDir             string                    `json:"runDir"`
	WorkspaceDir       string                    `json:"workspaceDir"`
	OutputsDir         string                    `json:"outputsDir"`
	Runner             domain.RunnerFeatures     `json:"runner"`
	IncompleteFeatures []string                  `json:"incompleteFeatures,omitempty"`
	Steps              []StepResult              `json:"steps"`
	Observations       []domain.ObservationEvent `json:"observations"`
	Assertions         []domain.AssertionResult  `json:"assertions"`
	Errors             []*domain.Error           `json:"errors,omitempty"`
	Resources          domain.ResourceSummary    `json:"resources"`
	Cleanup            domain.CleanupVerdict     `json:"cleanup"`
	StartedAt          time.Time                 `json:"startedAt"`
	CompletedAt        time.Time                 `json:"completedAt"`
}

func Execute(
	ctx context.Context,
	plan domain.ResolvedPlan,
	sourceRoot string,
	runRoot string,
	backendName string,
) (Outcome, error) {
	return NewRunner(OSCommandExecutor{}, DefaultConfig()).Execute(
		ctx,
		plan,
		sourceRoot,
		runRoot,
		backendName,
	)
}

func (r *Runner) Execute(
	ctx context.Context,
	plan domain.ResolvedPlan,
	sourceRoot string,
	runRoot string,
	backendName string,
) (Outcome, error) {
	prepared, err := r.Prepare(ctx, plan, sourceRoot, runRoot, backendName)
	if err != nil {
		return Outcome{}, err
	}
	return r.Run(ctx, prepared)
}

func (r *Runner) Prepare(
	ctx context.Context,
	plan domain.ResolvedPlan,
	sourceRoot string,
	runRoot string,
	backendName string,
) (*PreparedRun, error) {
	executionPlan := clonePlan(plan)
	steps, platform, err := r.validatePlan(executionPlan)
	if err != nil {
		return nil, err
	}

	features, err := r.Doctor(ctx, backendName)
	if err != nil {
		return nil, err
	}
	negotiation, err := NegotiateFeatures(
		executionPlan.RequiredRunnerFeatures,
		features,
	)
	if err != nil {
		return nil, err
	}

	runID, err := r.idGenerator()
	if err != nil {
		return nil, domain.WrapError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityCritical,
			"Cryptographically random run ID generation failed.",
			err,
		)
	}
	if !safeRunID(runID) {
		return nil, domain.NewError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityCritical,
			"Generated run ID is not safe for a container name.",
		)
	}

	prepareCtx, cancel := context.WithTimeout(ctx, r.config.PrepareTimeout)
	defer cancel()
	paths, err := r.prepareFilesystem(
		prepareCtx,
		sourceRoot,
		runRoot,
		runID,
		executionPlan.Source.TreeDigest,
	)
	if err != nil {
		return nil, err
	}
	structuredJSONSchemas, err := r.prepareStructuredJSONSchemas(
		executionPlan,
		paths.snapshotDir,
		paths.runDir,
	)
	if err != nil {
		return nil, err
	}
	inputs, err := prepareInputs(executionPlan.Inputs, paths.snapshotDir)
	if err != nil {
		cleanupErr := controllerfs.RemoveTree(paths.runDir)
		return nil, errors.Join(err, cleanupErr)
	}

	return &PreparedRun{
		Plan:                  clonePlan(executionPlan),
		Runner:                features,
		Backend:               strings.ToLower(strings.TrimSpace(backendName)),
		Platform:              platform,
		RunID:                 runID,
		RunDir:                paths.runDir,
		SourceSnapshotDir:     paths.snapshotDir,
		WorkspaceDir:          paths.workspaceDir,
		OutputsDir:            paths.outputsDir,
		Inputs:                inputs,
		IncompleteFeatures:    cloneStrings(negotiation.Incomplete),
		executionPlan:         executionPlan,
		executionPlanSealed:   true,
		structuredJSONSchemas: structuredJSONSchemas,
		steps:                 steps,
	}, nil
}

func (r *Runner) validatePlan(
	plan domain.ResolvedPlan,
) ([]preparedStep, string, error) {
	if plan.SchemaVersion != "4" {
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Execution requires resolved-plan schema version 4.",
		)
	}
	if !validResolvedEvidence(plan.Evidence) {
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Execution requires the exact resolved minimal-public evidence contract.",
		)
	}
	if plan.Cleanup.ClassifierVersion != cleanupClassifierVersion ||
		plan.Cleanup.AllowedResidue == nil ||
		len(plan.Cleanup.AllowedResidue) > 1 ||
		len(plan.Cleanup.AllowedResidue) == 1 &&
			plan.Cleanup.AllowedResidue[0] != "/outputs/**" {
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Execution requires the resolved cleanup classifier and exact allowed-residue contract.",
		)
	}
	cleanupFeatureCount := 0
	for _, feature := range plan.RequiredRunnerFeatures {
		if feature == "cleanup-residue-classification" {
			cleanupFeatureCount++
		}
	}
	if cleanupFeatureCount != 1 {
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Execution requires exactly one cleanup-residue-classification runner feature.",
		)
	}
	switch plan.JourneyDriver {
	case "cli":
		if plan.JourneyDriverVersion != "0.2.0" {
			return nil, "", domain.NewError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Execution requires CLI journey driver version 0.2.0.",
			)
		}
	case "http":
		if plan.JourneyDriverVersion != "0.1.0" {
			return nil, "", domain.NewError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Execution requires HTTP journey driver version 0.1.0.",
			)
		}
	default:
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Execution requires a supported journey driver.",
		)
	}
	if !validDigest(plan.BaseImageDigest) ||
		!validPinnedImageReference(plan.BaseImageReference, plan.BaseImageDigest) {
		err := domain.NewError(
			domain.CodeMutableBaseImage,
			domain.SeverityCritical,
			"Execution requires a full digest-pinned image reference.",
		)
		err.Details = map[string]any{
			"reference": plan.BaseImageReference,
			"digest":    plan.BaseImageDigest,
		}
		return nil, "", err
	}
	if strings.TrimSpace(plan.PlanDigest) == "" ||
		strings.TrimSpace(plan.Source.TreeDigest) == "" {
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Execution requires resolved plan and source tree digests.",
		)
	}
	if !exactRuntimeVersionPattern.MatchString(plan.RuntimeVersion) {
		return nil, "", domain.NewError(
			domain.CodeRuntimeVersionUnresolved,
			domain.SeverityHigh,
			"Execution requires an exact runtime version bound into the resolved plan.",
		)
	}
	if _, ok := runtimeExecutable(plan.RuntimeAdapter); !ok {
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Resolved runtime adapter has no trusted local runner implementation.",
		)
		err.Details = map[string]any{"runtimeAdapter": plan.RuntimeAdapter}
		return nil, "", err
	}
	platform, err := requiredPlanPlatform(plan.RequiredRunnerFeatures)
	if err != nil {
		return nil, "", err
	}
	if policyErr := runtimepolicy.Validate(
		plan.RuntimeAdapter,
		plan.RuntimeVersion,
		plan.BaseImageReference,
		plan.BaseImageDigest,
		platform,
	); policyErr != nil {
		return nil, "", policyErr
	}
	if plan.Resources.CPUMillis <= 0 ||
		plan.Resources.CPUMillis > r.config.MaxCPUMillis ||
		plan.Resources.MemoryBytes <= 0 ||
		plan.Resources.MemoryBytes > r.config.MaxMemoryBytes ||
		plan.Resources.PIDs <= 0 ||
		plan.Resources.PIDs > r.config.MaxPIDs ||
		plan.Resources.DiskBytes <= 0 ||
		plan.Resources.DiskBytes > r.config.MaxDiskBytes {
		err := domain.NewError(
			domain.CodeResourceLimitExceeded,
			domain.SeverityHigh,
			"Resolved resource limits are missing or exceed the local runner safety ceiling.",
		)
		err.Details = map[string]any{
			"cpuMillis":    plan.Resources.CPUMillis,
			"memoryBytes":  plan.Resources.MemoryBytes,
			"diskBytes":    plan.Resources.DiskBytes,
			"maxDiskBytes": r.config.MaxDiskBytes,
			"pids":         plan.Resources.PIDs,
		}
		return nil, "", err
	}
	for phase, capabilities := range plan.Capabilities {
		if len(capabilities.Network.Allow) > 0 {
			err := domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityHigh,
				"Setup network allowlists are recognized but not enforced by the local CLI runner.",
			)
			err.Phase = phase
			err.Details = map[string]any{
				"feature": "network-allowlist:" + string(phase),
			}
			return nil, "", err
		}
	}
	if len(plan.Commands) == 0 {
		return nil, "", domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Resolved plan contains no executable foreground commands.",
		)
	}

	steps := make([]preparedStep, 0, len(plan.Commands))
	commandIDs := make(map[string]struct{}, len(plan.Commands))
	for index, command := range plan.Commands {
		if !validPhase(command.Phase) {
			return nil, "", domain.NewError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Resolved command contains an unsupported phase.",
			)
		}
		if !assertionIDPattern.MatchString(command.ID) {
			return nil, "", commandError(
				command.Phase,
				"Resolved command ID is not schema-compatible.",
			)
		}
		if _, exists := commandIDs[command.ID]; exists {
			return nil, "", commandError(
				command.Phase,
				"Resolved command IDs must be unique.",
			)
		}
		commandIDs[command.ID] = struct{}{}
		if command.Role != "" &&
			command.Role != "foreground" &&
			command.Role != "journey" &&
			command.Role != "service" &&
			command.Role != "signal" {
			return nil, "", commandError(
				command.Phase,
				"Resolved command role is unsupported.",
			)
		}
		switch command.Role {
		case "service":
			if command.Phase != domain.PhaseRun ||
				command.Readiness == nil ||
				command.Signal != nil {
				return nil, "", commandError(
					command.Phase,
					"Resolved service command requires run-phase HTTP readiness.",
				)
			}
		case "signal":
			if command.Phase != domain.PhaseCleanup ||
				command.Signal == nil ||
				command.Readiness != nil ||
				len(command.Argv) != 0 {
				return nil, "", commandError(
					command.Phase,
					"Resolved signal command is not a cleanup service signal.",
				)
			}
		default:
			if command.Signal != nil || command.Readiness != nil {
				return nil, "", commandError(
					command.Phase,
					"Foreground and journey commands cannot contain service actions.",
				)
			}
		}
		if command.Role != "signal" && len(command.Argv) == 0 {
			return nil, "", commandError(
				command.Phase,
				"Resolved command argv must not be empty.",
			)
		}
		for _, argument := range command.Argv {
			if argument == "" || strings.ContainsRune(argument, 0) {
				return nil, "", commandError(
					command.Phase,
					"Resolved command arguments must be non-empty and contain no NUL bytes.",
				)
			}
		}
		timeout := r.config.DefaultStepTimeout
		if command.Timeout != "" {
			parsed, parseErr := time.ParseDuration(command.Timeout)
			if parseErr != nil || parsed <= 0 || parsed > r.config.MaxStepTimeout {
				return nil, "", commandError(
					command.Phase,
					"Resolved command timeout is invalid or exceeds the runner maximum.",
				)
			}
			timeout = parsed
		}
		steps = append(steps, preparedStep{
			command:  clonePlanCommand(command),
			timeout:  timeout,
			position: index,
		})
	}
	assertionIDs := make(map[string]struct{}, len(plan.JourneyAssertions))
	for _, assertion := range plan.JourneyAssertions {
		if !assertionIDPattern.MatchString(assertion.ID) {
			return nil, "", domain.NewError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Resolved journey assertion ID is not schema-compatible.",
			)
		}
		if _, exists := assertionIDs[assertion.ID]; exists {
			return nil, "", domain.NewError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Resolved journey assertion IDs must be unique.",
			)
		}
		assertionIDs[assertion.ID] = struct{}{}
		operations := 0
		if assertion.ExitCode != nil {
			operations++
		}
		if assertion.StdoutContains != "" {
			operations++
		}
		if assertion.StderrContains != "" {
			operations++
		}
		if assertion.StdoutRegex != "" {
			operations++
			if _, compileErr := regexp.Compile(assertion.StdoutRegex); compileErr != nil {
				return nil, "", domain.NewError(
					domain.CodePlanUnresolved,
					domain.SeverityHigh,
					"Resolved journey stdout regex is invalid.",
				)
			}
		}
		if assertion.StdoutJSONSchema != nil {
			operations++
			if err := validateStructuredJSONSchemaRef(
				*assertion.StdoutJSONSchema,
			); err != nil {
				return nil, "", err
			}
		}
		if assertion.FileExists != "" {
			operations++
		}
		if assertion.Response != nil {
			operations++
		}
		if assertion.JSONFile != nil {
			operations++
		}
		if operations != 1 {
			return nil, "", domain.NewError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Each resolved journey assertion must contain exactly one operation.",
			)
		}
	}
	if err := r.validateHTTPPlan(plan); err != nil {
		return nil, "", err
	}
	return steps, platform, nil
}

func (r *Runner) Run(ctx context.Context, prepared *PreparedRun) (Outcome, error) {
	if prepared == nil {
		err := domain.NewError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityHigh,
			"Prepared run is required.",
		)
		return Outcome{}, err
	}
	if !prepared.executionPlanSealed {
		return Outcome{}, domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityCritical,
			"Prepared run has no sealed execution-plan snapshot.",
		)
	}
	if prepared.Runner.WorkloadOS != "linux" || !prepared.Runner.Available {
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityCritical,
			"Prepared runner no longer represents an available Linux engine.",
		)
		return Outcome{}, errors.Join(err, cleanupPreparedCopies(prepared))
	}

	outcome := Outcome{
		RunID:              prepared.RunID,
		RunDir:             prepared.RunDir,
		WorkspaceDir:       prepared.WorkspaceDir,
		OutputsDir:         prepared.OutputsDir,
		Runner:             prepared.Runner,
		IncompleteFeatures: cloneStrings(prepared.IncompleteFeatures),
		Cleanup:            domain.CleanupNotTested,
		StartedAt:          r.now().UTC(),
	}
	containerName := "repopass-" + prepared.RunID
	var primaryError *domain.Error
	var finalizationErrors []*domain.Error
	var resourceErrors []*domain.Error
	filesystemState := filesystemObservationState{
		required: planRequiresFilesystemWriteObservation(
			prepared.executionPlan,
		),
	}
	engineDiffState := engineDiffObservationState{
		required: planRequiresFilesystemWriteObservation(
			prepared.executionPlan,
		),
	}
	activityTraceState := activityTraceObservationState{
		required: planRequiresFilesystemWriteObservation(
			prepared.executionPlan,
		),
		backendEligible: prepared.Backend == "docker",
	}
	operationNotificationState := newOperationNotificationObservationState(
		prepared,
		activityTraceState.required,
	)
	resourceState := resourceObservationState{
		required: planRequiresResourceObservation(
			prepared.executionPlan,
		),
	}
	peerPortState := peerPortObservationState{
		required: planRequiresPortObservation(
			prepared.executionPlan,
		),
	}
	if peerPortState.required {
		switch {
		case prepared.Backend != "docker":
			peerPortState.failure = "backend-not-live-qualified"
		default:
			declaredEndpoints, declaredErr :=
				declaredPeerPortEndpoints(prepared.executionPlan)
			if declaredErr != nil {
				peerPortState.failure = "unsupported-http-profile"
			} else {
				peerPortState.backendEligible = true
				peerPortState.declaredEndpoints = declaredEndpoints
			}
		}
	}
	containerStarted := false
	cleanupContainerID := ""
	cleanupSummary := newCleanupResidueSummary(
		prepared.executionPlan.Cleanup.AllowedResidue,
	)
	cleanupSummary.Failure = "inventory-not-attempted"
	var cleanupFinding *domain.Error
	exportSafe := false
	finalizationSucceeded := true
	var service *runningService
	serviceStepIndex := -1
	var signalStep *preparedStep
	httpAssertionResults := make(map[string]domain.AssertionResult)
	for _, step := range prepared.steps {
		if step.command.Role == "signal" {
			cloned := preparedStep{
				command:  clonePlanCommand(step.command),
				timeout:  step.timeout,
				position: step.position,
			}
			signalStep = &cloned
			break
		}
	}

	createArgs := r.buildCreateArgs(prepared, containerName)
	createCtx, cancelCreate := context.WithTimeout(ctx, r.config.CreateTimeout)
	createStdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	createStderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	createExit, createRunErr := r.executor.Run(
		createCtx,
		prepared.Backend,
		createArgs,
		createStdout,
		createStderr,
	)
	cancelCreate()
	if createRunErr != nil || createExit != 0 {
		primaryError = domain.WrapError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityHigh,
			"Long-lived sandbox container creation failed before workload execution.",
			createRunErr,
		)
		primaryError.Phase = domain.PhasePrepare
		primaryError.Details = map[string]any{
			"backend":       prepared.Backend,
			"containerName": containerName,
			"exitCode":      createExit,
		}
		outcome.Observations = append(outcome.Observations, lifecycleObservation(
			r.now().UTC(),
			prepared,
			domain.PhasePrepare,
			"container.create",
			containerName,
			"failed",
			map[string]any{"exitCode": createExit},
		))
	} else {
		containerID, containerIDErr := parseCreatedContainerID(
			createStdout.Bytes(),
		)
		if containerIDErr != nil {
			if filesystemState.required || resourceState.required ||
				activityTraceState.required ||
				peerPortState.backendEligible {
				if filesystemState.required {
					filesystemState.failure =
						"immutable-container-identity-unavailable"
				}
				if engineDiffState.required {
					engineDiffState.baselineFailure =
						"immutable-container-identity-unavailable"
					engineDiffState.finalFailure =
						"immutable-container-identity-unavailable"
				}
				if activityTraceState.required {
					activityTraceState.failure =
						"immutable-container-identity-unavailable"
				}
				if peerPortState.backendEligible {
					peerPortState.failure =
						"immutable-container-identity-unavailable"
				}
				if resourceState.required {
					primaryError = resourceObserverError(
						"Container creation did not yield a trustworthy immutable identity for resource preflight.",
						containerIDErr,
					)
				}
			}
		} else {
			cleanupContainerID = containerID
			if filesystemState.required {
				filesystemState.containerID = containerID
			}
			if engineDiffState.required {
				engineDiffState.containerID = containerID
			}
			if activityTraceState.required {
				activityTraceState.containerID = containerID
			}
			if peerPortState.backendEligible {
				peerPortState.targetID = containerID
			}
			if resourceState.required {
				resourceState.containerID = containerID
			}
		}
		outcome.Observations = append(outcome.Observations, lifecycleObservation(
			r.now().UTC(),
			prepared,
			domain.PhasePrepare,
			"container.create",
			containerName,
			"succeeded",
			map[string]any{
				"networkMode":  "none",
				"workloadUser": containerUser,
				"readOnlyRoot": true,
				"workspace":    "read-only",
			},
		))
		outcome.Observations = append(outcome.Observations, domain.ObservationEvent{
			SchemaVersion: "1",
			Timestamp:     r.now().UTC(),
			Phase:         domain.PhasePrepare,
			Actor:         "trusted-runner",
			Operation:     "resource.disk.limit",
			Resource:      containerOutputs,
			Result:        "succeeded",
			Observer:      prepared.Backend + "-cli",
			Coverage:      coverageEnforcementOnly,
			Confidence:    "high",
			Details: map[string]any{
				"plannedBytes": prepared.executionPlan.Resources.DiskBytes,
				"mechanism":    "engine-tmpfs",
				"sharedBy":     []string{"/outputs", "HOME", "TMPDIR"},
			},
		})

		startCtx, cancelStart := context.WithTimeout(ctx, r.config.CreateTimeout)
		startStdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
		startStderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
		startExit, startRunErr := r.executor.Run(
			startCtx,
			prepared.Backend,
			[]string{"start", containerName},
			startStdout,
			startStderr,
		)
		cancelStart()
		if startRunErr != nil || startExit != 0 {
			primaryError = domain.WrapError(
				domain.CodeSandboxStartFailed,
				domain.SeverityHigh,
				"Long-lived sandbox container could not be started.",
				startRunErr,
			)
			primaryError.Phase = domain.PhasePrepare
			primaryError.Details = map[string]any{
				"backend":       prepared.Backend,
				"containerName": containerName,
				"exitCode":      startExit,
			}
			outcome.Observations = append(outcome.Observations, lifecycleObservation(
				r.now().UTC(),
				prepared,
				domain.PhasePrepare,
				"container.start",
				containerName,
				"failed",
				map[string]any{"exitCode": startExit},
			))
		} else {
			containerStarted = true
			outcome.Observations = append(outcome.Observations, lifecycleObservation(
				r.now().UTC(),
				prepared,
				domain.PhasePrepare,
				"container.start",
				containerName,
				"succeeded",
				map[string]any{"detached": true},
			))

			if primaryError == nil && resourceState.required {
				resourceCtx, cancelResource := context.WithTimeout(
					ctx,
					r.config.CreateTimeout,
				)
				snapshot, resourceErr := r.collectLinuxResourceSnapshot(
					resourceCtx,
					prepared,
					resourceState.containerID,
				)
				cancelResource()
				if resourceErr == nil {
					resourceErr = validateLinuxResourcePreflight(
						snapshot,
						prepared.executionPlan.Resources,
					)
				}
				if resourceErr != nil {
					resourceState.failure = "active-preflight-failed"
					primaryError = resourceObserverError(
						"Sandbox Linux resource controls failed active cgroup v2 preflight.",
						resourceErr,
					)
				} else {
					resourceState.active = snapshot
					resourceState.activeReady = true
					outcome.Runner.ResourceLimitEnforcement = true
				}
			}

			if primaryError == nil {
				initCtx, cancelInit := context.WithTimeout(ctx, r.config.CreateTimeout)
				initErr := r.initializeOutputDirectories(
					initCtx,
					prepared,
					containerName,
				)
				cancelInit()
				if initErr != nil {
					primaryError = domain.WrapError(
						domain.CodeSandboxStartFailed,
						domain.SeverityHigh,
						"Sandbox controller directories could not be initialized inside the bounded output filesystem.",
						initErr,
					)
					primaryError.Phase = domain.PhasePrepare
					primaryError.Details = map[string]any{
						"backend":       prepared.Backend,
						"containerName": containerName,
					}
				} else {
					if filesystemState.required &&
						filesystemState.containerID != "" {
						filesystemCtx, cancelFilesystem :=
							context.WithTimeout(
								ctx,
								r.config.CreateTimeout,
							)
						identityErr :=
							r.inspectResourceContainerIdentity(
								filesystemCtx,
								prepared,
								filesystemState.containerID,
							)
						var baselineErr error
						if identityErr == nil {
							filesystemState.baselineIdentityVerified = true
							filesystemState.baseline, baselineErr =
								r.collectFilesystemSnapshot(
									filesystemCtx,
									prepared,
									filesystemState.containerID,
								)
						}
						cancelFilesystem()
						if identityErr != nil || baselineErr != nil {
							filesystemState.failure =
								"baseline-snapshot-failed"
						} else {
							filesystemState.baselineReady = true
						}
					}
					if engineDiffState.required &&
						engineDiffState.containerID != "" {
						engineDiffCtx, cancelEngineDiff :=
							context.WithTimeout(
								ctx,
								r.config.CreateTimeout,
							)
						identityErr :=
							r.inspectResourceContainerIdentity(
								engineDiffCtx,
								prepared,
								engineDiffState.containerID,
							)
						if identityErr != nil {
							engineDiffState.baselineFailure =
								"baseline-container-identity-failed"
						} else {
							engineDiffState.
								baselineIdentityVerified = true
							snapshot, snapshotErr :=
								r.collectDockerEngineDiff(
									engineDiffCtx,
									prepared,
									engineDiffState.containerID,
								)
							if snapshotErr != nil {
								engineDiffState.baselineFailure =
									"baseline-engine-diff-failed"
							} else {
								engineDiffState.baseline = snapshot
								engineDiffState.baselineReady = true
							}
						}
						cancelEngineDiff()
					}
				}
				if primaryError == nil {
					probeObservation, probeErr := r.verifyRuntimeVersion(
						ctx,
						prepared,
						containerName,
					)
					outcome.Observations = append(
						outcome.Observations,
						probeObservation,
					)
					if probeErr != nil {
						primaryError = probeErr
					} else {
						identityObservation, identityErr :=
							r.verifyWorkloadIdentity(
								ctx,
								prepared,
								containerName,
							)
						outcome.Observations = append(
							outcome.Observations,
							identityObservation,
						)
						if identityErr != nil {
							primaryError = identityErr
						} else {
							archiveObservation, archiveErr :=
								r.verifyArchiveHelper(
									ctx,
									prepared,
									containerName,
								)
							outcome.Observations = append(
								outcome.Observations,
								archiveObservation,
							)
							if archiveErr != nil {
								primaryError = archiveErr
							} else {
								exportSafe = true
								if activityTraceState.required {
									if !activityTraceState.backendEligible {
										activityTraceState.failure =
											"backend-not-live-qualified"
									} else if activityTraceState.containerID == "" {
										activityTraceState.failure =
											"immutable-container-identity-unavailable"
									} else {
										traceCtx, cancelTrace :=
											context.WithTimeout(
												ctx,
												r.config.CreateTimeout,
											)
										identityErr :=
											r.inspectResourceContainerIdentity(
												traceCtx,
												prepared,
												activityTraceState.containerID,
											)
										if identityErr != nil {
											activityTraceState.failure =
												"start-container-identity-failed"
										} else {
											activityTraceState.
												startIdentityVerified = true
											session, traceErr :=
												r.startOutputsActivityTrace(
													traceCtx,
													prepared,
													activityTraceState.containerID,
												)
											if traceErr != nil {
												activityTraceState.failure =
													"ready-transport-failed"
											} else {
												activityTraceState.session =
													session
												activityTraceState.ready = true
												identityErr =
													r.inspectResourceContainerIdentity(
														traceCtx,
														prepared,
														activityTraceState.containerID,
													)
												if identityErr != nil {
													session.abort()
													activityTraceState.session = nil
													activityTraceState.ready = false
													activityTraceState.failure =
														"ready-container-identity-failed"
												} else {
													activityTraceState.
														readyIdentityVerified = true
													activityTraceState.
														phaseSignalsComplete = true
												}
											}
										}
										cancelTrace()
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if primaryError == nil {
		for _, step := range prepared.steps {
			if step.command.Role == "signal" {
				continue
			}
			if step.command.Role == "service" {
				if peerPortState.required &&
					peerPortState.backendEligible &&
					peerPortState.failure == "" &&
					peerPortState.session == nil {
					peerPortState.startAttempted = true
					portCtx, cancelPort := context.WithTimeout(
						ctx,
						r.config.CreateTimeout,
					)
					session, peerID, portErr :=
						r.startPeerPortObservation(
							portCtx,
							prepared,
							peerPortState.targetID,
							peerPortState.declaredEndpoints,
						)
					cancelPort()
					peerPortState.peerID = peerID
					if portErr != nil {
						peerPortState.failure =
							"ready-transport-failed"
					} else {
						peerPortState.session = session
						peerPortState.startIdentityVerified = true
						peerPortState.readyIdentityVerified = true
						peerPortState.namespaceIsolationVerified = true
						peerPortState.ready = true
					}
				}
				markOutputsActivityPhase(
					&activityTraceState,
					&operationNotificationState,
					prepared.executionPlan,
					step.command.Phase,
					true,
				)
				service = r.startService(
					ctx,
					prepared,
					step,
					containerName,
				)
				recordFilesystemPhaseDispatch(
					&filesystemState,
					prepared.executionPlan,
					step.command.Phase,
				)
				serviceStepIndex = len(outcome.Steps)
				outcome.Steps = append(outcome.Steps, StepResult{
					ID:            step.command.ID,
					Phase:         step.command.Phase,
					Role:          step.command.Role,
					ExitCode:      -1,
					ContainerName: containerName,
				})
				outcome.Observations = append(
					outcome.Observations,
					lifecycleObservation(
						r.now().UTC(),
						prepared,
						domain.PhaseRun,
						"service.dispatch",
						step.command.ID,
						"observed",
						map[string]any{
							"attached": true,
							"state":    "attempted",
							"user":     containerUser,
						},
					),
				)
				readinessObservation, readinessErr :=
					r.waitForReadiness(
						ctx,
						prepared,
						containerName,
						service,
					)
				outcome.Observations = append(
					outcome.Observations,
					readinessObservation,
				)
				if readinessErr != nil {
					primaryError = readinessErr
					break
				}
				outcome.Observations = append(
					outcome.Observations,
					lifecycleObservation(
						r.now().UTC(),
						prepared,
						domain.PhaseRun,
						"service.start",
						step.command.ID,
						"succeeded",
						map[string]any{
							"attached":  true,
							"readiness": "succeeded",
							"user":      containerUser,
						},
					),
				)
				markOutputsActivityPhase(
					&activityTraceState,
					&operationNotificationState,
					prepared.executionPlan,
					domain.PhaseExercise,
					true,
				)
				_, assertionResults, observations, driverStarted, journeyErr :=
					r.executeHTTPJourney(
						ctx,
						prepared,
						containerName,
						service,
					)
				if driverStarted {
					recordFilesystemPhaseDispatch(
						&filesystemState,
						prepared.executionPlan,
						domain.PhaseExercise,
					)
				}
				for assertionID, assertion := range assertionResults {
					httpAssertionResults[assertionID] = assertion
				}
				outcome.Observations = append(
					outcome.Observations,
					observations...,
				)
				if journeyErr != nil {
					primaryError = journeyErr
					break
				}
				continue
			}
			r.verifyOperationNotificationQuiescenceBoundary(
				prepared,
				&activityTraceState,
				&operationNotificationState,
				true,
			)
			markOutputsActivityPhase(
				&activityTraceState,
				&operationNotificationState,
				prepared.executionPlan,
				step.command.Phase,
				true,
			)
			execution := r.runStep(ctx, prepared, step, containerName)
			recordOperationNotificationDispatch(
				&operationNotificationState,
				execution.dispatchConfirmed,
			)
			r.verifyOperationNotificationQuiescenceBoundary(
				prepared,
				&activityTraceState,
				&operationNotificationState,
				false,
			)
			recordFilesystemPhaseDispatch(
				&filesystemState,
				prepared.executionPlan,
				step.command.Phase,
			)
			outcome.Steps = append(outcome.Steps, execution.result)
			outcome.Observations = append(
				outcome.Observations,
				execution.observations...,
			)
			exportSafe = exportSafe && execution.exportSafe
			if execution.primaryError != nil {
				primaryError = execution.primaryError
				break
			}
		}
	}

	if containerStarted && service != nil && signalStep != nil {
		markOutputsActivityPhase(
			&activityTraceState,
			&operationNotificationState,
			prepared.executionPlan,
			domain.PhaseCleanup,
			true,
		)
		_, serviceFinishedBeforeSignal := pollServiceResult(service)
		signalTimeout := boundedSignalFinalizationTimeout(
			signalStep.timeout,
			r.config.CleanupTimeout,
		)
		signalCtx, cancelSignal := context.WithTimeout(
			context.Background(),
			signalTimeout,
		)
		signalTarget := containerName
		if fullContainerIDPattern.MatchString(cleanupContainerID) {
			signalTarget = cleanupContainerID
		}
		// This is the sole production authorization for an idempotent
		// quiescent signal no-op. Direct helper calls remain fail closed.
		const allowQuiescentNoop = true
		helper, signalResult, signalErr := r.signalService(
			signalCtx,
			prepared,
			signalTarget,
			signalStep.command,
			allowQuiescentNoop,
		)
		recordFilesystemSignalGrant(
			&filesystemState,
			prepared.executionPlan,
			helper,
			signalErr,
		)
		signalResult.ContainerName = containerName
		cancelSignal()
		if signalErr != nil {
			signalResult.ErrorCode = domain.CodeCleanupFailed
		}
		outcome.Steps = append(outcome.Steps, signalResult)
		outcome.Observations = append(
			outcome.Observations,
			signalObservation(
				r.now().UTC(),
				prepared,
				signalStep.command,
				helper,
				signalErr,
			),
		)
		if signalErr != nil {
			finalizationSucceeded = false
			service.cancel()
			err := domain.WrapError(
				domain.CodeCleanupFailed,
				domain.SeverityHigh,
				"Runner could not complete the resolved service signal action.",
				signalErr,
			)
			err.Phase = domain.PhaseCleanup
			err.Details = map[string]any{
				"service":       service.command.ID,
				"signalCommand": signalStep.command.ID,
			}
			finalizationErrors = append(finalizationErrors, err)
		}

		waitCtx, cancelWait := context.WithTimeout(
			context.Background(),
			r.config.CleanupTimeout,
		)
		serviceExecution, waitErr := waitServiceResult(waitCtx, service)
		cancelWait()
		if waitErr != nil {
			finalizationSucceeded = false
			service.cancel()
			err := domain.WrapError(
				domain.CodeCleanupFailed,
				domain.SeverityHigh,
				"Runner could not confirm attached service termination.",
				waitErr,
			)
			err.Phase = domain.PhaseCleanup
			err.Details = map[string]any{
				"service": service.command.ID,
			}
			finalizationErrors = append(finalizationErrors, err)
		} else {
			if serviceExecution.primaryError != nil &&
				primaryError == nil &&
				signalErr == nil {
				primaryError = serviceExecution.primaryError
			}
			if serviceExecution.primaryError != nil {
				serviceExecution.result.ErrorCode =
					serviceExecution.primaryError.Code
			}
			exportSafe = exportSafe && serviceExecution.exportSafe
			if serviceStepIndex >= 0 &&
				serviceStepIndex < len(outcome.Steps) {
				outcome.Steps[serviceStepIndex] =
					serviceExecution.result
			}
			outcome.Observations = append(
				outcome.Observations,
				serviceExitObservation(
					r.now().UTC(),
					prepared,
					service,
					serviceExecution,
					signalErr == nil &&
						serviceExecution.primaryError == nil &&
						!serviceFinishedBeforeSignal &&
						!helper.AlreadyExited,
					serviceFinishedBeforeSignal ||
						helper.AlreadyExited,
				),
			)
		}
	}

	if containerStarted {
		markOutputsActivityPhase(
			&activityTraceState,
			&operationNotificationState,
			prepared.executionPlan,
			domain.PhaseCleanup,
			false,
		)
		quiesceCtx, cancelQuiesce := context.WithTimeout(
			context.Background(),
			r.config.CleanupTimeout,
		)
		quiesceTarget := containerName
		immutableQuiescenceIdentity :=
			fullContainerIDPattern.MatchString(cleanupContainerID)
		if immutableQuiescenceIdentity {
			quiesceTarget = cleanupContainerID
		}
		quiesceErr := r.quiesceWorkloadProcesses(
			quiesceCtx,
			prepared,
			quiesceTarget,
		)
		cancelQuiesce()
		quiesceResult := "succeeded"
		if quiesceErr != nil {
			quiesceResult = "failed"
			finalizationSucceeded = false
			err := domain.WrapError(
				domain.CodeCleanupFailed,
				domain.SeverityHigh,
				"Runner could not quiesce workload and trusted driver processes before container removal.",
				quiesceErr,
			)
			err.Phase = domain.PhaseCleanup
			err.Details = map[string]any{
				"backend":       prepared.Backend,
				"containerName": containerName,
			}
			finalizationErrors = append(finalizationErrors, err)
		}
		outcome.Observations = append(outcome.Observations, lifecycleObservation(
			r.now().UTC(),
			prepared,
			domain.PhaseCleanup,
			"sandbox.processes.quiesce",
			containerName,
			quiesceResult,
			map[string]any{
				"immutableIdentity": immutableQuiescenceIdentity,
				"targetUsers":       []string{"65532", "65533"},
			},
		))

		if quiesceErr == nil && filesystemState.required {
			filesystemState.workloadQuiescenceVerified = true
		}
		if quiesceErr == nil && engineDiffState.required {
			engineDiffState.workloadQuiescenceVerified = true
		}
		if quiesceErr == nil && activityTraceState.required {
			activityTraceState.workloadQuiescenceVerified = true
		}
		if quiesceErr == nil && peerPortState.required {
			peerPortState.workloadQuiescenceVerified = true
		}
		if quiesceErr == nil && peerPortState.required &&
			peerPortState.session != nil &&
			peerPortState.ready &&
			peerPortState.readyIdentityVerified &&
			peerPortState.targetID != "" &&
			peerPortState.peerID != "" {
			portCtx, cancelPort := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			session := peerPortState.session
			var portErr error
			if err := r.inspectPeerPortTargetIdentity(
				portCtx,
				prepared,
				peerPortState.targetID,
				true,
			); err != nil {
				portErr = err
			}
			var targetNamespaces peerPortNamespaces
			if portErr == nil {
				targetNamespaces, portErr =
					r.collectPeerPortTargetNamespaces(
						portCtx,
						prepared,
						peerPortState.targetID,
					)
				if portErr == nil &&
					!samePeerPortNamespaces(
						targetNamespaces,
						session.targetNamespaces,
					) {
					portErr = errors.New(
						"port observer target namespace identity changed",
					)
				}
			}
			running := true
			if portErr == nil {
				_, portErr = r.inspectPeerPortContainerIdentity(
					portCtx,
					prepared,
					peerPortState.targetID,
					peerPortState.peerID,
					peerPortState.peerID,
					&running,
				)
			}
			var portResult peerPortResult
			if portErr == nil {
				portResult, portErr = session.finish(portCtx)
			} else {
				session.abort()
			}
			peerPortState.session = nil
			if portErr == nil {
				portErr = validatePeerPortNamespaceIsolation(
					portResult.Namespaces,
					targetNamespaces,
				)
			}
			if portErr == nil {
				portErr = r.inspectPeerPortTargetIdentity(
					portCtx,
					prepared,
					peerPortState.targetID,
					true,
				)
			}
			stopped := false
			if portErr == nil {
				_, portErr = r.inspectPeerPortContainerIdentity(
					portCtx,
					prepared,
					peerPortState.targetID,
					peerPortState.peerID,
					peerPortState.peerID,
					&stopped,
				)
			}
			if portErr != nil {
				peerPortState.failure = "final-transport-failed"
			} else {
				peerPortState.result = portResult
				peerPortState.finalReady = true
				peerPortState.finalIdentityVerified = true
				peerPortState.observedAt = r.now().UTC()
			}
			cancelPort()
		} else if quiesceErr != nil && peerPortState.required {
			peerPortState.failure = "workload-quiescence-failed"
			if peerPortState.session != nil {
				peerPortState.session.abort()
				peerPortState.session = nil
			}
		}
		if quiesceErr == nil && activityTraceState.required &&
			activityTraceState.session != nil &&
			activityTraceState.ready &&
			activityTraceState.readyIdentityVerified &&
			activityTraceState.containerID != "" {
			traceCtx, cancelTrace := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			identityErr := r.inspectResourceContainerIdentity(
				traceCtx,
				prepared,
				activityTraceState.containerID,
			)
			if identityErr != nil {
				activityTraceState.failure =
					"stop-container-identity-failed"
				activityTraceState.session.abort()
			} else {
				activityTraceState.stopIdentityVerified = true
				traceResult, traceErr :=
					activityTraceState.session.finish(traceCtx)
				if traceErr != nil {
					activityTraceState.failure =
						"final-transport-failed"
				} else {
					activityTraceState.result = traceResult
					activityTraceState.finalReady = true
					identityErr =
						r.inspectResourceContainerIdentity(
							traceCtx,
							prepared,
							activityTraceState.containerID,
						)
					if identityErr != nil {
						activityTraceState.failure =
							"final-container-identity-failed"
					} else {
						activityTraceState.
							finalIdentityVerified = true
						activityTraceState.observedAt =
							r.now().UTC()
					}
				}
			}
			cancelTrace()
		} else if quiesceErr != nil &&
			activityTraceState.required {
			activityTraceState.failure =
				"workload-quiescence-failed"
			if activityTraceState.session != nil {
				activityTraceState.session.abort()
			}
		}
		if quiesceErr == nil && filesystemState.required &&
			filesystemState.baselineReady &&
			filesystemState.containerID != "" {
			filesystemCtx, cancelFilesystem := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			identityErr := r.inspectResourceContainerIdentity(
				filesystemCtx,
				prepared,
				filesystemState.containerID,
			)
			if identityErr == nil {
				filesystemState.finalIdentityVerified = true
				finalSnapshot, snapshotErr :=
					r.collectFilesystemSnapshot(
						filesystemCtx,
						prepared,
						filesystemState.containerID,
					)
				if snapshotErr != nil {
					filesystemState.failure =
						"final-snapshot-failed"
				} else if boundErr := validateFilesystemChangeBound(
					filesystemState.baseline,
					finalSnapshot,
				); boundErr != nil {
					filesystemState.failure =
						"retained-state-change-bound-exceeded"
				} else {
					filesystemState.final = finalSnapshot
					filesystemState.finalReady = true
					filesystemState.observedAt = r.now().UTC()
				}
			} else {
				filesystemState.failure =
					"container-identity-readback-failed"
			}
			cancelFilesystem()
		} else if quiesceErr != nil && filesystemState.required {
			filesystemState.failure = "workload-quiescence-failed"
		}

		if quiesceErr == nil && engineDiffState.required &&
			engineDiffState.containerID != "" {
			engineDiffCtx, cancelEngineDiff := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			identityErr := r.inspectResourceContainerIdentity(
				engineDiffCtx,
				prepared,
				engineDiffState.containerID,
			)
			if identityErr != nil {
				engineDiffState.finalFailure =
					"final-container-identity-failed"
			} else {
				engineDiffState.finalIdentityVerified = true
				finalSnapshot, snapshotErr :=
					r.collectDockerEngineDiff(
						engineDiffCtx,
						prepared,
						engineDiffState.containerID,
					)
				if snapshotErr != nil {
					engineDiffState.finalFailure =
						"final-engine-diff-failed"
				} else {
					engineDiffState.final = finalSnapshot
					engineDiffState.finalReady = true
					engineDiffState.observedAt = r.now().UTC()
				}
			}
			cancelEngineDiff()
		} else if quiesceErr != nil && engineDiffState.required {
			engineDiffState.finalFailure = "workload-quiescence-failed"
		}

		if quiesceErr == nil && resourceState.containerID != "" {
			resourceCtx, cancelResource := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			identityErr := r.inspectResourceContainerIdentity(
				resourceCtx,
				prepared,
				resourceState.containerID,
			)
			if identityErr == nil {
				resourceState.identityVerified = true
				finalSnapshot, snapshotErr := r.collectLinuxResourceSnapshot(
					resourceCtx,
					prepared,
					resourceState.containerID,
				)
				if snapshotErr == nil {
					snapshotErr = validateLinuxResourceBinding(
						finalSnapshot,
						prepared.executionPlan.Resources,
					)
				}
				if snapshotErr == nil && resourceState.activeReady {
					snapshotErr = validateLinuxResourceMonotonic(
						resourceState.active,
						finalSnapshot,
					)
				}
				if snapshotErr == nil {
					resourceState.final = finalSnapshot
					resourceState.finalReady = true
					resourceState.observedAt = r.now().UTC()
					if resourceState.activeReady {
						if limitErr := resourceLimitEventError(
							resourceState.active,
							finalSnapshot,
						); limitErr != nil {
							resourceErrors = append(resourceErrors, limitErr)
						}
					}
				} else {
					resourceState.failure = "final-snapshot-failed"
					resourceErrors = append(
						resourceErrors,
						resourceObserverIncomplete(
							"Final sandbox cgroup v2 resource snapshot was incomplete.",
							snapshotErr,
						),
					)
				}
			} else {
				resourceState.failure = "container-identity-readback-failed"
				resourceErrors = append(
					resourceErrors,
					resourceObserverIncomplete(
						"Final resource snapshot could not verify the immutable container identity and run label.",
						identityErr,
					),
				)
			}
			cancelResource()
		} else if quiesceErr != nil && resourceState.required {
			resourceState.failure = "workload-quiescence-failed"
			resourceErrors = append(
				resourceErrors,
				resourceObserverIncomplete(
					"Final resource snapshot requires confirmed workload quiescence.",
					quiesceErr,
				),
			)
		}

		cleanupPreconditionsTrusted := quiesceErr == nil &&
			immutableQuiescenceIdentity
		cleanupSummary.QuiescenceConfirmed = quiesceErr == nil
		cleanupSummary.QuiescenceConfirmed =
			cleanupSummary.QuiescenceConfirmed &&
				immutableQuiescenceIdentity
		var cleanupEvidenceErr error
		switch {
		case quiesceErr != nil:
			cleanupSummary.Failure = "workload-quiescence-failed"
		case !fullContainerIDPattern.MatchString(cleanupContainerID):
			cleanupSummary.Failure =
				"immutable-container-identity-unavailable"
			cleanupEvidenceErr = cleanupInventoryFail(
				cleanupSummary.Failure,
			)
		default:
			inventoryCtx, cancelInventory := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			if err := r.removeCleanupDisposableDirectories(
				inventoryCtx,
				prepared,
				cleanupContainerID,
			); err != nil {
				cleanupSummary.Failure =
					cleanupInventoryFailureClass(err)
				cleanupEvidenceErr = err
				cleanupPreconditionsTrusted = false
			} else {
				cleanupSummary.DisposableCleanupVerified = true
			}
			if cleanupPreconditionsTrusted {
				if err := r.inspectResourceContainerIdentity(
					inventoryCtx,
					prepared,
					cleanupContainerID,
				); err != nil {
					cleanupSummary.Failure =
						"container-identity-readback-failed"
					cleanupEvidenceErr = err
					cleanupPreconditionsTrusted = false
				} else {
					cleanupSummary.IdentityVerified = true
				}
			}
			if cleanupPreconditionsTrusted {
				inventory, err := r.collectCleanupInventory(
					inventoryCtx,
					prepared,
					cleanupContainerID,
				)
				if err != nil {
					cleanupSummary.Failure =
						cleanupInventoryFailureClass(err)
					cleanupEvidenceErr = err
				} else {
					classified := classifyCleanupInventory(
						inventory,
						prepared.executionPlan.Cleanup.
							AllowedResidue,
						r.cleanupTokenKeyReader,
					)
					classified.QuiescenceConfirmed =
						cleanupSummary.QuiescenceConfirmed
					classified.DisposableCleanupVerified =
						cleanupSummary.
							DisposableCleanupVerified
					classified.IdentityVerified =
						cleanupSummary.IdentityVerified
					cleanupSummary = classified
					if cleanupSummary.Verdict ==
						domain.CleanupNotTested {
						cleanupEvidenceErr = cleanupInventoryFail(
							cleanupSummary.Failure,
						)
					}
				}
			}
			cancelInventory()
		}
		if cleanupEvidenceErr != nil {
			finalizationSucceeded = false
			finalizationErrors = append(
				finalizationErrors,
				cleanupTechnicalError(
					"Runner could not produce trustworthy bounded cleanup-residue evidence.",
					cleanupSummary.Failure,
					cleanupEvidenceErr,
				),
			)
		}
		outcome.Observations = append(
			outcome.Observations,
			cleanupResidueObservation(
				prepared,
				cleanupSummary,
				r.now().UTC(),
			),
		)
		cleanupFinding = cleanupResidueFinding(cleanupSummary)

		cleanupEvidenceTrusted := cleanupEvidenceErr == nil &&
			cleanupSummary.InventoryComplete &&
			cleanupSummary.Verdict != domain.CleanupNotTested
		unsafeResidue := cleanupSummary.SymlinkCount > 0 ||
			cleanupSummary.SpecialCount > 0
		if exportSafe && cleanupEvidenceTrusted &&
			fullContainerIDPattern.MatchString(cleanupContainerID) &&
			unsafeResidue {
			outcome.Observations = append(
				outcome.Observations,
				lifecycleObservation(
					r.now().UTC(),
					prepared,
					domain.PhaseCleanup,
					"sandbox.outputs.export",
					containerOutputs,
					"denied",
					map[string]any{
						"reason":       "unsafe-residue",
						"specialCount": cleanupSummary.SpecialCount,
						"symlinkCount": cleanupSummary.SymlinkCount,
					},
				),
			)
		}
		var repairErr error
		if exportSafe && cleanupEvidenceTrusted && !unsafeResidue &&
			fullContainerIDPattern.MatchString(cleanupContainerID) {
			repairCtx, cancelRepair := context.WithTimeout(
				context.Background(),
				r.config.CleanupTimeout,
			)
			repairErr = r.repairOutputPermissions(
				repairCtx,
				prepared,
				cleanupContainerID,
			)
			cancelRepair()
			repairResult := "succeeded"
			if repairErr != nil {
				repairResult = "failed"
				finalizationSucceeded = false
				err := domain.WrapError(
					domain.CodeCleanupFailed,
					domain.SeverityHigh,
					"Runner could not repair output directory permissions before export.",
					repairErr,
				)
				err.Phase = domain.PhaseCleanup
				err.Details = map[string]any{
					"backend": prepared.Backend,
					"scope":   containerOutputs,
				}
				finalizationErrors = append(finalizationErrors, err)
			}
			outcome.Observations = append(
				outcome.Observations,
				lifecycleObservation(
					r.now().UTC(),
					prepared,
					domain.PhaseCleanup,
					"sandbox.permissions.restore",
					containerOutputs,
					repairResult,
					map[string]any{
						"scope": "declared regular output tree after bounded residue inventory",
					},
				),
			)
		}
		if exportSafe && cleanupEvidenceTrusted && !unsafeResidue &&
			repairErr == nil &&
			fullContainerIDPattern.MatchString(cleanupContainerID) &&
			cleanupSummary.InventoryComplete {
			exportCtx, cancelExport := context.WithTimeout(
				context.Background(),
				r.config.ExportTimeout,
			)
			summary, exportErr := r.exportOutputs(
				exportCtx,
				prepared,
				cleanupContainerID,
			)
			cancelExport()
			exportResult := "succeeded"
			exportDetails := map[string]any{
				"limitBytes": prepared.executionPlan.Resources.DiskBytes,
				"mechanism":  "trusted-tar-stream",
			}
			if exportErr != nil {
				exportResult = "failed"
				finalizationSucceeded = false
				finalizationErrors = append(finalizationErrors, exportErr)
			} else {
				exportDetails["fileCount"] = summary.FileCount
				exportDetails["totalBytes"] = summary.TotalBytes
				outputBytes := summary.TotalBytes
				if resourceState.required {
					resourceState.outputBytes = &outputBytes
				}
			}
			outcome.Observations = append(outcome.Observations, lifecycleObservation(
				r.now().UTC(),
				prepared,
				domain.PhaseCleanup,
				"sandbox.outputs.export",
				containerOutputs,
				exportResult,
				exportDetails,
			))
		}
	}

	if !containerStarted {
		cleanupSummary = newCleanupResidueSummary(
			prepared.executionPlan.Cleanup.AllowedResidue,
		)
		cleanupSummary.Failure = "sandbox-boundary-unavailable"
		outcome.Observations = append(
			outcome.Observations,
			cleanupResidueObservation(
				prepared,
				cleanupSummary,
				r.now().UTC(),
			),
		)
	}

	if peerPortState.session != nil {
		peerPortState.session.abort()
		peerPortState.session = nil
		if peerPortState.failure == "" {
			peerPortState.failure = "final-transport-failed"
		}
	}
	if peerPortState.required &&
		peerPortState.failure == "" &&
		!peerPortState.startAttempted {
		peerPortState.failure = "observer-not-started"
	}
	if peerPortState.peerID != "" {
		peerRemoveCtx, cancelPeerRemove := context.WithTimeout(
			context.Background(),
			r.config.CleanupTimeout,
		)
		peerRemoveErr := r.removePeerPortContainer(
			peerRemoveCtx,
			peerPortState.peerID,
		)
		cancelPeerRemove()
		peerRemoveResult := "succeeded"
		if peerRemoveErr != nil {
			peerRemoveResult = "failed"
			peerPortState.failure = "peer-remove-failed"
			finalizationSucceeded = false
			err := domain.WrapError(
				domain.CodeSandboxDestroyFailed,
				domain.SeverityHigh,
				"Runner could not confirm forced removal of the peer port observer container.",
				peerRemoveErr,
			)
			err.Phase = domain.PhaseCleanup
			err.Details = map[string]any{
				"backend":  prepared.Backend,
				"observer": "docker-peer-port-listener-trace",
			}
			finalizationErrors = append(finalizationErrors, err)
		} else {
			peerPortState.peerRemoveVerified = true
		}
		outcome.Observations = append(
			outcome.Observations,
			lifecycleObservation(
				r.now().UTC(),
				prepared,
				domain.PhaseCleanup,
				"observer.container.remove",
				"tcp-listener-observer",
				peerRemoveResult,
				map[string]any{
					"forced":            true,
					"immutableIdentity": true,
				},
			),
		)
	}

	removeCtx, cancelRemove := context.WithTimeout(
		context.Background(),
		r.config.CleanupTimeout,
	)
	removeStdout := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	removeStderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	removeTarget := containerName
	if fullContainerIDPattern.MatchString(cleanupContainerID) {
		removeTarget = cleanupContainerID
	}
	removeExit, removeRunErr := r.executor.Run(
		removeCtx,
		prepared.Backend,
		[]string{"rm", "-f", removeTarget},
		removeStdout,
		removeStderr,
	)
	cancelRemove()
	removeSucceeded := removeRunErr == nil && removeExit == 0
	removeResult := "succeeded"
	if !removeSucceeded {
		removeResult = "failed"
		finalizationSucceeded = false
		err := domain.WrapError(
			domain.CodeSandboxDestroyFailed,
			domain.SeverityHigh,
			"Runner could not confirm forced removal of the long-lived sandbox container.",
			removeRunErr,
		)
		err.Phase = domain.PhaseCleanup
		err.Details = map[string]any{
			"backend":       prepared.Backend,
			"containerName": containerName,
			"exitCode":      removeExit,
		}
		finalizationErrors = append(finalizationErrors, err)
	}
	outcome.Observations = append(outcome.Observations, lifecycleObservation(
		r.now().UTC(),
		prepared,
		domain.PhaseCleanup,
		"container.remove",
		containerName,
		removeResult,
		map[string]any{"forced": true},
	))

	if prepared.executionPlan.HTTPJourney != nil {
		outcome.Assertions = evaluateHTTPJourneyAssertions(
			prepared,
			httpAssertionResults,
		)
	} else {
		outcome.Assertions = evaluateJourneyAssertions(
			prepared,
			outcome.Steps,
		)
	}
	if cleanupErr := cleanupPreparedCopies(prepared); cleanupErr != nil {
		finalizationSucceeded = false
		err := controllerCopyCleanupError(cleanupErr)
		finalizationErrors = append(finalizationErrors, err)
	}

	for index := range outcome.Steps {
		outcome.Steps[index].CleanupAttempted = true
		outcome.Steps[index].CleanupSucceeded = finalizationSucceeded
	}
	if primaryError != nil {
		outcome.Errors = append(outcome.Errors, primaryError)
	}
	if cleanupFinding != nil {
		outcome.Errors = append(outcome.Errors, cleanupFinding)
	}
	outcome.Errors = append(outcome.Errors, finalizationErrors...)
	outcome.Errors = append(outcome.Errors, resourceErrors...)
	outcome.CompletedAt = r.now().UTC()
	switch {
	case cleanupSummary.Verdict == domain.CleanupUndeclaredResidue:
		outcome.Cleanup = domain.CleanupUndeclaredResidue
	case !finalizationSucceeded:
		outcome.Cleanup = domain.CleanupNotTested
	default:
		outcome.Cleanup = cleanupSummary.Verdict
	}
	var resourceObservation domain.ObservationEvent
	var resourceCoverage string
	outcome.Resources, resourceObservation, resourceCoverage =
		summarizeResourceUsage(
			resourceState,
			outcome.StartedAt,
			outcome.CompletedAt,
			outcome.Steps,
			prepared.Backend,
			containerName,
		)
	if resourceState.required {
		outcome.Observations = append(
			outcome.Observations,
			resourceObservation,
		)
	}
	outcome.Runner.ResourceUsage = resourceCoverage
	if resourceCoverage == "high" {
		outcome.IncompleteFeatures = removeCompletedResourceFeatures(
			outcome.IncompleteFeatures,
		)
	}
	filesystemObservations, filesystemWriteCoverage, _ :=
		summarizeFilesystemRetainedState(
			filesystemState,
			prepared.Backend,
			containerName,
			outcome.CompletedAt,
		)
	retainedDeclarationFinding := filesystemDeclarationFinding(
		compareFilesystemRetainedState(filesystemState),
	)
	if filesystemState.required {
		outcome.Observations = append(
			outcome.Observations,
			filesystemObservations...,
		)
	}
	engineDiffObservation, engineDiffCoverage :=
		summarizeDockerEngineDiff(
			engineDiffState,
			containerName,
			outcome.CompletedAt,
		)
	if engineDiffState.required {
		outcome.Observations = append(
			outcome.Observations,
			engineDiffObservation,
		)
	}
	activityTraceObservation, activityTraceCoverage :=
		summarizeOutputsActivityTrace(
			activityTraceState,
			outcome.CompletedAt,
		)
	if activityTraceState.required {
		outcome.Observations = append(
			outcome.Observations,
			activityTraceObservation,
		)
	}
	operationNotificationObservation, operationNotificationFinding :=
		summarizeOperationNotifications(
			activityTraceState,
			operationNotificationState,
			outcome.CompletedAt,
		)
	if operationNotificationState.required {
		outcome.Observations = append(
			outcome.Observations,
			operationNotificationObservation,
		)
	}
	if declarationFinding := selectFilesystemDeclarationFinding(
		operationNotificationFinding,
		retainedDeclarationFinding,
	); declarationFinding != nil {
		outcome.Errors = append(
			outcome.Errors,
			declarationFinding,
		)
	}
	outcome.Runner.FilesystemWriteObservation =
		combineFilesystemWriteCoverage(
			filesystemWriteCoverage,
			engineDiffCoverage,
			activityTraceCoverage,
		)
	peerPortObservation, peerPortCoverage, peerPortFinding :=
		summarizePeerPortObservation(
			peerPortState,
			outcome.CompletedAt,
		)
	if peerPortState.required {
		outcome.Observations = append(
			outcome.Observations,
			peerPortObservation,
		)
	}
	if peerPortFinding != nil {
		outcome.Errors = append(outcome.Errors, peerPortFinding)
	}
	outcome.Runner.PortObservation = peerPortCoverage
	numberObservations(outcome.Observations)

	if primaryError != nil {
		return outcome, primaryError
	}
	if len(finalizationErrors) > 0 {
		return outcome, finalizationErrors[0]
	}
	if len(resourceErrors) > 0 {
		return outcome, resourceErrors[0]
	}
	if assertionErr := assertionFailure(outcome.Assertions); assertionErr != nil {
		outcome.Errors = append(outcome.Errors, assertionErr)
		return outcome, assertionErr
	}
	return outcome, nil
}

func controllerCopyCleanupError(cause error) *domain.Error {
	err := domain.WrapError(
		domain.CodeCleanupFailed,
		domain.SeverityHigh,
		"Runner could not remove the controller's read-only source copies.",
		cause,
	)
	err.Phase = domain.PhaseCleanup
	err.Details = map[string]any{"scope": "controller-source-copies"}
	return err
}

type stepExecution struct {
	result            StepResult
	observations      []domain.ObservationEvent
	primaryError      *domain.Error
	exportSafe        bool
	dispatchConfirmed bool
}

func (r *Runner) runStep(
	ctx context.Context,
	prepared *PreparedRun,
	step preparedStep,
	containerName string,
) (execution stepExecution) {
	execution.result = StepResult{
		ID:            step.command.ID,
		Phase:         step.command.Phase,
		Role:          step.command.Role,
		ExitCode:      -1,
		ContainerName: containerName,
	}

	logCapture := newLogCapture(r.config.MaxLogBytes)
	stepCtx, cancelStep := context.WithTimeout(ctx, step.timeout)
	startedAt := r.now()
	execArgs := []string{
		"exec",
		"--user", containerUser,
		"--workdir", containerWorkspace,
		containerName,
	}
	execArgs = append(execArgs, step.command.Argv...)
	exitCode, execErr := r.executor.Run(
		stepCtx,
		prepared.Backend,
		execArgs,
		logCapture.stdout,
		logCapture.stderr,
	)
	duration := r.now().Sub(startedAt)
	stepContextErr := stepCtx.Err()
	cancelStep()

	execution.result.ExitCode = exitCode
	execution.result.Stdout = logCapture.stdout.Bytes()
	execution.result.Stderr = logCapture.stderr.Bytes()
	execution.result.Duration = duration
	execution.result.LogBytes = logCapture.budget.Total()
	execution.result.LogTruncated = logCapture.budget.Truncated()
	execution.result.TimedOut = errors.Is(stepContextErr, context.DeadlineExceeded)
	expectedJourneyExit := acceptsJourneyExitCode(
		prepared.executionPlan.JourneyAssertions,
		step.command,
		exitCode,
	)

	operationalFailure := exitCode < 0
	if exitCode >= 125 && exitCode <= 127 {
		inspectCtx, cancelInspect := context.WithTimeout(
			context.Background(),
			r.config.CreateTimeout,
		)
		_, _ = r.containerRunning(
			inspectCtx,
			prepared,
			containerName,
		)
		cancelInspect()
		// Docker and Podman reserve 125-127 for CLI/exec setup failures.
		// A running supervisor does not make those statuses trustworthy as
		// workload exits (for example, a missing executable commonly returns
		// 127). Without a runner-owned exit sentinel, always fail closed.
		operationalFailure = true
	}
	execution.dispatchConfirmed = !operationalFailure

	exitResult := "succeeded"
	if (exitCode != 0 && !expectedJourneyExit) ||
		operationalFailure {
		exitResult = "failed"
	}
	execution.observations = append(execution.observations, domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     r.now().UTC(),
		Phase:         step.command.Phase,
		Actor:         "trusted-runner",
		Operation:     "foreground-process.exit",
		Resource:      step.command.Argv[0],
		Result:        exitResult,
		Observer:      prepared.Backend + "-cli",
		Coverage:      coverageBestEffort,
		Confidence:    "high",
		Details: map[string]any{
			"exitCode":     exitCode,
			"logBytes":     execution.result.LogBytes,
			"logTruncated": execution.result.LogTruncated,
			"execMode":     "nonroot-long-lived-container",
			"operational":  operationalFailure,
		},
	})

	switch {
	case errors.Is(stepContextErr, context.DeadlineExceeded):
		err := domain.WrapError(
			domain.CodeTimeout,
			domain.SeverityHigh,
			"Workload command exceeded its resolved wall timeout.",
			stepContextErr,
		)
		err.Phase = step.command.Phase
		execution.primaryError = err
		execution.result.ErrorCode = err.Code
		execution.exportSafe = false
	case errors.Is(stepContextErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		err := domain.WrapError(
			domain.CodeCancelled,
			domain.SeverityWarning,
			"Workload command was cancelled.",
			context.Canceled,
		)
		err.Phase = step.command.Phase
		execution.primaryError = err
		execution.result.ErrorCode = err.Code
		execution.exportSafe = false
	case operationalFailure:
		err := domain.WrapError(
			domain.CodeSandboxStartFailed,
			domain.SeverityHigh,
			"Container exec failed before a trustworthy workload exit was observed.",
			execErr,
		)
		err.Phase = step.command.Phase
		err.Details = map[string]any{
			"backend":       prepared.Backend,
			"containerName": containerName,
			"exitCode":      exitCode,
		}
		execution.primaryError = err
		execution.result.ErrorCode = err.Code
		execution.exportSafe = false
	case exitCode != 0 && expectedJourneyExit:
		execution.exportSafe = true
	case exitCode != 0:
		code := phaseFailureCode(step.command.Phase)
		err := domain.WrapError(
			code,
			domain.SeverityHigh,
			"Foreground workload command exited with a non-zero status.",
			execErr,
		)
		err.Phase = step.command.Phase
		err.Details = map[string]any{"exitCode": exitCode}
		execution.primaryError = err
		execution.result.ErrorCode = err.Code
		execution.exportSafe = true
	default:
		execution.exportSafe = true
	}
	return execution
}

func acceptsJourneyExitCode(
	assertions []domain.PlanAssertion,
	command domain.PlanCommand,
	actual int,
) bool {
	if command.Role != "journey" || command.Phase != domain.PhaseExercise {
		return false
	}
	for _, assertion := range assertions {
		if assertion.ExitCode != nil && *assertion.ExitCode == actual {
			return true
		}
	}
	return false
}

func (r *Runner) buildCreateArgs(
	prepared *PreparedRun,
	containerName string,
) []string {
	resources := prepared.executionPlan.Resources
	executable, _ := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	idleArgs := idleRuntimeArgs(prepared.executionPlan.RuntimeAdapter)
	args := []string{
		"create",
		"--name", containerName,
		"--label", runLabelKey + "=" + prepared.RunID,
		"--label", phaseLabelKey + "=" + string(domain.PhasePrepare),
		"--platform", prepared.Platform,
		"--network", "none",
		"--ipc", "none",
		"--cgroupns", "private",
		"--user", "0:0",
		"--cap-drop", "ALL",
		"--cap-add", "DAC_OVERRIDE",
		"--cap-add", "FOWNER",
		"--cap-add", "KILL",
		"--security-opt", "no-new-privileges=true",
		"--pids-limit", strconv.Itoa(resources.PIDs),
		"--memory", strconv.FormatInt(resources.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(resources.MemoryBytes, 10),
		"--cpus", cpuFlag(resources.CPUMillis),
		"--read-only",
		"--workdir", trustedHelperWorkdir,
		"--env", "HOME=/outputs/.home",
		"--env", "TMPDIR=/outputs/.tmp",
		"--env", "NODE_OPTIONS=",
		"--env", "NODE_PATH=",
		"--env", "PYTHONPATH=",
		"--env", "PYTHONHOME=",
		"--stop-timeout", "5",
		"--ulimit", "nofile=1024:1024",
		"--tmpfs", fmt.Sprintf(
			"/outputs:rw,nosuid,nodev,noexec,size=%d,mode=0777",
			resources.DiskBytes,
		),
		"--mount", bindMount(prepared.Backend, prepared.SourceSnapshotDir, containerSource, true),
		"--mount", bindMount(prepared.Backend, prepared.WorkspaceDir, containerWorkspace, true),
	}
	for _, input := range prepared.Inputs {
		args = append(
			args,
			"--mount",
			bindMount(prepared.Backend, input.SourcePath, input.ContainerPath, true),
		)
	}
	args = append(
		args,
		"--pull=never",
		"--entrypoint", executable,
		prepared.executionPlan.BaseImageReference,
	)
	args = append(args, idleArgs...)
	return args
}

func prepareInputs(inputs []domain.PlanInput, snapshotRoot string) ([]InputMount, error) {
	result := make([]InputMount, 0, len(inputs))
	for _, input := range inputs {
		if !input.ReadOnly {
			err := domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityCritical,
				"Local runner accepts only read-only fixture inputs.",
			)
			err.Details = map[string]any{"input": input.Name}
			return nil, err
		}
		fixture, err := cleanFixturePath(input.Fixture)
		if err != nil {
			return nil, err
		}
		mountPath, err := cleanInputMountPath(input.MountPath)
		if err != nil {
			return nil, err
		}
		for _, existing := range result {
			if sandboxPathsOverlap(existing.ContainerPath, mountPath) {
				return nil, domain.NewError(
					domain.CodeManifestInvalid,
					domain.SeverityHigh,
					"Resolved input mount paths must not overlap.",
				)
			}
		}

		sourcePath := filepath.Join(snapshotRoot, filepath.FromSlash(fixture))
		resolved, err := filepath.EvalSymlinks(sourcePath)
		if err != nil || !pathWithin(snapshotRoot, resolved) || !samePath(sourcePath, resolved) {
			return nil, domain.WrapError(
				domain.CodeSourceSymlinkEscape,
				domain.SeverityCritical,
				"Resolved fixture is absent or escapes the immutable source snapshot.",
				err,
			)
		}
		if unsafeMountSourcePath(resolved) {
			return nil, domain.NewError(
				domain.CodeSandboxPrepareFailed,
				domain.SeverityHigh,
				"Fixture mount source contains a comma or control character.",
			)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, domain.WrapError(
				domain.CodeSourceNotFound,
				domain.SeverityHigh,
				"Resolved fixture could not be opened.",
				err,
			)
		}
		switch input.Type {
		case "file":
			if !info.Mode().IsRegular() {
				return nil, domain.NewError(
					domain.CodeManifestInvalid,
					domain.SeverityHigh,
					"File fixture does not resolve to a regular file.",
				)
			}
		case "directory":
			if !info.IsDir() {
				return nil, domain.NewError(
					domain.CodeManifestInvalid,
					domain.SeverityHigh,
					"Directory fixture does not resolve to a directory.",
				)
			}
		default:
			return nil, domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityHigh,
				"Only file and directory fixtures can be mounted by the local runner.",
			)
		}
		result = append(result, InputMount{
			Name:          input.Name,
			SourcePath:    resolved,
			ContainerPath: mountPath,
			Type:          input.Type,
			ReadOnly:      true,
		})
	}
	return result, nil
}

func cleanFixturePath(value string) (string, error) {
	if value == "" ||
		strings.ContainsRune(value, 0) ||
		strings.Contains(value, "\\") ||
		path.IsAbs(value) {
		return "", domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Fixture path must be a source-relative POSIX path.",
		)
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != value {
		return "", domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Fixture path must be normalized and remain inside the source snapshot.",
		)
	}
	return cleaned, nil
}

func cleanInputMountPath(value string) (string, error) {
	if value == "" ||
		unsafeMountSourcePath(value) ||
		!path.IsAbs(value) ||
		path.Clean(value) != value ||
		(value != "/inputs" && !strings.HasPrefix(value, "/inputs/")) {
		return "", domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Fixture mount path must be a normalized absolute path beneath /inputs.",
		)
	}
	return value, nil
}

func sandboxPathsOverlap(first, second string) bool {
	return first == second ||
		strings.HasPrefix(first, strings.TrimSuffix(second, "/")+"/") ||
		strings.HasPrefix(second, strings.TrimSuffix(first, "/")+"/")
}

func bindMount(backend, source, destination string, readOnly bool) string {
	value := "type=bind,src=" + source + ",dst=" + destination
	if readOnly {
		value += ",readonly"
	}
	if strings.EqualFold(strings.TrimSpace(backend), "podman") {
		// Podman does not relabel bind mounts by default on SELinux hosts.
		// The mounted paths are controller-owned per-run copies, so a private
		// label preserves both SELinux isolation and source read-only state.
		value += ",relabel=private"
	}
	return value
}

func cpuFlag(cpuMillis int64) string {
	whole := cpuMillis / 1000
	fraction := cpuMillis % 1000
	if fraction == 0 {
		return strconv.FormatInt(whole, 10)
	}
	value := fmt.Sprintf("%d.%03d", whole, fraction)
	return strings.TrimRight(value, "0")
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

func validPinnedImageReference(reference, digest string) bool {
	if reference == "" ||
		reference[0] == '-' ||
		strings.ContainsAny(reference, " \t\r\n\x00,") {
		return false
	}
	return strings.HasSuffix(reference, "@"+digest) &&
		len(reference) > len("@"+digest)
}

func requiredPlanPlatform(features []string) (string, error) {
	var platformFeatures []string
	for _, feature := range features {
		value := strings.TrimSpace(feature)
		if strings.HasPrefix(strings.ToLower(value), "platform:") {
			platformFeatures = append(platformFeatures, feature)
		}
	}
	if len(platformFeatures) != 1 {
		err := domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Resolved plan must require exactly one workload platform.",
		)
		err.Details = map[string]any{"platformFeatureCount": len(platformFeatures)}
		return "", err
	}
	switch platformFeatures[0] {
	case "platform:linux/amd64":
		return "linux/amd64", nil
	case "platform:linux/arm64":
		return "linux/arm64", nil
	default:
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Resolved plan requires an unsupported workload platform.",
		)
		err.Details = map[string]any{"feature": platformFeatures[0]}
		return "", err
	}
}

func validPhase(phase domain.Phase) bool {
	for _, candidate := range domain.OrderedPhases {
		if phase == candidate {
			return true
		}
	}
	return false
}

func commandError(phase domain.Phase, message string) error {
	err := domain.NewError(domain.CodePlanUnresolved, domain.SeverityHigh, message)
	err.Phase = phase
	return err
}

func phaseFailureCode(phase domain.Phase) domain.ErrorCode {
	switch phase {
	case domain.PhaseSetup:
		return domain.CodeSetupFailed
	case domain.PhaseBuild:
		return domain.CodeBuildFailed
	case domain.PhaseCleanup:
		return domain.CodeCleanupFailed
	default:
		return domain.CodeJourneyAssertionFailed
	}
}

func secureRunID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

func safeRunID(value string) bool {
	if len(value) < 8 || len(value) > 40 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func clonePlan(plan domain.ResolvedPlan) domain.ResolvedPlan {
	cloned := plan
	cloned.Evidence.Include = cloneStrings(plan.Evidence.Include)
	cloned.Evidence.Exclude = cloneStrings(plan.Evidence.Exclude)
	if plan.Cleanup.AllowedResidue != nil {
		cloned.Cleanup.AllowedResidue = append(
			[]string{},
			plan.Cleanup.AllowedResidue...,
		)
	}
	cloned.AdapterVersions = make(map[string]string, len(plan.AdapterVersions))
	for key, value := range plan.AdapterVersions {
		cloned.AdapterVersions[key] = value
	}
	cloned.ObserverVersions = make(map[string]string, len(plan.ObserverVersions))
	for key, value := range plan.ObserverVersions {
		cloned.ObserverVersions[key] = value
	}
	cloned.Commands = make([]domain.PlanCommand, len(plan.Commands))
	for index, command := range plan.Commands {
		cloned.Commands[index] = clonePlanCommand(command)
	}
	cloned.Inputs = append([]domain.PlanInput(nil), plan.Inputs...)
	cloned.JourneyAssertions = make([]domain.PlanAssertion, len(plan.JourneyAssertions))
	for index, assertion := range plan.JourneyAssertions {
		cloned.JourneyAssertions[index] = assertion
		if assertion.ExitCode != nil {
			exitCode := *assertion.ExitCode
			cloned.JourneyAssertions[index].ExitCode = &exitCode
		}
		if assertion.StdoutJSONSchema != nil {
			schema := *assertion.StdoutJSONSchema
			cloned.JourneyAssertions[index].StdoutJSONSchema = &schema
		}
		if assertion.Response != nil {
			response := *assertion.Response
			if assertion.Response.Status != nil {
				status := *assertion.Response.Status
				response.Status = &status
			}
			if assertion.Response.Header != nil {
				header := *assertion.Response.Header
				response.Header = &header
			}
			if assertion.Response.BodyContains != nil {
				contains := *assertion.Response.BodyContains
				response.BodyContains = &contains
			}
			if assertion.Response.JSONPath != nil {
				jsonPath := *assertion.Response.JSONPath
				jsonPath.Equals = bytes.Clone(
					assertion.Response.JSONPath.Equals,
				)
				response.JSONPath = &jsonPath
			}
			if assertion.Response.JSONSchema != nil {
				schema := *assertion.Response.JSONSchema
				response.JSONSchema = &schema
			}
			cloned.JourneyAssertions[index].Response = &response
		}
		if assertion.JSONFile != nil {
			jsonFile := *assertion.JSONFile
			cloned.JourneyAssertions[index].JSONFile = &jsonFile
		}
	}
	if plan.HTTPJourney != nil {
		journey := *plan.HTTPJourney
		journey.Steps = make(
			[]domain.PlanHTTPDriverStep,
			len(plan.HTTPJourney.Steps),
		)
		for index, step := range plan.HTTPJourney.Steps {
			journey.Steps[index] = step
			if step.Request == nil {
				continue
			}
			request := *step.Request
			request.Headers = make(
				map[string]string,
				len(step.Request.Headers),
			)
			for name, value := range step.Request.Headers {
				request.Headers[name] = value
			}
			if step.Request.Body != nil {
				body := *step.Request.Body
				request.Body = &body
			}
			request.JSON = bytes.Clone(step.Request.JSON)
			journey.Steps[index].Request = &request
		}
		cloned.HTTPJourney = &journey
	}
	cloned.RequiredRunnerFeatures = cloneStrings(plan.RequiredRunnerFeatures)
	cloned.ObserverSet = cloneStrings(plan.ObserverSet)
	cloned.Capabilities = make(map[domain.Phase]domain.CapabilitySet, len(plan.Capabilities))
	for phase, capabilities := range plan.Capabilities {
		copied := capabilities
		copied.Network.Allow = append(
			[]domain.NetworkDestination(nil),
			capabilities.Network.Allow...,
		)
		copied.Filesystem.Read = cloneStrings(capabilities.Filesystem.Read)
		copied.Filesystem.Write = cloneStrings(capabilities.Filesystem.Write)
		copied.Filesystem.Create = cloneStrings(
			capabilities.Filesystem.Create,
		)
		copied.Filesystem.Delete = cloneStrings(
			capabilities.Filesystem.Delete,
		)
		copied.Filesystem.Rename = cloneStrings(
			capabilities.Filesystem.Rename,
		)
		copied.Filesystem.Chmod = cloneStrings(
			capabilities.Filesystem.Chmod,
		)
		copied.Filesystem.Symlink = cloneStrings(
			capabilities.Filesystem.Symlink,
		)
		copied.Ports.Listen = append(
			[]domain.PortBinding(nil),
			capabilities.Ports.Listen...,
		)
		copied.Process.Exec = cloneStrings(capabilities.Process.Exec)
		copied.Process.ChildProcesses = cloneBoolPointer(
			capabilities.Process.ChildProcesses,
		)
		copied.Process.Shell = cloneBoolPointer(
			capabilities.Process.Shell,
		)
		copied.Process.BackgroundProcesses = cloneBoolPointer(
			capabilities.Process.BackgroundProcesses,
		)
		if capabilities.Environment != nil {
			environment := *capabilities.Environment
			environment.Read = cloneStrings(
				capabilities.Environment.Read,
			)
			environment.Write = cloneStrings(
				capabilities.Environment.Write,
			)
			copied.Environment = &environment
		}
		copied.Secrets = cloneStrings(capabilities.Secrets)
		if capabilities.Resources != nil {
			resources := *capabilities.Resources
			resources.CPU = clonePlanJSONValue(
				capabilities.Resources.CPU,
			)
			resources.LogBytes = cloneInt64Pointer(
				capabilities.Resources.LogBytes,
			)
			copied.Resources = &resources
		}
		copied.Devices = cloneBoolPointer(capabilities.Devices)
		copied.HostIntegration = cloneBoolPointer(
			capabilities.HostIntegration,
		)
		cloned.Capabilities[phase] = copied
	}
	return cloned
}

func validResolvedEvidence(value domain.PlanEvidence) bool {
	if value.Profile != "minimal-public" ||
		!equalStringSlices(value.Exclude, []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"}) {
		return false
	}
	return equalStringSlices(value.Include, []string{"normalized-observations", "verification-summary"}) ||
		equalStringSlices(value.Include, []string{"normalized-observations", "sbom", "verification-summary"})
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func clonePlanJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, item := range typed {
			cloned[key] = clonePlanJSONValue(item)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = clonePlanJSONValue(item)
		}
		return cloned
	case []string:
		return cloneStrings(typed)
	case json.RawMessage:
		return bytes.Clone(typed)
	case []byte:
		return bytes.Clone(typed)
	default:
		return typed
	}
}

func clonePlanCommand(command domain.PlanCommand) domain.PlanCommand {
	cloned := command
	cloned.Argv = cloneStrings(command.Argv)
	if command.Signal != nil {
		signal := *command.Signal
		cloned.Signal = &signal
	}
	if command.Readiness != nil {
		readiness := *command.Readiness
		cloned.Readiness = &readiness
	}
	return cloned
}

func numberObservations(observations []domain.ObservationEvent) {
	for index := range observations {
		observations[index].Sequence = uint64(index + 1)
	}
}

type sharedLogBudget struct {
	mu        sync.Mutex
	remaining int64
	total     int64
	truncated bool
}

func (b *sharedLogBudget) take(length int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total += int64(length)
	if b.remaining <= 0 {
		if length > 0 {
			b.truncated = true
		}
		return 0
	}
	accepted := int64(length)
	if accepted > b.remaining {
		accepted = b.remaining
		b.truncated = true
	}
	b.remaining -= accepted
	return int(accepted)
}

func (b *sharedLogBudget) Total() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

func (b *sharedLogBudget) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

type budgetWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	budget *sharedLogBudget
}

func (w *budgetWriter) Write(value []byte) (int, error) {
	originalLength := len(value)
	accepted := w.budget.take(originalLength)
	if accepted == 0 {
		return originalLength, nil
	}
	w.mu.Lock()
	_, _ = w.buffer.Write(value[:accepted])
	w.mu.Unlock()
	return originalLength, nil
}

func (w *budgetWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buffer.Bytes())
}

type logCapture struct {
	budget *sharedLogBudget
	stdout *budgetWriter
	stderr *budgetWriter
}

func newLogCapture(limit int64) logCapture {
	budget := &sharedLogBudget{remaining: limit}
	return logCapture{
		budget: budget,
		stdout: &budgetWriter{budget: budget},
		stderr: &budgetWriter{budget: budget},
	}
}

var _ io.Writer = (*budgetWriter)(nil)
