package sourcequalification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

const (
	controllerCodeGateFailed  = "SOURCE_QUAL_GATE_FAILED"
	controllerCodeGateBlocked = "SOURCE_QUAL_GATE_BLOCKED"
	controllerCodeGateNotRun  = "SOURCE_QUAL_GATE_NOT_RUN"
	controllerCodeSourceDirty = "SOURCE_QUAL_SOURCE_DIRTY"
	controllerRuntimePrefix   = ".repopass-source-qualification-runtime-"
	controllerStagePrefix     = ".repopass-source-qualification-stage-"
)

// ProduceLaneRequest is the complete, caller-supplied subject and run input
// for the private RFC-0002 lane controller. Platform, tool, repository, tree,
// controller, and gate facts are deliberately not caller selected.
type ProduceLaneRequest struct {
	RepoRoot               string
	Lane                   Lane
	Event                  string
	ExpectedRef            string
	ExpectedBaseRevision   string
	ExpectedTestedRevision string
	WorkflowRunID          string
	WorkflowRunAttempt     int64
	PrivateLogRoot         string
	OutputDir              string
}

type produceLaneStageOutcome struct {
	StageReady          bool
	QualificationStatus QualificationStatus
	Code                string
	TestedRevision      string
	TreeSHA             string
}

type produceLaneRuntime struct {
	createWorkspace  func(string) (string, func() error, error)
	allocateStage    func(string) (string, error)
	produce          func(context.Context, ProduceLaneRequest) (produceLaneStageOutcome, error)
	promoteNoReplace func(string, string) error
	withdrawStage    func(string) error
	publishTombstone func(string, string, QualificationStatus) error
}

// ProduceLane validates the public request and runs the real, fixed
// controller adapters. All raw adapter failures remain private.
func ProduceLane(ctx context.Context, request ProduceLaneRequest) (ControllerResult, error) {
	if !validProduceLaneRequest(ctx, request) {
		return controllerFailure(controllerCodeInvalidInput)
	}
	return produceLaneWithRuntime(ctx, request, newProductionProduceLaneRuntime(request))
}

// produceLaneWithRuntime owns the ordering boundary between untrusted source
// execution and public evidence. A lane is first written to an absent
// same-parent stage. The private workspace must be cleaned before the stage
// can be atomically promoted without replacement.
func produceLaneWithRuntime(
	ctx context.Context,
	request ProduceLaneRequest,
	dependencies produceLaneRuntime,
) (ControllerResult, error) {
	if ctx == nil || ctx.Err() != nil ||
		dependencies.createWorkspace == nil || dependencies.allocateStage == nil ||
		dependencies.produce == nil || dependencies.promoteNoReplace == nil ||
		dependencies.withdrawStage == nil || dependencies.publishTombstone == nil {
		return controllerFailure(controllerCodeInvalidInput)
	}

	workspacePath, cleanup, err := dependencies.createWorkspace(request.PrivateLogRoot)
	if err != nil || cleanup == nil || workspacePath == "" {
		return controllerFailure(controllerCodeInvalidInput)
	}

	stagePath, allocationErr := dependencies.allocateStage(filepath.Dir(request.OutputDir))
	if allocationErr != nil || stagePath == "" {
		if cleanupErr := cleanup(); cleanupErr != nil {
			return controllerFailure(controllerCodeCleanupFailed)
		}
		return controllerFailure(controllerCodeInvalidInput)
	}

	producerRequest := request
	producerRequest.PrivateLogRoot = workspacePath
	producerRequest.OutputDir = stagePath
	outcome, producerErr := dependencies.produce(ctx, producerRequest)
	code, status, validOutcome := normalizeProduceLaneOutcome(request, outcome, producerErr)

	cleanupErr := cleanup()
	if cleanupErr != nil {
		withdrawErr := dependencies.withdrawStage(stagePath)
		if withdrawErr == nil && outcome.StageReady && validProduceLaneVerifiedIdentity(request, outcome) {
			_ = dependencies.publishTombstone(
				request.OutputDir,
				controllerCodeCleanupFailed,
				StatusFail,
			)
		}
		return controllerFailure(controllerCodeCleanupFailed)
	}

	if !outcome.StageReady {
		if withdrawErr := dependencies.withdrawStage(stagePath); withdrawErr != nil {
			return controllerFailure(controllerCodeCleanupFailed)
		}
		if !validOutcome {
			return controllerFailure(controllerCodeInvalidInput)
		}
		return controllerFailureWithStatus(code, status)
	}

	if !validOutcome {
		if withdrawErr := dependencies.withdrawStage(stagePath); withdrawErr != nil {
			return controllerFailure(controllerCodeCleanupFailed)
		}
		return controllerFailure(controllerCodeInvalidInput)
	}

	if err := dependencies.promoteNoReplace(stagePath, request.OutputDir); err != nil {
		if withdrawErr := dependencies.withdrawStage(stagePath); withdrawErr != nil {
			return controllerFailure(controllerCodeCleanupFailed)
		}
		return controllerFailure(controllerCodeDestinationExists)
	}

	if status != StatusPass {
		return controllerFailureWithStatus(code, status)
	}
	return controllerSuccess(
		controllerStatusPass,
		controllerNotApplicable,
		outcome.TestedRevision,
		outcome.TreeSHA,
	), nil
}

func normalizeProduceLaneOutcome(
	request ProduceLaneRequest,
	outcome produceLaneStageOutcome,
	producerErr error,
) (string, QualificationStatus, bool) {
	if outcome.StageReady && !validProduceLaneVerifiedIdentity(request, outcome) {
		return controllerCodeInvalidInput, StatusFail, false
	}
	if outcome.QualificationStatus == StatusPass {
		if outcome.StageReady && outcome.Code == "" && producerErr == nil {
			return controllerCodeOK, StatusPass, true
		}
		return controllerCodeInvalidInput, StatusFail, false
	}
	wantStatus, ok := attemptTombstoneStatusForCode(outcome.Code)
	if !ok || outcome.QualificationStatus != wantStatus || producerErr == nil {
		return controllerCodeInvalidInput, StatusFail, false
	}
	return outcome.Code, outcome.QualificationStatus, true
}

func validProduceLaneVerifiedIdentity(
	request ProduceLaneRequest,
	outcome produceLaneStageOutcome,
) bool {
	return outcome.TestedRevision == request.ExpectedTestedRevision &&
		validReceiptGitSHA1(outcome.TestedRevision) && validReceiptGitSHA1(outcome.TreeSHA)
}

func controllerFailureWithStatus(
	code string,
	status QualificationStatus,
) (ControllerResult, error) {
	want, ok := attemptTombstoneStatusForCode(code)
	if !ok || want != status || status == StatusPass {
		return controllerFailure(controllerCodeInvalidInput)
	}
	return ControllerResult{
		Code:                code,
		QualificationStatus: string(status),
		SHA256:              controllerNotApplicable,
		TestedRevision:      controllerNotApplicable,
		TreeSHA:             controllerNotApplicable,
	}, errors.New(code)
}

func validProduceLaneRequest(ctx context.Context, request ProduceLaneRequest) bool {
	if ctx == nil || ctx.Err() != nil ||
		(request.Lane != LaneLinuxAMD64 && request.Lane != LaneWindowsAMD64) ||
		!validReceiptEventRef(request.Event, request.ExpectedRef) ||
		!validReceiptGitSHA1(request.ExpectedBaseRevision) ||
		!validReceiptGitSHA1(request.ExpectedTestedRevision) ||
		!validReceiptPositiveDecimal(request.WorkflowRunID, 20) ||
		request.WorkflowRunAttempt != 1 {
		return false
	}
	if (request.Lane == LaneLinuxAMD64 && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64")) ||
		(request.Lane == LaneWindowsAMD64 && (runtime.GOOS != "windows" || runtime.GOARCH != "amd64")) {
		return false
	}

	repository, ok := exactControllerRuntimePath(request.RepoRoot)
	if !ok {
		return false
	}
	privateRoot, ok := exactControllerRuntimePath(request.PrivateLogRoot)
	if !ok {
		return false
	}
	output, ok := exactControllerRuntimePath(request.OutputDir)
	if !ok {
		return false
	}
	if packagePathsOverlapOrUnsafe(repository, privateRoot) ||
		packagePathsOverlapOrUnsafe(repository, output) ||
		packagePathsOverlapOrUnsafe(privateRoot, output) {
		return false
	}
	if !validQualificationWorkspaceName(filepath.Base(privateRoot)) ||
		requirePackageOutputAbsent(privateRoot) != nil || requirePackageOutputAbsent(output) != nil {
		return false
	}
	for _, parent := range []string{filepath.Dir(privateRoot), filepath.Dir(output)} {
		directory, _, err := openValidatedPackageDirectory(parent)
		if err != nil {
			return false
		}
		if err := directory.Close(); err != nil {
			return false
		}
	}
	return true
}

func exactControllerRuntimePath(path string) (string, bool) {
	canonical, err := canonicalPackageFilesystemPath(path)
	return canonical, err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		sameCanonicalPath(canonical, path)
}

type productionProduceLaneState struct {
	request ProduceLaneRequest
	receipt *qualificationReceipt
}

func newProductionProduceLaneRuntime(request ProduceLaneRequest) produceLaneRuntime {
	state := &productionProduceLaneState{request: request}
	return produceLaneRuntime{
		createWorkspace: createControllerRuntimeWorkspace,
		allocateStage:   allocateControllerLaneStage,
		produce: func(ctx context.Context, current ProduceLaneRequest) (produceLaneStageOutcome, error) {
			outcome, receipt, err := produceControllerLaneStage(ctx, current)
			state.receipt = receipt
			return outcome, err
		},
		promoteNoReplace: func(stagePath, outputPath string) error {
			return promoteControllerLaneStageNoReplace(stagePath, outputPath, request.Lane)
		},
		withdrawStage: func(stagePath string) error {
			return withdrawControllerLaneStage(stagePath, request.Lane)
		},
		publishTombstone: func(outputPath, code string, status QualificationStatus) error {
			return state.publishTombstone(outputPath, code, status)
		},
	}
}

func createControllerRuntimeWorkspace(path string) (string, func() error, error) {
	canonical, ok := exactControllerRuntimePath(path)
	if !ok || !validQualificationWorkspaceName(filepath.Base(canonical)) {
		return "", nil, errQualificationWorkspaceInvalid
	}
	return createPrivateQualificationWorkspace(filepath.Dir(canonical), filepath.Base(canonical))
}

func allocateControllerLaneStage(parent string) (string, error) {
	canonicalParent, ok := exactControllerRuntimePath(parent)
	if !ok {
		return "", errQualificationLaneInvalidInput
	}
	directory, parentSnapshot, err := openValidatedPackageDirectory(canonicalParent)
	if err != nil {
		return "", errQualificationLaneInvalidInput
	}
	if err := directory.Close(); err != nil {
		return "", errQualificationLaneInvalidInput
	}

	for attempt := 0; attempt < 8; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", errQualificationLaneInvalidInput
		}
		name := controllerStagePrefix + hex.EncodeToString(nonce[:])
		stage := filepath.Join(canonicalParent, name)
		if filepath.Dir(stage) != canonicalParent || requirePackageDirectoryIdentity(
			canonicalParent,
			parentSnapshot.identity,
		) != nil {
			return "", errQualificationLaneInvalidInput
		}
		if err := requirePackageOutputAbsent(stage); err == nil {
			return stage, nil
		}
	}
	return "", errQualificationLaneDestinationExists
}

func (state *productionProduceLaneState) publishTombstone(
	outputPath, code string,
	status QualificationStatus,
) error {
	if state == nil || state.receipt == nil {
		return errAttemptTombstoneInput
	}
	receipt := *state.receipt
	if receipt.Subject.BaseRevision != state.request.ExpectedBaseRevision ||
		receipt.Subject.TestedRevision != state.request.ExpectedTestedRevision ||
		receipt.Run.WorkflowRunID != state.request.WorkflowRunID ||
		receipt.Run.WorkflowRunAttempt != state.request.WorkflowRunAttempt ||
		receipt.Run.Lane != state.request.Lane || receipt.Attempt.Ordinal != 1 {
		return errAttemptTombstoneInput
	}
	document := qualificationAttemptTombstone{
		ArtifactType:           attemptTombstoneArtifactType,
		AttemptID:              receipt.Attempt.AttemptID,
		Code:                   code,
		ExpectedBaseRevision:   receipt.Subject.BaseRevision,
		ExpectedTestedRevision: receipt.Subject.TestedRevision,
		ExpectedTreeSHA:        receipt.Subject.TreeSHA,
		Lane:                   receipt.Run.Lane,
		Ordinal:                receipt.Attempt.Ordinal,
		QualificationRunID:     receipt.Run.QualificationRunID,
		QualificationStatus:    status,
		SchemaVersion:          attemptTombstoneSchemaVersion,
		WorkflowRunAttempt:     receipt.Run.WorkflowRunAttempt,
		WorkflowRunID:          receipt.Run.WorkflowRunID,
	}
	return publishAttemptTombstone(outputPath, document)
}

func qualificationLaneErrorCode(err error, status QualificationStatus) string {
	switch {
	case errors.Is(err, errGateCleanupFailed),
		errors.Is(err, errQualificationLaneCleanupFailed):
		return controllerCodeCleanupFailed
	case errors.Is(err, errGateOutputLimit):
		return controllerCodeOutputLimit
	case errors.Is(err, errQualificationLaneDestinationExists):
		return controllerCodeDestinationExists
	case errors.Is(err, errQualificationLaneArchiveInvalid):
		return controllerCodeArchiveInvalid
	case errors.Is(err, errQualificationLaneReceiptInvalid):
		return controllerCodeReceiptInvalid
	case errors.Is(err, errQualificationLaneSourceDirty):
		return controllerCodeSourceDirty
	case errors.Is(err, errGateBlocked), status == StatusBlocked:
		return controllerCodeGateBlocked
	case errors.Is(err, errGateNotRun), status == StatusNotRun:
		return controllerCodeGateNotRun
	case errors.Is(err, errGateFailed):
		return controllerCodeGateFailed
	default:
		return controllerCodeInvalidInput
	}
}

func controllerLaneSpecifications(lane Lane, files map[string][]byte) ([]packageFileSpec, bool) {
	receiptName, ok := qualificationLaneReceiptName(lane)
	if !ok {
		return nil, false
	}
	specifications := []packageFileSpec{
		{name: archiveFilename, maxBytes: maxArchiveBytes, expected: files[archiveFilename]},
		{name: qualificationManifestFilename, maxBytes: int64(maxManifestBytes), expected: files[qualificationManifestFilename]},
		{name: receiptName, maxBytes: int64(receiptMaxBytes), expected: files[receiptName]},
	}
	for _, specification := range specifications {
		if len(specification.expected) == 0 {
			return nil, false
		}
	}
	return specifications, true
}

func promoteControllerLaneStageNoReplace(stagePath, outputPath string, lane Lane) error {
	stage, ok := exactControllerRuntimePath(stagePath)
	if !ok {
		return errQualificationLaneInvalidInput
	}
	output, ok := exactControllerRuntimePath(outputPath)
	if !ok || sameCanonicalPath(stage, output) ||
		!sameCanonicalPath(filepath.Dir(stage), filepath.Dir(output)) {
		return errQualificationLaneInvalidInput
	}
	if err := requirePackageOutputAbsent(output); err != nil {
		return errQualificationLaneDestinationExists
	}

	first, err := readQualificationLaneDirectory(stage, lane, nil, nil)
	if err != nil {
		return errQualificationLaneReceiptInvalid
	}
	receiptName, _ := qualificationLaneReceiptName(lane)
	receipt, err := parseCanonicalReceipt(first.files[receiptName], lane)
	if err != nil || receipt.QualificationStatus == "" ||
		verifySourcePackage(
			first.files[archiveFilename],
			first.files[qualificationManifestFilename],
			sourceSubjectFromReceipt(receipt.Subject),
		) != nil ||
		!receiptBindingMatches(receipt.Source.Archive, first.files[archiveFilename]) ||
		!receiptBindingMatches(receipt.Source.Manifest, first.files[qualificationManifestFilename]) {
		return errQualificationLaneReceiptInvalid
	}
	specifications, ok := controllerLaneSpecifications(lane, first.files)
	if !ok {
		return errQualificationLaneReceiptInvalid
	}

	parentPath := filepath.Dir(output)
	parent, parentSnapshot, err := openValidatedPackageDirectory(parentPath)
	if err != nil {
		return errQualificationLaneInvalidInput
	}
	defer parent.Close()
	if parentSnapshot.identity == first.snapshot.identity {
		return errQualificationLaneInvalidInput
	}
	second, err := readExactPackageDirectory(stage, specifications)
	if err != nil || second.snapshot != first.snapshot {
		return errQualificationLaneReceiptInvalid
	}
	staging, stagingSnapshot, err := openValidatedPackageDirectory(stage)
	if err != nil || stagingSnapshot != second.snapshot {
		if staging != nil {
			_ = staging.Close()
		}
		return errQualificationLaneReceiptInvalid
	}
	if err := syncPackageDirectory(staging); err != nil {
		_ = staging.Close()
		return errQualificationLaneInvalidInput
	}
	if err := staging.Close(); err != nil {
		return errQualificationLaneInvalidInput
	}
	if err := requirePackageDirectoryIdentity(parentPath, parentSnapshot.identity); err != nil ||
		requirePackageOutputAbsent(output) != nil {
		return errQualificationLaneDestinationExists
	}
	if err := publishPackageDirectoryNoReplace(stage, output); err != nil {
		return errQualificationLaneDestinationExists
	}
	if err := syncPublishedPackageParent(parent); err != nil {
		if cleanupErr := cleanupPublishedPackage(
			output,
			second.snapshot.identity,
			specifications,
			parent,
		); cleanupErr != nil {
			return errQualificationLaneCleanupFailed
		}
		return errQualificationLaneInvalidInput
	}
	return nil
}

func withdrawControllerLaneStage(stagePath string, lane Lane) error {
	stage, ok := exactControllerRuntimePath(stagePath)
	if !ok {
		return errQualificationLaneCleanupFailed
	}
	if _, err := os.Lstat(stage); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errQualificationLaneCleanupFailed
	}
	read, err := readQualificationLaneDirectory(stage, lane, nil, nil)
	if err != nil {
		return errQualificationLaneCleanupFailed
	}
	specifications, ok := controllerLaneSpecifications(lane, read.files)
	if !ok {
		return errQualificationLaneCleanupFailed
	}
	parent, _, err := openValidatedPackageDirectory(filepath.Dir(stage))
	if err != nil {
		return errQualificationLaneCleanupFailed
	}
	defer parent.Close()
	return cleanupPublishedPackage(stage, read.snapshot.identity, specifications, parent)
}
