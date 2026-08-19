package sourcequalification

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

var (
	errQualificationLaneInvalidInput      = errors.New("SOURCE_QUAL_INVALID_INPUT")
	errQualificationLaneArchiveInvalid    = errors.New("SOURCE_QUAL_ARCHIVE_INVALID")
	errQualificationLaneReceiptInvalid    = errors.New("SOURCE_QUAL_RECEIPT_INVALID")
	errQualificationLaneSourceDirty       = errors.New("SOURCE_QUAL_SOURCE_DIRTY")
	errQualificationLaneCleanupFailed     = errors.New("SOURCE_QUAL_CLEANUP_FAILED")
	errQualificationLaneDestinationExists = errors.New("SOURCE_QUAL_DESTINATION_EXISTS")
)

type qualificationLaneRequest struct {
	Repository RepositoryRequest
	Gate       gateRunRequest
	Run        RunIdentity
	Platform   receiptPlatform
	OutputDir  string
}

type qualificationLaneDependencies struct {
	Repository     laneRepositoryInspector
	Executor       gateExecutor
	Clock          laneClock
	SelfController laneSelfController
	PrivateLogs    gatePrivateLogSink
	AttemptHistory laneAttemptHistoryProvider
}

// laneAttemptHistoryScope is the complete RFC-0002 attempt scope plus the
// current authenticated workflow execution that a provider must exclude from
// its prior-execution answer.
type laneAttemptHistoryScope struct {
	WorkflowRepository     string
	WorkflowPath           string
	TestedRevision         string
	Lane                   Lane
	CurrentWorkflowRunID   string
	CurrentWorkflowAttempt int64
}

// laneAttemptHistoryProvider is a trusted boundary. Implementations must use
// authenticated workflow history and return an error unless the answer is
// complete for the exact scope. Artifact content and receipt claims are not a
// history source.
type laneAttemptHistoryProvider interface {
	HasPriorExecution(context.Context, laneAttemptHistoryScope) (bool, error)
}

type laneRepositoryInspector interface {
	InspectRepository(RepositoryRequest) (RepositorySnapshot, error)
}

type laneClock interface {
	Now() time.Time
}

type laneSelfController interface {
	InspectSelfController() (receiptController, error)
}

func produceQualificationLane(
	ctx context.Context,
	request qualificationLaneRequest,
	dependencies qualificationLaneDependencies,
) (QualificationStatus, error) {
	outputPath, err := validateQualificationLaneRequest(ctx, request, dependencies)
	if err != nil {
		return StatusFail, err
	}
	prior, historyErr := dependencies.AttemptHistory.HasPriorExecution(
		ctx,
		qualificationLaneAttemptHistoryScope(request),
	)
	if historyErr != nil {
		return StatusBlocked, errGateBlocked
	}
	if prior {
		return StatusFail, errGateFailed
	}

	snapshot, err := dependencies.Repository.InspectRepository(request.Repository)
	if err != nil {
		return StatusFail, errQualificationLaneInvalidInput
	}
	subject, archiveFiles, err := sourceFromRepositorySnapshot(snapshot, request)
	if err != nil {
		return StatusFail, errQualificationLaneArchiveInvalid
	}
	archive, manifest, err := buildSourcePackage(subject, archiveFiles)
	if err != nil {
		return StatusFail, errQualificationLaneArchiveInvalid
	}

	controller, err := dependencies.SelfController.InspectSelfController()
	if err != nil || validateReceiptController(controller, receiptSubjectFromSource(subject)) != nil {
		return StatusFail, errQualificationLaneInvalidInput
	}

	started, ok := qualificationLaneTimestamp(dependencies.Clock.Now())
	if !ok {
		return StatusFail, errQualificationLaneReceiptInvalid
	}
	guardedExecutor := &qualificationLaneSourceGuard{
		inner:     dependencies.Executor,
		inspector: dependencies.Repository,
		request:   request.Repository,
		expected:  cloneQualificationLaneSnapshot(snapshot),
	}
	gates, gateErr := runRequiredGates(ctx, request.Gate, guardedExecutor, dependencies.PrivateLogs)
	finished, finishedOK := qualificationLaneTimestamp(dependencies.Clock.Now())
	if !finishedOK || finished.Before(started) {
		return StatusFail, errQualificationLaneReceiptInvalid
	}
	status, ok := qualificationLaneGateStatus(gates, request.Gate.Lane, gateErr)
	if !ok {
		return StatusFail, errQualificationLaneReceiptInvalid
	}

	receipt := qualificationLaneReceipt(
		request,
		subject,
		controller,
		archive,
		manifest,
		gates,
		status,
		started,
		finished,
	)
	receiptRaw, err := marshalCanonicalReceipt(receipt, request.Gate.Lane)
	if err != nil {
		return StatusFail, errQualificationLaneReceiptInvalid
	}
	publication := qualificationLanePublication{}
	if err := publishQualificationLane(
		outputPath,
		request.Gate.Lane,
		archive,
		manifest,
		receiptRaw,
		&publication,
	); err != nil {
		return StatusFail, err
	}
	if err := verifyQualificationLanePublicationSource(
		outputPath,
		request.Repository,
		dependencies.Repository,
		snapshot,
		publication,
	); err != nil {
		return StatusFail, err
	}
	if gateErr != nil {
		return status, gateErr
	}
	return status, nil
}

func validateQualificationLaneRequest(
	ctx context.Context,
	request qualificationLaneRequest,
	dependencies qualificationLaneDependencies,
) (string, error) {
	if ctx == nil || ctx.Err() != nil || nilGateDependency(dependencies.Repository) ||
		nilGateDependency(dependencies.Executor) || nilGateDependency(dependencies.Clock) ||
		nilGateDependency(dependencies.SelfController) || nilGateDependency(dependencies.PrivateLogs) ||
		nilGateDependency(dependencies.AttemptHistory) {
		return "", errQualificationLaneInvalidInput
	}
	if !validRepositoryOID(request.Repository.ExpectedBaseRevision) ||
		!validRepositoryOID(request.Repository.ExpectedTestedRevision) ||
		request.Repository.ExpectedTestedRevision != request.Gate.TestedRevision ||
		request.Repository.ExpectedTestedRevision != request.Run.TestedRevision ||
		!sameCanonicalPath(request.Repository.Root, request.Gate.RepositoryRoot) {
		return "", errQualificationLaneInvalidInput
	}
	if request.Run.WorkflowRepository != canonicalWorkflowRepository ||
		request.Run.WorkflowPath != canonicalWorkflowPath ||
		request.Run.WorkflowRunAttempt != 1 ||
		!validReceiptPositiveDecimal(request.Run.WorkflowRunID, 20) ||
		!validReceiptEventRef(request.Run.Event, request.Run.Ref) {
		return "", errQualificationLaneInvalidInput
	}
	if request.Platform.GOOS != request.Gate.GOOS ||
		request.Platform.GOARCH != request.Gate.GOARCH ||
		validateReceiptPlatform(request.Platform, request.Gate.Lane) != nil ||
		validateReceiptPrivacy(request.Platform) != nil {
		return "", errQualificationLaneInvalidInput
	}

	outputPath, err := canonicalPackageFilesystemPath(request.OutputDir)
	if err != nil || !filepath.IsAbs(request.OutputDir) ||
		filepath.Clean(request.OutputDir) != request.OutputDir ||
		!sameCanonicalPath(outputPath, request.OutputDir) {
		return "", errQualificationLaneInvalidInput
	}
	if outputPath == filepath.Dir(outputPath) ||
		packagePathsOverlapOrUnsafe(request.Repository.Root, outputPath) {
		return "", errQualificationLaneInvalidInput
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return "", errQualificationLaneDestinationExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errQualificationLaneInvalidInput
	}
	parent, _, err := openValidatedPackageDirectory(filepath.Dir(outputPath))
	if err != nil {
		return "", errQualificationLaneInvalidInput
	}
	if err := parent.Close(); err != nil {
		return "", errQualificationLaneInvalidInput
	}
	if _, _, valid := validateGateRunRequest(
		request.Gate,
		dependencies.Executor,
		dependencies.PrivateLogs,
	); !valid {
		return "", errQualificationLaneInvalidInput
	}
	return outputPath, nil
}

func qualificationLaneAttemptHistoryScope(
	request qualificationLaneRequest,
) laneAttemptHistoryScope {
	return laneAttemptHistoryScope{
		WorkflowRepository:     request.Run.WorkflowRepository,
		WorkflowPath:           request.Run.WorkflowPath,
		TestedRevision:         request.Run.TestedRevision,
		Lane:                   request.Gate.Lane,
		CurrentWorkflowRunID:   request.Run.WorkflowRunID,
		CurrentWorkflowAttempt: int64(request.Run.WorkflowRunAttempt),
	}
}

func sourceFromRepositorySnapshot(
	snapshot RepositorySnapshot,
	request qualificationLaneRequest,
) (Subject, []archiveFile, error) {
	subject := Subject{
		BaseRevision:    snapshot.Subject.BaseRevision,
		Dirty:           snapshot.Subject.Dirty,
		GitObjectFormat: snapshot.Subject.GitObjectFormat,
		ModulePath:      snapshot.Subject.ModulePath,
		ModuleVersion:   snapshot.Subject.ModuleVersion,
		Repository:      snapshot.Subject.Repository,
		TestedRevision:  snapshot.Subject.TestedRevision,
		TreeSHA:         snapshot.Subject.TreeSHA,
	}
	if validateSourceSubject(subject) != nil ||
		subject.BaseRevision != request.Repository.ExpectedBaseRevision ||
		subject.TestedRevision != request.Repository.ExpectedTestedRevision ||
		subject.TestedRevision != request.Gate.TestedRevision ||
		subject.TestedRevision != request.Run.TestedRevision {
		return Subject{}, nil, errQualificationLaneArchiveInvalid
	}
	files := make([]archiveFile, len(snapshot.Files))
	for index, file := range snapshot.Files {
		if file.Size < 0 || file.Size != int64(len(file.Data)) ||
			file.GitBlobSHA1 != gitBlobSHA1(file.Data) {
			return Subject{}, nil, errQualificationLaneArchiveInvalid
		}
		files[index] = archiveFile{
			Path:    file.Path,
			GitMode: file.GitMode,
			Data:    append([]byte(nil), file.Data...),
		}
	}
	return subject, files, nil
}

type qualificationLaneSourceGuard struct {
	inner     gateExecutor
	inspector laneRepositoryInspector
	request   RepositoryRequest
	expected  RepositorySnapshot
}

func (guard *qualificationLaneSourceGuard) Execute(
	ctx context.Context,
	request gateProcessRequest,
) (gateProcessResult, error) {
	result, executionErr := guard.inner.Execute(ctx, request)
	if isModuleDownloadGateProcess(request) {
		if restoreErr := restoreQualificationLaneTrackedFiles(guard.request.Root, guard.expected); restoreErr != nil {
			result.SourceChanged = true
		}
	}
	observed, inspectionErr := guard.inspector.InspectRepository(guard.request)
	if inspectionErr != nil || !sameQualificationLaneSnapshot(guard.expected, observed) {
		result.SourceChanged = true
	}
	return result, executionErr
}

func isModuleDownloadGateProcess(request gateProcessRequest) bool {
	for _, spec := range commonGateRegistry {
		if spec.ID != "RP-M0-QUAL-MODULE-DOWNLOAD" {
			continue
		}
		if len(spec.Argv) < 2 || len(request.Args) != len(spec.Argv)-1 {
			return false
		}
		for index, argument := range spec.Argv[1:] {
			if request.Args[index] != argument {
				return false
			}
		}
		return true
	}
	return false
}

// restoreQualificationLaneTrackedFiles overwrites snapshot-tracked worktree
// files in place. Go 1.26 `go mod download -modcacherw all` rewrites go.sum
// with modules that `go mod tidy` does not keep. The gate's job is to fill the
// private module cache; the inspected Git tree remains the source of truth.
// Untracked files are left in place so inspect still fails closed.
func restoreQualificationLaneTrackedFiles(root string, snapshot RepositorySnapshot) error {
	if root == "" {
		return errors.New("tracked restore root is empty")
	}
	for _, file := range snapshot.Files {
		if err := restoreQualificationLaneTrackedFile(root, file); err != nil {
			return err
		}
	}
	return nil
}

func restoreQualificationLaneTrackedFile(root string, file RepositoryFile) error {
	if err := validateRepositoryPath(file.Path); err != nil {
		return err
	}
	path := filepath.Clean(filepath.Join(root, filepath.FromSlash(file.Path)))
	if !filepath.IsAbs(path) {
		return errors.New("tracked restore path is not absolute")
	}
	contains, err := securePackagePathContains(root, path)
	if err != nil || !contains {
		return errors.New("tracked restore path escaped the repository")
	}

	info, statErr := os.Lstat(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return errors.New("tracked restore path is not a regular file")
		}
		if err := restoreQualificationLaneTrackedFileWritable(path, info); err != nil {
			return err
		}
		// Unlink before recreate. O_TRUNC on a shared inode would rewrite the
		// other hard link (Go's module cache) and leave nlink>1 for inspect.
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	mode := os.FileMode(0o644)
	if file.GitMode == "100755" {
		mode = 0o755
	}
	created, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if createErr != nil {
		return createErr
	}
	if err := writeAndCloseExactBytes(created, file.Data); err != nil {
		return err
	}
	return restoreQualificationLaneTrackedFileMode(path, file.GitMode)
}

func restoreQualificationLaneTrackedFileWritable(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o200 != 0 {
		return nil
	}
	return os.Chmod(path, info.Mode().Perm()|0o200)
}

func restoreQualificationLaneTrackedFileMode(path, gitMode string) error {
	mode := os.FileMode(0o644)
	if gitMode == "100755" {
		mode = 0o755
	}
	return os.Chmod(path, mode)
}

func writeAndCloseExactBytes(file *os.File, data []byte) error {
	written, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return closeErr
}

func cloneQualificationLaneSnapshot(snapshot RepositorySnapshot) RepositorySnapshot {
	result := snapshot
	result.Files = append([]RepositoryFile(nil), snapshot.Files...)
	for index := range result.Files {
		result.Files[index].Data = append([]byte(nil), snapshot.Files[index].Data...)
	}
	return result
}

func sameQualificationLaneSnapshot(left, right RepositorySnapshot) bool {
	if left.Subject != right.Subject || len(left.Files) != len(right.Files) {
		return false
	}
	for index := range left.Files {
		leftFile := left.Files[index]
		rightFile := right.Files[index]
		if leftFile.Path != rightFile.Path || leftFile.GitMode != rightFile.GitMode ||
			leftFile.GitBlobSHA1 != rightFile.GitBlobSHA1 || leftFile.Size != rightFile.Size ||
			!bytes.Equal(leftFile.Data, rightFile.Data) {
			return false
		}
	}
	return true
}

func qualificationLaneTimestamp(value time.Time) (time.Time, bool) {
	value = value.UTC().Truncate(time.Second)
	formatted := value.Format(receiptTimestampLayout)
	parsed, ok := parseReceiptTimestamp(formatted)
	return parsed, ok
}

func qualificationLaneGateStatus(
	gates []receiptGate,
	lane Lane,
	gateErr error,
) (QualificationStatus, bool) {
	if len(gates) != len(RequiredGates(lane)) || len(gates) == 0 {
		return StatusFail, false
	}
	statuses := make([]QualificationStatus, len(gates))
	for index, gate := range gates {
		statuses[index] = gate.Status
	}
	status := AggregateQualificationStatus(statuses)
	if status == StatusPass {
		return status, gateErr == nil
	}
	return status, gateErr != nil
}

func qualificationLaneReceipt(
	request qualificationLaneRequest,
	subject Subject,
	controller receiptController,
	archive, manifest []byte,
	gates []receiptGate,
	status QualificationStatus,
	started, finished time.Time,
) qualificationReceipt {
	qualificationRunID := QualificationRunID(request.Run)
	manualActionCount := int64(0)
	if request.Run.Event == "workflow_dispatch" {
		manualActionCount = 1
	}
	skipped := int64(0)
	for _, gate := range gates {
		if gate.Status == StatusNotRun {
			skipped++
		}
	}
	return qualificationReceipt{
		ArtifactType: receiptArtifactType,
		Attempt: receiptAttempt{
			AttemptID:     AttemptID(qualificationRunID, request.Gate.Lane, 1),
			FinishedAt:    finished.Format(receiptTimestampLayout),
			Ordinal:       1,
			PriorAttempts: []receiptPriorAttempt{},
			RetryOf:       nil,
			StartedAt:     started.Format(receiptTimestampLayout),
		},
		Controller: controller,
		Execution: receiptExecution{
			ManualActionCount: manualActionCount,
			RawLogsPublished:  false,
			RetryCount:        0,
			SkippedGateCount:  skipped,
		},
		Gates:               append([]receiptGate(nil), gates...),
		Limitations:         FixedLimitations(),
		NotApplicable:       qualificationLaneNotApplicable(),
		Platform:            request.Platform,
		PredicateType:       receiptPredicateType,
		ProductDimensions:   qualificationLaneProductDimensions(),
		QualificationStatus: status,
		Run: receiptRun{
			Event:              request.Run.Event,
			HeadSHA:            subject.TestedRevision,
			Issuer:             "NOT_ESTABLISHED",
			Lane:               request.Gate.Lane,
			QualificationRunID: qualificationRunID,
			Ref:                request.Run.Ref,
			WorkflowPath:       request.Run.WorkflowPath,
			WorkflowRepository: request.Run.WorkflowRepository,
			WorkflowRunAttempt: int64(request.Run.WorkflowRunAttempt),
			WorkflowRunID:      request.Run.WorkflowRunID,
			WorkflowURL:        receiptRepositoryURL + "/actions/runs/" + request.Run.WorkflowRunID,
		},
		SchemaVersion: receiptSchemaVersion,
		Source: receiptSource{
			Archive: receiptBinding{
				Name: archiveFilename, Role: receiptArchiveRole,
				SHA256: sha256Digest(archive), Size: int64(len(archive)),
			},
			Manifest: receiptBinding{
				Name: qualificationManifestFilename, Role: receiptManifestRole,
				SHA256: sha256Digest(manifest), Size: int64(len(manifest)),
			},
		},
		Subject: receiptSubjectFromSource(subject),
	}
}

func receiptSubjectFromSource(subject Subject) receiptSubject {
	return receiptSubject{
		BaseRevision:    subject.BaseRevision,
		Dirty:           subject.Dirty,
		GitObjectFormat: subject.GitObjectFormat,
		ModulePath:      subject.ModulePath,
		ModuleVersion:   subject.ModuleVersion,
		Repository:      subject.Repository,
		TestedRevision:  subject.TestedRevision,
		TreeSHA:         subject.TreeSHA,
	}
}

func qualificationLaneNotApplicable() receiptNotApplicable {
	return receiptNotApplicable{
		CgroupVersion:          receiptNotApplicableValue,
		ContainerEngineVersion: receiptNotApplicableValue,
		EngineProviderVersion:  receiptNotApplicableValue,
		ImageDigests:           receiptNotApplicableValue,
		ObserverSetDigest:      receiptNotApplicableValue,
		PlanDigest:             receiptNotApplicableValue,
		PolicyDigest:           receiptNotApplicableValue,
		RuntimeVersion:         receiptNotApplicableValue,
		SBOMDigest:             receiptNotApplicableValue,
		SignatureDigest:        receiptNotApplicableValue,
		TrustPolicyDigest:      receiptNotApplicableValue,
	}
}

func qualificationLaneProductDimensions() receiptProductDimensions {
	dimension := receiptDimension{
		EvaluationStatus: string(StatusNotRun),
		Reason:           receiptDimensionReason,
		Value:            nil,
	}
	return receiptProductDimensions{
		Capability:      dimension,
		Cleanup:         dimension,
		Coverage:        dimension,
		Evidence:        dimension,
		Freshness:       dimension,
		Functional:      dimension,
		Overall:         dimension,
		Reproducibility: dimension,
	}
}

func qualificationLaneReceiptName(lane Lane) (string, bool) {
	switch lane {
	case LaneLinuxAMD64:
		return qualificationLinuxReceiptFilename, true
	case LaneWindowsAMD64:
		return qualificationWindowsReceiptFilename, true
	default:
		return "", false
	}
}

type qualificationLanePublication struct {
	identity       packageFileIdentity
	specifications []packageFileSpec
}

func publishQualificationLane(
	outputPath string,
	lane Lane,
	archive, manifest, receipt []byte,
	publication *qualificationLanePublication,
) (returnErr error) {
	receiptName, ok := qualificationLaneReceiptName(lane)
	if publication == nil || !ok || len(archive) == 0 || int64(len(archive)) > maxArchiveBytes ||
		len(manifest) == 0 || len(manifest) > maxManifestBytes ||
		len(receipt) == 0 || len(receipt) > receiptMaxBytes {
		return errQualificationLaneInvalidInput
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		if _, statErr := os.Lstat(outputPath); statErr == nil {
			return errQualificationLaneDestinationExists
		}
		return errQualificationLaneInvalidInput
	}

	outputParent := filepath.Dir(outputPath)
	parent, parentSnapshot, err := openValidatedPackageDirectory(outputParent)
	if err != nil {
		return errQualificationLaneInvalidInput
	}
	defer parent.Close()

	stagingPath := ""
	var cleanupStaging func() error
	var releaseStaging func() error
	defer func() {
		if cleanupStaging == nil {
			return
		}
		if err := cleanupStaging(); err != nil {
			returnErr = errQualificationLaneCleanupFailed
		}
	}()

	stagingPath, cleanupStaging, releaseStaging, err = createPrivateQualificationStaging(
		outputParent,
		qualificationStagingPrefix,
	)
	if err != nil {
		return errQualificationLaneInvalidInput
	}
	if err := securePrivatePackagePath(stagingPath, true); err != nil {
		return errQualificationLaneInvalidInput
	}
	if err := requirePrivatePackageDirectory(stagingPath); err != nil {
		return errQualificationLaneInvalidInput
	}
	if err := requirePackageDirectoryIdentity(outputParent, parentSnapshot.identity); err != nil {
		return errQualificationLaneInvalidInput
	}

	specifications := []packageFileSpec{
		{name: archiveFilename, maxBytes: maxArchiveBytes, expected: archive},
		{name: qualificationManifestFilename, maxBytes: int64(maxManifestBytes), expected: manifest},
		{name: receiptName, maxBytes: int64(receiptMaxBytes), expected: receipt},
	}
	for _, specification := range specifications {
		if err := writePrivatePackageFile(
			filepath.Join(stagingPath, specification.name),
			specification.expected,
		); err != nil {
			return errQualificationLaneInvalidInput
		}
	}
	staged, err := readExactPackageDirectory(stagingPath, specifications)
	if err != nil {
		return errQualificationLaneInvalidInput
	}
	staging, stagingSnapshot, err := openValidatedPackageDirectory(stagingPath)
	if err != nil {
		return errQualificationLaneInvalidInput
	}
	if stagingSnapshot != staged.snapshot {
		_ = staging.Close()
		return errQualificationLaneInvalidInput
	}
	if err := syncPackageDirectory(staging); err != nil {
		_ = staging.Close()
		return errQualificationLaneInvalidInput
	}
	if err := staging.Close(); err != nil {
		return errQualificationLaneInvalidInput
	}

	if err := requirePackageDirectoryIdentity(outputParent, parentSnapshot.identity); err != nil {
		return errQualificationLaneInvalidInput
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		if _, statErr := os.Lstat(outputPath); statErr == nil {
			return errQualificationLaneDestinationExists
		}
		return errQualificationLaneInvalidInput
	}
	if err := publishPackageDirectoryNoReplace(stagingPath, outputPath); err != nil {
		if _, statErr := os.Lstat(outputPath); statErr == nil {
			return errQualificationLaneDestinationExists
		}
		return errQualificationLaneInvalidInput
	}
	if err := releaseStaging(); err != nil {
		cleanupStaging = nil
		if cleanupErr := cleanupPublishedPackage(
			outputPath,
			staged.snapshot.identity,
			specifications,
			parent,
		); cleanupErr != nil {
			return errQualificationLaneCleanupFailed
		}
		return errQualificationLaneCleanupFailed
	}
	cleanupStaging = nil
	releaseStaging = nil
	stagingPath = ""
	if err := syncPackageDirectory(parent); err != nil {
		if cleanupErr := cleanupPublishedPackage(
			outputPath,
			staged.snapshot.identity,
			specifications,
			parent,
		); cleanupErr != nil {
			return errQualificationLaneCleanupFailed
		}
		return errQualificationLaneInvalidInput
	}
	publication.identity = staged.snapshot.identity
	publication.specifications = make([]packageFileSpec, len(specifications))
	for index, specification := range specifications {
		publication.specifications[index] = specification
		publication.specifications[index].expected = append([]byte(nil), specification.expected...)
	}
	return nil
}

func verifyQualificationLanePublicationSource(
	outputPath string,
	request RepositoryRequest,
	inspector laneRepositoryInspector,
	expected RepositorySnapshot,
	publication qualificationLanePublication,
) error {
	if nilGateDependency(inspector) || len(publication.specifications) != 3 {
		return errQualificationLaneCleanupFailed
	}
	parent, parentSnapshot, err := openValidatedPackageDirectory(filepath.Dir(outputPath))
	if err != nil {
		return errQualificationLaneCleanupFailed
	}

	observed, inspectionErr := inspector.InspectRepository(request)
	read, readErr := readExactPackageDirectory(outputPath, publication.specifications)
	parentErr := requirePackageDirectoryIdentity(filepath.Dir(outputPath), parentSnapshot.identity)
	sourceChanged := inspectionErr != nil || !sameQualificationLaneSnapshot(expected, observed)
	publicationChanged := readErr != nil || read.snapshot.identity != publication.identity || parentErr != nil
	if !sourceChanged && !publicationChanged {
		if err := parent.Close(); err != nil {
			return errQualificationLaneCleanupFailed
		}
		return nil
	}

	cleanupErr := cleanupPublishedPackage(
		outputPath,
		publication.identity,
		publication.specifications,
		parent,
	)
	closeErr := parent.Close()
	if cleanupErr != nil || closeErr != nil {
		return errQualificationLaneCleanupFailed
	}
	if sourceChanged {
		return errQualificationLaneSourceDirty
	}
	return errQualificationLaneInvalidInput
}
