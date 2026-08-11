package sourcequalification

import (
	"errors"
	"os"
	"strings"
)

const (
	controllerCodeOK                = "SOURCE_QUAL_OK"
	controllerCodeInvalidInput      = "SOURCE_QUAL_INVALID_INPUT"
	controllerCodeSubjectMismatch   = "SOURCE_QUAL_SUBJECT_MISMATCH"
	controllerCodeArchiveInvalid    = "SOURCE_QUAL_ARCHIVE_INVALID"
	controllerCodeReceiptInvalid    = "SOURCE_QUAL_RECEIPT_INVALID"
	controllerCodeCleanupFailed     = "SOURCE_QUAL_CLEANUP_FAILED"
	controllerCodeOutputLimit       = "SOURCE_QUAL_OUTPUT_LIMIT"
	controllerCodeDestinationExists = "SOURCE_QUAL_DESTINATION_EXISTS"

	controllerStatusPass                = "PASS"
	controllerStatusFail                = "FAIL"
	controllerStatusHistoricalIntegrity = "HISTORICAL_INTEGRITY"
	controllerStatusSubjectMatch        = "SUBJECT_MATCH"
	controllerNotApplicable             = "NOT_APPLICABLE"
)

// ControllerResult is the bounded public fact set returned by the private
// RFC-0002 controller facade. Underlying errors and filesystem paths never
// enter this value.
type ControllerResult struct {
	Code                string
	QualificationStatus string
	SHA256              string
	TestedRevision      string
	TreeSHA             string
}

type AssembleRequest struct {
	LinuxDir                   string
	WindowsDir                 string
	ExpectedBaseRevision       string
	ExpectedTestedRevision     string
	ExpectedTreeSHA            string
	ExpectedQualificationRunID string
	ExpectedWorkflowRunID      string
	ExpectedWorkflowRunAttempt int64
	OutputDir                  string
}

type AssembleToolsRequest struct {
	PackageDir        string
	LinuxController   string
	WindowsController string
	OutputDir         string
}

type VerifyIntegrityRequest struct {
	PackageDir string
}

type VerifySubjectRequest struct {
	PackageDir                 string
	ExpectedRepository         string
	ExpectedBaseRevision       string
	ExpectedTestedRevision     string
	ExpectedTreeSHA            string
	ExpectedQualificationRunID string
	ExpectedWorkflowRunID      string
	ExpectedWorkflowRunAttempt int64
	ExpectedPackageDigest      string
	ToolManifestPath           string
	ExpectedToolManifestDigest string
	ExpectedExecutableDigest   string
}

// Assemble validates all six independently supplied identities against the
// exact lane bytes held by the package assembler before it creates staging or
// publishes an output directory.
func Assemble(request AssembleRequest) (ControllerResult, error) {
	if !validAssembleRequest(request) {
		return controllerFailure(controllerCodeInvalidInput)
	}
	linuxDir, err := canonicalPackageFilesystemPath(request.LinuxDir)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	windowsDir, err := canonicalPackageFilesystemPath(request.WindowsDir)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	outputDir, code := controllerOutputDestination(request.OutputDir)
	if code != "" {
		return controllerFailure(code)
	}

	digest, err := assembleQualificationPackageWithExpectation(
		linuxDir,
		windowsDir,
		outputDir,
		&qualificationPackageExpectation{
			baseRevision:       request.ExpectedBaseRevision,
			testedRevision:     request.ExpectedTestedRevision,
			treeSHA:            request.ExpectedTreeSHA,
			qualificationRunID: request.ExpectedQualificationRunID,
			workflowRunID:      request.ExpectedWorkflowRunID,
			workflowRunAttempt: request.ExpectedWorkflowRunAttempt,
		},
	)
	if err != nil {
		if errors.Is(err, errQualificationPackageExpectationMismatch) {
			return controllerFailure(controllerCodeSubjectMismatch)
		}
		return controllerFailure(controllerPublicationErrorCode(
			err,
			outputDir,
			controllerCodeReceiptInvalid,
		))
	}
	return controllerSuccess(
		controllerStatusPass,
		digest,
		request.ExpectedTestedRevision,
		request.ExpectedTreeSHA,
	), nil
}

func AssembleTools(request AssembleToolsRequest) (ControllerResult, error) {
	if request.PackageDir == "" || request.LinuxController == "" ||
		request.WindowsController == "" || request.OutputDir == "" {
		return controllerFailure(controllerCodeInvalidInput)
	}
	packageDir, err := canonicalPackageFilesystemPath(request.PackageDir)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	linuxController, err := canonicalPackageFilesystemPath(request.LinuxController)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	windowsController, err := canonicalPackageFilesystemPath(request.WindowsController)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	outputDir, code := controllerOutputDestination(request.OutputDir)
	if code != "" {
		return controllerFailure(code)
	}

	var subject Subject
	digest, err := assembleQualificationToolsWithSubject(
		packageDir,
		linuxController,
		windowsController,
		outputDir,
		&subject,
	)
	if err != nil {
		return controllerFailure(controllerPublicationErrorCode(
			err,
			outputDir,
			controllerCodeReceiptInvalid,
		))
	}
	return controllerSuccess(
		controllerStatusPass,
		digest,
		subject.TestedRevision,
		subject.TreeSHA,
	), nil
}

func VerifyIntegrity(request VerifyIntegrityRequest) (ControllerResult, error) {
	if request.PackageDir == "" {
		return controllerFailure(controllerCodeInvalidInput)
	}
	packageDir, err := canonicalPackageFilesystemPath(request.PackageDir)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	report, err := inspectQualificationPackage(packageDir)
	if err != nil {
		return controllerFailure(controllerCodeArchiveInvalid)
	}
	return controllerSuccess(
		controllerStatusHistoricalIntegrity,
		report.PackageDigest,
		report.Subject.TestedRevision,
		report.Subject.TreeSHA,
	), nil
}

func VerifySubject(request VerifySubjectRequest) (ControllerResult, error) {
	packageDir, err := canonicalPackageFilesystemPath(request.PackageDir)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	toolManifestPath, err := canonicalPackageFilesystemPath(request.ToolManifestPath)
	if err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	internalRequest := qualificationSubjectRequest{
		PackageDir:                 packageDir,
		ExpectedRepository:         request.ExpectedRepository,
		ExpectedBaseRevision:       request.ExpectedBaseRevision,
		ExpectedTestedRevision:     request.ExpectedTestedRevision,
		ExpectedTreeSHA:            request.ExpectedTreeSHA,
		ExpectedQualificationRunID: request.ExpectedQualificationRunID,
		ExpectedWorkflowRunID:      request.ExpectedWorkflowRunID,
		ExpectedWorkflowRunAttempt: request.ExpectedWorkflowRunAttempt,
		ExpectedPackageDigest:      request.ExpectedPackageDigest,
		ToolManifestPath:           toolManifestPath,
		ExpectedToolManifestDigest: request.ExpectedToolManifestDigest,
		ExpectedExecutableDigest:   request.ExpectedExecutableDigest,
	}
	if err := validateQualificationSubjectRequest(internalRequest); err != nil {
		return controllerFailure(controllerCodeInvalidInput)
	}
	report, err := verifyQualificationSubject(internalRequest)
	if err != nil {
		return controllerFailure(controllerCodeSubjectMismatch)
	}
	return controllerSuccess(
		controllerStatusSubjectMatch,
		report.PackageDigest,
		report.Subject.TestedRevision,
		report.Subject.TreeSHA,
	), nil
}

func validAssembleRequest(request AssembleRequest) bool {
	return request.LinuxDir != "" && request.WindowsDir != "" && request.OutputDir != "" &&
		validReceiptGitSHA1(request.ExpectedBaseRevision) &&
		validReceiptGitSHA1(request.ExpectedTestedRevision) &&
		validReceiptGitSHA1(request.ExpectedTreeSHA) &&
		validReceiptSHA256(request.ExpectedQualificationRunID) &&
		validReceiptPositiveDecimal(request.ExpectedWorkflowRunID, 20) &&
		request.ExpectedWorkflowRunAttempt >= 1 &&
		request.ExpectedWorkflowRunAttempt <= receiptMaxInt32
}

func controllerOutputDestination(path string) (string, string) {
	canonical, err := canonicalPackageFilesystemPath(path)
	if err != nil {
		return "", controllerCodeInvalidInput
	}
	_, err = os.Lstat(canonical)
	if err == nil {
		return "", controllerCodeDestinationExists
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", controllerCodeInvalidInput
	}
	return canonical, ""
}

func controllerPublicationErrorCode(err error, outputDir, fallback string) string {
	if err == nil {
		return controllerCodeInvalidInput
	}
	message := err.Error()
	if strings.Contains(message, "cleanup") {
		return controllerCodeCleanupFailed
	}
	if strings.Contains(message, "limit") || strings.Contains(message, "bound") {
		return controllerCodeOutputLimit
	}
	if _, statErr := os.Lstat(outputDir); statErr == nil {
		return controllerCodeDestinationExists
	}
	return fallback
}

func controllerSuccess(status, digest, testedRevision, treeSHA string) ControllerResult {
	return ControllerResult{
		Code:                controllerCodeOK,
		QualificationStatus: status,
		SHA256:              digest,
		TestedRevision:      testedRevision,
		TreeSHA:             treeSHA,
	}
}

func controllerFailure(code string) (ControllerResult, error) {
	return ControllerResult{
		Code:                code,
		QualificationStatus: controllerStatusFail,
		SHA256:              controllerNotApplicable,
		TestedRevision:      controllerNotApplicable,
		TreeSHA:             controllerNotApplicable,
	}, errors.New(code)
}
