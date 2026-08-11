package main

import (
	"errors"
	"io"
	"strconv"
	"strings"
)

const canonicalRepository = "https://github.com/taipei49314/RepoPassport"

type controllerCommandOperations interface {
	ProduceLane(produceLaneCommandRequest) (controllerRecord, error)
	Assemble(assembleCommandRequest) (controllerRecord, error)
	AssembleTools(assembleToolsCommandRequest) (controllerRecord, error)
	VerifyIntegrity(verifyIntegrityCommandRequest) (controllerRecord, error)
	VerifySubject(verifySubjectCommandRequest) (controllerRecord, error)
}

type produceLaneCommandRequest struct {
	RepoRoot               string
	Lane                   string
	Event                  string
	ExpectedRef            string
	ExpectedBaseRevision   string
	ExpectedTestedRevision string
	WorkflowRunID          string
	WorkflowRunAttempt     int
	PrivateLogRoot         string
	OutputDir              string
}

type assembleCommandRequest struct {
	LinuxDir                   string
	WindowsDir                 string
	ExpectedBaseRevision       string
	ExpectedTestedRevision     string
	ExpectedTreeSHA            string
	ExpectedQualificationRunID string
	ExpectedWorkflowRunID      string
	ExpectedWorkflowRunAttempt int
	OutputDir                  string
}

type assembleToolsCommandRequest struct {
	PackageDir        string
	LinuxController   string
	WindowsController string
	OutputDir         string
}

type verifyIntegrityCommandRequest struct {
	PackageDir string
}

type verifySubjectCommandRequest struct {
	PackageDir                 string
	ExpectedRepository         string
	ExpectedBaseRevision       string
	ExpectedTestedRevision     string
	ExpectedTreeSHA            string
	ExpectedQualificationRunID string
	ExpectedWorkflowRunID      string
	ExpectedWorkflowRunAttempt int
	ExpectedPackageDigest      string
	ToolManifestPath           string
	ExpectedToolManifestDigest string
	ExpectedExecutableDigest   string
}

// unavailableControllerCommandOperations keeps production honest until the
// filesystem and verification adapters are installed. A syntactically valid
// command still fails with one fixed public record and no raw diagnostic.
type unavailableControllerCommandOperations struct{}

var errControllerOperationUnavailable = errors.New("controller operation unavailable")

func (unavailableControllerCommandOperations) ProduceLane(produceLaneCommandRequest) (controllerRecord, error) {
	return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
}

func (unavailableControllerCommandOperations) Assemble(assembleCommandRequest) (controllerRecord, error) {
	return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
}

func (unavailableControllerCommandOperations) AssembleTools(assembleToolsCommandRequest) (controllerRecord, error) {
	return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
}

func (unavailableControllerCommandOperations) VerifyIntegrity(verifyIntegrityCommandRequest) (controllerRecord, error) {
	return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
}

func (unavailableControllerCommandOperations) VerifySubject(verifySubjectCommandRequest) (controllerRecord, error) {
	return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
}

func runWithControllerOperations(
	args []string,
	stdout, stderr io.Writer,
	operations controllerCommandOperations,
) int {
	_ = stderr

	if len(args) == 0 || !deferredCommand(args[0]) {
		return runWithoutControllerOperations(args, stdout, stderr)
	}

	record := newControllerRecord(codeInvalidInput, controllerID, statusFail)
	exitCode := 2
	if operations != nil {
		var operationErr error
		switch args[0] {
		case commandProduceLane:
			var request produceLaneCommandRequest
			request, operationErr = parseProduceLaneCommand(args)
			if operationErr == nil {
				record, operationErr = operations.ProduceLane(request)
				record, exitCode = sanitizeControllerRecord(commandProduceLane, record, operationErr)
			}
		case commandAssemble:
			var request assembleCommandRequest
			request, operationErr = parseAssembleCommand(args)
			if operationErr == nil {
				record, operationErr = operations.Assemble(request)
				record, exitCode = sanitizeControllerRecord(commandAssemble, record, operationErr)
			}
		case commandAssembleTools:
			var request assembleToolsCommandRequest
			request, operationErr = parseAssembleToolsCommand(args)
			if operationErr == nil {
				record, operationErr = operations.AssembleTools(request)
				record, exitCode = sanitizeControllerRecord(commandAssembleTools, record, operationErr)
			}
		case commandVerifyIntegrity:
			var request verifyIntegrityCommandRequest
			request, operationErr = parseVerifyIntegrityCommand(args)
			if operationErr == nil {
				record, operationErr = operations.VerifyIntegrity(request)
				record, exitCode = sanitizeControllerRecord(commandVerifyIntegrity, record, operationErr)
			}
		case commandVerifySubject:
			var request verifySubjectCommandRequest
			request, operationErr = parseVerifySubjectCommand(args)
			if operationErr == nil {
				record, operationErr = operations.VerifySubject(request)
				record, exitCode = sanitizeControllerRecord(commandVerifySubject, record, operationErr)
			}
		}
	}

	if !writeControllerRecord(stdout, record) {
		return 1
	}
	return exitCode
}

var errInvalidControllerCommand = errors.New("invalid controller command")

func parseProduceLaneCommand(args []string) (produceLaneCommandRequest, error) {
	values, ok := parseOrderedFlagValues(args, commandProduceLane, []string{
		flagRepoRoot,
		flagLane,
		flagEvent,
		flagExpectedRef,
		flagExpectedBaseRevision,
		flagExpectedTestedRevision,
		flagWorkflowRunID,
		flagWorkflowRunAttempt,
		flagPrivateLogRoot,
		flagOutDir,
	})
	if !ok {
		return produceLaneCommandRequest{}, errInvalidControllerCommand
	}
	attempt, ok := parseWorkflowRunAttempt(values[7])
	if !ok || !validLane(values[1]) || !validEventRef(values[2], values[3]) ||
		!validLowerHex(values[4], 40) || !validLowerHex(values[5], 40) ||
		!validWorkflowRunID(values[6]) {
		return produceLaneCommandRequest{}, errInvalidControllerCommand
	}
	return produceLaneCommandRequest{
		RepoRoot:               values[0],
		Lane:                   values[1],
		Event:                  values[2],
		ExpectedRef:            values[3],
		ExpectedBaseRevision:   values[4],
		ExpectedTestedRevision: values[5],
		WorkflowRunID:          values[6],
		WorkflowRunAttempt:     attempt,
		PrivateLogRoot:         values[8],
		OutputDir:              values[9],
	}, nil
}

func parseAssembleCommand(args []string) (assembleCommandRequest, error) {
	values, ok := parseOrderedFlagValues(args, commandAssemble, []string{
		flagLinuxDir,
		flagWindowsDir,
		flagExpectedBaseRevision,
		flagExpectedTestedRevision,
		flagExpectedTree,
		flagExpectedQualificationRunID,
		flagExpectedWorkflowRunID,
		flagExpectedWorkflowRunAttempt,
		flagOutDir,
	})
	if !ok {
		return assembleCommandRequest{}, errInvalidControllerCommand
	}
	attempt, ok := parseWorkflowRunAttempt(values[7])
	if !ok || !validLowerHex(values[2], 40) || !validLowerHex(values[3], 40) ||
		!validLowerHex(values[4], 40) || !validSHA256(values[5]) ||
		!validWorkflowRunID(values[6]) {
		return assembleCommandRequest{}, errInvalidControllerCommand
	}
	return assembleCommandRequest{
		LinuxDir:                   values[0],
		WindowsDir:                 values[1],
		ExpectedBaseRevision:       values[2],
		ExpectedTestedRevision:     values[3],
		ExpectedTreeSHA:            values[4],
		ExpectedQualificationRunID: values[5],
		ExpectedWorkflowRunID:      values[6],
		ExpectedWorkflowRunAttempt: attempt,
		OutputDir:                  values[8],
	}, nil
}

func parseAssembleToolsCommand(args []string) (assembleToolsCommandRequest, error) {
	values, ok := parseOrderedFlagValues(args, commandAssembleTools, []string{
		flagPackageDir,
		flagLinuxController,
		flagWindowsController,
		flagOutDir,
	})
	if !ok {
		return assembleToolsCommandRequest{}, errInvalidControllerCommand
	}
	return assembleToolsCommandRequest{
		PackageDir:        values[0],
		LinuxController:   values[1],
		WindowsController: values[2],
		OutputDir:         values[3],
	}, nil
}

func parseVerifyIntegrityCommand(args []string) (verifyIntegrityCommandRequest, error) {
	values, ok := parseOrderedFlagValues(args, commandVerifyIntegrity, []string{flagPackageDir})
	if !ok {
		return verifyIntegrityCommandRequest{}, errInvalidControllerCommand
	}
	return verifyIntegrityCommandRequest{PackageDir: values[0]}, nil
}

func parseVerifySubjectCommand(args []string) (verifySubjectCommandRequest, error) {
	values, ok := parseOrderedFlagValues(args, commandVerifySubject, []string{
		flagPackageDir,
		flagExpectedRepository,
		flagExpectedBaseRevision,
		flagExpectedTestedRevision,
		flagExpectedTree,
		flagExpectedQualificationRunID,
		flagExpectedWorkflowRunID,
		flagExpectedWorkflowRunAttempt,
		flagExpectedPackageDigest,
		flagToolManifest,
		flagExpectedToolManifestDigest,
		flagExpectedExecutableDigest,
	})
	if !ok {
		return verifySubjectCommandRequest{}, errInvalidControllerCommand
	}
	attempt, ok := parseWorkflowRunAttempt(values[7])
	if !ok || values[1] != canonicalRepository || !validLowerHex(values[2], 40) ||
		!validLowerHex(values[3], 40) || !validLowerHex(values[4], 40) ||
		!validSHA256(values[5]) || !validWorkflowRunID(values[6]) ||
		!validSHA256(values[8]) || !validSHA256(values[10]) || !validSHA256(values[11]) {
		return verifySubjectCommandRequest{}, errInvalidControllerCommand
	}
	return verifySubjectCommandRequest{
		PackageDir:                 values[0],
		ExpectedRepository:         values[1],
		ExpectedBaseRevision:       values[2],
		ExpectedTestedRevision:     values[3],
		ExpectedTreeSHA:            values[4],
		ExpectedQualificationRunID: values[5],
		ExpectedWorkflowRunID:      values[6],
		ExpectedWorkflowRunAttempt: attempt,
		ExpectedPackageDigest:      values[8],
		ToolManifestPath:           values[9],
		ExpectedToolManifestDigest: values[10],
		ExpectedExecutableDigest:   values[11],
	}, nil
}

func parseOrderedFlagValues(args []string, command string, flags []string) ([]string, bool) {
	if len(args) != 1+2*len(flags) || args[0] != command {
		return nil, false
	}
	values := make([]string, len(flags))
	for index, flag := range flags {
		argumentIndex := 1 + 2*index
		if args[argumentIndex] != flag || args[argumentIndex+1] == "" {
			return nil, false
		}
		values[index] = args[argumentIndex+1]
	}
	return values, true
}

func validLane(value string) bool {
	return value == "linux-amd64" || value == "windows-amd64"
}

func validEventRef(event, ref string) bool {
	switch event {
	case "push":
		return ref == "refs/heads/main"
	case "pull_request":
		const prefix = "refs/pull/"
		const suffix = "/merge"
		return len(ref) <= 4096 && strings.HasPrefix(ref, prefix) && strings.HasSuffix(ref, suffix) &&
			validPositiveDecimal(ref[len(prefix):len(ref)-len(suffix)], 4096)
	case "workflow_dispatch":
		const prefix = "refs/heads/"
		return len(ref) <= 255 && len(ref) > len(prefix) && strings.HasPrefix(ref, prefix) && validPrintableASCII(ref)
	default:
		return false
	}
}

func validPrintableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validWorkflowRunID(value string) bool {
	return validPositiveDecimal(value, 20)
}

func validPositiveDecimal(value string, maximumDigits int) bool {
	if len(value) == 0 || len(value) > maximumDigits || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func parseWorkflowRunAttempt(value string) (int, bool) {
	if !validPositiveDecimal(value, 10) {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 1 {
		return 0, false
	}
	return int(parsed), true
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := 0; index < len(value); index++ {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") &&
		validLowerHex(strings.TrimPrefix(value, "sha256:"), 64)
}

func sanitizeControllerRecord(command string, record controllerRecord, operationErr error) (controllerRecord, int) {
	fallback := newControllerRecord(codeInvalidInput, controllerID, statusFail)
	if record.ID != controllerID || !allowedControllerCode(record.Code) ||
		!allowedControllerStatus(record.QualificationStatus) ||
		!allowedDigestOrNotApplicable(record.SHA256) ||
		!allowedRevisionOrNotApplicable(record.TestedRevision) ||
		!allowedRevisionOrNotApplicable(record.TreeSHA) {
		return fallback, 1
	}

	if operationErr == nil {
		if record.Code != codeOK || record.QualificationStatus != successfulCommandStatus(command) ||
			record.TestedRevision == notApplicable || record.TreeSHA == notApplicable {
			return fallback, 1
		}
		if command == commandProduceLane {
			if record.SHA256 != notApplicable {
				return fallback, 1
			}
		} else if record.SHA256 == notApplicable {
			return fallback, 1
		}
		return record, 0
	}

	if record.Code == codeOK || record.QualificationStatus != failureStatusForCode(record.Code) ||
		record.SHA256 != notApplicable || record.TestedRevision != notApplicable || record.TreeSHA != notApplicable {
		return fallback, 1
	}
	return record, 1
}

func successfulCommandStatus(command string) string {
	switch command {
	case commandProduceLane, commandAssemble, commandAssembleTools:
		return statusPass
	case commandVerifyIntegrity:
		return "HISTORICAL_INTEGRITY"
	case commandVerifySubject:
		return "SUBJECT_MATCH"
	default:
		return ""
	}
}

func failureStatusForCode(code string) string {
	switch code {
	case "SOURCE_QUAL_GATE_BLOCKED":
		return "BLOCKED"
	case "SOURCE_QUAL_GATE_NOT_RUN":
		return "NOT_RUN"
	default:
		return statusFail
	}
}

func allowedControllerCode(code string) bool {
	switch code {
	case codeOK,
		codeInvalidInput,
		"SOURCE_QUAL_SOURCE_DIRTY",
		"SOURCE_QUAL_SUBJECT_MISMATCH",
		"SOURCE_QUAL_ARCHIVE_INVALID",
		codeManifestInvalid,
		"SOURCE_QUAL_RECEIPT_INVALID",
		"SOURCE_QUAL_GATE_SET_INVALID",
		"SOURCE_QUAL_GATE_FAILED",
		"SOURCE_QUAL_GATE_BLOCKED",
		"SOURCE_QUAL_GATE_NOT_RUN",
		"SOURCE_QUAL_PRIVACY_INVALID",
		"SOURCE_QUAL_CLEANUP_FAILED",
		"SOURCE_QUAL_OUTPUT_LIMIT",
		"SOURCE_QUAL_DESTINATION_EXISTS":
		return true
	default:
		return false
	}
}

func allowedControllerStatus(status string) bool {
	switch status {
	case statusPass, statusFail, "BLOCKED", "NOT_RUN", "HISTORICAL_INTEGRITY", "SUBJECT_MATCH":
		return true
	default:
		return false
	}
}

func allowedDigestOrNotApplicable(value string) bool {
	return value == notApplicable || validSHA256(value)
}

func allowedRevisionOrNotApplicable(value string) bool {
	return value == notApplicable || validLowerHex(value, 40)
}
