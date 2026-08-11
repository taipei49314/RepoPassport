package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/sourcequalification"
)

const (
	commandProduceLane        = "produce-lane"
	commandAssemble           = "assemble"
	commandAssembleTools      = "assemble-tools"
	commandVerifyIntegrity    = "verify-integrity"
	commandVerifySubject      = "verify-subject"
	commandValidateSchemaJSON = "validate-schema-json"
	commandVersion            = "version"

	flagRepoRoot                   = "--repo-root"
	flagLane                       = "--lane"
	flagEvent                      = "--event"
	flagExpectedRef                = "--expected-ref"
	flagExpectedBaseRevision       = "--expected-base-revision"
	flagExpectedTestedRevision     = "--expected-tested-revision"
	flagExpectedTree               = "--expected-tree"
	flagExpectedQualificationRunID = "--expected-qualification-run-id"
	flagWorkflowRunID              = "--workflow-run-id"
	flagWorkflowRunAttempt         = "--workflow-run-attempt"
	flagExpectedWorkflowRunID      = "--expected-workflow-run-id"
	flagExpectedWorkflowRunAttempt = "--expected-workflow-run-attempt"
	flagPrivateLogRoot             = "--private-log-root"
	flagOutDir                     = "--out-dir"
	flagLinuxDir                   = "--linux-dir"
	flagWindowsDir                 = "--windows-dir"
	flagPackageDir                 = "--package-dir"
	flagLinuxController            = "--linux-controller"
	flagWindowsController          = "--windows-controller"
	flagExpectedRepository         = "--expected-repository"
	flagExpectedPackageDigest      = "--expected-package-digest"
	flagToolManifest               = "--tool-manifest"
	flagExpectedToolManifestDigest = "--expected-tool-manifest-digest"
	flagExpectedExecutableDigest   = "--expected-executable-digest"
	flagRoot                       = "--root"

	codeOK              = "SOURCE_QUAL_OK"
	codeInvalidInput    = "SOURCE_QUAL_INVALID_INPUT"
	codeManifestInvalid = "SOURCE_QUAL_MANIFEST_INVALID"
	controllerID        = "repopass-source-qualify"
	schemaJSONGateID    = "RP-M0-QUAL-SCHEMA-JSON"
	statusPass          = "PASS"
	statusFail          = "FAIL"
	notApplicable       = "NOT_APPLICABLE"
	maxPublicRecord     = 4096
)

type controllerRecord struct {
	Code                string `json:"code"`
	ID                  string `json:"id"`
	QualificationStatus string `json:"qualificationStatus"`
	SHA256              string `json:"sha256"`
	TestedRevision      string `json:"testedRevision"`
	TreeSHA             string `json:"treeSHA"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithControllerOperations(args, stdout, stderr, newProductionControllerCommandOperations())
}

func runWithoutControllerOperations(args []string, stdout, stderr io.Writer) int {
	// Public controller diagnostics never use stderr. Retain the parameter so
	// callers can prove that flag parsing and underlying errors remain private.
	_ = stderr
	_ = rfcCommandAndFlagVocabulary

	record := newControllerRecord(codeInvalidInput, controllerID, statusFail)
	exitCode := 2
	if len(args) == 1 && args[0] == commandVersion {
		record = newControllerRecord(codeOK, controllerID, statusPass)
		exitCode = 0
	} else if len(args) > 0 && args[0] == commandValidateSchemaJSON {
		record, exitCode = runValidateSchemaJSON(args)
	}

	if !writeControllerRecord(stdout, record) {
		return 1
	}
	return exitCode
}

func runValidateSchemaJSON(args []string) (controllerRecord, int) {
	if len(args) != 3 || args[1] != flagRoot || args[2] == "" {
		return newControllerRecord(codeInvalidInput, controllerID, statusFail), 2
	}
	root, err := filepath.Abs(args[2])
	if err != nil {
		return newControllerRecord(codeManifestInvalid, schemaJSONGateID, statusFail), 1
	}
	if err := sourcequalification.ValidateSchemaJSON(filepath.Clean(root)); err != nil {
		return newControllerRecord(codeManifestInvalid, schemaJSONGateID, statusFail), 1
	}
	return newControllerRecord(codeOK, schemaJSONGateID, statusPass), 0
}

func deferredCommand(value string) bool {
	switch value {
	case commandProduceLane,
		commandAssemble,
		commandAssembleTools,
		commandVerifyIntegrity,
		commandVerifySubject:
		return true
	default:
		return false
	}
}

func newControllerRecord(code, id, status string) controllerRecord {
	return controllerRecord{
		Code:                code,
		ID:                  id,
		QualificationStatus: status,
		SHA256:              notApplicable,
		TestedRevision:      notApplicable,
		TreeSHA:             notApplicable,
	}
}

func writeControllerRecord(destination io.Writer, record controllerRecord) bool {
	if destination == nil {
		return false
	}
	raw, err := canonicaljson.Marshal(record)
	if err != nil || len(raw)+1 > maxPublicRecord {
		return false
	}
	raw = append(raw, '\n')
	written, err := destination.Write(raw)
	return err == nil && written == len(raw)
}

// Keep the complete RFC command and flag vocabulary in this private binary.
// Implemented dispatch still accepts only the exact token shapes above.
var rfcCommandAndFlagVocabulary = [...]string{
	commandProduceLane,
	commandAssemble,
	commandAssembleTools,
	commandVerifyIntegrity,
	commandVerifySubject,
	commandValidateSchemaJSON,
	commandVersion,
	flagRepoRoot,
	flagLane,
	flagEvent,
	flagExpectedRef,
	flagExpectedBaseRevision,
	flagExpectedTestedRevision,
	flagExpectedTree,
	flagExpectedQualificationRunID,
	flagWorkflowRunID,
	flagWorkflowRunAttempt,
	flagExpectedWorkflowRunID,
	flagExpectedWorkflowRunAttempt,
	flagPrivateLogRoot,
	flagOutDir,
	flagLinuxDir,
	flagWindowsDir,
	flagPackageDir,
	flagLinuxController,
	flagWindowsController,
	flagExpectedRepository,
	flagExpectedPackageDigest,
	flagToolManifest,
	flagExpectedToolManifestDigest,
	flagExpectedExecutableDigest,
	flagRoot,
}
