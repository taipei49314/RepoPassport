package main

// Production facade adapter contract under test:
//
//	type productionControllerCommandOperations struct {
//		produceLane     func(context.Context, sourcequalification.ProduceLaneRequest) (sourcequalification.ControllerResult, error)
//		assemble        func(sourcequalification.AssembleRequest) (sourcequalification.ControllerResult, error)
//		assembleTools   func(sourcequalification.AssembleToolsRequest) (sourcequalification.ControllerResult, error)
//		verifyIntegrity func(sourcequalification.VerifyIntegrityRequest) (sourcequalification.ControllerResult, error)
//		verifySubject   func(sourcequalification.VerifySubjectRequest) (sourcequalification.ControllerResult, error)
//	}
//
// The five available methods map every private CLI request field into the
// exported internal-only typed facade. run uses this production adapter by
// default, so a valid available command is never reported as a parser/deferred-
// command failure.

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/sourcequalification"
)

func TestProductionControllerOperationsMapEveryFacadeRequestField(t *testing.T) {
	fixture := newCLICommandFixture(t)
	const maximumAttempt = int(math.MaxInt32)

	produceLaneInput := produceLaneCommandRequest{
		RepoRoot:               fixture.repoRoot,
		Lane:                   "linux-amd64",
		Event:                  "push",
		ExpectedRef:            "refs/heads/main",
		ExpectedBaseRevision:   fixture.baseRevision,
		ExpectedTestedRevision: fixture.testedRevision,
		WorkflowRunID:          fixture.workflowRunID,
		WorkflowRunAttempt:     1,
		PrivateLogRoot:         fixture.privateLogRoot,
		OutputDir:              fixture.laneOutputDir,
	}
	cliSetExpectedTreeSHA(t, &produceLaneInput, fixture.treeSHA)
	assembleInput := assembleCommandRequest{
		LinuxDir:                   fixture.linuxDir,
		WindowsDir:                 fixture.windowsDir,
		ExpectedBaseRevision:       fixture.baseRevision,
		ExpectedTestedRevision:     fixture.testedRevision,
		ExpectedTreeSHA:            fixture.treeSHA,
		ExpectedQualificationRunID: fixture.qualificationRunID,
		ExpectedWorkflowRunID:      fixture.workflowRunID,
		ExpectedWorkflowRunAttempt: maximumAttempt,
		OutputDir:                  fixture.aggregateOutputDir,
	}
	assembleToolsInput := assembleToolsCommandRequest{
		PackageDir:        fixture.packageDir,
		LinuxController:   fixture.linuxController,
		WindowsController: fixture.windowsController,
		OutputDir:         fixture.toolsOutputDir,
	}
	verifyIntegrityInput := verifyIntegrityCommandRequest{PackageDir: fixture.packageDir}
	verifySubjectInput := verifySubjectCommandRequest{
		PackageDir:                 fixture.packageDir,
		ExpectedRepository:         canonicalRepository,
		ExpectedBaseRevision:       fixture.baseRevision,
		ExpectedTestedRevision:     fixture.testedRevision,
		ExpectedTreeSHA:            fixture.treeSHA,
		ExpectedQualificationRunID: fixture.qualificationRunID,
		ExpectedWorkflowRunID:      fixture.workflowRunID,
		ExpectedWorkflowRunAttempt: maximumAttempt,
		ExpectedPackageDigest:      fixture.packageDigest,
		ToolManifestPath:           fixture.toolManifest,
		ExpectedToolManifestDigest: fixture.toolManifestDigest,
		ExpectedExecutableDigest:   fixture.executableDigest,
	}

	var gotProduceLane sourcequalification.ProduceLaneRequest
	var gotAssemble sourcequalification.AssembleRequest
	var gotAssembleTools sourcequalification.AssembleToolsRequest
	var gotVerifyIntegrity sourcequalification.VerifyIntegrityRequest
	var gotVerifySubject sourcequalification.VerifySubjectRequest
	results := map[string]sourcequalification.ControllerResult{
		commandProduceLane: {
			Code:                codeOK,
			QualificationStatus: statusPass,
			SHA256:              notApplicable,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		},
		commandAssemble: {
			Code:                codeOK,
			QualificationStatus: statusPass,
			SHA256:              fixture.packageDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		},
		commandAssembleTools: {
			Code:                codeOK,
			QualificationStatus: statusPass,
			SHA256:              fixture.toolManifestDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		},
		commandVerifyIntegrity: {
			Code:                codeOK,
			QualificationStatus: cliHistoricalIntegrity,
			SHA256:              fixture.packageDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		},
		commandVerifySubject: {
			Code:                codeOK,
			QualificationStatus: cliSubjectMatch,
			SHA256:              fixture.packageDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		},
	}
	operations := productionControllerCommandOperations{
		produceLane: func(_ context.Context, request sourcequalification.ProduceLaneRequest) (sourcequalification.ControllerResult, error) {
			gotProduceLane = request
			return results[commandProduceLane], nil
		},
		assemble: func(request sourcequalification.AssembleRequest) (sourcequalification.ControllerResult, error) {
			gotAssemble = request
			return results[commandAssemble], nil
		},
		assembleTools: func(request sourcequalification.AssembleToolsRequest) (sourcequalification.ControllerResult, error) {
			gotAssembleTools = request
			return results[commandAssembleTools], nil
		},
		verifyIntegrity: func(request sourcequalification.VerifyIntegrityRequest) (sourcequalification.ControllerResult, error) {
			gotVerifyIntegrity = request
			return results[commandVerifyIntegrity], nil
		},
		verifySubject: func(request sourcequalification.VerifySubjectRequest) (sourcequalification.ControllerResult, error) {
			gotVerifySubject = request
			return results[commandVerifySubject], nil
		},
	}

	tests := []struct {
		name       string
		invoke     func() (controllerRecord, error)
		wantResult sourcequalification.ControllerResult
	}{
		{commandProduceLane, func() (controllerRecord, error) { return operations.ProduceLane(produceLaneInput) }, results[commandProduceLane]},
		{commandAssemble, func() (controllerRecord, error) { return operations.Assemble(assembleInput) }, results[commandAssemble]},
		{commandAssembleTools, func() (controllerRecord, error) { return operations.AssembleTools(assembleToolsInput) }, results[commandAssembleTools]},
		{commandVerifyIntegrity, func() (controllerRecord, error) { return operations.VerifyIntegrity(verifyIntegrityInput) }, results[commandVerifyIntegrity]},
		{commandVerifySubject, func() (controllerRecord, error) { return operations.VerifySubject(verifySubjectInput) }, results[commandVerifySubject]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, err := test.invoke()
			if err != nil {
				t.Fatalf("production adapter %s: %v", test.name, err)
			}
			adapterRequireControllerRecord(t, record, test.wantResult)
		})
	}

	wantProduceLane := sourcequalification.ProduceLaneRequest{
		RepoRoot:               produceLaneInput.RepoRoot,
		Lane:                   sourcequalification.Lane(produceLaneInput.Lane),
		Event:                  produceLaneInput.Event,
		ExpectedRef:            produceLaneInput.ExpectedRef,
		ExpectedBaseRevision:   produceLaneInput.ExpectedBaseRevision,
		ExpectedTestedRevision: produceLaneInput.ExpectedTestedRevision,
		WorkflowRunID:          produceLaneInput.WorkflowRunID,
		WorkflowRunAttempt:     int64(produceLaneInput.WorkflowRunAttempt),
		PrivateLogRoot:         produceLaneInput.PrivateLogRoot,
		OutputDir:              produceLaneInput.OutputDir,
	}
	cliSetExpectedTreeSHA(t, &wantProduceLane, fixture.treeSHA)
	adapterRequireEqual(t, gotProduceLane, wantProduceLane)
	adapterRequireEqual(t, gotAssemble, sourcequalification.AssembleRequest{
		LinuxDir:                   assembleInput.LinuxDir,
		WindowsDir:                 assembleInput.WindowsDir,
		ExpectedBaseRevision:       assembleInput.ExpectedBaseRevision,
		ExpectedTestedRevision:     assembleInput.ExpectedTestedRevision,
		ExpectedTreeSHA:            assembleInput.ExpectedTreeSHA,
		ExpectedQualificationRunID: assembleInput.ExpectedQualificationRunID,
		ExpectedWorkflowRunID:      assembleInput.ExpectedWorkflowRunID,
		ExpectedWorkflowRunAttempt: int64(maximumAttempt),
		OutputDir:                  assembleInput.OutputDir,
	})
	adapterRequireEqual(t, gotAssembleTools, sourcequalification.AssembleToolsRequest{
		PackageDir:        assembleToolsInput.PackageDir,
		LinuxController:   assembleToolsInput.LinuxController,
		WindowsController: assembleToolsInput.WindowsController,
		OutputDir:         assembleToolsInput.OutputDir,
	})
	adapterRequireEqual(t, gotVerifyIntegrity, sourcequalification.VerifyIntegrityRequest{
		PackageDir: verifyIntegrityInput.PackageDir,
	})
	adapterRequireEqual(t, gotVerifySubject, sourcequalification.VerifySubjectRequest{
		PackageDir:                 verifySubjectInput.PackageDir,
		ExpectedRepository:         verifySubjectInput.ExpectedRepository,
		ExpectedBaseRevision:       verifySubjectInput.ExpectedBaseRevision,
		ExpectedTestedRevision:     verifySubjectInput.ExpectedTestedRevision,
		ExpectedTreeSHA:            verifySubjectInput.ExpectedTreeSHA,
		ExpectedQualificationRunID: verifySubjectInput.ExpectedQualificationRunID,
		ExpectedWorkflowRunID:      verifySubjectInput.ExpectedWorkflowRunID,
		ExpectedWorkflowRunAttempt: int64(maximumAttempt),
		ExpectedPackageDigest:      verifySubjectInput.ExpectedPackageDigest,
		ToolManifestPath:           verifySubjectInput.ToolManifestPath,
		ExpectedToolManifestDigest: verifySubjectInput.ExpectedToolManifestDigest,
		ExpectedExecutableDigest:   verifySubjectInput.ExpectedExecutableDigest,
	})
}

func TestProductionControllerOperationsKeepFacadeErrorsPrivate(t *testing.T) {
	fixture := newCLICommandFixture(t)
	privateError := errors.New("private facade failure at " + fixture.privateMarker)
	result := sourcequalification.ControllerResult{
		Code:                "SOURCE_QUAL_ARCHIVE_INVALID",
		QualificationStatus: statusFail,
		SHA256:              notApplicable,
		TestedRevision:      notApplicable,
		TreeSHA:             notApplicable,
	}
	operations := productionControllerCommandOperations{
		verifyIntegrity: func(request sourcequalification.VerifyIntegrityRequest) (sourcequalification.ControllerResult, error) {
			if request.PackageDir != fixture.packageDir {
				t.Fatalf("VerifyIntegrity package dir = %q", request.PackageDir)
			}
			return result, privateError
		},
	}

	record, err := operations.VerifyIntegrity(verifyIntegrityCommandRequest{PackageDir: fixture.packageDir})
	if !errors.Is(err, privateError) {
		t.Fatalf("production adapter replaced facade error: %v", err)
	}
	adapterRequireControllerRecord(t, record, result)

	exitCode, stdout, stderr := cliRunWithOperations(fixture.verifyIntegrityArgs(), operations)
	if exitCode == 0 {
		t.Fatal("run returned success after facade failure")
	}
	cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
		"SOURCE_QUAL_ARCHIVE_INVALID", cliControllerID, statusFail,
	))
	cliAssertPrivate(t, stdout, privateError.Error(), fixture.privateMarker, fixture.packageDir)
}

func TestProductionControllerOperationsKeepProduceLaneExplicitlyUnavailable(t *testing.T) {
	fixture := newCLICommandFixture(t)
	operations := productionControllerCommandOperations{
		assemble: func(sourcequalification.AssembleRequest) (sourcequalification.ControllerResult, error) {
			panic("produce-lane reached assemble facade")
		},
		assembleTools: func(sourcequalification.AssembleToolsRequest) (sourcequalification.ControllerResult, error) {
			panic("produce-lane reached assemble-tools facade")
		},
		verifyIntegrity: func(sourcequalification.VerifyIntegrityRequest) (sourcequalification.ControllerResult, error) {
			panic("produce-lane reached verify-integrity facade")
		},
		verifySubject: func(sourcequalification.VerifySubjectRequest) (sourcequalification.ControllerResult, error) {
			panic("produce-lane reached verify-subject facade")
		},
	}

	record, err := operations.ProduceLane(produceLaneCommandRequest{})
	if !errors.Is(err, errControllerOperationUnavailable) {
		t.Fatalf("ProduceLane error = %v, want explicit unavailable", err)
	}
	if !reflect.DeepEqual(record, newControllerRecord(codeInvalidInput, controllerID, statusFail)) {
		t.Fatalf("ProduceLane unavailable record = %#v", record)
	}

	exitCode, stdout, stderr := cliRunWithOperations(fixture.produceLaneArgs(), operations)
	if exitCode == 0 {
		t.Fatal("ProduceLane reported success without a runtime facade")
	}
	cliAssertRecord(t, stdout, stderr, cliExpectedRecord(codeInvalidInput, cliControllerID, statusFail))
	cliAssertPrivate(t, stdout, fixture.repoRoot, fixture.privateLogRoot, fixture.laneOutputDir)
}

func TestRunDefaultDelegatesFourAvailableCommandsToTypedFacade(t *testing.T) {
	fixture := newCLICommandFixture(t)
	root := t.TempDir()
	fixture.linuxDir = filepath.Join(root, "linux-empty")
	fixture.windowsDir = filepath.Join(root, "windows-empty")
	fixture.packageDir = filepath.Join(root, "package-empty")
	fixture.linuxController = filepath.Join(root, "linux-controller")
	fixture.windowsController = filepath.Join(root, "windows-controller.exe")
	fixture.aggregateOutputDir = filepath.Join(root, "aggregate-absent")
	fixture.toolsOutputDir = filepath.Join(root, "tools-absent")
	fixture.toolManifest = filepath.Join(root, "tool-manifest.json")
	for _, directory := range []string{fixture.linuxDir, fixture.windowsDir, fixture.packageDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{fixture.linuxController, fixture.windowsController, fixture.toolManifest} {
		if err := os.WriteFile(path, []byte("invalid but private fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name     string
		args     []string
		wantCode string
	}{
		{commandAssemble, fixture.assembleArgs(), "SOURCE_QUAL_RECEIPT_INVALID"},
		{commandAssembleTools, fixture.assembleToolsArgs(), "SOURCE_QUAL_RECEIPT_INVALID"},
		{commandVerifyIntegrity, fixture.verifyIntegrityArgs(), "SOURCE_QUAL_ARCHIVE_INVALID"},
		{commandVerifySubject, fixture.verifySubjectArgs(), "SOURCE_QUAL_SUBJECT_MISMATCH"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := cliRun(test.args)
			if exitCode == 0 {
				t.Fatalf("default %s unexpectedly succeeded on invalid facade input", test.name)
			}
			cliAssertRecord(t, stdout, stderr, cliExpectedRecord(test.wantCode, cliControllerID, statusFail))
			cliAssertPrivate(t, stdout, root, fixture.packageDir, fixture.toolManifest)
		})
	}
}

func adapterRequireControllerRecord(
	t *testing.T,
	got controllerRecord,
	want sourcequalification.ControllerResult,
) {
	t.Helper()
	expected := controllerRecord{
		Code:                want.Code,
		ID:                  controllerID,
		QualificationStatus: want.QualificationStatus,
		SHA256:              want.SHA256,
		TestedRevision:      want.TestedRevision,
		TreeSHA:             want.TreeSHA,
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("controller record mismatch\n got: %#v\nwant: %#v", got, expected)
	}
}

func adapterRequireEqual[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("facade request mismatch\n got: %#v\nwant: %#v", got, want)
	}
}
