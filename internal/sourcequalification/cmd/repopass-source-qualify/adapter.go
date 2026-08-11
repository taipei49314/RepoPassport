package main

import (
	"context"

	"github.com/taipei49314/RepoPassport/internal/sourcequalification"
)

type productionControllerCommandOperations struct {
	produceLane     func(context.Context, sourcequalification.ProduceLaneRequest) (sourcequalification.ControllerResult, error)
	assemble        func(sourcequalification.AssembleRequest) (sourcequalification.ControllerResult, error)
	assembleTools   func(sourcequalification.AssembleToolsRequest) (sourcequalification.ControllerResult, error)
	verifyIntegrity func(sourcequalification.VerifyIntegrityRequest) (sourcequalification.ControllerResult, error)
	verifySubject   func(sourcequalification.VerifySubjectRequest) (sourcequalification.ControllerResult, error)
}

func newProductionControllerCommandOperations() productionControllerCommandOperations {
	return productionControllerCommandOperations{
		produceLane:     sourcequalification.ProduceLane,
		assemble:        sourcequalification.Assemble,
		assembleTools:   sourcequalification.AssembleTools,
		verifyIntegrity: sourcequalification.VerifyIntegrity,
		verifySubject:   sourcequalification.VerifySubject,
	}
}

func (operations productionControllerCommandOperations) ProduceLane(
	request produceLaneCommandRequest,
) (controllerRecord, error) {
	if operations.produceLane == nil {
		return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
	}
	result, err := operations.produceLane(context.Background(), sourcequalification.ProduceLaneRequest{
		RepoRoot:               request.RepoRoot,
		Lane:                   sourcequalification.Lane(request.Lane),
		Event:                  request.Event,
		ExpectedRef:            request.ExpectedRef,
		ExpectedBaseRevision:   request.ExpectedBaseRevision,
		ExpectedTestedRevision: request.ExpectedTestedRevision,
		ExpectedTreeSHA:        request.ExpectedTreeSHA,
		WorkflowRunID:          request.WorkflowRunID,
		WorkflowRunAttempt:     int64(request.WorkflowRunAttempt),
		PrivateLogRoot:         request.PrivateLogRoot,
		OutputDir:              request.OutputDir,
	})
	return controllerRecordFromFacade(result), err
}

func (operations productionControllerCommandOperations) Assemble(request assembleCommandRequest) (controllerRecord, error) {
	if operations.assemble == nil {
		return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
	}
	result, err := operations.assemble(sourcequalification.AssembleRequest{
		LinuxDir:                   request.LinuxDir,
		WindowsDir:                 request.WindowsDir,
		ExpectedBaseRevision:       request.ExpectedBaseRevision,
		ExpectedTestedRevision:     request.ExpectedTestedRevision,
		ExpectedTreeSHA:            request.ExpectedTreeSHA,
		ExpectedQualificationRunID: request.ExpectedQualificationRunID,
		ExpectedWorkflowRunID:      request.ExpectedWorkflowRunID,
		ExpectedWorkflowRunAttempt: int64(request.ExpectedWorkflowRunAttempt),
		OutputDir:                  request.OutputDir,
	})
	return controllerRecordFromFacade(result), err
}

func (operations productionControllerCommandOperations) AssembleTools(request assembleToolsCommandRequest) (controllerRecord, error) {
	if operations.assembleTools == nil {
		return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
	}
	result, err := operations.assembleTools(sourcequalification.AssembleToolsRequest{
		PackageDir:        request.PackageDir,
		LinuxController:   request.LinuxController,
		WindowsController: request.WindowsController,
		OutputDir:         request.OutputDir,
	})
	return controllerRecordFromFacade(result), err
}

func (operations productionControllerCommandOperations) VerifyIntegrity(request verifyIntegrityCommandRequest) (controllerRecord, error) {
	if operations.verifyIntegrity == nil {
		return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
	}
	result, err := operations.verifyIntegrity(sourcequalification.VerifyIntegrityRequest{
		PackageDir: request.PackageDir,
	})
	return controllerRecordFromFacade(result), err
}

func (operations productionControllerCommandOperations) VerifySubject(request verifySubjectCommandRequest) (controllerRecord, error) {
	if operations.verifySubject == nil {
		return newControllerRecord(codeInvalidInput, controllerID, statusFail), errControllerOperationUnavailable
	}
	result, err := operations.verifySubject(sourcequalification.VerifySubjectRequest{
		PackageDir:                 request.PackageDir,
		ExpectedRepository:         request.ExpectedRepository,
		ExpectedBaseRevision:       request.ExpectedBaseRevision,
		ExpectedTestedRevision:     request.ExpectedTestedRevision,
		ExpectedTreeSHA:            request.ExpectedTreeSHA,
		ExpectedQualificationRunID: request.ExpectedQualificationRunID,
		ExpectedWorkflowRunID:      request.ExpectedWorkflowRunID,
		ExpectedWorkflowRunAttempt: int64(request.ExpectedWorkflowRunAttempt),
		ExpectedPackageDigest:      request.ExpectedPackageDigest,
		ToolManifestPath:           request.ToolManifestPath,
		ExpectedToolManifestDigest: request.ExpectedToolManifestDigest,
		ExpectedExecutableDigest:   request.ExpectedExecutableDigest,
	})
	return controllerRecordFromFacade(result), err
}

func controllerRecordFromFacade(result sourcequalification.ControllerResult) controllerRecord {
	return controllerRecord{
		Code:                result.Code,
		ID:                  controllerID,
		QualificationStatus: result.QualificationStatus,
		SHA256:              result.SHA256,
		TestedRevision:      result.TestedRevision,
		TreeSHA:             result.TreeSHA,
	}
}
