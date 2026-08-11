package sourcequalification

// Tests-first contract for the RFC-0002 produce-lane runtime facade.
// Production is expected to provide:
//
//	type ProduceLaneRequest struct {
//		RepoRoot               string
//		Lane                   Lane
//		Event                  string
//		ExpectedRef            string
//		ExpectedBaseRevision   string
//		ExpectedTestedRevision string
//		ExpectedTreeSHA        string
//		WorkflowRunID          string
//		WorkflowRunAttempt     int64
//		PrivateLogRoot         string
//		OutputDir              string
//	}
//	func ProduceLane(context.Context, ProduceLaneRequest) (ControllerResult, error)
//
// The exported facade owns real adapters. The unexported
// produceLaneWithRuntime helper owns only the security-critical sequence and
// accepts a produceLaneRuntime so that these tests never execute tools or
// derive ambient platform facts. The producer writes an absent same-parent
// stage. Its private workspace must be cleaned before that stage can be
// promoted with no replacement.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestProduceLaneFacadeExactTypedSurface(t *testing.T) {
	var _ int64 = ProduceLaneRequest{}.WorkflowRunAttempt
	var _ func(context.Context, ProduceLaneRequest) (ControllerResult, error) = ProduceLane

	controllerRuntimeRequireFields(t, ProduceLaneRequest{}, []string{
		"RepoRoot",
		"Lane",
		"Event",
		"ExpectedRef",
		"ExpectedBaseRevision",
		"ExpectedTestedRevision",
		"ExpectedTreeSHA",
		"WorkflowRunID",
		"WorkflowRunAttempt",
		"PrivateLogRoot",
		"OutputDir",
	})
}

func TestProductionProduceLaneStageBlocksWithoutAuthenticatedHistory(t *testing.T) {
	request := controllerRuntimeRequest(t)
	outcome, receipt, err := produceControllerLaneStage(context.Background(), request)
	if !errors.Is(err, errGateBlocked) || outcome != (produceLaneStageOutcome{
		QualificationStatus: StatusBlocked,
		Code:                controllerCodeGateBlocked,
	}) || receipt != nil {
		t.Fatalf("unavailable production history = (%#v, %#v, %v), want fixed BLOCKED with no receipt",
			outcome, receipt, err)
	}
	if _, statErr := os.Lstat(request.OutputDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unavailable production history published output: %v", statErr)
	}
}

func TestProduceLaneRejectsInvalidExpectedTreeBeforeRuntimeAdapters(t *testing.T) {
	request := controllerRuntimeRequest(t)
	request.Lane = controllerRuntimeHostLane(t)
	controllerRuntimeSetExpectedTreeSHA(t, &request, strings.Repeat("A", 40))

	result, err := ProduceLane(context.Background(), request)
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeInvalidInput,
		StatusFail,
	)
	for _, path := range []string{request.PrivateLogRoot, request.OutputDir} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("invalid expected tree reached a runtime adapter at %q: %v", filepath.Base(path), statErr)
		}
	}
}

func TestProduceLanePublishesExactPreconstructionTombstoneWhenAuthenticatedHistoryIsUnavailable(t *testing.T) {
	request := controllerRuntimeRequest(t)
	request.Lane = controllerRuntimeHostLane(t)
	controllerRuntimeSetExpectedTreeSHA(t, &request, strings.Repeat("3", 40))

	result, err := ProduceLane(context.Background(), request)
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeGateBlocked,
		StatusBlocked,
	)
	if !errors.Is(err, ErrAttemptArtifactPublished) {
		t.Fatalf("production tombstone error = %v, want publication marker", err)
	}

	raw, readErr := os.ReadFile(filepath.Join(request.OutputDir, attemptTombstoneFilename))
	if readErr != nil {
		t.Fatalf("read authenticated-history tombstone: %v", readErr)
	}
	document, parseErr := parseCanonicalAttemptTombstone(raw)
	if parseErr != nil {
		t.Fatalf("parse authenticated-history tombstone: %v", parseErr)
	}
	runIdentityBytes := strings.Join([]string{
		"github-actions",
		canonicalWorkflowRepository,
		canonicalWorkflowPath,
		request.Event,
		request.ExpectedRef,
		request.WorkflowRunID,
		strconv.FormatInt(request.WorkflowRunAttempt, 10),
		request.ExpectedTestedRevision,
	}, "\x00")
	runIdentityDigest := sha256.Sum256([]byte(runIdentityBytes))
	qualificationRunID := "sha256:" + hex.EncodeToString(runIdentityDigest[:])
	want := qualificationAttemptTombstone{
		ArtifactType:           attemptTombstoneArtifactType,
		AttemptID:              qualificationRunID + ":" + string(request.Lane) + ":1",
		Code:                   controllerCodeGateBlocked,
		ExpectedBaseRevision:   request.ExpectedBaseRevision,
		ExpectedTestedRevision: request.ExpectedTestedRevision,
		ExpectedTreeSHA:        strings.Repeat("3", 40),
		Lane:                   request.Lane,
		Ordinal:                1,
		QualificationRunID:     qualificationRunID,
		QualificationStatus:    StatusBlocked,
		SchemaVersion:          attemptTombstoneSchemaVersion,
		WorkflowRunAttempt:     request.WorkflowRunAttempt,
		WorkflowRunID:          request.WorkflowRunID,
	}
	if document != want {
		t.Fatalf("authenticated-history tombstone mismatch\n got: %#v\nwant: %#v", document, want)
	}
	entries, readDirErr := os.ReadDir(request.OutputDir)
	if readDirErr != nil || len(entries) != 1 || entries[0].Name() != attemptTombstoneFilename ||
		!entries[0].Type().IsRegular() {
		t.Fatalf("preconstruction artifact inventory = %v, %v; want one exact regular tombstone", entries, readDirErr)
	}
	if _, statErr := os.Lstat(request.PrivateLogRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("private runtime workspace survived tombstone publication: %v", statErr)
	}
}

func TestProduceLaneRuntimeCleansWorkspaceBeforePassingPromotion(t *testing.T) {
	request := controllerRuntimeRequest(t)
	fake := newControllerRuntimeFake(request)
	fake.outcome = produceLaneStageOutcome{
		StageReady:          true,
		QualificationStatus: StatusPass,
		TestedRevision:      request.ExpectedTestedRevision,
		TreeSHA:             strings.Repeat("3", 40),
	}

	result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
	if err != nil {
		t.Fatalf("produceLaneWithRuntime: %v", err)
	}
	controllerRuntimeRequireResult(t, result, ControllerResult{
		Code:                controllerCodeOK,
		QualificationStatus: controllerStatusPass,
		SHA256:              controllerNotApplicable,
		TestedRevision:      request.ExpectedTestedRevision,
		TreeSHA:             fake.outcome.TreeSHA,
	})
	controllerRuntimeRequireEvents(t, fake.events, []string{
		"workspace:create",
		"stage:allocate",
		"producer:run",
		"workspace:cleanup",
		"stage:promote-no-replace",
	})
	controllerRuntimeRequireSameParentStage(t, request, fake)
	if fake.producerRequest.PrivateLogRoot != fake.workspacePath {
		t.Fatalf("producer private log root = %q, want owned workspace", fake.producerRequest.PrivateLogRoot)
	}
	if fake.stageState != "promoted" || fake.outputKind != "pass" {
		t.Fatalf("publication state = stage %q output %q, want promoted PASS", fake.stageState, fake.outputKind)
	}
}

func TestProduceLaneRuntimePromotesSafeNonPassingAttemptAfterCleanup(t *testing.T) {
	tests := []struct {
		name       string
		status     QualificationStatus
		code       string
		outputKind string
	}{
		{
			name:       "gate fail",
			status:     StatusFail,
			code:       "SOURCE_QUAL_GATE_FAILED",
			outputKind: "attempt-fail",
		},
		{
			name:       "gate blocked",
			status:     StatusBlocked,
			code:       "SOURCE_QUAL_GATE_BLOCKED",
			outputKind: "attempt-blocked",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := controllerRuntimeRequest(t)
			fake := newControllerRuntimeFake(request)
			fake.outcome = produceLaneStageOutcome{
				StageReady:          true,
				QualificationStatus: test.status,
				Code:                test.code,
				TestedRevision:      request.ExpectedTestedRevision,
				TreeSHA:             strings.Repeat("3", 40),
			}
			fake.produceErr = errors.New(controllerRuntimePrivateMarker + " gate output at " + request.PrivateLogRoot)

			result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
			controllerRuntimeRequireFixedFailure(t, result, err, test.code, test.status)
			if !errors.Is(err, ErrAttemptArtifactPublished) {
				t.Fatalf("published non-PASS attempt error = %v, want publication marker", err)
			}
			controllerRuntimeRequireEvents(t, fake.events, []string{
				"workspace:create",
				"stage:allocate",
				"producer:run",
				"workspace:cleanup",
				"stage:promote-no-replace",
			})
			controllerRuntimeRequireSameParentStage(t, request, fake)
			if fake.stageState != "promoted" || fake.outputKind != test.outputKind {
				t.Fatalf("non-PASS publication = stage %q output %q, want preserved %s",
					fake.stageState, fake.outputKind, test.outputKind)
			}
			if fake.tombstoneCalls != 0 {
				t.Fatalf("safe three-file attempt was replaced by %d tombstones", fake.tombstoneCalls)
			}
		})
	}
}

func TestProduceLaneRuntimePublishesAllowlistedPreconstructionTombstoneAfterCleanupAndWithdrawal(t *testing.T) {
	tests := []struct {
		name   string
		status QualificationStatus
		code   string
	}{
		{name: "fail", status: StatusFail, code: controllerCodeArchiveInvalid},
		{name: "blocked", status: StatusBlocked, code: controllerCodeGateBlocked},
		{name: "not run", status: StatusNotRun, code: controllerCodeGateNotRun},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := controllerRuntimeRequest(t)
			fake := newControllerRuntimeFake(request)
			fake.outcome = produceLaneStageOutcome{
				StageReady:          false,
				QualificationStatus: test.status,
				Code:                test.code,
			}
			fake.produceErr = errors.New(controllerRuntimePrivateMarker + " source path " + request.RepoRoot)

			result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
			controllerRuntimeRequireFixedFailure(t, result, err, test.code, test.status)
			if !errors.Is(err, ErrAttemptArtifactPublished) {
				t.Fatalf("published preconstruction error = %v, want publication marker", err)
			}
			controllerRuntimeRequireEvents(t, fake.events, []string{
				"workspace:create",
				"stage:allocate",
				"producer:run",
				"workspace:cleanup",
				"stage:withdraw",
				"tombstone:publish",
			})
			if fake.stageState != "withdrawn" || fake.outputKind != "tombstone" {
				t.Fatalf("preconstruction state = stage %q output %q, want withdrawn tombstone",
					fake.stageState, fake.outputKind)
			}
			if fake.tombstoneCalls != 1 || fake.tombstoneCode != test.code || fake.tombstoneStatus != test.status {
				t.Fatalf("preconstruction tombstone = calls %d code %q status %q",
					fake.tombstoneCalls, fake.tombstoneCode, fake.tombstoneStatus)
			}
		})
	}
}

func TestProduceLaneRuntimeCleanupFailureWithdrawsStageBeforeTombstone(t *testing.T) {
	request := controllerRuntimeRequest(t)
	fake := newControllerRuntimeFake(request)
	fake.outcome = produceLaneStageOutcome{
		StageReady:          true,
		QualificationStatus: StatusPass,
		TestedRevision:      request.ExpectedTestedRevision,
		TreeSHA:             strings.Repeat("3", 40),
	}
	fake.cleanupErr = errors.New(controllerRuntimePrivateMarker + " cleanup " + fake.workspacePath)

	result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeCleanupFailed,
		StatusFail,
	)
	if !errors.Is(err, ErrAttemptArtifactPublished) {
		t.Fatalf("cleanup tombstone error = %v, want publication marker", err)
	}
	controllerRuntimeRequireEvents(t, fake.events, []string{
		"workspace:create",
		"stage:allocate",
		"producer:run",
		"workspace:cleanup",
		"stage:withdraw",
		"tombstone:publish",
	})
	if fake.promoteCalls != 0 {
		t.Fatalf("cleanup failure reached promotion %d times", fake.promoteCalls)
	}
	if fake.stageState != "withdrawn" || fake.outputKind != "tombstone" {
		t.Fatalf("cleanup failure state = stage %q output %q, want withdrawn then tombstone",
			fake.stageState, fake.outputKind)
	}
	if fake.tombstoneCode != controllerCodeCleanupFailed || fake.tombstoneStatus != StatusFail {
		t.Fatalf("cleanup tombstone = (%q, %q)", fake.tombstoneCode, fake.tombstoneStatus)
	}
}

func TestProduceLaneRuntimePromotionFailureLeavesNoAcceptedOutput(t *testing.T) {
	request := controllerRuntimeRequest(t)
	fake := newControllerRuntimeFake(request)
	fake.outcome = produceLaneStageOutcome{
		StageReady:          true,
		QualificationStatus: StatusPass,
		TestedRevision:      request.ExpectedTestedRevision,
		TreeSHA:             strings.Repeat("3", 40),
	}
	fake.promoteErr = errors.New(controllerRuntimePrivateMarker + " destination " + request.OutputDir)

	result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeDestinationExists,
		StatusFail,
	)
	controllerRuntimeRequireEvents(t, fake.events, []string{
		"workspace:create",
		"stage:allocate",
		"producer:run",
		"workspace:cleanup",
		"stage:promote-no-replace",
		"stage:withdraw",
	})
	if fake.stageState != "withdrawn" || fake.outputKind != "absent" || fake.acceptedOutput {
		t.Fatalf("promotion failure left stage=%q output=%q accepted=%t",
			fake.stageState, fake.outputKind, fake.acceptedOutput)
	}
	if fake.tombstoneCalls != 0 {
		t.Fatalf("promotion collision attempted %d same-destination tombstones", fake.tombstoneCalls)
	}
}

func TestProduceLaneRuntimeRejectsUnallowlistedProducerCodeWithoutDisclosure(t *testing.T) {
	request := controllerRuntimeRequest(t)
	fake := newControllerRuntimeFake(request)
	fake.outcome = produceLaneStageOutcome{
		StageReady:          false,
		QualificationStatus: StatusFail,
		Code:                controllerRuntimePrivateMarker + " " + request.RepoRoot,
	}
	fake.produceErr = errors.New(controllerRuntimePrivateMarker + " raw stderr")

	result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeInvalidInput,
		StatusFail,
	)
	if fake.tombstoneCalls != 0 || fake.outputKind != "absent" || fake.stageState != "withdrawn" {
		t.Fatalf("invalid producer result created public evidence: calls=%d output=%q stage=%q",
			fake.tombstoneCalls, fake.outputKind, fake.stageState)
	}
}

func TestProduceLaneRuntimeDoesNotPublishMalformedPreconstructionOutcome(t *testing.T) {
	tests := []struct {
		name       string
		status     QualificationStatus
		code       string
		produceErr error
	}{
		{
			name:       "allowlisted code with mismatched status",
			status:     StatusFail,
			code:       controllerCodeGateBlocked,
			produceErr: errors.New(controllerRuntimePrivateMarker),
		},
		{
			name:       "preconstruction pass",
			status:     StatusPass,
			produceErr: errors.New(controllerRuntimePrivateMarker),
		},
		{
			name:   "non-pass without producer error",
			status: StatusNotRun,
			code:   controllerCodeGateNotRun,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := controllerRuntimeRequest(t)
			fake := newControllerRuntimeFake(request)
			fake.outcome = produceLaneStageOutcome{
				QualificationStatus: test.status,
				Code:                test.code,
			}
			fake.produceErr = test.produceErr

			result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
			controllerRuntimeRequireFixedFailure(
				t,
				result,
				err,
				controllerCodeInvalidInput,
				StatusFail,
			)
			controllerRuntimeRequireEvents(t, fake.events, []string{
				"workspace:create",
				"stage:allocate",
				"producer:run",
				"workspace:cleanup",
				"stage:withdraw",
			})
			if fake.tombstoneCalls != 0 || fake.outputKind != "absent" || fake.stageState != "withdrawn" {
				t.Fatalf("malformed outcome created public evidence: calls=%d output=%q stage=%q",
					fake.tombstoneCalls, fake.outputKind, fake.stageState)
			}
		})
	}
}

func TestProduceLaneRuntimeDoesNotMarkFailedTombstonePublicationAsSafe(t *testing.T) {
	request := controllerRuntimeRequest(t)
	fake := newControllerRuntimeFake(request)
	fake.outcome = produceLaneStageOutcome{
		QualificationStatus: StatusBlocked,
		Code:                controllerCodeGateBlocked,
	}
	fake.produceErr = errors.New(controllerRuntimePrivateMarker)
	fake.tombstoneErr = errors.New(controllerRuntimePrivateMarker + " output collision")

	result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeGateBlocked,
		StatusBlocked,
	)
	if errors.Is(err, ErrAttemptArtifactPublished) {
		t.Fatal("failed tombstone publication was marked safe for upload")
	}
	if fake.tombstoneCalls != 1 || fake.outputKind != "absent" || fake.stageState != "withdrawn" {
		t.Fatalf("failed tombstone publication state = calls=%d output=%q stage=%q",
			fake.tombstoneCalls, fake.outputKind, fake.stageState)
	}
}

func TestProduceLaneRuntimeRejectsConstructedTreeDifferentFromContext(t *testing.T) {
	request := controllerRuntimeRequest(t)
	fake := newControllerRuntimeFake(request)
	fake.outcome = produceLaneStageOutcome{
		StageReady:          true,
		QualificationStatus: StatusPass,
		TestedRevision:      request.ExpectedTestedRevision,
		TreeSHA:             strings.Repeat("4", 40),
	}

	result, err := produceLaneWithRuntime(context.Background(), request, fake.dependencies())
	controllerRuntimeRequireFixedFailure(
		t,
		result,
		err,
		controllerCodeInvalidInput,
		StatusFail,
	)
	controllerRuntimeRequireEvents(t, fake.events, []string{
		"workspace:create",
		"stage:allocate",
		"producer:run",
		"workspace:cleanup",
		"stage:withdraw",
	})
	if fake.promoteCalls != 0 || fake.tombstoneCalls != 0 ||
		fake.stageState != "withdrawn" || fake.outputKind != "absent" {
		t.Fatalf("tree mismatch created public evidence: promote=%d tombstone=%d stage=%q output=%q",
			fake.promoteCalls, fake.tombstoneCalls, fake.stageState, fake.outputKind)
	}
}

const controllerRuntimePrivateMarker = "RAW-PRIVATE-RUNTIME-3c7ab649"

type controllerRuntimeFake struct {
	request         ProduceLaneRequest
	events          []string
	outcome         produceLaneStageOutcome
	produceErr      error
	cleanupErr      error
	promoteErr      error
	withdrawErr     error
	tombstoneErr    error
	workspacePath   string
	stagePath       string
	producerRequest ProduceLaneRequest
	stageState      string
	outputKind      string
	acceptedOutput  bool
	promoteCalls    int
	tombstoneCalls  int
	tombstoneCode   string
	tombstoneStatus QualificationStatus
}

func newControllerRuntimeFake(request ProduceLaneRequest) *controllerRuntimeFake {
	return &controllerRuntimeFake{
		request:       request,
		workspacePath: filepath.Join(request.PrivateLogRoot, "run-"+controllerRuntimePrivateMarker),
		stagePath: filepath.Join(
			filepath.Dir(request.OutputDir),
			".repopass-source-qualification-stage-"+controllerRuntimePrivateMarker,
		),
		stageState: "absent",
		outputKind: "absent",
	}
}

func (fake *controllerRuntimeFake) dependencies() produceLaneRuntime {
	return produceLaneRuntime{
		createWorkspace: func(root string) (string, func() error, error) {
			fake.events = append(fake.events, "workspace:create")
			if root != fake.request.PrivateLogRoot {
				return "", nil, errors.New("unexpected private root")
			}
			return fake.workspacePath, func() error {
				fake.events = append(fake.events, "workspace:cleanup")
				return fake.cleanupErr
			}, nil
		},
		allocateStage: func(parent string) (string, error) {
			fake.events = append(fake.events, "stage:allocate")
			if !sameCanonicalPath(parent, filepath.Dir(fake.request.OutputDir)) {
				return "", errors.New("stage parent differs")
			}
			return fake.stagePath, nil
		},
		produce: func(ctx context.Context, request ProduceLaneRequest) (produceLaneStageOutcome, error) {
			fake.events = append(fake.events, "producer:run")
			fake.producerRequest = request
			if ctx == nil {
				return produceLaneStageOutcome{}, errors.New("nil context")
			}
			if fake.outcome.StageReady {
				fake.stageState = "safe"
			}
			return fake.outcome, fake.produceErr
		},
		promoteNoReplace: func(stagePath, outputPath string) error {
			fake.events = append(fake.events, "stage:promote-no-replace")
			fake.promoteCalls++
			if stagePath != fake.stagePath || outputPath != fake.request.OutputDir {
				return errors.New("unexpected promotion paths")
			}
			if fake.promoteErr != nil {
				return fake.promoteErr
			}
			if fake.stageState != "safe" || fake.outputKind != "absent" {
				return errors.New("unsafe promotion state")
			}
			fake.stageState = "promoted"
			switch fake.outcome.QualificationStatus {
			case StatusPass:
				fake.outputKind = "pass"
				fake.acceptedOutput = true
			case StatusBlocked:
				fake.outputKind = "attempt-blocked"
			default:
				fake.outputKind = "attempt-fail"
			}
			return nil
		},
		withdrawStage: func(stagePath string) error {
			fake.events = append(fake.events, "stage:withdraw")
			if stagePath != fake.stagePath {
				return errors.New("unexpected withdrawal path")
			}
			if fake.withdrawErr != nil {
				return fake.withdrawErr
			}
			fake.stageState = "withdrawn"
			return nil
		},
		publishTombstone: func(outputPath, code string, status QualificationStatus) error {
			fake.events = append(fake.events, "tombstone:publish")
			fake.tombstoneCalls++
			fake.tombstoneCode = code
			fake.tombstoneStatus = status
			if outputPath != fake.request.OutputDir {
				return errors.New("unexpected tombstone path")
			}
			if fake.tombstoneErr != nil {
				return fake.tombstoneErr
			}
			if fake.outputKind != "absent" {
				return errors.New("tombstone replaced output")
			}
			fake.outputKind = "tombstone"
			return nil
		},
	}
}

func controllerRuntimeRequest(t *testing.T) ProduceLaneRequest {
	t.Helper()
	root := t.TempDir()
	request := ProduceLaneRequest{
		RepoRoot:               filepath.Join(root, "checkout-"+controllerRuntimePrivateMarker),
		Lane:                   LaneLinuxAMD64,
		Event:                  "push",
		ExpectedRef:            canonicalMainRef,
		ExpectedBaseRevision:   strings.Repeat("1", 40),
		ExpectedTestedRevision: strings.Repeat("2", 40),
		WorkflowRunID:          "123456789",
		WorkflowRunAttempt:     1,
		PrivateLogRoot:         filepath.Join(root, "private-logs-"+controllerRuntimePrivateMarker),
		OutputDir:              filepath.Join(root, "public-attempt"),
	}
	controllerRuntimeSetExpectedTreeSHAIfPresent(&request, strings.Repeat("3", 40))
	return request
}

func controllerRuntimeSetExpectedTreeSHAIfPresent(request any, treeSHA string) {
	value := reflect.ValueOf(request)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return
	}
	field := value.Elem().FieldByName("ExpectedTreeSHA")
	if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
		field.SetString(treeSHA)
	}
}

func controllerRuntimeSetExpectedTreeSHA(t *testing.T, request any, treeSHA string) {
	t.Helper()
	value := reflect.ValueOf(request)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		t.Fatal("expected a non-nil pointer to a produce-lane request")
	}
	field := value.Elem().FieldByName("ExpectedTreeSHA")
	if !field.IsValid() || !field.CanSet() || field.Kind() != reflect.String {
		t.Fatalf("%s is missing writable string ExpectedTreeSHA", value.Elem().Type())
	}
	field.SetString(treeSHA)
}

func controllerRuntimeHostLane(t *testing.T) Lane {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("production lane controller supports amd64, running %s", runtime.GOARCH)
	}
	switch runtime.GOOS {
	case "linux":
		return LaneLinuxAMD64
	case "windows":
		return LaneWindowsAMD64
	default:
		t.Skipf("production lane controller does not support %s", runtime.GOOS)
		return ""
	}
}

func controllerRuntimeRequireFields(t *testing.T, value any, want []string) {
	t.Helper()
	typeOf := reflect.TypeOf(value)
	got := make([]string, typeOf.NumField())
	for index := 0; index < typeOf.NumField(); index++ {
		got[index] = typeOf.Field(index).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s fields = %#v, want exact %#v", typeOf.Name(), got, want)
	}
}

func controllerRuntimeRequireResult(t *testing.T, got, want ControllerResult) {
	t.Helper()
	if got != want {
		t.Fatalf("controller result = %#v, want %#v", got, want)
	}
}

func controllerRuntimeRequireFixedFailure(
	t *testing.T,
	result ControllerResult,
	err error,
	code string,
	status QualificationStatus,
) {
	t.Helper()
	if err == nil || err.Error() != code {
		t.Fatalf("failure error = %v, want exact %q", err, code)
	}
	controllerRuntimeRequireResult(t, result, ControllerResult{
		Code:                code,
		QualificationStatus: string(status),
		SHA256:              controllerNotApplicable,
		TestedRevision:      controllerNotApplicable,
		TreeSHA:             controllerNotApplicable,
	})
	disclosure := fmt.Sprintf("%#v %v", result, err)
	if strings.Contains(disclosure, controllerRuntimePrivateMarker) ||
		strings.Contains(disclosure, string(filepath.Separator)) {
		t.Fatalf("public failure disclosed private material: %q", disclosure)
	}
}

func controllerRuntimeRequireEvents(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime events = %#v, want exact %#v", got, want)
	}
}

func controllerRuntimeRequireSameParentStage(
	t *testing.T,
	request ProduceLaneRequest,
	fake *controllerRuntimeFake,
) {
	t.Helper()
	if fake.producerRequest.OutputDir == request.OutputDir ||
		!sameCanonicalPath(filepath.Dir(fake.producerRequest.OutputDir), filepath.Dir(request.OutputDir)) ||
		fake.producerRequest.OutputDir != fake.stagePath {
		t.Fatalf("producer output = %q, final = %q; want distinct same-parent stage",
			fake.producerRequest.OutputDir, request.OutputDir)
	}
}
