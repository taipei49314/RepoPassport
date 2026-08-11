package sourcequalification

// Package-private production contract under test. The lane producer is the
// only orchestration boundary allowed to turn an inspected clean repository
// into one publishable RFC-0002 lane directory.
//
//	type qualificationLaneRequest struct {
//		Repository RepositoryRequest
//		Gate gateRunRequest
//		Run RunIdentity
//		Platform receiptPlatform
//		OutputDir string
//	}
//	type qualificationLaneDependencies struct {
//		Repository laneRepositoryInspector
//		Executor gateExecutor
//		Clock laneClock
//		SelfController laneSelfController
//		PrivateLogs gatePrivateLogSink
//	}
//	type laneRepositoryInspector interface {
//		InspectRepository(RepositoryRequest) (RepositorySnapshot, error)
//	}
//	type laneClock interface { Now() time.Time }
//	type laneSelfController interface {
//		InspectSelfController() (receiptController, error)
//	}
//	func produceQualificationLane(context.Context, qualificationLaneRequest, qualificationLaneDependencies) (QualificationStatus, error)

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestProduceQualificationLanePublishesCanonicalPassingAttempt(t *testing.T) {
	fixture := newLaneProducerFixture(t, LaneLinuxAMD64)
	status, err := produceQualificationLane(context.Background(), fixture.request, fixture.dependencies)
	if err != nil {
		t.Fatalf("produceQualificationLane: %v", err)
	}
	if status != StatusPass {
		t.Fatalf("status = %q, want PASS", status)
	}
	wantInspections := 1 + len(RequiredGates(fixture.request.Gate.Lane))
	if len(fixture.inspector.requests) != wantInspections || fixture.controller.calls != 1 || fixture.clock.calls != 2 {
		t.Fatalf("dependency calls inspector/controller/clock = %d/%d/%d, want %d/1/2",
			len(fixture.inspector.requests), fixture.controller.calls, fixture.clock.calls, wantInspections)
	}
	if !reflect.DeepEqual(fixture.inspector.requests[0], fixture.request.Repository) {
		t.Fatalf("repository request = %#v, want %#v", fixture.inspector.requests[0], fixture.request.Repository)
	}
	if got, want := len(fixture.executor.requests), len(RequiredGates(fixture.request.Gate.Lane)); got != want {
		t.Fatalf("executed %d gates, want %d", got, want)
	}
	if got, want := len(fixture.logs.entries), len(RequiredGates(fixture.request.Gate.Lane)); got != want {
		t.Fatalf("private log entries = %d, want %d", got, want)
	}

	files := readExactLaneProducerOutput(t, fixture.request.OutputDir, fixture.request.Gate.Lane)
	archive := files[archiveFilename]
	manifest := files[qualificationManifestFilename]
	expectedSubject := laneProducerSourceSubject(fixture.snapshot.Subject)
	if err := verifySourcePackage(archive, manifest, expectedSubject); err != nil {
		t.Fatalf("published source package is not canonical: %v", err)
	}

	receiptRaw := files[laneProducerReceiptFilename(fixture.request.Gate.Lane)]
	receipt, err := parseCanonicalReceipt(receiptRaw, fixture.request.Gate.Lane)
	if err != nil {
		t.Fatalf("published receipt is not canonical: %v", err)
	}
	requireLaneProducerReceiptFacts(t, receipt, fixture, archive, manifest, StatusPass, 0)
	for index, gate := range receipt.Gates {
		if gate.Status != StatusPass {
			t.Fatalf("gate %d status = %q, want PASS", index, gate.Status)
		}
	}
	assertLaneProducerPrivateBytesAbsent(t, files, laneProducerRawMarker)
}

func TestProduceQualificationLanePublishesFirstFailOrBlockedAttempt(t *testing.T) {
	tests := []struct {
		name       string
		result     gateProcessResult
		runError   error
		wantStatus QualificationStatus
	}{
		{
			name: "FAIL",
			result: gateProcessResult{
				ExitCode: gateTestInt64(17),
				Stdout:   []byte(laneProducerRawMarker + "-stdout"),
				Stderr:   []byte(laneProducerRawMarker + "-stderr"),
			},
			wantStatus: StatusFail,
		},
		{
			name: "BLOCKED",
			result: gateProcessResult{
				Blocked: true,
				Stdout:  []byte(laneProducerRawMarker + "-stdout"),
				Stderr:  []byte(laneProducerRawMarker + "-stderr"),
			},
			runError:   errors.New("private process prerequisite failed"),
			wantStatus: StatusBlocked,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLaneProducerFixture(t, LaneWindowsAMD64)
			const terminalIndex = 1
			fixture.executor.steps[terminalIndex] = gateTestStep{result: test.result, err: test.runError}

			status, err := produceQualificationLane(context.Background(), fixture.request, fixture.dependencies)
			if err == nil {
				t.Fatal("non-passing lane returned nil error")
			}
			if status != test.wantStatus {
				t.Fatalf("status = %q, want %q", status, test.wantStatus)
			}
			if got, want := len(fixture.executor.requests), terminalIndex+1; got != want {
				t.Fatalf("executed %d gates, want stop after %d", got, want)
			}
			if !fixture.logs.contains(laneProducerRawMarker) {
				t.Fatal("raw stdout/stderr did not reach the private log sink")
			}

			files := readExactLaneProducerOutput(t, fixture.request.OutputDir, fixture.request.Gate.Lane)
			archive := files[archiveFilename]
			manifest := files[qualificationManifestFilename]
			if err := verifySourcePackage(archive, manifest, laneProducerSourceSubject(fixture.snapshot.Subject)); err != nil {
				t.Fatalf("non-passing attempt source package is invalid: %v", err)
			}
			receipt, err := parseCanonicalReceipt(
				files[laneProducerReceiptFilename(fixture.request.Gate.Lane)],
				fixture.request.Gate.Lane,
			)
			if err != nil {
				t.Fatalf("non-passing attempt receipt is not canonical: %v", err)
			}
			requireLaneProducerReceiptFacts(
				t,
				receipt,
				fixture,
				archive,
				manifest,
				test.wantStatus,
				int64(len(RequiredGates(fixture.request.Gate.Lane))-terminalIndex-1),
			)
			if receipt.Gates[0].Status != StatusPass || receipt.Gates[terminalIndex].Status != test.wantStatus {
				t.Fatalf("terminal gate sequence = %q/%q, want PASS/%s",
					receipt.Gates[0].Status, receipt.Gates[terminalIndex].Status, test.wantStatus)
			}
			for index := terminalIndex + 1; index < len(receipt.Gates); index++ {
				if receipt.Gates[index].Status != StatusNotRun || receipt.Gates[index].StartedAt != nil || receipt.Gates[index].FinishedAt != nil {
					t.Fatalf("gate %d = %#v, want untouched NOT_RUN", index, receipt.Gates[index])
				}
			}
			assertLaneProducerPrivateBytesAbsent(t, files, laneProducerRawMarker)
		})
	}
}

func TestProduceQualificationLaneFailsGateWhenRepositoryChangesAfterExecution(t *testing.T) {
	fixture := newLaneProducerFixture(t, LaneLinuxAMD64)
	mutated := cloneLaneProducerSnapshot(fixture.snapshot)
	mutated.Files[0].Data = []byte("mutated tracked bytes\n")
	mutated.Files[0].Size = int64(len(mutated.Files[0].Data))
	mutated.Files[0].GitBlobSHA1 = gitBlobSHA1(mutated.Files[0].Data)
	fixture.inspector.afterInitial = &mutated

	status, err := produceQualificationLane(context.Background(), fixture.request, fixture.dependencies)
	if err == nil || status != StatusFail {
		t.Fatalf("mutated repository result = (%q, %v), want FAIL error", status, err)
	}
	if got := len(fixture.executor.requests); got != 1 {
		t.Fatalf("mutated repository executed %d gates, want exactly first gate", got)
	}
	if got := len(fixture.inspector.requests); got != 2 {
		t.Fatalf("repository was inspected %d times, want initial plus first gate", got)
	}
	if got := len(fixture.logs.entries); got != 1 {
		t.Fatalf("mutated repository wrote %d private gate logs, want 1", got)
	}

	files := readExactLaneProducerOutput(t, fixture.request.OutputDir, fixture.request.Gate.Lane)
	archive := files[archiveFilename]
	manifest := files[qualificationManifestFilename]
	if err := verifySourcePackage(archive, manifest, laneProducerSourceSubject(fixture.snapshot.Subject)); err != nil {
		t.Fatalf("mutated attempt source package is invalid: %v", err)
	}
	receipt, err := parseCanonicalReceipt(
		files[laneProducerReceiptFilename(fixture.request.Gate.Lane)],
		fixture.request.Gate.Lane,
	)
	if err != nil {
		t.Fatalf("mutated attempt receipt is not canonical: %v", err)
	}
	requireLaneProducerReceiptFacts(
		t,
		receipt,
		fixture,
		archive,
		manifest,
		StatusFail,
		int64(len(RequiredGates(fixture.request.Gate.Lane))-1),
	)
	if receipt.Gates[0].Status != StatusFail || receipt.Gates[0].ExitCode == nil || *receipt.Gates[0].ExitCode != 0 {
		t.Fatalf("mutating first gate = %#v, want FAIL with its exit 0", receipt.Gates[0])
	}
	for index := 1; index < len(receipt.Gates); index++ {
		if receipt.Gates[index].Status != StatusNotRun || receipt.Gates[index].StartedAt != nil || receipt.Gates[index].FinishedAt != nil {
			t.Fatalf("gate %d = %#v, want untouched NOT_RUN", index, receipt.Gates[index])
		}
	}
}

func TestProduceQualificationLaneDoesNotInventAttemptAfterPreconstructionFailure(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*laneProducerFixture)
	}{
		{
			name: "repository inspection",
			mutate: func(fixture *laneProducerFixture) {
				fixture.inspector.err = errors.New("private repository construction failed")
			},
		},
		{
			name: "self controller inspection",
			mutate: func(fixture *laneProducerFixture) {
				fixture.controller.err = errors.New("private controller construction failed")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLaneProducerFixture(t, LaneLinuxAMD64)
			test.mutate(&fixture)

			status, err := produceQualificationLane(context.Background(), fixture.request, fixture.dependencies)
			if err == nil || status == StatusPass {
				t.Fatalf("preconstruction result = (%q, %v), want non-PASS error", status, err)
			}
			if _, statErr := os.Lstat(fixture.request.OutputDir); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("preconstruction failure invented output lane: %v", statErr)
			}
			if len(fixture.executor.requests) != 0 || len(fixture.logs.entries) != 0 {
				t.Fatalf("preconstruction failure executed %d gates and wrote %d logs",
					len(fixture.executor.requests), len(fixture.logs.entries))
			}
		})
	}
}

func TestProduceQualificationLaneNeverReplacesPreexistingOutput(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "file",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("preexisting-file"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "sentinel"), []byte("preexisting-directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLaneProducerFixture(t, LaneLinuxAMD64)
			test.setup(t, fixture.request.OutputDir)
			before := snapshotLaneProducerPath(t, fixture.request.OutputDir)

			status, err := produceQualificationLane(context.Background(), fixture.request, fixture.dependencies)
			if err == nil || status == StatusPass {
				t.Fatalf("preexisting output result = (%q, %v), want non-PASS error", status, err)
			}
			after := snapshotLaneProducerPath(t, fixture.request.OutputDir)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("preexisting output changed: before=%#v after=%#v", before, after)
			}
			if len(fixture.executor.requests) != 0 || len(fixture.logs.entries) != 0 {
				t.Fatalf("known no-replace failure executed %d gates and wrote %d logs",
					len(fixture.executor.requests), len(fixture.logs.entries))
			}
		})
	}
}

const laneProducerRawMarker = "RAW-PRIVATE-LANE-OUTPUT-9f02d45b"

type laneProducerFixture struct {
	request      qualificationLaneRequest
	dependencies qualificationLaneDependencies
	snapshot     RepositorySnapshot
	inspector    *laneProducerRepositoryFake
	executor     *gateTestExecutor
	clock        *laneProducerClockFake
	controller   *laneProducerSelfControllerFake
	logs         *gateTestLogSink
}

func newLaneProducerFixture(t *testing.T, lane Lane) laneProducerFixture {
	t.Helper()
	gate := newGateRunnerFixture(t, lane)
	files := []RepositoryFile{
		laneProducerRepositoryFile("README.md", "100644", []byte("RepoPassport source qualification fixture\n")),
		laneProducerRepositoryFile("go.mod", "100644", []byte("module "+canonicalModulePath+"\n")),
	}
	archiveFiles := make([]archiveFile, len(files))
	for index, file := range files {
		archiveFiles[index] = archiveFile{Path: file.Path, GitMode: file.GitMode, Data: append([]byte(nil), file.Data...)}
	}
	treeSHA, err := reconstructGitTreeSHA1(archiveFiles)
	if err != nil {
		t.Fatalf("build repository fixture tree: %v", err)
	}
	snapshot := RepositorySnapshot{
		Subject: RepositorySubject{
			Repository:      canonicalRepositoryURL,
			ModulePath:      canonicalModulePath,
			ModuleVersion:   canonicalModuleVersion,
			GitObjectFormat: "sha1",
			BaseRevision:    strings.Repeat("b", 40),
			TestedRevision:  gate.request.TestedRevision,
			TreeSHA:         treeSHA,
			Dirty:           false,
		},
		Files: files,
	}
	inspector := &laneProducerRepositoryFake{snapshot: snapshot}
	executor := &gateTestExecutor{steps: passingGateSteps(gate.request)}
	clock := &laneProducerClockFake{values: []time.Time{
		time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 11, 0, 0, 3, 0, time.UTC),
	}}
	controller := &laneProducerSelfControllerFake{facts: receiptController{
		GoVersion:   receiptGoVersion,
		MainPackage: receiptControllerPackage,
		ModulePath:  canonicalModulePath,
		SHA256:      sha256Digest([]byte("lane-controller-" + string(lane))),
		VCSModified: false,
		VCSRevision: gate.request.TestedRevision,
	}}
	logs := &gateTestLogSink{}
	run := RunIdentity{
		WorkflowRepository: canonicalWorkflowRepository,
		WorkflowPath:       canonicalWorkflowPath,
		Event:              "push",
		Ref:                canonicalMainRef,
		WorkflowRunID:      "123456789",
		WorkflowRunAttempt: 1,
		TestedRevision:     gate.request.TestedRevision,
	}
	request := qualificationLaneRequest{
		Repository: RepositoryRequest{
			Root:                   gate.request.RepositoryRoot,
			ExpectedBaseRevision:   snapshot.Subject.BaseRevision,
			ExpectedTestedRevision: snapshot.Subject.TestedRevision,
		},
		Gate:      gate.request,
		Run:       run,
		Platform:  laneProducerPlatform(lane),
		OutputDir: filepath.Join(gate.privateRoot, "published-"+string(lane)),
	}
	dependencies := qualificationLaneDependencies{
		Repository:     inspector,
		Executor:       executor,
		Clock:          clock,
		SelfController: controller,
		PrivateLogs:    logs,
	}
	return laneProducerFixture{
		request: request, dependencies: dependencies, snapshot: snapshot,
		inspector: inspector, executor: executor, clock: clock, controller: controller, logs: logs,
	}
}

type laneProducerRepositoryFake struct {
	snapshot     RepositorySnapshot
	afterInitial *RepositorySnapshot
	err          error
	requests     []RepositoryRequest
}

func (fake *laneProducerRepositoryFake) InspectRepository(request RepositoryRequest) (RepositorySnapshot, error) {
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return RepositorySnapshot{}, fake.err
	}
	result := fake.snapshot
	if len(fake.requests) > 1 && fake.afterInitial != nil {
		result = *fake.afterInitial
	}
	return cloneLaneProducerSnapshot(result), nil
}

func cloneLaneProducerSnapshot(snapshot RepositorySnapshot) RepositorySnapshot {
	result := snapshot
	result.Files = append([]RepositoryFile(nil), snapshot.Files...)
	for index := range result.Files {
		result.Files[index].Data = append([]byte(nil), result.Files[index].Data...)
	}
	return result
}

type laneProducerClockFake struct {
	values []time.Time
	calls  int
}

func (fake *laneProducerClockFake) Now() time.Time {
	index := fake.calls
	fake.calls++
	if index >= len(fake.values) {
		return fake.values[len(fake.values)-1]
	}
	return fake.values[index]
}

type laneProducerSelfControllerFake struct {
	facts receiptController
	err   error
	calls int
}

func (fake *laneProducerSelfControllerFake) InspectSelfController() (receiptController, error) {
	fake.calls++
	return fake.facts, fake.err
}

func laneProducerRepositoryFile(path, mode string, data []byte) RepositoryFile {
	return RepositoryFile{
		Path: path, GitMode: mode, GitBlobSHA1: gitBlobSHA1(data),
		Size: int64(len(data)), Data: append([]byte(nil), data...),
	}
}

func laneProducerPlatform(lane Lane) receiptPlatform {
	result := receiptPlatform{
		GitVersion:         "git version 2.50.1",
		GoVersion:          receiptGoVersion,
		GOARCH:             "amd64",
		GOOS:               "linux",
		KernelVersion:      "6.11.0",
		PowerShellVersion:  "7.5.2",
		RunnerArch:         "X64",
		RunnerImage:        "ubuntu-24.04",
		RunnerImageVersion: "20260810.1",
		RunnerOS:           "Linux",
	}
	if lane == LaneWindowsAMD64 {
		result.GOOS = "windows"
		result.KernelVersion = "10.0.26100"
		result.PowerShellVersion = "5.1.26100.1"
		result.RunnerImage = "windows-2025"
		result.RunnerOS = "Windows"
	}
	return result
}

func laneProducerSourceSubject(subject RepositorySubject) Subject {
	return Subject{
		Repository: subject.Repository, ModulePath: subject.ModulePath,
		ModuleVersion: subject.ModuleVersion, GitObjectFormat: subject.GitObjectFormat,
		BaseRevision: subject.BaseRevision, TestedRevision: subject.TestedRevision,
		TreeSHA: subject.TreeSHA, Dirty: subject.Dirty,
	}
}

func laneProducerReceiptSubject(subject RepositorySubject) receiptSubject {
	return receiptSubject{
		Repository: subject.Repository, ModulePath: subject.ModulePath,
		ModuleVersion: subject.ModuleVersion, GitObjectFormat: subject.GitObjectFormat,
		BaseRevision: subject.BaseRevision, TestedRevision: subject.TestedRevision,
		TreeSHA: subject.TreeSHA, Dirty: subject.Dirty,
	}
}

func laneProducerReceiptFilename(lane Lane) string {
	if lane == LaneLinuxAMD64 {
		return qualificationLinuxReceiptFilename
	}
	return qualificationWindowsReceiptFilename
}

func readExactLaneProducerOutput(t *testing.T, directory string, lane Lane) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read lane directory: %v", err)
	}
	gotNames := make([]string, len(entries))
	result := make(map[string][]byte, len(entries))
	for index, entry := range entries {
		gotNames[index] = entry.Name()
		if entry.Type()&os.ModeType != 0 {
			t.Fatalf("lane entry %q is not a regular file", entry.Name())
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("lane entry %q is not stable regular file: %v", entry.Name(), err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("lane entry %q permissions = %#o, want private", entry.Name(), info.Mode().Perm())
		}
		result[entry.Name()], err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("read lane entry %q: %v", entry.Name(), err)
		}
	}
	wantNames := []string{archiveFilename, qualificationManifestFilename, laneProducerReceiptFilename(lane)}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("lane inventory = %#v, want exact %#v", gotNames, wantNames)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("lane directory is not private: mode=%v err=%v", info, err)
		}
	}
	return result
}

func requireLaneProducerReceiptFacts(
	t *testing.T,
	receipt qualificationReceipt,
	fixture laneProducerFixture,
	archive, manifest []byte,
	status QualificationStatus,
	skipped int64,
) {
	t.Helper()
	runID := QualificationRunID(fixture.request.Run)
	wantRun := receiptRun{
		Event: fixture.request.Run.Event, HeadSHA: fixture.snapshot.Subject.TestedRevision,
		Issuer: "NOT_ESTABLISHED", Lane: fixture.request.Gate.Lane,
		QualificationRunID: runID, Ref: fixture.request.Run.Ref,
		WorkflowPath:       fixture.request.Run.WorkflowPath,
		WorkflowRepository: fixture.request.Run.WorkflowRepository,
		WorkflowRunAttempt: int64(fixture.request.Run.WorkflowRunAttempt),
		WorkflowRunID:      fixture.request.Run.WorkflowRunID,
		WorkflowURL:        receiptRepositoryURL + "/actions/runs/" + fixture.request.Run.WorkflowRunID,
	}
	if receipt.QualificationStatus != status || receipt.Subject != laneProducerReceiptSubject(fixture.snapshot.Subject) ||
		receipt.Run != wantRun || receipt.Controller != fixture.controller.facts || receipt.Platform != fixture.request.Platform {
		t.Fatalf("receipt facts differ: status=%q subject=%#v run=%#v controller=%#v platform=%#v",
			receipt.QualificationStatus, receipt.Subject, receipt.Run, receipt.Controller, receipt.Platform)
	}
	wantAttempt := receiptAttempt{
		AttemptID:  AttemptID(runID, fixture.request.Gate.Lane, 1),
		FinishedAt: fixture.clock.values[1].Format(receiptTimestampLayout),
		Ordinal:    1, PriorAttempts: []receiptPriorAttempt{}, RetryOf: nil,
		StartedAt: fixture.clock.values[0].Format(receiptTimestampLayout),
	}
	if !reflect.DeepEqual(receipt.Attempt, wantAttempt) {
		t.Fatalf("attempt = %#v, want %#v", receipt.Attempt, wantAttempt)
	}
	if receipt.Execution != (receiptExecution{
		ManualActionCount: 0, RawLogsPublished: false, RetryCount: 0, SkippedGateCount: skipped,
	}) {
		t.Fatalf("execution = %#v, want rawLogsPublished=false skipped=%d", receipt.Execution, skipped)
	}
	if !receiptBindingMatches(receipt.Source.Archive, archive) || !receiptBindingMatches(receipt.Source.Manifest, manifest) {
		t.Fatalf("receipt source bindings do not match exact source bytes: %#v", receipt.Source)
	}
}

func assertLaneProducerPrivateBytesAbsent(t *testing.T, files map[string][]byte, marker string) {
	t.Helper()
	for name, raw := range files {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("public lane file %q contains raw private gate output", name)
		}
	}
}

func snapshotLaneProducerPath(t *testing.T, path string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result["."] = raw
		return result
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = raw
	}
	return result
}
