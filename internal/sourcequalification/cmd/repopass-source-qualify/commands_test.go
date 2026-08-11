package main

// Production command-dispatch contract under test:
//
//	type controllerCommandOperations interface {
//		ProduceLane(produceLaneCommandRequest) (controllerRecord, error)
//		Assemble(assembleCommandRequest) (controllerRecord, error)
//		AssembleTools(assembleToolsCommandRequest) (controllerRecord, error)
//		VerifyIntegrity(verifyIntegrityCommandRequest) (controllerRecord, error)
//		VerifySubject(verifySubjectCommandRequest) (controllerRecord, error)
//	}
//	func runWithControllerOperations(
//		args []string,
//		stdout, stderr io.Writer,
//		operations controllerCommandOperations,
//	) int
//
// run delegates only after parsing the exact RFC-0002 token grammar. The
// production adapter owns all filesystem, Git, gate, build-info, and offline
// verification work. Its raw error is private; only its validated fixed record
// is eligible for the one public JSONL line.

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	cliHistoricalIntegrity = "HISTORICAL_INTEGRITY"
	cliSubjectMatch        = "SUBJECT_MATCH"
)

func TestRunControllerCommandsDispatchExactRequestsAndRecords(t *testing.T) {
	fixture := newCLICommandFixture(t)

	t.Run("produce lane", func(t *testing.T) {
		operations := &cliCommandOperationsFake{result: controllerRecord{
			Code:                "SOURCE_QUAL_OK",
			ID:                  cliControllerID,
			QualificationStatus: "PASS",
			SHA256:              cliNotApplicable,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		}}
		exitCode, stdout, stderr := cliRunWithOperations(fixture.produceLaneArgs(), operations)
		if exitCode != 0 {
			t.Fatalf("produce-lane exit code = %d, want 0", exitCode)
		}
		if len(operations.calls) != 1 || operations.calls[0] != commandProduceLane {
			t.Fatalf("produce-lane dispatch calls = %v", operations.calls)
		}
		want := produceLaneCommandRequest{
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
		if !reflect.DeepEqual(operations.produceLaneRequest, want) {
			t.Fatalf("produce-lane request mismatch\n got: %#v\nwant: %#v", operations.produceLaneRequest, want)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedOperationRecord(
			"SOURCE_QUAL_OK", "PASS", cliNotApplicable,
			fixture.testedRevision, fixture.treeSHA,
		))
		cliAssertPrivate(t, stdout, fixture.repoRoot, fixture.privateLogRoot, fixture.laneOutputDir)
	})

	t.Run("assemble", func(t *testing.T) {
		operations := &cliCommandOperationsFake{result: controllerRecord{
			Code:                "SOURCE_QUAL_OK",
			ID:                  cliControllerID,
			QualificationStatus: "PASS",
			SHA256:              fixture.packageDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		}}
		exitCode, stdout, stderr := cliRunWithOperations(fixture.assembleArgs(), operations)
		if exitCode != 0 {
			t.Fatalf("assemble exit code = %d, want 0", exitCode)
		}
		want := assembleCommandRequest{
			LinuxDir:                   fixture.linuxDir,
			WindowsDir:                 fixture.windowsDir,
			ExpectedBaseRevision:       fixture.baseRevision,
			ExpectedTestedRevision:     fixture.testedRevision,
			ExpectedTreeSHA:            fixture.treeSHA,
			ExpectedQualificationRunID: fixture.qualificationRunID,
			ExpectedWorkflowRunID:      fixture.workflowRunID,
			ExpectedWorkflowRunAttempt: 1,
			OutputDir:                  fixture.aggregateOutputDir,
		}
		if !reflect.DeepEqual(operations.assembleRequest, want) {
			t.Fatalf("assemble request mismatch\n got: %#v\nwant: %#v", operations.assembleRequest, want)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedOperationRecord(
			"SOURCE_QUAL_OK", "PASS", fixture.packageDigest,
			fixture.testedRevision, fixture.treeSHA,
		))
		cliAssertPrivate(t, stdout, fixture.linuxDir, fixture.windowsDir, fixture.aggregateOutputDir)
	})

	t.Run("assemble tools", func(t *testing.T) {
		operations := &cliCommandOperationsFake{result: controllerRecord{
			Code:                "SOURCE_QUAL_OK",
			ID:                  cliControllerID,
			QualificationStatus: "PASS",
			SHA256:              fixture.toolManifestDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		}}
		exitCode, stdout, stderr := cliRunWithOperations(fixture.assembleToolsArgs(), operations)
		if exitCode != 0 {
			t.Fatalf("assemble-tools exit code = %d, want 0", exitCode)
		}
		want := assembleToolsCommandRequest{
			PackageDir:        fixture.packageDir,
			LinuxController:   fixture.linuxController,
			WindowsController: fixture.windowsController,
			OutputDir:         fixture.toolsOutputDir,
		}
		if !reflect.DeepEqual(operations.assembleToolsRequest, want) {
			t.Fatalf("assemble-tools request mismatch\n got: %#v\nwant: %#v", operations.assembleToolsRequest, want)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedOperationRecord(
			"SOURCE_QUAL_OK", "PASS", fixture.toolManifestDigest,
			fixture.testedRevision, fixture.treeSHA,
		))
		cliAssertPrivate(t, stdout, fixture.packageDir, fixture.linuxController, fixture.windowsController, fixture.toolsOutputDir)
	})

	t.Run("verify integrity", func(t *testing.T) {
		operations := &cliCommandOperationsFake{result: controllerRecord{
			Code:                "SOURCE_QUAL_OK",
			ID:                  cliControllerID,
			QualificationStatus: cliHistoricalIntegrity,
			SHA256:              fixture.packageDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		}}
		exitCode, stdout, stderr := cliRunWithOperations(fixture.verifyIntegrityArgs(), operations)
		if exitCode != 0 {
			t.Fatalf("verify-integrity exit code = %d, want 0", exitCode)
		}
		want := verifyIntegrityCommandRequest{PackageDir: fixture.packageDir}
		if !reflect.DeepEqual(operations.verifyIntegrityRequest, want) {
			t.Fatalf("verify-integrity request mismatch\n got: %#v\nwant: %#v", operations.verifyIntegrityRequest, want)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedOperationRecord(
			"SOURCE_QUAL_OK", cliHistoricalIntegrity, fixture.packageDigest,
			fixture.testedRevision, fixture.treeSHA,
		))
		cliAssertPrivate(t, stdout, fixture.packageDir)
	})

	t.Run("verify subject", func(t *testing.T) {
		operations := &cliCommandOperationsFake{result: controllerRecord{
			Code:                "SOURCE_QUAL_OK",
			ID:                  cliControllerID,
			QualificationStatus: cliSubjectMatch,
			SHA256:              fixture.packageDigest,
			TestedRevision:      fixture.testedRevision,
			TreeSHA:             fixture.treeSHA,
		}}
		exitCode, stdout, stderr := cliRunWithOperations(fixture.verifySubjectArgs(), operations)
		if exitCode != 0 {
			t.Fatalf("verify-subject exit code = %d, want 0", exitCode)
		}
		want := verifySubjectCommandRequest{
			PackageDir:                 fixture.packageDir,
			ExpectedRepository:         "https://github.com/taipei49314/RepoPassport",
			ExpectedBaseRevision:       fixture.baseRevision,
			ExpectedTestedRevision:     fixture.testedRevision,
			ExpectedTreeSHA:            fixture.treeSHA,
			ExpectedQualificationRunID: fixture.qualificationRunID,
			ExpectedWorkflowRunID:      fixture.workflowRunID,
			ExpectedWorkflowRunAttempt: 1,
			ExpectedPackageDigest:      fixture.packageDigest,
			ToolManifestPath:           fixture.toolManifest,
			ExpectedToolManifestDigest: fixture.toolManifestDigest,
			ExpectedExecutableDigest:   fixture.executableDigest,
		}
		if !reflect.DeepEqual(operations.verifySubjectRequest, want) {
			t.Fatalf("verify-subject request mismatch\n got: %#v\nwant: %#v", operations.verifySubjectRequest, want)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedOperationRecord(
			"SOURCE_QUAL_OK", cliSubjectMatch, fixture.packageDigest,
			fixture.testedRevision, fixture.treeSHA,
		))
		cliAssertPrivate(t, stdout, fixture.packageDir, fixture.toolManifest)
	})
}

func TestRunControllerCommandsRejectsNonExactFlagGrammarBeforeDispatch(t *testing.T) {
	fixture := newCLICommandFixture(t)
	commands := []struct {
		name  string
		args  []string
		extra []cliArgsMutation
	}{
		{
			name: "produce lane",
			args: fixture.produceLaneArgs(),
			extra: []cliArgsMutation{
				cliReplaceMutation("invalid lane", flagLane, "darwin-amd64"),
				cliReplaceMutation("invalid event", flagEvent, "schedule"),
				cliReplaceMutation("event ref mismatch", flagExpectedRef, "refs/heads/other"),
				cliReplaceMutation("invalid base revision", flagExpectedBaseRevision, strings.ToUpper(fixture.baseRevision)),
				cliReplaceMutation("invalid tested revision", flagExpectedTestedRevision, fixture.testedRevision[:39]),
				cliReplaceMutation("noncanonical workflow run id", flagWorkflowRunID, "01"),
				cliReplaceMutation("zero workflow run attempt", flagWorkflowRunAttempt, "0"),
				cliReplaceMutation("overflow workflow run attempt", flagWorkflowRunAttempt, "2147483648"),
				cliReplaceFlagMutation("expected workflow id flag is forbidden", flagWorkflowRunID, flagExpectedWorkflowRunID),
				cliReplaceFlagMutation("expected workflow attempt flag is forbidden", flagWorkflowRunAttempt, flagExpectedWorkflowRunAttempt),
			},
		},
		{
			name: "assemble",
			args: fixture.assembleArgs(),
			extra: []cliArgsMutation{
				cliReplaceMutation("invalid base revision", flagExpectedBaseRevision, fixture.baseRevision[:39]),
				cliReplaceMutation("invalid tested revision", flagExpectedTestedRevision, strings.ToUpper(fixture.testedRevision)),
				cliReplaceMutation("invalid tree", flagExpectedTree, fixture.treeSHA+"0"),
				cliReplaceMutation("invalid qualification run digest", flagExpectedQualificationRunID, strings.TrimPrefix(fixture.qualificationRunID, "sha256:")),
				cliReplaceMutation("noncanonical expected workflow run id", flagExpectedWorkflowRunID, "00"),
				cliReplaceMutation("negative expected workflow attempt", flagExpectedWorkflowRunAttempt, "-1"),
				cliReplaceFlagMutation("producer workflow id flag is forbidden", flagExpectedWorkflowRunID, flagWorkflowRunID),
				cliReplaceFlagMutation("producer workflow attempt flag is forbidden", flagExpectedWorkflowRunAttempt, flagWorkflowRunAttempt),
			},
		},
		{
			name: "assemble tools",
			args: fixture.assembleToolsArgs(),
		},
		{
			name: "verify integrity",
			args: fixture.verifyIntegrityArgs(),
		},
		{
			name: "verify subject",
			args: fixture.verifySubjectArgs(),
			extra: []cliArgsMutation{
				cliReplaceMutation("wrong repository", flagExpectedRepository, "https://github.com/example/RepoPassport"),
				cliReplaceMutation("invalid base revision", flagExpectedBaseRevision, "not-a-revision"),
				cliReplaceMutation("invalid tested revision", flagExpectedTestedRevision, strings.ToUpper(fixture.testedRevision)),
				cliReplaceMutation("invalid tree", flagExpectedTree, fixture.treeSHA[:39]),
				cliReplaceMutation("invalid qualification run digest", flagExpectedQualificationRunID, "sha256:"+strings.Repeat("A", 64)),
				cliReplaceMutation("noncanonical expected workflow run id", flagExpectedWorkflowRunID, "+123"),
				cliReplaceMutation("zero expected workflow attempt", flagExpectedWorkflowRunAttempt, "0"),
				cliReplaceMutation("invalid package digest", flagExpectedPackageDigest, "sha512:"+strings.Repeat("5", 64)),
				cliReplaceMutation("invalid tool manifest digest", flagExpectedToolManifestDigest, "sha256:"+strings.Repeat("g", 64)),
				cliReplaceMutation("invalid executable digest", flagExpectedExecutableDigest, "sha256:"+strings.Repeat("7", 63)),
				cliReplaceFlagMutation("producer workflow id flag is forbidden", flagExpectedWorkflowRunID, flagWorkflowRunID),
				cliReplaceFlagMutation("producer workflow attempt flag is forbidden", flagExpectedWorkflowRunAttempt, flagWorkflowRunAttempt),
			},
		},
	}

	for _, command := range commands {
		mutations := cliCommonInvalidMutations(command.args)
		mutations = append(mutations, command.extra...)
		for _, mutation := range mutations {
			t.Run(command.name+"/"+mutation.name, func(t *testing.T) {
				operations := &cliCommandOperationsFake{result: newControllerRecord(
					"SOURCE_QUAL_OK", cliControllerID, "PASS",
				)}
				args := mutation.apply(command.args)
				exitCode, stdout, stderr := cliRunWithOperations(args, operations)
				if exitCode == 0 {
					t.Fatal("controller accepted non-exact command grammar")
				}
				if len(operations.calls) != 0 {
					t.Fatalf("invalid input reached controller adapter: %v", operations.calls)
				}
				cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
					"SOURCE_QUAL_INVALID_INPUT", cliControllerID, "FAIL",
				))
				cliAssertPrivate(t, stdout,
					fixture.privateMarker,
					fixture.repoRoot,
					fixture.privateLogRoot,
					fixture.packageDir,
					fixture.toolManifest,
					"Usage of",
					"flag provided",
				)
			})
		}
	}
}

func TestRunControllerCommandsKeepsAdapterErrorsPrivate(t *testing.T) {
	fixture := newCLICommandFixture(t)
	commands := []struct {
		name string
		args []string
		code string
	}{
		{"produce lane", fixture.produceLaneArgs(), "SOURCE_QUAL_GATE_FAILED"},
		{"assemble", fixture.assembleArgs(), "SOURCE_QUAL_SUBJECT_MISMATCH"},
		{"assemble tools", fixture.assembleToolsArgs(), "SOURCE_QUAL_RECEIPT_INVALID"},
		{"verify integrity", fixture.verifyIntegrityArgs(), "SOURCE_QUAL_ARCHIVE_INVALID"},
		{"verify subject", fixture.verifySubjectArgs(), "SOURCE_QUAL_SUBJECT_MISMATCH"},
	}

	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			privateError := "raw adapter failure at " + fixture.privateMarker
			operations := &cliCommandOperationsFake{
				result: newControllerRecord(command.code, cliControllerID, "FAIL"),
				err:    errors.New(privateError),
			}
			exitCode, stdout, stderr := cliRunWithOperations(command.args, operations)
			if exitCode == 0 {
				t.Fatal("controller returned success after its adapter failed")
			}
			if len(operations.calls) != 1 {
				t.Fatalf("adapter call count = %d, want 1", len(operations.calls))
			}
			cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
				command.code, cliControllerID, "FAIL",
			))
			cliAssertPrivate(t, stdout, privateError, fixture.privateMarker, "raw adapter failure")
		})
	}
}

func TestRunControllerCommandsRejectsMaliciousOrInconsistentAdapterRecords(t *testing.T) {
	fixture := newCLICommandFixture(t)
	private := filepath.Join(t.TempDir(), "private-user-secret-token-value")
	validSuccess := controllerRecord{
		Code:                "SOURCE_QUAL_OK",
		ID:                  cliControllerID,
		QualificationStatus: "PASS",
		SHA256:              cliNotApplicable,
		TestedRevision:      fixture.testedRevision,
		TreeSHA:             fixture.treeSHA,
	}
	validFailure := newControllerRecord(
		"SOURCE_QUAL_GATE_FAILED",
		cliControllerID,
		"FAIL",
	)
	tests := []struct {
		name   string
		record controllerRecord
		err    error
	}{
		{
			name: "private code",
			record: func() controllerRecord {
				result := validFailure
				result.Code = private
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name: "unknown code",
			record: func() controllerRecord {
				result := validFailure
				result.Code = "SOURCE_QUAL_UNKNOWN_FUTURE_CODE"
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name: "private id",
			record: func() controllerRecord {
				result := validFailure
				result.ID = private
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name: "private status",
			record: func() controllerRecord {
				result := validFailure
				result.QualificationStatus = private
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name: "private digest",
			record: func() controllerRecord {
				result := validFailure
				result.SHA256 = private
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name: "private tested revision",
			record: func() controllerRecord {
				result := validFailure
				result.TestedRevision = private
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name: "private tree",
			record: func() controllerRecord {
				result := validFailure
				result.TreeSHA = private
				return result
			}(),
			err: errors.New("private adapter failure"),
		},
		{
			name:   "pass with error",
			record: validSuccess,
			err:    errors.New("private adapter failure " + private),
		},
		{
			name:   "failure without error",
			record: validFailure,
			err:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := &cliCommandOperationsFake{result: test.record, err: test.err}
			exitCode, stdout, stderr := cliRunWithOperations(fixture.produceLaneArgs(), operations)
			if exitCode == 0 {
				t.Fatal("controller accepted an inconsistent adapter outcome")
			}
			if len(operations.calls) != 1 || operations.calls[0] != commandProduceLane {
				t.Fatalf("adapter calls = %v, want one produce-lane call", operations.calls)
			}
			cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
				"SOURCE_QUAL_INVALID_INPUT",
				cliControllerID,
				"FAIL",
			))
			cliAssertPrivate(t, stdout,
				private,
				"private-user-secret-token-value",
				"SOURCE_QUAL_UNKNOWN_FUTURE_CODE",
				"private adapter failure",
			)
		})
	}
}

type cliCommandFixture struct {
	privateMarker      string
	repoRoot           string
	privateLogRoot     string
	laneOutputDir      string
	linuxDir           string
	windowsDir         string
	aggregateOutputDir string
	packageDir         string
	linuxController    string
	windowsController  string
	toolsOutputDir     string
	toolManifest       string
	baseRevision       string
	testedRevision     string
	treeSHA            string
	workflowRunID      string
	qualificationRunID string
	packageDigest      string
	toolManifestDigest string
	executableDigest   string
}

func newCLICommandFixture(t *testing.T) cliCommandFixture {
	t.Helper()
	root := t.TempDir()
	privateMarker := "private-user-secret-token-value"
	returnValue := cliCommandFixture{
		privateMarker:      privateMarker,
		repoRoot:           filepath.Join(root, "repo-"+privateMarker),
		privateLogRoot:     filepath.Join(root, "private-logs-"+privateMarker),
		laneOutputDir:      filepath.Join(root, "lane-output"),
		linuxDir:           filepath.Join(root, "linux-lane"),
		windowsDir:         filepath.Join(root, "windows-lane"),
		aggregateOutputDir: filepath.Join(root, "aggregate-output"),
		packageDir:         filepath.Join(root, "package-"+privateMarker),
		linuxController:    filepath.Join(root, "linux-controller"),
		windowsController:  filepath.Join(root, "windows-controller.exe"),
		toolsOutputDir:     filepath.Join(root, "tools-output"),
		toolManifest:       filepath.Join(root, "tool-manifest-"+privateMarker+".json"),
		baseRevision:       strings.Repeat("a", 40),
		testedRevision:     strings.Repeat("b", 40),
		treeSHA:            strings.Repeat("c", 40),
		workflowRunID:      "123456789",
		qualificationRunID: "sha256:" + strings.Repeat("4", 64),
		packageDigest:      "sha256:" + strings.Repeat("5", 64),
		toolManifestDigest: "sha256:" + strings.Repeat("6", 64),
		executableDigest:   "sha256:" + strings.Repeat("7", 64),
	}
	return returnValue
}

func (fixture cliCommandFixture) produceLaneArgs() []string {
	return []string{
		commandProduceLane,
		flagRepoRoot, fixture.repoRoot,
		flagLane, "linux-amd64",
		flagEvent, "push",
		flagExpectedRef, "refs/heads/main",
		flagExpectedBaseRevision, fixture.baseRevision,
		flagExpectedTestedRevision, fixture.testedRevision,
		flagWorkflowRunID, fixture.workflowRunID,
		flagWorkflowRunAttempt, "1",
		flagPrivateLogRoot, fixture.privateLogRoot,
		flagOutDir, fixture.laneOutputDir,
	}
}

func (fixture cliCommandFixture) assembleArgs() []string {
	return []string{
		commandAssemble,
		flagLinuxDir, fixture.linuxDir,
		flagWindowsDir, fixture.windowsDir,
		flagExpectedBaseRevision, fixture.baseRevision,
		flagExpectedTestedRevision, fixture.testedRevision,
		flagExpectedTree, fixture.treeSHA,
		flagExpectedQualificationRunID, fixture.qualificationRunID,
		flagExpectedWorkflowRunID, fixture.workflowRunID,
		flagExpectedWorkflowRunAttempt, "1",
		flagOutDir, fixture.aggregateOutputDir,
	}
}

func (fixture cliCommandFixture) assembleToolsArgs() []string {
	return []string{
		commandAssembleTools,
		flagPackageDir, fixture.packageDir,
		flagLinuxController, fixture.linuxController,
		flagWindowsController, fixture.windowsController,
		flagOutDir, fixture.toolsOutputDir,
	}
}

func (fixture cliCommandFixture) verifyIntegrityArgs() []string {
	return []string{commandVerifyIntegrity, flagPackageDir, fixture.packageDir}
}

func (fixture cliCommandFixture) verifySubjectArgs() []string {
	return []string{
		commandVerifySubject,
		flagPackageDir, fixture.packageDir,
		flagExpectedRepository, "https://github.com/taipei49314/RepoPassport",
		flagExpectedBaseRevision, fixture.baseRevision,
		flagExpectedTestedRevision, fixture.testedRevision,
		flagExpectedTree, fixture.treeSHA,
		flagExpectedQualificationRunID, fixture.qualificationRunID,
		flagExpectedWorkflowRunID, fixture.workflowRunID,
		flagExpectedWorkflowRunAttempt, "1",
		flagExpectedPackageDigest, fixture.packageDigest,
		flagToolManifest, fixture.toolManifest,
		flagExpectedToolManifestDigest, fixture.toolManifestDigest,
		flagExpectedExecutableDigest, fixture.executableDigest,
	}
}

func cliExpectedOperationRecord(code, status, digest, testedRevision, treeSHA string) map[string]any {
	return map[string]any{
		"code":                code,
		"id":                  cliControllerID,
		"qualificationStatus": status,
		"sha256":              digest,
		"testedRevision":      testedRevision,
		"treeSHA":             treeSHA,
	}
}

func cliRunWithOperations(args []string, operations controllerCommandOperations) (int, []byte, []byte) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := runWithControllerOperations(args, &stdout, &stderr, operations)
	return exitCode, bytes.Clone(stdout.Bytes()), bytes.Clone(stderr.Bytes())
}

type cliCommandOperationsFake struct {
	result controllerRecord
	err    error
	calls  []string

	produceLaneRequest     produceLaneCommandRequest
	assembleRequest        assembleCommandRequest
	assembleToolsRequest   assembleToolsCommandRequest
	verifyIntegrityRequest verifyIntegrityCommandRequest
	verifySubjectRequest   verifySubjectCommandRequest
}

func (fake *cliCommandOperationsFake) ProduceLane(request produceLaneCommandRequest) (controllerRecord, error) {
	fake.calls = append(fake.calls, commandProduceLane)
	fake.produceLaneRequest = request
	return fake.result, fake.err
}

func (fake *cliCommandOperationsFake) Assemble(request assembleCommandRequest) (controllerRecord, error) {
	fake.calls = append(fake.calls, commandAssemble)
	fake.assembleRequest = request
	return fake.result, fake.err
}

func (fake *cliCommandOperationsFake) AssembleTools(request assembleToolsCommandRequest) (controllerRecord, error) {
	fake.calls = append(fake.calls, commandAssembleTools)
	fake.assembleToolsRequest = request
	return fake.result, fake.err
}

func (fake *cliCommandOperationsFake) VerifyIntegrity(request verifyIntegrityCommandRequest) (controllerRecord, error) {
	fake.calls = append(fake.calls, commandVerifyIntegrity)
	fake.verifyIntegrityRequest = request
	return fake.result, fake.err
}

func (fake *cliCommandOperationsFake) VerifySubject(request verifySubjectCommandRequest) (controllerRecord, error) {
	fake.calls = append(fake.calls, commandVerifySubject)
	fake.verifySubjectRequest = request
	return fake.result, fake.err
}

type cliArgsMutation struct {
	name  string
	apply func([]string) []string
}

func cliCommonInvalidMutations(valid []string) []cliArgsMutation {
	mutations := []cliArgsMutation{
		{
			name: "unknown trailing flag",
			apply: func(args []string) []string {
				return append(cliCloneArgs(args), "--unknown", "private-user-secret-token-value")
			},
		},
		{
			name: "trailing positional value",
			apply: func(args []string) []string {
				return append(cliCloneArgs(args), "private-user-secret-token-value")
			},
		},
	}
	if len(valid) >= 3 {
		firstFlag := valid[1]
		firstValue := valid[2]
		mutations = append(mutations,
			cliReplaceMutation("empty value", firstFlag, ""),
			cliArgsMutation{
				name: "duplicate flag",
				apply: func(args []string) []string {
					return append(cliCloneArgs(args), firstFlag, firstValue)
				},
			},
			cliArgsMutation{
				name: "equals syntax",
				apply: func(args []string) []string {
					result := cliCloneArgs(args)
					result[1] = firstFlag + "=" + firstValue
					return append(result[:2], result[3:]...)
				},
			},
		)
	}
	if len(valid) >= 5 {
		mutations = append(mutations, cliArgsMutation{
			name: "flag order",
			apply: func(args []string) []string {
				result := cliCloneArgs(args)
				result[1], result[3] = result[3], result[1]
				result[2], result[4] = result[4], result[2]
				return result
			},
		})
	}
	for index := 1; index+1 < len(valid); index += 2 {
		flag := valid[index]
		mutations = append(mutations, cliArgsMutation{
			name: "missing " + strings.TrimPrefix(flag, "--"),
			apply: func(args []string) []string {
				return cliRemoveFlag(args, flag)
			},
		})
	}
	return mutations
}

func cliReplaceMutation(name, flag, value string) cliArgsMutation {
	return cliArgsMutation{
		name: name,
		apply: func(args []string) []string {
			result := cliCloneArgs(args)
			for index := 1; index+1 < len(result); index += 2 {
				if result[index] == flag {
					result[index+1] = value
					return result
				}
			}
			panic("test mutation flag not found: " + flag)
		},
	}
}

func cliReplaceFlagMutation(name, oldFlag, newFlag string) cliArgsMutation {
	return cliArgsMutation{
		name: name,
		apply: func(args []string) []string {
			result := cliCloneArgs(args)
			for index := 1; index+1 < len(result); index += 2 {
				if result[index] == oldFlag {
					result[index] = newFlag
					return result
				}
			}
			panic("test mutation flag not found: " + oldFlag)
		},
	}
}

func cliRemoveFlag(args []string, flag string) []string {
	result := cliCloneArgs(args)
	for index := 1; index+1 < len(result); index += 2 {
		if result[index] == flag {
			return append(result[:index], result[index+2:]...)
		}
	}
	panic("test removal flag not found: " + flag)
}

func cliCloneArgs(args []string) []string {
	return append([]string(nil), args...)
}
