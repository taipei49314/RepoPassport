package sourcequalification

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	attemptTombstoneFilename      = "source-qualification-attempt-v1.json"
	attemptTombstoneArtifactType  = "repopass-source-qualification-attempt"
	attemptTombstoneSchemaVersion = "1"
	attemptTombstoneMaxBytes      = 16 << 10
	attemptTombstoneMaxDepth      = 4
	attemptTombstoneMaxNodes      = 32
	attemptTombstoneStagingPrefix = ".repopass-source-qualification-attempt-"
)

var (
	errAttemptTombstoneInput       = errors.New("source qualification attempt input is invalid")
	errAttemptTombstoneBytes       = errors.New("source qualification attempt bytes are invalid")
	errAttemptTombstoneJSON        = errors.New("source qualification attempt JSON is invalid")
	errAttemptTombstoneCanonical   = errors.New("source qualification attempt JSON is not canonical")
	errAttemptTombstoneShape       = errors.New("source qualification attempt shape is invalid")
	errAttemptTombstoneContract    = errors.New("source qualification attempt contract is invalid")
	errAttemptTombstoneEncoding    = errors.New("source qualification attempt encoding failed")
	errAttemptTombstonePublication = errors.New("source qualification attempt publication failed")
)

type qualificationAttemptTombstone struct {
	ArtifactType           string              `json:"artifactType"`
	AttemptID              string              `json:"attemptId"`
	Code                   string              `json:"code"`
	ExpectedBaseRevision   string              `json:"expectedBaseRevision"`
	ExpectedTestedRevision string              `json:"expectedTestedRevision"`
	ExpectedTreeSHA        string              `json:"expectedTreeSHA"`
	Lane                   Lane                `json:"lane"`
	Ordinal                int64               `json:"ordinal"`
	QualificationRunID     string              `json:"qualificationRunId"`
	QualificationStatus    QualificationStatus `json:"qualificationStatus"`
	SchemaVersion          string              `json:"schemaVersion"`
	WorkflowRunAttempt     int64               `json:"workflowRunAttempt"`
	WorkflowRunID          string              `json:"workflowRunId"`
}

func marshalAttemptTombstone(document qualificationAttemptTombstone) ([]byte, error) {
	if err := validateAttemptTombstone(document); err != nil {
		return nil, errAttemptTombstoneInput
	}
	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		return nil, errAttemptTombstoneEncoding
	}
	if len(raw) == 0 || len(raw) > attemptTombstoneMaxBytes {
		return nil, errAttemptTombstoneBytes
	}
	return raw, nil
}

func parseCanonicalAttemptTombstone(raw []byte) (qualificationAttemptTombstone, error) {
	var result qualificationAttemptTombstone
	if len(raw) == 0 || len(raw) > attemptTombstoneMaxBytes {
		return result, errAttemptTombstoneBytes
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: attemptTombstoneMaxBytes,
		MaxDepth: attemptTombstoneMaxDepth,
		MaxNodes: attemptTombstoneMaxNodes,
	})
	if err != nil {
		return result, errAttemptTombstoneJSON
	}
	canonical, err := canonicaljson.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return result, errAttemptTombstoneCanonical
	}
	if !validAttemptTombstoneShape(value) {
		return result, errAttemptTombstoneShape
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return qualificationAttemptTombstone{}, errAttemptTombstoneShape
	}
	if err := validateAttemptTombstone(result); err != nil {
		return qualificationAttemptTombstone{}, errAttemptTombstoneContract
	}
	return result, nil
}

func validateAttemptTombstone(document qualificationAttemptTombstone) error {
	if document.ArtifactType != attemptTombstoneArtifactType ||
		document.SchemaVersion != attemptTombstoneSchemaVersion ||
		!validReceiptGitSHA1(document.ExpectedBaseRevision) ||
		!validReceiptGitSHA1(document.ExpectedTestedRevision) ||
		!validReceiptGitSHA1(document.ExpectedTreeSHA) ||
		(document.Lane != LaneLinuxAMD64 && document.Lane != LaneWindowsAMD64) ||
		document.Ordinal < 1 || document.Ordinal > receiptMaxInt32 ||
		!validReceiptSHA256(document.QualificationRunID) ||
		document.AttemptID != document.QualificationRunID+":"+string(document.Lane)+":"+
			strconv.FormatInt(document.Ordinal, 10) ||
		document.WorkflowRunAttempt < 1 || document.WorkflowRunAttempt > receiptMaxInt32 ||
		!validReceiptPositiveDecimal(document.WorkflowRunID, 20) {
		return errAttemptTombstoneContract
	}
	wantStatus, ok := attemptTombstoneStatusForCode(document.Code)
	if !ok || document.QualificationStatus != wantStatus {
		return errAttemptTombstoneContract
	}
	return nil
}

func attemptTombstoneStatusForCode(code string) (QualificationStatus, bool) {
	switch code {
	case "SOURCE_QUAL_GATE_BLOCKED":
		return StatusBlocked, true
	case "SOURCE_QUAL_GATE_NOT_RUN":
		return StatusNotRun, true
	case "SOURCE_QUAL_INVALID_INPUT",
		"SOURCE_QUAL_SOURCE_DIRTY",
		"SOURCE_QUAL_SUBJECT_MISMATCH",
		"SOURCE_QUAL_ARCHIVE_INVALID",
		"SOURCE_QUAL_MANIFEST_INVALID",
		"SOURCE_QUAL_RECEIPT_INVALID",
		"SOURCE_QUAL_GATE_SET_INVALID",
		"SOURCE_QUAL_GATE_FAILED",
		"SOURCE_QUAL_PRIVACY_INVALID",
		"SOURCE_QUAL_CLEANUP_FAILED",
		"SOURCE_QUAL_OUTPUT_LIMIT",
		"SOURCE_QUAL_DESTINATION_EXISTS":
		return StatusFail, true
	default:
		return "", false
	}
}

func validAttemptTombstoneShape(value any) bool {
	root, ok := value.(map[string]any)
	if !ok || len(root) != 13 {
		return false
	}
	for _, key := range []string{
		"artifactType", "attemptId", "code", "expectedBaseRevision",
		"expectedTestedRevision", "expectedTreeSHA", "lane", "ordinal",
		"qualificationRunId", "qualificationStatus", "schemaVersion",
		"workflowRunAttempt", "workflowRunId",
	} {
		if _, exists := root[key]; !exists {
			return false
		}
	}
	return true
}

func publishAttemptTombstone(outputDir string, document qualificationAttemptTombstone) (returnErr error) {
	raw, err := marshalAttemptTombstone(document)
	if err != nil {
		return errAttemptTombstoneInput
	}
	outputPath, err := canonicalPackageFilesystemPath(outputDir)
	if err != nil {
		return errAttemptTombstonePublication
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return errAttemptTombstonePublication
	}
	parentPath := filepath.Dir(outputPath)
	parent, parentSnapshot, err := openValidatedPackageDirectory(parentPath)
	if err != nil {
		return errAttemptTombstonePublication
	}
	defer parent.Close()

	stagingPath := ""
	defer func() {
		if stagingPath == "" {
			return
		}
		if err := os.RemoveAll(stagingPath); err != nil {
			returnErr = errors.New("source qualification attempt staging cleanup failed")
		}
	}()

	stagingPath, err = os.MkdirTemp(parentPath, attemptTombstoneStagingPrefix)
	if err != nil {
		return errAttemptTombstonePublication
	}
	if err := securePrivatePackagePath(stagingPath, true); err != nil {
		return errAttemptTombstonePublication
	}
	if err := requirePrivatePackageDirectory(stagingPath); err != nil {
		return errAttemptTombstonePublication
	}
	if err := requirePackageDirectoryIdentity(parentPath, parentSnapshot.identity); err != nil {
		return errAttemptTombstonePublication
	}

	specifications := []packageFileSpec{{
		name:     attemptTombstoneFilename,
		maxBytes: int64(attemptTombstoneMaxBytes),
		expected: raw,
	}}
	if err := writePrivatePackageFile(filepath.Join(stagingPath, attemptTombstoneFilename), raw); err != nil {
		return errAttemptTombstonePublication
	}
	staged, err := readExactPackageDirectory(stagingPath, specifications)
	if err != nil {
		return errAttemptTombstonePublication
	}
	staging, stagingSnapshot, err := openValidatedPackageDirectory(stagingPath)
	if err != nil {
		return errAttemptTombstonePublication
	}
	if stagingSnapshot != staged.snapshot {
		_ = staging.Close()
		return errAttemptTombstonePublication
	}
	if err := syncPackageDirectory(staging); err != nil {
		_ = staging.Close()
		return errAttemptTombstonePublication
	}
	if err := staging.Close(); err != nil {
		return errAttemptTombstonePublication
	}

	if err := requirePackageDirectoryIdentity(parentPath, parentSnapshot.identity); err != nil {
		return errAttemptTombstonePublication
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return errAttemptTombstonePublication
	}
	if err := publishPackageDirectoryNoReplace(stagingPath, outputPath); err != nil {
		return errAttemptTombstonePublication
	}
	stagingPath = ""
	if err := syncPublishedPackageParent(parent); err != nil {
		if cleanupErr := cleanupPublishedPackage(
			outputPath,
			staged.snapshot.identity,
			specifications,
			parent,
		); cleanupErr != nil {
			return errors.New("source qualification published attempt cleanup failed")
		}
		return errAttemptTombstonePublication
	}
	return nil
}
