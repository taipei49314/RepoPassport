package acceptanceregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const evaluationDigestDomain = "repopass.acceptance-evaluation.v1\x00"

var (
	errEvaluationInvalid = errors.New("acceptance evaluation is invalid")
	errSubjectInvalid    = errors.New("acceptance evaluation subject is invalid")
	errCheckInputInvalid = errors.New("acceptance required-check input is invalid")
	errIncomplete        = errors.New("acceptance roadmap is incomplete")
)

func Evaluate(registryRaw []byte, request EvaluationRequest) ([]byte, error) {
	registry, err := ParseRegistry(registryRaw)
	if err != nil {
		return nil, err
	}
	registryDigest, err := RegistryDigest(registryRaw)
	if err != nil {
		return nil, err
	}
	if err := validateSubjectAndRun(request.Subject, request.Run); err != nil {
		return nil, err
	}
	results := map[string]string{
		"ci/container-matrix": request.Checks.Container,
		"ci/go":               request.Checks.Go,
		"ci/schema-json":      request.Checks.SchemaJSON,
		"ci/windows-go":       request.Checks.WindowsGo,
	}
	for _, result := range results {
		if !validCheckResult(result) {
			return nil, errCheckInputInvalid
		}
	}
	rows := make([]RowEvaluation, len(registry.Rows))
	for index, row := range registry.Rows {
		rows[index] = evaluateRow(row, request.Run, results)
	}
	overall, stable := aggregateRows(rows)
	evaluation := Evaluation{
		ArtifactType:   "repopass-acceptance-evaluation",
		FormalClaim:    false,
		OverallStatus:  overall,
		RegistryDigest: registryDigest,
		Rows:           rows,
		Run:            request.Run,
		SchemaVersion:  "1",
		StableEligible: stable,
		Subject:        request.Subject,
		TrustBoundary:  "producer-owned-ci",
	}
	digest, err := computeEvaluationDigest(evaluation)
	if err != nil {
		return nil, errEvaluationInvalid
	}
	evaluation.EvaluationDigest = digest
	return canonicaljson.Marshal(evaluation)
}

func ParseEvaluation(registryRaw, raw []byte) (Evaluation, error) {
	registry, err := ParseRegistry(registryRaw)
	if err != nil {
		return Evaluation{}, err
	}
	registryDigest, err := RegistryDigest(registryRaw)
	if err != nil {
		return Evaluation{}, err
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: MaxEvaluationBytes,
		MaxDepth: 16,
		MaxNodes: 16_384,
	})
	if err != nil {
		return Evaluation{}, errEvaluationInvalid
	}
	canonical, err := canonicaljson.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Evaluation{}, errEvaluationInvalid
	}
	evaluation, err := decodeEvaluation(value)
	if err != nil || evaluation.RegistryDigest != registryDigest || len(evaluation.Rows) != len(registry.Rows) {
		return Evaluation{}, errEvaluationInvalid
	}
	if err := validateSubjectAndRun(evaluation.Subject, evaluation.Run); err != nil {
		return Evaluation{}, errEvaluationInvalid
	}
	if evaluation.ArtifactType != "repopass-acceptance-evaluation" ||
		evaluation.SchemaVersion != "1" || evaluation.TrustBoundary != "producer-owned-ci" ||
		evaluation.FormalClaim {
		return Evaluation{}, errEvaluationInvalid
	}
	for index := range registry.Rows {
		if evaluation.Rows[index].ID != registry.Rows[index].ID ||
			!validRowEvaluation(registry.Rows[index], evaluation.Run, evaluation.Rows[index]) {
			return Evaluation{}, errEvaluationInvalid
		}
	}
	overall, stable := aggregateRows(evaluation.Rows)
	if evaluation.OverallStatus != overall || evaluation.StableEligible != stable {
		return Evaluation{}, errEvaluationInvalid
	}
	wantDigest, err := computeEvaluationDigest(evaluation)
	if err != nil || evaluation.EvaluationDigest != wantDigest {
		return Evaluation{}, errEvaluationInvalid
	}
	return evaluation, nil
}

func RequireComplete(registryRaw, evaluationRaw []byte) error {
	evaluation, err := ParseEvaluation(registryRaw, evaluationRaw)
	if err != nil {
		return err
	}
	if evaluation.OverallStatus != OverallPass || !evaluation.StableEligible {
		return errIncomplete
	}
	return nil
}

// RequireCompleteEvaluation validates an evaluation against the exact
// RFC-0003 registry embedded in this implementation and requires all rows to
// pass. It intentionally does not discover a registry from the filesystem.
func RequireCompleteEvaluation(evaluationRaw []byte) error {
	registryRaw, err := canonicaljson.Marshal(expectedRegistry())
	if err != nil {
		return errEvaluationInvalid
	}
	return RequireComplete(registryRaw, evaluationRaw)
}

func evaluateRow(row RegistryRow, run Run, results map[string]string) RowEvaluation {
	switch row.Evaluation.Kind {
	case "blocked":
		return RowEvaluation{Evidence: []EvidenceRecord{}, ID: row.ID, ReasonCode: row.Evaluation.ReasonCode, Status: StatusBlocked}
	case "not-run":
		return RowEvaluation{Evidence: []EvidenceRecord{}, ID: row.ID, ReasonCode: row.Evaluation.ReasonCode, Status: StatusNotRun}
	case "required-checks":
		evidence := make([]EvidenceRecord, len(row.Evaluation.RequiredChecks))
		if row.ID == "RP-B00" && (run.Event != "push" || run.Ref != "refs/heads/main") {
			for index, checkID := range row.Evaluation.RequiredChecks {
				evidence[index] = EvidenceRecord{CheckID: checkID, Result: results[checkID]}
			}
			return RowEvaluation{Evidence: evidence, ID: row.ID, ReasonCode: "NOT_DEFAULT_BRANCH", Status: StatusNotRun}
		}
		status := StatusPass
		reason := "CURRENT_REQUIRED_CHECKS_PASSED"
		for index, checkID := range row.Evaluation.RequiredChecks {
			result := results[checkID]
			evidence[index] = EvidenceRecord{CheckID: checkID, Result: result}
			switch result {
			case "failure":
				status, reason = StatusFail, "REQUIRED_CHECK_FAILED"
			case "cancelled":
				if reason != "REQUIRED_CHECK_FAILED" {
					status, reason = StatusFail, "REQUIRED_CHECK_CANCELLED"
				}
			case "skipped":
				if status != StatusFail {
					status, reason = StatusNotRun, "REQUIRED_CHECK_MISSING_OR_SKIPPED"
				}
			}
		}
		return RowEvaluation{Evidence: evidence, ID: row.ID, ReasonCode: reason, Status: status}
	default:
		return RowEvaluation{Evidence: []EvidenceRecord{}, ID: row.ID, ReasonCode: "ROADMAP_WORK_NOT_SCHEDULED", Status: StatusNotRun}
	}
}

func validRowEvaluation(row RegistryRow, run Run, got RowEvaluation) bool {
	results := make(map[string]string, len(got.Evidence))
	for index, evidence := range got.Evidence {
		if !validCheckID(evidence.CheckID) || !validCheckResult(evidence.Result) ||
			index >= len(row.Evaluation.RequiredChecks) || evidence.CheckID != row.Evaluation.RequiredChecks[index] {
			return false
		}
		results[evidence.CheckID] = evidence.Result
	}
	if row.Evaluation.Kind != "required-checks" && len(got.Evidence) != 0 {
		return false
	}
	want := evaluateRow(row, run, results)
	return rowEvaluationEqual(got, want)
}

func rowEvaluationEqual(left, right RowEvaluation) bool {
	leftRaw, leftErr := canonicaljson.Marshal(left)
	rightRaw, rightErr := canonicaljson.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func aggregateRows(rows []RowEvaluation) (OverallStatus, bool) {
	if len(rows) != 37 {
		return OverallFail, false
	}
	incomplete := false
	ids := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if _, duplicate := ids[row.ID]; duplicate {
			return OverallFail, false
		}
		ids[row.ID] = struct{}{}
		switch row.Status {
		case StatusFail:
			return OverallFail, false
		case StatusBlocked, StatusNotRun:
			incomplete = true
		case StatusPass:
		default:
			return OverallFail, false
		}
	}
	if incomplete {
		return OverallIncomplete, false
	}
	return OverallPass, true
}

func computeEvaluationDigest(evaluation Evaluation) (string, error) {
	evaluation.EvaluationDigest = ""
	type evaluationWithoutDigest struct {
		ArtifactType   string          `json:"artifactType"`
		FormalClaim    bool            `json:"formalClaim"`
		OverallStatus  OverallStatus   `json:"overallStatus"`
		RegistryDigest string          `json:"registryDigest"`
		Rows           []RowEvaluation `json:"rows"`
		Run            Run             `json:"run"`
		SchemaVersion  string          `json:"schemaVersion"`
		StableEligible bool            `json:"stableEligible"`
		Subject        Subject         `json:"subject"`
		TrustBoundary  string          `json:"trustBoundary"`
	}
	raw, err := canonicaljson.Marshal(evaluationWithoutDigest{
		ArtifactType: evaluation.ArtifactType, FormalClaim: evaluation.FormalClaim,
		OverallStatus: evaluation.OverallStatus, RegistryDigest: evaluation.RegistryDigest,
		Rows: evaluation.Rows, Run: evaluation.Run, SchemaVersion: evaluation.SchemaVersion,
		StableEligible: evaluation.StableEligible, Subject: evaluation.Subject,
		TrustBoundary: evaluation.TrustBoundary,
	})
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(evaluationDigestDomain))
	_, _ = hash.Write(raw)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func validateSubjectAndRun(subject Subject, run Run) error {
	if subject.Repository != "github.com/taipei49314/RepoPassport" ||
		!lowerHex(subject.Revision, 40) || !lowerHex(subject.TreeSHA, 40) ||
		run.Attempt < 1 || run.Attempt > 2_147_483_647 || run.ID < 1 || run.ID > 9_007_199_254_740_991 ||
		run.WorkflowPath != ".github/workflows/ci.yml" || !validEvent(run.Event) || !validRef(run.Ref) {
		return errSubjectInvalid
	}
	refProjection, err := canonicaljson.Marshal(map[string]string{"ref": run.Ref})
	if err != nil {
		return errSubjectInvalid
	}
	if _, err := privacy.Evaluate(refProjection); err != nil {
		return errSubjectInvalid
	}
	return nil
}

func validEvent(value string) bool {
	return value == "push" || value == "pull_request" || value == "workflow_dispatch"
}

func validRef(value string) bool {
	if len(value) < 6 || len(value) > 256 || !strings.HasPrefix(value, "refs/") || strings.Contains(value, "..") || strings.Contains(value, "@{") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || strings.ContainsRune(" ~^:?*[\\", character) {
			return false
		}
	}
	return true
}

func validCheckResult(value string) bool {
	return value == "success" || value == "failure" || value == "cancelled" || value == "skipped"
}

func validCheckID(value string) bool {
	return value == "ci/container-matrix" || value == "ci/go" || value == "ci/schema-json" || value == "ci/windows-go"
}

func lowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, character := range value {
		if character < '0' || (character > '9' && character < 'a') || character > 'f' {
			return false
		}
	}
	return true
}

func decodeEvaluation(value any) (Evaluation, error) {
	root, ok := value.(map[string]any)
	if !ok || !exactKeys(root, "artifactType", "evaluationDigest", "formalClaim", "overallStatus", "registryDigest", "rows", "run", "schemaVersion", "stableEligible", "subject", "trustBoundary") {
		return Evaluation{}, errEvaluationInvalid
	}
	artifactType, okArtifact := exactString(root, "artifactType")
	evaluationDigest, okDigest := exactString(root, "evaluationDigest")
	overall, okOverall := exactString(root, "overallStatus")
	registryDigest, okRegistry := exactString(root, "registryDigest")
	schemaVersion, okSchema := exactString(root, "schemaVersion")
	trust, okTrust := exactString(root, "trustBoundary")
	formal, okFormal := root["formalClaim"].(bool)
	stable, okStable := root["stableEligible"].(bool)
	if !okArtifact || !okDigest || !okOverall || !okRegistry || !okSchema || !okTrust || !okFormal || !okStable {
		return Evaluation{}, errEvaluationInvalid
	}
	subject, ok := decodeSubject(root["subject"])
	if !ok {
		return Evaluation{}, errEvaluationInvalid
	}
	run, ok := decodeRun(root["run"])
	if !ok {
		return Evaluation{}, errEvaluationInvalid
	}
	rowsValue, ok := root["rows"].([]any)
	if !ok || len(rowsValue) != 37 {
		return Evaluation{}, errEvaluationInvalid
	}
	rows := make([]RowEvaluation, len(rowsValue))
	for index, value := range rowsValue {
		row, ok := decodeRowEvaluation(value)
		if !ok {
			return Evaluation{}, errEvaluationInvalid
		}
		rows[index] = row
	}
	return Evaluation{ArtifactType: artifactType, EvaluationDigest: evaluationDigest, FormalClaim: formal, OverallStatus: OverallStatus(overall), RegistryDigest: registryDigest, Rows: rows, Run: run, SchemaVersion: schemaVersion, StableEligible: stable, Subject: subject, TrustBoundary: trust}, nil
}

func decodeSubject(value any) (Subject, bool) {
	object, ok := value.(map[string]any)
	if !ok || !exactKeys(object, "repository", "revision", "treeSHA") {
		return Subject{}, false
	}
	repository, okRepository := exactString(object, "repository")
	revision, okRevision := exactString(object, "revision")
	treeSHA, okTree := exactString(object, "treeSHA")
	return Subject{Repository: repository, Revision: revision, TreeSHA: treeSHA}, okRepository && okRevision && okTree
}

func decodeRun(value any) (Run, bool) {
	object, ok := value.(map[string]any)
	if !ok || !exactKeys(object, "attempt", "event", "id", "ref", "workflowPath") {
		return Run{}, false
	}
	attempt, okAttempt := exactInt64(object["attempt"])
	id, okID := exactInt64(object["id"])
	event, okEvent := exactString(object, "event")
	ref, okRef := exactString(object, "ref")
	workflow, okWorkflow := exactString(object, "workflowPath")
	return Run{Attempt: attempt, Event: event, ID: id, Ref: ref, WorkflowPath: workflow}, okAttempt && okID && okEvent && okRef && okWorkflow
}

func exactInt64(value any) (int64, bool) {
	number, ok := value.(string)
	if ok {
		parsed, err := strconv.ParseInt(number, 10, 64)
		return parsed, err == nil
	}
	if raw, ok := value.(interface{ String() string }); ok {
		parsed, err := strconv.ParseInt(raw.String(), 10, 64)
		return parsed, err == nil
	}
	return 0, false
}

func decodeRowEvaluation(value any) (RowEvaluation, bool) {
	object, ok := value.(map[string]any)
	if !ok || !exactKeys(object, "evidence", "id", "reasonCode", "status") {
		return RowEvaluation{}, false
	}
	id, okID := exactString(object, "id")
	reason, okReason := exactString(object, "reasonCode")
	status, okStatus := exactString(object, "status")
	evidenceValues, okEvidence := object["evidence"].([]any)
	if !okID || !okReason || !okStatus || !okEvidence || len(evidenceValues) > 4 {
		return RowEvaluation{}, false
	}
	evidence := make([]EvidenceRecord, len(evidenceValues))
	for index, raw := range evidenceValues {
		item, ok := raw.(map[string]any)
		if !ok || !exactKeys(item, "checkId", "result") {
			return RowEvaluation{}, false
		}
		checkID, okCheck := exactString(item, "checkId")
		result, okResult := exactString(item, "result")
		if !okCheck || !okResult {
			return RowEvaluation{}, false
		}
		evidence[index] = EvidenceRecord{CheckID: checkID, Result: result}
	}
	return RowEvaluation{Evidence: evidence, ID: id, ReasonCode: reason, Status: RowStatus(status)}, true
}
