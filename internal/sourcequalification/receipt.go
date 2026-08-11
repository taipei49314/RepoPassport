// Package sourcequalification implements the frozen RFC-0002 source
// qualification contracts.
package sourcequalification

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	canonicalWorkflowRepository = "taipei49314/RepoPassport"
	canonicalWorkflowPath       = ".github/workflows/source-qualification.yml"
	canonicalMainRef            = "refs/heads/main"

	StatusPass    QualificationStatus = "PASS"
	StatusFail    QualificationStatus = "FAIL"
	StatusBlocked QualificationStatus = "BLOCKED"
	StatusNotRun  QualificationStatus = "NOT_RUN"

	LaneLinuxAMD64   Lane = "linux-amd64"
	LaneWindowsAMD64 Lane = "windows-amd64"
)

type QualificationStatus string

type Lane string

type RunIdentity struct {
	WorkflowRepository string
	WorkflowPath       string
	Event              string
	Ref                string
	WorkflowRunID      string
	WorkflowRunAttempt int
	TestedRevision     string
}

var receiptTopLevelKeys = []string{
	"artifactType",
	"attempt",
	"controller",
	"execution",
	"gates",
	"limitations",
	"notApplicable",
	"platform",
	"predicateType",
	"productDimensions",
	"qualificationStatus",
	"run",
	"schemaVersion",
	"source",
	"subject",
}

var fixedLimitations = []string{
	"currentness-requires-live-caller-input",
	"gate-execution-is-self-ci",
	"github-artifact-is-untrusted-transport",
	"lfs-pointers-not-resolved",
	"network-service-state-is-not-bound",
	"no-external-review",
	"no-publisher-or-workflow-identity",
	"no-signature-transparency-trusted-time-or-revocation",
	"product-verdicts-not-evaluated",
	"rp-m0-qual-only",
	"stable-release-not-authorized",
}

func ReceiptTopLevelKeys() []string {
	return append([]string(nil), receiptTopLevelKeys...)
}

func FixedLimitations() []string {
	return append([]string(nil), fixedLimitations...)
}

func AggregateQualificationStatus(statuses []QualificationStatus) QualificationStatus {
	result := StatusPass
	for _, status := range statuses {
		switch status {
		case StatusFail:
			return StatusFail
		case StatusBlocked:
			if result != StatusFail {
				result = StatusBlocked
			}
		case StatusNotRun:
			if result == StatusPass {
				result = StatusNotRun
			}
		case StatusPass:
		default:
			return StatusFail
		}
	}
	return result
}

func QualificationRunID(run RunIdentity) string {
	parts := []string{
		"github-actions",
		run.WorkflowRepository,
		run.WorkflowPath,
		run.Event,
		run.Ref,
		run.WorkflowRunID,
		strconv.Itoa(run.WorkflowRunAttempt),
		run.TestedRevision,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func AttemptID(qualificationRunID string, lane Lane, ordinal int) string {
	return qualificationRunID + ":" + string(lane) + ":" + strconv.Itoa(ordinal)
}

func ClosingAttemptEligible(run RunIdentity, ordinal int) bool {
	return run.WorkflowRepository == canonicalWorkflowRepository &&
		run.WorkflowPath == canonicalWorkflowPath &&
		run.Event == "push" &&
		run.Ref == canonicalMainRef &&
		run.WorkflowRunAttempt == 1 &&
		ordinal == 1
}
