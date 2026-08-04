package domain

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable public identifier. Messages may improve over time, but
// codes are part of the CLI and JSON compatibility contract.
type ErrorCode string

const (
	CodeSourceNotFound            ErrorCode = "SOURCE_NOT_FOUND"
	CodeSourceTooLarge            ErrorCode = "SOURCE_TOO_LARGE"
	CodeSourceTooManyFiles        ErrorCode = "SOURCE_TOO_MANY_FILES"
	CodeSourcePathTraversal       ErrorCode = "SOURCE_PATH_TRAVERSAL"
	CodeSourceSymlinkEscape       ErrorCode = "SOURCE_SYMLINK_ESCAPE"
	CodeSourceRefUnresolved       ErrorCode = "SOURCE_REF_UNRESOLVED"
	CodeSourceDigestMismatch      ErrorCode = "SOURCE_DIGEST_MISMATCH"
	CodeManifestNotFound          ErrorCode = "MANIFEST_NOT_FOUND"
	CodeManifestInvalid           ErrorCode = "MANIFEST_INVALID"
	CodeManifestUnknownField      ErrorCode = "MANIFEST_UNKNOWN_FIELD"
	CodeManifestLiteralSecret     ErrorCode = "MANIFEST_LITERAL_SECRET"
	CodeManifestUnsafeShell       ErrorCode = "MANIFEST_UNSAFE_SHELL"
	CodePlanUnresolved            ErrorCode = "PLAN_UNRESOLVED"
	CodePlanDrift                 ErrorCode = "PLAN_DRIFT"
	CodeMutableBaseImage          ErrorCode = "MUTABLE_BASE_IMAGE"
	CodeRuntimeVersionUnresolved  ErrorCode = "RUNTIME_VERSION_UNRESOLVED"
	CodePolicyBundleUnresolved    ErrorCode = "POLICY_BUNDLE_UNRESOLVED"
	CodeRunnerUnavailable         ErrorCode = "RUNNER_UNAVAILABLE"
	CodeRunnerFeatureUnavailable  ErrorCode = "RUNNER_FEATURE_UNAVAILABLE"
	CodeSandboxPrepareFailed      ErrorCode = "SANDBOX_PREPARE_FAILED"
	CodeSandboxStartFailed        ErrorCode = "SANDBOX_START_FAILED"
	CodeSandboxDestroyFailed      ErrorCode = "SANDBOX_DESTROY_FAILED"
	CodeResourceLimitExceeded     ErrorCode = "RESOURCE_LIMIT_EXCEEDED"
	CodeTimeout                   ErrorCode = "TIMEOUT"
	CodeSetupFailed               ErrorCode = "SETUP_FAILED"
	CodeBuildFailed               ErrorCode = "BUILD_FAILED"
	CodeServiceStartFailed        ErrorCode = "SERVICE_START_FAILED"
	CodeReadinessFailed           ErrorCode = "READINESS_FAILED"
	CodeJourneyAssertionFailed    ErrorCode = "JOURNEY_ASSERTION_FAILED"
	CodeCleanupFailed             ErrorCode = "CLEANUP_FAILED"
	CodeProcessLeak               ErrorCode = "PROCESS_LEAK"
	CodeUndeclaredFilesystemWrite ErrorCode = "UNDECLARED_FILESYSTEM_WRITE"
	CodeForbiddenFilesystemAccess ErrorCode = "FORBIDDEN_FILESYSTEM_ACCESS"
	CodeUndeclaredNetwork         ErrorCode = "UNDECLARED_NETWORK_DESTINATION"
	CodeForbiddenNetworkAttempt   ErrorCode = "FORBIDDEN_NETWORK_ATTEMPT"
	CodeUndeclaredPortListen      ErrorCode = "UNDECLARED_PORT_LISTEN"
	CodeUndeclaredProcessExec     ErrorCode = "UNDECLARED_PROCESS_EXEC"
	CodeCleanupResidue            ErrorCode = "CLEANUP_RESIDUE"
	CodeObserverStartFailed       ErrorCode = "OBSERVER_START_FAILED"
	CodeObserverIncomplete        ErrorCode = "OBSERVER_INCOMPLETE"
	CodeObservationSchemaInvalid  ErrorCode = "OBSERVATION_SCHEMA_INVALID"
	CodeNondeterministicResult    ErrorCode = "NONDETERMINISTIC_RESULT"
	CodeEvidenceBuildFailed       ErrorCode = "EVIDENCE_BUILD_FAILED"
	CodeEvidenceDigestMismatch    ErrorCode = "EVIDENCE_DIGEST_MISMATCH"
	CodeEvidencePrivacyBlocked    ErrorCode = "EVIDENCE_PRIVACY_BLOCKED"
	CodeAttestationInvalid        ErrorCode = "ATTESTATION_INVALID"
	CodeAttestationUntrusted      ErrorCode = "ATTESTATION_UNTRUSTED"
	CodeEvidenceStale             ErrorCode = "EVIDENCE_STALE"
	CodeSigningFailed             ErrorCode = "SIGNING_FAILED"
	CodePolicyDenied              ErrorCode = "POLICY_DENIED"
	CodePolicyEvaluationFailed    ErrorCode = "POLICY_EVALUATION_FAILED"
	CodeInternal                  ErrorCode = "INTERNAL_ERROR"
	CodeCancelled                 ErrorCode = "CANCELLED"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Error is safe for structured output. Cause is never serialized and may
// contain local implementation details.
type Error struct {
	SchemaVersion string         `json:"schemaVersion" yaml:"schemaVersion"`
	Code          ErrorCode      `json:"code" yaml:"code"`
	Phase         Phase          `json:"phase,omitempty" yaml:"phase,omitempty"`
	Severity      Severity       `json:"severity" yaml:"severity"`
	Message       string         `json:"message" yaml:"message"`
	Details       map[string]any `json:"details,omitempty" yaml:"details,omitempty"`
	EvidenceRefs  []string       `json:"evidenceRefs" yaml:"evidenceRefs"`
	Suggestion    string         `json:"suggestion,omitempty" yaml:"suggestion,omitempty"`
	Retryable     bool           `json:"retryable" yaml:"retryable"`
	Cause         error          `json:"-" yaml:"-"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Phase != "" {
		return fmt.Sprintf("%s (%s): %s", e.Code, e.Phase, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

func NewError(code ErrorCode, severity Severity, message string) *Error {
	return &Error{
		SchemaVersion: "1",
		Code:          code,
		Severity:      severity,
		Message:       message,
		EvidenceRefs:  []string{},
	}
}

func WrapError(code ErrorCode, severity Severity, message string, cause error) *Error {
	return &Error{
		SchemaVersion: "1",
		Code:          code,
		Severity:      severity,
		Message:       message,
		EvidenceRefs:  []string{},
		Cause:         cause,
	}
}

func ErrorCodeOf(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return CodeInternal
}
