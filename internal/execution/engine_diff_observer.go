package execution

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

const engineDiffControlLimit = 4 << 20

type engineDiffCommitment struct {
	Digest    string
	ByteCount int
	NonEmpty  bool
}

type engineDiffObservationState struct {
	required                   bool
	containerID                string
	baseline                   engineDiffCommitment
	baselineReady              bool
	baselineIdentityVerified   bool
	baselineFailure            string
	final                      engineDiffCommitment
	finalReady                 bool
	finalIdentityVerified      bool
	finalFailure               string
	workloadQuiescenceVerified bool
	observedAt                 time.Time
}

func (r *Runner) collectDockerEngineDiff(
	ctx context.Context,
	prepared *PreparedRun,
	containerID string,
) (engineDiffCommitment, error) {
	if prepared == nil || prepared.Backend != "docker" {
		return engineDiffCommitment{}, errors.New(
			"engine filesystem diff is supported only by the Docker backend",
		)
	}
	if !fullContainerIDPattern.MatchString(containerID) {
		return engineDiffCommitment{}, errors.New(
			"engine filesystem diff has no immutable container ID",
		)
	}
	stdout := &cappedBuffer{limit: engineDiffControlLimit}
	stderr := &cappedBuffer{limit: engineDiffControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		"docker",
		[]string{"container", "diff", containerID},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 || stdout.truncated ||
		stderr.truncated || len(stderr.Bytes()) != 0 {
		return engineDiffCommitment{}, errors.New(
			"Docker engine filesystem diff did not complete cleanly",
		)
	}
	return commitDockerEngineDiff(stdout.Bytes()), nil
}

func commitDockerEngineDiff(raw []byte) engineDiffCommitment {
	digest := sha256.Sum256(raw)
	return engineDiffCommitment{
		Digest:    fmt.Sprintf("sha256:%x", digest),
		ByteCount: len(raw),
		NonEmpty:  len(raw) != 0,
	}
}

func summarizeDockerEngineDiff(
	state engineDiffObservationState,
	containerName string,
	completedAt time.Time,
) (domain.ObservationEvent, string) {
	if !state.required {
		return domain.ObservationEvent{}, coverageUnavailable
	}
	coverage := coverageUnavailable
	result := "unavailable"
	confidence := "unknown"
	if state.finalReady && state.finalIdentityVerified &&
		state.workloadQuiescenceVerified {
		coverage = coverageBestEffort
		result = "observed"
		confidence = "high"
	}
	timestamp := state.observedAt
	if timestamp.IsZero() {
		timestamp = completedAt
	}
	details := map[string]any{
		"scope":                       "docker-engine-filesystem-diff",
		"snapshotBoundary":            "image-to-post-quiesce-pre-repair",
		"engineSemantics":             "changes-since-container-create",
		"opaqueTranscript":            true,
		"transcriptParsed":            false,
		"baselineDiagnosticOnly":      true,
		"includesPreWorkloadChanges":  true,
		"includesTrustedObserverWork": true,
		"contentIncluded":             false,
		"pathsIncluded":               false,
		"publicEvidence":              "aggregate-only",
		"actorAttribution":            "unavailable",
		"baselineIdentityVerified":    state.baselineIdentityVerified,
		"finalIdentityVerified":       state.finalIdentityVerified,
		"workloadQuiescenceVerified":  state.workloadQuiescenceVerified,
		"baselineReady":               state.baselineReady,
		"finalReady":                  state.finalReady,
		"engineDiffCoverage":          coverage,
		"mountedFilesystemCoverage":   "unavailable",
		"operationHistoryCoverage":    "unavailable",
		"pathClassificationAvailable": false,
		"blindSpots": []string{
			"outputs-tmpfs",
			"bind-and-other-mounts",
			"transient-create-delete",
			"write-then-restore",
			"same-classification-rewrite",
			"ambiguous-cli-path-records",
			"content-and-metadata-details",
			"operation-time",
			"process-phase-attribution",
			"rename-vs-delete-create",
			"non-docker-backends",
		},
	}
	if state.baselineReady {
		details["baselineDigest"] = state.baseline.Digest
		details["baselineByteCount"] = state.baseline.ByteCount
		details["baselineNonEmpty"] = state.baseline.NonEmpty
	}
	if coverage == coverageBestEffort {
		details["finalDigest"] = state.final.Digest
		details["finalByteCount"] = state.final.ByteCount
		details["finalNonEmpty"] = state.final.NonEmpty
		if state.baselineReady {
			details["transcriptChangedFromBaseline"] =
				state.baseline.Digest != state.final.Digest
		}
	}
	if state.baselineFailure != "" {
		details["baselineFailure"] = state.baselineFailure
	}
	if state.finalFailure != "" {
		details["failure"] = state.finalFailure
	}
	return domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "filesystem.engine-diff.summary",
		Resource:      containerName,
		Result:        result,
		Observer:      "docker-container-diff",
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       details,
	}, coverage
}

func combineFilesystemWriteCoverage(
	componentCoverages ...string,
) string {
	for _, coverage := range componentCoverages {
		if coverage == coverageBestEffort {
			return coverageBestEffort
		}
	}
	return coverageUnavailable
}
