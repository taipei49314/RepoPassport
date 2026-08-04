package execution

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

var assertionIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func evaluateJourneyAssertions(
	prepared *PreparedRun,
	steps []StepResult,
) []domain.AssertionResult {
	results := make(
		[]domain.AssertionResult,
		0,
		len(prepared.executionPlan.JourneyAssertions),
	)
	journey, journeyIndex := journeyStep(steps)
	for _, assertion := range prepared.executionPlan.JourneyAssertions {
		result := domain.AssertionResult{
			SchemaVersion: "1",
			ID:            assertion.ID,
			Required:      true,
			Status:        "blocked",
			EvidenceRefs:  []string{},
			Message:       "Journey command did not produce assertion input.",
		}
		if journey != nil {
			result.DurationMillis = journey.Duration.Milliseconds()
			result.EvidenceRefs = []string{fmt.Sprintf("step:%03d", journeyIndex+1)}
		}

		switch {
		case assertion.ExitCode != nil:
			result.Type = "exit-code"
			result.Expected = *assertion.ExitCode
			if journey == nil || journey.ExitCode < 0 {
				result.Actual = nil
				if journey != nil {
					result.Status = "inconclusive"
				}
				break
			}
			result.Actual = journey.ExitCode
			if journey.ExitCode == *assertion.ExitCode {
				result.Status = "passed"
				result.Message = "Trusted runner observed the expected exit code."
			} else {
				result.Status = "failed"
				result.Message = "Trusted runner observed a different exit code."
			}
		case assertion.StdoutContains != "":
			result.Type = "stdout-contains"
			result.Expected = assertion.StdoutContains
			if journey == nil {
				result.Actual = false
				break
			}
			matched := strings.Contains(string(journey.Stdout), assertion.StdoutContains)
			result.Actual = matched
			setStreamAssertionStatus(&result, matched, journey.LogTruncated)
		case assertion.StderrContains != "":
			result.Type = "stderr-contains"
			result.Expected = assertion.StderrContains
			if journey == nil {
				result.Actual = false
				break
			}
			matched := strings.Contains(string(journey.Stderr), assertion.StderrContains)
			result.Actual = matched
			setStreamAssertionStatus(&result, matched, journey.LogTruncated)
		case assertion.StdoutRegex != "":
			result.Type = "stdout-regex"
			result.Expected = assertion.StdoutRegex
			if journey == nil {
				result.Actual = false
				break
			}
			expression, err := regexp.Compile(assertion.StdoutRegex)
			if err != nil {
				result.Status = "blocked"
				result.Actual = false
				result.Message = "Resolved stdout regex is invalid."
				break
			}
			matched := expression.Match(journey.Stdout)
			result.Actual = matched
			setStreamAssertionStatus(&result, matched, journey.LogTruncated)
		case assertion.StdoutJSONSchema != nil:
			result = evaluateStdoutJSONSchemaAssertion(
				prepared,
				assertion.ID,
				*assertion.StdoutJSONSchema,
				journey,
				journeyIndex,
			)
		case assertion.FileExists != "":
			result = evaluateFileExistsAssertion(
				prepared,
				assertion.ID,
				assertion.FileExists,
			)
		default:
			result.Type = "exit-code"
			result.Expected = nil
			result.Actual = nil
			result.Status = "blocked"
			result.Message = "Resolved assertion has no supported operation."
		}
		results = append(results, result)
	}
	return results
}

func evaluateStdoutJSONSchemaAssertion(
	prepared *PreparedRun,
	assertionID string,
	reference domain.PlanJSONSchemaRef,
	journey *StepResult,
	journeyIndex int,
) domain.AssertionResult {
	result := domain.AssertionResult{
		SchemaVersion: "1",
		ID:            assertionID,
		Type:          "stdout-json-schema",
		Required:      true,
		Expected: map[string]any{
			"path":             reference.Path,
			"digest":           reference.Digest,
			"dialect":          reference.Dialect,
			"validatorVersion": reference.ValidatorVersion,
		},
		Actual: map[string]any{
			"failure": "journey-unavailable",
		},
		Status:       "blocked",
		EvidenceRefs: []string{"json-schema:" + reference.Digest},
		Message:      "Journey command did not produce complete stdout for schema evaluation.",
	}
	if journey == nil {
		return result
	}

	result.DurationMillis = journey.Duration.Milliseconds()
	result.EvidenceRefs = []string{
		fmt.Sprintf("step:%03d", journeyIndex+1),
		"json-schema:" + reference.Digest,
	}
	if journey.LogTruncated {
		result.Status = "inconclusive"
		result.Actual = map[string]any{
			"stdoutComplete": false,
			"failure":        "log-capture-truncated",
		}
		result.Message = "Shared bounded log capture was incomplete, so complete stdout could not be established."
		return result
	}

	actual := map[string]any{"stdoutComplete": true}
	document, decodeErr := structuredjson.Decode(
		journey.Stdout,
		structuredjson.DefaultInstanceDecodeLimits(),
	)
	if decodeErr != nil {
		actual["strictJSON"] = false
		failure := "strict-json-invalid"
		if kind := structuredjson.KindOf(decodeErr); kind != "" {
			failure = string(kind)
		}
		actual["failure"] = failure
		result.Actual = actual
		result.Status = "failed"
		result.Message = "Trusted complete stdout is not bounded strict JSON."
		return result
	}
	actual["strictJSON"] = true

	schema, available := prepared.structuredJSONSchema(reference)
	if !available {
		actual["failure"] = "schema-binding-unavailable"
		result.Actual = actual
		result.Status = "blocked"
		result.Message = "Plan-bound JSON Schema was unavailable to the controller."
		return result
	}
	if validateErr := schema.Validate(document); validateErr != nil {
		actual["jsonSchemaMatched"] = false
		if structuredjson.KindOf(validateErr) ==
			structuredjson.ErrorSchemaNotSatisfied {
			actual["failure"] = "schema-not-satisfied"
			result.Actual = actual
			result.Status = "failed"
			result.Message = "Trusted complete stdout did not satisfy the plan-bound schema."
			return result
		}
		actual["failure"] = "schema-evaluation-incomplete"
		result.Actual = actual
		result.Status = "inconclusive"
		result.Message = "Controller-owned JSON Schema evaluation could not complete."
		return result
	}

	actual["jsonSchemaMatched"] = true
	result.Actual = actual
	result.Status = "passed"
	result.Message = "Trusted complete stdout satisfied the plan-bound schema."
	return result
}

func evaluateFileExistsAssertion(
	prepared *PreparedRun,
	assertionID string,
	sandboxPath string,
) domain.AssertionResult {
	result := domain.AssertionResult{
		SchemaVersion: "1",
		ID:            assertionID,
		Type:          "file-exists",
		Required:      true,
		Expected:      true,
		Actual:        false,
		Status:        "blocked",
		EvidenceRefs:  []string{"run:" + prepared.RunID + ":filesystem"},
	}
	hostPath, err := hostPathForAssertion(prepared, sandboxPath)
	if err != nil {
		result.Status = "inconclusive"
		result.Message = "Resolved assertion path could not be inspected without crossing a trust boundary."
		return result
	}
	info, statErr := os.Lstat(hostPath)
	switch {
	case statErr == nil && info.Mode()&os.ModeSymlink == 0:
		result.Status = "passed"
		result.Actual = true
		result.Message = "Trusted runner observed the declared file-system entry."
	case statErr == nil:
		result.Status = "failed"
		result.Message = "Symbolic links do not satisfy file-exists assertions."
	case errors.Is(statErr, os.ErrNotExist):
		result.Status = "failed"
		result.Message = "Trusted runner did not observe the declared file-system entry."
	default:
		result.Status = "inconclusive"
		result.Message = "Trusted runner could not inspect the declared file-system entry."
	}
	return result
}

func journeyStep(steps []StepResult) (*StepResult, int) {
	for index := len(steps) - 1; index >= 0; index-- {
		if steps[index].Role == "journey" {
			return &steps[index], index
		}
	}
	return nil, -1
}

func setStreamAssertionStatus(
	result *domain.AssertionResult,
	matched bool,
	truncated bool,
) {
	switch {
	case matched:
		result.Status = "passed"
		result.Message = "Trusted bounded output matched the declared assertion."
	case truncated:
		result.Status = "inconclusive"
		result.Message = "Bounded output was truncated before absence could be established."
	default:
		result.Status = "failed"
		result.Message = "Trusted bounded output did not match the declared assertion."
	}
}

func hostPathForAssertion(prepared *PreparedRun, sandboxPath string) (string, error) {
	if !path.IsAbs(sandboxPath) || path.Clean(sandboxPath) != sandboxPath {
		return "", errors.New("assertion path is not normalized")
	}
	type mapping struct {
		container string
		host      string
	}
	mappings := []mapping{
		{container: containerOutputs, host: prepared.OutputsDir},
		{container: containerWorkspace, host: prepared.WorkspaceDir},
		{container: containerSource, host: prepared.SourceSnapshotDir},
	}
	for _, input := range prepared.Inputs {
		mappings = append(mappings, mapping{
			container: input.ContainerPath,
			host:      input.SourcePath,
		})
	}
	for _, candidate := range mappings {
		if sandboxPath != candidate.container &&
			!strings.HasPrefix(sandboxPath, strings.TrimSuffix(candidate.container, "/")+"/") {
			continue
		}
		relative := strings.TrimPrefix(sandboxPath, candidate.container)
		relative = strings.TrimPrefix(relative, "/")
		hostPath := filepath.Join(candidate.host, filepath.FromSlash(relative))
		if !pathWithin(candidate.host, hostPath) {
			return "", errors.New("assertion path escaped mount")
		}
		if err := rejectSymlinkPath(candidate.host, hostPath); err != nil {
			return "", err
		}
		return hostPath, nil
	}
	return "", errors.New("assertion path is outside runner-owned mounts")
}

func rejectSymlinkPath(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(relative) ||
		relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("assertion path escaped mount")
	}
	current := root
	segments := []string{}
	if relative != "." {
		segments = strings.Split(relative, string(filepath.Separator))
	}
	for _, segment := range segments {
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("assertion path traverses a symbolic link or reparse point")
		}
	}
	if resolved, evalErr := filepath.EvalSymlinks(target); evalErr == nil {
		if !samePath(resolved, target) || !pathWithin(root, resolved) {
			return errors.New("assertion path resolves outside its runner-owned mount")
		}
	}
	return nil
}

func assertionFailure(assertions []domain.AssertionResult) *domain.Error {
	for _, assertion := range assertions {
		if assertion.Status == "failed" {
			err := domain.NewError(
				domain.CodeJourneyAssertionFailed,
				domain.SeverityHigh,
				"One or more required journey assertions failed.",
			)
			err.EvidenceRefs = cloneStrings(assertion.EvidenceRefs)
			err.Details = map[string]any{"assertionId": assertion.ID}
			return err
		}
	}
	for _, assertion := range assertions {
		if assertion.Status == "blocked" || assertion.Status == "inconclusive" {
			err := domain.NewError(
				domain.CodeObserverIncomplete,
				domain.SeverityHigh,
				"One or more required journey assertions are inconclusive.",
			)
			err.EvidenceRefs = cloneStrings(assertion.EvidenceRefs)
			err.Details = map[string]any{"assertionId": assertion.ID}
			return err
		}
	}
	return nil
}
