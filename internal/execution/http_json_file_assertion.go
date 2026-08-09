package execution

import (
	"context"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

func (r *Runner) inspectHTTPJSONFileAssertion(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	assertion domain.PlanAssertion,
) domain.AssertionResult {
	return r.inspectHTTPJSONFileAssertionWithStart(
		ctx,
		prepared,
		containerName,
		assertion,
		nil,
	)
}

func (r *Runner) inspectHTTPJSONFileAssertionWithStart(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	assertion domain.PlanAssertion,
	onStart func(),
) domain.AssertionResult {
	result := domain.AssertionResult{
		SchemaVersion: "1",
		ID:            assertion.ID,
		Type:          "json-file",
		Required:      true,
		Status:        "inconclusive",
		EvidenceRefs: []string{
			"http-assertion:" + assertion.ID + ":json-file-snapshot",
		},
		Message: "Controller could not establish a trusted ordered JSON file assertion result.",
	}
	if assertion.JSONFile == nil {
		result.Status = "blocked"
		result.Message = "Resolved HTTP assertion has no JSON file operation."
		return result
	}
	spec := assertion.JSONFile
	result.Expected = map[string]any{
		"path": spec.Path,
		"schema": map[string]any{
			"path":    spec.Schema.Path,
			"digest":  spec.Schema.Digest,
			"dialect": spec.Schema.Dialect,
		},
	}
	result.EvidenceRefs = append(
		result.EvidenceRefs,
		"json-schema:"+spec.Schema.Digest,
	)
	startedAt := r.now()
	snapshot, err := r.readHTTPOutputJSONFileWithStart(
		ctx,
		prepared,
		containerName,
		spec.Path,
		onStart,
	)
	result.DurationMillis = r.now().Sub(startedAt).Milliseconds()
	if err != nil {
		failure := httpJSONFileReadFailureOf(err)
		result.Actual = map[string]any{
			"path":    spec.Path,
			"failure": string(failure),
		}
		switch failure {
		case httpJSONFileInvalidPath, httpJSONFileUnsupportedRuntime:
			result.Status = "blocked"
			result.Message = "Resolved HTTP JSON file assertion could not be executed safely."
		case httpJSONFileMissing:
			result.Status = "failed"
			result.Message = "Declared ordered JSON output file was missing."
		case httpJSONFileSymlink:
			result.Status = "failed"
			result.Message = "A symbolic link cannot satisfy an ordered JSON file assertion."
		case httpJSONFileDirectory:
			result.Status = "failed"
			result.Message = "A directory cannot satisfy an ordered JSON file assertion."
		case httpJSONFileSpecial:
			result.Status = "failed"
			result.Message = "A special file cannot satisfy an ordered JSON file assertion."
		case httpJSONFileTooLarge:
			result.Status = "failed"
			result.Message = "Declared ordered JSON output file exceeded the 1 MiB profile limit."
		default:
			result.Status = "inconclusive"
			result.Message = "Trusted ordered JSON file snapshot could not be established."
		}
		return result
	}

	actual := map[string]any{
		"path":   spec.Path,
		"bytes":  snapshot.size,
		"sha256": snapshot.sha256,
	}
	document, decodeErr := structuredjson.Decode(
		snapshot.content,
		structuredjson.DefaultInstanceDecodeLimits(),
	)
	if decodeErr != nil {
		actual["strictJSON"] = false
		actual["failure"] = string(structuredjson.KindOf(decodeErr))
		result.Actual = actual
		result.Status = "failed"
		result.Message = "Trusted ordered output snapshot is not bounded strict JSON."
		return result
	}
	actual["strictJSON"] = true
	schema, available := prepared.structuredJSONSchema(spec.Schema)
	if !available {
		actual["jsonSchemaEvaluated"] = false
		result.Actual = actual
		result.Status = "blocked"
		result.Message = "Plan-bound JSON Schema was unavailable to the controller."
		return result
	}
	if validateErr := schema.Validate(document); validateErr != nil {
		actual["jsonSchemaMatched"] = false
		actual["failure"] = string(structuredjson.KindOf(validateErr))
		result.Actual = actual
		if structuredjson.KindOf(validateErr) ==
			structuredjson.ErrorSchemaNotSatisfied {
			result.Status = "failed"
			result.Message = "Trusted ordered JSON file did not satisfy the plan-bound schema."
		} else {
			result.Status = "inconclusive"
			result.Message = "Controller-owned JSON Schema evaluation could not complete."
		}
		return result
	}
	actual["jsonSchemaMatched"] = true
	result.Actual = actual
	result.Status = "passed"
	result.Message = "Trusted point-in-time JSON file snapshot satisfied the plan-bound schema."
	return result
}
