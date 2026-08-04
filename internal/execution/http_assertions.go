package execution

import (
	"strings"

	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

type httpExchange struct {
	Request  trustedHTTPRequest
	Response trustedHTTPResponse
}

func evaluateHTTPJourneyAssertions(
	prepared *PreparedRun,
	assertionResults map[string]domain.AssertionResult,
) []domain.AssertionResult {
	if prepared.executionPlan.HTTPJourney == nil {
		return []domain.AssertionResult{}
	}
	assertions := make(
		map[string]domain.PlanAssertion,
		len(prepared.executionPlan.JourneyAssertions),
	)
	for _, assertion := range prepared.executionPlan.JourneyAssertions {
		assertions[assertion.ID] = assertion
	}
	results := make(
		[]domain.AssertionResult,
		0,
		len(prepared.executionPlan.JourneyAssertions),
	)
	for _, step := range prepared.executionPlan.HTTPJourney.Steps {
		if step.AssertionID == "" {
			continue
		}
		assertion, ok := assertions[step.AssertionID]
		if !ok {
			continue
		}
		switch {
		case assertion.Response != nil:
			if snapshot, exists := assertionResults[assertion.ID]; exists {
				results = append(results, snapshot)
			} else {
				results = append(
					results,
					blockedOrderedHTTPAssertion(
						assertion.ID,
						"http-response",
					),
				)
			}
		case assertion.FileExists != "", assertion.JSONFile != nil:
			if snapshot, exists := assertionResults[assertion.ID]; exists {
				results = append(results, snapshot)
			} else {
				assertionType := "file-exists"
				if assertion.JSONFile != nil {
					assertionType = "json-file"
				}
				results = append(
					results,
					blockedOrderedHTTPAssertion(
						assertion.ID,
						assertionType,
					),
				)
			}
		}
	}
	if results == nil {
		return []domain.AssertionResult{}
	}
	return results
}

func blockedOrderedHTTPAssertion(
	id string,
	assertionType string,
) domain.AssertionResult {
	return domain.AssertionResult{
		SchemaVersion: "1",
		ID:            id,
		Type:          assertionType,
		Required:      true,
		Expected:      nil,
		Actual:        nil,
		Status:        "blocked",
		EvidenceRefs:  []string{},
		Message:       "Ordered HTTP assertion step was not reached.",
	}
}

func evaluateHTTPResponseAssertion(
	prepared *PreparedRun,
	assertion domain.PlanAssertion,
	exchanges map[string]httpExchange,
) domain.AssertionResult {
	spec := assertion.Response
	result := domain.AssertionResult{
		SchemaVersion: "1",
		ID:            assertion.ID,
		Type:          "http-response",
		Required:      true,
		Status:        "blocked",
		EvidenceRefs:  []string{},
		Message:       "The referenced HTTP request did not produce a trusted response.",
	}
	if spec == nil {
		result.Message = "Resolved HTTP assertion has no response operation."
		return result
	}
	result.EvidenceRefs = []string{"http-request:" + spec.RequestID}
	expected := map[string]any{"requestId": spec.RequestID}
	actual := map[string]any{"requestId": spec.RequestID}
	exchange, ok := exchanges[spec.RequestID]
	if !ok {
		result.Expected = expected
		result.Actual = actual
		return result
	}
	result.DurationMillis = exchange.Response.DurationMillis
	status := "passed"
	message := "Trusted bounded HTTP response matched every declared predicate."
	if spec.Status != nil {
		expected["status"] = *spec.Status
		actual["status"] = exchange.Response.Status
		if exchange.Response.Status != *spec.Status {
			status = "failed"
			message = "Trusted HTTP response status did not match."
		}
	}
	if spec.Header != nil {
		expected["header"] = map[string]any{
			"name": spec.Header.Name, "contains": spec.Header.Contains,
		}
		headerMatched := false
		for _, header := range exchange.Response.Headers {
			if strings.EqualFold(header.Name, spec.Header.Name) &&
				strings.Contains(header.Value, spec.Header.Contains) {
				headerMatched = true
				break
			}
		}
		actual["headerMatched"] = headerMatched
		if !headerMatched {
			status = "failed"
			message = "Trusted HTTP response headers did not match."
		}
	}
	if spec.BodyContains != nil {
		// The repository-controlled substring remains private. The sealed plan
		// digest binds the predicate while public assertion evidence exposes only
		// fixed metadata about whether the check was configured.
		expected["substringCheck"] = map[string]any{
			"configured":     true,
			"valuePublished": false,
		}
		bodyMatched := strings.Contains(
			string(exchange.Response.Body),
			*spec.BodyContains,
		)
		actual["bodyContainsMatched"] = bodyMatched
		actual["bodyTruncated"] = exchange.Response.BodyTruncated
		switch {
		case bodyMatched:
		case exchange.Response.BodyTruncated && status != "failed":
			status = "inconclusive"
			message = "Bounded HTTP body was truncated before absence could be established."
		default:
			status = "failed"
			message = "Trusted bounded HTTP response body did not match."
		}
	}
	if spec.JSONPath != nil || spec.JSONSchema != nil {
		switch {
		case exchange.Response.BodyTruncated:
			actual["structuredJSONBodyTruncated"] = true
			if status != "failed" {
				status = "inconclusive"
				message = "Bounded HTTP body was truncated before structured JSON assertions could be evaluated."
			}
		default:
			document, decodeErr := structuredjson.Decode(
				exchange.Response.Body,
				structuredjson.DefaultInstanceDecodeLimits(),
			)
			if decodeErr != nil {
				actual["structuredJSONValid"] = false
				status = "failed"
				message = "Trusted complete HTTP response body is not bounded strict JSON."
				break
			}
			actual["structuredJSONValid"] = true
			if spec.JSONPath != nil {
				expected["jsonPath"] = map[string]any{
					"path": spec.JSONPath.Path,
				}
				compiledPath, pathErr := structuredjson.CompilePath(
					spec.JSONPath.Path,
				)
				expectedValue, expectedErr := structuredjson.Decode(
					spec.JSONPath.Equals,
					structuredjson.DefaultInstanceDecodeLimits(),
				)
				if pathErr != nil || expectedErr != nil {
					actual["jsonPathEvaluated"] = false
					if status != "failed" {
						status = "blocked"
						message = "Resolved HTTP JSONPath assertion could not be revalidated."
					}
				} else {
					actualValue, found := compiledPath.Lookup(document)
					matched := found && structuredjson.SemanticEqual(
						actualValue,
						expectedValue,
					)
					actual["jsonPathFound"] = found
					actual["jsonPathMatched"] = matched
					if !matched {
						status = "failed"
						if found {
							message = "Trusted HTTP JSONPath value did not match."
						} else {
							message = "Trusted HTTP JSONPath did not resolve to a value."
						}
					}
				}
			}
			if spec.JSONSchema != nil {
				expected["jsonSchema"] = map[string]any{
					"path":    spec.JSONSchema.Path,
					"digest":  spec.JSONSchema.Digest,
					"dialect": spec.JSONSchema.Dialect,
				}
				schema, available := prepared.structuredJSONSchema(
					*spec.JSONSchema,
				)
				if !available {
					actual["jsonSchemaEvaluated"] = false
					if status != "failed" {
						status = "blocked"
						message = "Plan-bound JSON Schema was unavailable to the controller."
					}
				} else if validateErr := schema.Validate(document); validateErr != nil {
					actual["jsonSchemaMatched"] = false
					if structuredjson.KindOf(validateErr) ==
						structuredjson.ErrorSchemaNotSatisfied {
						status = "failed"
						message = "Trusted HTTP response JSON did not satisfy the plan-bound schema."
					} else if status != "failed" {
						status = "inconclusive"
						message = "Controller-owned JSON Schema evaluation could not complete."
					}
				} else {
					actual["jsonSchemaMatched"] = true
				}
			}
		}
	}
	result.Expected = expected
	result.Actual = actual
	result.Status = status
	result.Message = message
	return result
}
