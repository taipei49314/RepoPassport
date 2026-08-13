package acceptanceregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

var (
	errRegistryInvalid = errors.New("acceptance registry is invalid")
	errScopeMismatch   = errors.New("acceptance registry scope differs from RFC-0003")
)

func ParseRegistry(raw []byte) (Registry, error) {
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: MaxRegistryBytes,
		MaxDepth: 16,
		MaxNodes: 16_384,
	})
	if err != nil {
		return Registry{}, errRegistryInvalid
	}
	canonical, err := canonicaljson.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Registry{}, errRegistryInvalid
	}
	registry, err := decodeRegistry(value)
	if err != nil {
		return Registry{}, errRegistryInvalid
	}
	want := expectedRegistry()
	gotCanonical, gotErr := canonicaljson.Marshal(registry)
	wantCanonical, wantErr := canonicaljson.Marshal(want)
	if gotErr != nil || wantErr != nil || !bytes.Equal(gotCanonical, wantCanonical) {
		return Registry{}, errScopeMismatch
	}
	return registry, nil
}

func RegistryDigest(raw []byte) (string, error) {
	if _, err := ParseRegistry(raw); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ErrorCode maps private validation errors to stable, non-disclosing public
// command codes.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, errScopeMismatch):
		return "ACCEPTANCE_SCOPE_MISMATCH"
	case errors.Is(err, errRegistryInvalid):
		return "ACCEPTANCE_REGISTRY_INVALID"
	case errors.Is(err, errSubjectInvalid):
		return "ACCEPTANCE_SUBJECT_INVALID"
	case errors.Is(err, errCheckInputInvalid):
		return "ACCEPTANCE_CHECK_INPUT_INVALID"
	case errors.Is(err, errIncomplete):
		return "ACCEPTANCE_INCOMPLETE"
	default:
		return "ACCEPTANCE_EVALUATION_INVALID"
	}
}

func decodeRegistry(value any) (Registry, error) {
	root, ok := value.(map[string]any)
	if !ok || !exactKeys(root, "artifactType", "product", "rows", "schemaVersion") {
		return Registry{}, errRegistryInvalid
	}
	artifactType, okArtifact := exactString(root, "artifactType")
	product, okProduct := exactString(root, "product")
	schemaVersion, okSchema := exactString(root, "schemaVersion")
	rowValues, okRows := root["rows"].([]any)
	if !okArtifact || !okProduct || !okSchema || !okRows || len(rowValues) != 37 {
		return Registry{}, errRegistryInvalid
	}
	rows := make([]RegistryRow, len(rowValues))
	for index, rawRow := range rowValues {
		row, ok := rawRow.(map[string]any)
		if !ok || !exactKeys(row, "appliesTo", "criterion", "evaluation", "id", "milestone", "required") {
			return Registry{}, errRegistryInvalid
		}
		appliesTo, okApplies := exactStringArray(row["appliesTo"])
		criterion, okCriterion := exactString(row, "criterion")
		id, okID := exactString(row, "id")
		milestone, okMilestone := exactString(row, "milestone")
		required, okRequired := row["required"].(bool)
		policyValue, okPolicy := row["evaluation"].(map[string]any)
		if !okApplies || !okCriterion || !okID || !okMilestone || !okRequired || !okPolicy {
			return Registry{}, errRegistryInvalid
		}
		policy, err := decodePolicy(policyValue)
		if err != nil {
			return Registry{}, err
		}
		rows[index] = RegistryRow{AppliesTo: appliesTo, Criterion: criterion, Evaluation: policy, ID: id, Milestone: milestone, Required: required}
	}
	return Registry{ArtifactType: artifactType, Product: product, Rows: rows, SchemaVersion: schemaVersion}, nil
}

func decodePolicy(value map[string]any) (EvaluationPolicy, error) {
	kind, ok := exactString(value, "kind")
	if !ok {
		return EvaluationPolicy{}, errRegistryInvalid
	}
	switch kind {
	case "required-checks":
		if !exactKeys(value, "kind", "requiredChecks") {
			return EvaluationPolicy{}, errRegistryInvalid
		}
		checks, ok := exactStringArray(value["requiredChecks"])
		if !ok || len(checks) == 0 || len(checks) > 4 || !strictlySortedUnique(checks) {
			return EvaluationPolicy{}, errRegistryInvalid
		}
		return EvaluationPolicy{Kind: kind, RequiredChecks: checks}, nil
	case "blocked", "not-run":
		if !exactKeys(value, "kind", "reasonCode") {
			return EvaluationPolicy{}, errRegistryInvalid
		}
		reason, ok := exactString(value, "reasonCode")
		if !ok {
			return EvaluationPolicy{}, errRegistryInvalid
		}
		return EvaluationPolicy{Kind: kind, ReasonCode: reason}, nil
	default:
		return EvaluationPolicy{}, errRegistryInvalid
	}
}

func exactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func exactString(value map[string]any, key string) (string, bool) {
	result, ok := value[key].(string)
	return result, ok
}

func exactStringArray(value any) ([]string, bool) {
	raw, ok := value.([]any)
	if !ok || len(raw) == 0 || len(raw) > 16 {
		return nil, false
	}
	result := make([]string, len(raw))
	for index, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result[index] = text
	}
	return result, true
}

func strictlySortedUnique(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}
