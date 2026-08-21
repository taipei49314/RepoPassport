package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/controllerfs"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

type structuredJSONSchemaBinding struct {
	path             string
	digest           string
	dialect          string
	validatorVersion string
}

func (r *Runner) prepareStructuredJSONSchemas(
	plan domain.ResolvedPlan,
	snapshotRoot string,
	runDir string,
) (map[structuredJSONSchemaBinding]*structuredjson.Schema, error) {
	references := structuredJSONSchemaReferences(plan)
	if len(references) == 0 {
		return map[structuredJSONSchemaBinding]*structuredjson.Schema{}, nil
	}
	compiled := make(
		map[structuredJSONSchemaBinding]*structuredjson.Schema,
		len(references),
	)
	for _, reference := range references {
		binding, err := structuredJSONSchemaBindingFor(reference)
		if err != nil {
			cleanupErr := controllerfs.RemoveTree(runDir)
			return nil, errors.Join(err, cleanupErr)
		}
		raw, err := readPreparedSchema(snapshotRoot, reference)
		if err != nil {
			cleanupErr := controllerfs.RemoveTree(runDir)
			return nil, errors.Join(err, cleanupErr)
		}
		if _, exists := compiled[binding]; exists {
			continue
		}
		schema, err := structuredjson.CompileSchema(raw)
		if err != nil {
			planErr := domain.WrapError(
				domain.CodePlanUnresolved,
				domain.SeverityHigh,
				"Resolved JSON Schema is invalid or outside the bounded offline profile.",
				err,
			)
			planErr.Details = map[string]any{
				"path":   reference.Path,
				"digest": reference.Digest,
			}
			cleanupErr := controllerfs.RemoveTree(runDir)
			return nil, errors.Join(planErr, cleanupErr)
		}
		compiled[binding] = schema
	}
	return compiled, nil
}

func structuredJSONSchemaReferences(
	plan domain.ResolvedPlan,
) []domain.PlanJSONSchemaRef {
	references := make([]domain.PlanJSONSchemaRef, 0)
	for _, assertion := range plan.JourneyAssertions {
		if assertion.StdoutJSONSchema != nil {
			references = append(references, *assertion.StdoutJSONSchema)
		}
		if assertion.Response != nil &&
			assertion.Response.JSONSchema != nil {
			references = append(references, *assertion.Response.JSONSchema)
		}
		if assertion.JSONFile != nil {
			references = append(references, assertion.JSONFile.Schema)
		}
	}
	return references
}

func validateStructuredJSONSchemaRef(
	reference domain.PlanJSONSchemaRef,
) error {
	if reference.Dialect != domain.AlphaJSONSchemaDialect ||
		reference.ValidatorVersion != domain.AlphaJSONValidatorVersion ||
		!validDigest(reference.Digest) ||
		!validPortableSchemaPath(reference.Path) {
		return planError(
			"Resolved JSON Schema reference is not canonical or is outside the alpha profile.",
		)
	}
	return nil
}

func structuredJSONSchemaBindingFor(
	reference domain.PlanJSONSchemaRef,
) (structuredJSONSchemaBinding, error) {
	if err := validateStructuredJSONSchemaRef(reference); err != nil {
		return structuredJSONSchemaBinding{}, err
	}
	return structuredJSONSchemaBinding{
		path:             reference.Path,
		digest:           reference.Digest,
		dialect:          reference.Dialect,
		validatorVersion: reference.ValidatorVersion,
	}, nil
}

func validPortableSchemaPath(value string) bool {
	if value == "" ||
		len([]byte(value)) > 4096 ||
		strings.Contains(value, "\\") ||
		strings.ContainsAny(value, "\x00\r\n") ||
		path.IsAbs(value) ||
		path.Clean(value) != value ||
		value == "." ||
		value == ".." ||
		strings.HasPrefix(value, "../") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" ||
			segment == "." ||
			segment == ".." ||
			len(segment) > 255 ||
			strings.HasSuffix(segment, ".") ||
			strings.HasSuffix(segment, " ") ||
			portableSchemaWindowsDeviceName(segment) {
			return false
		}
		for _, character := range segment {
			if character < 0x20 ||
				character > 0x7e ||
				strings.ContainsRune(`<>:"\|?*`, character) {
				return false
			}
		}
	}
	return true
}

func portableSchemaWindowsDeviceName(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return true
	}
	if len(base) != 4 {
		return false
	}
	prefix := base[:3]
	return (prefix == "COM" || prefix == "LPT") &&
		base[3] >= '1' && base[3] <= '9'
}

func readPreparedSchema(
	snapshotRoot string,
	reference domain.PlanJSONSchemaRef,
) ([]byte, error) {
	if err := validateStructuredJSONSchemaRef(reference); err != nil {
		return nil, err
	}
	candidate := filepath.Join(
		snapshotRoot,
		filepath.FromSlash(reference.Path),
	)
	if !pathWithin(snapshotRoot, candidate) {
		return nil, domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Resolved JSON Schema path escaped the immutable source snapshot.",
		)
	}
	resolved, err := pathsecurity.Resolve(candidate)
	if err != nil ||
		!pathWithin(snapshotRoot, resolved) ||
		!samePath(candidate, resolved) {
		return nil, domain.WrapError(
			domain.CodeSourceSymlinkEscape,
			domain.SeverityCritical,
			"Resolved JSON Schema is absent or resolves through a symbolic link.",
			err,
		)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, domain.WrapError(
			domain.CodeSourceNotFound,
			domain.SeverityHigh,
			"Resolved JSON Schema could not be opened.",
			err,
		)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Size() < 1 ||
		info.Size() > domain.AlphaJSONSchemaMaxBytes {
		return nil, domain.WrapError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Resolved JSON Schema is not a bounded regular file.",
			err,
		)
	}
	raw, err := io.ReadAll(io.LimitReader(
		file,
		domain.AlphaJSONSchemaMaxBytes+1,
	))
	if err != nil {
		return nil, domain.WrapError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"Resolved JSON Schema could not be read completely.",
			err,
		)
	}
	if int64(len(raw)) != info.Size() ||
		int64(len(raw)) > domain.AlphaJSONSchemaMaxBytes {
		return nil, domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"Resolved JSON Schema changed or exceeded its bound while being read.",
		)
	}
	sum := sha256.Sum256(raw)
	actualDigest := "sha256:" + hex.EncodeToString(sum[:])
	if actualDigest != reference.Digest {
		digestErr := domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityCritical,
			"Resolved JSON Schema bytes do not match the plan-bound digest.",
		)
		digestErr.Details = map[string]any{
			"path":     reference.Path,
			"expected": reference.Digest,
			"actual":   actualDigest,
		}
		return nil, digestErr
	}
	return raw, nil
}

func (prepared *PreparedRun) structuredJSONSchema(
	reference domain.PlanJSONSchemaRef,
) (*structuredjson.Schema, bool) {
	if prepared == nil ||
		!prepared.executionPlanSealed ||
		prepared.structuredJSONSchemas == nil {
		return nil, false
	}
	binding, err := structuredJSONSchemaBindingFor(reference)
	if err != nil {
		return nil, false
	}
	schema, ok := prepared.structuredJSONSchemas[binding]
	return schema, ok && schema != nil
}
