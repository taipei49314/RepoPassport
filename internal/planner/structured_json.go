package planner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

type schemaResolver struct {
	snapshot domain.SourceSnapshot
	cache    map[string]domain.PlanJSONSchemaRef
}

func newSchemaResolver(snapshot domain.SourceSnapshot) *schemaResolver {
	return &schemaResolver{
		snapshot: snapshot,
		cache:    make(map[string]domain.PlanJSONSchemaRef),
	}
}

func (r *schemaResolver) resolve(
	portablePath string,
) (domain.PlanJSONSchemaRef, error) {
	if !validSchemaRepositoryPath(portablePath) {
		return domain.PlanJSONSchemaRef{}, schemaSourceError(
			domain.CodeSourcePathTraversal,
			"JSON Schema path is not a portable normalized repository path.",
			portablePath,
		)
	}

	entry, err := schemaInventoryEntry(r.snapshot.Inventory, portablePath)
	if err != nil {
		return domain.PlanJSONSchemaRef{}, err
	}
	if entry.Mode != "0644" && entry.Mode != "0755" {
		return domain.PlanJSONSchemaRef{}, schemaSourceError(
			domain.CodeSourcePathTraversal,
			"JSON Schema inventory entry is not a regular source file.",
			portablePath,
		)
	}
	if entry.Size < 0 || entry.Size > domain.AlphaJSONSchemaMaxBytes {
		result := schemaSourceError(
			domain.CodeSourceTooLarge,
			"JSON Schema exceeds the alpha byte limit.",
			portablePath,
		)
		result.Details["limit"] = domain.AlphaJSONSchemaMaxBytes
		result.Details["size"] = entry.Size
		return domain.PlanJSONSchemaRef{}, result
	}
	if !validSchemaDigest(entry.Digest) {
		return domain.PlanJSONSchemaRef{}, schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema inventory digest is invalid.",
			portablePath,
		)
	}

	before, err := readSnapshotSchema(
		r.snapshot.Root,
		portablePath,
		domain.AlphaJSONSchemaMaxBytes,
	)
	if err != nil {
		return domain.PlanJSONSchemaRef{}, err
	}
	if err := verifySchemaSnapshotBytes(before, entry, portablePath); err != nil {
		return domain.PlanJSONSchemaRef{}, err
	}
	after, err := readSnapshotSchema(
		r.snapshot.Root,
		portablePath,
		domain.AlphaJSONSchemaMaxBytes,
	)
	if err != nil {
		return domain.PlanJSONSchemaRef{}, err
	}
	if err := verifySchemaSnapshotBytes(after, entry, portablePath); err != nil {
		return domain.PlanJSONSchemaRef{}, err
	}
	if !bytes.Equal(before, after) {
		return domain.PlanJSONSchemaRef{}, schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema source changed while the plan was being resolved.",
			portablePath,
		)
	}
	if cached, ok := r.cache[portablePath]; ok {
		return cached, nil
	}
	if _, err := structuredjson.CompileSchema(before); err != nil {
		return domain.PlanJSONSchemaRef{}, schemaSourceError(
			domain.CodePlanUnresolved,
			"JSON Schema is invalid or uses a feature outside the bounded offline profile.",
			portablePath,
		)
	}

	resolved := domain.PlanJSONSchemaRef{
		Path:             portablePath,
		Digest:           entry.Digest,
		Dialect:          domain.AlphaJSONSchemaDialect,
		ValidatorVersion: domain.AlphaJSONValidatorVersion,
	}
	r.cache[portablePath] = resolved
	return resolved, nil
}

func schemaInventoryEntry(
	inventory []domain.FileEntry,
	portablePath string,
) (domain.FileEntry, error) {
	var (
		result domain.FileEntry
		found  bool
	)
	for _, entry := range inventory {
		if entry.Path != portablePath {
			continue
		}
		if found {
			return domain.FileEntry{}, schemaSourceError(
				domain.CodeSourceDigestMismatch,
				"JSON Schema appears more than once in the immutable source inventory.",
				portablePath,
			)
		}
		result = entry
		found = true
	}
	if !found {
		return domain.FileEntry{}, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema is absent from the immutable source inventory.",
			portablePath,
		)
	}
	return result, nil
}

func readSnapshotSchema(
	root string,
	portablePath string,
	maximumBytes int64,
) ([]byte, error) {
	if root == "" {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema snapshot root is unavailable.",
			portablePath,
		)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema snapshot root could not be resolved.",
			portablePath,
		)
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema snapshot root could not be opened.",
			portablePath,
		)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, schemaSourceError(
			domain.CodeSourceSymlinkEscape,
			"JSON Schema snapshot root must not be a symbolic link.",
			portablePath,
		)
	}
	if !rootInfo.IsDir() {
		return nil, schemaSourceError(
			domain.CodeSourcePathTraversal,
			"JSON Schema snapshot root is not a directory.",
			portablePath,
		)
	}

	candidate := filepath.Join(absoluteRoot, filepath.FromSlash(portablePath))
	relative, err := filepath.Rel(absoluteRoot, candidate)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(relative) {
		return nil, schemaSourceError(
			domain.CodeSourcePathTraversal,
			"JSON Schema path escaped the source snapshot.",
			portablePath,
		)
	}
	if err := validateSchemaPathComponents(
		absoluteRoot,
		portablePath,
	); err != nil {
		return nil, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema snapshot root could not be resolved.",
			portablePath,
		)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema source file could not be resolved.",
			portablePath,
		)
	}
	resolvedRelative, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil || resolvedRelative == ".." ||
		strings.HasPrefix(
			resolvedRelative,
			".."+string(filepath.Separator),
		) ||
		filepath.IsAbs(resolvedRelative) ||
		filepath.Clean(resolvedCandidate) != filepath.Clean(candidate) {
		return nil, schemaSourceError(
			domain.CodeSourceSymlinkEscape,
			"JSON Schema source path resolved through a symbolic link.",
			portablePath,
		)
	}

	beforeInfo, err := os.Lstat(candidate)
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema source file could not be opened.",
			portablePath,
		)
	}
	if beforeInfo.Mode()&os.ModeSymlink != 0 {
		return nil, schemaSourceError(
			domain.CodeSourceSymlinkEscape,
			"JSON Schema source file must not be a symbolic link.",
			portablePath,
		)
	}
	if !beforeInfo.Mode().IsRegular() {
		return nil, schemaSourceError(
			domain.CodeSourcePathTraversal,
			"JSON Schema source is not a regular file.",
			portablePath,
		)
	}

	file, err := os.Open(candidate)
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceNotFound,
			"JSON Schema source file could not be opened.",
			portablePath,
		)
	}
	defer file.Close()
	openInfo, err := file.Stat()
	if err != nil || !openInfo.Mode().IsRegular() ||
		!os.SameFile(beforeInfo, openInfo) {
		return nil, schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema source changed before it could be read.",
			portablePath,
		)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema source could not be read consistently.",
			portablePath,
		)
	}
	if int64(len(raw)) > maximumBytes {
		return nil, schemaSourceError(
			domain.CodeSourceTooLarge,
			"JSON Schema exceeds the alpha byte limit.",
			portablePath,
		)
	}
	afterInfo, err := file.Stat()
	if err != nil || !os.SameFile(openInfo, afterInfo) ||
		openInfo.Size() != afterInfo.Size() {
		return nil, schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema source changed while it was being read.",
			portablePath,
		)
	}
	return raw, nil
}

func validateSchemaPathComponents(root, portablePath string) error {
	current := root
	segments := strings.Split(portablePath, "/")
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			return schemaSourceError(
				domain.CodeSourceNotFound,
				"JSON Schema source path does not exist.",
				portablePath,
			)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return schemaSourceError(
				domain.CodeSourceSymlinkEscape,
				"JSON Schema source path must not contain symbolic links.",
				portablePath,
			)
		}
		final := index == len(segments)-1
		if !final && !info.IsDir() {
			return schemaSourceError(
				domain.CodeSourcePathTraversal,
				"JSON Schema source parent is not a directory.",
				portablePath,
			)
		}
		if final && !info.Mode().IsRegular() {
			return schemaSourceError(
				domain.CodeSourcePathTraversal,
				"JSON Schema source is not a regular file.",
				portablePath,
			)
		}
	}
	return nil
}

func verifySchemaSnapshotBytes(
	raw []byte,
	entry domain.FileEntry,
	portablePath string,
) error {
	if int64(len(raw)) != entry.Size {
		return schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema source size does not match the immutable inventory.",
			portablePath,
		)
	}
	digest := sha256.Sum256(raw)
	actual := domain.AlphaJSONSchemaDigestPrefix +
		hex.EncodeToString(digest[:])
	if actual != entry.Digest {
		result := schemaSourceError(
			domain.CodeSourceDigestMismatch,
			"JSON Schema source digest does not match the immutable inventory.",
			portablePath,
		)
		result.Details["expected"] = entry.Digest
		result.Details["actual"] = actual
		return result
	}
	return nil
}

func validSchemaDigest(value string) bool {
	if len(value) != len(domain.AlphaJSONSchemaDigestPrefix)+sha256.Size*2 ||
		!strings.HasPrefix(value, domain.AlphaJSONSchemaDigestPrefix) {
		return false
	}
	for _, character := range value[len(domain.AlphaJSONSchemaDigestPrefix):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validSchemaRepositoryPath(value string) bool {
	if value == "" || len([]byte(value)) > 4096 ||
		strings.Contains(value, "\\") ||
		path.IsAbs(value) ||
		path.Clean(value) != value ||
		value == "." {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || len([]byte(segment)) > 255 ||
			segment == "." || segment == ".." ||
			strings.HasSuffix(segment, ".") ||
			strings.HasSuffix(segment, " ") ||
			portableSchemaWindowsDeviceName(segment) {
			return false
		}
		for _, character := range segment {
			if character < 0x20 || character > 0x7e ||
				strings.ContainsRune(`\:*?"<>|`, character) {
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

func schemaSourceError(
	code domain.ErrorCode,
	message string,
	portablePath string,
) *domain.Error {
	result := domain.NewError(code, domain.SeverityHigh, message)
	result.Details = map[string]any{"path": portablePath}
	return result
}
