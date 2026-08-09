package manifest

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/schemas"
	"gopkg.in/yaml.v3"
)

const maxManifestBytes = 4 << 20

func Load(path string) (*Document, error) {
	return load(path, nil)
}

// load is split from Load only so package tests can deterministically prove that
// a replacement after the first read fails closed. Production callers use Load.
func load(path string, afterFirstRead func()) (*Document, error) {
	data, err := readStableManifest(path, afterFirstRead)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&root); err != nil {
		return nil, domain.WrapError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest YAML is invalid.", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, domain.WrapError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"Manifest must contain exactly one YAML document.",
			err,
		)
	}
	if len(root.Content) != 1 {
		return nil, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest must contain exactly one YAML document.")
	}
	if err := rejectAliases(root.Content[0], "$"); err != nil {
		return nil, err
	}
	if err := detectLiteralSecret(root.Content[0], "$", false); err != nil {
		return nil, err
	}
	if err := validateKnownFields(root.Content[0], reflect.TypeOf(Manifest{}), "$"); err != nil {
		return nil, err
	}

	var parsed Manifest
	if err := root.Content[0].Decode(&parsed); err != nil {
		return nil, domain.WrapError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest values do not match the schema.", err)
	}

	var raw any
	if err := root.Content[0].Decode(&raw); err != nil {
		return nil, domain.WrapError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest could not be normalized.", err)
	}
	if err := schemas.ValidateManifest(raw); err != nil {
		return nil, domain.WrapError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"Manifest does not satisfy the public v1alpha1 schema.",
			err,
		)
	}
	digest, err := canonicaljson.Digest(raw)
	if err != nil {
		return nil, domain.WrapError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest could not be canonicalized.", err)
	}
	return &Document{Manifest: &parsed, Raw: raw, Digest: digest, Path: path}, nil
}

// readStableManifest keeps untrusted filesystem objects outside the YAML parser.
// It rejects native links, special files, and over-limit content both before and
// through the opened handle. The two reads bind the parser input to a stable
// handle and fail closed if the path is replaced or mutated concurrently.
func readStableManifest(path string, afterFirstRead func()) ([]byte, error) {
	if path == "" || !safeManifestNativePath(path) {
		return nil, invalidManifestRead()
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, invalidManifestRead()
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, manifestNotFound()
		}
		return nil, invalidManifestRead()
	}
	if before.Size() > maxManifestBytes {
		return nil, manifestReadFailure(errManifestTooLarge)
	}
	if !safeManifestFileInfo(before) || isManifestReparsePoint(absolute) {
		return nil, invalidManifestRead()
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameManifestPath(absolute, resolved) {
		return nil, invalidManifestRead()
	}

	file, err := os.Open(absolute)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, manifestNotFound()
		}
		return nil, invalidManifestRead()
	}
	defer file.Close()
	opened, err := file.Stat()
	if err == nil && opened.Size() > maxManifestBytes {
		return nil, manifestReadFailure(errManifestTooLarge)
	}
	if err != nil || !safeManifestFileInfo(opened) || !os.SameFile(before, opened) ||
		validateManifestOpenedHandle(file, absolute) != nil {
		return nil, invalidManifestRead()
	}

	first, err := readBoundedManifest(file)
	if err != nil {
		return nil, manifestReadFailure(err)
	}
	defer clear(first)
	firstInfo, err := file.Stat()
	if err != nil || !stableManifestFileInfo(opened, firstInfo) {
		return nil, manifestChanged()
	}
	if afterFirstRead != nil {
		afterFirstRead()
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, manifestChanged()
	}
	second, err := readBoundedManifest(file)
	if err != nil {
		return nil, manifestChanged()
	}
	defer clear(second)
	finalHandle, handleErr := file.Stat()
	finalPath, pathErr := os.Lstat(absolute)
	finalResolved, resolveErr := filepath.EvalSymlinks(absolute)
	if handleErr != nil || pathErr != nil || resolveErr != nil ||
		!safeManifestFileInfo(finalPath) || isManifestReparsePoint(absolute) ||
		!sameManifestPath(absolute, finalResolved) || !stableManifestFileInfo(opened, finalHandle) ||
		!stableManifestFileInfo(before, finalPath) || !os.SameFile(finalHandle, finalPath) ||
		validateManifestOpenedHandle(file, absolute) != nil || !bytes.Equal(first, second) {
		return nil, manifestChanged()
	}
	return append([]byte(nil), first...), nil
}

func readBoundedManifest(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		clear(raw)
		return nil, err
	}
	if len(raw) > maxManifestBytes {
		clear(raw)
		return nil, errManifestTooLarge
	}
	return raw, nil
}

func safeManifestFileInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Size() >= 0 && info.Size() <= maxManifestBytes
}

func stableManifestFileInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Mode() == right.Mode() && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}

func safeManifestNativePath(value string) bool {
	if strings.IndexByte(value, 0) >= 0 {
		return false
	}
	if runtime.GOOS != "windows" {
		return true
	}
	normalized := strings.ReplaceAll(value, "/", `\`)
	if strings.HasPrefix(normalized, `\\?\`) || strings.HasPrefix(normalized, `\\.\`) {
		return false
	}
	volume := filepath.VolumeName(value)
	if strings.HasPrefix(strings.ReplaceAll(volume, "/", `\`), `\\`) {
		return false
	}
	remainder := strings.TrimPrefix(value, volume)
	if strings.Contains(remainder, ":") {
		return false
	}
	for _, segment := range strings.Split(normalized, `\`) {
		if segment == "." || segment == ".." {
			continue
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return false
		}
	}
	return true
}

func sameManifestPath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

var errManifestTooLarge = fmt.Errorf("manifest too large")

func manifestNotFound() error {
	return domain.NewError(domain.CodeManifestNotFound, domain.SeverityHigh, "Unable to read the manifest.")
}

func invalidManifestRead() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest must be a bounded regular file without links.")
}

func manifestChanged() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest changed while it was being read.")
}

func manifestReadFailure(err error) error {
	if err == errManifestTooLarge {
		return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest exceeds the 4 MiB limit.")
	}
	return invalidManifestRead()
}

func detectLiteralSecret(node *yaml.Node, path string, insideSecret bool) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			value := node.Content[i+1]
			nextPath := path + "." + key
			nextInside := insideSecret || strings.Contains(nextPath, ".secrets.")
			lowerKey := strings.ToLower(key)
			if insideSecret && (lowerKey == "value" || lowerKey == "literal" || lowerKey == "token" || lowerKey == "password" || lowerKey == "secretvalue") {
				e := domain.NewError(domain.CodeManifestLiteralSecret, domain.SeverityCritical, "Literal secret material is forbidden in a manifest.")
				e.Details = map[string]any{"path": nextPath}
				e.Suggestion = "Use a synthetic secret reference scoped to the required phases."
				return e
			}
			if insideSecret && key == "source" && value.Kind == yaml.ScalarNode && value.Value != "synthetic" {
				e := domain.NewError(domain.CodeManifestLiteralSecret, domain.SeverityCritical, "v0.1 accepts only synthetic secret references.")
				e.Details = map[string]any{"path": nextPath}
				e.Suggestion = "Use source: synthetic."
				return e
			}
			if err := detectLiteralSecret(value, nextPath, nextInside); err != nil {
				return err
			}
		}
		return nil
	}
	for i, child := range node.Content {
		if err := detectLiteralSecret(child, fmt.Sprintf("%s[%d]", path, i), insideSecret); err != nil {
			return err
		}
	}
	return nil
}

func rejectAliases(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode {
		e := domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "YAML aliases and merge keys are not supported.")
		e.Details = map[string]any{"path": path}
		return e
	}
	for i, child := range node.Content {
		if child.Value == "<<" {
			e := domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "YAML merge keys are not supported.")
			e.Details = map[string]any{"path": path}
			return e
		}
		if err := rejectAliases(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func validateKnownFields(node *yaml.Node, target reflect.Type, path string) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if node.Tag == "!!null" {
		return nil
	}
	switch target.Kind() {
	case reflect.Interface:
		return nil
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if _, exists := seen[key]; exists {
				return duplicateKeyError(path, key)
			}
			seen[key] = struct{}{}
			if err := validateKnownFields(node.Content[i+1], target.Elem(), path+"."+key); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		if node.Kind != yaml.SequenceNode {
			return nil
		}
		for i, child := range node.Content {
			if err := validateKnownFields(child, target.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		fields := yamlFields(target)
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			keyNode, valueNode := node.Content[i], node.Content[i+1]
			if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
				return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest mapping keys must be strings.")
			}
			key := keyNode.Value
			if _, exists := seen[key]; exists {
				return duplicateKeyError(path, key)
			}
			seen[key] = struct{}{}
			if strings.HasPrefix(key, "x-") {
				continue
			}
			fieldType, ok := fields[key]
			if !ok {
				e := domain.NewError(domain.CodeManifestUnknownField, domain.SeverityHigh, "Manifest contains an unknown field.")
				e.Details = map[string]any{"path": path + "." + key}
				e.Suggestion = "Fix the field name or prefix an experimental extension with x-."
				return e
			}
			if err := validateKnownFields(valueNode, fieldType, path+"."+key); err != nil {
				return err
			}
		}
	}
	return nil
}

func yamlFields(target reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, target.NumField())
	for i := 0; i < target.NumField(); i++ {
		field := target.Field(i)
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == "" {
			tag = strings.ToLower(field.Name[:1]) + field.Name[1:]
		}
		if tag == "-" {
			continue
		}
		fields[tag] = field.Type
	}
	return fields
}

func duplicateKeyError(path, key string) error {
	e := domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest contains a duplicate mapping key.")
	e.Details = map[string]any{"path": path + "." + key}
	return e
}
