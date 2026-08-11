package sourcequalification

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	maxSchemaJSONFileBytes = 16 << 20
	maxSchemaJSONFiles     = 32_768
	maxSchemaJSONTotal     = int64(512 << 20)
)

// ValidateSchemaJSON enforces the RFC-0002 syntax gate over every repository
// schema and JSON fixture. Diagnostics deliberately do not expose paths or
// document bytes because this function feeds a public CI controller.
func ValidateSchemaJSON(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("schema JSON root is invalid")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("schema JSON root is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || !sameSchemaJSONPath(root, resolved) {
		return errors.New("schema JSON root is redirected")
	}

	schemaCount := 0
	fileCount := 0
	total := int64(0)
	for _, scope := range []struct {
		path     string
		required bool
		schema   bool
	}{
		{path: filepath.Join(root, "schemas"), required: true, schema: true},
		{path: filepath.Join(root, "testdata", "fixtures")},
	} {
		if err := walkSchemaJSON(scope.path, scope.required, func(path string, raw []byte) error {
			fileCount++
			if fileCount > maxSchemaJSONFiles || int64(len(raw)) > maxSchemaJSONTotal-total {
				return errors.New("schema JSON inventory exceeds its bound")
			}
			total += int64(len(raw))
			if scope.schema {
				schemaCount++
			}
			_, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
				MaxBytes: maxSchemaJSONFileBytes,
				MaxDepth: 256,
				MaxNodes: 500_000,
			})
			if err != nil {
				return errors.New("schema JSON document is invalid")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if schemaCount == 0 {
		return errors.New("schema JSON inventory contains no schema")
	}
	return nil
}

func walkSchemaJSON(root string, required bool, visit func(string, []byte) error) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("schema JSON scope is unavailable")
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("schema JSON inventory is unreadable")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("schema JSON inventory contains a redirected entry")
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("schema JSON inventory contains a special entry")
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		if info.Size() < 1 || info.Size() > maxSchemaJSONFileBytes {
			return errors.New("schema JSON document size is invalid")
		}
		raw, err := os.ReadFile(path)
		if err != nil || int64(len(raw)) != info.Size() {
			return errors.New("schema JSON document changed while reading")
		}
		return visit(path, raw)
	})
}

func sameSchemaJSONPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
