package sourcequalification

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	maxSchemaJSONFileBytes  = 16 << 20
	maxSchemaJSONFiles      = 32_768
	maxSchemaJSONTotal      = int64(512 << 20)
	maxSchemaJSONEntries    = 32_768
	maxSchemaJSONDepth      = 64
	schemaJSONReadBatchSize = 128
)

type schemaJSONDirectory interface {
	ReadDir(n int) ([]os.DirEntry, error)
	Close() error
}

type schemaJSONWalkState struct {
	entries int
}

type schemaJSONWalkOperations struct {
	openDirectory func(string) (schemaJSONDirectory, error)
	inspectEntry  func(string, os.DirEntry, func(string, []byte) error) (bool, error)
}

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
	resolved, err := pathsecurity.Resolve(root)
	if err != nil {
		if _, qualification := pathsecurity.QualificationTestDescriptor(); qualification {
			return errors.New("schema JSON root is unavailable")
		}
		resolved = root
	}
	resolved = filepath.Clean(resolved)
	if !sameSchemaJSONPath(root, resolved) && !sameSchemaJSONRootIdentity(root, resolved) {
		return errors.New("schema JSON root is redirected")
	}

	schemaCount := 0
	fileCount := 0
	total := int64(0)
	walkState := &schemaJSONWalkState{}
	for _, scope := range []struct {
		path     string
		required bool
		schema   bool
	}{
		{path: filepath.Join(root, "schemas"), required: true, schema: true},
		{path: filepath.Join(root, "testdata", "fixtures")},
	} {
		if err := walkSchemaJSON(scope.path, scope.required, walkState, func(path string, raw []byte) error {
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

func walkSchemaJSON(
	root string,
	required bool,
	state *schemaJSONWalkState,
	visit func(string, []byte) error,
) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("schema JSON scope is unavailable")
	}
	operations := schemaJSONWalkOperations{
		openDirectory: openSchemaJSONDirectory,
		inspectEntry:  inspectSchemaJSONEntry,
	}
	return walkSchemaJSONDirectory(root, 0, state, operations, visit)
}

func walkSchemaJSONDirectory(
	path string,
	depth int,
	state *schemaJSONWalkState,
	operations schemaJSONWalkOperations,
	visit func(string, []byte) error,
) (returnErr error) {
	if depth < 0 || depth > maxSchemaJSONDepth || state == nil ||
		operations.openDirectory == nil || operations.inspectEntry == nil || visit == nil {
		return errors.New("schema JSON inventory exceeds its bound")
	}
	directory, err := operations.openDirectory(path)
	if err != nil || directory == nil {
		return errors.New("schema JSON inventory contains a redirected entry")
	}
	defer func() {
		if err := directory.Close(); returnErr == nil && err != nil {
			returnErr = errors.New("schema JSON inventory is unreadable")
		}
	}()

	for {
		entries, readErr := directory.ReadDir(schemaJSONReadBatchSize)
		if len(entries) > schemaJSONReadBatchSize ||
			readErr != nil && !errors.Is(readErr, io.EOF) {
			return errors.New("schema JSON inventory is unreadable")
		}
		if len(entries) == 0 && readErr == nil {
			return errors.New("schema JSON inventory is unreadable")
		}
		for _, entry := range entries {
			state.entries++
			if state.entries > maxSchemaJSONEntries {
				return errors.New("schema JSON inventory exceeds its bound")
			}
			if entry == nil || !validSchemaJSONEntryName(entry.Name()) {
				return errors.New("schema JSON inventory contains an invalid entry")
			}
			childPath := filepath.Join(path, entry.Name())
			if filepath.Dir(childPath) != filepath.Clean(path) {
				return errors.New("schema JSON inventory contains an invalid entry")
			}
			isDirectory, err := operations.inspectEntry(childPath, entry, visit)
			if err != nil {
				return err
			}
			if isDirectory {
				if err := walkSchemaJSONDirectory(
					childPath,
					depth+1,
					state,
					operations,
					visit,
				); err != nil {
					return err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func openSchemaJSONDirectory(path string) (schemaJSONDirectory, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("schema JSON inventory contains a redirected entry")
	}
	directory, err := openPackageDirectory(path)
	if err != nil {
		return nil, errors.New("schema JSON inventory contains a redirected entry")
	}
	if _, err := snapshotPackageHandle(directory, true); err != nil {
		_ = directory.Close()
		return nil, errors.New("schema JSON inventory contains a redirected entry")
	}
	return directory, nil
}

func inspectSchemaJSONEntry(
	path string,
	entry os.DirEntry,
	visit func(string, []byte) error,
) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || entry.Type()&os.ModeSymlink != 0 {
		return false, errors.New("schema JSON inventory contains a redirected entry")
	}
	if info.IsDir() {
		directory, err := openSchemaJSONDirectory(path)
		if err != nil {
			return false, errors.New("schema JSON inventory contains a redirected entry")
		}
		closeErr := directory.Close()
		if closeErr != nil {
			return false, errors.New("schema JSON inventory is unreadable")
		}
		return true, nil
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("schema JSON inventory contains a special entry")
	}
	file, err := openPackageRegularFile(path)
	if err != nil {
		return false, errors.New("schema JSON inventory contains a redirected entry")
	}
	before, snapshotErr := snapshotPackageHandle(file, false)
	if snapshotErr != nil {
		_ = file.Close()
		return false, errors.New("schema JSON inventory contains a redirected entry")
	}
	if !strings.HasSuffix(entry.Name(), ".json") {
		if err := file.Close(); err != nil {
			return false, errors.New("schema JSON inventory is unreadable")
		}
		return false, nil
	}
	if before.size < 1 || before.size > maxSchemaJSONFileBytes {
		_ = file.Close()
		return false, errors.New("schema JSON document size is invalid")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(maxSchemaJSONFileBytes)+1))
	after, afterErr := snapshotPackageHandle(file, false)
	closeErr := file.Close()
	if readErr != nil || afterErr != nil || closeErr != nil || before != after ||
		int64(len(raw)) != before.size || len(raw) > maxSchemaJSONFileBytes {
		return false, errors.New("schema JSON document changed while reading")
	}
	if err := visit(path, raw); err != nil {
		return false, err
	}
	return false, nil
}

func validSchemaJSONEntryName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		filepath.Base(name) == name && filepath.VolumeName(name) == "" &&
		filepath.Clean(name) == name
}

func sameSchemaJSONPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func sameSchemaJSONRootIdentity(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}
