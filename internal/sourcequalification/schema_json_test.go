package sourcequalification

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestValidateSchemaJSONAcceptsStrictSchemaAndFixtureDocuments(t *testing.T) {
	root := t.TempDir()
	writeSchemaJSONFixture(t, root, "schemas/example.schema.json", []byte(`{"type":"object"}`))
	writeSchemaJSONFixture(t, root, "testdata/fixtures/example/fixture.json", []byte(`{"status":"healthy"}`))
	if err := ValidateSchemaJSON(root); err != nil {
		t.Fatalf("ValidateSchemaJSON rejected strict fixture tree: %v", err)
	}
}

func TestValidateSchemaJSONRejectsInvalidOrMissingContracts(t *testing.T) {
	tests := []struct {
		name  string
		files map[string][]byte
	}{
		{
			name:  "no schema",
			files: map[string][]byte{"testdata/fixtures/value.json": []byte(`{}`)},
		},
		{
			name:  "duplicate key",
			files: map[string][]byte{"schemas/value.schema.json": []byte(`{"type":"object","type":"array"}`)},
		},
		{
			name:  "trailing value",
			files: map[string][]byte{"schemas/value.schema.json": []byte(`{} {}`)},
		},
		{
			name:  "oversized JSON",
			files: map[string][]byte{"schemas/value.schema.json": append([]byte(`{"value":"`), append(make([]byte, (16<<20)+1), []byte(`"}`)...)...)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for path, raw := range test.files {
				writeSchemaJSONFixture(t, root, path, raw)
			}
			if err := ValidateSchemaJSON(root); err == nil {
				t.Fatal("ValidateSchemaJSON accepted invalid JSON contract tree")
			}
		})
	}
}

func TestWalkSchemaJSONBoundsBatchedReadsBeforeInspectingCapPlusOne(t *testing.T) {
	directory := &schemaJSONWideTestDirectory{remaining: maxSchemaJSONEntries + 1}
	inspected := 0
	visited := 0
	state := &schemaJSONWalkState{}
	operations := schemaJSONWalkOperations{
		openDirectory: func(string) (schemaJSONDirectory, error) {
			return directory, nil
		},
		inspectEntry: func(string, os.DirEntry, func(string, []byte) error) (bool, error) {
			inspected++
			return false, nil
		},
	}
	err := walkSchemaJSONDirectory("synthetic-root", 0, state, operations, func(string, []byte) error {
		visited++
		return nil
	})
	if err == nil {
		t.Fatal("wide non-JSON directory crossed the traversal entry bound")
	}
	if directory.emitted != maxSchemaJSONEntries+1 {
		t.Fatalf("directory entries emitted = %d, want cap+1 %d", directory.emitted, maxSchemaJSONEntries+1)
	}
	if inspected != maxSchemaJSONEntries {
		t.Fatalf("entries inspected = %d, want exactly cap %d before immediate rejection", inspected, maxSchemaJSONEntries)
	}
	if visited != 0 {
		t.Fatalf("non-JSON entries visited as documents = %d", visited)
	}
	if len(directory.requests) == 0 {
		t.Fatal("directory was not read")
	}
	for _, request := range directory.requests {
		if request != schemaJSONReadBatchSize {
			t.Fatalf("ReadDir request = %d, want bounded batch %d", request, schemaJSONReadBatchSize)
		}
	}
}

func TestWalkSchemaJSONRejectsDepthBeforeOpeningBeyondCap(t *testing.T) {
	requests := []int{}
	opened := 0
	operations := schemaJSONWalkOperations{
		openDirectory: func(string) (schemaJSONDirectory, error) {
			opened++
			return &schemaJSONSingleChildTestDirectory{requests: &requests}, nil
		},
		inspectEntry: func(string, os.DirEntry, func(string, []byte) error) (bool, error) {
			return true, nil
		},
	}
	err := walkSchemaJSONDirectory(
		"synthetic-root",
		0,
		&schemaJSONWalkState{},
		operations,
		func(string, []byte) error { return nil },
	)
	if err == nil {
		t.Fatal("schema traversal crossed its directory depth bound")
	}
	if opened != maxSchemaJSONDepth+1 {
		t.Fatalf("directories opened = %d, want depths 0..%d only", opened, maxSchemaJSONDepth)
	}
	for _, request := range requests {
		if request != schemaJSONReadBatchSize {
			t.Fatalf("ReadDir request = %d, want bounded batch %d", request, schemaJSONReadBatchSize)
		}
	}
}

func TestValidateSchemaJSONRejectsDirectoryRedirectWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	writeSchemaJSONFixture(t, root, "schemas/example.schema.json", []byte(`{"type":"object"}`))
	external := t.TempDir()
	writeSchemaJSONFixture(t, external, "private.json", []byte(`{"private":true}`))
	fixtures := filepath.Join(root, "testdata", "fixtures")
	if err := os.MkdirAll(fixtures, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(fixtures, "redirect")
	if !createSchemaJSONDirectoryRedirect(t, redirect, external) {
		t.Skip("directory redirect fixture is unavailable")
	}
	if err := ValidateSchemaJSON(root); err == nil {
		t.Fatal("ValidateSchemaJSON accepted a symlink or Windows junction")
	}
}

type schemaJSONWideTestDirectory struct {
	remaining int
	emitted   int
	requests  []int
}

func (directory *schemaJSONWideTestDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	directory.requests = append(directory.requests, n)
	if directory.remaining == 0 {
		return nil, io.EOF
	}
	count := n
	if count > directory.remaining {
		count = directory.remaining
	}
	entries := make([]os.DirEntry, count)
	for index := range entries {
		entries[index] = schemaJSONTestEntry("non-json-" + strconv.Itoa(directory.emitted+index) + ".txt")
	}
	directory.remaining -= count
	directory.emitted += count
	return entries, nil
}

func (*schemaJSONWideTestDirectory) Close() error { return nil }

type schemaJSONSingleChildTestDirectory struct {
	read     bool
	requests *[]int
}

func (directory *schemaJSONSingleChildTestDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	*directory.requests = append(*directory.requests, n)
	if directory.read {
		return nil, io.EOF
	}
	directory.read = true
	return []os.DirEntry{schemaJSONTestEntry("child")}, nil
}

func (*schemaJSONSingleChildTestDirectory) Close() error { return nil }

type schemaJSONTestEntry string

func (entry schemaJSONTestEntry) Name() string         { return string(entry) }
func (schemaJSONTestEntry) IsDir() bool                { return false }
func (schemaJSONTestEntry) Type() os.FileMode          { return 0 }
func (schemaJSONTestEntry) Info() (os.FileInfo, error) { return nil, nil }

func createSchemaJSONDirectoryRedirect(t *testing.T, path, target string) bool {
	t.Helper()
	if err := os.Symlink(target, path); err == nil {
		t.Cleanup(func() { _ = os.Remove(path) })
		return true
	} else if runtime.GOOS != "windows" {
		t.Fatalf("create schema directory symlink: %v", err)
	}
	command := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", path, target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Logf("Windows junction fixture unavailable: %v (%s)", err, strings.TrimSpace(string(output)))
		return false
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return true
}

func writeSchemaJSONFixture(t *testing.T, root, relative string, raw []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
