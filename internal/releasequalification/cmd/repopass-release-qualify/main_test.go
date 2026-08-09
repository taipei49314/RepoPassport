package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunEmitsExactFailureCodesAndExecutionOrderWithoutPrivatePaths(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"repopass-linux-amd64",
		"repopass-windows-amd64.exe",
		"repopass-verify-linux-amd64",
		"repopass-verify-windows-amd64.exe",
		"repopass-kit-host.exe",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("not a Go executable\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	revision := strings.Repeat("1", 40)
	tree := strings.Repeat("2", 40)
	var output bytes.Buffer
	if code := run([]string{
		"-phase", "pre-helper",
		"-root", root,
		"-tested-revision", revision,
		"-tree", tree,
	}, &output); code == 0 {
		t.Fatal("invalid executables returned success")
	}
	if strings.Contains(output.String(), root) || strings.Contains(output.String(), filepath.ToSlash(root)) {
		t.Fatalf("qualification output leaked private root: %s", output.String())
	}

	records := decodeOutputRecords(t, output.Bytes())
	firstFailures := 0
	for _, record := range records {
		if record["status"] != "FAIL" || record["code"] != "BUILD_INFO_UNREADABLE" {
			t.Fatalf("failure record lost exact RFC status/code: %#v", record)
		}
		if first, _ := record["firstFailure"].(bool); first {
			firstFailures++
			if record["id"] != "full-linux-amd64" {
				t.Fatalf("execution-order first failure = %#v", record)
			}
		}
	}
	if firstFailures != 1 {
		t.Fatalf("firstFailure markers = %d, want exactly one", firstFailures)
	}
}

func TestRunLabelsInvalidInputNotRunWithoutEchoingInput(t *testing.T) {
	private := filepath.Join(t.TempDir(), "private-marker")
	var output bytes.Buffer
	if code := run([]string{"-phase", "bad", "-root", private}, &output); code == 0 {
		t.Fatal("invalid input returned success")
	}
	if strings.Contains(output.String(), private) || strings.Contains(output.String(), filepath.ToSlash(private)) {
		t.Fatalf("input failure leaked private root: %s", output.String())
	}
	records := decodeOutputRecords(t, output.Bytes())
	if len(records) != 1 || records[0]["status"] != "NOT_RUN" || records[0]["code"] != "REQUIRED_CHECK_NOT_RUN" {
		t.Fatalf("invalid input record = %#v", records)
	}
}

func TestPublishQualifiedDirectoryAllowsOnlySameParentAtomicDistRename(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, ".release-sealed-0123456789abcdef")
	destination := filepath.Join(parent, "dist")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishQualifiedDirectory(source, destination); err != nil {
		t.Fatalf("same-parent dist publication failed: %v", err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after atomic publication: %v", err)
	}
	if info, err := os.Lstat(destination); err != nil || !info.IsDir() {
		t.Fatalf("destination missing after atomic publication: %v", err)
	}
}

func TestWriteQualificationBeforePublicationFailureLeavesNoDist(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, ".release-sealed-write-failure")
	destination := filepath.Join(parent, "dist")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	writer := &failingWriter{err: io.ErrClosedPipe}
	if err := writeQualificationThenPublish(writer, []byte("allowlisted record\n"), source, destination); err == nil {
		t.Fatal("failed qualification output unexpectedly published")
	}
	if info, err := os.Lstat(source); err != nil || !info.IsDir() {
		t.Fatalf("source was not retained after output failure: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("dist exists after output failure: %v", err)
	}
}

func TestWriteQualificationThenAtomicPublicationHasNoPostRenameWrite(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, ".release-sealed-write-success")
	destination := filepath.Join(parent, "dist")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeQualificationThenPublish(&output, []byte("allowlisted record\n"), source, destination); err != nil {
		t.Fatal(err)
	}
	if output.String() != "allowlisted record\n" {
		t.Fatalf("qualification output = %q", output.String())
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after publication: %v", err)
	}
	if info, err := os.Lstat(destination); err != nil || !info.IsDir() {
		t.Fatalf("destination missing after publication: %v", err)
	}
}

func TestPublishQualifiedDirectoryRejectsPathScopeAndOverwrite(t *testing.T) {
	parent := t.TempDir()
	tests := []struct {
		name        string
		source      string
		destination string
	}{
		{"wrong source prefix", filepath.Join(parent, ".release-publish-a"), filepath.Join(parent, "dist")},
		{"wrong destination name", filepath.Join(parent, ".release-sealed-a"), filepath.Join(parent, "other")},
		{"different parent", filepath.Join(parent, ".release-sealed-b"), filepath.Join(t.TempDir(), "dist")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Mkdir(test.source, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := publishQualifiedDirectory(test.source, test.destination); err == nil {
				t.Fatal("out-of-scope publication path accepted")
			}
		})
	}

	source := filepath.Join(parent, ".release-sealed-c")
	destination := filepath.Join(parent, "dist")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishQualifiedDirectory(source, destination); err == nil {
		t.Fatal("existing publication destination was overwritten")
	}
}

func decodeOutputRecords(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []map[string]any
	for {
		var record map[string]any
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(record))
		for key := range record {
			keys = append(keys, key)
		}
		if !sameKeySet(keys, []string{"code", "firstFailure", "id", "revision", "sha256", "status", "tree"}) {
			t.Fatalf("output keys = %q, want exact allowlist", keys)
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		t.Fatal("qualification emitted no records")
	}
	return records
}

func sameKeySet(left, right []string) bool {
	set := func(values []string) map[string]bool {
		result := make(map[string]bool, len(values))
		for _, value := range values {
			result[value] = true
		}
		return result
	}
	return reflect.DeepEqual(set(left), set(right))
}

type failingWriter struct {
	err error
}

func (writer *failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}
