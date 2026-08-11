package sourcequalification

// Tests-first contract for the RFC-0002 preconstruction attempt artifact.
// Production is expected to provide:
//
//	type qualificationAttemptTombstone struct { ... }
//	func marshalAttemptTombstone(qualificationAttemptTombstone) ([]byte, error)
//	func parseCanonicalAttemptTombstone([]byte) (qualificationAttemptTombstone, error)
//	func publishAttemptTombstone(outputDir string, qualificationAttemptTombstone) error
//
// Publication owns one exact, absent output directory and places only the
// canonical source-qualification-attempt-v1.json file in it. The directory
// and file are private until the workflow deliberately uploads that directory.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestAttemptTombstoneCanonicalWireContract(t *testing.T) {
	if attemptTombstoneFilename != "source-qualification-attempt-v1.json" {
		t.Fatalf("tombstone filename = %q", attemptTombstoneFilename)
	}
	if attemptTombstoneArtifactType != "repopass-source-qualification-attempt" {
		t.Fatalf("tombstone artifact type = %q", attemptTombstoneArtifactType)
	}
	if attemptTombstoneSchemaVersion != "1" {
		t.Fatalf("tombstone schema version = %q", attemptTombstoneSchemaVersion)
	}
	if attemptTombstoneMaxBytes != 16<<10 || attemptTombstoneMaxDepth != 4 {
		t.Fatalf("tombstone bounds = %d bytes/depth %d", attemptTombstoneMaxBytes, attemptTombstoneMaxDepth)
	}

	document := attemptTombstoneFixture()
	raw, err := marshalAttemptTombstone(document)
	if err != nil {
		t.Fatalf("marshal canonical tombstone: %v", err)
	}
	want := []byte(`{"artifactType":"repopass-source-qualification-attempt","attemptId":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:linux-amd64:1","code":"SOURCE_QUAL_SOURCE_DIRTY","expectedBaseRevision":"1111111111111111111111111111111111111111","expectedTestedRevision":"2222222222222222222222222222222222222222","expectedTreeSHA":"3333333333333333333333333333333333333333","lane":"linux-amd64","ordinal":1,"qualificationRunId":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","qualificationStatus":"FAIL","schemaVersion":"1","workflowRunAttempt":1,"workflowRunId":"123456789"}`)
	if !bytes.Equal(raw, want) {
		t.Fatalf("canonical tombstone bytes changed:\n got %s\nwant %s", raw, want)
	}
	if len(raw) == 0 || len(raw) > attemptTombstoneMaxBytes || raw[len(raw)-1] == '\n' {
		t.Fatalf("canonical tombstone is empty, oversized, or newline terminated: %d bytes", len(raw))
	}

	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"artifactType", "attemptId", "code", "expectedBaseRevision",
		"expectedTestedRevision", "expectedTreeSHA", "lane", "ordinal",
		"qualificationRunId", "qualificationStatus", "schemaVersion",
		"workflowRunAttempt", "workflowRunId",
	}
	if !attemptTombstoneHasExactKeys(shape, wantKeys) {
		t.Fatalf("tombstone does not have the exact 13-key contract: %#v", shape)
	}

	parsed, err := parseCanonicalAttemptTombstone(raw)
	if err != nil {
		t.Fatalf("parse canonical tombstone: %v", err)
	}
	if parsed != document {
		t.Fatalf("parsed tombstone differs:\n got %#v\nwant %#v", parsed, document)
	}
	replayed, err := marshalAttemptTombstone(parsed)
	if err != nil || !bytes.Equal(replayed, raw) {
		t.Fatalf("canonical tombstone replay differs: %v", err)
	}
}

func TestAttemptTombstoneFailureCodeAndStatusContract(t *testing.T) {
	valid := []struct {
		code   string
		status QualificationStatus
	}{
		{"SOURCE_QUAL_INVALID_INPUT", StatusFail},
		{"SOURCE_QUAL_SOURCE_DIRTY", StatusFail},
		{"SOURCE_QUAL_SUBJECT_MISMATCH", StatusFail},
		{"SOURCE_QUAL_ARCHIVE_INVALID", StatusFail},
		{"SOURCE_QUAL_MANIFEST_INVALID", StatusFail},
		{"SOURCE_QUAL_RECEIPT_INVALID", StatusFail},
		{"SOURCE_QUAL_GATE_SET_INVALID", StatusFail},
		{"SOURCE_QUAL_GATE_FAILED", StatusFail},
		{"SOURCE_QUAL_GATE_BLOCKED", StatusBlocked},
		{"SOURCE_QUAL_GATE_NOT_RUN", StatusNotRun},
		{"SOURCE_QUAL_PRIVACY_INVALID", StatusFail},
		{"SOURCE_QUAL_CLEANUP_FAILED", StatusFail},
		{"SOURCE_QUAL_OUTPUT_LIMIT", StatusFail},
		{"SOURCE_QUAL_DESTINATION_EXISTS", StatusFail},
	}
	statuses := []QualificationStatus{StatusPass, StatusFail, StatusBlocked, StatusNotRun, "", "fail"}
	for _, contract := range valid {
		t.Run(contract.code, func(t *testing.T) {
			document := attemptTombstoneFixture()
			document.Code = contract.code
			document.QualificationStatus = contract.status
			raw, err := marshalAttemptTombstone(document)
			if err != nil {
				t.Fatalf("valid code/status was rejected: %v", err)
			}
			if _, err := parseCanonicalAttemptTombstone(raw); err != nil {
				t.Fatalf("valid code/status did not parse: %v", err)
			}
			for _, status := range statuses {
				if status == contract.status {
					continue
				}
				invalid := document
				invalid.QualificationStatus = status
				if _, err := marshalAttemptTombstone(invalid); err == nil {
					t.Errorf("code %s accepted mismatched status %q", contract.code, status)
				}
				if _, err := parseCanonicalAttemptTombstone(attemptTombstoneCanonicalUnchecked(t, invalid)); err == nil {
					t.Errorf("parser accepted code %s with mismatched status %q", contract.code, status)
				}
			}
		})
	}

	for _, code := range []string{"", "SOURCE_QUAL_UNKNOWN", "source_qual_source_dirty", "SOURCE_QUAL_SOURCE_DIRTY\n"} {
		t.Run("unknown_"+strings.ReplaceAll(code, "\n", "LF"), func(t *testing.T) {
			document := attemptTombstoneFixture()
			document.Code = code
			if _, err := marshalAttemptTombstone(document); err == nil {
				t.Fatalf("unknown diagnostic code %q was accepted", code)
			}
			if _, err := parseCanonicalAttemptTombstone(attemptTombstoneCanonicalUnchecked(t, document)); err == nil {
				t.Fatalf("parser accepted unknown diagnostic code %q", code)
			}
		})
	}
}

func TestAttemptTombstoneRejectsInvalidIdentityAndAttemptCombinations(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*qualificationAttemptTombstone)
	}{
		{"artifact type", func(value *qualificationAttemptTombstone) { value.ArtifactType = "future" }},
		{"schema", func(value *qualificationAttemptTombstone) { value.SchemaVersion = "2" }},
		{"base uppercase", func(value *qualificationAttemptTombstone) { value.ExpectedBaseRevision = strings.Repeat("A", 40) }},
		{"base short", func(value *qualificationAttemptTombstone) { value.ExpectedBaseRevision = strings.Repeat("1", 39) }},
		{"tested nonhex", func(value *qualificationAttemptTombstone) { value.ExpectedTestedRevision = strings.Repeat("z", 40) }},
		{"tree long", func(value *qualificationAttemptTombstone) { value.ExpectedTreeSHA = strings.Repeat("3", 41) }},
		{"unknown lane", func(value *qualificationAttemptTombstone) { value.Lane = "darwin-amd64" }},
		{"zero ordinal", func(value *qualificationAttemptTombstone) {
			value.Ordinal = 0
			value.AttemptID = AttemptID(value.QualificationRunID, value.Lane, 0)
		}},
		{"negative ordinal", func(value *qualificationAttemptTombstone) {
			value.Ordinal = -1
			value.AttemptID = AttemptID(value.QualificationRunID, value.Lane, -1)
		}},
		{"ordinal int32 overflow", func(value *qualificationAttemptTombstone) {
			value.Ordinal = 2147483648
			value.AttemptID = AttemptID(value.QualificationRunID, value.Lane, 2147483648)
		}},
		{"attempt ID digest", func(value *qualificationAttemptTombstone) {
			value.AttemptID = "sha256:" + strings.Repeat("b", 64) + ":linux-amd64:1"
		}},
		{"attempt ID lane", func(value *qualificationAttemptTombstone) {
			value.AttemptID = value.QualificationRunID + ":windows-amd64:1"
		}},
		{"attempt ID ordinal", func(value *qualificationAttemptTombstone) {
			value.AttemptID = value.QualificationRunID + ":linux-amd64:01"
		}},
		{"qualification ID missing prefix", func(value *qualificationAttemptTombstone) {
			value.QualificationRunID = strings.Repeat("a", 64)
			value.AttemptID = AttemptID(value.QualificationRunID, value.Lane, 1)
		}},
		{"qualification ID uppercase", func(value *qualificationAttemptTombstone) {
			value.QualificationRunID = "sha256:" + strings.Repeat("A", 64)
			value.AttemptID = AttemptID(value.QualificationRunID, value.Lane, 1)
		}},
		{"qualification ID short", func(value *qualificationAttemptTombstone) {
			value.QualificationRunID = "sha256:" + strings.Repeat("a", 63)
			value.AttemptID = AttemptID(value.QualificationRunID, value.Lane, 1)
		}},
		{"workflow run empty", func(value *qualificationAttemptTombstone) { value.WorkflowRunID = "" }},
		{"workflow run leading zero", func(value *qualificationAttemptTombstone) { value.WorkflowRunID = "0123" }},
		{"workflow run sign", func(value *qualificationAttemptTombstone) { value.WorkflowRunID = "+123" }},
		{"workflow run nondigit", func(value *qualificationAttemptTombstone) { value.WorkflowRunID = "123x" }},
		{"workflow run over 20 digits", func(value *qualificationAttemptTombstone) { value.WorkflowRunID = strings.Repeat("9", 21) }},
		{"workflow attempt zero", func(value *qualificationAttemptTombstone) { value.WorkflowRunAttempt = 0 }},
		{"workflow attempt negative", func(value *qualificationAttemptTombstone) { value.WorkflowRunAttempt = -1 }},
		{"workflow attempt int32 overflow", func(value *qualificationAttemptTombstone) { value.WorkflowRunAttempt = 2147483648 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			document := attemptTombstoneFixture()
			test.mutate(&document)
			if _, err := marshalAttemptTombstone(document); err == nil {
				t.Fatal("marshal accepted invalid tombstone")
			}
			raw := attemptTombstoneCanonicalUnchecked(t, document)
			if _, err := parseCanonicalAttemptTombstone(raw); err == nil {
				t.Fatal("parser accepted invalid tombstone")
			}
		})
	}

	for _, lane := range []Lane{LaneLinuxAMD64, LaneWindowsAMD64} {
		for _, ordinal := range []int64{1, 2, 2147483647} {
			document := attemptTombstoneFixture()
			document.Lane = lane
			document.Ordinal = ordinal
			document.AttemptID = AttemptID(document.QualificationRunID, lane, int(ordinal))
			if _, err := marshalAttemptTombstone(document); err != nil {
				t.Errorf("valid lane/ordinal %s/%d rejected: %v", lane, ordinal, err)
			} else if _, err := parseCanonicalAttemptTombstone(attemptTombstoneCanonicalUnchecked(t, document)); err != nil {
				t.Errorf("parser rejected valid lane/ordinal %s/%d: %v", lane, ordinal, err)
			}
		}
	}
	for _, workflowAttempt := range []int64{1, 2, 2147483647} {
		document := attemptTombstoneFixture()
		document.WorkflowRunAttempt = workflowAttempt
		document.Ordinal = 2147483647
		document.AttemptID = AttemptID(document.QualificationRunID, document.Lane, int(document.Ordinal))
		if _, err := marshalAttemptTombstone(document); err != nil {
			t.Errorf("valid workflow run attempt %d rejected: %v", workflowAttempt, err)
		} else if _, err := parseCanonicalAttemptTombstone(attemptTombstoneCanonicalUnchecked(t, document)); err != nil {
			t.Errorf("parser rejected valid workflow run attempt %d: %v", workflowAttempt, err)
		}
	}
	boundary := attemptTombstoneFixture()
	boundary.WorkflowRunID = strings.Repeat("9", 20)
	if _, err := marshalAttemptTombstone(boundary); err != nil {
		t.Fatalf("20-digit workflow run ID was rejected: %v", err)
	}
}

func TestAttemptTombstoneRejectsWrongJSONTypes(t *testing.T) {
	raw, err := marshalAttemptTombstone(attemptTombstoneFixture())
	if err != nil {
		t.Fatal(err)
	}
	object := attemptTombstoneDecodeObject(t, raw)
	wrongTypes := map[string]any{
		"artifactType":           false,
		"attemptId":              int64(1),
		"code":                   nil,
		"expectedBaseRevision":   []any{},
		"expectedTestedRevision": map[string]any{},
		"expectedTreeSHA":        true,
		"lane":                   int64(1),
		"ordinal":                "1",
		"qualificationRunId":     false,
		"qualificationStatus":    int64(1),
		"schemaVersion":          nil,
		"workflowRunAttempt":     "1",
		"workflowRunId":          int64(123456789),
	}
	for field, wrong := range wrongTypes {
		t.Run(field, func(t *testing.T) {
			candidate := make(map[string]any, len(object))
			for name, value := range object {
				candidate[name] = value
			}
			candidate[field] = wrong
			if _, err := parseCanonicalAttemptTombstone(attemptTombstoneMarshalObject(t, candidate)); err == nil {
				t.Fatal("parser accepted a field with the wrong JSON type")
			}
		})
	}
}

func TestAttemptTombstoneParserRejectsUnknownDuplicateAndNoncanonicalJSON(t *testing.T) {
	canonical, err := marshalAttemptTombstone(attemptTombstoneFixture())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"artifactType":"repopass-source-qualification-attempt",`), canonical[1:]...)
	unknown := attemptTombstoneDecodeObject(t, canonical)
	unknown["error"] = `C:\Users\runneradmin\private\raw.log`
	missing := attemptTombstoneDecodeObject(t, canonical)
	delete(missing, "code")
	tooDeep := attemptTombstoneDecodeObject(t, canonical)
	tooDeep["extra"] = []any{[]any{[]any{[]any{[]any{"private"}}}}}

	firstComma := bytes.IndexByte(canonical, ',')
	secondRelative := bytes.IndexByte(canonical[firstComma+1:], ',')
	if firstComma < 0 || secondRelative < 0 {
		t.Fatal("canonical fixture does not contain enough fields")
	}
	secondComma := firstComma + 1 + secondRelative
	reordered := make([]byte, 0, len(canonical))
	reordered = append(reordered, '{')
	reordered = append(reordered, canonical[firstComma+1:secondComma]...)
	reordered = append(reordered, ',')
	reordered = append(reordered, canonical[1:firstComma]...)
	reordered = append(reordered, canonical[secondComma:]...)

	cases := map[string][]byte{
		"duplicate top-level key": duplicate,
		"unknown field":           attemptTombstoneMarshalObject(t, unknown),
		"missing field":           attemptTombstoneMarshalObject(t, missing),
		"reordered keys":          reordered,
		"leading BOM":             append([]byte{0xef, 0xbb, 0xbf}, canonical...),
		"leading whitespace":      append([]byte(" "), canonical...),
		"internal whitespace":     append([]byte("{ "), canonical[1:]...),
		"trailing newline":        append(bytes.Clone(canonical), '\n'),
		"trailing CRLF":           append(bytes.Clone(canonical), '\r', '\n'),
		"invalid UTF-8":           append([]byte{0xff}, canonical...),
		"noncanonical escape":     bytes.Replace(canonical, []byte("SOURCE_QUAL_SOURCE_DIRTY"), []byte(`SOURCE_QUAL_SOURCE_\u0044IRTY`), 1),
		"excess nesting":          attemptTombstoneMarshalObject(t, tooDeep),
		"empty":                   nil,
		"oversized":               bytes.Repeat([]byte{'x'}, attemptTombstoneMaxBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCanonicalAttemptTombstone(raw); err == nil {
				t.Fatal("parser accepted malformed, noncanonical, or out-of-bounds tombstone")
			}
		})
	}
}

func TestAttemptTombstoneContainsNoFreeTextOrPrivatePathChannel(t *testing.T) {
	secret := `C:\Users\runneradmin\work\_temp\raw-stderr-token.txt`
	mutations := []func(*qualificationAttemptTombstone){
		func(value *qualificationAttemptTombstone) { value.ArtifactType = secret },
		func(value *qualificationAttemptTombstone) { value.AttemptID = secret },
		func(value *qualificationAttemptTombstone) { value.Code = secret },
		func(value *qualificationAttemptTombstone) { value.ExpectedBaseRevision = secret },
		func(value *qualificationAttemptTombstone) { value.ExpectedTestedRevision = secret },
		func(value *qualificationAttemptTombstone) { value.ExpectedTreeSHA = secret },
		func(value *qualificationAttemptTombstone) { value.Lane = Lane(secret) },
		func(value *qualificationAttemptTombstone) { value.QualificationRunID = secret },
		func(value *qualificationAttemptTombstone) { value.QualificationStatus = QualificationStatus(secret) },
		func(value *qualificationAttemptTombstone) { value.SchemaVersion = secret },
		func(value *qualificationAttemptTombstone) { value.WorkflowRunID = secret },
	}
	for index, mutate := range mutations {
		document := attemptTombstoneFixture()
		mutate(&document)
		if _, err := marshalAttemptTombstone(document); err == nil {
			t.Errorf("private path channel %d was accepted", index)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("diagnostic echoed private path for channel %d", index)
		}
	}

	object := attemptTombstoneDecodeObject(t, attemptTombstoneCanonicalUnchecked(t, attemptTombstoneFixture()))
	for _, key := range []string{"error", "message", "output", "path", "stderr", "stdout", "environment"} {
		t.Run(key, func(t *testing.T) {
			candidate := make(map[string]any, len(object)+1)
			for name, value := range object {
				candidate[name] = value
			}
			candidate[key] = secret
			if _, err := parseCanonicalAttemptTombstone(attemptTombstoneMarshalObject(t, candidate)); err == nil {
				t.Fatal("parser accepted a free-text/private-data field")
			} else if strings.Contains(err.Error(), secret) {
				t.Fatal("parser diagnostic echoed private field bytes")
			}
		})
	}
}

func TestPublishAttemptTombstoneCreatesPrivateExactSingleFileArtifact(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "attempt-artifact")
	document := attemptTombstoneFixture()
	want, err := marshalAttemptTombstone(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishAttemptTombstone(output, document); err != nil {
		t.Fatalf("publish tombstone: %v", err)
	}

	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 1 || entries[0].Name() != attemptTombstoneFilename || !entries[0].Type().IsRegular() {
		t.Fatalf("published artifact inventory is not one exact regular file: entries=%v err=%v", entries, err)
	}
	if err := requirePrivatePackageDirectory(output); err != nil {
		t.Fatalf("published tombstone directory is not private: %v", err)
	}
	path := filepath.Join(output, attemptTombstoneFilename)
	file, err := openPackageRegularFile(path)
	if err != nil {
		t.Fatalf("open published tombstone safely: %v", err)
	}
	info, statErr := file.Stat()
	privacyErr := error(nil)
	if statErr == nil {
		privacyErr = validatePrivatePackagePermissions(file, info, false)
	}
	closeErr := file.Close()
	if statErr != nil || privacyErr != nil || closeErr != nil {
		t.Fatalf("published tombstone file is not private: stat=%v privacy=%v close=%v", statErr, privacyErr, closeErr)
	}
	raw, _, err := readStablePackageFile(path, int64(attemptTombstoneMaxBytes), want)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("published tombstone differs from canonical bytes: %v", err)
	}
	if parsed, err := parseCanonicalAttemptTombstone(raw); err != nil || parsed != document {
		t.Fatalf("published tombstone is not canonical and bound: parsed=%#v err=%v", parsed, err)
	}
}

func TestPublishAttemptTombstoneNeverOverwritesOrRepairsExistingDestination(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			output := filepath.Join(parent, "attempt-artifact")
			sentinel := output
			if kind == "directory" {
				if err := os.Mkdir(output, 0o755); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(output, "keep.txt")
			}
			if err := os.WriteFile(sentinel, []byte("preexisting\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			err := publishAttemptTombstone(output, attemptTombstoneFixture())
			if err == nil {
				t.Fatalf("publisher replaced a preexisting %s", kind)
			}
			if strings.Contains(err.Error(), output) || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("publication diagnostic exposed a private path: %v", err)
			}
			if got, readErr := os.ReadFile(sentinel); readErr != nil || !bytes.Equal(got, []byte("preexisting\n")) {
				t.Fatalf("preexisting destination was mutated: %q, %v", got, readErr)
			}
		})
	}
}

func TestPublishAttemptTombstoneRejectsPreexistingSymlinkWithoutFollowingIt(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target.txt")
	if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "attempt-artifact")
	if err := os.Symlink(target, output); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := publishAttemptTombstone(output, attemptTombstoneFixture()); err == nil {
		t.Fatal("publisher accepted a preexisting symlink destination")
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, []byte("target\n")) {
		t.Fatalf("publisher followed or changed symlink target: %q, %v", got, err)
	}
	info, err := os.Lstat(output)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("publisher replaced preexisting symlink: %v, %v", info, err)
	}
}

func TestPublishAttemptTombstoneValidatesBeforeCreatingDestination(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "must-remain-absent")
	document := attemptTombstoneFixture()
	document.Code = `C:\private\raw-output.log`
	if err := publishAttemptTombstone(output, document); err == nil {
		t.Fatal("publisher accepted invalid tombstone")
	} else if strings.Contains(err.Error(), document.Code) || strings.Contains(err.Error(), output) {
		t.Fatalf("publication diagnostic exposed private input: %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("invalid tombstone left a publication destination: %v", err)
	}
}

func FuzzParseCanonicalAttemptTombstone(f *testing.F) {
	document := attemptTombstoneFixture()
	canonical, err := marshalAttemptTombstone(document)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(canonical)
	f.Add(append(bytes.Clone(canonical), '\n'))
	f.Add(append([]byte(`{"code":"SOURCE_QUAL_SOURCE_DIRTY",`), canonical[1:]...))
	f.Add([]byte(`{"artifactType":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > attemptTombstoneMaxBytes+1 {
			return
		}
		parsed, err := parseCanonicalAttemptTombstone(raw)
		if err != nil {
			return
		}
		replayed, err := marshalAttemptTombstone(parsed)
		if err != nil {
			t.Fatalf("parser accepted a tombstone the emitter rejects: %v", err)
		}
		if !bytes.Equal(replayed, raw) {
			t.Fatal("parser accepted noncanonical tombstone bytes")
		}
	})
}

func attemptTombstoneFixture() qualificationAttemptTombstone {
	qualificationRunID := "sha256:" + strings.Repeat("a", 64)
	return qualificationAttemptTombstone{
		ArtifactType:           "repopass-source-qualification-attempt",
		AttemptID:              qualificationRunID + ":linux-amd64:1",
		Code:                   "SOURCE_QUAL_SOURCE_DIRTY",
		ExpectedBaseRevision:   strings.Repeat("1", 40),
		ExpectedTestedRevision: strings.Repeat("2", 40),
		ExpectedTreeSHA:        strings.Repeat("3", 40),
		Lane:                   LaneLinuxAMD64,
		Ordinal:                1,
		QualificationRunID:     qualificationRunID,
		QualificationStatus:    StatusFail,
		SchemaVersion:          "1",
		WorkflowRunAttempt:     1,
		WorkflowRunID:          "123456789",
	}
}

func attemptTombstoneCanonicalUnchecked(t *testing.T, document qualificationAttemptTombstone) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func attemptTombstoneDecodeObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func attemptTombstoneMarshalObject(t *testing.T, object map[string]any) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func attemptTombstoneHasExactKeys(object map[string]any, keys []string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}
