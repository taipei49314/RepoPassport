package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestDecodeCleanupInventoryAcceptsStrictValidControl(t *testing.T) {
	entries := []cleanupInventoryEntry{
		{Path: "artifact.json", Type: "file", Mode: 0o644},
		{Path: "reports", Type: "directory", Mode: 0o755},
		{Path: "reports/result.txt", Type: "file", Mode: 0o600},
	}

	got, err := decodeCleanupInventory(cleanupInventoryControlJSON(t, entries))
	if err != nil {
		t.Fatalf("decodeCleanupInventory() error = %v", err)
	}
	if !reflect.DeepEqual(got.Entries, entries) {
		t.Fatalf("decoded entries = %#v, want %#v", got.Entries, entries)
	}
}

func TestDecodeCleanupInventoryRejectsAmbiguousOrMalformedControl(t *testing.T) {
	valid := cleanupInventoryControlJSON(t, []cleanupInventoryEntry{{
		Path: "artifact.json",
		Type: "file",
		Mode: 0o644,
	}})

	unknown := cleanupInventoryControlMap([]cleanupInventoryEntry{{
		Path: "artifact.json",
		Type: "file",
		Mode: 0o644,
	}})
	unknown["unexpected"] = true

	missing := cleanupInventoryControlMap([]cleanupInventoryEntry{{
		Path: "artifact.json",
		Type: "file",
		Mode: 0o644,
	}})
	delete(missing, "scope")

	nullValue := cleanupInventoryControlMap([]cleanupInventoryEntry{{
		Path: "artifact.json",
		Type: "file",
		Mode: 0o644,
	}})
	nullValue["scope"] = nil

	missingTimestamp := cleanupInventoryControlMap([]cleanupInventoryEntry{{
		Path: "artifact.json",
		Type: "file",
		Mode: 0o644,
	}})
	missingTimestampIdentity := missingTimestamp["rootBefore"].(cleanupInventoryIdentity)
	missingTimestamp["rootBefore"] = map[string]any{
		"device":  missingTimestampIdentity.Device,
		"inode":   missingTimestampIdentity.Inode,
		"mode":    missingTimestampIdentity.Mode,
		"mtimeNs": missingTimestampIdentity.MtimeNS,
	}

	mutatedRoot := cleanupInventoryControlMap([]cleanupInventoryEntry{{
		Path: "artifact.json",
		Type: "file",
		Mode: 0o644,
	}})
	mutatedIdentity := mutatedRoot["rootAfter"].(cleanupInventoryIdentity)
	mutatedIdentity.MtimeNS = "5"
	mutatedRoot["rootAfter"] = mutatedIdentity

	duplicate := bytes.Replace(
		valid,
		[]byte(`"scope":"/outputs"`),
		[]byte(`"scope":"/outputs","scope":"/outputs"`),
		1,
	)
	if bytes.Equal(duplicate, valid) {
		t.Fatal("test fixture did not inject a duplicate key")
	}

	invalidUTF8 := cleanupInventoryControlJSON(t, []cleanupInventoryEntry{{
		Path: "INVALID_UTF8",
		Type: "file",
		Mode: 0o644,
	}})
	invalidUTF8 = bytes.Replace(
		invalidUTF8,
		[]byte("INVALID_UTF8"),
		[]byte{0xff},
		1,
	)

	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "unknown key",
			raw:  cleanupMarshalControl(t, unknown),
		},
		{
			name: "duplicate key",
			raw:  duplicate,
		},
		{
			name: "missing key",
			raw:  cleanupMarshalControl(t, missing),
		},
		{
			name: "null value",
			raw:  cleanupMarshalControl(t, nullValue),
		},
		{
			name: "missing root timestamp",
			raw:  cleanupMarshalControl(t, missingTimestamp),
		},
		{
			name: "root membership timestamp changed",
			raw:  cleanupMarshalControl(t, mutatedRoot),
		},
		{
			name: "trailing value",
			raw:  append(append([]byte(nil), valid...), []byte(` true`)...),
		},
		{
			name: "invalid UTF-8",
			raw:  invalidUTF8,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireCleanupInventoryFailure(t, test.raw, "invalid-control")
		})
	}
}

func TestDecodeCleanupInventoryRejectsOrderingAndCountMismatch(t *testing.T) {
	tests := []struct {
		name  string
		raw   []byte
		class string
	}{
		{
			name: "unsorted",
			raw: cleanupInventoryControlJSON(t, []cleanupInventoryEntry{
				{Path: "z-last", Type: "file", Mode: 0o644},
				{Path: "a-first", Type: "file", Mode: 0o644},
			}),
			class: "unsorted-or-duplicate",
		},
		{
			name: "duplicate path",
			raw: cleanupInventoryControlJSON(t, []cleanupInventoryEntry{
				{Path: "same", Type: "directory", Mode: 0o755},
				{Path: "same", Type: "file", Mode: 0o644},
			}),
			class: "unsorted-or-duplicate",
		},
		{
			name: "count mismatch",
			raw: cleanupInventoryControlJSONWithCount(
				t,
				2,
				[]cleanupInventoryEntry{{
					Path: "only-entry",
					Type: "file",
					Mode: 0o644,
				}},
			),
			class: "count-mismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireCleanupInventoryFailure(t, test.raw, test.class)
		})
	}
}

func TestDecodeCleanupInventoryEnforcesEntryPathAndDepthBoundaries(
	t *testing.T,
) {
	maxEntries := make([]cleanupInventoryEntry, cleanupInventoryMaxEntries)
	for index := range maxEntries {
		maxEntries[index] = cleanupInventoryEntry{
			Path: fmt.Sprintf("entry-%04d", index),
			Type: "file",
			Mode: 0o7777,
		}
	}
	got, err := decodeCleanupInventory(
		cleanupInventoryControlJSON(t, maxEntries),
	)
	if err != nil {
		t.Fatalf("maximum entry count rejected: %v", err)
	}
	if len(got.Entries) != cleanupInventoryMaxEntries {
		t.Fatalf(
			"decoded entry count = %d, want %d",
			len(got.Entries),
			cleanupInventoryMaxEntries,
		)
	}

	tooManyEntries := append(
		append([]cleanupInventoryEntry(nil), maxEntries...),
		cleanupInventoryEntry{
			Path: "entry-overflow",
			Type: "file",
			Mode: 0o644,
		},
	)
	requireCleanupInventoryFailure(
		t,
		cleanupInventoryControlJSON(t, tooManyEntries),
		"entry-limit",
	)

	maxPath := strings.Repeat("a", cleanupInventoryMaxPathBytes)
	if _, err := decodeCleanupInventory(cleanupInventoryControlJSON(
		t,
		[]cleanupInventoryEntry{{
			Path: maxPath,
			Type: "file",
			Mode: 0o7777,
		}},
	)); err != nil {
		t.Fatalf("maximum path length rejected: %v", err)
	}
	requireCleanupInventoryFailure(
		t,
		cleanupInventoryControlJSON(t, []cleanupInventoryEntry{{
			Path: strings.Repeat("a", cleanupInventoryMaxPathBytes+1),
			Type: "file",
			Mode: 0o644,
		}}),
		"invalid-entry",
	)

	maxDepth := strings.Repeat("a/", cleanupInventoryMaxDepth-1) + "a"
	if _, err := decodeCleanupInventory(cleanupInventoryControlJSON(
		t,
		[]cleanupInventoryEntry{{
			Path: maxDepth,
			Type: "file",
			Mode: 0o644,
		}},
	)); err != nil {
		t.Fatalf("maximum path depth rejected: %v", err)
	}
	requireCleanupInventoryFailure(
		t,
		cleanupInventoryControlJSON(t, []cleanupInventoryEntry{{
			Path: strings.Repeat("a/", cleanupInventoryMaxDepth) + "a",
			Type: "file",
			Mode: 0o644,
		}}),
		"invalid-entry",
	)
}

func TestClassifyCleanupInventoryVerdictsAndCounts(t *testing.T) {
	tests := []struct {
		name           string
		inventory      cleanupInventory
		allowedResidue []string
		wantVerdict    domain.CleanupVerdict
		wantFiles      int
		wantDirs       int
		wantSymlinks   int
		wantSpecial    int
		wantUnmatched  int
	}{
		{
			name:        "clean",
			inventory:   cleanupInventory{Entries: []cleanupInventoryEntry{}},
			wantVerdict: domain.CleanupClean,
		},
		{
			name: "allowed regular residue",
			inventory: cleanupInventory{Entries: []cleanupInventoryEntry{
				{Path: "artifact.json", Type: "file", Mode: 0o644},
				{Path: "reports", Type: "directory", Mode: 0o755},
			}},
			allowedResidue: []string{containerOutputs + "/**"},
			wantVerdict:    domain.CleanupAllowedResidue,
			wantFiles:      1,
			wantDirs:       1,
		},
		{
			name: "empty allowlist rejects regular residue",
			inventory: cleanupInventory{Entries: []cleanupInventoryEntry{
				{Path: "artifact.json", Type: "file", Mode: 0o644},
			}},
			wantVerdict:   domain.CleanupUndeclaredResidue,
			wantFiles:     1,
			wantUnmatched: 1,
		},
		{
			name: "special and symlink residue is always undeclared",
			inventory: cleanupInventory{Entries: []cleanupInventoryEntry{
				{Path: "link", Type: "symlink", Mode: 0o777},
				{Path: "pipe", Type: "fifo", Mode: 0o600},
			}},
			allowedResidue: []string{containerOutputs + "/**"},
			wantVerdict:    domain.CleanupUndeclaredResidue,
			wantSymlinks:   1,
			wantSpecial:    1,
			wantUnmatched:  2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary := classifyCleanupInventory(
				test.inventory,
				test.allowedResidue,
				bytes.NewReader(bytes.Repeat(
					[]byte{0x42},
					cleanupInventoryTokenKeyBytes,
				)),
			)
			if summary.Verdict != test.wantVerdict ||
				summary.EntryCount != len(test.inventory.Entries) ||
				summary.RegularFileCount != test.wantFiles ||
				summary.DirectoryCount != test.wantDirs ||
				summary.SymlinkCount != test.wantSymlinks ||
				summary.SpecialCount != test.wantSpecial ||
				summary.UnmatchedCount != test.wantUnmatched {
				t.Fatalf("classification summary = %#v", summary)
			}
			if !cleanupTokenPattern.MatchString(summary.OpaqueToken) {
				t.Fatalf(
					"opaque token = %q, want hmac-sha256 plus 64 lowercase hex",
					summary.OpaqueToken,
				)
			}
			if summary.Failure != "" {
				t.Fatalf("unexpected classification failure %q", summary.Failure)
			}
		})
	}
}

func TestClassifyCleanupInventoryFailsClosedWhenRandomnessUnavailable(
	t *testing.T,
) {
	summary := classifyCleanupInventory(
		cleanupInventory{Entries: []cleanupInventoryEntry{{
			Path: "artifact.json",
			Type: "file",
			Mode: 0o644,
		}}},
		[]string{containerOutputs + "/**"},
		cleanupAlwaysErrorReader{},
	)
	if summary.Verdict != domain.CleanupNotTested ||
		summary.Failure != "random-unavailable" ||
		summary.OpaqueToken != "" {
		t.Fatalf("randomness failure summary = %#v", summary)
	}
}

func TestCleanupResiduePublicEvidenceIsAggregateOnly(t *testing.T) {
	privateValues := []string{
		"private/residue.json",
		"symlink-target-etc-passwd",
		"file-content-super-secret",
		"helper-stderr-private-token",
	}
	inventory := cleanupInventory{Entries: []cleanupInventoryEntry{
		{Path: privateValues[0], Type: "file", Mode: 0o600},
		{Path: privateValues[1], Type: "symlink", Mode: 0o777},
		{Path: privateValues[2], Type: "file", Mode: 0o600},
		{Path: privateValues[3], Type: "fifo", Mode: 0o600},
	}}
	key := bytes.Repeat([]byte{0xab}, cleanupInventoryTokenKeyBytes)
	summary := classifyCleanupInventory(
		inventory,
		[]string{},
		bytes.NewReader(key),
	)
	if summary.Verdict != domain.CleanupUndeclaredResidue {
		t.Fatalf("cleanup verdict = %q", summary.Verdict)
	}
	if !cleanupTokenPattern.MatchString(summary.OpaqueToken) {
		t.Fatalf("opaque inventory token = %q", summary.OpaqueToken)
	}

	observation := cleanupResidueObservation(
		&PreparedRun{},
		summary,
		time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC),
	)
	finding := cleanupResidueFinding(summary)
	if finding == nil {
		t.Fatal("cleanupResidueFinding() = nil for undeclared residue")
	}
	technical := cleanupTechnicalError(
		"Cleanup inventory could not be verified.",
		"dirty-stderr",
		errors.New(privateValues[3]),
	)
	public, err := json.Marshal(struct {
		Observation domain.ObservationEvent `json:"observation"`
		Finding     *domain.Error           `json:"finding"`
		Technical   *domain.Error           `json:"technical"`
	}{
		Observation: observation,
		Finding:     finding,
		Technical:   technical,
	})
	if err != nil {
		t.Fatalf("marshal public cleanup evidence: %v", err)
	}
	for _, privateValue := range privateValues {
		if bytes.Contains(public, []byte(privateValue)) {
			t.Fatalf(
				"public cleanup evidence leaked private value %q: %s",
				privateValue,
				public,
			)
		}
	}
	if bytes.Contains(public, []byte(strings.Repeat("ab", len(key)))) {
		t.Fatalf("public cleanup evidence leaked the ephemeral HMAC key: %s", public)
	}
	if len(finding.EvidenceRefs) != 0 {
		t.Fatalf(
			"cleanup finding must not reference an unopenable token: %#v",
			finding.EvidenceRefs,
		)
	}
	details := observation.Details
	if details["opaqueInventoryToken"] != summary.OpaqueToken ||
		details["tokenScheme"] !=
			"ephemeral-keyed-hmac-sha256" {
		t.Fatalf("cleanup observation opaque token details = %#v", details)
	}
	for _, forbiddenKey := range []string{
		"path",
		"paths",
		"target",
		"content",
		"stdout",
		"stderr",
		"helperOutput",
	} {
		if _, exists := details[forbiddenKey]; exists {
			t.Fatalf(
				"cleanup observation contains forbidden detail %q: %#v",
				forbiddenKey,
				details,
			)
		}
	}
}

func TestCleanupHelperScriptsUseBoundedNoFollowStreamingTraversal(
	t *testing.T,
) {
	tests := []struct {
		name       string
		script     string
		required   []string
		prohibited []string
	}{
		{
			name:   "node disposable removal",
			script: nodeCleanupDisposableScript,
			required: []string{
				"LIMIT=2048",
				"opendirSync",
				"directory.readSync()",
				"C.O_NOFOLLOW",
			},
			prohibited: []string{
				"readdirSync",
				"rmSync",
				"readFileSync",
			},
		},
		{
			name:   "node inventory",
			script: nodeCleanupInventoryScript,
			required: []string{
				"MAX_ENTRIES=2048",
				"MAX_PATH=1024",
				"MAX_DEPTH=64",
				"opendirSync",
				"directory.readSync()",
				"C.O_NOFOLLOW",
				"ctimeNs",
				"mtimeNs",
				"rootAfter:identity(after)",
			},
			prohibited: []string{
				"readdirSync",
				"rmSync",
				"readFileSync",
				"rootAfter:identity(before)",
			},
		},
		{
			name:   "python disposable removal",
			script: pythonCleanupDisposableScript,
			required: []string{
				"LIMIT=2048",
				"os.scandir(fd)",
				"os.O_NOFOLLOW",
			},
			prohibited: []string{
				"shutil.rmtree",
				"list(os.scandir",
				".read(",
			},
		},
		{
			name:   "python inventory",
			script: pythonCleanupInventoryScript,
			required: []string{
				"MAX_ENTRIES=2048",
				"MAX_PATH=1024",
				"MAX_DEPTH=64",
				"os.scandir(fd)",
				"os.O_NOFOLLOW",
				"st_ctime_ns",
				"st_mtime_ns",
				`"rootAfter":identity(after)`,
			},
			prohibited: []string{
				"shutil.rmtree",
				"list(os.scandir",
				".read(",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, required := range test.required {
				if !strings.Contains(test.script, required) {
					t.Errorf("helper script is missing %q", required)
				}
			}
			for _, prohibited := range test.prohibited {
				if strings.Contains(test.script, prohibited) {
					t.Errorf("helper script contains prohibited %q", prohibited)
				}
			}
		})
	}
}

var cleanupTokenPattern = regexp.MustCompile(
	`^hmac-sha256:[0-9a-f]{64}$`,
)

type cleanupAlwaysErrorReader struct{}

func (cleanupAlwaysErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func cleanupInventoryControlMap(
	entries []cleanupInventoryEntry,
) map[string]any {
	entryCopy := make([]cleanupInventoryEntry, len(entries))
	copy(entryCopy, entries)
	identity := cleanupInventoryIdentity{
		Device:  "1",
		Inode:   "2",
		Mode:    0o777,
		CtimeNS: "3",
		MtimeNS: "4",
	}
	return map[string]any{
		"schemaVersion":    "1",
		"ok":               true,
		"scope":            containerOutputs,
		"count":            len(entryCopy),
		"rootBefore":       identity,
		"rootAfter":        identity,
		"disposableAbsent": true,
		"entries":          entryCopy,
	}
}

func cleanupInventoryControlJSON(
	t *testing.T,
	entries []cleanupInventoryEntry,
) []byte {
	t.Helper()
	return cleanupMarshalControl(t, cleanupInventoryControlMap(entries))
}

func cleanupInventoryControlJSONWithCount(
	t *testing.T,
	count int,
	entries []cleanupInventoryEntry,
) []byte {
	t.Helper()
	control := cleanupInventoryControlMap(entries)
	control["count"] = count
	return cleanupMarshalControl(t, control)
}

func cleanupMarshalControl(t *testing.T, control map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(control)
	if err != nil {
		t.Fatalf("marshal cleanup inventory control: %v", err)
	}
	return raw
}

func requireCleanupInventoryFailure(
	t *testing.T,
	raw []byte,
	wantClass string,
) {
	t.Helper()
	_, err := decodeCleanupInventory(raw)
	if err == nil {
		t.Fatalf(
			"decodeCleanupInventory() error = nil, want class %q",
			wantClass,
		)
	}
	if got := cleanupInventoryFailureClass(err); got != wantClass {
		t.Fatalf(
			"decodeCleanupInventory() failure class = %q, want %q: %v",
			got,
			wantClass,
			err,
		)
	}
}
