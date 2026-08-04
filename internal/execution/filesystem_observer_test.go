package execution

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

const filesystemTestDigest = "sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestDecodeFilesystemControlAcceptsExactEnvelope(t *testing.T) {
	entries := []filesystemSnapshotEntry{
		{
			Path:   "/outputs/a",
			Type:   "directory",
			Mode:   0o755,
			Size:   0,
			Digest: "",
		},
		{
			Path:   "/outputs/a/result.json",
			Type:   "file",
			Mode:   0o640,
			Size:   17,
			Digest: filesystemTestDigest,
		},
		{
			Path:   "/outputs/link",
			Type:   "symlink",
			Mode:   0o777,
			Size:   6,
			Digest: filesystemTestDigest,
		},
	}
	raw := filesystemControlForEntries(t, entries)

	snapshot, err := decodeFilesystemControl(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(snapshot.Entries, entries) {
		t.Fatalf("entries = %#v, want %#v", snapshot.Entries, entries)
	}
	if !filesystemDigestPattern.MatchString(snapshot.Digest) {
		t.Fatalf("snapshot digest = %q", snapshot.Digest)
	}
}

func TestDecodeFilesystemControlRejectsNonExactEnvelope(t *testing.T) {
	valid := `{"ok":true,"entries":[]}`
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "duplicate top-level key",
			raw:  []byte(`{"ok":true,"ok":true,"entries":[]}`),
		},
		{
			name: "unknown top-level key",
			raw:  []byte(`{"ok":true,"entries":[],"extra":false}`),
		},
		{
			name: "null required value",
			raw:  []byte(`{"ok":null,"entries":[]}`),
		},
		{
			name: "trailing object",
			raw:  []byte(valid + `{}`),
		},
		{
			name: "success union confusion",
			raw: []byte(
				`{"ok":true,"entries":[],"error":"snapshot-unavailable"}`,
			),
		},
		{
			name: "failure missing exact error",
			raw:  []byte(`{"ok":false}`),
		},
		{
			name: "failure union confusion",
			raw: []byte(
				`{"ok":false,"error":"snapshot-unavailable","entries":[]}`,
			),
		},
		{
			name: "unknown failure does not leak",
			raw:  []byte(`{"ok":false,"error":"RAW_FILESYSTEM_SECRET"}`),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeFilesystemControl(test.raw)
			if err == nil {
				t.Fatal("non-exact filesystem control was accepted")
			}
			if strings.Contains(err.Error(), "RAW_FILESYSTEM_SECRET") {
				t.Fatalf("raw helper data leaked through error: %v", err)
			}
		})
	}
}

func TestDecodeFilesystemControlAcceptsOnlyExactFailureEnvelope(t *testing.T) {
	_, err := decodeFilesystemControl(
		[]byte(`{"ok":false,"error":"snapshot-unavailable"}`),
	)
	if err == nil ||
		err.Error() != "filesystem retained-state snapshot is unavailable" {
		t.Fatalf("exact failure envelope error = %v", err)
	}
}

func TestDecodeFilesystemEntryRejectsUnsafeShapeAndPath(t *testing.T) {
	valid := `{"path":"/outputs/result.json","type":"file",` +
		`"mode":420,"size":1,"digest":"` + filesystemTestDigest + `"}`
	overlongPath := "/outputs/" +
		strings.Repeat("a", filesystemPathLimit-len("/outputs/")+1)
	tests := []struct {
		name  string
		entry string
	}{
		{
			name: "duplicate field",
			entry: `{"path":"/outputs/a","path":"/outputs/b",` +
				`"type":"directory","mode":493,"size":0,"digest":""}`,
		},
		{
			name: "unknown field",
			entry: strings.TrimSuffix(valid, "}") +
				`,"unknown":true}`,
		},
		{
			name:  "null path",
			entry: strings.Replace(valid, `"/outputs/result.json"`, "null", 1),
		},
		{
			name: "outside outputs",
			entry: strings.Replace(
				valid,
				"/outputs/result.json",
				"/workspace/result.json",
				1,
			),
		},
		{
			name:  "outputs root is not an entry path",
			entry: strings.Replace(valid, "/outputs/result.json", "/outputs", 1),
		},
		{
			name: "unclean path",
			entry: strings.Replace(
				valid,
				"/outputs/result.json",
				"/outputs/a/../result.json",
				1,
			),
		},
		{
			name: "control character",
			entry: strings.Replace(
				valid,
				"/outputs/result.json",
				`/outputs/bad\u0001name`,
				1,
			),
		},
		{
			name:  "path byte limit",
			entry: strings.Replace(valid, "/outputs/result.json", overlongPath, 1),
		},
		{
			name:  "unknown type",
			entry: strings.Replace(valid, `"type":"file"`, `"type":"socket"`, 1),
		},
		{
			name:  "negative mode",
			entry: strings.Replace(valid, `"mode":420`, `"mode":-1`, 1),
		},
		{
			name:  "mode overflow",
			entry: strings.Replace(valid, `"mode":420`, `"mode":4096`, 1),
		},
		{
			name:  "negative size",
			entry: strings.Replace(valid, `"size":1`, `"size":-1`, 1),
		},
		{
			name: "unsafe integer size",
			entry: strings.Replace(
				valid,
				`"size":1`,
				`"size":9007199254740992`,
				1,
			),
		},
		{
			name: "file missing digest",
			entry: strings.Replace(
				valid,
				filesystemTestDigest,
				"",
				1,
			),
		},
		{
			name: "file malformed digest",
			entry: strings.Replace(
				valid,
				filesystemTestDigest,
				"sha256:ABC",
				1,
			),
		},
		{
			name: "directory has digest",
			entry: strings.Replace(
				valid,
				`"type":"file"`,
				`"type":"directory"`,
				1,
			),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(`{"ok":true,"entries":[` + test.entry + `]}`)
			if _, err := decodeFilesystemControl(raw); err == nil {
				t.Fatalf("unsafe entry was accepted: %s", test.entry)
			}
		})
	}
}

func TestDecodeFilesystemControlRejectsInvalidUTF8Path(t *testing.T) {
	raw := []byte(
		`{"ok":true,"entries":[{"path":"/outputs/`,
	)
	raw = append(raw, 0xff)
	raw = append(
		raw,
		[]byte(
			`","type":"directory","mode":493,"size":0,"digest":""}]}`,
		)...,
	)

	if _, err := decodeFilesystemControl(raw); err == nil {
		t.Fatal("invalid UTF-8 helper control was accepted")
	}
}

func TestDecodeFilesystemEntriesRequireUniqueSortedPaths(t *testing.T) {
	entry := func(path string) string {
		return fmt.Sprintf(
			`{"path":%q,"type":"directory","mode":493,"size":0,"digest":""}`,
			path,
		)
	}
	tests := []struct {
		name    string
		entries string
	}{
		{
			name:    "descending",
			entries: entry("/outputs/b") + "," + entry("/outputs/a"),
		},
		{
			name:    "duplicate",
			entries: entry("/outputs/a") + "," + entry("/outputs/a"),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(`{"ok":true,"entries":[` + test.entries + `]}`)
			if _, err := decodeFilesystemControl(raw); err == nil {
				t.Fatal("non-unique or unsorted entries were accepted")
			}
		})
	}
}

func TestDecodeFilesystemEntriesEnforcesExactEntryLimit(t *testing.T) {
	atLimit := make([]filesystemSnapshotEntry, filesystemEntryLimit)
	for index := range atLimit {
		atLimit[index] = filesystemDirectoryEntry(
			fmt.Sprintf("/outputs/%04d", index),
		)
	}
	if _, err := decodeFilesystemControl(
		filesystemControlForEntries(t, atLimit),
	); err != nil {
		t.Fatalf("entry limit should be accepted: %v", err)
	}

	overLimit := append(
		slices.Clone(atLimit),
		filesystemDirectoryEntry(
			fmt.Sprintf("/outputs/%04d", filesystemEntryLimit),
		),
	)
	if _, err := decodeFilesystemControl(
		filesystemControlForEntries(t, overLimit),
	); err == nil {
		t.Fatal("entry count above the exact limit was accepted")
	}
}

func TestDiffFilesystemSnapshotsClassifiesBoundedRetainedChanges(t *testing.T) {
	baseline := filesystemSnapshot{Entries: []filesystemSnapshotEntry{
		{
			Path: "/outputs/b-delete", Type: "file",
			Mode: 0o644, Size: 1, Digest: filesystemTestDigest,
		},
		{
			Path: "/outputs/c-modify", Type: "file",
			Mode: 0o644, Size: 1, Digest: filesystemTestDigest,
		},
		{
			Path: "/outputs/d-type-change", Type: "file",
			Mode: 0o644, Size: 1, Digest: filesystemTestDigest,
		},
		{
			Path: "/outputs/e-unchanged", Type: "directory",
			Mode: 0o755, Size: 0,
		},
	}}
	changedDigest := "sha256:" + strings.Repeat("f", 64)
	final := filesystemSnapshot{Entries: []filesystemSnapshotEntry{
		filesystemDirectoryEntry("/outputs/a-create"),
		{
			Path: "/outputs/c-modify", Type: "file",
			Mode: 0o600, Size: 2, Digest: changedDigest,
		},
		{
			Path: "/outputs/d-type-change", Type: "symlink",
			Mode: 0o777, Size: 6, Digest: changedDigest,
		},
		{
			Path: "/outputs/e-unchanged", Type: "directory",
			Mode: 0o755, Size: 0,
		},
	}}

	changes := diffFilesystemSnapshots(baseline, final)
	if len(changes) != 4 {
		t.Fatalf("changes = %#v", changes)
	}
	wantPaths := []string{
		"/outputs/a-create",
		"/outputs/b-delete",
		"/outputs/c-modify",
		"/outputs/d-type-change",
	}
	wantKinds := []string{"create", "delete", "modify", "type-change"}
	for index, change := range changes {
		if change.Path != wantPaths[index] || change.Kind != wantKinds[index] {
			t.Fatalf("change[%d] = %#v", index, change)
		}
	}
	if changes[0].Before != nil || changes[0].After == nil {
		t.Fatalf("create pointers = %#v", changes[0])
	}
	if changes[1].Before == nil || changes[1].After != nil {
		t.Fatalf("delete pointers = %#v", changes[1])
	}
	for _, change := range changes[2:] {
		if change.Before == nil || change.After == nil {
			t.Fatalf("two-sided change pointers = %#v", change)
		}
	}
}

func TestValidateFilesystemChangeBoundRejectsMoreThanPublicLimit(t *testing.T) {
	final := filesystemSnapshot{
		Entries: make([]filesystemSnapshotEntry, filesystemChangeLimit),
	}
	for index := range final.Entries {
		final.Entries[index] = filesystemDirectoryEntry(
			fmt.Sprintf("/outputs/%04d", index),
		)
	}
	if err := validateFilesystemChangeBound(
		filesystemSnapshot{},
		final,
	); err != nil {
		t.Fatalf("exact change limit should be accepted: %v", err)
	}

	final.Entries = append(
		final.Entries,
		filesystemDirectoryEntry(
			fmt.Sprintf("/outputs/%04d", filesystemChangeLimit),
		),
	)
	if err := validateFilesystemChangeBound(
		filesystemSnapshot{},
		final,
	); err == nil {
		t.Fatal("change count above public evidence limit was accepted")
	}
}

func TestFilesystemDeclarationPatternMatchingIsExactAndBounded(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		observed string
		want     bool
	}{
		{name: "exact", pattern: "/outputs/result.json", observed: "/outputs/result.json", want: true},
		{name: "exact prefix rejected", pattern: "/outputs/result.json", observed: "/outputs/result.json.extra"},
		{name: "case sensitive", pattern: "/outputs/Result.json", observed: "/outputs/result.json"},
		{name: "one child", pattern: "/outputs/*", observed: "/outputs/result.json", want: true},
		{name: "one child rejects descendant", pattern: "/outputs/*", observed: "/outputs/nested/result.json"},
		{name: "recursive root", pattern: "/outputs/**", observed: "/outputs/file", want: true},
		{name: "recursive base", pattern: "/outputs/nested/**", observed: "/outputs/nested", want: true},
		{name: "recursive descendant", pattern: "/outputs/nested/**", observed: "/outputs/nested/result.json", want: true},
		{name: "recursive segment boundary", pattern: "/outputs/nested/**", observed: "/outputs/nested-other/result.json"},
		{name: "literal star", pattern: "/outputs/literal*name", observed: "/outputs/literal*name", want: true},
		{name: "literal star is not wildcard", pattern: "/outputs/literal*name", observed: "/outputs/literalXname"},
		{name: "literal question", pattern: "/outputs/literal?name", observed: "/outputs/literal?name", want: true},
		{name: "literal question is not wildcard", pattern: "/outputs/literal?name", observed: "/outputs/literalXname"},
		{name: "literal bracket", pattern: "/outputs/literal[name", observed: "/outputs/literal[name", want: true},
		{name: "literal bracket is not a class", pattern: "/outputs/literal[name", observed: "/outputs/literalnname"},
		{name: "outside outputs rejected", pattern: "/workspace/**", observed: "/outputs/file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := filesystemDeclarationPatternMatches(
				test.pattern,
				test.observed,
			); got != test.want {
				t.Fatalf("match = %t, want %t", got, test.want)
			}
		})
	}

	tooLong := "/outputs/" + strings.Repeat("x", filesystemPathLimit)
	for _, invalid := range []string{
		"", "/workspace/**", "/outputs/../source", "/outputs//x",
		"/outputs/x\\y", "/outputs/control\nname", tooLong,
	} {
		if validFilesystemDeclarationPattern(invalid) {
			t.Fatal("invalid declaration pattern was accepted")
		}
	}
}

func TestFilesystemRuntimePhaseGrantsUseOnlyDispatchedPhases(t *testing.T) {
	plan := domain.ResolvedPlan{Capabilities: map[domain.Phase]domain.CapabilitySet{
		domain.PhaseSetup: {
			Filesystem: domain.FilesystemCapability{Write: []string{
				"/outputs/setup.json", "/outputs/shared/**",
			}},
		},
		domain.PhaseBuild: {
			Filesystem: domain.FilesystemCapability{Write: []string{
				"/outputs/**",
			}},
		},
		domain.PhaseExercise: {
			Filesystem: domain.FilesystemCapability{Write: []string{
				"/outputs/shared/**", "/outputs/result.json",
			}},
		},
	}}
	state := filesystemObservationState{required: true}
	recordFilesystemPhaseDispatch(&state, plan, domain.PhaseSetup)
	if len(state.declarationPatterns) != 2 {
		t.Fatalf("setup grant count = %d, want 2", len(state.declarationPatterns))
	}
	if _, widened := state.declarationPatterns["/outputs/**"]; widened {
		t.Fatal("unexecuted build phase widened the declaration union")
	}
	recordFilesystemPhaseDispatch(&state, plan, domain.PhaseExercise)
	if len(state.declarationPatterns) != 3 {
		t.Fatalf("deduplicated grant count = %d, want 3", len(state.declarationPatterns))
	}

	complete := completeFilesystemObservationState(
		"/outputs/build-only.json",
		time.Now(),
	)
	complete.declarationPatterns = state.declarationPatterns
	comparison := compareFilesystemRetainedState(complete)
	if comparison.Result != "nonconforming-retained-state" ||
		comparison.DeclaredPatternCount != 3 ||
		comparison.UndeclaredChangeCount != 1 {
		t.Fatalf("runtime phase comparison = %#v", comparison)
	}
}

func TestFilesystemRuntimeGrantBoundsAndSignalDelivery(t *testing.T) {
	duplicates := make([]string, filesystemDeclarationPatternLimit+1)
	for index := range duplicates {
		duplicates[index] = "/outputs/duplicate.json"
	}
	duplicatePlan := domain.ResolvedPlan{
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseSetup: {
				Filesystem: domain.FilesystemCapability{Write: duplicates},
			},
		},
	}
	deduplicated := filesystemObservationState{required: true}
	recordFilesystemPhaseDispatch(
		&deduplicated,
		duplicatePlan,
		domain.PhaseSetup,
	)
	if deduplicated.declarationScopeAmbiguous ||
		len(deduplicated.declarationPatterns) != 1 {
		t.Fatalf("257 duplicate grants were not deduplicated: %#v", deduplicated)
	}

	atLimit := make([]string, filesystemDeclarationPatternLimit)
	for index := range atLimit {
		atLimit[index] = fmt.Sprintf("/outputs/%03d", index)
	}
	atLimitPlan := domain.ResolvedPlan{
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseSetup: {
				Filesystem: domain.FilesystemCapability{Write: atLimit},
			},
		},
	}
	atLimitState := filesystemObservationState{required: true}
	recordFilesystemPhaseDispatch(
		&atLimitState,
		atLimitPlan,
		domain.PhaseSetup,
	)
	if atLimitState.declarationScopeAmbiguous ||
		len(atLimitState.declarationPatterns) !=
			filesystemDeclarationPatternLimit {
		t.Fatalf("256 distinct grants did not remain complete: %#v", atLimitState)
	}
	atLimitComplete := completeFilesystemObservationState(
		"/outputs/000",
		time.Now(),
	)
	atLimitComplete.declarationPatterns = atLimitState.declarationPatterns
	atLimitComparison := compareFilesystemRetainedState(atLimitComplete)
	if atLimitComparison.Result != "conforming-retained-state" ||
		atLimitComparison.DeclaredPatternCount !=
			filesystemDeclarationPatternLimit {
		t.Fatalf("256 distinct comparison = %#v", atLimitComparison)
	}

	tooMany := make([]string, filesystemDeclarationPatternLimit+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("/outputs/%03d", index)
	}
	plan := domain.ResolvedPlan{Capabilities: map[domain.Phase]domain.CapabilitySet{
		domain.PhaseSetup: {
			Filesystem: domain.FilesystemCapability{Write: tooMany},
		},
		domain.PhaseCleanup: {
			Filesystem: domain.FilesystemCapability{Write: []string{
				"/outputs/cleanup.json",
			}},
		},
	}}
	bounded := filesystemObservationState{required: true}
	recordFilesystemPhaseDispatch(&bounded, plan, domain.PhaseSetup)
	if !bounded.declarationScopeAmbiguous ||
		bounded.declarationScopeFailure != "declared-write-scope-bound-exceeded" ||
		bounded.declarationPatterns != nil {
		t.Fatalf("oversized grant did not fail closed: %#v", bounded)
	}

	tests := []struct {
		name          string
		helper        signalHelperResult
		err           error
		wantGrant     bool
		wantAmbiguous bool
	}{
		{
			name: "delivered",
			helper: signalHelperResult{
				OK: true, InitialTargets: 2, Sent: 2, Remaining: 0,
			},
			wantGrant: true,
		},
		{
			name: "quiescent no-op",
			helper: signalHelperResult{
				OK: true, AlreadyExited: true,
			},
		},
		{
			name:          "ambiguous failure",
			err:           errors.New("synthetic signal failure"),
			wantAmbiguous: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := filesystemObservationState{required: true}
			recordFilesystemSignalGrant(
				&state,
				plan,
				test.helper,
				test.err,
			)
			_, granted := state.declarationPatterns["/outputs/cleanup.json"]
			if granted != test.wantGrant ||
				state.declarationScopeAmbiguous != test.wantAmbiguous {
				t.Fatalf("signal grant state = %#v", state)
			}
		})
	}
}

func TestFilesystemDeclarationComparisonAccountsEveryRetainedKind(t *testing.T) {
	changedDigest := "sha256:" + strings.Repeat("f", 64)
	state := filesystemObservationState{
		required: true,
		baseline: filesystemSnapshot{Entries: []filesystemSnapshotEntry{
			{Path: "/outputs/b-delete", Type: "file", Mode: 0o644, Size: 1, Digest: filesystemTestDigest},
			{Path: "/outputs/c-modify", Type: "file", Mode: 0o644, Size: 1, Digest: filesystemTestDigest},
			{Path: "/outputs/d-type", Type: "file", Mode: 0o644, Size: 1, Digest: filesystemTestDigest},
		}},
		baselineReady:            true,
		baselineIdentityVerified: true,
		final: filesystemSnapshot{Entries: []filesystemSnapshotEntry{
			filesystemDirectoryEntry("/outputs/a-create"),
			{Path: "/outputs/c-modify", Type: "file", Mode: 0o600, Size: 2, Digest: changedDigest},
			{Path: "/outputs/d-type", Type: "symlink", Mode: 0o777, Size: 6, Digest: changedDigest},
		}},
		finalReady:                 true,
		finalIdentityVerified:      true,
		workloadQuiescenceVerified: true,
		declarationPatterns: map[string]struct{}{
			"/outputs/a-create": {},
			"/outputs/c-modify": {},
			"/outputs/d-type":   {},
		},
	}
	comparison := compareFilesystemRetainedState(state)
	if comparison.Result != "nonconforming-retained-state" ||
		comparison.ComparedChangeCount != 4 ||
		comparison.AllowedChangeCount != 3 ||
		comparison.UndeclaredChangeCount != 1 ||
		comparison.CreateChangeCount != 1 ||
		comparison.DeleteChangeCount != 1 ||
		comparison.ModifyChangeCount != 1 ||
		comparison.TypeChangeCount != 1 {
		t.Fatalf("retained declaration comparison = %#v", comparison)
	}
	finding := filesystemDeclarationFinding(comparison)
	if finding == nil || finding.Code != domain.CodeUndeclaredFilesystemWrite ||
		finding.Severity != domain.SeverityHigh {
		t.Fatalf("retained declaration finding = %#v", finding)
	}
	if finding.Phase != "" || finding.Cause != nil ||
		len(finding.EvidenceRefs) != 0 || finding.Suggestion != "" ||
		finding.Retryable {
		t.Fatalf("finding overstated attribution or operation semantics: %#v", finding)
	}
}

func TestFilesystemDeclarationComparisonOverflowIsNotTested(t *testing.T) {
	state := completeFilesystemObservationState("/outputs/0000", time.Now())
	state.final.Entries = make([]filesystemSnapshotEntry, filesystemChangeLimit+1)
	for index := range state.final.Entries {
		state.final.Entries[index] = filesystemDirectoryEntry(
			fmt.Sprintf("/outputs/%04d", index),
		)
	}
	comparison := compareFilesystemRetainedState(state)
	if comparison.Result != "not-tested" ||
		comparison.Failure != "retained-state-change-bound-exceeded" ||
		filesystemDeclarationFinding(comparison) != nil {
		t.Fatalf("overflow comparison = %#v", comparison)
	}
}

func TestFilesystemDeclarationComparisonRejectsInvalidObservedPath(t *testing.T) {
	state := completeFilesystemObservationState(
		"/outputs/a/../RAW-INVALID-PATH",
		time.Now(),
	)
	comparison := compareFilesystemRetainedState(state)
	if comparison.Result != "not-tested" ||
		comparison.Failure != "retained-state-path-invalid" ||
		filesystemDeclarationFinding(comparison) != nil {
		t.Fatalf("invalid observed path comparison = %#v", comparison)
	}
}

func TestSummarizeFilesystemRetainedStateIsAggregateOnly(t *testing.T) {
	const rawSecretPath = "/outputs/RAW-SOURCE-SECRET-IN-FILENAME"
	const rawSecretPattern = "/outputs/RAW-DECLARATION-SECRET*"
	completedAt := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	state := completeFilesystemObservationState(rawSecretPath, completedAt)
	state.declarationPatterns = map[string]struct{}{
		rawSecretPattern: {},
	}

	observations, writeCoverage, retainedCoverage :=
		summarizeFilesystemRetainedState(
			state,
			"docker",
			"rp-test-container",
			completedAt.Add(time.Minute),
		)
	if writeCoverage != coverageBestEffort ||
		retainedCoverage != "high" {
		t.Fatalf(
			"write=%q retained=%q",
			writeCoverage,
			retainedCoverage,
		)
	}
	if len(observations) != 1 {
		t.Fatalf("public observations = %d, want one aggregate", len(observations))
	}
	observation := observations[0]
	if observation.Operation != "filesystem.retained-state.summary" ||
		observation.Actor != "trusted-runner" ||
		observation.Phase != domain.PhaseCleanup ||
		observation.Resource != "rp-test-container" ||
		observation.Result != "observed" ||
		observation.Coverage != "high" ||
		observation.Confidence != "high" ||
		observation.Observer != "docker-filesystem-retained-state" {
		t.Fatalf("aggregate observation = %#v", observation)
	}
	wire, err := json.Marshal(observations)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), rawSecretPath) ||
		strings.Contains(string(wire), "RAW-SOURCE-SECRET") ||
		strings.Contains(string(wire), rawSecretPattern) ||
		strings.Contains(string(wire), "RAW-DECLARATION-SECRET") {
		t.Fatalf("raw workload-controlled path entered public evidence: %s", wire)
	}
	comparison := compareFilesystemRetainedState(state)
	finding := filesystemDeclarationFinding(comparison)
	if finding == nil {
		t.Fatalf("nonconforming retained state produced no finding: %#v", comparison)
	}
	findingWire, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(findingWire), rawSecretPath) ||
		strings.Contains(string(findingWire), "RAW-SOURCE-SECRET") ||
		strings.Contains(string(findingWire), rawSecretPattern) ||
		strings.Contains(string(findingWire), "RAW-DECLARATION-SECRET") {
		t.Fatalf("raw path or pattern entered public finding: %s", findingWire)
	}
	if strings.Contains(finding.Error(), rawSecretPath) ||
		strings.Contains(finding.Error(), "RAW-SOURCE-SECRET") ||
		strings.Contains(finding.Error(), rawSecretPattern) ||
		strings.Contains(finding.Error(), "RAW-DECLARATION-SECRET") {
		t.Fatalf("raw path or pattern entered finding error string: %s", finding.Error())
	}

	details := observation.Details
	for key, want := range map[string]any{
		"scope":                            "outputs-retained-state",
		"snapshotBoundary":                 "post-init-pre-workload-to-post-quiesce-pre-repair",
		"includesTrustedHelpers":           true,
		"includesRunnerManagedDirectories": true,
		"contentIncluded":                  false,
		"publicEvidence":                   "aggregate-only",
		"actorAttribution":                 "unavailable",
		"baselineIdentityVerified":         true,
		"finalIdentityVerified":            true,
		"workloadQuiescenceVerified":       true,
		"baselineReady":                    true,
		"finalReady":                       true,
		"retainedStateCoverage":            "high",
		"baselineDigest":                   "sha256:baseline",
		"baselineEntryCount":               0,
		"finalDigest":                      "sha256:final",
		"finalEntryCount":                  1,
		"changeCount":                      1,
		"declarationComparisonScope":       filesystemDeclarationScope,
		"declarationComparisonVersion":     filesystemDeclarationVersion,
		"declarationComparisonResult":      "nonconforming-retained-state",
		"declaredPatternCount":             1,
		"comparedChangeCount":              1,
		"allowedChangeCount":               0,
		"undeclaredChangeCount":            1,
		"createChangeCount":                1,
		"deleteChangeCount":                0,
		"modifyChangeCount":                0,
		"typeChangeCount":                  0,
	} {
		if got := details[key]; got != want {
			t.Errorf("details[%q] = %#v, want %#v", key, got, want)
		}
	}
	blindSpots, ok := details["blindSpots"].([]string)
	if !ok {
		t.Fatalf("blindSpots = %#v", details["blindSpots"])
	}
	for _, required := range []string{
		"outside-outputs",
		"transient-create-delete",
		"write-then-restore",
		"operation-time",
		"process-phase-attribution",
		"exact-actor-and-operation-kind",
		"unexecuted-phase-declarations",
		"rename-vs-delete-create",
		"ownership",
		"timestamps",
		"xattr-acl",
		"inode-device",
	} {
		if !slices.Contains(blindSpots, required) {
			t.Errorf("blindSpots omitted %q: %v", required, blindSpots)
		}
	}
}

func TestSummarizeFilesystemRetainedStateRequiresEveryBoundaryGate(
	t *testing.T,
) {
	completedAt := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	base := completeFilesystemObservationState(
		"/outputs/secret-path-must-not-leak",
		completedAt,
	)
	tests := []struct {
		name              string
		mutate            func(*filesystemObservationState)
		retainedAvailable bool
	}{
		{
			name: "baseline snapshot missing",
			mutate: func(value *filesystemObservationState) {
				value.baselineReady = false
			},
		},
		{
			name: "final snapshot missing",
			mutate: func(value *filesystemObservationState) {
				value.finalReady = false
			},
		},
		{
			name: "baseline identity missing",
			mutate: func(value *filesystemObservationState) {
				value.baselineIdentityVerified = false
			},
		},
		{
			name: "final identity missing",
			mutate: func(value *filesystemObservationState) {
				value.finalIdentityVerified = false
			},
		},
		{
			name: "workload quiescence missing",
			mutate: func(value *filesystemObservationState) {
				value.workloadQuiescenceVerified = false
			},
		},
		{
			name: "snapshot failure recorded",
			mutate: func(value *filesystemObservationState) {
				value.failure = "snapshot-failed"
			},
		},
		{
			name:              "declaration scope ambiguous",
			retainedAvailable: true,
			mutate: func(value *filesystemObservationState) {
				value.declarationScopeAmbiguous = true
				value.declarationScopeFailure =
					"runtime-phase-scope-ambiguous"
				value.declarationPatterns = nil
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			state := base
			test.mutate(&state)
			observations, writeCoverage, retainedCoverage :=
				summarizeFilesystemRetainedState(
					state,
					"docker",
					"rp-test-container",
					completedAt,
				)
			if test.retainedAvailable {
				if writeCoverage != coverageBestEffort ||
					retainedCoverage != "high" ||
					len(observations) != 1 ||
					observations[0].Result != "observed" ||
					observations[0].Coverage != "high" ||
					observations[0].Confidence != "high" {
					t.Fatalf("available retained aggregate = %#v", observations)
				}
			} else {
				if writeCoverage != coverageUnavailable ||
					retainedCoverage != coverageUnavailable {
					t.Fatalf(
						"missing gate retained write=%q retained=%q",
						writeCoverage,
						retainedCoverage,
					)
				}
				if len(observations) != 1 ||
					observations[0].Result != "unavailable" ||
					observations[0].Coverage != coverageUnavailable ||
					observations[0].Confidence != "unknown" {
					t.Fatalf("unavailable aggregate = %#v", observations)
				}
			}
			details := observations[0].Details
			if details["retainedStateCoverage"] != retainedCoverage {
				t.Fatalf("retained coverage detail = %#v", details)
			}
			if details["declarationComparisonResult"] != "not-tested" {
				t.Fatalf("declaration comparison was overstated: %#v", details)
			}
			comparison := compareFilesystemRetainedState(state)
			if comparison.Result != "not-tested" ||
				filesystemDeclarationFinding(comparison) != nil {
				t.Fatalf("missing gate produced a finding: %#v", comparison)
			}
			if _, present := details["undeclaredChangeCount"]; present {
				t.Fatalf("untested comparison exposed a count: %#v", details)
			}
			if !test.retainedAvailable {
				for _, forbidden := range []string{
					"baselineDigest",
					"baselineEntryCount",
					"finalDigest",
					"finalEntryCount",
					"changeCount",
				} {
					if _, present := details[forbidden]; present {
						t.Errorf("unavailable summary exposed %q", forbidden)
					}
				}
			}
			wire, err := json.Marshal(observations)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(wire), "secret-path-must-not-leak") {
				t.Fatalf("raw path entered unavailable evidence: %s", wire)
			}
		})
	}
}

func TestSummarizeFilesystemRetainedStateSkipsUnrequiredObserver(t *testing.T) {
	observations, writeCoverage, retainedCoverage :=
		summarizeFilesystemRetainedState(
			filesystemObservationState{},
			"docker",
			"rp-test-container",
			time.Now(),
		)
	if observations != nil ||
		writeCoverage != coverageUnavailable ||
		retainedCoverage != coverageUnavailable {
		t.Fatalf(
			"unrequired observer observations=%#v write=%q retained=%q",
			observations,
			writeCoverage,
			retainedCoverage,
		)
	}
}

func filesystemControlForEntries(
	t *testing.T,
	entries []filesystemSnapshotEntry,
) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		OK      bool                      `json:"ok"`
		Entries []filesystemSnapshotEntry `json:"entries"`
	}{
		OK:      true,
		Entries: entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func filesystemDirectoryEntry(path string) filesystemSnapshotEntry {
	return filesystemSnapshotEntry{
		Path: path, Type: "directory", Mode: 0o755, Size: 0, Digest: "",
	}
}

func completeFilesystemObservationState(
	rawPath string,
	observedAt time.Time,
) filesystemObservationState {
	return filesystemObservationState{
		required:                   true,
		baseline:                   filesystemSnapshot{Entries: []filesystemSnapshotEntry{}, Digest: "sha256:baseline"},
		baselineReady:              true,
		baselineIdentityVerified:   true,
		final:                      filesystemSnapshot{Entries: []filesystemSnapshotEntry{filesystemDirectoryEntry(rawPath)}, Digest: "sha256:final"},
		finalReady:                 true,
		finalIdentityVerified:      true,
		workloadQuiescenceVerified: true,
		observedAt:                 observedAt,
		declarationPatterns: map[string]struct{}{
			"/outputs/**": {},
		},
	}
}
