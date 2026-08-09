// Package releasequalification freezes the RFC-0001 release-qualification API
// below. This is deliberately a tests-first contract; production may be absent
// while this file is introduced.
//
//	type ArtifactSpec struct {
//		ID       string
//		Path     string
//		Identity buildidentity.BuildIdentity
//	}
//	type ArtifactReport struct {
//		ID      string
//		Size    int64
//		SHA256  string // exact "sha256:<64 lowercase hex>"
//		Results []buildidentity.Result // failure-only
//	}
//	type KitSpec struct {
//		ID                     string
//		Path                   string
//		TargetOS               string // exactly linux or windows; amd64 is fixed
//		StandaloneVerifierPath string
//	}
//	type KitReport struct {
//		ID               string
//		Size             int64
//		SHA256           string
//		EmbeddedVerifier ArtifactReport
//	}
//	type LogRecord struct {
//		ID       string `json:"id"`
//		SHA256   string `json:"sha256"`
//		Revision string `json:"revision"`
//		Tree     string `json:"tree"`
//	}
//	type QualificationReport struct {
//		Artifacts []ArtifactReport
//		Kits      []KitReport
//		Results   []buildidentity.Result // deterministic flattened failures
//		Log       []LogRecord
//	}
//
//	func InspectArtifact(spec ArtifactSpec, testedRevision string) ArtifactReport
//	func InspectPortableKit(spec KitSpec, testedRevision string) (KitReport, error)
//	func QualifyPreHelper(root, testedRevision, treeSHA string) (QualificationReport, error)
//	func QualifyPrePublish(root, testedRevision, treeSHA string) (QualificationReport, error)
//
// InspectArtifact must open one regular non-link handle and use that same fixed
// handle for hash -> debug/buildinfo -> hash/fstat stability checks. The two
// Qualify functions return a non-nil error whenever Results is non-empty, while
// retaining the RFC buildidentity results. Errors are for structural/input or
// overall release blocking; they do not invent new RFC identity labels.
package releasequalification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

var preHelperContract = []struct {
	id       string
	name     string
	identity buildidentity.BuildIdentity
	fixture  func(*qualificationFixture) string
}{
	{"full-linux-amd64", "repopass-linux-amd64", buildidentity.FullCLIIdentity, func(f *qualificationFixture) string { return f.fullLinux }},
	{"full-windows-amd64", "repopass-windows-amd64.exe", buildidentity.FullCLIIdentity, func(f *qualificationFixture) string { return f.fullWindows }},
	{"verifier-linux-amd64", "repopass-verify-linux-amd64", buildidentity.VerifierIdentity, func(f *qualificationFixture) string { return f.verifierLinux }},
	{"verifier-windows-amd64", "repopass-verify-windows-amd64.exe", buildidentity.VerifierIdentity, func(f *qualificationFixture) string { return f.verifierWindows }},
	{"kit-helper-host", "repopass-kit-host.exe", buildidentity.HostKitHelperIdentity, func(f *qualificationFixture) string { return f.helper }},
}

func TestInspectArtifactBindsExactHashAndBuildInfoFromOneSnapshot(t *testing.T) {
	fixture := testQualificationFixture(t)
	report := InspectArtifact(ArtifactSpec{
		ID:       "verifier-linux-amd64",
		Path:     fixture.verifierLinux,
		Identity: buildidentity.VerifierIdentity,
	}, fixture.revision)

	wantSize, wantDigest := fileDigest(t, fixture.verifierLinux)
	if report.ID != "verifier-linux-amd64" || report.Size != wantSize || report.SHA256 != wantDigest {
		t.Fatalf("artifact report = %#v, want id, size %d and digest %q", report, wantSize, wantDigest)
	}
	if len(report.Results) != 0 {
		t.Fatalf("exact fixed-handle artifact failed identity: %#v", report.Results)
	}
}

func TestInspectArtifactRejectsNonRegularAndSymlinkInputs(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := t.TempDir()
	directory := filepath.Join(root, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(root, "not-go")
	if err := os.WriteFile(malformed, []byte("not a Go executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs := []struct {
		name string
		path string
	}{
		{"missing", filepath.Join(root, "missing")},
		{"directory", directory},
		{"malformed", malformed},
	}
	link := filepath.Join(root, "verifier-link")
	if err := os.Symlink(fixture.verifierLinux, link); err == nil {
		inputs = append(inputs, struct{ name, path string }{"symlink", link})
	}
	for _, input := range inputs {
		t.Run(input.name, func(t *testing.T) {
			report := InspectArtifact(ArtifactSpec{ID: input.name, Path: input.path, Identity: buildidentity.VerifierIdentity}, fixture.revision)
			requireResultCode(t, report.Results, buildidentity.CodeBuildInfoUnreadable, input.name)
			if report.SHA256 != "" {
				t.Fatalf("untrusted input exposed a digest as accepted snapshot: %#v", report)
			}
		})
	}
}

func TestInspectArtifactRejectsAFileChangingDuringHashAndBuildInfo(t *testing.T) {
	fixture := testQualificationFixture(t)
	path := filepath.Join(t.TempDir(), "changing-verifier")
	copyFixtureFile(t, fixture.verifierLinux, path)
	const paddedSize = int64(24 << 20)
	if err := os.Truncate(path, paddedSize); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer file.Close()
		var value byte
		first := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			value ^= 1
			_, _ = file.WriteAt([]byte{value}, paddedSize-1)
			if first {
				close(started)
				first = false
			}
			runtime.Gosched()
		}
	}()
	<-started
	report := InspectArtifact(ArtifactSpec{ID: "changing", Path: path, Identity: buildidentity.VerifierIdentity}, fixture.revision)
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture writer did not stop")
	}
	requireResultCode(t, report.Results, buildidentity.CodeBuildInfoUnreadable, "changing")
	if report.SHA256 != "" {
		t.Fatalf("unstable bytes produced a trusted digest: %#v", report)
	}
}

func TestInspectArtifactImplementationNeverReopensForBuildInfo(t *testing.T) {
	files := productionGoFiles(t)
	foundHandleBasedRead := false
	for name, file := range files {
		buildInfoAliases := map[string]bool{}
		identityAliases := map[string]bool{}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			switch path {
			case "debug/buildinfo":
				alias := "buildinfo"
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				buildInfoAliases[alias] = true
			case canonicalModule + "/internal/buildidentity":
				alias := "buildidentity"
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				identityAliases[alias] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if buildInfoAliases[ident.Name] && selector.Sel.Name == "ReadFile" {
				t.Errorf("%s uses path-reopening debug/buildinfo.ReadFile; qualification must use the fixed handle", name)
			}
			if identityAliases[ident.Name] && selector.Sel.Name == "ValidateFile" {
				t.Errorf("%s uses path-reopening buildidentity.ValidateFile; qualification must pass its fixed snapshot", name)
			}
			if (buildInfoAliases[ident.Name] && selector.Sel.Name == "Read") ||
				(identityAliases[ident.Name] && selector.Sel.Name == "ValidateReaderAt") {
				foundHandleBasedRead = true
			}
			return true
		})
	}
	if !foundHandleBasedRead {
		t.Fatal("production qualification does not validate build info from a fixed io.ReaderAt snapshot")
	}
}

func TestQualifyPreHelperFreezesTwoFullTwoVerifierAndHostHelperSet(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := stagePreHelper(t, fixture)
	report, err := QualifyPreHelper(root, fixture.revision, fixture.tree)
	if err != nil {
		t.Fatalf("exact pre-helper set rejected: %v (report %#v)", err, report)
	}
	if len(report.Results) != 0 {
		t.Fatalf("exact pre-helper set has failures: %#v", report.Results)
	}
	wantIDs := preHelperIDs()
	if got := artifactIDs(report.Artifacts); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("pre-helper artifacts = %q, want fixed ordered set %q", got, wantIDs)
	}
	if len(report.Kits) != 0 {
		t.Fatalf("pre-helper unexpectedly inspected kits: %#v", report.Kits)
	}
	requireAllowlistedLog(t, report.Log, wantIDs, fixture.revision, fixture.tree, root)
}

func TestQualifyPreHelperInspectsEveryRequiredSlot(t *testing.T) {
	fixture := testQualificationFixture(t)
	for _, slot := range preHelperContract {
		t.Run(slot.id, func(t *testing.T) {
			root := stagePreHelper(t, fixture)
			if err := os.WriteFile(filepath.Join(root, slot.name), []byte("plausible filename, invalid executable"), 0o600); err != nil {
				t.Fatal(err)
			}
			report, err := QualifyPreHelper(root, fixture.revision, fixture.tree)
			if err == nil {
				t.Fatalf("invalid required slot %q did not block qualification", slot.id)
			}
			if got := artifactIDs(report.Artifacts); !reflect.DeepEqual(got, preHelperIDs()) {
				t.Fatalf("failure changed frozen required set: %q", got)
			}
			requireResultCode(t, report.Results, buildidentity.CodeBuildInfoUnreadable, slot.id)
		})
	}
}

func TestQualifiersRequireExactLowercaseRevisionAndTree(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := stagePreHelper(t, fixture)
	invalid := []string{
		"", fixture.revision[:39], fixture.revision + "0", strings.ToUpper(fixture.revision),
		strings.Repeat("g", 40), " " + fixture.revision, fixture.revision + "\n",
	}
	for _, value := range invalid {
		t.Run("revision-"+safeTestName(value), func(t *testing.T) {
			if report, err := QualifyPreHelper(root, value, fixture.tree); err == nil {
				t.Fatalf("invalid revision accepted with report %#v", report)
			}
		})
		t.Run("tree-"+safeTestName(value), func(t *testing.T) {
			if report, err := QualifyPreHelper(root, fixture.revision, value); err == nil {
				t.Fatalf("invalid tree accepted with report %#v", report)
			}
		})
	}
}

func TestQualificationLogHasOnlyAllowlistedPublicFieldsAndNeverAbsolutePaths(t *testing.T) {
	fixture := testQualificationFixture(t)
	root := stagePreHelper(t, fixture)
	report, err := QualifyPreHelper(root, fixture.revision, fixture.tree)
	if err != nil {
		t.Fatal(err)
	}
	requireAllowlistedLog(t, report.Log, preHelperIDs(), fixture.revision, fixture.tree, root)
}

func stagePreHelper(t *testing.T, fixture *qualificationFixture) string {
	t.Helper()
	root := t.TempDir()
	for _, slot := range preHelperContract {
		copyFixtureFile(t, slot.fixture(fixture), filepath.Join(root, slot.name))
	}
	return root
}

func requireAllowlistedLog(t *testing.T, records []LogRecord, wantIDs []string, revision, tree, privateRoot string) {
	t.Helper()
	if len(records) != len(wantIDs) {
		t.Fatalf("log records = %d, want %d: %#v", len(records), len(wantIDs), records)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	privateForms := []string{privateRoot, filepath.ToSlash(privateRoot), strings.ReplaceAll(privateRoot, `\`, `\\`)}
	for _, privateForm := range privateForms {
		if privateForm != "" && strings.Contains(string(encoded), privateForm) {
			t.Fatalf("potentially public log leaked absolute path %q: %s", privateForm, encoded)
		}
	}
	gotIDs := make([]string, 0, len(records))
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(data, &object); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if want := []string{"id", "revision", "sha256", "tree"}; !reflect.DeepEqual(keys, want) {
			t.Fatalf("log keys = %q, want allowlist %q", keys, want)
		}
		if record.Revision != revision || record.Tree != tree || !validSHA256(record.SHA256) {
			t.Fatalf("non-allowlisted log value: %#v", record)
		}
		gotIDs = append(gotIDs, record.ID)
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("log IDs = %q, want %q", gotIDs, wantIDs)
	}
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func requireResultCode(t *testing.T, results []buildidentity.Result, code buildidentity.Code, subject string) {
	t.Helper()
	for _, result := range results {
		if result.Status == buildidentity.StatusFail && result.Code == code && result.Subject == subject {
			return
		}
	}
	t.Fatalf("results = %#v, want FAIL/%s for %q", results, code, subject)
}

func preHelperIDs() []string {
	ids := make([]string, 0, len(preHelperContract))
	for _, item := range preHelperContract {
		ids = append(ids, item.id)
	}
	return ids
}

func artifactIDs(reports []ArtifactReport) []string {
	ids := make([]string, len(reports))
	for index, report := range reports {
		ids[index] = report.ID
	}
	return ids
}

func safeTestName(value string) string {
	if value == "" {
		return "empty"
	}
	return strings.NewReplacer("/", "_", "\\", "_", " ", "space", "\n", "newline").Replace(value)
}

func productionGoFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, directory, func(info os.FileInfo) bool {
		return strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]*ast.File)
	for _, pkg := range packages {
		for name, file := range pkg.Files {
			result[name] = file
		}
	}
	if len(result) == 0 {
		t.Fatal("releasequalification has no production implementation")
	}
	return result
}
