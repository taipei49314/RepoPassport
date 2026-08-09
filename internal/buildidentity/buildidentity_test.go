// Package buildidentity is expected to implement the RFC-0001 qualification
// contract through the following standard-library-only production API:
//
//	const CanonicalModulePath = "github.com/taipei49314/RepoPassport"
//	const LegacyModulePath = "github.com/repopass/repopass"
//
//	type BuildIdentity struct {
//		ModulePath  string
//		MainPackage string
//	}
//
//	var FullCLIIdentity BuildIdentity
//	var VerifierIdentity BuildIdentity
//	var HostKitHelperIdentity BuildIdentity
//
//	type Status string
//	const StatusPass Status = "PASS"
//	const StatusFail Status = "FAIL"
//	const StatusNotRun Status = "NOT_RUN"
//
//	type Code string
//	const CodeModulePathMismatch Code = "MODULE_PATH_MISMATCH"
//	const CodePackagePathMismatch Code = "PACKAGE_PATH_MISMATCH"
//	const CodeMainPackagePathMismatch Code = "MAIN_PACKAGE_PATH_MISMATCH"
//	const CodeLegacyModuleReference Code = "LEGACY_MODULE_REFERENCE"
//	const CodeBuildInfoUnreadable Code = "BUILD_INFO_UNREADABLE"
//	const CodeSourceRevisionMismatch Code = "SOURCE_REVISION_MISMATCH"
//	const CodeSourceTreeDirty Code = "SOURCE_TREE_DIRTY"
//	const CodeExternalImportFailed Code = "EXTERNAL_IMPORT_FAILED"
//	const CodeRequiredCheckNotRun Code = "REQUIRED_CHECK_NOT_RUN"
//
//	type Result struct {
//		Status  Status
//		Code    Code
//		Subject string
//	}
//
//	type Summary struct {
//		Status       Status
//		Results      []Result
//		FirstFailure *Result
//	}
//
//	func ValidateBuildInfo(info *debug.BuildInfo, expected BuildIdentity, testedRevision, subject string) []Result
//	func ValidateFile(path string, expected BuildIdentity, testedRevision, subject string) []Result
//	func Aggregate(results []Result) Summary
//
// Validation is pure and failure-only: a conforming BuildInfo returns nil.
// Aggregate sorts a copied result set and retains the first FAIL from the
// caller's execution order.
package buildidentity

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
)

const testedRevision = "0123456789abcdef0123456789abcdef01234567"

func TestCanonicalIdentities(t *testing.T) {
	if got, want := CanonicalModulePath, "github.com/taipei49314/RepoPassport"; got != want {
		t.Fatalf("CanonicalModulePath = %q, want %q", got, want)
	}
	if got, want := LegacyModulePath, "github.com/repopass/repopass"; got != want {
		t.Fatalf("LegacyModulePath = %q, want %q", got, want)
	}

	tests := []struct {
		name string
		got  BuildIdentity
		want BuildIdentity
	}{
		{
			name: "full CLI",
			got:  FullCLIIdentity,
			want: BuildIdentity{
				ModulePath:  "github.com/taipei49314/RepoPassport",
				MainPackage: "github.com/taipei49314/RepoPassport/cmd/repopass",
			},
		},
		{
			name: "portable verifier",
			got:  VerifierIdentity,
			want: BuildIdentity{
				ModulePath:  "github.com/taipei49314/RepoPassport",
				MainPackage: "github.com/taipei49314/RepoPassport/cmd/repopass-verify",
			},
		},
		{
			name: "host-only kit helper",
			got:  HostKitHelperIdentity,
			want: BuildIdentity{
				ModulePath:  "github.com/taipei49314/RepoPassport",
				MainPackage: "github.com/taipei49314/RepoPassport/cmd/repopass-kit",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("identity = %#v, want %#v", test.got, test.want)
			}
		})
	}
}

func TestStatusAndCodeConstantsAreExact(t *testing.T) {
	statuses := []struct {
		name string
		got  Status
		want string
	}{
		{"pass", StatusPass, "PASS"},
		{"fail", StatusFail, "FAIL"},
		{"not run", StatusNotRun, "NOT_RUN"},
	}
	for _, test := range statuses {
		t.Run(test.name, func(t *testing.T) {
			if string(test.got) != test.want {
				t.Fatalf("status = %q, want %q", test.got, test.want)
			}
		})
	}

	codes := []struct {
		got  Code
		want string
	}{
		{CodeModulePathMismatch, "MODULE_PATH_MISMATCH"},
		{CodePackagePathMismatch, "PACKAGE_PATH_MISMATCH"},
		{CodeMainPackagePathMismatch, "MAIN_PACKAGE_PATH_MISMATCH"},
		{CodeLegacyModuleReference, "LEGACY_MODULE_REFERENCE"},
		{CodeBuildInfoUnreadable, "BUILD_INFO_UNREADABLE"},
		{CodeSourceRevisionMismatch, "SOURCE_REVISION_MISMATCH"},
		{CodeSourceTreeDirty, "SOURCE_TREE_DIRTY"},
		{CodeExternalImportFailed, "EXTERNAL_IMPORT_FAILED"},
		{CodeRequiredCheckNotRun, "REQUIRED_CHECK_NOT_RUN"},
	}
	for _, test := range codes {
		if string(test.got) != test.want {
			t.Errorf("code = %q, want %q", test.got, test.want)
		}
	}
}

func TestValidateBuildInfoAcceptsExactArtifactIdentityAndVCS(t *testing.T) {
	artifacts := []struct {
		name     string
		identity BuildIdentity
	}{
		{"full CLI", FullCLIIdentity},
		{"portable verifier", VerifierIdentity},
		{"host-only kit helper", HostKitHelperIdentity},
	}
	for _, artifact := range artifacts {
		t.Run(artifact.name, func(t *testing.T) {
			info := exactBuildInfo(artifact.identity)
			info.Main.Version = "(devel)" // Version is explicitly outside this identity decision.
			info.Deps = []*debug.Module{{Path: "example.com/benign/dependency", Version: "v1.2.3"}}
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "GOOS", Value: "test-os"})

			if got := ValidateBuildInfo(info, artifact.identity, testedRevision, artifact.name); len(got) != 0 {
				t.Fatalf("ValidateBuildInfo() = %#v, want no failures", got)
			}
		})
	}
}

func TestValidateBuildInfoRejectsCaseVariantsAndModuleLookalikes(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"lowercase repository", "github.com/taipei49314/repopassport"},
		{"owner case variant", "github.com/Taipei49314/RepoPassport"},
		{"trailing slash", CanonicalModulePath + "/"},
		{"child path", CanonicalModulePath + "/submodule"},
		{"suffix appended", CanonicalModulePath + "-fork"},
		{"URL form", "https://github.com/taipei49314/RepoPassport"},
		{"transport suffix", CanonicalModulePath + ".git"},
		{"Unicode lookalike", "github.com/taipei49314/RepoPassp\u043ert"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := exactBuildInfo(FullCLIIdentity)
			info.Main.Path = test.path
			got := ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "full-cli")
			requireFailureCode(t, got, CodeModulePathMismatch)
		})
	}
}

func TestValidateBuildInfoRejectsCaseVariantsAndMainPackageLookalikes(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"lowercase repository", "github.com/taipei49314/repopassport/cmd/repopass"},
		{"command case variant", CanonicalModulePath + "/cmd/RepoPass"},
		{"trailing slash", FullCLIIdentity.MainPackage + "/"},
		{"child path", FullCLIIdentity.MainPackage + "/subcommand"},
		{"suffix appended", FullCLIIdentity.MainPackage + "-fork"},
		{"other canonical artifact", VerifierIdentity.MainPackage},
		{"URL form", "https://github.com/taipei49314/RepoPassport/cmd/repopass"},
		{"Unicode lookalike", CanonicalModulePath + "/cmd/repop\u0430ss"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := exactBuildInfo(FullCLIIdentity)
			info.Path = test.path
			got := ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "full-cli")
			requireFailureCode(t, got, CodeMainPackagePathMismatch)
		})
	}
}

func FuzzValidateBuildInfoAcceptsOnlyExactModuleAndMainPackage(f *testing.F) {
	f.Add(CanonicalModulePath, FullCLIIdentity.MainPackage)
	f.Add(strings.ToLower(CanonicalModulePath), FullCLIIdentity.MainPackage)
	f.Add(CanonicalModulePath, FullCLIIdentity.MainPackage+"/")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, modulePath, mainPackage string) {
		info := exactBuildInfo(FullCLIIdentity)
		info.Main.Path = modulePath
		info.Path = mainPackage
		accepted := len(ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "property")) == 0
		wantAccepted := modulePath == CanonicalModulePath && mainPackage == FullCLIIdentity.MainPackage
		if accepted != wantAccepted {
			t.Fatalf("accepted=%t for module/main pair %q / %q; want %t", accepted, modulePath, mainPackage, wantAccepted)
		}
	})
}

func TestValidateBuildInfoRequiresNilMainReplacement(t *testing.T) {
	for _, replacement := range []string{CanonicalModulePath, "example.invalid/replacement"} {
		t.Run(replacement, func(t *testing.T) {
			info := exactBuildInfo(FullCLIIdentity)
			info.Main.Replace = &debug.Module{Path: replacement}
			got := ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "full-cli")
			requireOnlyFailureCodes(t, got, CodeModulePathMismatch)
		})
	}
}

func TestValidateBuildInfoRejectsLegacyIdentityOnEveryExecutableSurface(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*debug.BuildInfo)
	}{
		{
			name: "main module",
			mutate: func(info *debug.BuildInfo) {
				info.Main.Path = LegacyModulePath
			},
		},
		{
			name: "main package",
			mutate: func(info *debug.BuildInfo) {
				info.Path = LegacyModulePath + "/cmd/repopass"
			},
		},
		{
			name: "main replacement",
			mutate: func(info *debug.BuildInfo) {
				info.Main.Replace = &debug.Module{Path: LegacyModulePath}
			},
		},
		{
			name: "dependency",
			mutate: func(info *debug.BuildInfo) {
				info.Deps = []*debug.Module{{Path: LegacyModulePath + "/schemas"}}
			},
		},
		{
			name: "dependency replacement",
			mutate: func(info *debug.BuildInfo) {
				info.Deps = []*debug.Module{{
					Path:    "example.invalid/dependency",
					Replace: &debug.Module{Path: LegacyModulePath + "/replacement"},
				}}
			},
		},
		{
			name: "build setting key",
			mutate: func(info *debug.BuildInfo) {
				info.Settings = append(info.Settings, debug.BuildSetting{
					Key:   LegacyModulePath + "/setting",
					Value: "benign",
				})
			},
		},
		{
			name: "build setting value",
			mutate: func(info *debug.BuildInfo) {
				info.Settings = append(info.Settings, debug.BuildSetting{
					Key:   "-ldflags",
					Value: "-X " + LegacyModulePath + "/internal/cli.Version=test",
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := exactBuildInfo(FullCLIIdentity)
			test.mutate(info)
			got := ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "full-cli")
			requireFailureCode(t, got, CodeLegacyModuleReference)
		})
	}
}

func TestValidateBuildInfoRequiresExactTestedRevision(t *testing.T) {
	tests := []struct {
		name     string
		settings []debug.BuildSetting
	}{
		{
			name: "missing",
			settings: []debug.BuildSetting{
				{Key: "vcs.modified", Value: "false"},
			},
		},
		{
			name: "different",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "fedcba9876543210fedcba9876543210fedcba98"},
				{Key: "vcs.modified", Value: "false"},
			},
		},
		{
			name: "case differs",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "0123456789ABCDEF0123456789ABCDEF01234567"},
				{Key: "vcs.modified", Value: "false"},
			},
		},
		{
			name: "key case differs",
			settings: []debug.BuildSetting{
				{Key: "VCS.REVISION", Value: testedRevision},
				{Key: "vcs.modified", Value: "false"},
			},
		},
		{
			name: "duplicate equal values",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: testedRevision},
				{Key: "vcs.revision", Value: testedRevision},
				{Key: "vcs.modified", Value: "false"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := exactBuildInfo(FullCLIIdentity)
			info.Settings = test.settings
			got := ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "full-cli")
			requireOnlyFailureCodes(t, got, CodeSourceRevisionMismatch)
		})
	}
}

func TestValidateBuildInfoRequiresOneExactCleanTreeSetting(t *testing.T) {
	tests := []struct {
		name     string
		modified []debug.BuildSetting
	}{
		{"missing", nil},
		{"true", []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}},
		{"capitalized false", []debug.BuildSetting{{Key: "vcs.modified", Value: "False"}}},
		{"numeric false", []debug.BuildSetting{{Key: "vcs.modified", Value: "0"}}},
		{"key case differs", []debug.BuildSetting{{Key: "VCS.MODIFIED", Value: "false"}}},
		{"duplicate false", []debug.BuildSetting{
			{Key: "vcs.modified", Value: "false"},
			{Key: "vcs.modified", Value: "false"},
		}},
		{"duplicate mixed", []debug.BuildSetting{
			{Key: "vcs.modified", Value: "false"},
			{Key: "vcs.modified", Value: "true"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := exactBuildInfo(FullCLIIdentity)
			info.Settings = []debug.BuildSetting{{Key: "vcs.revision", Value: testedRevision}}
			info.Settings = append(info.Settings, test.modified...)
			got := ValidateBuildInfo(info, FullCLIIdentity, testedRevision, "full-cli")
			requireOnlyFailureCodes(t, got, CodeSourceTreeDirty)
		})
	}
}

func TestValidateBuildInfoNilIsOnlyBuildInfoUnreadable(t *testing.T) {
	got := ValidateBuildInfo(nil, FullCLIIdentity, testedRevision, "full-cli")
	want := []Result{{
		Status:  StatusFail,
		Code:    CodeBuildInfoUnreadable,
		Subject: "full-cli",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValidateBuildInfo(nil) = %#v, want %#v", got, want)
	}
}

func TestValidateFileUnreadableEmitsNoDerivedFailures(t *testing.T) {
	temp := t.TempDir()
	notGoExecutable := filepath.Join(temp, "repopass")
	if err := os.WriteFile(notGoExecutable, []byte("not a Go executable"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(temp, "missing-repopass")},
		{"malformed file", notGoExecutable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ValidateFile(test.path, FullCLIIdentity, testedRevision, "full-cli")
			want := []Result{{
				Status:  StatusFail,
				Code:    CodeBuildInfoUnreadable,
				Subject: "full-cli",
			}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("ValidateFile() = %#v, want only %#v", got, want)
			}
		})
	}
}

func TestAggregatePrecedence(t *testing.T) {
	tests := []struct {
		name    string
		results []Result
		want    Status
	}{
		{
			name: "all pass",
			results: []Result{
				{Status: StatusPass, Code: Code("SOURCE"), Subject: "source"},
				{Status: StatusPass, Code: Code("BINARY"), Subject: "binary"},
			},
			want: StatusPass,
		},
		{
			name: "not run outranks pass",
			results: []Result{
				{Status: StatusPass, Code: Code("SOURCE"), Subject: "source"},
				{Status: StatusNotRun, Code: CodeRequiredCheckNotRun, Subject: "binary"},
			},
			want: StatusNotRun,
		},
		{
			name: "fail outranks not run and pass",
			results: []Result{
				{Status: StatusNotRun, Code: CodeRequiredCheckNotRun, Subject: "binary"},
				{Status: StatusPass, Code: Code("SOURCE"), Subject: "source"},
				{Status: StatusFail, Code: CodeModulePathMismatch, Subject: "full-cli"},
			},
			want: StatusFail,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Aggregate(test.results)
			if got.Status != test.want {
				t.Fatalf("Aggregate().Status = %q, want %q", got.Status, test.want)
			}
			if test.want != StatusFail && got.FirstFailure != nil {
				t.Fatalf("Aggregate().FirstFailure = %#v without a FAIL", got.FirstFailure)
			}
		})
	}
}

func TestAggregateSortsDeduplicatesAndRetainsFirstFailure(t *testing.T) {
	firstFailure := Result{Status: StatusFail, Code: CodeSourceTreeDirty, Subject: "artifact-b"}
	input := []Result{
		{Status: StatusPass, Code: Code("Z_PASS"), Subject: "subject-b"},
		{Status: StatusNotRun, Code: CodeRequiredCheckNotRun, Subject: "check-z"},
		firstFailure,
		{Status: StatusFail, Code: CodeModulePathMismatch, Subject: "artifact-z"},
		firstFailure, // only this byte-for-byte identical tuple is removed
		{Status: StatusFail, Code: CodeSourceRevisionMismatch, Subject: "artifact-a"},
		{Status: StatusNotRun, Code: CodeRequiredCheckNotRun, Subject: "check-a"},
		{Status: StatusPass, Code: Code("A_PASS"), Subject: "subject-z"},
		{Status: StatusPass, Code: Code("A_PASS"), Subject: "subject-a"},
		{Status: StatusFail, Code: CodeModulePathMismatch, Subject: "artifact-a"},
	}

	got := Aggregate(input)
	wantResults := []Result{
		{Status: StatusFail, Code: CodeModulePathMismatch, Subject: "artifact-a"},
		{Status: StatusFail, Code: CodeModulePathMismatch, Subject: "artifact-z"},
		{Status: StatusFail, Code: CodeSourceRevisionMismatch, Subject: "artifact-a"},
		{Status: StatusFail, Code: CodeSourceTreeDirty, Subject: "artifact-b"},
		{Status: StatusNotRun, Code: CodeRequiredCheckNotRun, Subject: "check-a"},
		{Status: StatusNotRun, Code: CodeRequiredCheckNotRun, Subject: "check-z"},
		{Status: StatusPass, Code: Code("A_PASS"), Subject: "subject-a"},
		{Status: StatusPass, Code: Code("A_PASS"), Subject: "subject-z"},
		{Status: StatusPass, Code: Code("Z_PASS"), Subject: "subject-b"},
	}
	if got.Status != StatusFail {
		t.Fatalf("Aggregate().Status = %q, want %q", got.Status, StatusFail)
	}
	if !reflect.DeepEqual(got.Results, wantResults) {
		t.Fatalf("Aggregate().Results = %#v, want %#v", got.Results, wantResults)
	}
	if got.FirstFailure == nil || *got.FirstFailure != firstFailure {
		t.Fatalf("Aggregate().FirstFailure = %#v, want execution-order failure %#v", got.FirstFailure, firstFailure)
	}
}

func TestAggregateDeduplicatesOnlyIdenticalTuples(t *testing.T) {
	input := []Result{
		{Status: StatusFail, Code: Code("X"), Subject: "a"},
		{Status: StatusFail, Code: Code("X"), Subject: "a"},
		{Status: StatusFail, Code: Code("X"), Subject: "b"},
		{Status: StatusFail, Code: Code("Y"), Subject: "a"},
		{Status: StatusPass, Code: Code("X"), Subject: "a"},
	}
	want := []Result{
		{Status: StatusFail, Code: Code("X"), Subject: "a"},
		{Status: StatusFail, Code: Code("X"), Subject: "b"},
		{Status: StatusFail, Code: Code("Y"), Subject: "a"},
		{Status: StatusPass, Code: Code("X"), Subject: "a"},
	}
	if got := Aggregate(input).Results; !reflect.DeepEqual(got, want) {
		t.Fatalf("Aggregate().Results = %#v, want %#v", got, want)
	}
}

func exactBuildInfo(identity BuildIdentity) *debug.BuildInfo {
	return &debug.BuildInfo{
		Path: identity.MainPackage,
		Main: debug.Module{
			Path: identity.ModulePath,
		},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: testedRevision},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

func requireFailureCode(t *testing.T, got []Result, want Code) {
	t.Helper()
	for _, result := range got {
		if result.Status == StatusFail && result.Code == want {
			return
		}
	}
	t.Fatalf("results = %#v, want FAIL/%s", got, want)
}

func requireOnlyFailureCodes(t *testing.T, got []Result, want ...Code) {
	t.Helper()
	actualCodes := make([]string, 0, len(got))
	for _, result := range got {
		if result.Status != StatusFail {
			t.Fatalf("result = %#v, want only FAIL results", result)
		}
		actualCodes = append(actualCodes, string(result.Code))
	}
	wantCodes := make([]string, len(want))
	for index, code := range want {
		wantCodes[index] = string(code)
	}
	sort.Strings(actualCodes)
	sort.Strings(wantCodes)
	if !reflect.DeepEqual(actualCodes, wantCodes) {
		t.Fatalf("failure codes = %q, want %q (full results: %#v)", actualCodes, wantCodes, got)
	}
}
