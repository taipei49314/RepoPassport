// Package buildidentity validates the build identity embedded in release
// executables.
package buildidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"debug/buildinfo"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
)

const (
	CanonicalModulePath string = "github.com/taipei49314/RepoPassport"
	LegacyModulePath    string = "github.com/repopass/repopass"

	// MaxExecutableBytes bounds executable build-information parsing. Release
	// kit members apply their smaller, format-specific bound before calling
	// ValidateReaderAt.
	MaxExecutableBytes int64 = 128 << 20
)

// BuildIdentity is the exact module and main-package pair required for an
// executable.
type BuildIdentity struct {
	ModulePath  string
	MainPackage string
}

var (
	FullCLIIdentity = BuildIdentity{
		ModulePath:  CanonicalModulePath,
		MainPackage: CanonicalModulePath + "/cmd/repopass",
	}
	VerifierIdentity = BuildIdentity{
		ModulePath:  CanonicalModulePath,
		MainPackage: CanonicalModulePath + "/cmd/repopass-verify",
	}
	HostKitHelperIdentity = BuildIdentity{
		ModulePath:  CanonicalModulePath,
		MainPackage: CanonicalModulePath + "/cmd/repopass-kit",
	}
)

// Status is a build-identity qualification result status.
type Status string

const (
	StatusPass   Status = "PASS"
	StatusFail   Status = "FAIL"
	StatusNotRun Status = "NOT_RUN"
)

// Code is a stable build-identity qualification result code.
type Code string

const (
	CodeModulePathMismatch      Code = "MODULE_PATH_MISMATCH"
	CodePackagePathMismatch     Code = "PACKAGE_PATH_MISMATCH"
	CodeMainPackagePathMismatch Code = "MAIN_PACKAGE_PATH_MISMATCH"
	CodeLegacyModuleReference   Code = "LEGACY_MODULE_REFERENCE"
	CodeBuildInfoUnreadable     Code = "BUILD_INFO_UNREADABLE"
	CodeSourceRevisionMismatch  Code = "SOURCE_REVISION_MISMATCH"
	CodeSourceTreeDirty         Code = "SOURCE_TREE_DIRTY"
	CodeExternalImportFailed    Code = "EXTERNAL_IMPORT_FAILED"
	CodeRequiredCheckNotRun     Code = "REQUIRED_CHECK_NOT_RUN"
)

// Result is one qualification observation.
type Result struct {
	Status  Status
	Code    Code
	Subject string
}

// Summary is a deterministic aggregate of qualification observations.
type Summary struct {
	Status       Status
	Results      []Result
	FirstFailure *Result
}

// ValidateBuildInfo returns failure observations for an already parsed Go
// build-information record. A valid record produces no observations.
func ValidateBuildInfo(info *debug.BuildInfo, expected BuildIdentity, testedRevision, subject string) []Result {
	if info == nil {
		return unreadable(subject)
	}

	results := make([]Result, 0, 5)
	if info.Main.Path != expected.ModulePath || info.Main.Replace != nil {
		results = append(results, failure(CodeModulePathMismatch, subject))
	}
	if info.Path != expected.MainPackage {
		results = append(results, failure(CodeMainPackagePathMismatch, subject))
	}
	if referencesLegacyModule(info) {
		results = append(results, failure(CodeLegacyModuleReference, subject))
	}

	revisionCount := 0
	revisionMatches := false
	modifiedCount := 0
	modifiedIsFalse := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revisionCount++
			revisionMatches = setting.Value == testedRevision
		case "vcs.modified":
			modifiedCount++
			modifiedIsFalse = setting.Value == "false"
		}
	}
	if revisionCount != 1 || !revisionMatches {
		results = append(results, failure(CodeSourceRevisionMismatch, subject))
	}
	if modifiedCount != 1 || !modifiedIsFalse {
		results = append(results, failure(CodeSourceTreeDirty, subject))
	}
	return results
}

// ValidateReaderAt parses a bounded executable snapshot and validates its
// build information. Invalid bounds and unreadable build information produce
// only BUILD_INFO_UNREADABLE.
func ValidateReaderAt(reader io.ReaderAt, size int64, expected BuildIdentity, testedRevision, subject string) []Result {
	if reader == nil || size < 1 || size > MaxExecutableBytes {
		return unreadable(subject)
	}
	info, err := buildinfo.Read(io.NewSectionReader(reader, 0, size))
	if err != nil {
		return unreadable(subject)
	}
	return ValidateBuildInfo(info, expected, testedRevision, subject)
}

// ValidateFile reads and validates a bounded regular file through one fixed
// handle. Symlinks, replacements, and files that change during inspection are
// treated as unreadable.
func ValidateFile(path string, expected BuildIdentity, testedRevision, subject string) []Result {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return unreadable(subject)
	}
	before, err := os.Lstat(absolute)
	if err != nil || !validExecutableFile(before) {
		return unreadable(subject)
	}

	file, err := os.Open(absolute)
	if err != nil {
		return unreadable(subject)
	}
	opened, err := file.Stat()
	if err != nil || !sameExecutableFile(before, opened) {
		_ = file.Close()
		return unreadable(subject)
	}

	raw := make([]byte, before.Size())
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, before.Size()), raw); err != nil {
		_ = file.Close()
		return unreadable(subject)
	}
	results := ValidateReaderAt(bytes.NewReader(raw), int64(len(raw)), expected, testedRevision, subject)
	firstDigest := sha256.Sum256(raw)
	secondHash := sha256.New()
	count, readErr := io.Copy(secondHash, io.NewSectionReader(file, 0, before.Size()))

	pathAfter, pathErr := os.Lstat(absolute)
	openedAfter, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || count != before.Size() ||
		subtle.ConstantTimeCompare(firstDigest[:], secondHash.Sum(nil)) != 1 ||
		pathErr != nil || statErr != nil || closeErr != nil ||
		!sameExecutableFile(before, openedAfter) || !sameExecutableFile(before, pathAfter) {
		return unreadable(subject)
	}
	return results
}

// Aggregate returns a fail-first summary without modifying results. Only
// byte-for-byte identical status/code/subject tuples are deduplicated.
func Aggregate(results []Result) Summary {
	status := StatusPass
	var firstFailure *Result
	unique := make([]Result, 0, len(results))
	seen := make(map[Result]struct{}, len(results))
	for _, result := range results {
		if result.Status == StatusFail {
			if firstFailure == nil {
				first := result
				firstFailure = &first
			}
			status = StatusFail
		} else if result.Status == StatusNotRun && status != StatusFail {
			status = StatusNotRun
		}
		if _, exists := seen[result]; exists {
			continue
		}
		seen[result] = struct{}{}
		unique = append(unique, result)
	}

	sort.Slice(unique, func(i, j int) bool {
		left, right := unique[i], unique[j]
		if leftRank, rightRank := statusRank(left.Status), statusRank(right.Status); leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		return left.Subject < right.Subject
	})
	return Summary{Status: status, Results: unique, FirstFailure: firstFailure}
}

func failure(code Code, subject string) Result {
	return Result{Status: StatusFail, Code: code, Subject: subject}
}

func unreadable(subject string) []Result {
	return []Result{failure(CodeBuildInfoUnreadable, subject)}
}

func referencesLegacyModule(info *debug.BuildInfo) bool {
	if containsLegacyModule(info.GoVersion) || containsLegacyModule(info.Path) {
		return true
	}
	seen := make(map[*debug.Module]struct{})
	if moduleReferencesLegacy(&info.Main, seen) {
		return true
	}
	for _, dependency := range info.Deps {
		if moduleReferencesLegacy(dependency, seen) {
			return true
		}
	}
	for _, setting := range info.Settings {
		if containsLegacyModule(setting.Key) || containsLegacyModule(setting.Value) {
			return true
		}
	}
	return false
}

func moduleReferencesLegacy(module *debug.Module, seen map[*debug.Module]struct{}) bool {
	if module == nil {
		return false
	}
	if _, exists := seen[module]; exists {
		return false
	}
	seen[module] = struct{}{}
	return containsLegacyModule(module.Path) ||
		containsLegacyModule(module.Version) ||
		containsLegacyModule(module.Sum) ||
		moduleReferencesLegacy(module.Replace, seen)
}

func containsLegacyModule(value string) bool {
	return strings.Contains(value, LegacyModulePath)
}

func validExecutableFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Size() >= 1 && info.Size() <= MaxExecutableBytes
}

func sameExecutableFile(before, after os.FileInfo) bool {
	return validExecutableFile(before) && validExecutableFile(after) &&
		os.SameFile(before, after) && before.Size() == after.Size() &&
		before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}

func statusRank(status Status) int {
	switch status {
	case StatusFail:
		return 0
	case StatusNotRun:
		return 1
	case StatusPass:
		return 2
	default:
		return 3
	}
}
