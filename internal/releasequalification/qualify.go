package releasequalification

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

var exactObjectID = regexp.MustCompile(`^[0-9a-f]{40}$`)

var readQualificationChecksumSnapshot = readStableQualificationFile

type requiredArtifact struct {
	id       string
	name     string
	identity buildidentity.BuildIdentity
}

var preHelperArtifacts = []requiredArtifact{
	{id: "full-linux-amd64", name: "repopass-linux-amd64", identity: buildidentity.FullCLIIdentity},
	{id: "full-windows-amd64", name: "repopass-windows-amd64.exe", identity: buildidentity.FullCLIIdentity},
	{id: "verifier-linux-amd64", name: "repopass-verify-linux-amd64", identity: buildidentity.VerifierIdentity},
	{id: "verifier-windows-amd64", name: "repopass-verify-windows-amd64.exe", identity: buildidentity.VerifierIdentity},
	{id: "kit-helper-host", name: "repopass-kit-host.exe", identity: buildidentity.HostKitHelperIdentity},
}

var prePublishArtifacts = preHelperArtifacts[:4]

type requiredKit struct {
	id           string
	name         string
	targetOS     string
	verifierName string
}

var prePublishKits = []requiredKit{
	{id: "kit-linux-amd64", name: "repopass-verify-linux-amd64.tar", targetOS: "linux", verifierName: "repopass-verify-linux-amd64"},
	{id: "kit-windows-amd64", name: "repopass-verify-windows-amd64.tar", targetOS: "windows", verifierName: "repopass-verify-windows-amd64.exe"},
}

// QualifyPreHelper inspects the exact two full executables, two standalone
// verifiers, and host-only kit helper before any helper is executed.
func QualifyPreHelper(root, testedRevision, treeSHA string) (QualificationReport, error) {
	if err := validateQualificationInputs(testedRevision, treeSHA); err != nil {
		return QualificationReport{}, err
	}

	expectedNames := requiredArtifactNames(preHelperArtifacts)
	structuralFailure := !qualificationInventoryExact(root, expectedNames)
	report := QualificationReport{
		Artifacts: inspectRequiredArtifacts(root, testedRevision, preHelperArtifacts),
	}
	summary := aggregateQualificationResults(report.Artifacts, nil)
	report.Results = summary.Results
	report.FirstFailure = summary.FirstFailure
	report.Log = qualificationLog(report.Artifacts, nil, testedRevision, treeSHA)
	// Reject a directory replacement or concurrent inventory change as well as
	// an initially malformed staging root.
	structuralFailure = !qualificationInventoryExact(root, expectedNames) || structuralFailure
	report.StructuralFailure = structuralFailure
	if structuralFailure || len(report.Results) != 0 {
		return report, errors.New("pre-helper release qualification failed")
	}
	return report, nil
}

// QualifyPrePublish independently re-inspects the four release executables and
// the two strict portable kits immediately before publication.
func QualifyPrePublish(root, testedRevision, treeSHA string) (QualificationReport, error) {
	if err := validateQualificationInputs(testedRevision, treeSHA); err != nil {
		return QualificationReport{}, err
	}

	expectedNames := append(requiredArtifactNames(prePublishArtifacts), requiredKitNames(prePublishKits)...)
	expectedNames = append(expectedNames, "SHA256SUMS")
	structuralFailure := !qualificationInventoryExact(root, expectedNames)
	report := QualificationReport{
		Artifacts: inspectRequiredArtifacts(root, testedRevision, prePublishArtifacts),
	}
	var kitFailure bool
	report.Kits, kitFailure = inspectRequiredKits(root, testedRevision)
	structuralFailure = structuralFailure || kitFailure
	checksumBefore, checksumExact := qualificationChecksumSnapshotExact(root, report.Artifacts, report.Kits)
	structuralFailure = !checksumExact || structuralFailure

	// Re-inspect every path after reading the checksum file. The final accepted
	// reports therefore bind the same bytes before the caller's atomic rename,
	// rather than trusting filenames after an earlier qualification pass.
	finalArtifacts := inspectRequiredArtifacts(root, testedRevision, prePublishArtifacts)
	finalKits, finalKitFailure := inspectRequiredKits(root, testedRevision)
	if finalKitFailure || !qualificationReportsEqual(report.Artifacts, finalArtifacts, report.Kits, finalKits) {
		structuralFailure = true
	}
	checksumAfter, checksumStillExact := qualificationChecksumSnapshotExact(root, finalArtifacts, finalKits)
	if !checksumStillExact || !bytes.Equal(checksumBefore, checksumAfter) {
		structuralFailure = true
	}
	summary := aggregateQualificationResults(report.Artifacts, report.Kits)
	report.Results = summary.Results
	report.FirstFailure = summary.FirstFailure
	report.Log = qualificationLog(report.Artifacts, report.Kits, testedRevision, treeSHA)
	structuralFailure = !qualificationInventoryExact(root, expectedNames) || structuralFailure
	report.StructuralFailure = structuralFailure
	if structuralFailure || len(report.Results) != 0 {
		return report, errors.New("pre-publish release qualification failed")
	}
	return report, nil
}

func inspectRequiredKits(root, testedRevision string) ([]KitReport, bool) {
	reports := make([]KitReport, 0, len(prePublishKits))
	failed := false
	for _, required := range prePublishKits {
		kit, err := InspectPortableKit(KitSpec{
			ID:                     required.id,
			Path:                   filepath.Join(root, required.name),
			TargetOS:               required.targetOS,
			StandaloneVerifierPath: filepath.Join(root, required.verifierName),
		}, testedRevision)
		reports = append(reports, kit)
		if err != nil {
			failed = true
		}
	}
	return reports, failed
}

func qualificationChecksumSnapshotExact(root string, artifacts []ArtifactReport, kits []KitReport) ([]byte, bool) {
	digests := make(map[string]string, len(artifacts)+len(kits))
	if len(artifacts) != len(prePublishArtifacts) || len(kits) != len(prePublishKits) {
		return nil, false
	}
	for index, report := range artifacts {
		if report.ID != prePublishArtifacts[index].id || !strings.HasPrefix(report.SHA256, "sha256:") {
			return nil, false
		}
		digests[prePublishArtifacts[index].name] = strings.TrimPrefix(report.SHA256, "sha256:")
	}
	for index, report := range kits {
		if report.ID != prePublishKits[index].id || !strings.HasPrefix(report.SHA256, "sha256:") {
			return nil, false
		}
		digests[prePublishKits[index].name] = strings.TrimPrefix(report.SHA256, "sha256:")
	}
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	var expected strings.Builder
	for _, name := range names {
		expected.WriteString(digests[name])
		expected.WriteString("  ")
		expected.WriteString(name)
		expected.WriteByte('\n')
	}
	actual, ok := readQualificationChecksumSnapshot(filepath.Join(root, "SHA256SUMS"), 64<<10)
	return actual, ok && bytes.Equal(actual, []byte(expected.String()))
}

func readStableQualificationFile(path string, maxSize int64) ([]byte, bool) {
	snapshot, err := openQualificationSnapshot(path, 1, maxSize)
	if err != nil {
		return nil, false
	}
	data := make([]byte, snapshot.before.Size())
	if _, err := io.ReadFull(io.NewSectionReader(snapshot.file, 0, snapshot.before.Size()), data); err != nil {
		_ = snapshot.file.Close()
		return nil, false
	}
	digest := qualificationDigest(data)
	if err := finishQualificationSnapshot(snapshot, digest); err != nil {
		return nil, false
	}
	return data, true
}

func qualificationReportsEqual(firstArtifacts, secondArtifacts []ArtifactReport, firstKits, secondKits []KitReport) bool {
	if len(firstArtifacts) != len(secondArtifacts) || len(firstKits) != len(secondKits) {
		return false
	}
	for index := range firstArtifacts {
		if !artifactReportsEqual(firstArtifacts[index], secondArtifacts[index]) {
			return false
		}
	}
	for index := range firstKits {
		if firstKits[index].ID != secondKits[index].ID || firstKits[index].Size != secondKits[index].Size ||
			firstKits[index].SHA256 != secondKits[index].SHA256 ||
			!artifactReportsEqual(firstKits[index].EmbeddedVerifier, secondKits[index].EmbeddedVerifier) {
			return false
		}
	}
	return true
}

func artifactReportsEqual(first, second ArtifactReport) bool {
	if first.ID != second.ID || first.Size != second.Size || first.SHA256 != second.SHA256 ||
		len(first.Results) != len(second.Results) {
		return false
	}
	for index := range first.Results {
		if first.Results[index] != second.Results[index] {
			return false
		}
	}
	return true
}

func requiredArtifactNames(required []requiredArtifact) []string {
	names := make([]string, 0, len(required))
	for _, artifact := range required {
		names = append(names, artifact.name)
	}
	return names
}

func requiredKitNames(required []requiredKit) []string {
	names := make([]string, 0, len(required))
	for _, kit := range required {
		names = append(names, kit.name)
	}
	return names
}

// qualificationInventoryExact rejects missing, extra, non-regular, and link
// entries using exact case-sensitive names. It intentionally returns no path
// detail suitable for accidental propagation into public logs.
func qualificationInventoryExact(root string, expected []string) bool {
	rootInfo, err := os.Lstat(root)
	if err != nil || qualificationPathHasReparsePoint(root) ||
		!rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return false
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(expected) {
		return false
	}
	wanted := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		if _, duplicate := wanted[name]; duplicate {
			return false
		}
		wanted[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := wanted[entry.Name()]; !ok {
			return false
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || qualificationPathHasReparsePoint(path) ||
			!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		delete(wanted, entry.Name())
	}
	return len(wanted) == 0
}

func validateQualificationInputs(testedRevision, treeSHA string) error {
	if !exactObjectID.MatchString(testedRevision) {
		return errors.New("tested revision must be one exact lowercase 40-hex object ID")
	}
	if !exactObjectID.MatchString(treeSHA) {
		return errors.New("tree must be one exact lowercase 40-hex object ID")
	}
	return nil
}

func inspectRequiredArtifacts(root, testedRevision string, required []requiredArtifact) []ArtifactReport {
	reports := make([]ArtifactReport, 0, len(required))
	for _, artifact := range required {
		reports = append(reports, InspectArtifact(ArtifactSpec{
			ID:       artifact.id,
			Path:     filepath.Join(root, artifact.name),
			Identity: artifact.identity,
		}, testedRevision))
	}
	return reports
}

func aggregateQualificationResults(artifacts []ArtifactReport, kits []KitReport) buildidentity.Summary {
	var observed []buildidentity.Result
	for _, artifact := range artifacts {
		observed = append(observed, artifact.Results...)
	}
	for _, kit := range kits {
		observed = append(observed, kit.EmbeddedVerifier.Results...)
	}
	return buildidentity.Aggregate(observed)
}

func qualificationLog(artifacts []ArtifactReport, kits []KitReport, testedRevision, treeSHA string) []LogRecord {
	records := make([]LogRecord, 0, len(artifacts)+len(kits))
	for _, artifact := range artifacts {
		if artifact.SHA256 == "" {
			continue
		}
		records = append(records, LogRecord{
			ID: artifact.ID, SHA256: artifact.SHA256, Revision: testedRevision, Tree: treeSHA,
		})
	}
	for _, kit := range kits {
		if kit.SHA256 == "" {
			continue
		}
		records = append(records, LogRecord{
			ID: kit.ID, SHA256: kit.SHA256, Revision: testedRevision, Tree: treeSHA,
		})
	}
	return records
}
