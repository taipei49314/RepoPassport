package sourcequalification

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

type qualificationPackageReport struct {
	PackageDigest     string
	Subject           Subject
	LinuxRun          receiptRun
	WindowsRun        receiptRun
	LinuxController   receiptController
	WindowsController receiptController
}

type qualificationSubjectRequest struct {
	PackageDir                 string
	ExpectedRepository         string
	ExpectedBaseRevision       string
	ExpectedTestedRevision     string
	ExpectedTreeSHA            string
	ExpectedQualificationRunID string
	ExpectedWorkflowRunID      string
	ExpectedWorkflowRunAttempt int64
	ExpectedPackageDigest      string
	ToolManifestPath           string
	ExpectedToolManifestDigest string
	ExpectedExecutableDigest   string
}

type qualificationExecutableSnapshot struct {
	file       *os.File
	path       string
	parentPath string
	snapshot   packageFileSnapshot
	size       int64
	digest     [sha256.Size]byte
}

func inspectQualificationPackage(directory string) (qualificationPackageReport, error) {
	packagePath, err := canonicalPackageFilesystemPath(directory)
	if err != nil {
		return qualificationPackageReport{}, errors.New("source qualification package path is invalid")
	}
	specifications := []packageFileSpec{
		{name: archiveFilename, maxBytes: maxArchiveBytes},
		{name: qualificationManifestFilename, maxBytes: int64(maxManifestBytes)},
		{name: qualificationLinuxReceiptFilename, maxBytes: int64(receiptMaxBytes)},
		{name: qualificationWindowsReceiptFilename, maxBytes: int64(receiptMaxBytes)},
	}
	packageRead, err := readExactPackageDirectory(packagePath, specifications)
	if err != nil {
		return qualificationPackageReport{}, errors.New("source qualification package inventory is invalid")
	}
	archive := packageRead.files[archiveFilename]
	manifest := packageRead.files[qualificationManifestFilename]
	linuxReceiptBytes := packageRead.files[qualificationLinuxReceiptFilename]
	windowsReceiptBytes := packageRead.files[qualificationWindowsReceiptFilename]
	if err := verifyReceiptPackageBindings(
		archive,
		manifest,
		linuxReceiptBytes,
		windowsReceiptBytes,
	); err != nil {
		return qualificationPackageReport{}, errors.New("source qualification package bindings are invalid")
	}
	linuxReceipt, err := parseCanonicalReceipt(linuxReceiptBytes, LaneLinuxAMD64)
	if err != nil || linuxReceipt.QualificationStatus != StatusPass {
		return qualificationPackageReport{}, errors.New("source qualification package Linux receipt is not passing")
	}
	windowsReceipt, err := parseCanonicalReceipt(windowsReceiptBytes, LaneWindowsAMD64)
	if err != nil || windowsReceipt.QualificationStatus != StatusPass {
		return qualificationPackageReport{}, errors.New("source qualification package Windows receipt is not passing")
	}

	return qualificationPackageReport{
		PackageDigest: qualificationPackageDigest(
			archive,
			manifest,
			linuxReceiptBytes,
			windowsReceiptBytes,
		),
		Subject:           sourceSubjectFromReceipt(linuxReceipt.Subject),
		LinuxRun:          linuxReceipt.Run,
		WindowsRun:        windowsReceipt.Run,
		LinuxController:   linuxReceipt.Controller,
		WindowsController: windowsReceipt.Controller,
	}, nil
}

func verifyQualificationSubject(
	request qualificationSubjectRequest,
) (qualificationPackageReport, error) {
	if err := validateQualificationSubjectRequest(request); err != nil {
		return qualificationPackageReport{}, err
	}

	self, err := openQualificationExecutableSnapshot()
	if err != nil {
		return qualificationPackageReport{}, err
	}
	defer self.close()
	if request.ExpectedExecutableDigest != self.digestString() {
		return qualificationPackageReport{}, errors.New("source qualification executable digest does not match")
	}

	report, err := inspectQualificationPackage(request.PackageDir)
	if err != nil {
		return qualificationPackageReport{}, errors.New("source qualification subject package is invalid")
	}
	if !qualificationReportMatchesRequest(report, request) {
		return qualificationPackageReport{}, errors.New("source qualification subject does not match expected values")
	}

	toolManifest, err := inspectQualificationToolManifest(request.ToolManifestPath)
	if err != nil {
		return qualificationPackageReport{}, err
	}
	if request.ExpectedToolManifestDigest != sha256Digest(toolManifest) {
		return qualificationPackageReport{}, errors.New("source qualification tool manifest digest does not match")
	}
	parsedToolManifest, err := decodeCanonicalToolManifest(toolManifest)
	if err != nil {
		return qualificationPackageReport{}, errors.New("source qualification tool manifest is invalid")
	}
	if err := bindQualificationToolManifest(parsedToolManifest, report, self); err != nil {
		return qualificationPackageReport{}, err
	}
	if err := self.finish(); err != nil {
		return qualificationPackageReport{}, err
	}
	return report, nil
}

func validateQualificationSubjectRequest(request qualificationSubjectRequest) error {
	if request.PackageDir == "" || request.ToolManifestPath == "" ||
		request.ExpectedRepository != canonicalRepositoryURL ||
		!validReceiptGitSHA1(request.ExpectedBaseRevision) ||
		!validReceiptGitSHA1(request.ExpectedTestedRevision) ||
		!validReceiptGitSHA1(request.ExpectedTreeSHA) ||
		!validReceiptSHA256(request.ExpectedQualificationRunID) ||
		!validReceiptPositiveDecimal(request.ExpectedWorkflowRunID, 20) ||
		request.ExpectedWorkflowRunAttempt < 1 ||
		request.ExpectedWorkflowRunAttempt > receiptMaxInt32 ||
		!validReceiptSHA256(request.ExpectedPackageDigest) ||
		!validReceiptSHA256(request.ExpectedToolManifestDigest) ||
		!validReceiptSHA256(request.ExpectedExecutableDigest) {
		return errors.New("source qualification subject request is invalid")
	}
	return nil
}

func qualificationReportMatchesRequest(
	report qualificationPackageReport,
	request qualificationSubjectRequest,
) bool {
	if report.PackageDigest != request.ExpectedPackageDigest ||
		report.Subject.Repository != request.ExpectedRepository ||
		report.Subject.BaseRevision != request.ExpectedBaseRevision ||
		report.Subject.TestedRevision != request.ExpectedTestedRevision ||
		report.Subject.TreeSHA != request.ExpectedTreeSHA {
		return false
	}
	for _, run := range []receiptRun{report.LinuxRun, report.WindowsRun} {
		if run.QualificationRunID != request.ExpectedQualificationRunID ||
			run.WorkflowRunID != request.ExpectedWorkflowRunID ||
			run.WorkflowRunAttempt != request.ExpectedWorkflowRunAttempt {
			return false
		}
	}
	return true
}

func inspectQualificationToolManifest(path string) ([]byte, error) {
	manifestPath, err := canonicalPackageFilesystemPath(path)
	if err != nil {
		return nil, errors.New("source qualification tool manifest path is invalid")
	}
	parentPath := filepath.Dir(manifestPath)
	if err := validatePackageDirectoryChain(parentPath); err != nil {
		return nil, errors.New("source qualification tool manifest directory is unsafe")
	}
	raw, snapshot, err := readStablePackageFile(manifestPath, int64(toolManifestMaxBytes), nil)
	if err != nil {
		return nil, errors.New("source qualification tool manifest could not be read safely")
	}
	if err := validatePackageDirectoryChain(parentPath); err != nil {
		return nil, errors.New("source qualification tool manifest directory changed")
	}
	if err := requirePackageFileIdentity(manifestPath, snapshot); err != nil {
		return nil, errors.New("source qualification tool manifest path changed")
	}
	return raw, nil
}

func bindQualificationToolManifest(
	manifest sourceQualificationToolManifest,
	report qualificationPackageReport,
	self *qualificationExecutableSnapshot,
) error {
	if manifest.ArtifactType != toolManifestArtifactType ||
		manifest.SchemaVersion != toolManifestSchemaVersion ||
		validateSourceSubject(manifest.Subject) != nil ||
		manifest.Subject != report.Subject || len(manifest.Tools) != 2 {
		return errors.New("source qualification tool manifest contract is invalid")
	}
	if !qualificationToolMatchesController(
		manifest.Tools[0],
		"linux",
		toolManifestLinuxPath,
		report.Subject,
		report.LinuxController,
	) || !qualificationToolMatchesController(
		manifest.Tools[1],
		"windows",
		toolManifestWindowsPath,
		report.Subject,
		report.WindowsController,
	) {
		return errors.New("source qualification tool manifest controller binding is invalid")
	}
	if runtime.GOARCH != "amd64" || (runtime.GOOS != "linux" && runtime.GOOS != "windows") {
		return errors.New("source qualification executable platform is unsupported")
	}
	selected := manifest.Tools[0]
	selectedController := report.LinuxController
	if runtime.GOOS == "windows" {
		selected = manifest.Tools[1]
		selectedController = report.WindowsController
	}
	if selected.SHA256 != self.digestString() ||
		selectedController.SHA256 != self.digestString() ||
		selected.Size != self.size {
		return errors.New("source qualification executable does not match its runtime lane")
	}
	return nil
}

func qualificationToolMatchesController(
	tool sourceQualificationTool,
	expectedGOOS, expectedPath string,
	subject Subject,
	controller receiptController,
) bool {
	return tool.GOARCH == "amd64" &&
		tool.GOOS == expectedGOOS &&
		tool.GoVersion == toolManifestGoVersion &&
		tool.MainPackage == toolManifestMainPackage &&
		tool.ModulePath == toolManifestModulePath &&
		tool.Path == expectedPath &&
		validReceiptSHA256(tool.SHA256) &&
		tool.Size > 0 && tool.Size <= buildidentity.MaxExecutableBytes &&
		!tool.VCSModified &&
		tool.VCSRevision == subject.TestedRevision &&
		tool.GoVersion == controller.GoVersion &&
		tool.MainPackage == controller.MainPackage &&
		tool.ModulePath == controller.ModulePath &&
		tool.SHA256 == controller.SHA256 &&
		tool.VCSModified == controller.VCSModified &&
		tool.VCSRevision == controller.VCSRevision
}

func openQualificationExecutableSnapshot() (*qualificationExecutableSnapshot, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, errors.New("source qualification executable path is unavailable")
	}
	path, err = canonicalPackageFilesystemPath(path)
	if err != nil {
		return nil, errors.New("source qualification executable path is invalid")
	}
	parentPath := filepath.Dir(path)
	if err := validatePackageDirectoryChain(parentPath); err != nil {
		return nil, errors.New("source qualification executable directory is unsafe")
	}
	file, err := openPackageRegularFile(path)
	if err != nil {
		return nil, errors.New("source qualification executable could not be opened safely")
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = file.Close()
		}
	}()
	snapshot, err := snapshotPackageHandle(file, false)
	if err != nil || snapshot.size <= 0 || snapshot.size > buildidentity.MaxExecutableBytes {
		return nil, errors.New("source qualification executable metadata is invalid")
	}
	digest, err := hashQualificationExecutable(file, snapshot.size)
	if err != nil {
		return nil, errors.New("source qualification executable could not be hashed")
	}
	afterHash, err := snapshotPackageHandle(file, false)
	if err != nil || snapshot != afterHash ||
		validatePackageDirectoryChain(parentPath) != nil ||
		requirePackageFileIdentity(path, snapshot) != nil {
		return nil, errors.New("source qualification executable changed during initial hashing")
	}
	keepOpen = true
	return &qualificationExecutableSnapshot{
		file:       file,
		path:       path,
		parentPath: parentPath,
		snapshot:   snapshot,
		size:       snapshot.size,
		digest:     digest,
	}, nil
}

func (snapshot *qualificationExecutableSnapshot) finish() error {
	if snapshot == nil || snapshot.file == nil {
		return errors.New("source qualification executable handle is invalid")
	}
	digest, hashErr := hashQualificationExecutable(snapshot.file, snapshot.size)
	last, snapshotErr := snapshotPackageHandle(snapshot.file, false)
	chainErr := validatePackageDirectoryChain(snapshot.parentPath)
	pathErr := requirePackageFileIdentity(snapshot.path, snapshot.snapshot)
	closeErr := snapshot.file.Close()
	snapshot.file = nil
	if hashErr != nil || snapshotErr != nil || last != snapshot.snapshot ||
		chainErr != nil || pathErr != nil || closeErr != nil ||
		subtle.ConstantTimeCompare(snapshot.digest[:], digest[:]) != 1 {
		return errors.New("source qualification executable changed during verification")
	}
	return nil
}

func (snapshot *qualificationExecutableSnapshot) close() {
	if snapshot != nil && snapshot.file != nil {
		_ = snapshot.file.Close()
		snapshot.file = nil
	}
}

func (snapshot *qualificationExecutableSnapshot) digestString() string {
	if snapshot == nil {
		return ""
	}
	return "sha256:" + hex.EncodeToString(snapshot.digest[:])
}

func hashQualificationExecutable(file *os.File, size int64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if file == nil || size <= 0 || size > buildidentity.MaxExecutableBytes {
		return result, errors.New("source qualification executable hash input is invalid")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.NewSectionReader(file, 0, size))
	if err != nil || written != size {
		return result, errors.New("source qualification executable hash is incomplete")
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}
