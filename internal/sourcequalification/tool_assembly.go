package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"
)

const (
	qualificationToolManifestFilename = "source-qualification-tool-manifest-v1.json"
	qualificationToolStagingPrefix    = ".repopass-source-qualification-tools-"
)

func assembleQualificationTools(
	packageDir, linuxController, windowsController, outputDir string,
) (toolManifestDigest string, returnErr error) {
	packagePath, err := canonicalPackageFilesystemPath(packageDir)
	if err != nil {
		return "", err
	}
	linuxControllerPath, err := canonicalPackageFilesystemPath(linuxController)
	if err != nil {
		return "", err
	}
	windowsControllerPath, err := canonicalPackageFilesystemPath(windowsController)
	if err != nil {
		return "", err
	}
	outputPath, err := canonicalPackageFilesystemPath(outputDir)
	if err != nil {
		return "", err
	}
	outputParent := filepath.Dir(outputPath)
	if outputParent == outputPath || packagePathContains(packagePath, outputPath) ||
		packagePathContains(outputPath, packagePath) ||
		packagePathContains(outputPath, linuxControllerPath) ||
		packagePathContains(outputPath, windowsControllerPath) {
		return "", errors.New("source qualification tool assembly paths overlap")
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return "", err
	}

	packageSpecifications := []packageFileSpec{
		{name: archiveFilename, maxBytes: maxArchiveBytes},
		{name: qualificationManifestFilename, maxBytes: int64(maxManifestBytes)},
		{name: qualificationLinuxReceiptFilename, maxBytes: int64(receiptMaxBytes)},
		{name: qualificationWindowsReceiptFilename, maxBytes: int64(receiptMaxBytes)},
	}
	packageRead, err := readExactPackageDirectory(packagePath, packageSpecifications)
	if err != nil {
		return "", errors.New("source qualification aggregate package is invalid")
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
		return "", errors.New("source qualification aggregate package bindings are invalid")
	}
	linuxReceipt, err := parseCanonicalReceipt(linuxReceiptBytes, LaneLinuxAMD64)
	if err != nil || linuxReceipt.QualificationStatus != StatusPass {
		return "", errors.New("source qualification Linux receipt is not passing")
	}
	windowsReceipt, err := parseCanonicalReceipt(windowsReceiptBytes, LaneWindowsAMD64)
	if err != nil || windowsReceipt.QualificationStatus != StatusPass {
		return "", errors.New("source qualification Windows receipt is not passing")
	}
	subject := sourceSubjectFromReceipt(linuxReceipt.Subject)

	linuxIdentity, linuxBytes, err := inspectQualificationController(
		linuxControllerPath,
		"linux",
		subject.TestedRevision,
	)
	if err != nil || linuxIdentity != linuxReceipt.Controller {
		return "", errors.New("source qualification Linux controller is invalid")
	}
	windowsIdentity, windowsBytes, err := inspectQualificationController(
		windowsControllerPath,
		"windows",
		subject.TestedRevision,
	)
	if err != nil || windowsIdentity != windowsReceipt.Controller {
		return "", errors.New("source qualification Windows controller is invalid")
	}

	toolManifest, err := marshalToolManifest(subject, linuxBytes, windowsBytes)
	if err != nil {
		return "", errors.New("source qualification tool manifest could not be created")
	}
	if _, err := parseCanonicalToolManifest(
		toolManifest,
		subject,
		linuxBytes,
		windowsBytes,
	); err != nil {
		return "", errors.New("source qualification tool manifest verification failed")
	}
	toolManifestDigest = sha256Digest(toolManifest)

	parent, parentSnapshot, err := openValidatedPackageDirectory(outputParent)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if parentSnapshot.identity == packageRead.snapshot.identity {
		return "", errors.New("source qualification tool output parent overlaps the aggregate package")
	}

	stagingPath := ""
	defer func() {
		if stagingPath == "" {
			return
		}
		if err := os.RemoveAll(stagingPath); err != nil {
			toolManifestDigest = ""
			returnErr = errors.New("source qualification tool staging cleanup failed")
		}
	}()

	stagingPath, err = os.MkdirTemp(outputParent, qualificationToolStagingPrefix)
	if err != nil {
		return "", errors.New("source qualification tool staging directory could not be created")
	}
	if err := securePrivatePackagePath(stagingPath, true); err != nil {
		return "", errors.New("source qualification tool staging permissions could not be restricted")
	}
	if err := requirePrivatePackageDirectory(stagingPath); err != nil {
		return "", err
	}
	if err := requirePackageDirectoryIdentity(outputParent, parentSnapshot.identity); err != nil {
		return "", err
	}

	outputSpecifications := []packageFileSpec{
		{name: toolManifestLinuxPath, maxBytes: int64(len(linuxBytes)), expected: linuxBytes},
		{name: toolManifestWindowsPath, maxBytes: int64(len(windowsBytes)), expected: windowsBytes},
		{name: qualificationToolManifestFilename, maxBytes: int64(toolManifestMaxBytes), expected: toolManifest},
	}
	for _, specification := range outputSpecifications {
		if err := writePrivatePackageFile(
			filepath.Join(stagingPath, specification.name),
			specification.expected,
		); err != nil {
			return "", err
		}
	}
	stagedTools, err := readExactPackageDirectory(stagingPath, outputSpecifications)
	if err != nil {
		return "", errors.New("source qualification staged tool directory verification failed")
	}
	staging, stagingSnapshot, err := openValidatedPackageDirectory(stagingPath)
	if err != nil {
		return "", err
	}
	if stagingSnapshot != stagedTools.snapshot {
		_ = staging.Close()
		return "", errors.New("source qualification staged tool directory changed before synchronization")
	}
	if err := syncPackageDirectory(staging); err != nil {
		_ = staging.Close()
		return "", errors.New("source qualification staged tool directory could not be synchronized")
	}
	if err := staging.Close(); err != nil {
		return "", errors.New("source qualification staged tool directory could not be closed")
	}

	if err := requirePackageDirectoryIdentity(outputParent, parentSnapshot.identity); err != nil {
		return "", err
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return "", err
	}
	if err := publishPackageDirectoryNoReplace(stagingPath, outputPath); err != nil {
		return "", errors.New("source qualification tool directory publication failed")
	}
	stagingPath = ""
	if err := syncPublishedPackageParent(parent); err != nil {
		if cleanupErr := cleanupPublishedPackage(
			outputPath,
			stagedTools.snapshot.identity,
			outputSpecifications,
			parent,
		); cleanupErr != nil {
			return "", errors.New("source qualification published tool directory cleanup failed")
		}
		return "", errors.New("source qualification tool output parent could not be synchronized")
	}

	return toolManifestDigest, nil
}
