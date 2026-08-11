package sourcequalification

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	qualificationManifestFilename       = "source-archive-manifest-v1.json"
	qualificationLinuxReceiptFilename   = "source-qualification-linux-amd64-v1.json"
	qualificationWindowsReceiptFilename = "source-qualification-windows-amd64-v1.json"
	qualificationStagingPrefix          = ".repopass-source-qualification-"
)

type packageFileIdentity struct {
	first  uint64
	second uint64
}

type packageFileSnapshot struct {
	identity packageFileIdentity
	size     int64
	mode     os.FileMode
	modTime  int64
}

type packageFileSpec struct {
	name     string
	maxBytes int64
	expected []byte
}

type packageDirectoryRead struct {
	files    map[string][]byte
	snapshot packageFileSnapshot
}

var syncPublishedPackageParent = syncPackageDirectory

func assembleQualificationPackage(linuxDir, windowsDir, outputDir string) (
	packageDigest string,
	returnErr error,
) {
	linuxPath, err := canonicalPackageFilesystemPath(linuxDir)
	if err != nil {
		return "", err
	}
	windowsPath, err := canonicalPackageFilesystemPath(windowsDir)
	if err != nil {
		return "", err
	}
	outputPath, err := canonicalPackageFilesystemPath(outputDir)
	if err != nil {
		return "", err
	}
	outputParent := filepath.Dir(outputPath)
	if outputParent == outputPath || packagePathContains(linuxPath, outputPath) ||
		packagePathContains(windowsPath, outputPath) {
		return "", errors.New("source qualification package paths overlap")
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return "", err
	}

	linux, err := readQualificationLaneDirectory(linuxPath, LaneLinuxAMD64, nil, nil)
	if err != nil {
		return "", err
	}
	windows, err := readQualificationLaneDirectory(
		windowsPath,
		LaneWindowsAMD64,
		linux.files[archiveFilename],
		linux.files[qualificationManifestFilename],
	)
	if err != nil {
		return "", err
	}
	if linux.snapshot.identity == windows.snapshot.identity {
		return "", errors.New("source qualification lane directories are not distinct")
	}

	archive := linux.files[archiveFilename]
	manifest := linux.files[qualificationManifestFilename]
	linuxReceipt := linux.files[qualificationLinuxReceiptFilename]
	windowsReceipt := windows.files[qualificationWindowsReceiptFilename]
	if err := verifyReceiptPackageBindings(archive, manifest, linuxReceipt, windowsReceipt); err != nil {
		return "", errors.New("source qualification lane bindings are invalid")
	}
	parsedLinux, err := parseCanonicalReceipt(linuxReceipt, LaneLinuxAMD64)
	if err != nil || parsedLinux.QualificationStatus != StatusPass {
		return "", errors.New("source qualification Linux lane is not passing")
	}
	parsedWindows, err := parseCanonicalReceipt(windowsReceipt, LaneWindowsAMD64)
	if err != nil || parsedWindows.QualificationStatus != StatusPass {
		return "", errors.New("source qualification Windows lane is not passing")
	}

	parent, parentSnapshot, err := openValidatedPackageDirectory(outputParent)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if parentSnapshot.identity == linux.snapshot.identity ||
		parentSnapshot.identity == windows.snapshot.identity {
		return "", errors.New("source qualification output parent overlaps a lane directory")
	}

	stagingPath := ""
	defer func() {
		if stagingPath == "" {
			return
		}
		if err := os.RemoveAll(stagingPath); err != nil {
			packageDigest = ""
			returnErr = errors.New("source qualification staging cleanup failed")
		}
	}()

	stagingPath, err = os.MkdirTemp(outputParent, qualificationStagingPrefix)
	if err != nil {
		return "", errors.New("source qualification staging directory could not be created")
	}
	if err := securePrivatePackagePath(stagingPath, true); err != nil {
		return "", errors.New("source qualification staging permissions could not be restricted")
	}
	if err := requirePrivatePackageDirectory(stagingPath); err != nil {
		return "", err
	}
	if err := requirePackageDirectoryIdentity(outputParent, parentSnapshot.identity); err != nil {
		return "", err
	}

	outputFiles := []packageFileSpec{
		{name: archiveFilename, maxBytes: maxArchiveBytes, expected: archive},
		{name: qualificationManifestFilename, maxBytes: int64(maxManifestBytes), expected: manifest},
		{name: qualificationLinuxReceiptFilename, maxBytes: int64(receiptMaxBytes), expected: linuxReceipt},
		{name: qualificationWindowsReceiptFilename, maxBytes: int64(receiptMaxBytes), expected: windowsReceipt},
	}
	for _, specification := range outputFiles {
		if err := writePrivatePackageFile(
			filepath.Join(stagingPath, specification.name),
			specification.expected,
		); err != nil {
			return "", err
		}
	}
	stagedPackage, err := readExactPackageDirectory(stagingPath, outputFiles)
	if err != nil {
		return "", errors.New("source qualification staged package verification failed")
	}
	staging, stagingSnapshot, err := openValidatedPackageDirectory(stagingPath)
	if err != nil {
		return "", err
	}
	if stagingSnapshot != stagedPackage.snapshot {
		_ = staging.Close()
		return "", errors.New("source qualification staged package changed before synchronization")
	}
	if err := syncPackageDirectory(staging); err != nil {
		_ = staging.Close()
		return "", errors.New("source qualification staged package could not be synchronized")
	}
	if err := staging.Close(); err != nil {
		return "", errors.New("source qualification staged package could not be closed")
	}

	if err := requirePackageDirectoryIdentity(outputParent, parentSnapshot.identity); err != nil {
		return "", err
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return "", err
	}
	if err := publishPackageDirectoryNoReplace(stagingPath, outputPath); err != nil {
		return "", errors.New("source qualification package publication failed")
	}
	stagingPath = ""
	if err := syncPublishedPackageParent(parent); err != nil {
		if cleanupErr := cleanupPublishedPackage(
			outputPath,
			stagedPackage.snapshot.identity,
			outputFiles,
			parent,
		); cleanupErr != nil {
			return "", errors.New("source qualification published package cleanup failed")
		}
		return "", errors.New("source qualification package parent could not be synchronized")
	}

	return qualificationPackageDigest(archive, manifest, linuxReceipt, windowsReceipt), nil
}

func cleanupPublishedPackage(
	outputPath string,
	expectedIdentity packageFileIdentity,
	specifications []packageFileSpec,
	parent *os.File,
) error {
	directory, snapshot, err := openValidatedPackageDirectory(outputPath)
	if err != nil {
		return errors.New("source qualification published package cleanup target is invalid")
	}
	info, statErr := directory.Stat()
	permissionsErr := error(nil)
	if statErr == nil {
		permissionsErr = validatePrivatePackagePermissions(directory, info, true)
	}
	inventoryErr := error(nil)
	if statErr == nil && permissionsErr == nil && snapshot.identity == expectedIdentity {
		inventoryErr = requireExactPackageInventory(directory, specifications)
	}
	closeErr := directory.Close()
	if statErr != nil || permissionsErr != nil || snapshot.identity != expectedIdentity ||
		inventoryErr != nil || closeErr != nil {
		return errors.New("source qualification published package cleanup target changed")
	}
	if err := os.RemoveAll(outputPath); err != nil {
		return errors.New("source qualification published package could not be removed")
	}
	if err := requirePackageOutputAbsent(outputPath); err != nil {
		return errors.New("source qualification published package removal is incomplete")
	}
	if err := syncPackageDirectory(parent); err != nil {
		return errors.New("source qualification published package removal could not be synchronized")
	}
	return nil
}

func readQualificationLaneDirectory(
	directory string,
	lane Lane,
	expectedArchive, expectedManifest []byte,
) (packageDirectoryRead, error) {
	receiptName := qualificationLinuxReceiptFilename
	if lane == LaneWindowsAMD64 {
		receiptName = qualificationWindowsReceiptFilename
	} else if lane != LaneLinuxAMD64 {
		return packageDirectoryRead{}, errors.New("source qualification lane is invalid")
	}
	specifications := []packageFileSpec{
		{name: archiveFilename, maxBytes: maxArchiveBytes, expected: expectedArchive},
		{name: qualificationManifestFilename, maxBytes: int64(maxManifestBytes), expected: expectedManifest},
		{name: receiptName, maxBytes: int64(receiptMaxBytes)},
	}
	return readExactPackageDirectory(directory, specifications)
}

func readExactPackageDirectory(
	directory string,
	specifications []packageFileSpec,
) (packageDirectoryRead, error) {
	firstDirectory, firstSnapshot, err := openValidatedPackageDirectory(directory)
	if err != nil {
		return packageDirectoryRead{}, err
	}
	defer firstDirectory.Close()
	if err := requireExactPackageInventory(firstDirectory, specifications); err != nil {
		return packageDirectoryRead{}, err
	}

	result := packageDirectoryRead{
		files:    make(map[string][]byte, len(specifications)),
		snapshot: firstSnapshot,
	}
	fileSnapshots := make(map[string]packageFileSnapshot, len(specifications))
	for _, specification := range specifications {
		data, snapshot, err := readStablePackageFile(
			filepath.Join(directory, specification.name),
			specification.maxBytes,
			specification.expected,
		)
		if err != nil {
			return packageDirectoryRead{}, err
		}
		result.files[specification.name] = data
		fileSnapshots[specification.name] = snapshot
	}

	secondDirectory, secondSnapshot, err := openValidatedPackageDirectory(directory)
	if err != nil {
		return packageDirectoryRead{}, err
	}
	if err := requireExactPackageInventory(secondDirectory, specifications); err != nil {
		_ = secondDirectory.Close()
		return packageDirectoryRead{}, err
	}
	if err := secondDirectory.Close(); err != nil {
		return packageDirectoryRead{}, errors.New("source qualification directory snapshot could not be closed")
	}
	if firstSnapshot != secondSnapshot {
		return packageDirectoryRead{}, errors.New("source qualification directory changed during inspection")
	}
	for _, specification := range specifications {
		if err := requirePackageFileIdentity(
			filepath.Join(directory, specification.name),
			fileSnapshots[specification.name],
		); err != nil {
			return packageDirectoryRead{}, err
		}
	}
	return result, nil
}

func requireExactPackageInventory(directory *os.File, specifications []packageFileSpec) error {
	entries, err := directory.ReadDir(-1)
	if err != nil || len(entries) != len(specifications) {
		return errors.New("source qualification directory inventory is invalid")
	}
	expected := make(map[string]struct{}, len(specifications))
	for _, specification := range specifications {
		if specification.name == "" {
			return errors.New("source qualification directory contract is invalid")
		}
		expected[specification.name] = struct{}{}
	}
	if len(expected) != len(specifications) {
		return errors.New("source qualification directory contract is duplicated")
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return errors.New("source qualification directory contains an unexpected entry")
		}
		delete(expected, entry.Name())
	}
	if len(expected) != 0 {
		return errors.New("source qualification directory is missing an entry")
	}
	return nil
}

func readStablePackageFile(
	path string,
	maxBytes int64,
	expected []byte,
) (result []byte, snapshot packageFileSnapshot, returnErr error) {
	if maxBytes <= 0 || int64(len(expected)) > maxBytes {
		return nil, packageFileSnapshot{}, errors.New("source qualification file bound is invalid")
	}
	file, err := openPackageRegularFile(path)
	if err != nil {
		return nil, packageFileSnapshot{}, errors.New("source qualification file could not be opened safely")
	}
	defer func() {
		if err := file.Close(); returnErr == nil && err != nil {
			result = nil
			snapshot = packageFileSnapshot{}
			returnErr = errors.New("source qualification file could not be closed")
		}
	}()

	first, err := snapshotPackageHandle(file, false)
	if err != nil || first.size <= 0 || first.size > maxBytes {
		return nil, packageFileSnapshot{}, errors.New("source qualification file metadata is invalid")
	}
	if expected != nil && first.size != int64(len(expected)) {
		return nil, packageFileSnapshot{}, errors.New("source qualification file size differs across lanes")
	}
	if expected == nil {
		result, err = io.ReadAll(io.LimitReader(file, maxBytes+1))
		if err != nil || len(result) == 0 || int64(len(result)) > maxBytes {
			return nil, packageFileSnapshot{}, errors.New("source qualification file read is invalid")
		}
	} else {
		if err := comparePackageFileBytes(file, expected); err != nil {
			return nil, packageFileSnapshot{}, err
		}
		result = expected
	}
	middle, err := snapshotPackageHandle(file, false)
	if err != nil || first != middle || middle.size != int64(len(result)) {
		return nil, packageFileSnapshot{}, errors.New("source qualification file changed during inspection")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, packageFileSnapshot{}, errors.New("source qualification file could not be reread")
	}
	if err := comparePackageFileBytes(file, result); err != nil {
		return nil, packageFileSnapshot{}, err
	}
	last, err := snapshotPackageHandle(file, false)
	if err != nil || first != last {
		return nil, packageFileSnapshot{}, errors.New("source qualification file changed during verification")
	}
	return result, first, nil
}

func comparePackageFileBytes(file *os.File, expected []byte) error {
	buffer := make([]byte, 32<<10)
	offset := 0
	for offset < len(expected) {
		remaining := len(expected) - offset
		if remaining < len(buffer) {
			buffer = buffer[:remaining]
		}
		n, err := io.ReadFull(file, buffer)
		if err != nil || n != len(buffer) || !bytes.Equal(buffer, expected[offset:offset+n]) {
			return errors.New("source qualification file bytes changed during inspection")
		}
		offset += n
	}
	var extra [1]byte
	if n, err := io.ReadFull(file, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("source qualification file length changed during inspection")
	}
	return nil
}

func snapshotPackageHandle(file *os.File, directory bool) (packageFileSnapshot, error) {
	info, err := file.Stat()
	if err != nil {
		return packageFileSnapshot{}, errors.New("source qualification filesystem metadata could not be read")
	}
	identity, err := validatePackageHandleMetadata(file, info, directory)
	if err != nil {
		return packageFileSnapshot{}, err
	}
	return packageFileSnapshot{
		identity: identity,
		size:     info.Size(),
		mode:     info.Mode(),
		modTime:  info.ModTime().UnixNano(),
	}, nil
}

func requirePackageFileIdentity(path string, expected packageFileSnapshot) error {
	file, err := openPackageRegularFile(path)
	if err != nil {
		return errors.New("source qualification file path changed during inspection")
	}
	actual, snapshotErr := snapshotPackageHandle(file, false)
	closeErr := file.Close()
	if snapshotErr != nil || closeErr != nil || actual != expected {
		return errors.New("source qualification file path changed during inspection")
	}
	return nil
}

func writePrivatePackageFile(path string, data []byte) error {
	if len(data) == 0 {
		return errors.New("source qualification output file is empty")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("source qualification output file could not be created")
	}
	if err := securePrivatePackagePath(path, false); err != nil {
		_ = file.Close()
		return errors.New("source qualification output file permissions could not be restricted")
	}
	info, statErr := file.Stat()
	var permissionsErr error
	if statErr == nil {
		permissionsErr = validatePrivatePackagePermissions(file, info, false)
	}
	if statErr != nil || permissionsErr != nil {
		_ = file.Close()
		return errors.New("source qualification output file permissions are not private")
	}
	written, writeErr := io.Copy(file, bytes.NewReader(data))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != int64(len(data)) || syncErr != nil || closeErr != nil {
		return errors.New("source qualification output file could not be written safely")
	}
	return nil
}

func requirePrivatePackageDirectory(path string) error {
	directory, _, err := openValidatedPackageDirectory(path)
	if err != nil {
		return err
	}
	info, statErr := directory.Stat()
	var permissionsErr error
	if statErr == nil {
		permissionsErr = validatePrivatePackagePermissions(directory, info, true)
	}
	closeErr := directory.Close()
	if statErr != nil || permissionsErr != nil || closeErr != nil {
		return errors.New("source qualification staging directory permissions are not private")
	}
	return nil
}

func openValidatedPackageDirectory(path string) (*os.File, packageFileSnapshot, error) {
	if err := validatePackageDirectoryChain(path); err != nil {
		return nil, packageFileSnapshot{}, err
	}
	directory, err := openPackageDirectory(path)
	if err != nil {
		return nil, packageFileSnapshot{}, errors.New("source qualification directory could not be opened safely")
	}
	snapshot, err := snapshotPackageHandle(directory, true)
	if err != nil {
		_ = directory.Close()
		return nil, packageFileSnapshot{}, err
	}
	return directory, snapshot, nil
}

func validatePackageDirectoryChain(path string) error {
	current := path
	for {
		directory, err := openPackageDirectory(current)
		if err != nil {
			return errors.New("source qualification directory chain is unsafe")
		}
		info, statErr := directory.Stat()
		var metadataErr error
		if statErr == nil {
			metadataErr = validatePackageAncestorDirectoryMetadata(directory, info)
		}
		closeErr := directory.Close()
		if statErr != nil || metadataErr != nil {
			return errors.New("source qualification directory chain is unsafe")
		}
		if closeErr != nil {
			return errors.New("source qualification directory chain is unsafe")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func requirePackageDirectoryIdentity(path string, expected packageFileIdentity) error {
	directory, snapshot, err := openValidatedPackageDirectory(path)
	if err != nil {
		return err
	}
	closeErr := directory.Close()
	if closeErr != nil || snapshot.identity != expected {
		return errors.New("source qualification output parent changed")
	}
	return nil
}

func canonicalPackageFilesystemPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("source qualification filesystem path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("source qualification filesystem path is invalid")
	}
	absolute = filepath.Clean(absolute)
	if err := validatePackagePlatformPath(absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

func packagePathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func requirePackageOutputAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return errors.New("source qualification output already exists")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("source qualification output metadata could not be inspected")
	}
	return nil
}
