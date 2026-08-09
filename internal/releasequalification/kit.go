package releasequalification

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

const (
	qualificationKitProductVersion  = "0.1.0-alpha.33"
	qualificationKitMaxBinaryBytes  = int64(32 << 20)
	qualificationKitMaxTextBytes    = int64(64 << 10)
	qualificationKitMaxArchiveBytes = qualificationKitMaxBinaryBytes + (1 << 20)
)

var qualificationKitEpoch = time.Unix(0, 0).UTC()

type qualificationKitMember struct {
	name string
	mode int64
	data []byte
}

// InspectPortableKit independently validates the canonical portable verifier
// archive and the build identity of the exact verifier bytes bound by it. It
// intentionally does not use the release-kit builder as a qualification
// oracle.
func InspectPortableKit(spec KitSpec, testedRevision string) (report KitReport, returnErr error) {
	report.ID = spec.ID
	if spec.ID == "" || spec.Path == "" || spec.StandaloneVerifierPath == "" {
		return report, errors.New("invalid portable-kit qualification input")
	}
	binaryName, err := qualificationKitBinaryName(spec.TargetOS)
	if err != nil {
		return report, err
	}

	snapshot, err := openQualificationSnapshot(spec.Path, 1536, qualificationKitMaxArchiveBytes)
	if err != nil {
		return report, err
	}
	firstDigest, err := hashQualificationSnapshot(snapshot.file, snapshot.before.Size())
	if err != nil {
		_ = snapshot.file.Close()
		return report, errors.New("portable-kit archive is unreadable")
	}
	if snapshot.before.Size()%512 != 0 || !qualificationKitHasZeroTrailer(snapshot.file, snapshot.before.Size()) {
		_ = snapshot.file.Close()
		return report, errors.New("portable-kit archive shape is not canonical")
	}
	members, verifier, err := parseQualificationKit(snapshot.file, snapshot.before.Size(), spec.TargetOS, binaryName)
	if err != nil {
		_ = snapshot.file.Close()
		return report, err
	}
	if !qualificationKitRawBytesCanonical(snapshot.file, snapshot.before.Size(), members) {
		_ = snapshot.file.Close()
		return report, errors.New("portable-kit raw bytes are not canonical USTAR")
	}
	if err := finishQualificationSnapshot(snapshot, firstDigest); err != nil {
		return report, err
	}
	report.Size = snapshot.before.Size()
	report.SHA256 = qualificationDigestText(firstDigest)

	verifierDigest := sha256.Sum256(verifier)
	report.EmbeddedVerifier = ArtifactReport{
		ID:     spec.ID,
		Size:   int64(len(verifier)),
		SHA256: qualificationDigestText(verifierDigest),
	}
	standaloneSize, standaloneDigest, err := qualificationStableVerifierDigest(spec.StandaloneVerifierPath)
	if err != nil {
		return report, err
	}
	if standaloneSize != int64(len(verifier)) ||
		subtle.ConstantTimeCompare(standaloneDigest[:], verifierDigest[:]) != 1 {
		return report, errors.New("portable-kit verifier does not match the standalone verifier")
	}

	extractionRoot, err := os.MkdirTemp("", "repopass-releasequalification-kit-")
	if err != nil {
		return report, errors.New("portable-kit verifier extraction failed")
	}
	defer func() {
		if cleanupErr := os.RemoveAll(extractionRoot); cleanupErr != nil {
			returnErr = errors.New("portable-kit verifier extraction cleanup failed")
			return
		}
		if _, statErr := os.Lstat(extractionRoot); !os.IsNotExist(statErr) {
			returnErr = errors.New("portable-kit verifier extraction cleanup failed")
		}
	}()

	extractedPath := filepath.Join(extractionRoot, binaryName)
	if err := writeQualificationVerifier(extractedPath, verifier); err != nil {
		return report, err
	}
	results, extractedSize, extractedDigest, err := inspectExtractedQualificationVerifier(extractedPath, testedRevision, spec.ID)
	if err != nil {
		return report, err
	}
	if extractedSize != int64(len(verifier)) ||
		subtle.ConstantTimeCompare(extractedDigest[:], verifierDigest[:]) != 1 {
		return report, errors.New("extracted portable-kit verifier changed during inspection")
	}
	report.EmbeddedVerifier.Results = results
	if len(results) != 0 {
		return report, errors.New("portable-kit embedded verifier identity qualification failed")
	}
	return report, nil
}

func qualificationKitBinaryName(targetOS string) (string, error) {
	switch targetOS {
	case "linux":
		return "repopass-verify", nil
	case "windows":
		return "repopass-verify.exe", nil
	default:
		return "", errors.New("unsupported portable-kit target")
	}
}

func parseQualificationKit(reader io.ReaderAt, size int64, targetOS, binaryName string) ([]qualificationKitMember, []byte, error) {
	wantNames := []string{
		"PORTABLE_VERIFIER_MANIFEST.json",
		"TRUST_BOUNDARY.txt",
		"USAGE.txt",
		binaryName,
	}
	archive := tar.NewReader(io.NewSectionReader(reader, 0, size))
	members := make([]qualificationKitMember, 0, len(wantNames))
	for index := 0; ; index++ {
		header, err := archive.Next()
		if err == io.EOF {
			if index != len(wantNames) {
				return nil, nil, errors.New("portable-kit inventory is incomplete")
			}
			break
		}
		if err != nil {
			return nil, nil, errors.New("portable-kit contains a malformed USTAR member")
		}
		if index >= len(wantNames) || header.Name != wantNames[index] {
			return nil, nil, errors.New("portable-kit inventory or member order is not canonical")
		}
		maxSize := qualificationKitMaxTextBytes
		mode := int64(0o644)
		if header.Name == binaryName {
			maxSize = qualificationKitMaxBinaryBytes
			mode = 0o755
		}
		if !qualificationKitHeaderCanonical(header, mode, maxSize) {
			return nil, nil, errors.New("portable-kit member header is not canonical USTAR")
		}
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(archive, data); err != nil {
			return nil, nil, errors.New("portable-kit member is truncated")
		}
		members = append(members, qualificationKitMember{name: header.Name, mode: mode, data: data})
	}
	if len(members) != len(wantNames) {
		return nil, nil, errors.New("portable-kit inventory mismatch")
	}
	verifier := members[len(members)-1].data
	if !bytes.Equal(members[0].data, qualificationKitManifest(targetOS, binaryName, verifier)) ||
		!bytes.Equal(members[1].data, []byte(qualificationKitTrustBoundary())) ||
		!bytes.Equal(members[2].data, []byte(qualificationKitUsage(targetOS))) {
		return nil, nil, errors.New("portable-kit manifest or sidecar binding mismatch")
	}
	return members, verifier, nil
}

func qualificationKitHeaderCanonical(header *tar.Header, mode, maxSize int64) bool {
	return header != nil &&
		header.Format == tar.FormatUSTAR &&
		header.Typeflag == tar.TypeReg &&
		header.Linkname == "" &&
		header.Size >= 1 && header.Size <= maxSize &&
		header.Mode == mode &&
		header.Uid == 0 && header.Gid == 0 &&
		header.Uname == "" && header.Gname == "" &&
		header.PAXRecords == nil && header.Xattrs == nil &&
		header.ModTime.Equal(qualificationKitEpoch) &&
		header.AccessTime.IsZero() && header.ChangeTime.IsZero() &&
		header.Devmajor == 0 && header.Devminor == 0
}

func qualificationKitManifest(targetOS, binaryName string, binary []byte) []byte {
	digest := sha256.Sum256(binary)
	text := "{" +
		"\"artifactType\":\"repopass-portable-offline-verifier\"," +
		"\"binary\":{\"path\":" + strconv.Quote(binaryName) + "," +
		"\"sha256\":" + strconv.Quote(qualificationDigestText(digest)) + "," +
		"\"size\":" + strconv.FormatInt(int64(len(binary)), 10) + "}," +
		"\"capabilities\":{\"commands\":[\"verify-attestation\",\"verify-release-index\"],\"bundleVersions\":[\"1\",\"2\"]," +
		"\"currentness\":\"optional-current-manifest\",\"historicalReplayRequiresWorktree\":false," +
		"\"networkRequired\":false,\"trustModes\":[\"explicit-spki\",\"offline-policy-v1\",\"signed-offline-policy-v2\",\"signed-offline-policy-v2-explicit-old-root-authority-transition-v1\",\"signed-offline-policy-v2-explicit-root-authority-transition-chain-v1\",\"release-index-explicit-root-policy\",\"release-index-explicit-old-root-authority-transition-v1\",\"release-index-explicit-root-authority-transition-chain-v1\"]}," +
		"\"productVersion\":" + strconv.Quote(qualificationKitProductVersion) + "," +
		"\"schemaVersion\":\"1\"," +
		"\"target\":{\"goarch\":\"amd64\",\"goos\":" + strconv.Quote(targetOS) + "}," +
		"\"trustBoundary\":{\"capability\":\"incomplete\",\"embeddedKeyIsTrustAnchor\":false,\"formalClaim\":false,\"identityAttestation\":\"none\",\"overall\":\"inconclusive\",\"timeAttestation\":\"none\"}}\n"
	return []byte(text)
}

func qualificationKitUsage(targetOS string) string {
	return "RepoPassport portable offline verifier (" + targetOS + "/amd64)\n" +
		"Commands: help, version, verify-attestation, verify-release-index\n" +
		"Acceptance is relative to explicit caller-supplied trust roots and policies.\n"
}

func qualificationKitTrustBoundary() string {
	return "embeddedKeyIsTrustAnchor=false\nformalClaim=false\ncapability=incomplete\noverall=inconclusive\nidentityAttestation=none\ntimeAttestation=none\nofflineTrustPolicySidecarsIncluded=false\nofflineTrustPolicyAuthorityTransitionSidecarsIncluded=false\nofflineTrustPolicyAuthorityTransitionChainSidecarsIncluded=false\nreleaseIndexSidecarsIncluded=false\nauthorityTransitionSidecarsIncluded=false\nevidenceIncluded=false\nprivateKeyIncluded=false\nrootKeyIncluded=false\n"
}

type qualificationKitCompareWriter struct {
	reader  io.ReaderAt
	size    int64
	offset  int64
	equal   bool
	scratch [32 << 10]byte
}

func (writer *qualificationKitCompareWriter) Write(data []byte) (int, error) {
	originalLength := len(data)
	if writer.offset+int64(originalLength) > writer.size {
		writer.equal = false
		writer.offset += int64(originalLength)
		return originalLength, nil
	}
	for len(data) > 0 {
		chunkSize := len(data)
		if chunkSize > len(writer.scratch) {
			chunkSize = len(writer.scratch)
		}
		chunk := writer.scratch[:chunkSize]
		read, err := writer.reader.ReadAt(chunk, writer.offset)
		if read != chunkSize || (err != nil && err != io.EOF) || !bytes.Equal(chunk[:read], data[:read]) {
			writer.equal = false
		}
		writer.offset += int64(chunkSize)
		data = data[chunkSize:]
	}
	return originalLength, nil
}

func qualificationKitRawBytesCanonical(reader io.ReaderAt, size int64, members []qualificationKitMember) bool {
	compare := &qualificationKitCompareWriter{reader: reader, size: size, equal: true}
	writer := tar.NewWriter(compare)
	for _, member := range members {
		header := &tar.Header{
			Name: member.name, Mode: member.mode, Size: int64(len(member.data)), Typeflag: tar.TypeReg,
			Format: tar.FormatUSTAR, ModTime: qualificationKitEpoch,
			Uid: 0, Gid: 0, Uname: "", Gname: "",
		}
		if err := writer.WriteHeader(header); err != nil {
			return false
		}
		if _, err := writer.Write(member.data); err != nil {
			return false
		}
	}
	if err := writer.Close(); err != nil {
		return false
	}
	return compare.equal && compare.offset == size
}

func qualificationKitHasZeroTrailer(reader io.ReaderAt, size int64) bool {
	if size < 1024 {
		return false
	}
	var trailer [1024]byte
	read, err := reader.ReadAt(trailer[:], size-int64(len(trailer)))
	if read != len(trailer) || (err != nil && err != io.EOF) {
		return false
	}
	for _, value := range trailer {
		if value != 0 {
			return false
		}
	}
	return true
}

type qualificationSnapshot struct {
	path   string
	file   *os.File
	before os.FileInfo
}

func openQualificationSnapshot(path string, minSize, maxSize int64) (qualificationSnapshot, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return qualificationSnapshot{}, errors.New("qualification input path is invalid")
	}
	if qualificationPathHasReparsePoint(absolute) {
		return qualificationSnapshot{}, errors.New("qualification input is a reparse point or is unreadable")
	}
	before, err := os.Lstat(absolute)
	if err != nil || !qualificationFileInfoValid(before, minSize, maxSize) {
		return qualificationSnapshot{}, errors.New("qualification input is not a bounded regular file")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return qualificationSnapshot{}, errors.New("qualification input is unreadable")
	}
	opened, err := file.Stat()
	if err != nil || !qualificationFileInfoSame(before, opened, minSize, maxSize) {
		_ = file.Close()
		return qualificationSnapshot{}, errors.New("qualification input changed while opening")
	}
	return qualificationSnapshot{path: absolute, file: file, before: before}, nil
}

func finishQualificationSnapshot(snapshot qualificationSnapshot, firstDigest [sha256.Size]byte) error {
	secondDigest, hashErr := hashQualificationSnapshot(snapshot.file, snapshot.before.Size())
	openedAfter, openedErr := snapshot.file.Stat()
	pathAfter, pathErr := os.Lstat(snapshot.path)
	reparseAfter := qualificationPathHasReparsePoint(snapshot.path)
	closeErr := snapshot.file.Close()
	if hashErr != nil || openedErr != nil || pathErr != nil || reparseAfter || closeErr != nil ||
		subtle.ConstantTimeCompare(firstDigest[:], secondDigest[:]) != 1 ||
		!qualificationFileInfoSame(snapshot.before, openedAfter, 1, qualificationKitMaxArchiveBytes) ||
		!qualificationFileInfoSame(snapshot.before, pathAfter, 1, qualificationKitMaxArchiveBytes) {
		return errors.New("qualification input changed during inspection")
	}
	return nil
}

func qualificationFileInfoValid(info os.FileInfo, minSize, maxSize int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Size() >= minSize && info.Size() <= maxSize
}

func qualificationFileInfoSame(before, after os.FileInfo, minSize, maxSize int64) bool {
	return qualificationFileInfoValid(before, minSize, maxSize) &&
		qualificationFileInfoValid(after, minSize, maxSize) &&
		os.SameFile(before, after) &&
		before.Size() == after.Size() && before.Mode() == after.Mode() &&
		before.ModTime().Equal(after.ModTime())
}

func hashQualificationSnapshot(reader io.ReaderAt, size int64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	digest := sha256.New()
	written, err := io.Copy(digest, io.NewSectionReader(reader, 0, size))
	if err != nil || written != size {
		return result, errors.New("qualification input is unreadable")
	}
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func qualificationStableVerifierDigest(path string) (int64, [sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	snapshot, err := openQualificationSnapshot(path, 1, qualificationKitMaxBinaryBytes)
	if err != nil {
		return 0, empty, errors.New("standalone verifier is not a bounded regular file")
	}
	digest, err := hashQualificationSnapshot(snapshot.file, snapshot.before.Size())
	if err != nil {
		_ = snapshot.file.Close()
		return 0, empty, errors.New("standalone verifier is unreadable")
	}
	if err := finishQualificationSnapshot(snapshot, digest); err != nil {
		return 0, empty, errors.New("standalone verifier changed during inspection")
	}
	return snapshot.before.Size(), digest, nil
}

func writeQualificationVerifier(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return errors.New("portable-kit verifier extraction failed")
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(data) || syncErr != nil || closeErr != nil {
		return errors.New("portable-kit verifier extraction failed")
	}
	return nil
}

func inspectExtractedQualificationVerifier(path, testedRevision, subject string) ([]buildidentity.Result, int64, [sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	snapshot, err := openQualificationSnapshot(path, 1, qualificationKitMaxBinaryBytes)
	if err != nil {
		return nil, 0, empty, errors.New("extracted portable-kit verifier is unreadable")
	}
	firstDigest, err := hashQualificationSnapshot(snapshot.file, snapshot.before.Size())
	if err != nil {
		_ = snapshot.file.Close()
		return nil, 0, empty, errors.New("extracted portable-kit verifier is unreadable")
	}
	results := buildidentity.ValidateReaderAt(
		snapshot.file,
		snapshot.before.Size(),
		buildidentity.VerifierIdentity,
		testedRevision,
		subject,
	)
	if err := finishQualificationSnapshot(snapshot, firstDigest); err != nil {
		return nil, 0, empty, errors.New("extracted portable-kit verifier changed during inspection")
	}
	return results, snapshot.before.Size(), firstDigest, nil
}

func qualificationDigestText(digest [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(digest[:])
}

func qualificationDigest(data []byte) [sha256.Size]byte {
	return sha256.Sum256(data)
}
