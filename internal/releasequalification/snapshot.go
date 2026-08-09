package releasequalification

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

// PreparePrePublish copies the exact final inventory through fixed file
// handles into a private, unique, same-parent directory and independently
// qualifies that sealed snapshot. The caller publishes only the returned
// directory; subsequent changes to the construction directory cannot change
// the accepted bytes.
func PreparePrePublish(root, destination, testedRevision, treeSHA string) (QualificationReport, string, error) {
	if err := validateQualificationInputs(testedRevision, treeSHA); err != nil {
		return QualificationReport{}, "", err
	}
	source, sourceErr := filepath.Abs(root)
	target, targetErr := filepath.Abs(destination)
	if sourceErr != nil || targetErr != nil ||
		!strings.HasPrefix(filepath.Base(source), ".release-publish-") ||
		filepath.Base(target) != "dist" ||
		!sameQualificationDirectory(filepath.Dir(source), filepath.Dir(target)) ||
		qualificationPathHasReparsePoint(source) || qualificationPathHasReparsePoint(filepath.Dir(target)) {
		return QualificationReport{}, "", errors.New("publication snapshot scope is invalid")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return QualificationReport{}, "", errors.New("publication destination already exists or is unreadable")
	}

	expected := append(requiredArtifactNames(prePublishArtifacts), requiredKitNames(prePublishKits)...)
	expected = append(expected, "SHA256SUMS")
	sort.Strings(expected)
	if !qualificationInventoryExact(source, expected) {
		return QualificationReport{}, "", errors.New("publication source inventory is invalid")
	}

	sealed, err := os.MkdirTemp(filepath.Dir(target), ".release-sealed-")
	if err != nil {
		return QualificationReport{}, "", errors.New("publication snapshot creation failed")
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = os.RemoveAll(sealed)
		}
	}()
	if qualificationPathHasReparsePoint(sealed) {
		return QualificationReport{}, "", errors.New("publication snapshot path is unsafe")
	}
	if err := secureQualificationSnapshotPath(sealed, true); err != nil {
		return QualificationReport{}, "", errors.New("publication snapshot permissions are unsafe")
	}
	for _, name := range expected {
		maximum := buildidentity.MaxExecutableBytes
		if name == "SHA256SUMS" {
			maximum = qualificationKitMaxTextBytes
		}
		if err := copyStableQualificationFile(filepath.Join(source, name), filepath.Join(sealed, name), maximum); err != nil {
			return QualificationReport{}, "", errors.New("publication snapshot copy failed")
		}
		if err := secureQualificationSnapshotPath(filepath.Join(sealed, name), false); err != nil {
			return QualificationReport{}, "", errors.New("publication snapshot permissions are unsafe")
		}
	}
	if !qualificationInventoryExact(source, expected) || !qualificationInventoryExact(sealed, expected) {
		return QualificationReport{}, "", errors.New("publication inventory changed during snapshot")
	}
	report, err := QualifyPrePublish(sealed, testedRevision, treeSHA)
	if err != nil {
		return report, "", errors.New("sealed publication snapshot qualification failed")
	}
	accepted = true
	return report, sealed, nil
}

func copyStableQualificationFile(source, destination string, maximum int64) error {
	pathBefore, err := os.Lstat(source)
	if err != nil || qualificationPathHasReparsePoint(source) ||
		!qualificationFileInfoValid(pathBefore, 1, maximum) {
		return errors.New("snapshot source is invalid")
	}
	input, err := os.Open(source)
	if err != nil {
		return errors.New("snapshot source is unreadable")
	}
	defer input.Close()
	openedBefore, err := input.Stat()
	if err != nil || !qualificationFileInfoSame(pathBefore, openedBefore, 1, maximum) {
		return errors.New("snapshot source identity is unstable")
	}

	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, pathBefore.Mode().Perm())
	if err != nil {
		return errors.New("snapshot output creation failed")
	}
	copyHash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, copyHash), io.NewSectionReader(input, 0, openedBefore.Size()))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || written != openedBefore.Size() || syncErr != nil || closeErr != nil {
		return errors.New("snapshot output write failed")
	}

	secondDigest, digestErr := artifactDigest(input, openedBefore.Size())
	openedAfter, statErr := input.Stat()
	pathAfter, pathErr := os.Lstat(source)
	if digestErr != nil || statErr != nil || pathErr != nil || qualificationPathHasReparsePoint(source) ||
		!qualificationFileInfoSame(openedBefore, openedAfter, 1, maximum) ||
		!qualificationFileInfoSame(pathBefore, pathAfter, 1, maximum) ||
		subtle.ConstantTimeCompare(copyHash.Sum(nil), secondDigest[:]) != 1 {
		return errors.New("snapshot source changed during copy")
	}

	copyInfo, err := os.Lstat(destination)
	if err != nil || qualificationPathHasReparsePoint(destination) ||
		!qualificationFileInfoValid(copyInfo, 1, maximum) || copyInfo.Size() != pathBefore.Size() {
		return errors.New("snapshot output is unstable")
	}
	return nil
}

func sameQualificationDirectory(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

// PublicationPathSafe lets the private controller recheck every existing path
// component immediately before cleanup or atomic rename without exporting any
// filesystem detail into its public log.
func PublicationPathSafe(path string) bool {
	return path != "" && !qualificationPathHasReparsePoint(path)
}
