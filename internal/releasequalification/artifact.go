package releasequalification

import (
	"crypto/sha256"
	"crypto/subtle"
	"debug/buildinfo"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

// InspectArtifact validates an executable through one fixed file handle. A
// digest is published only after the first hash, Go build-information read,
// second hash, and file/path stability checks all agree on the same snapshot.
func InspectArtifact(spec ArtifactSpec, testedRevision string) ArtifactReport {
	report := ArtifactReport{ID: spec.ID}
	absolute, err := filepath.Abs(spec.Path)
	if err != nil {
		return unreadableArtifact(report)
	}

	pathBefore, err := os.Lstat(absolute)
	if err != nil || qualificationPathHasReparsePoint(absolute) || !validArtifactFile(pathBefore) {
		return unreadableArtifact(report)
	}

	file, err := os.Open(absolute)
	if err != nil {
		return unreadableArtifact(report)
	}
	openedBefore, err := file.Stat()
	if err != nil || !sameArtifactFile(pathBefore, openedBefore) {
		_ = file.Close()
		return unreadableArtifact(report)
	}

	firstDigest, err := artifactDigest(file, openedBefore.Size())
	if err != nil {
		_ = file.Close()
		return unreadableArtifact(report)
	}
	info, buildInfoErr := buildinfo.Read(io.NewSectionReader(file, 0, openedBefore.Size()))
	secondDigest, secondHashErr := artifactDigest(file, openedBefore.Size())
	pathAfter, pathErr := os.Lstat(absolute)
	openedAfter, statErr := file.Stat()
	closeErr := file.Close()

	if buildInfoErr != nil || secondHashErr != nil || pathErr != nil || statErr != nil || closeErr != nil ||
		qualificationPathHasReparsePoint(absolute) ||
		subtle.ConstantTimeCompare(firstDigest[:], secondDigest[:]) != 1 ||
		!sameArtifactFile(pathBefore, pathAfter) || !sameArtifactFile(openedBefore, openedAfter) {
		return unreadableArtifact(report)
	}

	report.Size = openedBefore.Size()
	report.SHA256 = "sha256:" + hex.EncodeToString(firstDigest[:])
	report.Results = buildidentity.ValidateBuildInfo(info, spec.Identity, testedRevision, spec.ID)
	return report
}

func artifactDigest(file *os.File, size int64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	hash := sha256.New()
	written, err := io.Copy(hash, io.NewSectionReader(file, 0, size))
	if err != nil || written != size {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return result, err
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func unreadableArtifact(report ArtifactReport) ArtifactReport {
	report.Size = 0
	report.SHA256 = ""
	report.Results = []buildidentity.Result{{
		Status:  buildidentity.StatusFail,
		Code:    buildidentity.CodeBuildInfoUnreadable,
		Subject: report.ID,
	}}
	return report
}

func validArtifactFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Size() >= 1 && info.Size() <= buildidentity.MaxExecutableBytes
}

func sameArtifactFile(before, after os.FileInfo) bool {
	return validArtifactFile(before) && validArtifactFile(after) &&
		os.SameFile(before, after) && before.Size() == after.Size() &&
		before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}
