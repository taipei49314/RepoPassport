package sourcequalification

import (
	"crypto/sha256"
	"crypto/subtle"
	"debug/buildinfo"
	"errors"
	"io"
	"path/filepath"
	"runtime/debug"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
)

// inspectQualificationController binds executable bytes, metadata, and Go
// build information to one fixed handle. Path reopening is used only after all
// reads to prove that the named input still resolves to the inspected object.
func inspectQualificationController(
	path, expectedGOOS, testedRevision string,
) (identity receiptController, raw []byte, returnErr error) {
	if expectedGOOS != "linux" && expectedGOOS != "windows" {
		return receiptController{}, nil, errors.New("source qualification controller platform is invalid")
	}
	if !validReceiptGitSHA1(testedRevision) {
		return receiptController{}, nil, errors.New("source qualification controller revision is invalid")
	}
	controllerPath, err := canonicalPackageFilesystemPath(path)
	if err != nil {
		return receiptController{}, nil, errors.New("source qualification controller path is invalid")
	}
	parentPath := filepath.Dir(controllerPath)
	if err := validatePackageDirectoryChain(parentPath); err != nil {
		return receiptController{}, nil, errors.New("source qualification controller directory chain is unsafe")
	}

	file, err := openPackageRegularFile(controllerPath)
	if err != nil {
		return receiptController{}, nil, errors.New("source qualification controller could not be opened safely")
	}
	defer func() {
		if err := file.Close(); returnErr == nil && err != nil {
			identity = receiptController{}
			raw = nil
			returnErr = errors.New("source qualification controller could not be closed")
		}
	}()

	first, err := snapshotPackageHandle(file, false)
	if err != nil || first.size <= 0 || first.size > buildidentity.MaxExecutableBytes {
		return receiptController{}, nil, errors.New("source qualification controller metadata is invalid")
	}
	raw, err = io.ReadAll(io.NewSectionReader(file, 0, first.size))
	if err != nil || int64(len(raw)) != first.size {
		return receiptController{}, nil, errors.New("source qualification controller bytes could not be read")
	}
	firstDigest := sha256.Sum256(raw)

	info, err := buildinfo.Read(io.NewSectionReader(file, 0, first.size))
	if err != nil || !validQualificationControllerBuildInfo(info, expectedGOOS, testedRevision) {
		return receiptController{}, nil, errors.New("source qualification controller build information is invalid")
	}

	secondHash := sha256.New()
	count, hashErr := io.Copy(secondHash, io.NewSectionReader(file, 0, first.size))
	last, snapshotErr := snapshotPackageHandle(file, false)
	chainErr := validatePackageDirectoryChain(parentPath)
	pathErr := requirePackageFileIdentity(controllerPath, first)
	if hashErr != nil || count != first.size || snapshotErr != nil || first != last ||
		chainErr != nil || pathErr != nil ||
		subtle.ConstantTimeCompare(firstDigest[:], secondHash.Sum(nil)) != 1 {
		return receiptController{}, nil, errors.New("source qualification controller changed during inspection")
	}

	revision, _ := exactQualificationBuildSetting(info, "vcs.revision")
	modified, _ := exactQualificationBuildSetting(info, "vcs.modified")
	return receiptController{
		GoVersion:   info.GoVersion,
		MainPackage: info.Path,
		ModulePath:  info.Main.Path,
		SHA256:      sha256Digest(raw),
		VCSModified: modified != "false",
		VCSRevision: revision,
	}, raw, nil
}

func validQualificationControllerBuildInfo(
	info *debug.BuildInfo,
	expectedGOOS, testedRevision string,
) bool {
	if info == nil || info.GoVersion != toolManifestGoVersion {
		return false
	}
	results := buildidentity.ValidateBuildInfo(
		info,
		buildidentity.BuildIdentity{
			ModulePath:  toolManifestModulePath,
			MainPackage: toolManifestMainPackage,
		},
		testedRevision,
		"source-qualification-controller",
	)
	if len(results) != 0 {
		return false
	}
	goos, ok := exactQualificationBuildSetting(info, "GOOS")
	if !ok || goos != expectedGOOS {
		return false
	}
	goarch, ok := exactQualificationBuildSetting(info, "GOARCH")
	if !ok || goarch != "amd64" {
		return false
	}
	cgo, ok := exactQualificationBuildSetting(info, "CGO_ENABLED")
	if !ok || cgo != "0" {
		return false
	}
	trimpath, ok := exactQualificationBuildSetting(info, "-trimpath")
	return ok && trimpath == "true"
}

func exactQualificationBuildSetting(info *debug.BuildInfo, key string) (string, bool) {
	if info == nil {
		return "", false
	}
	value := ""
	count := 0
	for _, setting := range info.Settings {
		if setting.Key == key {
			value = setting.Value
			count++
		}
	}
	return value, count == 1
}
