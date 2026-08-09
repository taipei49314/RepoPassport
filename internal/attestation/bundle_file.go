package attestation

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

type temporaryBundleFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Close() error
	Chmod(os.FileMode) error
	Stat() (os.FileInfo, error)
}

type bundleFileOperations struct {
	createTemp    func(string, string) (temporaryBundleFile, error)
	lstat         func(string) (os.FileInfo, error)
	remove        func(string) error
	publish       func(string, string) (bool, error)
	syncDirectory func(string) error
}

type artifactPublication struct {
	name       string
	tempPrefix string
	maximum    int
}

func defaultBundleFileOperations() bundleFileOperations {
	return bundleFileOperations{
		createTemp: func(directory, pattern string) (temporaryBundleFile, error) {
			return os.CreateTemp(directory, pattern)
		},
		lstat:         os.Lstat,
		remove:        os.Remove,
		publish:       publishBundleNoReplace,
		syncDirectory: syncBundleDirectory,
	}
}

func WriteNewBundle(path string, bundle []byte) error {
	return writeNewBundle(path, bundle, defaultBundleFileOperations())
}

func writeNewBundle(path string, bundle []byte, operations bundleFileOperations) error {
	return writeNewArtifact(path, bundle, artifactPublication{
		name:       "attestation bundle",
		tempPrefix: ".repopass-attestation-*",
		maximum:    MaxBundleBytes,
	}, operations)
}

// WriteNewPublicKey publishes one canonical Ed25519 SubjectPublicKeyInfo PEM
// companion without replacing any existing destination.
func WriteNewPublicKey(path string, publicKeyPEM []byte) error {
	return writeNewPublicKey(path, publicKeyPEM, defaultBundleFileOperations())
}

func writeNewPublicKey(path string, publicKeyPEM []byte, operations bundleFileOperations) error {
	if _, _, err := parsePublicKey(publicKeyPEM); err != nil {
		return buildError("The public-key companion is not canonical Ed25519 SPKI PEM.")
	}
	return writeNewArtifact(path, publicKeyPEM, artifactPublication{
		name:       "public-key companion",
		tempPrefix: ".repopass-public-key-*",
		maximum:    MaxPublicKeyBytes,
	}, operations)
}

// WriteSigningArtifacts validates both destinations before publishing the
// optional public companion first and the authoritative bundle second.
func WriteSigningArtifacts(
	bundlePath string,
	bundle []byte,
	publicKeyPath string,
	publicKeyPEM []byte,
) error {
	operations := defaultBundleFileOperations()
	return writeSigningArtifacts(
		bundlePath,
		bundle,
		publicKeyPath,
		publicKeyPEM,
		operations,
		operations,
	)
}

func writeSigningArtifacts(
	bundlePath string,
	bundle []byte,
	publicKeyPath string,
	publicKeyPEM []byte,
	publicOperations bundleFileOperations,
	bundleOperations bundleFileOperations,
) error {
	if err := validateArtifactContent(bundle, artifactPublication{
		name:       "attestation bundle",
		tempPrefix: ".repopass-attestation-*",
		maximum:    MaxBundleBytes,
	}); err != nil {
		return err
	}
	bundleAbsolute, _, err := inspectNewArtifactDestination(bundlePath, bundleOperations)
	if err != nil {
		return err
	}
	if publicKeyPath == "" {
		return writeNewBundle(bundlePath, bundle, bundleOperations)
	}
	if _, _, err := parsePublicKey(publicKeyPEM); err != nil {
		return buildError("The public-key companion is not canonical Ed25519 SPKI PEM.")
	}
	publicAbsolute, _, err := inspectNewArtifactDestination(publicKeyPath, publicOperations)
	if err != nil {
		return err
	}
	if sameFilesystemPath(bundleAbsolute, publicAbsolute) {
		return buildError("The bundle and public-key companion must use distinct output paths.")
	}
	if err := writeNewPublicKey(publicKeyPath, publicKeyPEM, publicOperations); err != nil {
		return err
	}
	if err := writeNewBundle(bundlePath, bundle, bundleOperations); err != nil {
		return withPublishedPublicKey(err)
	}
	return nil
}

func writeNewArtifact(
	path string,
	content []byte,
	publication artifactPublication,
	operations bundleFileOperations,
) error {
	if err := validateArtifactContent(content, publication); err != nil {
		return err
	}
	absolute, parent, err := inspectNewArtifactDestination(path, operations)
	if err != nil {
		return err
	}

	temporary, err := operations.createTemp(parent, publication.tempPrefix)
	if err != nil {
		return buildError("A same-directory temporary output artifact cannot be created.")
	}
	temporaryPath := temporary.Name()
	closed := false
	cleanupAttempted := false
	var temporaryInfo os.FileInfo
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		if !cleanupAttempted && temporaryInfo != nil {
			_ = removeOwnedTemporary(temporaryPath, temporaryInfo, operations)
		}
	}()
	if !sameFilesystemPath(filepath.Dir(temporaryPath), parent) {
		return buildError("The temporary output artifact escaped its parent directory.")
	}
	temporaryInfo, err = temporary.Stat()
	if err != nil || !temporaryInfo.Mode().IsRegular() {
		return buildError("The temporary output artifact is not a regular file.")
	}
	if err := temporary.Chmod(0o600); err != nil {
		return buildError("The temporary output artifact permissions cannot be restricted.")
	}
	written, err := temporary.Write(content)
	if err != nil || written != len(content) {
		return buildError("The output artifact cannot be written completely.")
	}
	if err := temporary.Sync(); err != nil {
		return buildError("The temporary output artifact cannot be flushed safely.")
	}
	flushedInfo, err := temporary.Stat()
	if err != nil || !os.SameFile(temporaryInfo, flushedInfo) ||
		flushedInfo.Size() != int64(len(content)) {
		return buildError("The flushed temporary output artifact identity or size changed.")
	}
	if err := temporary.Close(); err != nil {
		return buildError("The temporary output artifact cannot be closed safely.")
	}
	closed = true
	closedInfo, err := operations.lstat(temporaryPath)
	if err != nil || !closedInfo.Mode().IsRegular() ||
		closedInfo.Mode()&os.ModeSymlink != 0 || isReparsePoint(temporaryPath) ||
		!os.SameFile(temporaryInfo, closedInfo) || closedInfo.Size() != int64(len(content)) {
		return buildError("The closed temporary output artifact identity or size changed.")
	}

	published, publishErr := operations.publish(temporaryPath, absolute)
	if publishErr != nil && !published {
		return buildError("The completed output artifact cannot be published without replacing an existing path.")
	}
	if !published {
		return buildError("The completed output artifact was not published.")
	}
	cleanupAttempted = true
	cleanupErr := removeOwnedTemporary(temporaryPath, temporaryInfo, operations)
	finalInfo, err := operations.lstat(absolute)
	if err != nil || !finalInfo.Mode().IsRegular() ||
		finalInfo.Mode()&os.ModeSymlink != 0 || isReparsePoint(absolute) ||
		!os.SameFile(temporaryInfo, finalInfo) || finalInfo.Size() != int64(len(content)) {
		return publishedArtifactBuildError(
			"The published output identity or size could not be confirmed.",
			"unknown",
			publication.name,
		)
	}
	if err := operations.syncDirectory(parent); err != nil {
		return publishedArtifactBuildError(
			"The complete output artifact was published, but directory-entry durability could not be confirmed.",
			"unknown",
			publication.name,
		)
	}
	if publishErr != nil || cleanupErr != nil {
		return publishedArtifactBuildError(
			"The complete output artifact was published durably, but publication or temporary-entry cleanup reported an error.",
			"confirmed",
			publication.name,
		)
	}
	return nil
}

func validateArtifactContent(content []byte, publication artifactPublication) error {
	if publication.maximum <= 0 || len(content) == 0 || len(content) > publication.maximum {
		return buildError("The " + publication.name + " is empty or exceeds its size limit.")
	}
	return nil
}

func inspectNewArtifactDestination(
	path string,
	operations bundleFileOperations,
) (string, string, error) {
	if !safeNativePath(path) {
		return "", "", buildError("Device, extended-namespace, alternate-data-stream, UNC, and reserved output paths are unsupported.")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", buildError("The output location cannot be resolved safely.")
	}
	parent := filepath.Dir(absolute)
	if err := requireUnlinkedDirectory(parent); err != nil {
		return "", "", buildError("The output parent must be an existing regular directory that does not resolve through an unsupported path, link, or reparse point.")
	}
	if _, err := operations.lstat(absolute); err == nil {
		return "", "", buildError("The output must be a new file and cannot overwrite an existing path.")
	} else if !os.IsNotExist(err) {
		return "", "", buildError("The output destination cannot be inspected safely.")
	}
	return absolute, parent, nil
}

func removeOwnedTemporary(
	path string,
	original os.FileInfo,
	operations bundleFileOperations,
) error {
	current, err := operations.lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(original, current) {
		return fmt.Errorf("temporary entry identity changed")
	}
	return operations.remove(path)
}

func publishedArtifactBuildError(message, durability, artifact string) error {
	err := buildError(message)
	if typed, ok := err.(*domain.Error); ok {
		typed.Details = map[string]any{
			"published":  true,
			"durability": durability,
			"artifact":   artifact,
		}
	}
	return err
}

func withPublishedPublicKey(err error) error {
	typed, ok := err.(*domain.Error)
	if !ok {
		typed = buildError("The bundle could not be published.").(*domain.Error)
		typed.Cause = err
	}
	if typed.Details == nil {
		typed.Details = map[string]any{}
	}
	typed.Details["publicKeyPublished"] = true
	typed.Details["publicKeyDurability"] = "confirmed"
	return typed
}
