package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const MaxPrivateKeyBytes = 16 << 10

func LoadPrivateKey(
	keyPath string,
	dataRoot string,
	outputPath string,
	workingDirectory string,
) (ed25519.PrivateKey, error) {
	return LoadPrivateKeyForArtifacts(
		keyPath,
		dataRoot,
		outputPath,
		"",
		workingDirectory,
	)
}

// LoadPrivateKeyForArtifacts validates every signing input and destination
// before private key material is parsed. The optional public-key companion and
// bundle must be isolated, new paths outside the run store and repository.
func LoadPrivateKeyForArtifacts(
	keyPath string,
	dataRoot string,
	bundleOutputPath string,
	publicKeyOutputPath string,
	workingDirectory string,
) (ed25519.PrivateKey, error) {
	if !safeNativePath(keyPath) || !safeNativePath(bundleOutputPath) ||
		(publicKeyOutputPath != "" && !safeNativePath(publicKeyOutputPath)) {
		return nil, signingError("Device, extended-namespace, and alternate-data-stream paths are unsupported for signing.")
	}
	keyAbsolute, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, signingError("The private key location cannot be resolved safely.")
	}
	bundleOutputCandidate, err := filepath.Abs(bundleOutputPath)
	if err != nil {
		return nil, buildError("The bundle output location cannot be resolved safely.")
	}
	if sameFilesystemPath(keyAbsolute, bundleOutputCandidate) {
		return nil, signingError("The private key must be distinct from every signing output.")
	}
	if publicKeyOutputPath != "" {
		publicOutputCandidate, resolveErr := filepath.Abs(publicKeyOutputPath)
		if resolveErr != nil {
			return nil, buildError("The public-key output location cannot be resolved safely.")
		}
		if sameFilesystemPath(keyAbsolute, publicOutputCandidate) {
			return nil, signingError("The private key must be distinct from every signing output.")
		}
	}
	bundleOutputAbsolute, err := canonicalNewOutputPath(bundleOutputPath)
	if err != nil {
		return nil, err
	}
	publicKeyOutputAbsolute := ""
	if publicKeyOutputPath != "" {
		publicKeyOutputAbsolute, err = canonicalNewOutputPath(publicKeyOutputPath)
		if err != nil {
			return nil, err
		}
		if sameFilesystemPath(bundleOutputAbsolute, publicKeyOutputAbsolute) {
			return nil, buildError("The bundle and public-key companion must use distinct output paths.")
		}
	}
	dataAbsolute, err := canonicalExistingDirectory(dataRoot)
	if err != nil {
		return nil, signingError("The authoritative data location cannot be resolved to a safe existing directory.")
	}
	repositoryRoot, repositoryFound := findRepositoryRoot(workingDirectory)
	if repositoryFound {
		repositoryRoot, err = canonicalExistingDirectory(repositoryRoot)
		if err != nil {
			return nil, signingError("The detected repository cannot be resolved to a safe existing directory.")
		}
	}
	for _, outputAbsolute := range []string{bundleOutputAbsolute, publicKeyOutputAbsolute} {
		if outputAbsolute == "" {
			continue
		}
		if pathWithin(dataAbsolute, outputAbsolute) ||
			(repositoryFound && pathWithin(repositoryRoot, outputAbsolute)) {
			return nil, buildError("Signing outputs must be outside the authoritative data store and detected repository.")
		}
		if sameFilesystemPath(keyAbsolute, outputAbsolute) {
			return nil, signingError("The private key must be distinct from every signing output.")
		}
	}
	if pathWithin(dataAbsolute, keyAbsolute) {
		return nil, signingError("The private key must be outside the data store and output path.")
	}
	if repositoryFound &&
		pathWithin(repositoryRoot, keyAbsolute) {
		return nil, signingError("The private key must be outside the detected repository.")
	}
	keyInfo, err := os.Lstat(keyAbsolute)
	if err != nil ||
		(runtime.GOOS != "windows" && keyInfo.Mode().Perm()&0o077 != 0) {
		return nil, signingError("The private key permissions must exclude group and other access.")
	}

	raw, err := readRegularFileValidated(
		keyAbsolute,
		MaxPrivateKeyBytes,
		validatePrivateKeyHandle,
	)
	if err != nil {
		return nil, signingError("The private key must be a bounded regular file that does not resolve through a link or reparse point.")
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, signingError("The private key must be canonical PKCS#8 PEM containing Ed25519 key material.")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, signingError("The private key must be canonical PKCS#8 PEM containing Ed25519 key material.")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, signingError("The private key must use Ed25519.")
	}
	defer clear(privateKey)
	canonicalDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, signingError("The private key cannot be normalized.")
	}
	defer clear(canonicalDER)
	canonicalPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: canonicalDER})
	defer clear(canonicalPEM)
	if subtle.ConstantTimeCompare(raw, canonicalPEM) != 1 ||
		subtle.ConstantTimeCompare(block.Bytes, canonicalDER) != 1 {
		return nil, signingError("The private key must use canonical PKCS#8 PEM encoding.")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

// LoadPrivateKeyForDerivedArtifacts adds target-repository isolation to the
// existing signing path. All target/key/output containment checks complete
// before LoadPrivateKeyForArtifacts opens private key material.
func LoadPrivateKeyForDerivedArtifacts(
	keyPath string,
	dataRoot string,
	bundleOutputPath string,
	publicKeyOutputPath string,
	targetRepositoryRoot string,
	workingDirectory string,
) (ed25519.PrivateKey, error) {
	targetRoot, err := canonicalExistingDirectory(targetRepositoryRoot)
	if err != nil {
		return nil, signingError("The derived target repository cannot be resolved to a safe existing directory.")
	}
	keyAbsolute, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, signingError("The private key location cannot be resolved safely.")
	}
	bundleAbsolute, err := canonicalNewOutputPath(bundleOutputPath)
	if err != nil {
		return nil, err
	}
	paths := []string{keyAbsolute, bundleAbsolute}
	if publicKeyOutputPath != "" {
		publicAbsolute, resolveErr := canonicalNewOutputPath(publicKeyOutputPath)
		if resolveErr != nil {
			return nil, resolveErr
		}
		paths = append(paths, publicAbsolute)
	}
	for _, candidate := range paths {
		if pathWithin(targetRoot, candidate) {
			return nil, signingError("Derived signing keys and outputs must be outside the target repository.")
		}
	}
	return LoadPrivateKeyForArtifacts(
		keyPath, dataRoot, bundleOutputPath, publicKeyOutputPath, workingDirectory,
	)
}

func canonicalNewOutputPath(value string) (string, error) {
	if value == "" || !safeNativePath(value) {
		return "", buildError("The output location cannot be resolved safely.")
	}
	absolute, err := filepath.Abs(value)
	if err != nil || requireUnlinkedDirectory(filepath.Dir(absolute)) != nil {
		return "", buildError("The output parent must be an existing unlinked regular directory.")
	}
	parent, err := canonicalExistingDirectory(filepath.Dir(absolute))
	if err != nil {
		return "", buildError("The output parent must be an existing unlinked regular directory.")
	}
	absolute = filepath.Join(parent, filepath.Base(absolute))
	if _, err := os.Lstat(absolute); err == nil {
		return "", buildError("Signing outputs must be new files and cannot overwrite an existing path.")
	} else if !os.IsNotExist(err) {
		return "", buildError("A signing output destination cannot be inspected safely.")
	}
	return absolute, nil
}

func ReadTrustKey(path string) ([]byte, error) {
	if !safeNativePath(path) {
		return nil, untrustedError("Device, extended-namespace, and alternate-data-stream trust-key paths are unsupported.")
	}
	raw, err := readRegularFile(path, MaxPublicKeyBytes)
	if err != nil {
		return nil, untrustedError("The trusted public key must be a bounded regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

// ReadOfflineTrustPolicy reads only a bounded unlinked regular file. Policy
// syntax and its independently supplied digest pin are validated by the caller
// after the evidence bundle's cryptographic checks have completed.
func ReadOfflineTrustPolicy(path string) ([]byte, error) {
	if !safeNativePath(path) {
		return nil, untrustedError("The offline trust policy path is unsupported.")
	}
	raw, err := readRegularFile(path, MaxOfflineTrustPolicyBytes)
	if err != nil || len(raw) == 0 {
		return nil, untrustedError("The offline trust policy must be a bounded regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

// ReadTrustPolicyAuthorityKey reads the distinct canonical authority key used
// only to authenticate a signed offline trust policy.
func ReadTrustPolicyAuthorityKey(path string) ([]byte, error) {
	return ReadTrustKey(path)
}

// ReadTrustPolicyAuthorityTransitionRootKey reads the explicit previous root
// through the same bounded, unlinked, stable-file boundary as direct-policy
// authority keys. Canonical SPKI validation remains a cryptographic-stage
// responsibility so callers can preserve the required no-probe order.
func ReadTrustPolicyAuthorityTransitionRootKey(path string) ([]byte, error) {
	raw, err := readStableRegularFile(path, MaxPublicKeyBytes)
	if err != nil || len(raw) == 0 {
		return nil, untrustedError("The offline trust-policy authority root must be a bounded stable regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

// ReadTrustPolicyAuthorityTransitionTerminalKey reads the exact public key
// that a verified transition must bind and that authenticates the terminal
// signed policy.
func ReadTrustPolicyAuthorityTransitionTerminalKey(path string) ([]byte, error) {
	raw, err := readStableRegularFile(path, MaxPublicKeyBytes)
	if err != nil || len(raw) == 0 {
		return nil, untrustedError("The offline trust-policy terminal authority must be a bounded stable regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

// ReadTrustPolicyAuthorityTransition reads only a bounded, unlinked regular
// file. Canonical envelope shape and authentication are checked later against
// the explicit root and terminal key.
func ReadTrustPolicyAuthorityTransition(path string) ([]byte, error) {
	if !safeNativePath(path) {
		return nil, untrustedError("The offline trust-policy authority transition path is unsupported.")
	}
	raw, err := readStableRegularFile(path, MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes)
	if err != nil || len(raw) == 0 {
		return nil, untrustedError("The offline trust-policy authority transition must be a bounded regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

// readStableRegularFile strengthens the normal attestation read boundary for
// trust-root continuity inputs. It retains bytes only after two reads through
// the same exclusive regular-file handle produce the same digest and the path,
// size, link count, and handle identity remain stable.
func readStableRegularFile(path string, maximum int) ([]byte, error) {
	if maximum <= 0 || !safeNativePath(path) {
		return nil, os.ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, os.ErrInvalid
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		isReparsePoint(absolute) || before.Size() < 0 || before.Size() > int64(maximum) {
		return nil, os.ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameFilesystemPath(absolute, resolved) {
		return nil, os.ErrInvalid
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, os.ErrInvalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) ||
		opened.Size() != before.Size() || validateStableInputHandle(file, absolute) != nil {
		return nil, os.ErrInvalid
	}

	firstHash := sha256.New()
	raw, err := io.ReadAll(io.TeeReader(io.LimitReader(file, int64(maximum)+1), firstHash))
	if err != nil || int64(len(raw)) != before.Size() {
		clear(raw)
		return nil, os.ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		clear(raw)
		return nil, os.ErrInvalid
	}
	secondHash := sha256.New()
	count, err := io.Copy(secondHash, io.LimitReader(file, int64(maximum)+1))
	if err != nil || count != before.Size() || subtle.ConstantTimeCompare(firstHash.Sum(nil), secondHash.Sum(nil)) != 1 {
		clear(raw)
		return nil, os.ErrInvalid
	}
	finalPath, pathErr := os.Lstat(absolute)
	finalOpen, openErr := file.Stat()
	if pathErr != nil || openErr != nil || !os.SameFile(before, finalPath) || !os.SameFile(before, finalOpen) ||
		finalPath.Size() != before.Size() || finalOpen.Size() != before.Size() || isReparsePoint(absolute) ||
		validateStableInputHandle(file, absolute) != nil {
		clear(raw)
		return nil, os.ErrInvalid
	}
	return raw, nil
}

// ReadSignedOfflineTrustPolicyEnvelope reads the bounded canonical DSSE
// envelope. Its syntax and authenticity are intentionally checked later.
func ReadSignedOfflineTrustPolicyEnvelope(path string) ([]byte, error) {
	if !safeNativePath(path) {
		return nil, untrustedError("The signed offline trust policy envelope path is unsupported.")
	}
	raw, err := readRegularFile(path, MaxSignedOfflineTrustPolicyEnvelopeBytes)
	if err != nil || len(raw) == 0 {
		return nil, untrustedError("The signed offline trust policy envelope must be a bounded regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

func ReadBundle(path string) ([]byte, error) {
	if !safeNativePath(path) {
		return nil, invalidError()
	}
	raw, err := readRegularFile(path, MaxBundleBytes)
	if err != nil || len(raw) == 0 {
		return nil, invalidError()
	}
	return raw, nil
}

func readRegularFile(path string, maximum int) ([]byte, error) {
	return readRegularFileValidated(path, maximum, nil)
}

func readRegularFileValidated(
	path string,
	maximum int,
	validateHandle func(*os.File, string) error,
) ([]byte, error) {
	if maximum <= 0 {
		return nil, os.ErrInvalid
	}
	if !safeNativePath(path) {
		return nil, os.ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || isReparsePoint(absolute) ||
		info.Size() < 0 || info.Size() > int64(maximum) {
		return nil, os.ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameFilesystemPath(absolute, resolved) {
		return nil, os.ErrInvalid
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || openedInfo.Size() > int64(maximum) {
		return nil, os.ErrInvalid
	}
	if validateHandle != nil {
		if err := validateHandle(file, absolute); err != nil {
			return nil, os.ErrInvalid
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) > maximum {
		return nil, os.ErrInvalid
	}
	finalInfo, err := os.Lstat(absolute)
	if err != nil || !os.SameFile(info, finalInfo) || finalInfo.Size() != int64(len(raw)) {
		clear(raw)
		return nil, os.ErrInvalid
	}
	return raw, nil
}

func requireUnlinkedDirectory(path string) error {
	if !safeNativePath(path) {
		return os.ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		isReparsePoint(absolute) {
		return os.ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameFilesystemPath(absolute, resolved) {
		return os.ErrInvalid
	}
	directory, err := os.Open(absolute)
	if err != nil {
		return os.ErrInvalid
	}
	defer directory.Close()
	openedInfo, err := directory.Stat()
	if err != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		return os.ErrInvalid
	}
	if err := validateDirectoryHandle(directory, absolute); err != nil {
		return os.ErrInvalid
	}
	return nil
}

func canonicalExistingDirectory(path string) (string, error) {
	if !safeNativePath(path) {
		return "", os.ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	if err := requireUnlinkedDirectory(resolved); err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func findRepositoryRoot(workingDirectory string) (string, bool) {
	current, err := filepath.Abs(workingDirectory)
	if err != nil {
		return "", false
	}
	for {
		for _, marker := range []string{"repo-passport.yml", ".git"} {
			if _, err := os.Lstat(filepath.Join(current, marker)); err == nil {
				return current, true
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

func pathWithin(parent, candidate string) bool {
	parentAbsolute, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	candidateAbsolute, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(parentAbsolute, candidateAbsolute)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	if runtime.GOOS == "windows" {
		relative = strings.ToLower(relative)
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func sameFilesystemPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func safeNativePath(value string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	normalized := strings.ReplaceAll(value, "/", "\\")
	if strings.HasPrefix(normalized, `\\?\`) ||
		strings.HasPrefix(normalized, `\\.\`) {
		return false
	}
	volume := filepath.VolumeName(value)
	normalizedVolume := strings.ReplaceAll(volume, "/", "\\")
	if strings.HasPrefix(normalizedVolume, `\\`) {
		return false
	}
	remainder := strings.TrimPrefix(value, volume)
	if strings.Contains(remainder, ":") {
		return false
	}
	for _, segment := range strings.Split(strings.ReplaceAll(remainder, "/", "\\"), "\\") {
		if segment == "" {
			continue
		}
		if segment == "." || segment == ".." ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") ||
			windowsReservedPathSegment(segment) {
			return false
		}
		for _, character := range segment {
			if character < 0x20 || strings.ContainsRune(`<>"|?*`, character) {
				return false
			}
		}
	}
	return true
}

func windowsReservedPathSegment(segment string) bool {
	trimmed := strings.TrimRight(segment, " .")
	base := strings.ToUpper(strings.SplitN(trimmed, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
		base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return base == "COM\u00b9" || base == "COM\u00b2" || base == "COM\u00b3" ||
		base == "LPT\u00b9" || base == "LPT\u00b2" || base == "LPT\u00b3"
}
