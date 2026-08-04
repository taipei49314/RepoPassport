package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/repopass/repopass/internal/attestation"
)

const (
	MaxPublicKeyBytes   = 16 << 10
	MaxPrivateKeyBytes  = 16 << 10
	MaxSHA256SUMSBytes  = 64 << 10
	MaxArtifactBytes    = 128 << 20
	MaxArtifactSetBytes = 512 << 20
)

func ReadIndex(path string) ([]byte, error)         { return readBoundedStable(path, MaxIndexBytes) }
func ReadEnvelope(path string) ([]byte, error)      { return readBoundedStable(path, MaxEnvelopeBytes) }
func ReadPublicKey(path string) ([]byte, error)     { return readBoundedStable(path, MaxPublicKeyBytes) }
func ReadPolicy(path string) ([]byte, error)        { return readBoundedStable(path, MaxPolicyEnvelopeBytes) }
func ReadPolicyPayload(path string) ([]byte, error) { return readBoundedStable(path, MaxPolicyBytes) }
func ReadAuthorityTransition(path string) ([]byte, error) {
	return readBoundedStable(path, MaxAuthorityTransitionEnvelopeBytes)
}
func ReadAuthorityTransitionChain(path string) ([]byte, error) {
	return readBoundedStable(path, MaxAuthorityTransitionChainBytes)
}

func readBoundedStable(path string, maximum int64) ([]byte, error) {
	raw, _, err := stableFile(path, maximum, true)
	if err != nil || len(raw) == 0 {
		return nil, ErrReadFailed
	}
	return raw, nil
}

func VerifyArtifacts(root string, verified *VerifiedIndex) error {
	if verified == nil {
		return ErrArtifactsInvalid
	}
	entries, err := inspectArtifactRoot(root, verified.index.Files)
	if err != nil {
		return ErrArtifactsInvalid
	}
	if len(entries) != len(verified.index.Files) {
		return ErrArtifactsInvalid
	}
	for i := range entries {
		if entries[i] != verified.index.Files[i] {
			return ErrArtifactsInvalid
		}
	}
	return nil
}

// inspectArtifactRoot returns a complete stable inventory and verifies the
// canonical SHA256SUMS chain. When expected is non-nil it also rejects any
// inventory spelling or count difference before hashing files.
func inspectArtifactRoot(root string, expected []FileEntry) ([]FileEntry, error) {
	return inspectArtifactRootWithInterFileHook(root, expected, nil)
}

type artifactScan struct {
	entries []FileEntry
	files   []os.FileInfo
}

func inspectArtifactRootWithInterFileHook(root string, expected []FileEntry, afterFile func(string)) ([]FileEntry, error) {
	absolute, err := safeExistingDirectory(root)
	if err != nil {
		return nil, ErrArtifactsInvalid
	}
	directoryBefore, err := os.Lstat(absolute)
	if err != nil || !directoryBefore.IsDir() {
		return nil, ErrArtifactsInvalid
	}
	first, err := scanArtifactRoot(absolute, expected, afterFile)
	if err != nil {
		return nil, ErrArtifactsInvalid
	}
	second, err := scanArtifactRoot(absolute, expected, nil)
	if err != nil || len(first.entries) != len(second.entries) {
		return nil, ErrArtifactsInvalid
	}
	for i := range first.entries {
		if first.entries[i] != second.entries[i] || !os.SameFile(first.files[i], second.files[i]) {
			return nil, ErrArtifactsInvalid
		}
	}
	directoryAfter, err := os.Lstat(absolute)
	finalNames, namesErr := directoryNames(absolute)
	if err != nil || namesErr != nil || !os.SameFile(directoryBefore, directoryAfter) || len(finalNames) != len(second.entries) {
		return nil, ErrArtifactsInvalid
	}
	for i := range finalNames {
		if finalNames[i] != second.entries[i].Path {
			return nil, ErrArtifactsInvalid
		}
	}
	return second.entries, nil
}

func scanArtifactRoot(absolute string, expected []FileEntry, afterFile func(string)) (artifactScan, error) {
	before, err := directoryNames(absolute)
	if err != nil || len(before) < 1 || len(before) > MaxFiles {
		return artifactScan{}, ErrArtifactsInvalid
	}
	if expected != nil {
		if len(before) != len(expected) {
			return artifactScan{}, ErrArtifactsInvalid
		}
		for i := range before {
			if before[i] != expected[i].Path {
				return artifactScan{}, ErrArtifactsInvalid
			}
		}
	}
	entries := make([]FileEntry, 0, len(before))
	identities := make([]os.FileInfo, 0, len(before))
	contents := make(map[string][]byte, len(before))
	var total int64
	for _, name := range before {
		if !portableBaseName(name) {
			return artifactScan{}, ErrArtifactsInvalid
		}
		maximum := int64(MaxArtifactBytes)
		if name == "SHA256SUMS" {
			maximum = MaxSHA256SUMSBytes
		}
		raw, stat, err := stableFile(filepath.Join(absolute, name), maximum, name == "SHA256SUMS")
		if err != nil || stat.size < 0 || uint64(stat.size) > MaxGeneration {
			return artifactScan{}, ErrArtifactsInvalid
		}
		if total > int64(MaxArtifactSetBytes)-stat.size {
			return artifactScan{}, ErrArtifactsInvalid
		}
		total += stat.size
		if name == "SHA256SUMS" {
			contents[name] = raw
		}
		entries = append(entries, FileEntry{Path: name, SHA256: stat.digest, Size: uint64(stat.size)})
		identities = append(identities, stat.info)
		if afterFile != nil {
			afterFile(name)
		}
	}
	after, err := directoryNames(absolute)
	if err != nil || !equalStrings(before, after) {
		return artifactScan{}, ErrArtifactsInvalid
	}
	if err := validateSHA256SUMS(entries, contents["SHA256SUMS"]); err != nil {
		return artifactScan{}, ErrArtifactsInvalid
	}
	return artifactScan{entries: entries, files: identities}, nil
}

type stableStat struct {
	size   int64
	digest string
	info   os.FileInfo
}

func stableFile(path string, maximum int64, retain bool) ([]byte, stableStat, error) {
	return stableFileWithPostReadHook(path, maximum, retain, nil)
}

func stableFileWithPostReadHook(path string, maximum int64, retain bool, postRead func()) ([]byte, stableStat, error) {
	if maximum < 0 || !safeNativePath(path) {
		return nil, stableStat{}, ErrReadFailed
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, stableStat{}, ErrReadFailed
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > maximum || isReparsePoint(absolute) {
		return nil, stableStat{}, ErrReadFailed
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !samePath(absolute, resolved) {
		return nil, stableStat{}, ErrReadFailed
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, stableStat{}, ErrReadFailed
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() || hardlinkCount(file) != 1 {
		return nil, stableStat{}, ErrReadFailed
	}
	if err := validateOpenedPath(file, absolute); err != nil {
		return nil, stableStat{}, ErrReadFailed
	}
	if err := validateNoAlternateDataStreams(absolute); err != nil {
		return nil, stableStat{}, ErrReadFailed
	}
	firstHash := sha256.New()
	var raw []byte
	if retain {
		if before.Size() > int64(^uint(0)>>1) {
			return nil, stableStat{}, ErrReadFailed
		}
		raw, err = io.ReadAll(io.TeeReader(io.LimitReader(file, maximum+1), firstHash))
		if err != nil || int64(len(raw)) != before.Size() {
			return nil, stableStat{}, ErrReadFailed
		}
	} else {
		count, copyErr := io.Copy(firstHash, io.LimitReader(file, maximum+1))
		if copyErr != nil || count != before.Size() {
			return nil, stableStat{}, ErrReadFailed
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, stableStat{}, ErrReadFailed
	}
	secondHash := sha256.New()
	count, err := io.Copy(secondHash, io.LimitReader(file, maximum+1))
	if err != nil || count != before.Size() || subtle.ConstantTimeCompare(firstHash.Sum(nil), secondHash.Sum(nil)) != 1 {
		return nil, stableStat{}, ErrReadFailed
	}
	if postRead != nil {
		postRead()
	}
	finalPath, err := os.Lstat(absolute)
	finalOpen, openErr := file.Stat()
	if err != nil || openErr != nil || !os.SameFile(before, finalPath) || !os.SameFile(before, finalOpen) || finalPath.Size() != before.Size() || finalOpen.Size() != before.Size() || isReparsePoint(absolute) || hardlinkCount(file) != 1 || validateOpenedPath(file, absolute) != nil || validateNoAlternateDataStreams(absolute) != nil {
		return nil, stableStat{}, ErrReadFailed
	}
	return raw, stableStat{size: before.Size(), digest: "sha256:" + hex.EncodeToString(firstHash.Sum(nil)), info: opened}, nil
}

func directoryNames(root string) ([]string, error) {
	items, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(items))
	folded := make(map[string]struct{}, len(items))
	for _, item := range items {
		name := item.Name()
		if !portableBaseName(name) {
			return nil, ErrArtifactsInvalid
		}
		fold := strings.ToLower(name)
		if _, ok := folded[fold]; ok {
			return nil, ErrArtifactsInvalid
		}
		folded[fold] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func validateSHA256SUMS(entries []FileEntry, raw []byte) error {
	if raw == nil {
		return ErrArtifactsInvalid
	}
	var out strings.Builder
	count := 0
	for _, entry := range entries {
		if entry.Path == "SHA256SUMS" {
			continue
		}
		out.WriteString(strings.TrimPrefix(entry.SHA256, "sha256:"))
		out.WriteString("  ")
		out.WriteString(entry.Path)
		out.WriteByte('\n')
		count++
	}
	if count == 0 || !bytes.Equal(raw, []byte(out.String())) {
		return ErrArtifactsInvalid
	}
	return nil
}

func safeExistingDirectory(path string) (string, error) {
	if !safeNativePath(path) {
		return "", ErrReadFailed
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", ErrReadFailed
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || isReparsePoint(absolute) {
		return "", ErrReadFailed
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !samePath(absolute, resolved) {
		return "", ErrReadFailed
	}
	directory, err := os.Open(absolute)
	if err != nil {
		return "", ErrReadFailed
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(before, opened) {
		return "", ErrReadFailed
	}
	if err := validateOpenedPath(directory, absolute); err != nil {
		return "", ErrReadFailed
	}
	return filepath.Clean(absolute), nil
}

func LoadPrivateKeyForRelease(keyPath, dataRoot, artifactRoot, outputDir, workingDir string) (ed25519.PrivateKey, error) {
	if !safeNativePath(keyPath) || !safeNativePath(outputDir) {
		return nil, ErrSigningFailed
	}
	keyAbsolute, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, ErrSigningFailed
	}
	dataAbsolute, err := safeExistingDirectory(dataRoot)
	if err != nil {
		return nil, ErrSigningFailed
	}
	artifactAbsolute, err := safeExistingDirectory(artifactRoot)
	if err != nil {
		return nil, ErrSigningFailed
	}
	outputAbsolute, err := filepath.Abs(outputDir)
	if err != nil || pathWithin(dataAbsolute, outputAbsolute) || pathWithin(artifactAbsolute, outputAbsolute) || pathWithin(dataAbsolute, keyAbsolute) || pathWithin(artifactAbsolute, keyAbsolute) || samePath(keyAbsolute, outputAbsolute) {
		return nil, ErrSigningFailed
	}
	if repo, ok := findRepositoryRoot(workingDir); ok && (pathWithin(repo, keyAbsolute) || pathWithin(repo, outputAbsolute)) {
		return nil, ErrSigningFailed
	}
	// The exported established loader carries the platform private-file ACL and
	// handle controls. Run it against both protected roots because release
	// signing isolates the key/output from both data and artifact trees.
	private, err := attestation.LoadPrivateKeyForArtifacts(keyPath, dataRoot, outputDir, "", workingDir)
	if err != nil {
		return nil, ErrSigningFailed
	}
	defer clear(private)
	privateAgain, err := attestation.LoadPrivateKeyForArtifacts(keyPath, artifactRoot, outputDir, "", workingDir)
	if err != nil || subtle.ConstantTimeCompare(private, privateAgain) != 1 {
		clear(privateAgain)
		return nil, ErrSigningFailed
	}
	defer clear(privateAgain)
	return bytes.Clone(private), nil
}

func LoadPrivateKeyForPolicy(keyPath, dataRoot, policyPath, outputDir, workingDir string) (ed25519.PrivateKey, error) {
	if !safeNativePath(keyPath) || !safeNativePath(policyPath) || !safeNativePath(outputDir) {
		return nil, ErrSigningFailed
	}
	policyAbsolute, err := filepath.Abs(policyPath)
	if err != nil {
		return nil, ErrSigningFailed
	}
	keyAbsolute, err := filepath.Abs(keyPath)
	if err != nil || samePath(keyAbsolute, policyAbsolute) {
		return nil, ErrSigningFailed
	}
	outputAbsolute, err := filepath.Abs(outputDir)
	if err != nil || samePath(outputAbsolute, policyAbsolute) || samePath(outputAbsolute, keyAbsolute) {
		return nil, ErrSigningFailed
	}
	if _, _, err := stableFile(policyAbsolute, MaxPolicyBytes, false); err != nil {
		return nil, ErrSigningFailed
	}
	private, err := attestation.LoadPrivateKeyForArtifacts(keyPath, dataRoot, outputDir, "", workingDir)
	if err != nil {
		return nil, ErrSigningFailed
	}
	return private, nil
}

// LoadPrivateKeyForAuthorityTransition applies the established private-key
// loader protections while additionally separating both public-key input and
// every data/output/working root. It returns the exact next-authority SPKI
// snapshot that remained stable across private-key loading, so authoring
// cannot accidentally sign an earlier, independently read companion.
func LoadPrivateKeyForAuthorityTransition(keyPath, dataRoot, nextAuthorityKeyPath, outputDir, workingDir string) (ed25519.PrivateKey, []byte, error) {
	return loadPrivateKeyForAuthorityTransition(keyPath, dataRoot, nextAuthorityKeyPath, outputDir, workingDir, nil)
}

func loadPrivateKeyForAuthorityTransition(keyPath, dataRoot, nextAuthorityKeyPath, outputDir, workingDir string, beforeNextReread func()) (ed25519.PrivateKey, []byte, error) {
	for _, path := range []string{keyPath, dataRoot, nextAuthorityKeyPath, outputDir, workingDir} {
		if !safeNativePath(path) {
			return nil, nil, ErrSigningFailed
		}
	}
	keyAbsolute, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	nextAbsolute, err := filepath.Abs(nextAuthorityKeyPath)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	outputAbsolute, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	dataAbsolute, err := safeExistingDirectory(dataRoot)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	workingAbsolute, err := safeExistingDirectory(workingDir)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	separated := []string{keyAbsolute, nextAbsolute, outputAbsolute, dataAbsolute, workingAbsolute}
	for left := 0; left < len(separated); left++ {
		for right := left + 1; right < len(separated); right++ {
			if pathWithin(separated[left], separated[right]) || pathWithin(separated[right], separated[left]) {
				return nil, nil, ErrSigningFailed
			}
		}
	}
	if repo, ok := findRepositoryRoot(workingAbsolute); ok &&
		(pathWithin(repo, keyAbsolute) || pathWithin(repo, nextAbsolute) || pathWithin(repo, outputAbsolute) || pathWithin(repo, dataAbsolute)) {
		return nil, nil, ErrSigningFailed
	}
	nextBefore, nextBeforeStat, err := stableFile(nextAbsolute, MaxPublicKeyBytes, true)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	_, nextDER, err := parseCanonicalSPKI(nextBefore)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	private, err := attestation.LoadPrivateKeyForArtifacts(keyPath, dataRoot, outputDir, "", workingDir)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	defer clear(private)
	privateAgain, err := attestation.LoadPrivateKeyForArtifacts(keyPath, filepath.Dir(nextAbsolute), outputDir, "", workingDir)
	if err != nil || subtle.ConstantTimeCompare(private, privateAgain) != 1 {
		clear(privateAgain)
		return nil, nil, ErrSigningFailed
	}
	defer clear(privateAgain)
	if beforeNextReread != nil {
		beforeNextReread()
	}
	nextAfter, nextAfterStat, err := stableFile(nextAbsolute, MaxPublicKeyBytes, true)
	if err != nil || !os.SameFile(nextBeforeStat.info, nextAfterStat.info) ||
		subtle.ConstantTimeCompare(nextBefore, nextAfter) != 1 {
		return nil, nil, ErrSigningFailed
	}
	previousDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil || subtle.ConstantTimeCompare(previousDER, nextDER) == 1 {
		return nil, nil, ErrSigningFailed
	}
	return bytes.Clone(private), bytes.Clone(nextBefore), nil
}

func samePath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func pathWithin(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	if runtime.GOOS == "windows" {
		relative = strings.ToLower(relative)
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func findRepositoryRoot(workingDir string) (string, bool) {
	current, err := filepath.Abs(workingDir)
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

func safeNativePath(value string) bool {
	if value == "" {
		return false
	}
	if runtime.GOOS != "windows" {
		return !strings.ContainsRune(value, 0)
	}
	normalized := strings.ReplaceAll(value, "/", "\\")
	if strings.HasPrefix(normalized, `\\?\`) || strings.HasPrefix(normalized, `\\.\`) {
		return false
	}
	volume := filepath.VolumeName(value)
	if strings.HasPrefix(strings.ReplaceAll(volume, "/", "\\"), `\\`) {
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
		if segment == "." || segment == ".." || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || !portableNativeSegment(segment) {
			return false
		}
	}
	return true
}

func portableNativeSegment(segment string) bool {
	for _, c := range segment {
		if c < 0x20 || strings.ContainsRune(`<>":|?*`, c) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(strings.TrimRight(segment, " ."), ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CLOCK$" || base == "CONIN$" || base == "CONOUT$" {
		return false
	}
	return !(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9')
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
