// Package releasestate provides purpose-separated durable monotonic state for
// authenticated authority transitions, release-key policies, and authorized external release indexes.
// Callers must authenticate inputs before observing them.
package releasestate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/repopass/repopass/internal/canonicaljson"
)

const (
	maxStateBytes = 4096
	maxGeneration = uint64(9007199254740991)
)

// lockTimeout bounds cross-process lock acquisition. Tests shorten it to
// exercise timeout behavior without weakening the production bound.
var lockTimeout = 5 * time.Second

// Evaluation describes how an authenticated observation compared with the
// durable record for its exact authority, product, channel, and state kind.
type Evaluation string

const (
	EvaluationInitialized          Evaluation = "initialized"
	EvaluationMatched              Evaluation = "matched"
	EvaluationAdvanced             Evaluation = "advanced"
	EvaluationRollbackRejected     Evaluation = "rollback-rejected"
	EvaluationEquivocationRejected Evaluation = "equivocation-rejected"
	EvaluationUnavailable          Evaluation = "unavailable"
)

// Error is a stable, redacted release-state error classification.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrGenerationRollback     Error = "release-state-generation-rollback"
	ErrGenerationEquivocation Error = "release-state-generation-equivocation"
	ErrUnavailable            Error = "release-state-unavailable"
)

// Result deliberately exposes no path, digest, or scope identifier.
type Result struct {
	Evaluation Evaluation
	Generation uint64
}

type stateKind string

const (
	policyState    stateKind = "policy"
	indexState     stateKind = "index"
	authorityState stateKind = "authority"
)

type record struct {
	AuthorityKeyID string `json:"authorityKeyId"`
	Channel        string `json:"channel"`
	Digest         string `json:"digest"`
	Generation     uint64 `json:"generation"`
	Kind           string `json:"kind"`
	Product        string `json:"product"`
	SchemaVersion  string `json:"schemaVersion"`
}

// ObservePolicy serializes an already-authenticated release-key-policy
// observation for the exact (authorityKeyID, product, channel) key.
func ObservePolicy(ctx context.Context, dataRoot, authorityKeyID, product, channel string, generation uint64, digest string) (Result, error) {
	return observe(ctx, dataRoot, policyState, authorityKeyID, product, channel, generation, digest)
}

// ObserveAuthority serializes an already-authenticated authority-transition
// observation. authorityKeyID is the previous (trust-root) authority ID; it
// deliberately does not make the next authority a state lookup anchor.
func ObserveAuthority(ctx context.Context, dataRoot, authorityKeyID, product, channel string, generation uint64, digest string) (Result, error) {
	return observe(ctx, dataRoot, authorityState, authorityKeyID, product, channel, generation, digest)
}

// ObserveAuthorityChain records one fully authenticated authority-transition
// chain in the existing root-anchored authority namespace. The caller must
// pass the initial explicit root as authorityKeyID and the domain-separated
// digest of the complete canonical chain. It intentionally shares the
// Alpha.29 namespace: a higher terminal generation may advance a prior
// one-hop observation, while same-generation/different-digest is
// equivocation. Call this only after every hop has been verified.
func ObserveAuthorityChain(ctx context.Context, dataRoot, authorityKeyID, product, channel string, terminalGeneration uint64, chainDigest string) (Result, error) {
	return ObserveAuthority(ctx, dataRoot, authorityKeyID, product, channel, terminalGeneration, chainDigest)
}

// ObserveIndex serializes an already-authorized and fully verified release
// index observation for the exact (authorityKeyID, product, channel) key.
func ObserveIndex(ctx context.Context, dataRoot, authorityKeyID, product, channel string, generation uint64, digest string) (Result, error) {
	return observe(ctx, dataRoot, indexState, authorityKeyID, product, channel, generation, digest)
}

func observe(ctx context.Context, dataRoot string, kind stateKind, authorityKeyID, product, channel string, generation uint64, digest string) (Result, error) {
	if ctx == nil || !validKeyID(authorityKeyID) || !validScope(product) || !validScope(channel) ||
		!validDigest(digest) || generation == 0 || generation > maxGeneration {
		return unavailable(0)
	}
	root, err := stateRoot(ctx, dataRoot, kind)
	if err != nil {
		return unavailable(0)
	}
	name := stateKey(authorityKeyID, product, channel)
	statePath := filepath.Join(root, name+".json")
	lockPath := filepath.Join(root, name+".lock")
	lock, err := openLock(lockPath)
	if err != nil {
		return unavailable(0)
	}
	defer lock.Close()
	release, err := acquireLock(ctx, lock, lockTimeout)
	if err != nil {
		return unavailable(0)
	}
	defer release()

	stored, exists, err := readRecord(statePath)
	if err != nil {
		return unavailable(0)
	}
	if exists {
		if stored.AuthorityKeyID != authorityKeyID || stored.Product != product || stored.Channel != channel || stored.Kind != string(kind) {
			return unavailable(stored.Generation)
		}
		switch {
		case generation < stored.Generation:
			return Result{Evaluation: EvaluationRollbackRejected, Generation: stored.Generation}, ErrGenerationRollback
		case generation == stored.Generation && digest != stored.Digest:
			return Result{Evaluation: EvaluationEquivocationRejected, Generation: stored.Generation}, ErrGenerationEquivocation
		case generation == stored.Generation:
			return Result{Evaluation: EvaluationMatched, Generation: stored.Generation}, nil
		}
	}

	next := record{
		AuthorityKeyID: authorityKeyID,
		Channel:        channel,
		Digest:         digest,
		Generation:     generation,
		Kind:           string(kind),
		Product:        product,
		SchemaVersion:  "1",
	}
	if err := writeAndVerifyRecord(root, statePath, next); err != nil {
		if exists {
			return unavailable(stored.Generation)
		}
		return unavailable(0)
	}
	if exists {
		return Result{Evaluation: EvaluationAdvanced, Generation: generation}, nil
	}
	return Result{Evaluation: EvaluationInitialized, Generation: generation}, nil
}

func unavailable(generation uint64) (Result, error) {
	return Result{Evaluation: EvaluationUnavailable, Generation: generation}, ErrUnavailable
}

func stateRoot(ctx context.Context, dataRoot string, kind stateKind) (string, error) {
	if kind != policyState && kind != indexState && kind != authorityState || !safeNativeInput(dataRoot) {
		return "", ErrUnavailable
	}
	absolute, err := filepath.Abs(dataRoot)
	if err != nil || !safeNativePath(absolute) || repositoryLocal(absolute) {
		return "", ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", ErrUnavailable
	}
	paths := []string{
		absolute,
		filepath.Join(absolute, "release-state"),
		filepath.Join(absolute, "release-state", "v1"),
		filepath.Join(absolute, "release-state", "v1", string(kind)),
	}
	for _, path := range paths {
		if _, err := ensurePrivateDirectory(path); err != nil {
			return "", ErrUnavailable
		}
		if err := validatePrivateStateDirectory(path); err != nil {
			return "", ErrUnavailable
		}
	}
	root := paths[len(paths)-1]
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || !samePath(root, resolved) {
		return "", ErrUnavailable
	}
	return resolved, nil
}

func repositoryLocal(dataRoot string) bool {
	current := dataRoot
	for {
		for _, marker := range []string{"repo-passport.yml", ".git"} {
			if _, err := os.Lstat(filepath.Join(current, marker)); err == nil {
				return true
			} else if !os.IsNotExist(err) {
				return true
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}

func ensurePrivateDirectory(path string) (bool, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	volume := filepath.VolumeName(absolute)
	base := volume + string(filepath.Separator)
	relative, err := filepath.Rel(base, absolute)
	if err != nil || filepath.IsAbs(relative) {
		return false, ErrUnavailable
	}
	current := base
	if err := validateDirectory(current); err != nil {
		return false, err
	}
	if relative == "." {
		return false, nil
	}
	createdTarget := false
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return false, ErrUnavailable
		}
		current = filepath.Join(current, component)
		created, err := createPrivateDirectory(current)
		if created && samePath(current, absolute) {
			createdTarget = true
		} else if err != nil {
			return false, err
		}
		if created {
			if err := validatePrivateStateDirectory(current); err != nil {
				return false, err
			}
		}
		if err := validateDirectory(current); err != nil {
			return false, err
		}
	}
	return createdTarget, nil
}

func validateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return ErrUnavailable
	}
	return validateDirectoryPlatform(path, info)
}

func validatePrivateStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return ErrUnavailable
	}
	return validatePrivateStateDirectoryPlatform(path, info)
}

func openLock(path string) (*os.File, error) {
	file, created, err := createPrivateLock(path)
	if err != nil {
		return nil, err
	}
	if !created {
		file, err = openExistingPrivateLock(path)
		if err != nil {
			return nil, err
		}
	}
	if err := validateOpenedRegularFile(file, path, true); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func readRecord(path string) (record, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return record{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return record{}, false, ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return record{}, false, err
	}
	defer file.Close()
	if err := validateOpenedRegularFile(file, path, true); err != nil {
		return record{}, false, err
	}
	raw, err := readBounded(file, maxStateBytes)
	if err != nil {
		return record{}, false, err
	}
	value, err := decodeRecord(raw)
	if err != nil {
		return record{}, false, err
	}
	return value, true, nil
}

func writeAndVerifyRecord(directory, target string, value record) error {
	raw, err := canonicalRecord(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".repopass-release-state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := convergePrivateFile(temporary, temporaryPath); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := atomicReplace(temporaryPath, target); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	actual, exists, err := readRecord(target)
	if err != nil || !exists || actual != value {
		return ErrUnavailable
	}
	return nil
}

func decodeRecord(raw []byte) (record, error) {
	if len(raw) == 0 || len(raw) > maxStateBytes || !utf8.Valid(raw) || bytes.Contains(raw, []byte{'\r'}) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return record{}, ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value record
	if err := decoder.Decode(&value); err != nil {
		return record{}, ErrUnavailable
	}
	if err := requireEOF(decoder); err != nil || value.SchemaVersion != "1" ||
		(value.Kind != string(policyState) && value.Kind != string(indexState) && value.Kind != string(authorityState)) ||
		value.Generation == 0 || value.Generation > maxGeneration || !validKeyID(value.AuthorityKeyID) ||
		!validScope(value.Product) || !validScope(value.Channel) || !validDigest(value.Digest) {
		return record{}, ErrUnavailable
	}
	canonical, err := canonicalRecord(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return record{}, ErrUnavailable
	}
	return value, nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	}
	return ErrUnavailable
}

func canonicalRecord(value record) ([]byte, error) {
	if value.SchemaVersion != "1" || (value.Kind != string(policyState) && value.Kind != string(indexState) && value.Kind != string(authorityState)) ||
		value.Generation == 0 || value.Generation > maxGeneration || !validKeyID(value.AuthorityKeyID) ||
		!validScope(value.Product) || !validScope(value.Channel) || !validDigest(value.Digest) {
		return nil, ErrUnavailable
	}
	raw, err := canonicaljson.Marshal(value)
	if err != nil || len(raw) > maxStateBytes {
		return nil, ErrUnavailable
	}
	return raw, nil
}

func readBounded(file *os.File, maximum int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) > maximum {
		return nil, ErrUnavailable
	}
	return raw, nil
}

func stateKey(authorityKeyID, product, channel string) string {
	hash := sha256.New()
	hash.Write([]byte("repopass.release-state.key.v1\x00"))
	for _, value := range []string{authorityKeyID, product, channel} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validKeyID(value string) bool { return validDigest(value) }

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validScope(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '.' {
			return false
		}
	}
	last := value[len(value)-1]
	return (last >= 'a' && last <= 'z') || (last >= '0' && last <= '9')
}

func containsNUL(value string) bool { return strings.IndexByte(value, 0) >= 0 }

func samePath(left, right string) bool {
	return samePathPlatform(filepath.Clean(left), filepath.Clean(right))
}
