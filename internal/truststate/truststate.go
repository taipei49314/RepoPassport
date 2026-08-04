// Package truststate provides the local, per-authority monotonic state used
// by the authenticated offline trust-policy v2 verifier. It deliberately has
// no policy parsing or key handling responsibilities: callers supply only
// already-authenticated canonical identifiers.
package truststate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// lockTimeout is fixed in production. Package tests temporarily shorten it to
// prove the bounded, nonblocking cross-process contention behavior.
var lockTimeout = 5 * time.Second

// Evaluation is the result of comparing an authenticated policy against its
// durable local record.
type Evaluation string

const (
	EvaluationInitialized          Evaluation = "initialized"
	EvaluationMatched              Evaluation = "matched"
	EvaluationAdvanced             Evaluation = "advanced"
	EvaluationRollbackRejected     Evaluation = "rollback-rejected"
	EvaluationEquivocationRejected Evaluation = "equivocation-rejected"
	EvaluationUnavailable          Evaluation = "unavailable"
)

var (
	ErrGenerationRollback     = errors.New("state-generation-rollback")
	ErrGenerationEquivocation = errors.New("state-generation-equivocation")
	ErrUnavailable            = errors.New("state-unavailable")
)

// Result deliberately exposes only the current durable generation. It never
// exposes a state path or digest.
type Result struct {
	Evaluation Evaluation
	Generation uint64
}

type record struct {
	AuthorityKeyID string `json:"authorityKeyId"`
	Generation     uint64 `json:"generation"`
	PolicyDigest   string `json:"policyDigest"`
	SchemaVersion  string `json:"schemaVersion"`
}

// Observe serializes one authenticated policy observation. It initializes or
// advances only after a complete same-directory atomic write has been
// re-read and verified. Every filesystem, topology, parsing, and locking
// failure is intentionally collapsed to ErrUnavailable.
func Observe(ctx context.Context, dataRoot, authorityKeyID string, generation uint64, policyDigest string) (Result, error) {
	if !validKeyID(authorityKeyID) || !validKeyID(policyDigest) || generation == 0 || generation > maxGeneration {
		return unavailable(0)
	}
	root, err := stateRoot(ctx, dataRoot)
	if err != nil {
		return unavailable(0)
	}
	authorityHex := strings.TrimPrefix(authorityKeyID, "sha256:")
	statePath := filepath.Join(root, authorityHex+".json")
	lockPath := filepath.Join(root, authorityHex+".lock")
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
		if stored.AuthorityKeyID != authorityKeyID {
			return unavailable(stored.Generation)
		}
		switch {
		case generation < stored.Generation:
			return Result{Evaluation: EvaluationRollbackRejected, Generation: stored.Generation}, ErrGenerationRollback
		case generation == stored.Generation && policyDigest != stored.PolicyDigest:
			return Result{Evaluation: EvaluationEquivocationRejected, Generation: stored.Generation}, ErrGenerationEquivocation
		case generation == stored.Generation:
			return Result{Evaluation: EvaluationMatched, Generation: stored.Generation}, nil
		}
	}

	next := record{
		AuthorityKeyID: authorityKeyID,
		Generation:     generation,
		PolicyDigest:   policyDigest,
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

func stateRoot(ctx context.Context, dataRoot string) (string, error) {
	if !safeNativeInput(dataRoot) {
		return "", ErrUnavailable
	}
	absolute, err := filepath.Abs(dataRoot)
	if err != nil || !safeNativePath(absolute) || repositoryLocal(absolute) {
		return "", ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", ErrUnavailable
	}
	_, err = ensurePrivateDirectory(absolute)
	if err != nil {
		return "", ErrUnavailable
	}
	if err := validatePrivateStateDirectory(absolute); err != nil {
		return "", ErrUnavailable
	}
	stateParent := filepath.Join(absolute, "trust-policy-state")
	_, err = ensurePrivateDirectory(stateParent)
	if err != nil {
		return "", ErrUnavailable
	}
	if err := validatePrivateStateDirectory(stateParent); err != nil {
		return "", ErrUnavailable
	}
	root := filepath.Join(stateParent, "v1")
	_, err = ensurePrivateDirectory(root)
	if err != nil {
		return "", ErrUnavailable
	}
	if err := validatePrivateStateDirectory(root); err != nil {
		return "", ErrUnavailable
	}
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
	temporary, err := os.CreateTemp(directory, ".repopass-trust-state-*")
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
	if err := requireEOF(decoder); err != nil || value.SchemaVersion != "1" || value.Generation == 0 || value.Generation > maxGeneration ||
		!validKeyID(value.AuthorityKeyID) || !validKeyID(value.PolicyDigest) {
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
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	return ErrUnavailable
}

func canonicalRecord(value record) ([]byte, error) {
	if value.SchemaVersion != "1" || value.Generation == 0 || value.Generation > maxGeneration || !validKeyID(value.AuthorityKeyID) || !validKeyID(value.PolicyDigest) {
		return nil, ErrUnavailable
	}
	raw, err := canonicaljson.Marshal(value)
	if err != nil || len(raw) > maxStateBytes {
		return nil, ErrUnavailable
	}
	return raw, nil
}

func readBounded(file *os.File, maximum int) ([]byte, error) {
	reader := io.LimitReader(file, int64(maximum)+1)
	raw, err := io.ReadAll(reader)
	if err != nil || len(raw) > maximum {
		return nil, ErrUnavailable
	}
	return raw, nil
}

func validKeyID(value string) bool {
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

func containsNUL(value string) bool { return strings.IndexByte(value, 0) >= 0 }

func samePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return samePathPlatform(left, right)
}
