// Package trustchainstate provides the root-scoped combined monotonic state
// for an already-authenticated offline trust-policy authority rotation chain
// and its already-authenticated terminal policy. Callers must validate the
// complete cryptographic tuple before calling Observe.
package trustchainstate

import (
	"bytes"
	"context"
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
	maxStateBytes = 8192
	maxGeneration = uint64(9007199254740991)

	// Purpose is the exact authority-rotation-chain purpose accepted by this
	// state namespace.
	Purpose = "offline-trust-policy-authority-rotation-chain"
	// PolicyPayloadType is the exact terminal policy type bound by this state
	// namespace.
	PolicyPayloadType = "application/vnd.repopass.offline-trust-policy.v2+json"
)

// lockTimeout bounds cross-process lock acquisition. Tests shorten it to
// exercise the timeout path without weakening the production bound.
var lockTimeout = 5 * time.Second

// Evaluation describes how a complete authenticated tuple compared with the
// one durable record rooted at the same explicit trust root.
type Evaluation string

const (
	EvaluationInitialized                   Evaluation = "initialized"
	EvaluationMatched                       Evaluation = "matched"
	EvaluationAdvanced                      Evaluation = "advanced"
	EvaluationRollbackRejected              Evaluation = "rollback-rejected"
	EvaluationAuthorityEquivocationRejected Evaluation = "authority-equivocation-rejected"
	EvaluationPolicyEquivocationRejected    Evaluation = "policy-equivocation-rejected"
	EvaluationUnavailable                   Evaluation = "unavailable"
)

// Error is a stable, redacted rotation-chain-state error classification.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrGenerationRollback    Error = "trust-rotation-chain-state-generation-rollback"
	ErrAuthorityEquivocation Error = "trust-rotation-chain-state-authority-equivocation"
	ErrPolicyEquivocation    Error = "trust-rotation-chain-state-policy-equivocation"
	ErrUnavailable           Error = "trust-rotation-chain-state-unavailable"
)

// Observation is the complete, already-authenticated authority-chain and
// terminal-policy tuple. Purpose and PolicyPayloadType are explicit so callers
// cannot accidentally observe data from another cryptographic domain.
type Observation struct {
	TrustRootKeyID          string
	Purpose                 string
	PolicyPayloadType       string
	ChainTerminalGeneration uint64
	ChainDigest             string
	ChainHopCount           uint64
	TerminalAuthorityKeyID  string
	PolicyGeneration        uint64
	PolicyPayloadDigest     string
}

// Result deliberately exposes no local path or digest. Both durable
// generations are returned because a single atomic record owns both axes.
type Result struct {
	Evaluation              Evaluation
	ChainTerminalGeneration uint64
	PolicyGeneration        uint64
}

// record is the exact canonical durable contract. Do not add migration or
// repair fields: an unrecognized record must fail closed.
type record struct {
	SchemaVersion           string `json:"schemaVersion"`
	TrustRootKeyID          string `json:"trustRootKeyId"`
	Purpose                 string `json:"purpose"`
	PolicyPayloadType       string `json:"policyPayloadType"`
	ChainTerminalGeneration uint64 `json:"chainTerminalGeneration"`
	ChainDigest             string `json:"chainDigest"`
	ChainHopCount           uint64 `json:"chainHopCount"`
	TerminalAuthorityKeyID  string `json:"terminalAuthorityKeyId"`
	PolicyGeneration        uint64 `json:"policyGeneration"`
	PolicyPayloadDigest     string `json:"policyPayloadDigest"`
}

// Observe serializes one complete authenticated tuple. It compares and commits
// both monotonic dimensions while holding one root-scoped lock, so callers can
// never observe a chain update without its bound policy update.
func Observe(ctx context.Context, dataRoot string, observation Observation) (Result, error) {
	if ctx == nil || !validObservation(observation) {
		return unavailable(0, 0)
	}
	if err := ctx.Err(); err != nil {
		return unavailable(0, 0)
	}
	root, err := stateRoot(ctx, dataRoot)
	if err != nil {
		return unavailable(0, 0)
	}
	rootHex := strings.TrimPrefix(observation.TrustRootKeyID, "sha256:")
	statePath := filepath.Join(root, rootHex+".json")
	lockPath := filepath.Join(root, rootHex+".lock")
	lock, err := openLock(lockPath)
	if err != nil {
		return unavailable(0, 0)
	}
	defer lock.Close()
	release, err := acquireLock(ctx, lock, lockTimeout)
	if err != nil {
		return unavailable(0, 0)
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return unavailable(0, 0)
	}

	stored, exists, err := readRecord(statePath)
	if err != nil {
		return unavailable(0, 0)
	}
	if exists {
		if !sameScope(stored, observation) {
			return unavailable(stored.ChainTerminalGeneration, stored.PolicyGeneration)
		}
		result := Result{
			ChainTerminalGeneration: stored.ChainTerminalGeneration,
			PolicyGeneration:        stored.PolicyGeneration,
		}
		switch {
		case observation.ChainTerminalGeneration < stored.ChainTerminalGeneration ||
			observation.PolicyGeneration < stored.PolicyGeneration:
			result.Evaluation = EvaluationRollbackRejected
			return result, ErrGenerationRollback
		case observation.ChainTerminalGeneration == stored.ChainTerminalGeneration &&
			(observation.ChainDigest != stored.ChainDigest ||
				observation.ChainHopCount != stored.ChainHopCount ||
				observation.TerminalAuthorityKeyID != stored.TerminalAuthorityKeyID):
			result.Evaluation = EvaluationAuthorityEquivocationRejected
			return result, ErrAuthorityEquivocation
		case observation.PolicyGeneration == stored.PolicyGeneration &&
			observation.PolicyPayloadDigest != stored.PolicyPayloadDigest:
			result.Evaluation = EvaluationPolicyEquivocationRejected
			return result, ErrPolicyEquivocation
		case observation.ChainTerminalGeneration == stored.ChainTerminalGeneration &&
			observation.PolicyGeneration == stored.PolicyGeneration:
			result.Evaluation = EvaluationMatched
			return result, nil
		}
	}

	next := recordFromObservation(observation)
	if err := writeAndVerifyRecord(root, statePath, next); err != nil {
		if exists {
			return unavailable(stored.ChainTerminalGeneration, stored.PolicyGeneration)
		}
		return unavailable(0, 0)
	}
	if exists {
		return Result{
			Evaluation:              EvaluationAdvanced,
			ChainTerminalGeneration: observation.ChainTerminalGeneration,
			PolicyGeneration:        observation.PolicyGeneration,
		}, nil
	}
	return Result{
		Evaluation:              EvaluationInitialized,
		ChainTerminalGeneration: observation.ChainTerminalGeneration,
		PolicyGeneration:        observation.PolicyGeneration,
	}, nil
}

func unavailable(chainTerminalGeneration, policyGeneration uint64) (Result, error) {
	return Result{
		Evaluation:              EvaluationUnavailable,
		ChainTerminalGeneration: chainTerminalGeneration,
		PolicyGeneration:        policyGeneration,
	}, ErrUnavailable
}

func sameScope(stored record, observation Observation) bool {
	return stored.SchemaVersion == "1" &&
		stored.TrustRootKeyID == observation.TrustRootKeyID &&
		stored.Purpose == observation.Purpose &&
		stored.PolicyPayloadType == observation.PolicyPayloadType
}

func recordFromObservation(observation Observation) record {
	return record{
		SchemaVersion:           "1",
		TrustRootKeyID:          observation.TrustRootKeyID,
		Purpose:                 observation.Purpose,
		PolicyPayloadType:       observation.PolicyPayloadType,
		ChainTerminalGeneration: observation.ChainTerminalGeneration,
		ChainDigest:             observation.ChainDigest,
		ChainHopCount:           observation.ChainHopCount,
		TerminalAuthorityKeyID:  observation.TerminalAuthorityKeyID,
		PolicyGeneration:        observation.PolicyGeneration,
		PolicyPayloadDigest:     observation.PolicyPayloadDigest,
	}
}

func validObservation(observation Observation) bool {
	return validKeyID(observation.TrustRootKeyID) &&
		observation.Purpose == Purpose &&
		observation.PolicyPayloadType == PolicyPayloadType &&
		observation.ChainTerminalGeneration > 0 && observation.ChainTerminalGeneration <= maxGeneration &&
		validDigest(observation.ChainDigest) &&
		observation.ChainHopCount >= 2 && observation.ChainHopCount <= 8 &&
		validKeyID(observation.TerminalAuthorityKeyID) &&
		observation.TrustRootKeyID != observation.TerminalAuthorityKeyID &&
		observation.PolicyGeneration > 0 && observation.PolicyGeneration <= maxGeneration &&
		validDigest(observation.PolicyPayloadDigest)
}

func stateRoot(ctx context.Context, dataRoot string) (string, error) {
	if ctx == nil || !safeNativeInput(dataRoot) {
		return "", ErrUnavailable
	}
	absolute, err := filepath.Abs(dataRoot)
	if err != nil || !safeNativePath(absolute) || repositoryLocal(absolute) {
		return "", ErrUnavailable
	}
	paths := []string{
		absolute,
		filepath.Join(absolute, "trust-policy-state"),
		filepath.Join(absolute, "trust-policy-state", "v1"),
		filepath.Join(absolute, "trust-policy-state", "v1", "rotation-chain"),
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return "", ErrUnavailable
		}
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
		return record{}, false, ErrUnavailable
	}
	defer file.Close()
	if err := validateOpenedRegularFile(file, path, true); err != nil {
		return record{}, false, ErrUnavailable
	}
	raw, err := readBounded(file, maxStateBytes)
	if err != nil {
		return record{}, false, ErrUnavailable
	}
	value, err := decodeRecord(raw)
	if err != nil {
		return record{}, false, ErrUnavailable
	}
	return value, true, nil
}

func writeAndVerifyRecord(directory, target string, value record) error {
	raw, err := canonicalRecord(value)
	if err != nil {
		return ErrUnavailable
	}
	temporary, err := createPrivateTemporaryFile(directory, ".repopass-trust-rotation-chain-state-")
	if err != nil {
		return ErrUnavailable
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	closeWithError := func() error {
		if err := temporary.Close(); err != nil {
			return ErrUnavailable
		}
		return nil
	}
	if err := validateOpenedRegularFile(temporary, temporaryPath, true); err != nil {
		_ = temporary.Close()
		return ErrUnavailable
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return ErrUnavailable
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return ErrUnavailable
	}
	if err := closeWithError(); err != nil {
		return err
	}
	if err := atomicReplace(temporaryPath, target); err != nil {
		return ErrUnavailable
	}
	if err := syncDirectory(directory); err != nil {
		return ErrUnavailable
	}
	actual, exists, err := readRecord(target)
	if err != nil || !exists || actual != value {
		return ErrUnavailable
	}
	return nil
}

func decodeRecord(raw []byte) (record, error) {
	if len(raw) == 0 || len(raw) > maxStateBytes || !utf8.Valid(raw) ||
		bytes.Contains(raw, []byte{'\r'}) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return record{}, ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value record
	if err := decoder.Decode(&value); err != nil || requireEOF(decoder) != nil || !validRecord(value) {
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
	if !validRecord(value) {
		return nil, ErrUnavailable
	}
	raw, err := canonicaljson.Marshal(value)
	if err != nil || len(raw) > maxStateBytes {
		return nil, ErrUnavailable
	}
	return raw, nil
}

func validRecord(value record) bool {
	return value.SchemaVersion == "1" &&
		validObservation(Observation{
			TrustRootKeyID:          value.TrustRootKeyID,
			Purpose:                 value.Purpose,
			PolicyPayloadType:       value.PolicyPayloadType,
			ChainTerminalGeneration: value.ChainTerminalGeneration,
			ChainDigest:             value.ChainDigest,
			ChainHopCount:           value.ChainHopCount,
			TerminalAuthorityKeyID:  value.TerminalAuthorityKeyID,
			PolicyGeneration:        value.PolicyGeneration,
			PolicyPayloadDigest:     value.PolicyPayloadDigest,
		})
}

func readBounded(file *os.File, maximum int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) > maximum {
		return nil, ErrUnavailable
	}
	return raw, nil
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

func containsNUL(value string) bool { return strings.IndexByte(value, 0) >= 0 }

func samePath(left, right string) bool {
	return samePathPlatform(filepath.Clean(left), filepath.Clean(right))
}
