package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/rendering"
	"github.com/repopass/repopass/internal/verification"
)

var runIDPattern = regexp.MustCompile(`^(?:run|vrf)_[a-zA-Z0-9._-]{3,96}$`)

type RunStore struct {
	Root string
}

func (s RunStore) Directory(id string) (string, error) {
	if !runIDPattern.MatchString(id) {
		return "", domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityHigh, "Run ID is invalid.")
	}
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, id)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || filepath.IsAbs(relative) {
		return "", domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityCritical, "Run directory escaped the data root.")
	}
	return directory, nil
}

func (s RunStore) Write(result domain.VerificationResult) (string, error) {
	if !runIDPattern.MatchString(result.RunID) {
		return "", domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityHigh, "Run ID is invalid.")
	}
	if result.RunID == "" || result.VerificationID == "" {
		return "", domain.NewError(
			domain.CodeEvidenceBuildFailed,
			domain.SeverityHigh,
			"Run and verification IDs are required.",
		)
	}
	if err := verification.VerifyIntegrity(result); err != nil {
		return "", err
	}
	root, err := secureRoot(s.Root, true)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, result.RunID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", domain.WrapError(
			domain.CodeEvidenceBuildFailed,
			domain.SeverityCritical,
			"Authoritative run directory is not a new regular directory.",
			err,
		)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil || !sameFilesystemPath(directory, resolvedDirectory) {
		return "", domain.WrapError(
			domain.CodeEvidenceBuildFailed,
			domain.SeverityCritical,
			"Authoritative run directory resolved through a link.",
			err,
		)
	}
	verificationJSON, err := canonicaljson.Indent(result)
	if err != nil {
		return "", err
	}
	reportHTML, err := rendering.HTML(result)
	if err != nil {
		return "", err
	}
	if err := atomicWrite(directory, "verification.json", verificationJSON, 0o600); err != nil {
		return "", err
	}
	if err := atomicWrite(directory, "report.html", reportHTML, 0o600); err != nil {
		return "", err
	}
	if err := writeNDJSON(directory, result.Observations); err != nil {
		return "", err
	}
	for name, value := range map[string]any{
		"assertions.json":       result.Assertions,
		"policy-decisions.json": result.PolicyDecisions,
	} {
		data, err := canonicaljson.Indent(value)
		if err != nil {
			return "", err
		}
		if err := atomicWrite(directory, name, data, 0o600); err != nil {
			return "", err
		}
	}
	return directory, nil
}

func (s RunStore) Read(id string) (domain.VerificationResult, error) {
	if !runIDPattern.MatchString(id) {
		return domain.VerificationResult{}, domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityHigh, "Run ID is invalid.")
	}
	root, err := secureRoot(s.Root, false)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	directory := filepath.Join(root, id)
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return domain.VerificationResult{}, domain.WrapError(domain.CodeSourceNotFound, domain.SeverityHigh, "Verification run was not found.", err)
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return domain.VerificationResult{}, domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Verification run directory is not a regular directory.")
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil || !sameFilesystemPath(directory, resolvedDirectory) {
		return domain.VerificationResult{}, domain.WrapError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Verification run directory resolved through a link.", err)
	}
	path := filepath.Join(directory, "verification.json")
	info, err := os.Lstat(path)
	if err != nil {
		return domain.VerificationResult{}, domain.WrapError(domain.CodeSourceNotFound, domain.SeverityHigh, "Verification run was not found.", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return domain.VerificationResult{}, domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Verification artifact is not a regular file.")
	}
	if info.Size() > 16<<20 {
		return domain.VerificationResult{}, domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityHigh, "Verification artifact exceeds the size limit.")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	result, err := rendering.DecodeVerification(data)
	if err != nil {
		return domain.VerificationResult{}, domain.WrapError(domain.CodeEvidenceDigestMismatch, domain.SeverityHigh, "Verification artifact is invalid.", err)
	}
	if err := verification.VerifyIntegrity(result); err != nil {
		return domain.VerificationResult{}, err
	}
	if result.RunID != id {
		return domain.VerificationResult{}, domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Verification run ID does not match its authoritative directory.")
	}
	return result, nil
}

func secureRoot(value string, create bool) (string, error) {
	root, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", domain.WrapError(domain.CodeSourceNotFound, domain.SeverityHigh, "Authoritative run root was not found.", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", domain.NewError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Authoritative run root is not a regular directory.")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || !sameFilesystemPath(root, resolved) {
		return "", domain.WrapError(domain.CodeEvidenceDigestMismatch, domain.SeverityCritical, "Authoritative run root resolved through a link.", err)
	}
	return resolved, nil
}

func sameFilesystemPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func atomicWrite(directory, name string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(directory, ".repopass-tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	target := filepath.Join(directory, name)
	if err := os.Rename(tempName, target); err != nil {
		return fmt.Errorf("replace %s: %w", target, err)
	}
	return nil
}

func writeNDJSON(directory string, events []domain.ObservationEvent) error {
	temp, err := os.CreateTemp(directory, ".repopass-observations-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	writer := bufio.NewWriter(temp)
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			temp.Close()
			return err
		}
		if _, err := writer.Write(append(data, '\n')); err != nil {
			temp.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, filepath.Join(directory, "observations.ndjson"))
}
