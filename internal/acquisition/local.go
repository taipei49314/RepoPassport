package acquisition

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
)

const (
	DefaultMaxFiles     = 50_000
	DefaultMaxTotalSize = int64(1 << 30)
	DefaultMaxFileSize  = int64(128 << 20)
)

type LocalProvider struct {
	MaxFiles     int
	MaxTotalSize int64
	MaxFileSize  int64
}

func NewLocalProvider() *LocalProvider {
	return &LocalProvider{
		MaxFiles:     DefaultMaxFiles,
		MaxTotalSize: DefaultMaxTotalSize,
		MaxFileSize:  DefaultMaxFileSize,
	}
}

func (p *LocalProvider) Resolve(ctx context.Context, ref domain.SourceRef) (domain.ResolvedSource, error) {
	return p.resolve(ctx, ref, true)
}

// ResolveCommandFree performs the same local root validation as Resolve but
// deliberately performs no Git or other repository command. It is the only
// resolution profile permitted during repository-derived SBOM observation.
func (p *LocalProvider) ResolveCommandFree(ctx context.Context, ref domain.SourceRef) (domain.ResolvedSource, error) {
	return p.resolve(ctx, ref, false)
}

func (p *LocalProvider) resolve(ctx context.Context, ref domain.SourceRef, observeGit bool) (domain.ResolvedSource, error) {
	if err := ctx.Err(); err != nil {
		return domain.ResolvedSource{}, domain.WrapError(domain.CodeCancelled, domain.SeverityWarning, "Source resolution was cancelled.", err)
	}
	if ref.Kind != "" && ref.Kind != "local" {
		return domain.ResolvedSource{}, domain.NewError(domain.CodeSourceRefUnresolved, domain.SeverityHigh, "Only local directory sources are enabled in this build.")
	}
	if strings.Contains(ref.Value, "://") {
		e := domain.NewError(domain.CodeSourceRefUnresolved, domain.SeverityHigh, "Remote Git acquisition is recognized but disabled until credential and SSRF isolation is available.")
		e.Suggestion = "Clone the public repository yourself and pass its local directory."
		return domain.ResolvedSource{}, e
	}
	absolute, err := filepath.Abs(ref.Value)
	if err != nil {
		return domain.ResolvedSource{}, domain.WrapError(domain.CodeSourceRefUnresolved, domain.SeverityHigh, "Source path could not be resolved.", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return domain.ResolvedSource{}, domain.WrapError(domain.CodeSourceNotFound, domain.SeverityHigh, "Source directory was not found.", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(absolute) {
		return domain.ResolvedSource{}, domain.NewError(domain.CodeSourceSymlinkEscape, domain.SeverityCritical, "Source root may not be a symlink or reparse point.")
	}
	if !info.IsDir() {
		return domain.ResolvedSource{}, domain.NewError(domain.CodeSourceRefUnresolved, domain.SeverityHigh, "Source must be a directory.")
	}
	commit := ""
	if observeGit {
		commit = gitCommit(ctx, absolute)
	}
	return domain.ResolvedSource{
		Kind:         "local",
		Canonical:    filepath.Clean(absolute),
		LocalPath:    filepath.Clean(absolute),
		Commit:       commit,
		RetrievedVia: "local-read-only",
	}, nil
}

func (p *LocalProvider) Fetch(ctx context.Context, source domain.ResolvedSource) (domain.SourceSnapshot, error) {
	maxFiles := p.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	maxTotal := p.MaxTotalSize
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotalSize
	}
	maxFile := p.MaxFileSize
	if maxFile <= 0 {
		maxFile = DefaultMaxFileSize
	}

	root := filepath.Clean(source.LocalPath)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return domain.SourceSnapshot{}, domain.WrapError(
			domain.CodeSourceNotFound,
			domain.SeverityHigh,
			"Source root could not be opened.",
			err,
		)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || isReparsePoint(root) {
		return domain.SourceSnapshot{}, domain.NewError(
			domain.CodeSourceSymlinkEscape,
			domain.SeverityCritical,
			"Source root changed to a symlink or reparse point.",
		)
	}
	if !rootInfo.IsDir() {
		return domain.SourceSnapshot{}, domain.NewError(
			domain.CodeSourceRefUnresolved,
			domain.SeverityHigh,
			"Source root is not a directory.",
		)
	}
	var entries []domain.FileEntry
	var total int64
	portableNames := map[string]string{}

	err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		normalized := filepath.ToSlash(relative)
		if normalized == ".." || strings.HasPrefix(normalized, "../") || filepath.IsAbs(relative) {
			return domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityCritical, "Source path escaped the source root.")
		}
		if shouldSkip(normalized, entry.IsDir()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || isReparsePoint(current) {
			e := domain.NewError(domain.CodeSourceSymlinkEscape, domain.SeverityCritical, "Symlinks and reparse points are rejected in v0.1 source snapshots.")
			e.Details = map[string]any{"path": normalized}
			return e
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			e := domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityHigh, "Special files are not accepted in a source snapshot.")
			e.Details = map[string]any{"path": normalized}
			return e
		}
		if err := validatePortablePath(normalized); err != nil {
			return err
		}
		portable := strings.ToLower(normalized)
		if previous, exists := portableNames[portable]; exists && previous != normalized {
			e := domain.NewError(domain.CodeSourcePathTraversal, domain.SeverityHigh, "Source contains a case-folding filename collision.")
			e.Details = map[string]any{"first": previous, "second": normalized}
			return e
		}
		portableNames[portable] = normalized
		if len(entries)+1 > maxFiles {
			return domain.NewError(domain.CodeSourceTooManyFiles, domain.SeverityHigh, "Source exceeds the configured file-count limit.")
		}
		if info.Size() > maxFile {
			e := domain.NewError(domain.CodeSourceTooLarge, domain.SeverityHigh, "A source file exceeds the per-file size limit.")
			e.Details = map[string]any{"path": normalized, "size": info.Size(), "limit": maxFile}
			return e
		}
		total += info.Size()
		if total > maxTotal {
			return domain.NewError(domain.CodeSourceTooLarge, domain.SeverityHigh, "Source exceeds the configured total-size limit.")
		}
		digest, err := digestFile(current, maxFile)
		if err != nil {
			return err
		}
		entries = append(entries, domain.FileEntry{
			Path:   normalized,
			Mode:   normalizedFileMode(info.Mode()),
			Size:   info.Size(),
			Digest: digest,
		})
		return nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return domain.SourceSnapshot{}, domain.WrapError(domain.CodeCancelled, domain.SeverityWarning, "Source snapshot was cancelled.", err)
		}
		var typed *domain.Error
		if errors.As(err, &typed) {
			return domain.SourceSnapshot{}, typed
		}
		return domain.SourceSnapshot{}, domain.WrapError(domain.CodeSourceRefUnresolved, domain.SeverityHigh, "Source inventory failed.", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	treeDigest, err := canonicaljson.Digest(entries)
	if err != nil {
		return domain.SourceSnapshot{}, domain.WrapError(domain.CodeSourceDigestMismatch, domain.SeverityHigh, "Source tree digest could not be computed.", err)
	}
	identity := treeDigest
	if source.Commit != "" {
		identity = "git:" + source.Commit
	}
	return domain.SourceSnapshot{
		Identity:   identity,
		Commit:     source.Commit,
		TreeDigest: treeDigest,
		Root:       root,
		Inventory:  entries,
		TotalSize:  total,
		FileCount:  len(entries),
	}, nil
}

func normalizedFileMode(mode os.FileMode) string {
	if mode.Perm()&0o111 != 0 {
		return "0755"
	}
	return "0644"
}

func validatePortablePath(value string) error {
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") ||
			isWindowsReservedDeviceName(segment) {
			return nonPortablePath(value)
		}
		for _, character := range segment {
			if character < 0x20 || character > 0x7e ||
				strings.ContainsRune(`\:*?"<>|`, character) {
				return nonPortablePath(value)
			}
		}
	}
	return nil
}

func isWindowsReservedDeviceName(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return true
	}
	if len(base) != 4 {
		return false
	}
	prefix := base[:3]
	return (prefix == "COM" || prefix == "LPT") &&
		base[3] >= '1' && base[3] <= '9'
}

func nonPortablePath(value string) error {
	err := domain.NewError(
		domain.CodeSourcePathTraversal,
		domain.SeverityHigh,
		"Source contains a path that is not portable in the v0.1 snapshot profile.",
	)
	err.Details = map[string]any{"path": value}
	err.Suggestion = "Use printable ASCII path segments without Windows-reserved characters or trailing dots/spaces."
	return err
}

func shouldSkip(normalized string, isDirectory bool) bool {
	parts := strings.Split(normalized, "/")
	first := parts[0]
	if strings.EqualFold(first, ".git") {
		return true
	}
	if strings.EqualFold(first, ".repopass") {
		switch {
		case len(parts) == 1:
			// Traverse the controller-state root only to reach the explicitly
			// portable schema subtree. A regular file named .repopass remains
			// internal state and is excluded.
			return !isDirectory
		case !strings.EqualFold(parts[1], "schemas"):
			return true
		case len(parts) == 2:
			// The schemas entry must be a directory. Schema files live below
			// it and become part of the immutable source tree identity.
			return !isDirectory
		default:
			return false
		}
	}
	return strings.EqualFold(normalized, "passport.lock.json")
}

func digestFile(path string, maxBytes int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxBytes {
		return "", domain.NewError(domain.CodeSourceTooLarge, domain.SeverityHigh, "Source file changed or exceeded its limit during hashing.")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func gitCommit(ctx context.Context, root string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	command := exec.CommandContext(ctx, "git", "-c", "credential.helper=", "-c", "core.hooksPath=", "rev-parse", "--verify", "HEAD")
	command.Dir = root
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return ""
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return ""
	}
	scanner := bufio.NewScanner(io.LimitReader(stdout, 128))
	var result string
	if scanner.Scan() {
		candidate := strings.TrimSpace(scanner.Text())
		if len(candidate) == 40 && isLowerHex(candidate) {
			result = candidate
		}
	}
	if err := command.Wait(); err != nil {
		return ""
	}
	return result
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
