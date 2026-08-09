package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/controllerfs"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

type preparedPaths struct {
	runDir       string
	snapshotDir  string
	workspaceDir string
	outputsDir   string
}

func (r *Runner) prepareFilesystem(
	ctx context.Context,
	sourceRoot string,
	runRoot string,
	runID string,
	expectedTreeDigest string,
) (preparedPaths, error) {
	sourceAbsolute, err := resolveExistingDirectory(sourceRoot)
	if err != nil {
		return preparedPaths{}, structuredPathError(
			domain.CodeSourceNotFound,
			"Source root is not an accessible directory.",
			err,
		)
	}
	if isFilesystemRoot(sourceAbsolute) {
		return preparedPaths{}, domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Filesystem roots cannot be used as a source snapshot.",
		)
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && samePath(sourceAbsolute, home) {
		return preparedPaths{}, domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"The host home directory cannot be used as a source snapshot.",
		)
	}
	provider := &acquisition.LocalProvider{
		MaxFiles:     r.config.MaxSourceFiles,
		MaxTotalSize: r.config.MaxSourceBytes,
		MaxFileSize:  r.config.MaxSourceBytes,
	}
	inventory, err := provider.Fetch(ctx, domain.ResolvedSource{
		Kind:      "local",
		LocalPath: sourceAbsolute,
	})
	if err != nil {
		return preparedPaths{}, err
	}
	if inventory.TreeDigest != expectedTreeDigest {
		digestErr := domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityCritical,
			"Live source inventory does not match the resolved plan tree digest.",
		)
		digestErr.Details = map[string]any{
			"expected": expectedTreeDigest,
			"actual":   inventory.TreeDigest,
		}
		return preparedPaths{}, digestErr
	}

	if strings.TrimSpace(runRoot) == "" {
		return preparedPaths{}, domain.NewError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityHigh,
			"Run artifact root is required.",
		)
	}
	runRootAbsolute, err := filepath.Abs(runRoot)
	if err != nil {
		return preparedPaths{}, structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Run artifact root could not be resolved.",
			err,
		)
	}
	if err := os.MkdirAll(runRootAbsolute, 0o700); err != nil {
		return preparedPaths{}, structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Run artifact root could not be created.",
			err,
		)
	}
	runRootAbsolute, err = resolveExistingDirectory(runRootAbsolute)
	if err != nil {
		return preparedPaths{}, structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Run artifact root could not be resolved.",
			err,
		)
	}
	if pathsOverlap(sourceAbsolute, runRootAbsolute) {
		return preparedPaths{}, domain.NewError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityHigh,
			"Source root and run artifact root must not contain one another.",
		)
	}

	runDir := filepath.Join(runRootAbsolute, "run-"+runID)
	if !pathWithin(runRootAbsolute, runDir) {
		return preparedPaths{}, domain.NewError(
			domain.CodeSandboxPrepareFailed,
			domain.SeverityCritical,
			"Generated run directory escaped the artifact root.",
		)
	}
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return preparedPaths{}, structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Run directory could not be created.",
			err,
		)
	}

	paths := preparedPaths{
		runDir:       runDir,
		snapshotDir:  filepath.Join(runDir, "source-snapshot"),
		workspaceDir: filepath.Join(runDir, "workspace"),
		outputsDir:   filepath.Join(runDir, "outputs"),
	}
	cleanupOnError := func(copyErr error) (preparedPaths, error) {
		cleanupErr := controllerfs.RemoveTree(runDir)
		return preparedPaths{}, errors.Join(copyErr, cleanupErr)
	}

	if err := copyInventory(
		ctx,
		sourceAbsolute,
		paths.snapshotDir,
		inventory.Inventory,
		false,
	); err != nil {
		return cleanupOnError(err)
	}
	if err := verifyCopiedInventory(ctx, provider, paths.snapshotDir, inventory); err != nil {
		return cleanupOnError(err)
	}
	if err := copyInventory(
		ctx,
		paths.snapshotDir,
		paths.workspaceDir,
		inventory.Inventory,
		false,
	); err != nil {
		return cleanupOnError(err)
	}
	if err := verifyCopiedInventory(ctx, provider, paths.workspaceDir, inventory); err != nil {
		return cleanupOnError(err)
	}
	if err := os.Mkdir(paths.outputsDir, 0o700); err != nil {
		return cleanupOnError(structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Output directory could not be created.",
			err,
		))
	}
	if err := os.Chmod(paths.outputsDir, 0o700); err != nil {
		return cleanupOnError(structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Output directory permissions could not be prepared.",
			err,
		))
	}

	for _, path := range []string{
		paths.snapshotDir,
		paths.workspaceDir,
		paths.outputsDir,
	} {
		if unsafeMountSourcePath(path) {
			return cleanupOnError(domain.NewError(
				domain.CodeSandboxPrepareFailed,
				domain.SeverityHigh,
				"Container mount source paths cannot contain comma or control characters.",
			))
		}
	}
	return paths, nil
}

func cleanupPreparedCopies(prepared *PreparedRun) error {
	if prepared == nil {
		return nil
	}
	runDir, err := filepath.Abs(prepared.RunDir)
	if err != nil || isFilesystemRoot(runDir) {
		return errors.New("prepared run directory is not safe to clean")
	}
	snapshotDir, snapshotErr := filepath.Abs(prepared.SourceSnapshotDir)
	workspaceDir, workspaceErr := filepath.Abs(prepared.WorkspaceDir)
	if snapshotErr != nil || workspaceErr != nil {
		return errors.Join(snapshotErr, workspaceErr)
	}

	// Only remove copies created at the exact locations used by Prepare.
	// Synthetic PreparedRun values used by lower-level tests are left alone.
	if !samePath(snapshotDir, filepath.Join(runDir, "source-snapshot")) ||
		!samePath(workspaceDir, filepath.Join(runDir, "workspace")) {
		return nil
	}
	return errors.Join(
		controllerfs.RemoveTree(snapshotDir),
		controllerfs.RemoveTree(workspaceDir),
	)
}

func copyInventory(
	ctx context.Context,
	sourceRoot string,
	destinationRoot string,
	inventory []domain.FileEntry,
	writable bool,
) error {
	if err := os.Mkdir(destinationRoot, 0o700); err != nil {
		return structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Destination snapshot root could not be created.",
			err,
		)
	}
	for _, entry := range inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative := filepath.FromSlash(entry.Path)
		sourcePath := filepath.Join(sourceRoot, relative)
		destinationPath := filepath.Join(destinationRoot, relative)
		if !pathWithin(sourceRoot, sourcePath) || !pathWithin(destinationRoot, destinationPath) {
			return domain.NewError(
				domain.CodeSourcePathTraversal,
				domain.SeverityCritical,
				"Inventory entry escaped its source or destination root.",
			)
		}
		resolvedSource, err := filepath.EvalSymlinks(sourcePath)
		if err != nil || !samePath(sourcePath, resolvedSource) ||
			!pathWithin(sourceRoot, resolvedSource) {
			return domain.WrapError(
				domain.CodeSourceSymlinkEscape,
				domain.SeverityCritical,
				"Inventory entry resolves through a symbolic link or reparse point.",
				err,
			)
		}
		info, err := os.Lstat(resolvedSource)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() ||
			info.Size() != entry.Size ||
			normalizedExecutionMode(info.Mode()) != entry.Mode {
			return domain.NewError(
				domain.CodeSourceDigestMismatch,
				domain.SeverityCritical,
				"Inventory metadata changed before the execution snapshot was copied.",
			)
		}
		parentMode := fs.FileMode(0o755)
		if writable {
			parentMode = 0o777
		}
		if err := os.MkdirAll(filepath.Dir(destinationPath), parentMode); err != nil {
			return err
		}
		if err := copyRegularFile(resolvedSource, destinationPath, info, entry.Digest); err != nil {
			return err
		}
		mode := fs.FileMode(0o444)
		if writable {
			mode = 0o666
		}
		if entry.Mode == "0755" {
			mode |= 0o111
		}
		if err := os.Chmod(destinationPath, mode); err != nil {
			return err
		}
	}

	rootMode := fs.FileMode(0o555)
	if writable {
		rootMode = 0o777
	}
	if err := filepath.WalkDir(destinationRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, rootMode)
		}
		return nil
	}); err != nil {
		return structuredPathError(
			domain.CodeSandboxPrepareFailed,
			"Snapshot directory permissions could not be finalized.",
			err,
		)
	}
	return nil
}

func copyRegularFile(
	sourcePath string,
	destinationPath string,
	expected fs.FileInfo,
	expectedDigest string,
) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	openedInfo, err := source.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() ||
		openedInfo.Size() != expected.Size() ||
		openedInfo.Mode() != expected.Mode() ||
		!openedInfo.ModTime().Equal(expected.ModTime()) {
		return domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"Source entry changed while the execution snapshot was being prepared.",
		)
	}

	destination, err := os.OpenFile(
		destinationPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return err
	}
	hash := sha256.New()
	copied, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if copied != expected.Size() {
		return domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"Source entry changed while it was copied.",
		)
	}
	actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actualDigest != expectedDigest {
		return domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityCritical,
			"Copied source bytes do not match the resolved inventory digest.",
		)
	}
	finalInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if !finalInfo.Mode().IsRegular() ||
		finalInfo.Size() != expected.Size() ||
		finalInfo.Mode() != expected.Mode() ||
		!finalInfo.ModTime().Equal(expected.ModTime()) {
		return domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"Source entry changed while the execution snapshot was being prepared.",
		)
	}
	return nil
}

func verifyCopiedInventory(
	ctx context.Context,
	provider *acquisition.LocalProvider,
	root string,
	expected domain.SourceSnapshot,
) error {
	actual, err := provider.Fetch(ctx, domain.ResolvedSource{
		Kind:      "local",
		LocalPath: root,
	})
	if err != nil {
		return err
	}
	if actual.TreeDigest != expected.TreeDigest ||
		len(actual.Inventory) != len(expected.Inventory) {
		return domain.NewError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityCritical,
			"Copied snapshot inventory does not match the resolved source tree.",
		)
	}
	for index := range expected.Inventory {
		if actual.Inventory[index] != expected.Inventory[index] {
			return domain.NewError(
				domain.CodeSourceDigestMismatch,
				domain.SeverityCritical,
				"Copied snapshot contains changed, missing, or extra entries.",
			)
		}
	}
	return nil
}

func normalizedExecutionMode(mode fs.FileMode) string {
	if mode.Perm()&0o111 != 0 {
		return "0755"
	}
	return "0644"
}

func unsafeMountSourcePath(value string) bool {
	if strings.Contains(value, ",") {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func resolveExistingDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(parent, candidate string) bool {
	parent = filepath.Clean(parent)
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(parent, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func samePath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(first, second)
	}
	return first == second
}

func isFilesystemRoot(path string) bool {
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	return samePath(path, root)
}

func structuredPathError(code domain.ErrorCode, message string, cause error) error {
	return domain.WrapError(code, domain.SeverityHigh, message, cause)
}
