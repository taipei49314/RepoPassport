package execution

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/repopass/repopass/internal/domain"
)

const archiveHeaderAllowancePerEntry int64 = 4096

var errArchiveByteLimit = errors.New(
	"sandbox output archive exceeded its hard byte limit",
)

type outputExportSummary struct {
	FileCount  int
	TotalBytes int64
}

type archiveCommandResult struct {
	exitCode int
	err      error
}

func (r *Runner) exportOutputs(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
) (outputExportSummary, *domain.Error) {
	stagingDir := filepath.Join(prepared.RunDir, ".outputs-export")
	if !pathWithin(prepared.RunDir, stagingDir) {
		return outputExportSummary{}, outputExportError(
			domain.CodeForbiddenFilesystemAccess,
			"Controller output staging path escaped the private run directory.",
			nil,
			prepared,
			containerName,
		)
	}
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		return outputExportSummary{}, outputExportError(
			domain.CodeCleanupFailed,
			"Controller output staging directory could not be created.",
			err,
			prepared,
			containerName,
		)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	archiveLimit, limitErr := outputArchiveByteLimit(
		prepared.executionPlan.Resources.DiskBytes,
		r.config.MaxSourceFiles,
	)
	if limitErr != nil {
		return outputExportSummary{}, outputExportError(
			domain.CodeResourceLimitExceeded,
			"Resolved output limits cannot produce a safe archive byte ceiling.",
			limitErr,
			prepared,
			containerName,
		)
	}

	archiveReader, archiveWriter := io.Pipe()
	commandResult := make(chan archiveCommandResult, 1)
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	go func() {
		exitCode, runErr := r.executor.Run(
			ctx,
			prepared.Backend,
			[]string{
				"exec",
				"--user", "0:0",
				"--workdir", containerOutputs,
				containerName,
				"/bin/tar",
				"--format=ustar",
				"--blocking-factor=1",
				"--exclude=./.home",
				"--exclude=./.tmp",
				"-C", containerOutputs,
				"-cf", "-",
				".",
			},
			archiveWriter,
			stderr,
		)
		_ = archiveWriter.CloseWithError(runErr)
		commandResult <- archiveCommandResult{
			exitCode: exitCode,
			err:      runErr,
		}
	}()

	summary, extractErr := r.extractOutputArchive(
		archiveReader,
		stagingDir,
		prepared.executionPlan.Resources.DiskBytes,
		archiveLimit,
	)
	if extractErr != nil {
		_ = archiveReader.CloseWithError(extractErr)
	} else {
		_ = archiveReader.Close()
	}
	result := <-commandResult
	if extractErr != nil {
		extractErr.Phase = domain.PhaseCleanup
		extractErr.Details = mergeOutputDetails(
			extractErr.Details,
			map[string]any{
				"backend":           prepared.Backend,
				"containerName":     containerName,
				"limitBytes":        prepared.executionPlan.Resources.DiskBytes,
				"archiveLimitBytes": archiveLimit,
			},
		)
		return outputExportSummary{}, extractErr
	}
	if result.err != nil || result.exitCode != 0 {
		err := outputExportError(
			domain.CodeCleanupFailed,
			"Trusted sandbox tar export helper did not complete successfully.",
			result.err,
			prepared,
			containerName,
		)
		err.Details["exitCode"] = result.exitCode
		return outputExportSummary{}, err
	}

	validationSummary, validationErr := r.validateExportedOutputs(
		stagingDir,
		prepared.executionPlan.Resources.DiskBytes,
	)
	if validationErr != nil {
		validationErr.Phase = domain.PhaseCleanup
		validationErr.Details = mergeOutputDetails(
			validationErr.Details,
			map[string]any{
				"backend":       prepared.Backend,
				"containerName": containerName,
				"limitBytes":    prepared.executionPlan.Resources.DiskBytes,
			},
		)
		return outputExportSummary{}, validationErr
	}
	if validationSummary != summary {
		return outputExportSummary{}, outputExportError(
			domain.CodeCleanupFailed,
			"Post-extraction output inventory did not match the trusted stream inventory.",
			nil,
			prepared,
			containerName,
		)
	}

	outputInfo, statErr := os.Lstat(prepared.OutputsDir)
	if statErr != nil || !outputInfo.IsDir() ||
		outputInfo.Mode()&fs.ModeSymlink != 0 {
		return outputExportSummary{}, outputExportError(
			domain.CodeForbiddenFilesystemAccess,
			"Controller-owned output destination changed before export commit.",
			statErr,
			prepared,
			containerName,
		)
	}
	if err := os.Remove(prepared.OutputsDir); err != nil {
		return outputExportSummary{}, outputExportError(
			domain.CodeCleanupFailed,
			"Controller-owned output destination was not empty at export commit.",
			err,
			prepared,
			containerName,
		)
	}
	if err := os.Rename(stagingDir, prepared.OutputsDir); err != nil {
		_ = os.Mkdir(prepared.OutputsDir, 0o700)
		return outputExportSummary{}, outputExportError(
			domain.CodeCleanupFailed,
			"Validated sandbox outputs could not be committed atomically.",
			err,
			prepared,
			containerName,
		)
	}
	committed = true
	return summary, nil
}

func (r *Runner) extractOutputArchive(
	raw io.Reader,
	root string,
	diskLimit int64,
	archiveLimit int64,
) (outputExportSummary, *domain.Error) {
	limited := &archiveLimitReader{
		reader:    raw,
		remaining: archiveLimit,
	}
	archive := tar.NewReader(limited)
	summary := outputExportSummary{}
	seen := make(map[string]string)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			if drainErr := drainZeroArchivePadding(limited); drainErr != nil {
				code := domain.CodeCleanupFailed
				message := "Sandbox output tar stream has invalid trailing data."
				if errors.Is(drainErr, errArchiveByteLimit) {
					code = domain.CodeResourceLimitExceeded
					message = "Sandbox output tar stream exceeded its hard archive byte limit."
				}
				return outputExportSummary{}, domain.WrapError(
					code,
					domain.SeverityCritical,
					message,
					drainErr,
				)
			}
			return summary, nil
		}
		if err != nil {
			code := domain.CodeCleanupFailed
			message := "Sandbox output tar stream was truncated or invalid."
			if errors.Is(err, errArchiveByteLimit) {
				code = domain.CodeResourceLimitExceeded
				message = "Sandbox output tar stream exceeded its hard archive byte limit."
			}
			return outputExportSummary{}, domain.WrapError(
				code,
				domain.SeverityCritical,
				message,
				err,
			)
		}
		if header.Format != tar.FormatUSTAR ||
			len(header.PAXRecords) > 0 ||
			len(header.Xattrs) > 0 {
			return outputExportSummary{}, unsafeArchiveError(
				"Only plain USTAR metadata is accepted for sandbox outputs.",
			)
		}
		relative, pathErr := portableArchiveHeaderPath(
			header.Name,
			header.Typeflag,
		)
		if pathErr != nil {
			return outputExportSummary{}, unsafeArchiveError(
				"Sandbox output archive contains a non-portable or unsafe path.",
			)
		}
		if relative == "" {
			if header.Typeflag != tar.TypeDir {
				return outputExportSummary{}, unsafeArchiveError(
					"Sandbox output archive root is not a directory.",
				)
			}
			continue
		}
		collisionKey := strings.ToLower(relative)
		if previous, exists := seen[collisionKey]; exists {
			message := "Sandbox output archive contains duplicate paths."
			if previous != relative {
				message = "Sandbox output archive contains a portable case-fold path collision."
			}
			return outputExportSummary{}, unsafeArchiveError(message)
		}
		seen[collisionKey] = relative
		summary.FileCount++
		if summary.FileCount > r.config.MaxSourceFiles {
			return outputExportSummary{}, domain.NewError(
				domain.CodeResourceLimitExceeded,
				domain.SeverityCritical,
				"Sandbox outputs contain too many filesystem entries.",
			)
		}

		destination := filepath.Join(root, filepath.FromSlash(relative))
		if !pathWithin(root, destination) {
			return outputExportSummary{}, unsafeArchiveError(
				"Sandbox output archive entry escaped controller staging.",
			)
		}
		if header.Linkname != "" {
			return outputExportSummary{}, unsafeArchiveError(
				"Links are forbidden in sandbox outputs.",
			)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return outputExportSummary{}, unsafeArchiveError(
					"Sandbox output directory has an invalid tar size.",
				)
			}
			if err := os.Mkdir(destination, 0o700); err != nil {
				return outputExportSummary{}, domain.WrapError(
					domain.CodeCleanupFailed,
					domain.SeverityHigh,
					"Sandbox output directory could not be materialized safely.",
					err,
				)
			}
			if err := os.Chmod(destination, 0o755); err != nil {
				return outputExportSummary{}, domain.WrapError(
					domain.CodeCleanupFailed,
					domain.SeverityHigh,
					"Sandbox output directory mode could not be finalized.",
					err,
				)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 ||
				summary.TotalBytes > math.MaxInt64-header.Size ||
				header.Size > diskLimit-summary.TotalBytes {
				return outputExportSummary{}, domain.NewError(
					domain.CodeResourceLimitExceeded,
					domain.SeverityCritical,
					"Sandbox output files exceed the resolved disk byte limit.",
				)
			}
			output, openErr := os.OpenFile(
				destination,
				os.O_CREATE|os.O_EXCL|os.O_WRONLY,
				0o600,
			)
			if openErr != nil {
				return outputExportSummary{}, domain.WrapError(
					domain.CodeCleanupFailed,
					domain.SeverityHigh,
					"Sandbox output file could not be materialized safely.",
					openErr,
				)
			}
			copied, copyErr := io.CopyN(output, archive, header.Size)
			closeErr := output.Close()
			if copyErr != nil || copied != header.Size || closeErr != nil {
				return outputExportSummary{}, domain.WrapError(
					domain.CodeCleanupFailed,
					domain.SeverityHigh,
					"Sandbox output file content was truncated during extraction.",
					errors.Join(copyErr, closeErr),
				)
			}
			mode := fs.FileMode(0o644)
			if header.FileInfo().Mode()&0o111 != 0 {
				mode = 0o755
			}
			if err := os.Chmod(destination, mode); err != nil {
				return outputExportSummary{}, domain.WrapError(
					domain.CodeCleanupFailed,
					domain.SeverityHigh,
					"Sandbox output file mode could not be finalized.",
					err,
				)
			}
			summary.TotalBytes += header.Size
		default:
			return outputExportSummary{}, unsafeArchiveError(
				"Links and special filesystem entries are forbidden in sandbox outputs.",
			)
		}
	}
}

func portableArchiveHeaderPath(value string, typeflag byte) (string, error) {
	if typeflag == tar.TypeDir {
		if strings.HasSuffix(value, "/") {
			value = strings.TrimSuffix(value, "/")
			if strings.HasSuffix(value, "/") {
				return "", errors.New("archive directory has repeated trailing separators")
			}
		}
	} else if strings.HasSuffix(value, "/") {
		return "", errors.New("non-directory archive entry has a trailing separator")
	}
	return portableArchivePath(value)
}

func portableArchivePath(value string) (string, error) {
	if value == "." || value == "./" {
		return "", nil
	}
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	if value == "" ||
		len(value) > 4096 ||
		path.IsAbs(value) ||
		path.Clean(value) != value ||
		strings.Contains(value, "\\") {
		return "", errors.New("archive path is not normalized")
	}
	segments := strings.Split(value, "/")
	for index, segment := range segments {
		if segment == "" ||
			segment == "." ||
			segment == ".." ||
			len(segment) > 255 ||
			strings.HasSuffix(segment, ".") ||
			strings.HasSuffix(segment, " ") {
			return "", errors.New("archive path segment is invalid")
		}
		if index == 0 && (segment == ".home" || segment == ".tmp") {
			return "", errors.New(
				"runner-managed disposable output path is excluded from export",
			)
		}
		for _, character := range segment {
			if character < 0x20 || character > 0x7e ||
				strings.ContainsRune(`\:*?"<>|`, character) {
				return "", errors.New("archive path contains a non-portable character")
			}
		}
		base := segment
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		switch strings.ToUpper(base) {
		case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$",
			"COM1", "COM2", "COM3", "COM4", "COM5",
			"COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
			"LPT6", "LPT7", "LPT8", "LPT9":
			return "", errors.New("archive path uses a reserved device name")
		}
	}
	return value, nil
}

func drainZeroArchivePadding(reader io.Reader) error {
	buffer := make([]byte, 32<<10)
	for {
		count, err := reader.Read(buffer)
		for _, value := range buffer[:count] {
			if value != 0 {
				return errors.New("archive trailing data is not zero padding")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
}

func outputArchiveByteLimit(
	diskLimit int64,
	maxEntries int,
) (int64, error) {
	if diskLimit <= 0 || maxEntries <= 0 {
		return 0, errors.New("archive limits must be positive")
	}
	if int64(maxEntries) >
		(math.MaxInt64-(1<<20))/archiveHeaderAllowancePerEntry {
		return 0, errors.New("archive entry overhead overflow")
	}
	overhead := int64(maxEntries)*archiveHeaderAllowancePerEntry + (1 << 20)
	if diskLimit > math.MaxInt64-overhead {
		return 0, errors.New("archive byte limit overflow")
	}
	return diskLimit + overhead, nil
}

type archiveLimitReader struct {
	reader    io.Reader
	remaining int64
}

func (r *archiveLimitReader) Read(buffer []byte) (int, error) {
	if r.remaining > 0 {
		if int64(len(buffer)) > r.remaining {
			buffer = buffer[:r.remaining]
		}
		count, err := r.reader.Read(buffer)
		r.remaining -= int64(count)
		return count, err
	}
	var probe [1]byte
	count, err := r.reader.Read(probe[:])
	if count > 0 {
		return 0, errArchiveByteLimit
	}
	return 0, err
}

func (r *Runner) validateExportedOutputs(
	root string,
	limitBytes int64,
) (outputExportSummary, *domain.Error) {
	if limitBytes <= 0 {
		return outputExportSummary{}, domain.NewError(
			domain.CodeResourceLimitExceeded,
			domain.SeverityHigh,
			"Resolved output byte limit is not positive.",
		)
	}
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return outputExportSummary{}, domain.WrapError(
			domain.CodeForbiddenFilesystemAccess,
			domain.SeverityCritical,
			"Exported output root could not be resolved.",
			err,
		)
	}

	summary := outputExportSummary{}
	portableNames := make(map[string]string)
	walkErr := filepath.WalkDir(rootAbsolute, func(
		current string,
		entry fs.DirEntry,
		entryErr error,
	) error {
		if entryErr != nil {
			return entryErr
		}
		if !pathWithin(rootAbsolute, current) {
			return outputValidationFailure{
				code:    domain.CodeForbiddenFilesystemAccess,
				message: "Exported output entry escaped controller staging.",
			}
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if current == rootAbsolute {
			if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
				return outputValidationFailure{
					code:    domain.CodeForbiddenFilesystemAccess,
					message: "Exported output root is not a plain directory.",
				}
			}
			return nil
		}

		relative, relativeErr := filepath.Rel(rootAbsolute, current)
		if relativeErr != nil {
			return relativeErr
		}
		portable := filepath.ToSlash(relative)
		if _, portableErr := portableArchivePath(portable); portableErr != nil {
			return outputValidationFailure{
				code:    domain.CodeForbiddenFilesystemAccess,
				message: "Exported output entry has a non-portable path.",
			}
		}
		key := strings.ToLower(portable)
		if previous, exists := portableNames[key]; exists && previous != portable {
			return outputValidationFailure{
				code:    domain.CodeForbiddenFilesystemAccess,
				message: "Exported outputs contain a portable case-fold collision.",
			}
		}
		portableNames[key] = portable
		summary.FileCount++
		if summary.FileCount > r.config.MaxSourceFiles {
			return outputValidationFailure{
				code:    domain.CodeResourceLimitExceeded,
				message: "Exported outputs contain too many filesystem entries.",
			}
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return outputValidationFailure{
				code:    domain.CodeForbiddenFilesystemAccess,
				message: "Symbolic links are forbidden in exported outputs.",
			}
		case info.IsDir():
			return nil
		case info.Mode().IsRegular():
			if info.Size() < 0 ||
				summary.TotalBytes > math.MaxInt64-info.Size() ||
				info.Size() > limitBytes-summary.TotalBytes {
				return outputValidationFailure{
					code:    domain.CodeResourceLimitExceeded,
					message: "Exported outputs exceed the resolved disk byte limit.",
				}
			}
			summary.TotalBytes += info.Size()
			return nil
		default:
			return outputValidationFailure{
				code:    domain.CodeForbiddenFilesystemAccess,
				message: "Special filesystem entries are forbidden in exported outputs.",
			}
		}
	})
	if walkErr == nil {
		return summary, nil
	}
	var validationFailure outputValidationFailure
	if errors.As(walkErr, &validationFailure) {
		err := domain.NewError(
			validationFailure.code,
			domain.SeverityCritical,
			validationFailure.message,
		)
		err.Details = map[string]any{
			"fileCount":  summary.FileCount,
			"totalBytes": summary.TotalBytes,
		}
		return outputExportSummary{}, err
	}
	return outputExportSummary{}, domain.WrapError(
		domain.CodeCleanupFailed,
		domain.SeverityHigh,
		"Exported outputs could not be inspected safely.",
		walkErr,
	)
}

type outputValidationFailure struct {
	code    domain.ErrorCode
	message string
}

func (e outputValidationFailure) Error() string {
	return e.message
}

func unsafeArchiveError(message string) *domain.Error {
	return domain.NewError(
		domain.CodeForbiddenFilesystemAccess,
		domain.SeverityCritical,
		message,
	)
}

func outputExportError(
	code domain.ErrorCode,
	message string,
	cause error,
	prepared *PreparedRun,
	containerName string,
) *domain.Error {
	err := domain.WrapError(code, domain.SeverityHigh, message, cause)
	err.Phase = domain.PhaseCleanup
	err.Details = map[string]any{
		"backend":       prepared.Backend,
		"containerName": containerName,
	}
	return err
}

func mergeOutputDetails(
	current map[string]any,
	additions map[string]any,
) map[string]any {
	result := make(map[string]any, len(current)+len(additions))
	for key, value := range current {
		result[key] = value
	}
	for key, value := range additions {
		result[key] = value
	}
	return result
}
