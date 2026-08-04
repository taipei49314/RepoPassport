package spdx

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ReadFile performs the frozen bounded no-link, same-handle double-read.
// Every returned error is fixed and deliberately contains no caller path.
func ReadFile(path string) ([]byte, error) {
	return readFileWithProfile(path, nil, false)
}

func readFileWithHook(path string, afterFirstRead func()) ([]byte, error) {
	return readFileWithProfile(path, afterFirstRead, false)
}

// ReadDerivedFile adds an exclusive-link-count requirement to the legacy
// stable reader without changing the caller-supplied SPDX path's semantics.
func ReadDerivedFile(path string) ([]byte, error) {
	return readFileWithProfile(path, nil, true)
}

func readFileWithProfile(path string, afterFirstRead func(), exclusive bool) ([]byte, error) {
	if path == "" || !safeNativePath(path) {
		return nil, invalid("file")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || requireUnlinkedParents(filepath.Dir(absolute)) != nil {
		return nil, invalid("file")
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		isReparsePoint(absolute) || before.Size() < 0 || before.Size() > MaxBytes {
		return nil, invalid("file")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !samePath(absolute, resolved) {
		return nil, invalid("file")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, invalid("file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) ||
		opened.Size() > MaxBytes || validateOpenedHandle(file, absolute) != nil ||
		(exclusive && validateExclusiveLink(file) != nil) {
		return nil, invalid("file")
	}
	first, err := boundedRead(file)
	if err != nil {
		return nil, invalid("file")
	}
	defer func() {
		if first != nil {
			clear(first)
		}
	}()
	firstInfo, err := file.Stat()
	if err != nil || !stableFileInfo(opened, firstInfo) {
		return nil, invalid("file-changed")
	}
	if afterFirstRead != nil {
		afterFirstRead()
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, invalid("file-changed")
	}
	second, err := boundedRead(file)
	if err != nil {
		return nil, invalid("file-changed")
	}
	defer clear(second)
	finalHandle, handleErr := file.Stat()
	finalPath, pathErr := os.Lstat(absolute)
	finalResolved, resolveErr := filepath.EvalSymlinks(absolute)
	if handleErr != nil || pathErr != nil || resolveErr != nil ||
		requireUnlinkedParents(filepath.Dir(absolute)) != nil || isReparsePoint(absolute) ||
		!samePath(absolute, finalResolved) || !stableFileInfo(opened, finalHandle) ||
		!stableFileInfo(before, finalPath) || !os.SameFile(finalHandle, finalPath) ||
		validateOpenedHandle(file, absolute) != nil ||
		(exclusive && validateExclusiveLink(file) != nil) || !bytes.Equal(first, second) {
		return nil, invalid("file-changed")
	}
	result := append([]byte(nil), first...)
	clear(first)
	first = nil
	return result, nil
}

func boundedRead(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxBytes {
		clear(raw)
		return nil, os.ErrInvalid
	}
	return raw, nil
}

func stableFileInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Mode() == right.Mode() && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}

func requireUnlinkedParents(directory string) error {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	root := volume + string(filepath.Separator)
	if volume == "" {
		root = string(filepath.Separator)
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil || filepath.IsAbs(relative) || strings.HasPrefix(relative, "..") {
		return os.ErrInvalid
	}
	current := root
	if relative != "." {
		for _, segment := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, segment)
			info, statErr := os.Lstat(current)
			if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(current) {
				return os.ErrInvalid
			}
		}
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !samePath(absolute, resolved) {
		return os.ErrInvalid
	}
	return nil
}

func samePath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func safeNativePath(value string) bool {
	if strings.IndexByte(value, 0) >= 0 {
		return false
	}
	if runtime.GOOS != "windows" {
		return true
	}
	normalized := strings.ReplaceAll(value, "/", `\`)
	if strings.HasPrefix(normalized, `\\?\`) || strings.HasPrefix(normalized, `\\.\`) {
		return false
	}
	volume := filepath.VolumeName(value)
	if strings.HasPrefix(strings.ReplaceAll(volume, "/", `\`), `\\`) {
		return false
	}
	remainder := strings.TrimPrefix(value, volume)
	if strings.Contains(remainder, ":") {
		return false
	}
	for _, segment := range strings.Split(normalized, `\`) {
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return false
		}
	}
	return true
}
