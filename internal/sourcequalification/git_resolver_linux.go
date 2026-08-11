//go:build linux

package sourcequalification

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var linuxTrustedGitCandidates = [...]string{"/usr/bin/git"}

type linuxTrustedGitSnapshot struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
}

func linuxTrustedGitCandidatePaths() []string {
	return append([]string(nil), linuxTrustedGitCandidates[:]...)
}

func resolveTrustedGitExecutablePlatform(repositoryRoot string) (string, error) {
	for _, candidate := range linuxTrustedGitCandidates {
		resolved, err := validateLinuxTrustedGitCandidate(repositoryRoot, candidate)
		if err == nil {
			return resolved, nil
		}
	}
	return "", errors.New("fixed machine Git application is unavailable")
}

func validateLinuxTrustedGitCandidate(repositoryRoot, candidate string) (string, error) {
	if candidate != linuxTrustedGitCandidates[0] || !filepath.IsAbs(candidate) ||
		filepath.Clean(candidate) != candidate || pathWithinRepository(repositoryRoot, candidate) {
		return "", errors.New("Linux Git candidate is not a fixed machine path")
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || resolved != candidate {
		return "", errors.New("Linux Git candidate traverses a link")
	}

	components := strings.Split(strings.TrimPrefix(candidate, "/"), "/")
	paths := []string{"/"}
	current := "/"
	for _, component := range components {
		if component == "" {
			return "", errors.New("Linux Git candidate path is invalid")
		}
		current = filepath.Join(current, component)
		paths = append(paths, current)
	}
	for index, current := range paths {
		descriptor, err := unix.Open(current, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return "", errors.New("Linux Git candidate could not be opened safely")
		}
		var opened unix.Stat_t
		openErr := unix.Fstat(descriptor, &opened)
		if openErr != nil || !validLinuxTrustedGitMetadata(&opened, index == len(paths)-1) {
			_ = unix.Close(descriptor)
			return "", errors.New("Linux Git candidate metadata is not machine protected")
		}
		openedSnapshot := linuxTrustedGitSnapshot{
			device: uint64(opened.Dev),
			inode:  opened.Ino,
			mode:   opened.Mode,
			uid:    opened.Uid,
		}
		var currentPath unix.Stat_t
		pathErr := unix.Fstatat(unix.AT_FDCWD, current, &currentPath, unix.AT_SYMLINK_NOFOLLOW)
		closeErr := unix.Close(descriptor)
		if pathErr != nil || closeErr != nil || openedSnapshot != (linuxTrustedGitSnapshot{
			device: uint64(currentPath.Dev),
			inode:  currentPath.Ino,
			mode:   currentPath.Mode,
			uid:    currentPath.Uid,
		}) {
			return "", errors.New("Linux Git candidate identity changed during validation")
		}
	}
	return candidate, nil
}

func validLinuxTrustedGitMetadata(metadata *unix.Stat_t, executable bool) bool {
	if metadata == nil || metadata.Uid != 0 || metadata.Mode&0o022 != 0 {
		return false
	}
	kind := metadata.Mode & unix.S_IFMT
	if executable {
		return kind == unix.S_IFREG && metadata.Mode&0o111 != 0
	}
	return kind == unix.S_IFDIR
}
