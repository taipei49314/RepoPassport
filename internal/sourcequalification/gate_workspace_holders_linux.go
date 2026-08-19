//go:build linux

package sourcequalification

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const unixWorkspaceHolderReapTimeout = 5 * time.Second

func reapUnixQualificationWorkspaceHolders(workspace string) {
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return
	}
	deadline := time.Now().Add(unixWorkspaceHolderReapTimeout)
	for {
		holders := unixWorkspaceHolderPIDs(workspace)
		if len(holders) == 0 {
			return
		}
		for _, pid := range holders {
			_ = unixKillProcess(pid)
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func unixWorkspaceHolderPIDs(workspace string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	parent := os.Getppid()
	holders := make([]int, 0, 8)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == self || pid == parent {
			continue
		}
		if unixProcessHoldsWorkspace(pid, workspace) {
			holders = append(holders, pid)
		}
	}
	return holders
}

func unixProcessHoldsWorkspace(pid int, workspace string) bool {
	proc := "/proc/" + strconv.Itoa(pid)
	if cwd, err := os.Readlink(proc + "/cwd"); err == nil && unixPathInsideWorkspace(workspace, cwd) {
		return true
	}
	if root, err := os.Readlink(proc + "/root"); err == nil && unixPathInsideWorkspace(workspace, root) {
		return true
	}
	descriptors, err := os.ReadDir(proc + "/fd")
	if err != nil {
		return false
	}
	for index, descriptor := range descriptors {
		if index > 4096 {
			break
		}
		target, err := os.Readlink(proc + "/fd/" + descriptor.Name())
		if err != nil {
			continue
		}
		if unixPathInsideWorkspace(workspace, target) {
			return true
		}
	}
	return false
}

func unixPathInsideWorkspace(workspace, candidate string) bool {
	workspace = filepath.Clean(workspace)
	candidate = filepath.Clean(candidate)
	if !filepath.IsAbs(workspace) || !filepath.IsAbs(candidate) {
		return false
	}
	rel, err := filepath.Rel(workspace, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
