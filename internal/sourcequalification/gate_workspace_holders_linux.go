//go:build linux

package sourcequalification

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func reapUnixQualificationWorkspaceHolders(workspace string, root *os.File) {
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return
	}
	canonical := unixQualificationWorkspaceCanonicalPath(workspace, root)
	deadline := time.Now().Add(unixWorkspaceHolderReapTimeout)
	for {
		holders := unixWorkspaceHolderPIDs(canonical, root)
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

func unixQualificationWorkspaceCanonicalPath(workspace string, root *os.File) string {
	if root != nil {
		if target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(root.Fd()))); err == nil {
			target = strings.TrimSuffix(filepath.Clean(target), " (deleted)")
			if filepath.IsAbs(target) {
				return target
			}
		}
	}
	if resolved, err := filepath.EvalSymlinks(workspace); err == nil && filepath.IsAbs(resolved) {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(workspace)
}

func unixWorkspaceHolderPIDs(workspace string, root *os.File) []int {
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
		if unixProcessHoldsWorkspace(pid, workspace, root) {
			holders = append(holders, pid)
		}
	}
	return holders
}

func unixProcessHoldsWorkspace(pid int, workspace string, root *os.File) bool {
	held, complete := unixProcessInspectWorkspaceUnprivileged(pid, workspace, root)
	if held || complete {
		return held
	}
	return unixProcessHoldsWorkspacePrivileged(pid, workspace)
}

func unixProcessInspectWorkspaceUnprivileged(pid int, workspace string, root *os.File) (held bool, complete bool) {
	proc := "/proc/" + strconv.Itoa(pid)
	cwd, cwdErr := os.Readlink(proc + "/cwd")
	if cwdErr == nil && unixPathInsideWorkspace(workspace, cwd) {
		return true, true
	}
	if chroot, err := os.Readlink(proc + "/root"); err == nil && unixPathInsideWorkspace(workspace, chroot) {
		return true, true
	}
	if unixProcessCwdInsideWorkspaceByInode(pid, root) {
		return true, true
	}
	descriptors, err := os.ReadDir(proc + "/fd")
	if err != nil {
		return false, false
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
			return true, true
		}
	}
	return false, true
}

func unixProcessHoldsWorkspacePrivileged(pid int, workspace string) bool {
	if cwd, err := linuxPrivilegedReadlink("/proc/" + strconv.Itoa(pid) + "/cwd"); err == nil &&
		unixPathInsideWorkspace(workspace, cwd) {
		return true
	}
	if root, err := linuxPrivilegedReadlink("/proc/" + strconv.Itoa(pid) + "/root"); err == nil &&
		unixPathInsideWorkspace(workspace, root) {
		return true
	}
	names, err := linuxPrivilegedListDirectory("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		return false
	}
	for index, name := range names {
		if index > 4096 {
			break
		}
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		target, err := linuxPrivilegedReadlink("/proc/" + strconv.Itoa(pid) + "/fd/" + name)
		if err != nil {
			continue
		}
		if unixPathInsideWorkspace(workspace, target) {
			return true
		}
	}
	return false
}

func unixProcessCwdInsideWorkspaceByInode(pid int, root *os.File) bool {
	if root == nil {
		return false
	}
	var want unix.Stat_t
	if err := unix.Fstat(int(root.Fd()), &want); err != nil {
		return false
	}
	fd, err := unix.Open("/proc/"+strconv.Itoa(pid)+"/cwd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	return unixDirectoryFdInsideWorkspace(fd, want)
}

func unixDirectoryFdInsideWorkspace(fd int, want unix.Stat_t) bool {
	current := fd
	owned := false
	defer func() {
		if owned {
			_ = unix.Close(current)
		}
	}()
	for range 64 {
		var st unix.Stat_t
		if err := unix.Fstat(current, &st); err != nil {
			return false
		}
		if uint64(st.Dev) == uint64(want.Dev) && uint64(st.Ino) == uint64(want.Ino) {
			return true
		}
		parent, err := unix.Openat(current, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return false
		}
		var parentSt unix.Stat_t
		if err := unix.Fstat(parent, &parentSt); err != nil {
			_ = unix.Close(parent)
			return false
		}
		if st.Dev == parentSt.Dev && st.Ino == parentSt.Ino {
			_ = unix.Close(parent)
			return false
		}
		if owned {
			_ = unix.Close(current)
		}
		current = parent
		owned = true
	}
	return false
}

func unixPathInsideWorkspace(workspace, candidate string) bool {
	workspace = filepath.Clean(workspace)
	candidate = strings.TrimSuffix(filepath.Clean(candidate), " (deleted)")
	if !filepath.IsAbs(workspace) || !filepath.IsAbs(candidate) {
		return false
	}
	rel, err := filepath.Rel(workspace, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func validLinuxProcHolderPath(path string) bool {
	if !strings.HasPrefix(path, "/proc/") || strings.Contains(path, "..") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/proc/"), "/")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 1 {
		return false
	}
	switch {
	case len(parts) == 2 && (parts[1] == "cwd" || parts[1] == "root" || parts[1] == "fd"):
		return true
	case len(parts) == 3 && parts[1] == "fd":
		fd, err := strconv.Atoi(parts[2])
		return err == nil && fd >= 0 && fd <= 4096
	default:
		return false
	}
}

func linuxPrivilegedReadlink(path string) (string, error) {
	sudo, arguments, ok := linuxPrivilegedReadlinkCommand(path)
	if !ok {
		return "", syscall.EPERM
	}
	output, err := linuxPrivilegedHelperOutput(sudo, arguments)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(bytes.TrimSpace(output)), "\x00"), nil
}

func linuxPrivilegedListDirectory(path string) ([]string, error) {
	sudo, arguments, ok := linuxPrivilegedListDirectoryCommand(path)
	if !ok {
		return nil, syscall.EPERM
	}
	output, err := linuxPrivilegedHelperOutput(sudo, arguments)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(output))
	return fields, nil
}
