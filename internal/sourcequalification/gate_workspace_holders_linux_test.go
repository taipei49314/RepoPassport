//go:build linux

package sourcequalification

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestUnixPathInsideWorkspace(t *testing.T) {
	t.Parallel()
	const workspace = "/tmp/repopass-workspace"
	tests := []struct {
		candidate string
		want      bool
	}{
		{candidate: "/tmp/repopass-workspace", want: true},
		{candidate: "/tmp/repopass-workspace/tmp", want: true},
		{candidate: "/tmp/repopass-workspace-evil", want: false},
		{candidate: "/tmp", want: false},
		{candidate: "/tmp/repopass-workspace/../secret", want: false},
		{candidate: "relative", want: false},
	}
	for _, test := range tests {
		if got := unixPathInsideWorkspace(workspace, test.candidate); got != test.want {
			t.Fatalf("unixPathInsideWorkspace(%q, %q) = %v, want %v", workspace, test.candidate, got, test.want)
		}
	}
}

func TestUnixReapWorkspaceHoldersKillsSetsidProcessWithCwdInside(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	held := startSetsidSleep(t, workspace)
	safe := startSetsidSleep(t, outside)
	defer func() { _ = safe.Process.Kill(); _ = safe.Wait() }()
	waitUntilWorkspaceHolder(t, held.Process.Pid, workspace)

	reapUnixQualificationWorkspaceHolders(workspace)
	waitDone := make(chan error, 1)
	go func() { waitDone <- held.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("setsid holder with cwd inside the workspace survived reap")
	}
	if err := syscall.Kill(safe.Process.Pid, 0); err != nil {
		t.Fatalf("process outside the workspace was killed: %v", err)
	}
}

func TestUnixReapWorkspaceHoldersKillsProcessHoldingWorkspaceFile(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	heldFile, err := os.OpenFile(filepath.Join(workspace, "held"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer heldFile.Close()
	command := exec.Command("sleep", "30")
	command.Dir = outside
	command.ExtraFiles = []*os.File{heldFile}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := heldFile.Close(); err != nil {
		t.Fatal(err)
	}
	waitUntilWorkspaceHolder(t, command.Process.Pid, workspace)

	reapUnixQualificationWorkspaceHolders(workspace)
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("setsid holder of a workspace file survived reap")
	}
}

func TestPrivateQualificationWorkspaceCleanupReapsSetsidCwdHolder(t *testing.T) {
	parent := t.TempDir()
	path, cleanup, err := createPrivateQualificationWorkspace(parent, "private-run")
	if err != nil {
		t.Fatal(err)
	}
	held := startSetsidSleep(t, path)
	waitUntilWorkspaceHolder(t, held.Process.Pid, path)
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup with setsid cwd holder: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("workspace remained after holder reap: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- held.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("setsid cwd holder survived workspace cleanup")
	}
}

func waitUntilWorkspaceHolder(t *testing.T, pid int, workspace string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if unixProcessHoldsWorkspace(pid, workspace) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pid %d never appeared as a holder of %s", pid, workspace)
}

func startSetsidSleep(t *testing.T, directory string) *exec.Cmd {
	t.Helper()
	command := exec.Command("sleep", "30")
	command.Dir = directory
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	return command
}
