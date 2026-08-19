package sourcequalification

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestQualificationLaneSourceGuardRestoresModuleDownloadTrackedMutation(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	readme := filepath.Join(fixture.root, "README.md")
	original, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("read tracked README.md: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.WriteFile(readme, append(append([]byte(nil), original...), []byte("download-side-effect\n")...), 0o644)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if result.SourceChanged {
		t.Fatal("MODULE-DOWNLOAD tracked checksum side effect was treated as SOURCE_DIRTY")
	}
	restored, err := os.ReadFile(readme)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("MODULE-DOWNLOAD worktree = %q, want restored snapshot bytes %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardRestoresModuleDownloadGoSum(t *testing.T) {
	fixture := newGitRepositoryFixtureWithGoSum(t)
	sumPath := filepath.Join(fixture.root, "go.sum")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read tracked go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.WriteFile(sumPath, append(append([]byte(nil), original...), []byte("golang.org/x/sync v0.21.0 h1:deadbeef\n")...), 0o644)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if result.SourceChanged {
		t.Fatal("MODULE-DOWNLOAD go.sum rewrite was treated as SOURCE_DIRTY")
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("go.sum after MODULE-DOWNLOAD = %q, want snapshot bytes %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardRestoresReadOnlyModuleDownloadGoSum(t *testing.T) {
	fixture := newGitRepositoryFixtureWithGoSum(t)
	sumPath := filepath.Join(fixture.root, "go.sum")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read tracked go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			if err := os.WriteFile(sumPath, append(append([]byte(nil), original...), []byte("golang.org/x/sync v0.21.0 h1:deadbeef\n")...), 0o644); err != nil {
				return err
			}
			return os.Chmod(sumPath, 0o444)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if result.SourceChanged {
		t.Fatal("read-only MODULE-DOWNLOAD go.sum rewrite was treated as SOURCE_DIRTY")
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("read-only go.sum after MODULE-DOWNLOAD = %q, want snapshot bytes %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardRestoresModuleDownloadExecutableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows worktree inspect does not bind the Git executable bit")
	}
	fixture := newGitRepositoryFixture(t)
	readme := filepath.Join(fixture.root, "README.md")
	original, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("read tracked README.md: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.Chmod(readme, 0o755)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if result.SourceChanged {
		t.Fatal("MODULE-DOWNLOAD executable-bit side effect was treated as SOURCE_DIRTY")
	}
	info, err := os.Lstat(readme)
	if err != nil {
		t.Fatalf("stat restored README.md: %v", err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("README.md mode = %s, want non-executable after MODULE-DOWNLOAD restore", info.Mode())
	}
	restored, err := os.ReadFile(readme)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("README.md after MODULE-DOWNLOAD = %q, want snapshot bytes %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardBreaksModuleDownloadHardLink(t *testing.T) {
	fixture := newGitRepositoryFixtureWithGoSum(t)
	sumPath := filepath.Join(fixture.root, "go.sum")
	alias := filepath.Join(t.TempDir(), "go.sum.alias")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read tracked go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.Link(sumPath, alias)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		if strings.Contains(execErr.Error(), "hard-link") || errors.Is(execErr, os.ErrPermission) {
			t.Skipf("hard-link fixture is unavailable: %v", execErr)
		}
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if result.SourceChanged {
		if _, err := os.Lstat(alias); err != nil {
			t.Skipf("hard-link fixture is unavailable: %v", err)
		}
		t.Fatal("MODULE-DOWNLOAD hard-linked go.sum was treated as SOURCE_DIRTY")
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("hard-linked go.sum after MODULE-DOWNLOAD = %q, want snapshot bytes %q (err=%v)", restored, original, err)
	}
	info, err := os.Lstat(sumPath)
	if err != nil {
		t.Fatalf("stat restored go.sum: %v", err)
	}
	if err := validateWorktreeEntryMetadata(sumPath, info, "100644"); err != nil {
		t.Fatalf("restored go.sum still has a hard-link alias: %v", err)
	}
}

func TestQualificationLaneSourceGuardRejectsModuleDownloadUntrackedFile(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	untracked := filepath.Join(fixture.root, "untracked.txt")
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.WriteFile(untracked, []byte("download-created\n"), 0o644)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if !result.SourceChanged {
		t.Fatal("MODULE-DOWNLOAD untracked file was accepted")
	}
	if _, err := os.Lstat(untracked); err != nil {
		t.Fatalf("untracked MODULE-DOWNLOAD file was removed: %v", err)
	}
}

func TestQualificationLaneSourceGuardRejectsNonDownloadTrackedMutation(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	readme := filepath.Join(fixture.root, "README.md")
	original, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("read tracked README.md: %v", err)
	}
	mutated := append(append([]byte(nil), original...), []byte("go-version-side-effect\n")...)
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.WriteFile(readme, mutated, 0o644)
		},
	})

	result, execErr := guard.Execute(context.Background(), gateProcessRequest{
		Application: "go",
		Args:        []string{"version"},
	})
	if execErr != nil {
		t.Fatalf("GO-VERSION source guard returned execution error: %v", execErr)
	}
	if !result.SourceChanged {
		t.Fatal("non-download tracked mutation was restored or ignored")
	}
	current, err := os.ReadFile(readme)
	if err != nil || !bytes.Equal(current, mutated) {
		t.Fatalf("non-download worktree = %q, want unrepaired mutation %q (err=%v)", current, mutated, err)
	}
}

func TestQualificationLaneSourceGuardDoesNotRestorePartialDownloadArgv(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	readme := filepath.Join(fixture.root, "README.md")
	original, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("read tracked README.md: %v", err)
	}
	mutated := append(append([]byte(nil), original...), []byte("partial-download-argv\n")...)
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.WriteFile(readme, mutated, 0o644)
		},
	})

	result, execErr := guard.Execute(context.Background(), gateProcessRequest{
		Application: "go",
		Args:        []string{"mod", "download", "-modcacherw"},
	})
	if execErr != nil {
		t.Fatalf("partial download argv source guard returned execution error: %v", execErr)
	}
	if !result.SourceChanged {
		t.Fatal("tracked mutation after incomplete download argv was restored")
	}
}

func TestQualificationLaneSourceGuardRecreatesDeletedGoSumAfterModuleDownload(t *testing.T) {
	fixture := newGitRepositoryFixtureWithGoSum(t)
	sumPath := filepath.Join(fixture.root, "go.sum")
	original, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatalf("read tracked go.sum: %v", err)
	}
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.Remove(sumPath)
		},
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if execErr != nil {
		t.Fatalf("MODULE-DOWNLOAD source guard returned execution error: %v", execErr)
	}
	if result.SourceChanged {
		t.Fatal("deleted go.sum after MODULE-DOWNLOAD was treated as SOURCE_DIRTY")
	}
	restored, err := os.ReadFile(sumPath)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("recreated go.sum = %q, want snapshot bytes %q (err=%v)", restored, original, err)
	}
}

func TestQualificationLaneSourceGuardRestoresModuleDownloadAfterFailedExecute(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	readme := filepath.Join(fixture.root, "README.md")
	original, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("read tracked README.md: %v", err)
	}
	executeErr := errors.New("download failed after writing go.sum")
	guard := newQualificationLaneSourceGuard(t, fixture, worktreeMutatingExecutor{
		mutate: func() error {
			return os.WriteFile(readme, append(append([]byte(nil), original...), []byte("failed-download-side-effect\n")...), 0o644)
		},
		execErr: executeErr,
	})

	result, execErr := guard.Execute(context.Background(), moduleDownloadGateProcessRequest())
	if !errors.Is(execErr, executeErr) {
		t.Fatalf("failed MODULE-DOWNLOAD execution error = %v, want %v", execErr, executeErr)
	}
	if result.SourceChanged {
		t.Fatal("failed MODULE-DOWNLOAD tracked side effect was treated as SOURCE_DIRTY")
	}
	restored, err := os.ReadFile(readme)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("failed MODULE-DOWNLOAD worktree = %q, want restored snapshot bytes %q (err=%v)", restored, original, err)
	}
}

func newQualificationLaneSourceGuard(
	t *testing.T,
	fixture *gitRepositoryFixture,
	inner gateExecutor,
) *qualificationLaneSourceGuard {
	t.Helper()
	snapshot, err := InspectRepository(fixture.request())
	if err != nil {
		t.Fatalf("InspectRepository rejected clean fixture: %v", err)
	}
	return &qualificationLaneSourceGuard{
		inner:     inner,
		inspector: productionLaneRepositoryInspector{},
		request:   fixture.request(),
		expected:  cloneQualificationLaneSnapshot(snapshot),
	}
}

func newGitRepositoryFixtureWithGoSum(t *testing.T) *gitRepositoryFixture {
	t.Helper()
	fixture := newGitRepositoryFixture(t)
	sum := []byte("example.com/mod v1.0.0 h1:abc=\nexample.com/mod v1.0.0/go.mod h1:def=\n")
	writeGitFixtureFile(t, filepath.Join(fixture.root, "go.sum"), sum)
	fixture.git(t, "add", "go.sum")
	parent := fixture.tested
	fixture.commit(t, "go.sum", "2000-01-03T00:00:00Z")
	fixture.base = parent
	fixture.tested = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))
	fixture.tree = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD^{tree}"))
	fixture.fileData["go.sum"] = sum
	return fixture
}

func moduleDownloadGateProcessRequest() gateProcessRequest {
	return gateProcessRequest{
		Application: "go",
		Args:        []string{"mod", "download", "-modcacherw", "all"},
	}
}

type worktreeMutatingExecutor struct {
	mutate  func() error
	execErr error
}

func (executor worktreeMutatingExecutor) BindApplications(
	context.Context,
	map[string]string,
) (gateApplicationBinding, error) {
	return &gateTestApplicationBinding{}, nil
}

func (executor worktreeMutatingExecutor) Execute(
	context.Context,
	gateProcessRequest,
) (gateProcessResult, error) {
	if executor.mutate != nil {
		if err := executor.mutate(); err != nil {
			return gateProcessResult{}, err
		}
	}
	zero := int64(0)
	return gateProcessResult{ExitCode: &zero}, executor.execErr
}
