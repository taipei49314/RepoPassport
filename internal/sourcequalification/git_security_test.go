package sourcequalification

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInspectRepositoryRejectsExternalHardLinkAlias(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	tracked := filepath.Join(fixture.root, "README.md")
	externalAlias := filepath.Join(filepath.Dir(fixture.root), "external-readme-hard-link")
	if err := os.Link(tracked, externalAlias); err != nil {
		t.Fatalf("create external hard-link regression fixture: %v", err)
	}

	requireRepositoryInspectionRejected(t, fixture.request())
}

func TestInspectRepositoryRejectsNestedObjectStoreRedirect(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	packDirectory := filepath.Join(fixture.root, ".git", "objects", "pack")
	externalDirectory := filepath.Join(filepath.Dir(fixture.root), "external-object-pack")
	if err := os.Remove(packDirectory); err != nil {
		t.Fatalf("remove local object-pack directory: %v", err)
	}
	if err := os.Mkdir(externalDirectory, 0o700); err != nil {
		t.Fatalf("create external object-pack directory: %v", err)
	}
	if !createDirectoryRedirectForTest(t, packDirectory, externalDirectory) {
		t.Skip("directory redirects are unavailable without elevated host support")
	}

	requireRepositoryInspectionRejected(t, fixture.request())
}

func TestInspectRepositoryErrorRedactsAbsoluteRoot(t *testing.T) {
	const privateMarker = "repopass-private-root-9d8f071a"
	privateRoot := filepath.Join(t.TempDir(), privateMarker, "missing-repository")
	request := RepositoryRequest{
		Root:                   privateRoot,
		ExpectedBaseRevision:   strings.Repeat("1", 40),
		ExpectedTestedRevision: strings.Repeat("2", 40),
	}

	_, err := InspectRepository(request)
	if err == nil {
		t.Fatal("InspectRepository accepted a missing private repository root")
	}
	if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(privateMarker)) {
		t.Fatalf("repository diagnostic disclosed a private absolute path: %q", err)
	}
}

func TestGitCommandErrorRedactsRawStderr(t *testing.T) {
	const privateOutput = "credential-like-private-stderr-6f2c9bb8"
	stderr := &boundedBuffer{limit: 1024}
	if _, err := stderr.Write([]byte(privateOutput)); err != nil {
		t.Fatalf("prepare bounded stderr fixture: %v", err)
	}

	err := gitCommandError("cat-file --batch", errors.New("exit status 1"), nil, stderr)
	if strings.Contains(err.Error(), privateOutput) {
		t.Fatalf("Git diagnostic disclosed raw stderr: %q", err)
	}
}

func TestValidateGitExecutablePathIgnoresCheckoutBinary(t *testing.T) {
	trustedGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("resolve trusted Git fixture executable: %v", err)
	}
	fixture := newGitRepositoryFixture(t)
	candidate := filepath.Join(fixture.root, filepath.Base(trustedGit))
	copyExecutableForTest(t, trustedGit, candidate)
	t.Setenv("PATH", fixture.root+string(os.PathListSeparator)+os.Getenv("PATH"))

	inspector, cleanup, err := newRepositoryInspector(fixture.root)
	if cleanup != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			t.Fatalf("remove isolated Git test environment: %v", cleanupErr)
		}
	}
	if err != nil {
		t.Fatalf("fixed machine Git resolver was redirected or unavailable: %v", err)
	}
	if inspector == nil || sameCanonicalPath(inspector.gitPath, candidate) {
		t.Fatalf("repository-local Git executable was selected: inspector=%v path=%q", inspector != nil, candidate)
	}
}

func copyExecutableForTest(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatalf("open trusted Git fixture executable: %v", err)
	}
	defer input.Close()

	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatalf("create repository-local Git fixture executable: %v", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatalf("copy repository-local Git fixture executable: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close repository-local Git fixture executable: %v", err)
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		t.Fatalf("make repository-local Git fixture executable: %v", err)
	}
}

func createDirectoryRedirectForTest(t *testing.T, path, target string) bool {
	t.Helper()
	if err := os.Symlink(target, path); err == nil {
		t.Cleanup(func() { _ = os.Remove(path) })
		return true
	} else if runtime.GOOS != "windows" {
		t.Fatalf("create object-store symlink fixture: %v", err)
	}

	command := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", path, target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Logf("Windows junction fixture unavailable: %v (%s)", err, strings.TrimSpace(string(output)))
		return false
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return true
}
