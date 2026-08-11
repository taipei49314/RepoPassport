// Package sourcequalification is expected to expose the following minimal
// repository-inspection API. Inspection reads exact Git objects, never accepts
// a dirty worktree, and returns no partial snapshot on failure.
//
//	type RepositoryRequest struct {
//		Root                   string
//		ExpectedBaseRevision   string
//		ExpectedTestedRevision string
//	}
//	type RepositorySubject struct {
//		Repository      string
//		ModulePath      string
//		ModuleVersion   string
//		GitObjectFormat string
//		BaseRevision    string
//		TestedRevision  string
//		TreeSHA         string
//		Dirty           bool
//	}
//	type RepositoryFile struct {
//		Path         string
//		GitMode      string
//		GitBlobSHA1  string
//		Size         int64
//		Data         []byte
//	}
//	type RepositorySnapshot struct {
//		Subject RepositorySubject
//		Files   []RepositoryFile
//	}
//	func InspectRepository(RepositoryRequest) (RepositorySnapshot, error)
package sourcequalification

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	testCanonicalRepository = "https://github.com/taipei49314/RepoPassport"
	testCanonicalModule     = "github.com/taipei49314/RepoPassport"
	testModuleVersion       = "0.1.0-alpha.33"
)

type gitRepositoryFixture struct {
	root     string
	home     string
	base     string
	tested   string
	tree     string
	fileData map[string][]byte
}

func TestInspectRepositoryReturnsExactSubjectAndFiles(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	snapshot, err := InspectRepository(fixture.request())
	if err != nil {
		t.Fatalf("InspectRepository rejected exact clean repository: %v", err)
	}

	wantSubject := RepositorySubject{
		Repository:      testCanonicalRepository,
		ModulePath:      testCanonicalModule,
		ModuleVersion:   testModuleVersion,
		GitObjectFormat: "sha1",
		BaseRevision:    fixture.base,
		TestedRevision:  fixture.tested,
		TreeSHA:         fixture.tree,
		Dirty:           false,
	}
	if !reflect.DeepEqual(snapshot.Subject, wantSubject) {
		t.Fatalf("repository subject = %#v, want %#v", snapshot.Subject, wantSubject)
	}

	wantFiles := []RepositoryFile{
		testRepositoryFile(".gitignore", "100644", fixture.fileData[".gitignore"]),
		testRepositoryFile("README.md", "100644", fixture.fileData["README.md"]),
		testRepositoryFile("go.mod", "100644", fixture.fileData["go.mod"]),
		testRepositoryFile("scripts/run.sh", "100755", fixture.fileData["scripts/run.sh"]),
	}
	if !reflect.DeepEqual(snapshot.Files, wantFiles) {
		t.Fatalf("repository files = %#v, want exact raw-path ordered inventory %#v", snapshot.Files, wantFiles)
	}
}

func TestInspectRepositoryRejectsDirtyUntrackedAndIgnoredState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *gitRepositoryFixture)
	}{
		{
			name: "tracked unstaged",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				writeGitFixtureFile(t, filepath.Join(fixture.root, "README.md"), []byte("dirty\n"))
			},
		},
		{
			name: "tracked staged",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				writeGitFixtureFile(t, filepath.Join(fixture.root, "README.md"), []byte("staged\n"))
				fixture.git(t, "add", "README.md")
			},
		},
		{
			name: "untracked",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				writeGitFixtureFile(t, filepath.Join(fixture.root, "untracked.txt"), []byte("untrusted\n"))
			},
		},
		{
			name: "ignored",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				writeGitFixtureFile(t, filepath.Join(fixture.root, "ignored.tmp"), []byte("ignored but forbidden\n"))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitRepositoryFixture(t)
			test.mutate(t, fixture)
			requireRepositoryInspectionRejected(t, fixture.request())
		})
	}
}

func TestInspectRepositoryRejectsShallowAndInjectedGitState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *gitRepositoryFixture)
	}{
		{
			name: "shallow",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				gitDirectory := strings.TrimSpace(fixture.git(t, "rev-parse", "--git-dir"))
				if !filepath.IsAbs(gitDirectory) {
					gitDirectory = filepath.Join(fixture.root, gitDirectory)
				}
				writeGitFixtureFile(t, filepath.Join(gitDirectory, "shallow"), []byte(fixture.tested+"\n"))
			},
		},
		{
			name: "replace object",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				fixture.git(t, "replace", fixture.tested, fixture.base)
			},
		},
		{
			name: "assume unchanged",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				fixture.git(t, "update-index", "--assume-unchanged", "README.md")
			},
		},
		{
			name: "skip worktree",
			mutate: func(t *testing.T, fixture *gitRepositoryFixture) {
				fixture.git(t, "update-index", "--skip-worktree", "README.md")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitRepositoryFixture(t)
			test.mutate(t, fixture)
			requireRepositoryInspectionRejected(t, fixture.request())
		})
	}
}

func TestInspectRepositoryRejectsUnsupportedGitMode(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	linkData := []byte("scripts/run.sh\n")
	blob := strings.TrimSpace(fixture.gitInput(t, linkData, "hash-object", "-w", "--stdin"))
	writeGitFixtureFile(t, filepath.Join(fixture.root, "link"), linkData)
	fixture.git(t, "update-index", "--add", "--cacheinfo", "120000", blob, "link")
	fixture.commit(t, "unsupported-mode", "2000-01-03T00:00:00Z")

	request := RepositoryRequest{
		Root:                   fixture.root,
		ExpectedBaseRevision:   fixture.tested,
		ExpectedTestedRevision: strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD")),
	}
	requireRepositoryInspectionRejected(t, request)
}

func TestInspectRepositoryParsesReplacementNamespaces(t *testing.T) {
	t.Run("unrelated replacement is permitted", func(t *testing.T) {
		fixture := newGitRepositoryFixture(t)
		module := append([]byte(nil), fixture.fileData["go.mod"]...)
		module = append(module, []byte("\nreplace example.invalid/dependency => example.invalid/fork v1.0.0\n")...)
		writeGitFixtureFile(t, filepath.Join(fixture.root, "go.mod"), module)
		fixture.git(t, "add", "go.mod")
		fixture.commit(t, "unrelated-replace", "2000-01-03T00:00:00Z")
		request := RepositoryRequest{
			Root:                   fixture.root,
			ExpectedBaseRevision:   fixture.tested,
			ExpectedTestedRevision: strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD")),
		}
		if _, err := InspectRepository(request); err != nil {
			t.Fatalf("InspectRepository rejected unrelated replacement: %v", err)
		}
	})

	t.Run("escaped canonical replacement is rejected", func(t *testing.T) {
		fixture := newGitRepositoryFixture(t)
		module := append([]byte(nil), fixture.fileData["go.mod"]...)
		module = append(module, []byte("\nreplace \"github.com/taipei49314/RepoPass\\x70ort\" => example.invalid/fork v1.0.0\n")...)
		writeGitFixtureFile(t, filepath.Join(fixture.root, "go.mod"), module)
		fixture.git(t, "add", "go.mod")
		fixture.commit(t, "canonical-replace", "2000-01-03T00:00:00Z")
		request := RepositoryRequest{
			Root:                   fixture.root,
			ExpectedBaseRevision:   fixture.tested,
			ExpectedTestedRevision: strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD")),
		}
		requireRepositoryInspectionRejected(t, request)
	})
}

func TestInspectRepositoryRejectsMismatchedExpectedIdentity(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	wrong := strings.Repeat("0", 40)
	for _, request := range []RepositoryRequest{
		{Root: fixture.root, ExpectedBaseRevision: wrong, ExpectedTestedRevision: fixture.tested},
		{Root: fixture.root, ExpectedBaseRevision: fixture.base, ExpectedTestedRevision: wrong},
	} {
		requireRepositoryInspectionRejected(t, request)
	}
}

func newGitRepositoryFixture(t *testing.T) *gitRepositoryFixture {
	t.Helper()
	parent := t.TempDir()
	fixture := &gitRepositoryFixture{
		root: filepath.Join(parent, "repository"),
		home: filepath.Join(parent, "home"),
		fileData: map[string][]byte{
			".gitignore":     []byte("ignored.tmp\n"),
			"README.md":      []byte("tested\n"),
			"go.mod":         []byte("module " + testCanonicalModule + "\n\ngo 1.26\n"),
			"scripts/run.sh": []byte("#!/bin/sh\nexit 0\n"),
		},
	}
	if err := os.MkdirAll(fixture.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fixture.home, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.git(t, "init", "--initial-branch=main")
	fixture.git(t, "config", "user.name", "RepoPassport Test")
	fixture.git(t, "config", "user.email", "repopass-test@example.invalid")
	fixture.git(t, "config", "core.autocrlf", "false")
	fixture.git(t, "config", "core.filemode", "false")

	for path, data := range fixture.fileData {
		initial := data
		if path == "README.md" {
			initial = []byte("base\n")
		}
		writeGitFixtureFile(t, filepath.Join(fixture.root, filepath.FromSlash(path)), initial)
	}
	fixture.git(t, "add", "--all")
	fixture.git(t, "update-index", "--chmod=+x", "scripts/run.sh")
	fixture.commit(t, "base", "2000-01-01T00:00:00Z")
	fixture.base = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))

	writeGitFixtureFile(t, filepath.Join(fixture.root, "README.md"), fixture.fileData["README.md"])
	fixture.git(t, "add", "README.md")
	fixture.commit(t, "tested", "2000-01-02T00:00:00Z")
	fixture.tested = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))
	fixture.tree = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD^{tree}"))
	return fixture
}

func (fixture *gitRepositoryFixture) request() RepositoryRequest {
	return RepositoryRequest{
		Root:                   fixture.root,
		ExpectedBaseRevision:   fixture.base,
		ExpectedTestedRevision: fixture.tested,
	}
}

func (fixture *gitRepositoryFixture) commit(t *testing.T, message, timestamp string) {
	t.Helper()
	fixture.gitWithExtraEnv(t, nil, []string{
		"GIT_AUTHOR_DATE=" + timestamp,
		"GIT_COMMITTER_DATE=" + timestamp,
	}, "commit", "--no-gpg-sign", "-m", message)
}

func (fixture *gitRepositoryFixture) git(t *testing.T, arguments ...string) string {
	t.Helper()
	return fixture.gitWithExtraEnv(t, nil, nil, arguments...)
}

func (fixture *gitRepositoryFixture) gitInput(t *testing.T, input []byte, arguments ...string) string {
	t.Helper()
	return fixture.gitWithExtraEnv(t, input, nil, arguments...)
}

func (fixture *gitRepositoryFixture) gitWithExtraEnv(t *testing.T, input []byte, extraEnv []string, arguments ...string) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("Git is required for source-qualification contract tests: %v", err)
	}
	command := exec.Command(git, arguments...)
	command.Dir = fixture.root
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"HOME="+fixture.home,
		"USERPROFILE="+fixture.home,
		"XDG_CONFIG_HOME="+fixture.home,
	)
	command.Env = append(command.Env, extraEnv...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func requireRepositoryInspectionRejected(t *testing.T, request RepositoryRequest) {
	t.Helper()
	snapshot, err := InspectRepository(request)
	if err == nil {
		t.Fatalf("InspectRepository accepted invalid repository state: %#v", snapshot)
	}
	if !reflect.DeepEqual(snapshot, RepositorySnapshot{}) {
		t.Fatalf("rejected repository returned a partial accepted snapshot: %#v", snapshot)
	}
}

func testRepositoryFile(path, mode string, data []byte) RepositoryFile {
	return RepositoryFile{
		Path:        path,
		GitMode:     mode,
		GitBlobSHA1: testGitBlobSHA1(data),
		Size:        int64(len(data)),
		Data:        append([]byte(nil), data...),
	}
}

func testGitBlobSHA1(data []byte) string {
	digest := sha1.New() // Git SHA-1 object identity, not a security digest.
	_, _ = fmt.Fprintf(digest, "blob %d%c", len(data), byte(0))
	_, _ = digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeGitFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
