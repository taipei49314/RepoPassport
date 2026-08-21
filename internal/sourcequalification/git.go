package sourcequalification

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
)

const (
	maximumRepositoryFiles                   = maxArchiveFiles
	maximumRepositoryFileSize                = maxArchiveFileBytes
	maximumRepositoryDataSize                = maxArchiveBytes
	maximumGitOutputSize                     = int64(16 << 20)
	maximumGitErrorSize                      = int64(64 << 10)
	maximumGitMetadataEntries                = 1_000_000
	maximumGitWorktreeEntries                = 1_000_000
	maximumGitTraversalDepth                 = 64
	gitTraversalBatchSize                    = 128
	gitCommandTimeout                        = 30 * time.Second
	repositoryScratchPrefix                  = "repopass-sourcequalification-"
	repositoryScratchEntropyBytes            = 16
	maximumRepositoryScratchCreationAttempts = 8
)

var (
	errRepositoryScratchCleanup = errors.New("isolated Git environment cleanup failed")
	errGitTraversalInvalid      = errors.New("Git filesystem traversal configuration is invalid")
	errGitTraversalUnsafe       = errors.New("Git filesystem traversal is unsafe")
	errGitTraversalEntryLimit   = errors.New("Git filesystem traversal entry bound exceeded")
	errGitTraversalDepthLimit   = errors.New("Git filesystem traversal depth bound exceeded")
)

type gitTraversalBudget struct {
	entries        int
	maximumEntries int
	maximumDepth   int
}

func (budget *gitTraversalBudget) consume(depth int) error {
	if budget == nil || budget.maximumEntries <= 0 || budget.maximumDepth < 0 || depth < 0 {
		return errGitTraversalInvalid
	}
	if budget.entries >= budget.maximumEntries {
		return errGitTraversalEntryLimit
	}
	budget.entries++
	if depth > budget.maximumDepth {
		return errGitTraversalDepthLimit
	}
	return nil
}

type repositoryScratchCreator func(parent, name string) (
	path string,
	cleanup func() error,
	err error,
)

// RepositoryRequest identifies the checkout and the independently supplied
// first-parent and tested commit identities that it is expected to contain.
type RepositoryRequest struct {
	Root                   string
	ExpectedBaseRevision   string
	ExpectedTestedRevision string
}

// RepositorySubject is the exact source subject bound into qualification
// manifests and receipts.
type RepositorySubject struct {
	Repository      string
	ModulePath      string
	ModuleVersion   string
	GitObjectFormat string
	BaseRevision    string
	TestedRevision  string
	TreeSHA         string
	Dirty           bool
}

// RepositoryFile contains bytes obtained from a verified Git blob object. The
// worktree is inspected only to prove that it is an exact, clean checkout.
type RepositoryFile struct {
	Path        string
	GitMode     string
	GitBlobSHA1 string
	Size        int64
	Data        []byte
}

// RepositorySnapshot is returned only after every repository, index, object,
// and worktree check has completed. Errors never return a partial snapshot.
type RepositorySnapshot struct {
	Subject RepositorySubject
	Files   []RepositoryFile
}

type repositoryInspector struct {
	root    string
	gitDir  string
	gitPath string
	env     []string
}

type repositoryTreeEntry struct {
	Path string
	Mode string
	OID  string
	Size int64
}

type repositoryGitState struct {
	ObjectFormat string
	Head         string
	Base         string
	Tree         string
	Entries      []repositoryTreeEntry
}

// InspectRepository reads one complete SHA-1 Git tree through fixed plumbing.
// It deliberately resolves the Git application before replacing its process
// environment so ambient GIT_* inputs cannot redirect subsequent commands.
func InspectRepository(request RepositoryRequest) (RepositorySnapshot, error) {
	return inspectRepositoryWithScratch(
		request,
		createPrivateQualificationWorkspace,
		rand.Reader,
	)
}

func inspectRepositoryWithScratch(
	request RepositoryRequest,
	createScratch repositoryScratchCreator,
	entropy io.Reader,
) (RepositorySnapshot, error) {
	if !validRepositoryOID(request.ExpectedBaseRevision) {
		return RepositorySnapshot{}, errors.New("expected base revision is not a lowercase SHA-1 object ID")
	}
	if !validRepositoryOID(request.ExpectedTestedRevision) {
		return RepositorySnapshot{}, errors.New("expected tested revision is not a lowercase SHA-1 object ID")
	}

	inspector, cleanup, err := newRepositoryInspectorWithScratch(
		request.Root,
		createScratch,
		entropy,
	)
	if err != nil {
		return RepositorySnapshot{}, err
	}

	snapshot, inspectErr := inspector.inspect(request)
	return completeRepositoryInspection(snapshot, inspectErr, cleanup)
}

func completeRepositoryInspection(
	snapshot RepositorySnapshot,
	inspectErr error,
	cleanup func() error,
) (RepositorySnapshot, error) {
	if cleanup == nil {
		return RepositorySnapshot{}, errRepositoryScratchCleanup
	}
	cleanupErr := cleanup()
	if cleanupErr != nil {
		if inspectErr != nil {
			return RepositorySnapshot{}, errors.Join(errRepositoryScratchCleanup, inspectErr)
		}
		return RepositorySnapshot{}, errRepositoryScratchCleanup
	}
	if inspectErr != nil {
		return RepositorySnapshot{}, inspectErr
	}
	return snapshot, nil
}

func newRepositoryInspector(requestedRoot string) (*repositoryInspector, func() error, error) {
	return newRepositoryInspectorWithScratch(
		requestedRoot,
		createPrivateQualificationWorkspace,
		rand.Reader,
	)
}

func newRepositoryInspectorWithScratch(
	requestedRoot string,
	createScratch repositoryScratchCreator,
	entropy io.Reader,
) (*repositoryInspector, func() error, error) {
	if requestedRoot == "" || !filepath.IsAbs(requestedRoot) || filepath.Clean(requestedRoot) != requestedRoot {
		return nil, nil, errors.New("repository root must be a clean absolute path")
	}
	rootInfo, err := os.Lstat(requestedRoot)
	if err != nil {
		return nil, nil, errors.New("repository root could not be inspected")
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("repository root is not a real directory")
	}
	if err := validateNoLinkMetadata(requestedRoot, rootInfo); err != nil {
		return nil, nil, err
	}
	resolvedRoot, err := pathsecurity.Resolve(requestedRoot)
	if err != nil {
		return nil, nil, errors.New("repository root could not be resolved")
	}
	if !sameCanonicalPath(requestedRoot, resolvedRoot) {
		return nil, nil, errors.New("repository root traverses a symlink or reparse point")
	}

	gitDir := filepath.Join(requestedRoot, ".git")
	gitInfo, err := os.Lstat(gitDir)
	if err != nil {
		return nil, nil, errors.New("Git metadata directory could not be inspected")
	}
	if !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("linked worktrees and redirected Git directories are unsupported")
	}
	if err := validateNoLinkMetadata(gitDir, gitInfo); err != nil {
		return nil, nil, err
	}

	gitPath, err := resolveTrustedGitExecutable(requestedRoot)
	if err != nil {
		return nil, nil, err
	}

	if createScratch == nil || entropy == nil {
		return nil, nil, errors.New("isolated Git environment could not be created")
	}
	scratchParent, err := canonicalIsolatedGitScratchParent(requestedRoot, os.TempDir())
	if err != nil {
		return nil, nil, err
	}
	for attempt := 0; attempt < maximumRepositoryScratchCreationAttempts; attempt++ {
		name, err := newRepositoryScratchName(entropy)
		if err != nil {
			return nil, nil, errors.New("isolated Git environment could not be created")
		}
		scratch, cleanup, err := createScratch(scratchParent, name)
		if err != nil {
			continue
		}
		if cleanup == nil || scratch != filepath.Join(scratchParent, name) ||
			!validGateExternalDirectory(requestedRoot, scratch) {
			if cleanup != nil && cleanup() != nil {
				return nil, nil, errRepositoryScratchCleanup
			}
			return nil, nil, errors.New("isolated Git environment could not be created safely")
		}
		inspector := &repositoryInspector{
			root:    requestedRoot,
			gitDir:  gitDir,
			gitPath: gitPath,
			env:     isolatedGitEnvironment(gitPath, scratch),
		}
		return inspector, cleanup, nil
	}
	return nil, nil, errors.New("isolated Git environment could not be created")
}

func newRepositoryScratchName(entropy io.Reader) (string, error) {
	random := make([]byte, repositoryScratchEntropyBytes)
	if _, err := io.ReadFull(entropy, random); err != nil {
		return "", err
	}
	return repositoryScratchPrefix + hex.EncodeToString(random), nil
}

func canonicalIsolatedGitScratchParent(repositoryRoot, tempDir string) (string, error) {
	if tempDir == "" {
		return "", errors.New("isolated Git environment parent is invalid")
	}
	absolute, err := filepath.Abs(tempDir)
	if err != nil {
		return "", errors.New("isolated Git environment parent is invalid")
	}
	absolute = filepath.Clean(absolute)
	resolved, err := pathsecurity.Resolve(absolute)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("isolated Git environment parent is invalid")
	}
	resolved = filepath.Clean(resolved)
	if !validGateExternalDirectory(repositoryRoot, resolved) {
		return "", errors.New("isolated Git environment parent is invalid")
	}
	return resolved, nil
}

func resolveTrustedGitExecutable(repositoryRoot string) (string, error) {
	return resolveTrustedGitExecutablePlatform(repositoryRoot)
}

func pathWithinRepository(repositoryRoot, candidate string) bool {
	contains, err := securePackagePathContains(repositoryRoot, candidate)
	return err != nil || contains
}

func isolatedGitEnvironment(gitPath, scratch string) []string {
	values := make(map[string]string)
	for _, item := range os.Environ() {
		name, value, found := strings.Cut(item, "=")
		if found {
			values[strings.ToUpper(name)] = value
		}
	}

	pathParts := []string{filepath.Dir(gitPath)}
	if systemRoot := values["SYSTEMROOT"]; runtime.GOOS == "windows" && systemRoot != "" {
		pathParts = append(pathParts, filepath.Join(systemRoot, "System32"))
	}
	environment := []string{
		"PATH=" + strings.Join(pathParts, string(os.PathListSeparator)),
		"HOME=" + scratch,
		"USERPROFILE=" + scratch,
		"XDG_CONFIG_HOME=" + scratch,
		"TMPDIR=" + scratch,
		"TMP=" + scratch,
		"TEMP=" + scratch,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=" + os.DevNull,
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_LITERAL_PATHSPECS=1",
		"GIT_PAGER=",
		"PAGER=",
		"GCM_INTERACTIVE=Never",
	}
	for _, name := range []string{"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"} {
		if value := values[name]; value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func (inspector *repositoryInspector) inspect(request RepositoryRequest) (RepositorySnapshot, error) {
	before, err := inspector.captureState(request)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	files, err := inspector.readBlobBatch(before.Entries)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	if err := validateModuleSource(files); err != nil {
		return RepositorySnapshot{}, err
	}
	if err := inspector.verifyWorktree(files); err != nil {
		return RepositorySnapshot{}, err
	}

	after, err := inspector.captureState(request)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	if !sameRepositoryState(before, after) {
		return RepositorySnapshot{}, errors.New("repository state changed during inspection")
	}
	if err := inspector.verifyWorktree(files); err != nil {
		return RepositorySnapshot{}, err
	}

	return RepositorySnapshot{
		Subject: RepositorySubject{
			Repository:      canonicalRepositoryURL,
			ModulePath:      canonicalModulePath,
			ModuleVersion:   canonicalModuleVersion,
			GitObjectFormat: before.ObjectFormat,
			BaseRevision:    before.Base,
			TestedRevision:  before.Head,
			TreeSHA:         before.Tree,
			Dirty:           false,
		},
		Files: files,
	}, nil
}

func (inspector *repositoryInspector) captureState(request RepositoryRequest) (repositoryGitState, error) {
	if err := inspector.validateMetadataLayout(); err != nil {
		return repositoryGitState{}, err
	}
	if err := inspector.requireGitBoolean("--is-inside-work-tree", true); err != nil {
		return repositoryGitState{}, err
	}
	if err := inspector.requireGitBoolean("--is-bare-repository", false); err != nil {
		return repositoryGitState{}, err
	}
	if err := inspector.requireGitBoolean("--is-shallow-repository", false); err != nil {
		return repositoryGitState{}, err
	}
	if err := inspector.rejectUnsafeConfiguration(); err != nil {
		return repositoryGitState{}, err
	}
	replacements, err := inspector.runGit(maximumGitOutputSize, "for-each-ref", "--format=%(refname)", "refs/replace/")
	if err != nil {
		return repositoryGitState{}, err
	}
	if len(replacements) != 0 {
		return repositoryGitState{}, errors.New("replacement object refs are forbidden")
	}

	objectFormat, err := inspector.gitLine("rev-parse", "--show-object-format")
	if err != nil {
		return repositoryGitState{}, err
	}
	if objectFormat != "sha1" {
		return repositoryGitState{}, errors.New("repository does not use SHA-1 Git object IDs")
	}
	head, err := inspector.gitLine("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return repositoryGitState{}, err
	}
	if head != request.ExpectedTestedRevision {
		return repositoryGitState{}, errors.New("HEAD does not equal the expected tested revision")
	}
	tested, err := inspector.gitLine("rev-parse", "--verify", request.ExpectedTestedRevision+"^{commit}")
	if err != nil || tested != head {
		return repositoryGitState{}, errors.New("expected tested revision is not the exact HEAD commit")
	}
	base, err := inspector.gitLine("rev-parse", "--verify", request.ExpectedTestedRevision+"^1")
	if err != nil {
		return repositoryGitState{}, errors.New("tested revision has no unambiguous first parent")
	}
	if base != request.ExpectedBaseRevision {
		return repositoryGitState{}, errors.New("first parent does not equal the expected base revision")
	}
	verifiedBase, err := inspector.gitLine("rev-parse", "--verify", request.ExpectedBaseRevision+"^{commit}")
	if err != nil || verifiedBase != base {
		return repositoryGitState{}, errors.New("expected base revision is not a commit")
	}
	tree, err := inspector.gitLine("rev-parse", "--verify", request.ExpectedTestedRevision+"^{tree}")
	if err != nil || !validRepositoryOID(tree) {
		return repositoryGitState{}, errors.New("tested revision tree is invalid")
	}
	entries, err := inspector.readTree(request.ExpectedTestedRevision)
	if err != nil {
		return repositoryGitState{}, err
	}
	if err := inspector.verifyIndex(entries); err != nil {
		return repositoryGitState{}, err
	}

	return repositoryGitState{
		ObjectFormat: objectFormat,
		Head:         head,
		Base:         base,
		Tree:         tree,
		Entries:      entries,
	}, nil
}

func (inspector *repositoryInspector) validateMetadataLayout() error {
	for _, path := range []string{
		filepath.Join(inspector.gitDir, "commondir"),
		filepath.Join(inspector.gitDir, "gitdir"),
		filepath.Join(inspector.gitDir, "config.worktree"),
		filepath.Join(inspector.gitDir, "shallow"),
		filepath.Join(inspector.gitDir, "info", "sparse-checkout"),
		filepath.Join(inspector.gitDir, "objects", "info", "alternates"),
		filepath.Join(inspector.gitDir, "objects", "info", "http-alternates"),
	} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("forbidden Git metadata state: %s", filepath.Base(path))
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("Git metadata state could not be inspected")
		}
	}
	for _, path := range []string{
		inspector.gitDir,
		filepath.Join(inspector.gitDir, "objects"),
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Git metadata directory is missing or redirected")
		}
		if err := validateNoLinkMetadata(path, info); err != nil {
			return err
		}
	}
	for _, path := range []string{
		filepath.Join(inspector.gitDir, "HEAD"),
		filepath.Join(inspector.gitDir, "config"),
		filepath.Join(inspector.gitDir, "index"),
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("required Git metadata file is missing or redirected")
		}
		if err := validateNoLinkMetadata(path, info); err != nil {
			return err
		}
	}
	return validateObjectStoreLayout(filepath.Join(inspector.gitDir, "objects"))
}

func validateObjectStoreLayout(objectRoot string) error {
	return validateObjectStoreLayoutWithLimits(
		objectRoot,
		maximumGitMetadataEntries,
		maximumGitTraversalDepth,
	)
}

func validateObjectStoreLayoutWithLimits(objectRoot string, maximumEntries, maximumDepth int) error {
	budget := &gitTraversalBudget{
		maximumEntries: maximumEntries,
		maximumDepth:   maximumDepth,
	}
	err := walkGitTreeBounded(
		objectRoot,
		budget,
		func(_ string, info os.FileInfo, _ int) error {
			if !info.IsDir() && !info.Mode().IsRegular() {
				return errors.New("Git object store contains a special entry")
			}
			return nil
		},
	)
	switch {
	case errors.Is(err, errGitTraversalEntryLimit):
		return errors.New("Git object store exceeds the metadata entry bound")
	case errors.Is(err, errGitTraversalDepthLimit):
		return errors.New("Git object store exceeds the metadata depth bound")
	case errors.Is(err, errGitTraversalInvalid):
		return errors.New("Git object store traversal bound is invalid")
	default:
		return err
	}
}

func walkGitTreeBounded(
	root string,
	budget *gitTraversalBudget,
	visit func(path string, info os.FileInfo, depth int) error,
) error {
	if root == "" || visit == nil || budget == nil {
		return errGitTraversalInvalid
	}
	before, err := os.Lstat(root)
	if err != nil || !before.IsDir() {
		return errGitTraversalUnsafe
	}
	if err := validateNoLinkMetadata(root, before); err != nil {
		return err
	}

	directory, _, err := openValidatedPackageDirectory(root)
	if err != nil {
		return errGitTraversalUnsafe
	}
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = directory.Close()
		return errGitTraversalUnsafe
	}
	if err := budget.consume(0); err != nil {
		_ = directory.Close()
		return err
	}
	if err := visit(root, opened, 0); err != nil {
		_ = directory.Close()
		return err
	}

	walkErr := walkOpenedGitDirectory(directory, root, 0, budget, visit)
	closeErr := directory.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeErr != nil {
		return errGitTraversalUnsafe
	}
	return requireGitTraversalDirectoryIdentity(root, opened)
}

func walkOpenedGitDirectory(
	directory *os.File,
	directoryPath string,
	depth int,
	budget *gitTraversalBudget,
	visit func(path string, info os.FileInfo, depth int) error,
) error {
	for {
		entries, readErr := directory.ReadDir(gitTraversalBatchSize)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return errGitTraversalUnsafe
		}
		if len(entries) > gitTraversalBatchSize {
			return errGitTraversalUnsafe
		}

		childDepth := depth + 1
		for range entries {
			if err := budget.consume(childDepth); err != nil {
				return err
			}
		}
		sort.Slice(entries, func(left, right int) bool {
			return entries[left].Name() < entries[right].Name()
		})
		for _, entry := range entries {
			name := entry.Name()
			if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
				return errGitTraversalUnsafe
			}
			path := filepath.Join(directoryPath, name)
			info, err := os.Lstat(path)
			if err != nil {
				return errGitTraversalUnsafe
			}
			if err := validateNoLinkMetadata(path, info); err != nil {
				return err
			}
			if !info.IsDir() {
				if err := visit(path, info, childDepth); err != nil {
					return err
				}
				continue
			}

			child, _, err := openValidatedPackageDirectory(path)
			if err != nil {
				return errGitTraversalUnsafe
			}
			opened, statErr := child.Stat()
			if statErr != nil || !os.SameFile(info, opened) {
				_ = child.Close()
				return errGitTraversalUnsafe
			}
			visitErr := visit(path, opened, childDepth)
			if visitErr == nil {
				visitErr = walkOpenedGitDirectory(child, path, childDepth, budget, visit)
			}
			closeErr := child.Close()
			if visitErr != nil {
				return visitErr
			}
			if closeErr != nil {
				return errGitTraversalUnsafe
			}
			if err := requireGitTraversalDirectoryIdentity(path, opened); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func requireGitTraversalDirectoryIdentity(path string, expected os.FileInfo) error {
	directory, _, err := openValidatedPackageDirectory(path)
	if err != nil {
		return errGitTraversalUnsafe
	}
	actual, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(expected, actual) {
		return errGitTraversalUnsafe
	}
	return nil
}

func (inspector *repositoryInspector) rejectUnsafeConfiguration() error {
	pattern := "^(alias\\.|include\\.|includeif\\.|core\\.worktree$|core\\.fsmonitor$|core\\.sparsecheckout|index\\.sparse$|extensions\\.worktreeconfig$|extensions\\.partialclone$)"
	output, exitCode, err := inspector.runGitExit(maximumGitOutputSize, "config", "--local", "--name-only", "--get-regexp", pattern)
	if err != nil {
		return err
	}
	if exitCode == 0 || len(output) != 0 {
		return errors.New("repository contains injected or sparse Git configuration")
	}
	if exitCode != 1 {
		return errors.New("could not inspect local Git configuration")
	}
	return nil
}

func (inspector *repositoryInspector) requireGitBoolean(argument string, expected bool) error {
	value, err := inspector.gitLine("rev-parse", argument)
	if err != nil {
		return err
	}
	want := strconv.FormatBool(expected)
	if value != want {
		return fmt.Errorf("Git repository property %s does not match its required value", argument)
	}
	return nil
}

func (inspector *repositoryInspector) readTree(testedRevision string) ([]repositoryTreeEntry, error) {
	// Keep this plumbing invocation byte-for-byte aligned with RFC-0002.
	output, err := inspector.runGit(maximumGitOutputSize, "ls-tree", "-r", "-z", "--full-tree", "--long", testedRevision)
	if err != nil {
		return nil, err
	}
	records, err := splitNULTerminated(output)
	if err != nil {
		return nil, errors.New("Git tree inventory framing is invalid")
	}
	if len(records) > maximumRepositoryFiles {
		return nil, errors.New("Git tree contains too many files")
	}

	entries := make([]repositoryTreeEntry, 0, len(records))
	rawPaths := make(map[string]struct{}, len(records))
	foldedPaths := make(map[string]struct{}, len(records))
	var total int64
	for _, record := range records {
		metadata, path, found := bytes.Cut(record, []byte{'\t'})
		if !found {
			return nil, errors.New("Git tree entry has no path separator")
		}
		fields := strings.Fields(string(metadata))
		if len(fields) != 4 || fields[1] != "blob" {
			return nil, errors.New("Git tree contains a non-blob entry")
		}
		if fields[0] != "100644" && fields[0] != "100755" {
			return nil, errors.New("Git tree contains an unsupported file mode")
		}
		if !validRepositoryOID(fields[2]) {
			return nil, errors.New("Git tree contains an invalid blob object ID")
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > maximumRepositoryFileSize {
			return nil, errors.New("Git tree contains a file outside the size bound")
		}
		if total > maximumRepositoryDataSize-size {
			return nil, errors.New("Git tree exceeds the total data bound")
		}
		total += size

		portablePath := string(path)
		if err := validateRepositoryPath(portablePath); err != nil {
			return nil, err
		}
		if _, exists := rawPaths[portablePath]; exists {
			return nil, errors.New("Git tree contains a duplicate path")
		}
		rawPaths[portablePath] = struct{}{}
		folded := foldRepositoryPath(portablePath)
		if _, exists := foldedPaths[folded]; exists {
			return nil, errors.New("Git tree contains a case-fold path collision")
		}
		foldedPaths[folded] = struct{}{}
		entries = append(entries, repositoryTreeEntry{
			Path: portablePath,
			Mode: fields[0],
			OID:  fields[2],
			Size: size,
		})
	}
	for path := range rawPaths {
		for slash := strings.IndexByte(path, '/'); slash >= 0; {
			if _, exists := rawPaths[path[:slash]]; exists {
				return nil, errors.New("Git tree contains a file-directory path collision")
			}
			next := strings.IndexByte(path[slash+1:], '/')
			if next < 0 {
				break
			}
			slash += next + 1
		}
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	return entries, nil
}

func (inspector *repositoryInspector) verifyIndex(tree []repositoryTreeEntry) error {
	output, err := inspector.runGit(maximumGitOutputSize, "ls-files", "--stage", "-z", "--")
	if err != nil {
		return err
	}
	records, err := splitNULTerminated(output)
	if err != nil || len(records) != len(tree) {
		return errors.New("Git index does not contain the exact tree inventory")
	}
	byPath := make(map[string]repositoryTreeEntry, len(tree))
	for _, entry := range tree {
		byPath[entry.Path] = entry
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		metadata, pathBytes, found := bytes.Cut(record, []byte{'\t'})
		fields := strings.Fields(string(metadata))
		path := string(pathBytes)
		entry, exists := byPath[path]
		if !found || len(fields) != 3 || fields[2] != "0" || !exists || fields[0] != entry.Mode || fields[1] != entry.OID {
			return errors.New("Git index differs from the tested tree")
		}
		if _, duplicate := seen[path]; duplicate {
			return errors.New("Git index contains a duplicate path")
		}
		seen[path] = struct{}{}
	}

	flags, err := inspector.runGit(maximumGitOutputSize, "ls-files", "-v", "-z", "--")
	if err != nil {
		return err
	}
	flagRecords, err := splitNULTerminated(flags)
	if err != nil || len(flagRecords) != len(tree) {
		return errors.New("Git index flags do not cover the exact tree inventory")
	}
	seen = make(map[string]struct{}, len(flagRecords))
	for _, record := range flagRecords {
		if len(record) < 3 || record[0] != 'H' || record[1] != ' ' {
			return errors.New("assume-unchanged, skip-worktree, or non-cached index state is forbidden")
		}
		path := string(record[2:])
		if _, exists := byPath[path]; !exists {
			return errors.New("Git index flag inventory differs from the tested tree")
		}
		if _, duplicate := seen[path]; duplicate {
			return errors.New("Git index flag inventory contains a duplicate path")
		}
		seen[path] = struct{}{}
	}
	return nil
}

func (inspector *repositoryInspector) readBlobBatch(entries []repositoryTreeEntry) ([]RepositoryFile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	command := inspector.gitCommand(ctx, "cat-file", "--batch")
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, errors.New("git cat-file input could not be opened")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("git cat-file output could not be opened")
	}
	stderr := &boundedBuffer{limit: maximumGitErrorSize}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, errors.New("git cat-file could not be started")
	}
	waited := false
	defer func() {
		if !waited {
			_ = stdin.Close()
			cancel()
			_ = command.Wait()
		}
	}()

	reader := bufio.NewReaderSize(stdout, 64<<10)
	files := make([]RepositoryFile, 0, len(entries))
	for _, entry := range entries {
		if _, err := io.WriteString(stdin, entry.OID+"\n"); err != nil {
			return nil, errors.New("git cat-file request could not be written")
		}
		header, err := readBoundedLine(reader, 256)
		if err != nil {
			return nil, errors.New("git cat-file header could not be read")
		}
		wantHeader := fmt.Sprintf("%s blob %d\n", entry.OID, entry.Size)
		if header != wantHeader {
			return nil, errors.New("git cat-file object ID, type, or size differs from the tree")
		}
		if entry.Size > int64(maximumInt()) {
			return nil, errors.New("Git blob is too large for this platform")
		}
		data := make([]byte, int(entry.Size))
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, errors.New("git cat-file blob could not be read")
		}
		delimiter, err := reader.ReadByte()
		if err != nil || delimiter != '\n' {
			return nil, errors.New("git cat-file blob response is truncated")
		}
		if repositoryBlobOID(data) != entry.OID {
			return nil, errors.New("git cat-file blob bytes do not match their SHA-1 object ID")
		}
		files = append(files, RepositoryFile{
			Path:        entry.Path,
			GitMode:     entry.Mode,
			GitBlobSHA1: entry.OID,
			Size:        entry.Size,
			Data:        data,
		})
	}
	if err := stdin.Close(); err != nil {
		return nil, errors.New("git cat-file input could not be closed")
	}
	trailing, err := io.ReadAll(io.LimitReader(reader, 2))
	if err != nil || len(trailing) != 0 {
		return nil, errors.New("git cat-file emitted trailing output")
	}
	if err := command.Wait(); err != nil {
		waited = true
		return nil, gitCommandError("cat-file --batch", err, ctx.Err(), stderr)
	}
	waited = true
	if stderr.exceeded {
		return nil, errors.New("git cat-file exceeded the stderr bound")
	}
	return files, nil
}

func (inspector *repositoryInspector) verifyWorktree(files []RepositoryFile) error {
	return inspector.verifyWorktreeWithTraversalLimits(
		files,
		maximumGitWorktreeEntries,
		maximumGitTraversalDepth,
	)
}

func (inspector *repositoryInspector) verifyWorktreeWithTraversalLimits(
	files []RepositoryFile,
	maximumEntries int,
	maximumDepth int,
) error {
	expectedFiles := make(map[string]RepositoryFile, len(files))
	expectedDirectories := make(map[string]struct{})
	for _, file := range files {
		expectedFiles[file.Path] = file
		for slash := strings.IndexByte(file.Path, '/'); slash >= 0; {
			expectedDirectories[file.Path[:slash]] = struct{}{}
			next := strings.IndexByte(file.Path[slash+1:], '/')
			if next < 0 {
				break
			}
			slash += next + 1
		}
	}

	seenFiles := make(map[string]struct{}, len(files))
	seenDirectories := make(map[string]struct{}, len(expectedDirectories))
	seenFileIdentities := make(map[packageFileIdentity]struct{}, len(files))
	budget := &gitTraversalBudget{
		maximumEntries: maximumEntries,
		maximumDepth:   maximumDepth,
	}
	err := walkGitTreeBounded(inspector.root, budget, func(path string, info os.FileInfo, depth int) error {
		if depth == 0 {
			return nil
		}
		relative, err := filepath.Rel(inspector.root, path)
		if err != nil {
			return errors.New("worktree inventory path could not be normalized")
		}
		portablePath := filepath.ToSlash(relative)
		if portablePath == ".git" {
			if !info.IsDir() {
				return errors.New("Git metadata path is redirected")
			}
			return nil
		}
		if strings.HasPrefix(portablePath, ".git/") {
			if !info.IsDir() && !info.Mode().IsRegular() {
				return errors.New("Git metadata contains a special filesystem entry")
			}
			return nil
		}
		if info.IsDir() {
			if err := validateWorktreeEntryMetadata(path, info, ""); err != nil {
				return err
			}
			if _, exists := expectedDirectories[portablePath]; !exists {
				return errors.New("worktree contains an untracked or ignored directory")
			}
			seenDirectories[portablePath] = struct{}{}
			return nil
		}
		expected, exists := expectedFiles[portablePath]
		if !exists {
			return errors.New("worktree contains an untracked or ignored filesystem entry")
		}
		if !info.Mode().IsRegular() {
			return errors.New("worktree contains a special filesystem entry")
		}
		if err := validateWorktreeEntryMetadata(path, info, expected.GitMode); err != nil {
			return err
		}
		opened, err := openPackageRegularFile(path)
		if err != nil {
			return errors.New("tracked worktree file could not be opened")
		}
		openedInfo, err := opened.Stat()
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = opened.Close()
			return errors.New("worktree entry changed while it was opened")
		}
		if err := validateOpenedWorktreeFileMetadata(opened, openedInfo, expected.GitMode); err != nil {
			_ = opened.Close()
			return err
		}
		identity, identityErr := validatePackageHandleMetadata(opened, openedInfo, false)
		if identityErr != nil {
			_ = opened.Close()
			return errors.New("tracked worktree file identity is unsafe")
		}
		if _, duplicate := seenFileIdentities[identity]; duplicate {
			_ = opened.Close()
			return errors.New("worktree contains a hard-link alias")
		}
		seenFileIdentities[identity] = struct{}{}
		if openedInfo.Size() != expected.Size || openedInfo.Size() < 0 || openedInfo.Size() > maximumRepositoryFileSize {
			_ = opened.Close()
			return errors.New("worktree file size differs from the tested Git tree")
		}
		data, err := io.ReadAll(io.LimitReader(opened, maximumRepositoryFileSize+1))
		closeErr := opened.Close()
		if err != nil || closeErr != nil {
			return errors.New("could not read a tracked worktree file")
		}
		afterInfo, err := os.Lstat(path)
		if err != nil || !os.SameFile(openedInfo, afterInfo) || afterInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("worktree entry changed while it was read")
		}
		if err := validateWorktreeEntryMetadata(path, afterInfo, expected.GitMode); err != nil {
			return err
		}
		if !bytes.Equal(data, expected.Data) {
			return errors.New("tracked worktree bytes differ from the tested Git blob")
		}
		seenFiles[portablePath] = struct{}{}
		return nil
	})
	switch {
	case errors.Is(err, errGitTraversalEntryLimit):
		return errors.New("worktree exceeds the inventory entry bound")
	case errors.Is(err, errGitTraversalDepthLimit):
		return errors.New("worktree exceeds the inventory depth bound")
	case errors.Is(err, errGitTraversalInvalid):
		return errors.New("worktree inventory traversal bound is invalid")
	case errors.Is(err, errGitTraversalUnsafe):
		return errors.New("worktree inventory could not be traversed safely")
	case err != nil:
		return err
	}
	if len(seenFiles) != len(expectedFiles) || len(seenDirectories) != len(expectedDirectories) {
		return errors.New("worktree is missing a tracked file or directory")
	}
	return nil
}

func validateModuleSource(files []RepositoryFile) error {
	archiveFiles := make([]archiveFile, len(files))
	for index, file := range files {
		archiveFiles[index] = archiveFile{
			Path:    file.Path,
			GitMode: file.GitMode,
			Data:    file.Data,
		}
	}
	return validateSourceModule(archiveFiles)
}

func (inspector *repositoryInspector) gitCommand(ctx context.Context, arguments ...string) *exec.Cmd {
	global := []string{
		"--no-replace-objects",
		"--git-dir=" + inspector.gitDir,
		"--work-tree=" + inspector.root,
		"-c", "core.fsmonitor=false",
		"-c", "core.untrackedCache=false",
		"-c", "core.preloadIndex=false",
		"-c", "core.abbrev=40",
		"-c", "color.ui=false",
	}
	command := exec.CommandContext(ctx, inspector.gitPath, append(global, arguments...)...)
	command.Dir = inspector.root
	command.Env = append([]string(nil), inspector.env...)
	return command
}

func (inspector *repositoryInspector) runGit(limit int64, arguments ...string) ([]byte, error) {
	output, exitCode, err := inspector.runGitExit(limit, arguments...)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("git %s exited with status %d", arguments[0], exitCode)
	}
	return output, nil
}

func (inspector *repositoryInspector) runGitExit(limit int64, arguments ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	command := inspector.gitCommand(ctx, arguments...)
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: maximumGitErrorSize}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, -1, errors.New("Git command exceeded its output bound")
	}
	if err == nil {
		return append([]byte(nil), stdout.Bytes()...), 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return append([]byte(nil), stdout.Bytes()...), exitError.ExitCode(), nil
	}
	return nil, -1, gitCommandError(arguments[0], err, ctx.Err(), stderr)
}

func (inspector *repositoryInspector) gitLine(arguments ...string) (string, error) {
	output, err := inspector.runGit(1024, arguments...)
	if err != nil {
		return "", err
	}
	if len(output) < 2 || output[len(output)-1] != '\n' || bytes.ContainsAny(output[:len(output)-1], "\r\n\x00") {
		return "", errors.New("Git command did not return one canonical line")
	}
	return string(output[:len(output)-1]), nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := buffer.limit - int64(buffer.Len())
	if remaining <= 0 {
		buffer.exceeded = true
		return originalLength, nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
		buffer.exceeded = true
	}
	_, _ = buffer.Buffer.Write(data)
	return originalLength, nil
}

func gitCommandError(name string, commandErr, contextErr error, stderr *boundedBuffer) error {
	_ = commandErr
	_ = stderr
	if contextErr != nil {
		return fmt.Errorf("git %s timed out or was cancelled", name)
	}
	return fmt.Errorf("git %s failed", name)
}

func splitNULTerminated(output []byte) ([][]byte, error) {
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != 0 {
		return nil, errors.New("NUL-terminated Git output is truncated")
	}
	parts := bytes.Split(output[:len(output)-1], []byte{0})
	for _, part := range parts {
		if len(part) == 0 {
			return nil, errors.New("NUL-terminated Git output contains an empty record")
		}
	}
	return parts, nil
}

func readBoundedLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for len(line) <= limit {
		fragment, err := reader.ReadSlice('\n')
		line = append(line, fragment...)
		if err == nil {
			if len(line) > limit {
				return "", errors.New("line exceeds its bound")
			}
			return string(line), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
	return "", errors.New("line exceeds its bound")
}

func validRepositoryOID(value string) bool {
	if len(value) != 2*sha1.Size {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha1.Size {
		return false
	}
	for _, current := range value {
		if current >= 'A' && current <= 'F' {
			return false
		}
	}
	return true
}

func repositoryBlobOID(data []byte) string {
	digest := sha1.New() // Git SHA-1 object identity, not a security digest.
	_, _ = fmt.Fprintf(digest, "blob %d%c", len(data), byte(0))
	_, _ = digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil))
}

func validateRepositoryPath(path string) error {
	if len(path) == 0 || len(path) > 255 {
		return errors.New("Git tree path length is outside the portable profile")
	}
	componentStart := 0
	for index := 0; index <= len(path); index++ {
		if index < len(path) && path[index] != '/' {
			current := path[index]
			if current < 0x20 || current > 0x7e {
				return errors.New("Git tree path contains a non-printable ASCII byte")
			}
			switch current {
			case '\\', ':', '*', '?', '"', '<', '>', '|':
				return errors.New("Git tree path contains a forbidden byte")
			}
			continue
		}
		component := path[componentStart:index]
		if component == "" || component == "." || component == ".." {
			return errors.New("Git tree path contains an invalid component")
		}
		if component[len(component)-1] == '.' || component[len(component)-1] == ' ' || reservedRepositoryComponent(component) {
			return errors.New("Git tree path contains a non-portable component")
		}
		componentStart = index + 1
	}
	return nil
}

func reservedRepositoryComponent(component string) bool {
	base := component
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9'
}

func foldRepositoryPath(path string) string {
	folded := []byte(path)
	for index, current := range folded {
		if current >= 'A' && current <= 'Z' {
			folded[index] = current + ('a' - 'A')
		}
	}
	return string(folded)
}

func sameRepositoryState(left, right repositoryGitState) bool {
	if left.ObjectFormat != right.ObjectFormat || left.Head != right.Head || left.Base != right.Base || left.Tree != right.Tree || len(left.Entries) != len(right.Entries) {
		return false
	}
	for index := range left.Entries {
		if left.Entries[index] != right.Entries[index] {
			return false
		}
	}
	return true
}

func sameCanonicalPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func maximumInt() int {
	return int(^uint(0) >> 1)
}
