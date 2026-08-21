package sourcequalification

// Production contract under test:
//
//	func assembleQualificationTools(packageDir, linuxController, windowsController, outputDir string) (toolManifestDigest string, err error)
//
// The operation must verify the exact four-file package before it trusts its
// subject or controller bindings. It then inspects each controller's digest and
// Go build information through one fixed regular-file handle and publishes an
// exact, private, no-replace three-file tool directory.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

const toolAssemblyManifestFilename = "source-qualification-tool-manifest-v1.json"

type toolAssemblyFixture struct {
	root                    string
	subject                 Subject
	archive                 []byte
	manifest                []byte
	packageDir              string
	linuxController         string
	windowsController       string
	wrongRevisionController string
	legacySubject           Subject
	legacyArchive           []byte
	legacyManifest          []byte
	legacyPackageDir        string
	legacyLinuxController   string
	legacyWindowsController string
}

type toolAssemblyCase struct {
	root              string
	packageDir        string
	linuxController   string
	windowsController string
	outputDir         string
}

func TestAssembleQualificationToolsContract(t *testing.T) {
	fixture := newToolAssemblyFixture(t)

	t.Run("publishes exact private bound tool set", func(t *testing.T) {
		input := newToolAssemblyCase(
			t,
			fixture.packageDir,
			fixture.linuxController,
			fixture.windowsController,
		)
		linuxBytes := toolAssemblyRead(t, input.linuxController)
		windowsBytes := toolAssemblyRead(t, input.windowsController)

		digest, err := assembleQualificationTools(
			input.packageDir,
			input.linuxController,
			input.windowsController,
			input.outputDir,
		)
		if err != nil {
			t.Fatalf("assembleQualificationTools: %v", err)
		}

		manifestPath := filepath.Join(input.outputDir, toolAssemblyManifestFilename)
		manifestBytes := toolAssemblyRead(t, manifestPath)
		if digest != sha256Digest(manifestBytes) {
			t.Fatalf("tool manifest digest = %q, want digest of exact manifest bytes", digest)
		}
		if _, err := parseCanonicalToolManifest(
			manifestBytes,
			fixture.subject,
			linuxBytes,
			windowsBytes,
		); err != nil {
			t.Fatalf("published tool manifest is not canonical and bound: %v", err)
		}

		want := []packageFileSpec{
			{name: toolManifestLinuxPath, maxBytes: int64(len(linuxBytes)), expected: linuxBytes},
			{name: toolManifestWindowsPath, maxBytes: int64(len(windowsBytes)), expected: windowsBytes},
			{name: toolAssemblyManifestFilename, maxBytes: toolManifestMaxBytes, expected: manifestBytes},
		}
		published, err := readExactPackageDirectory(input.outputDir, want)
		if err != nil {
			t.Fatalf("published tool directory is not exact and private: %v", err)
		}
		for _, specification := range want {
			if !bytes.Equal(published.files[specification.name], specification.expected) {
				t.Fatalf("published tool %q differs from its verified input", specification.name)
			}
		}

		toolAssemblyWrite(t, input.linuxController, []byte("mutated controller input\n"))
		toolAssemblyWrite(
			t,
			filepath.Join(input.packageDir, packageFilesManifestName),
			[]byte("mutated package input\n"),
		)
		toolAssemblyRequireBytes(
			t,
			filepath.Join(input.outputDir, toolManifestLinuxPath),
			linuxBytes,
		)
		toolAssemblyRequireBytes(t, manifestPath, manifestBytes)
	})

	t.Run("rejects non-exact or substituted inputs without output", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(*testing.T) *toolAssemblyCase
			mutate func(*testing.T, *toolAssemblyCase)
		}{
			{
				name: "missing package member",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyRemove(t, filepath.Join(input.packageDir, packageFilesManifestName))
				},
			},
			{
				name: "extra package member",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyWritePrivate(t, filepath.Join(input.packageDir, "unexpected.json"), []byte("{}"), false)
				},
			},
			{
				name: "tampered package archive",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyWrite(t, filepath.Join(input.packageDir, packageFilesArchiveName), []byte("not canonical ustar"))
				},
			},
			{
				name: "package member hard link",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyReplaceWithHardLink(t, filepath.Join(input.packageDir, packageFilesLinuxReceiptName), input.root)
				},
			},
			{
				name: "package member reparse or symbolic link",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyReplaceWithSymlink(t, filepath.Join(input.packageDir, packageFilesWindowsReceiptName), input.root)
				},
			},
			{
				name: "lane controllers substituted for each other",
				setup: func(t *testing.T) *toolAssemblyCase {
					input := newToolAssemblyCase(t, fixture.packageDir, fixture.windowsController, fixture.linuxController)
					toolAssemblyWriteQualificationPackage(
						t,
						input.packageDir,
						fixture.subject,
						fixture.archive,
						fixture.manifest,
						toolAssemblyRead(t, input.linuxController),
						toolAssemblyRead(t, input.windowsController),
					)
					return input
				},
			},
			{
				name: "controller built from wrong revision",
				setup: func(t *testing.T) *toolAssemblyCase {
					input := newToolAssemblyCase(t, fixture.packageDir, fixture.wrongRevisionController, fixture.windowsController)
					toolAssemblyWriteQualificationPackage(
						t,
						input.packageDir,
						fixture.subject,
						fixture.archive,
						fixture.manifest,
						toolAssemblyRead(t, input.linuxController),
						toolAssemblyRead(t, input.windowsController),
					)
					return input
				},
			},
			{
				name: "legacy module controllers",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(
						t,
						fixture.legacyPackageDir,
						fixture.legacyLinuxController,
						fixture.legacyWindowsController,
					)
				},
			},
			{
				name: "non-Go controller with matching receipt digest",
				setup: func(t *testing.T) *toolAssemblyCase {
					input := newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
					toolAssemblyWrite(t, input.linuxController, []byte("substituted non-Go controller\n"))
					toolAssemblyWriteQualificationPackage(
						t,
						input.packageDir,
						fixture.subject,
						fixture.archive,
						fixture.manifest,
						toolAssemblyRead(t, input.linuxController),
						toolAssemblyRead(t, input.windowsController),
					)
					return input
				},
			},
			{
				name: "controller hard link",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyReplaceWithHardLink(t, input.linuxController, input.root)
				},
			},
			{
				name: "controller reparse or symbolic link",
				setup: func(t *testing.T) *toolAssemblyCase {
					return newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
				},
				mutate: func(t *testing.T, input *toolAssemblyCase) {
					toolAssemblyReplaceWithSymlink(t, input.windowsController, input.root)
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				input := test.setup(t)
				if test.mutate != nil {
					test.mutate(t, input)
				}
				digest, err := assembleQualificationTools(
					input.packageDir,
					input.linuxController,
					input.windowsController,
					input.outputDir,
				)
				if err == nil {
					t.Fatal("assembleQualificationTools accepted an invalid or substituted input")
				}
				if digest != "" {
					t.Fatalf("failed assembly returned tool manifest digest %q", digest)
				}
				packageFilesRequireAbsent(t, input.outputDir)
			})
		}
	})

	t.Run("never replaces a preexisting destination", func(t *testing.T) {
		input := newToolAssemblyCase(t, fixture.packageDir, fixture.linuxController, fixture.windowsController)
		toolAssemblyMkdirPrivate(t, input.outputDir)
		sentinel := filepath.Join(input.outputDir, "operator-owned.txt")
		toolAssemblyWritePrivate(t, sentinel, []byte("do not replace\n"), false)

		digest, err := assembleQualificationTools(
			input.packageDir,
			input.linuxController,
			input.windowsController,
			input.outputDir,
		)
		if err == nil {
			t.Fatal("assembleQualificationTools replaced a preexisting destination")
		}
		if digest != "" {
			t.Fatalf("failed no-replace assembly returned digest %q", digest)
		}
		entries, readErr := os.ReadDir(input.outputDir)
		if readErr != nil || len(entries) != 1 || entries[0].Name() != "operator-owned.txt" {
			t.Fatalf("preexisting destination changed: entries=%v err=%v", entries, readErr)
		}
		toolAssemblyRequireBytes(t, sentinel, []byte("do not replace\n"))
	})
}

func newToolAssemblyFixture(t *testing.T) *toolAssemblyFixture {
	t.Helper()
	if runtime.Version() != toolManifestGoVersion {
		t.Fatalf("tool assembly fixtures require %s, running %s", toolManifestGoVersion, runtime.Version())
	}
	root := filepath.Join(t.TempDir(), "tool-assembly")
	toolAssemblyMkdirPrivate(t, root)
	outputs := filepath.Join(root, "controller-outputs")
	toolAssemblyMkdirPrivate(t, outputs)

	canonicalRoot := filepath.Join(root, "canonical-source")
	toolAssemblyCreateModule(t, canonicalRoot, canonicalModulePath)
	canonicalRevision := toolAssemblyCommit(t, canonicalRoot, "canonical controller")
	linuxController := filepath.Join(outputs, "canonical-linux")
	windowsController := filepath.Join(outputs, "canonical-windows.exe")
	toolAssemblyBuildController(t, canonicalRoot, linuxController, "linux")
	toolAssemblyBuildController(t, canonicalRoot, windowsController, "windows")

	toolAssemblyWritePrivate(t, filepath.Join(canonicalRoot, "revision-marker.txt"), []byte("next revision\n"), false)
	wrongRevision := toolAssemblyCommit(t, canonicalRoot, "different revision")
	if wrongRevision == canonicalRevision {
		t.Fatal("controller fixture revisions are not distinct")
	}
	wrongRevisionController := filepath.Join(outputs, "wrong-revision-linux")
	toolAssemblyBuildController(t, canonicalRoot, wrongRevisionController, "linux")

	legacyRoot := filepath.Join(root, "legacy-source")
	toolAssemblyCreateModule(t, legacyRoot, legacyModulePath)
	legacyRevision := toolAssemblyCommit(t, legacyRoot, "legacy controller")
	legacyLinuxController := filepath.Join(outputs, "legacy-linux")
	legacyWindowsController := filepath.Join(outputs, "legacy-windows.exe")
	toolAssemblyBuildController(t, legacyRoot, legacyLinuxController, "linux")
	toolAssemblyBuildController(t, legacyRoot, legacyWindowsController, "windows")

	subject, archive, manifest := toolAssemblySourcePackage(t, canonicalRevision)
	packageDir := filepath.Join(root, "canonical-package")
	toolAssemblyWriteQualificationPackage(
		t,
		packageDir,
		subject,
		archive,
		manifest,
		toolAssemblyRead(t, linuxController),
		toolAssemblyRead(t, windowsController),
	)
	legacySubject, legacyArchive, legacyManifest := toolAssemblySourcePackage(t, legacyRevision)
	legacyPackageDir := filepath.Join(root, "legacy-package")
	toolAssemblyWriteQualificationPackage(
		t,
		legacyPackageDir,
		legacySubject,
		legacyArchive,
		legacyManifest,
		toolAssemblyRead(t, legacyLinuxController),
		toolAssemblyRead(t, legacyWindowsController),
	)

	return &toolAssemblyFixture{
		root:                    root,
		subject:                 subject,
		archive:                 archive,
		manifest:                manifest,
		packageDir:              packageDir,
		linuxController:         linuxController,
		windowsController:       windowsController,
		wrongRevisionController: wrongRevisionController,
		legacySubject:           legacySubject,
		legacyArchive:           legacyArchive,
		legacyManifest:          legacyManifest,
		legacyPackageDir:        legacyPackageDir,
		legacyLinuxController:   legacyLinuxController,
		legacyWindowsController: legacyWindowsController,
	}
}

func newToolAssemblyCase(
	t *testing.T,
	packageDir, linuxController, windowsController string,
) *toolAssemblyCase {
	t.Helper()
	root := filepath.Join(t.TempDir(), "tool-assembly-case")
	toolAssemblyMkdirPrivate(t, root)
	input := &toolAssemblyCase{
		root:              root,
		packageDir:        filepath.Join(root, "package"),
		linuxController:   filepath.Join(root, "linux-controller"),
		windowsController: filepath.Join(root, "windows-controller.exe"),
		outputDir:         filepath.Join(root, "tools"),
	}
	toolAssemblyCopyDirectory(t, packageDir, input.packageDir)
	toolAssemblyCopyPrivateFile(t, linuxController, input.linuxController)
	toolAssemblyCopyPrivateFile(t, windowsController, input.windowsController)
	return input
}

func toolAssemblySourcePackage(t *testing.T, testedRevision string) (Subject, []byte, []byte) {
	t.Helper()
	files := []archiveFile{
		{Path: "go.mod", GitMode: "100644", Data: []byte("module github.com/taipei49314/RepoPassport\n")},
	}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatalf("reconstruct tool assembly source tree: %v", err)
	}
	subject := Subject{
		Repository:      canonicalRepositoryURL,
		ModulePath:      canonicalModulePath,
		ModuleVersion:   canonicalModuleVersion,
		GitObjectFormat: "sha1",
		BaseRevision:    "0123456789abcdef0123456789abcdef01234567",
		TestedRevision:  testedRevision,
		TreeSHA:         tree,
	}
	archive, manifest, err := buildSourcePackage(subject, files)
	if err != nil {
		t.Fatalf("build tool assembly source package: %v", err)
	}
	return subject, archive, manifest
}

func toolAssemblyWriteQualificationPackage(
	t *testing.T,
	directory string,
	subject Subject,
	archive, manifest, linuxController, windowsController []byte,
) {
	t.Helper()
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		toolAssemblyMkdirPrivate(t, directory)
	} else if err != nil {
		t.Fatalf("inspect package fixture directory: %v", err)
	}
	linuxReceipt := toolAssemblyReceipt(t, LaneLinuxAMD64, subject, archive, manifest, linuxController)
	windowsReceipt := toolAssemblyReceipt(t, LaneWindowsAMD64, subject, archive, manifest, windowsController)
	for name, raw := range map[string][]byte{
		packageFilesArchiveName:        archive,
		packageFilesManifestName:       manifest,
		packageFilesLinuxReceiptName:   linuxReceipt,
		packageFilesWindowsReceiptName: windowsReceipt,
	} {
		toolAssemblyWritePrivate(t, filepath.Join(directory, name), raw, false)
	}
}

func toolAssemblyReceipt(
	t *testing.T,
	lane Lane,
	subject Subject,
	archive, manifest, controller []byte,
) []byte {
	t.Helper()
	document := receiptParserDocument(lane, archive, manifest)
	subjectDocument := receiptParserObject(document, "subject")
	subjectDocument["baseRevision"] = subject.BaseRevision
	subjectDocument["dirty"] = subject.Dirty
	subjectDocument["gitObjectFormat"] = subject.GitObjectFormat
	subjectDocument["modulePath"] = subject.ModulePath
	subjectDocument["moduleVersion"] = subject.ModuleVersion
	subjectDocument["repository"] = subject.Repository
	subjectDocument["testedRevision"] = subject.TestedRevision
	subjectDocument["treeSHA"] = subject.TreeSHA

	run := receiptParserObject(document, "run")
	run["headSHA"] = subject.TestedRevision
	identity := RunIdentity{
		WorkflowRepository: run["workflowRepository"].(string),
		WorkflowPath:       run["workflowPath"].(string),
		Event:              run["event"].(string),
		Ref:                run["ref"].(string),
		WorkflowRunID:      run["workflowRunId"].(string),
		WorkflowRunAttempt: run["workflowRunAttempt"].(int),
		TestedRevision:     subject.TestedRevision,
	}
	qualificationRunID := QualificationRunID(identity)
	run["qualificationRunId"] = qualificationRunID
	attempt := receiptParserObject(document, "attempt")
	attempt["attemptId"] = AttemptID(qualificationRunID, lane, attempt["ordinal"].(int))

	controllerDocument := receiptParserObject(document, "controller")
	controllerDocument["sha256"] = sha256Digest(controller)
	controllerDocument["vcsRevision"] = subject.TestedRevision
	for _, rawGate := range receiptParserArray(document, "gates") {
		gate := rawGate.(map[string]any)
		argv := gate["argv"].([]string)
		for index, value := range argv {
			if value == "89abcdef0123456789abcdef0123456789abcdef" {
				argv[index] = subject.TestedRevision
			}
		}
	}

	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		t.Fatalf("marshal tool assembly receipt: %v", err)
	}
	return raw
}

func toolAssemblyCreateModule(t *testing.T, root, modulePath string) {
	t.Helper()
	directory := filepath.Join(root, "internal", "sourcequalification", "cmd", "repopass-source-qualify")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create controller fixture source: %v", err)
	}
	toolAssemblyWrite(t, filepath.Join(directory, "main.go"), []byte("package main\nfunc main() {}\n"))
	toolAssemblyWrite(t, filepath.Join(root, "go.mod"), []byte("module "+modulePath+"\n\ngo 1.26.0\n"))
	toolAssemblyRun(t, root, "git", "init", "-q")
	toolAssemblyRun(t, root, "git", "config", "user.name", "RepoPassport source qualification test")
	toolAssemblyRun(t, root, "git", "config", "user.email", "source-qualification@example.invalid")
}

func toolAssemblyCommit(t *testing.T, root, message string) string {
	t.Helper()
	toolAssemblyRun(t, root, "git", "add", "--", ".")
	toolAssemblyRun(t, root, "git", "commit", "-q", "-m", message)
	return strings.TrimSpace(toolAssemblyRun(t, root, "git", "rev-parse", "HEAD"))
}

func toolAssemblyBuildController(t *testing.T, root, output, goos string) {
	t.Helper()
	buildOutput := output + ".build"
	goExecutable := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goExecutable += ".exe"
	}
	command := exec.Command(
		goExecutable,
		"build",
		"-buildvcs=true",
		"-trimpath",
		"-o",
		buildOutput,
		"./internal/sourcequalification/cmd/repopass-source-qualify",
	)
	command.Dir = root
	command.Env = toolAssemblyEnvironment(map[string]string{
		"CGO_ENABLED": "0",
		"GOARCH":      "amd64",
		"GOENV":       "off",
		"GOFLAGS":     "",
		"GOTOOLCHAIN": "local",
		"GOWORK":      "off",
		"GOOS":        goos,
		"GOCACHEPROG": "",
		"GOTELEMETRY": "off",
	})
	if outputBytes, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s controller fixture: %v: %s", goos, err, outputBytes)
	}
	controller := toolAssemblyRead(t, buildOutput)
	toolAssemblyRemove(t, buildOutput)
	toolAssemblyWritePrivate(t, output, controller, false)
}

func toolAssemblyEnvironment(overrides map[string]string) []string {
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[strings.ToUpper(key)]; !replaced {
			environment = append(environment, entry)
		}
	}
	for _, key := range []string{
		"CGO_ENABLED", "GOARCH", "GOENV", "GOFLAGS", "GOTOOLCHAIN", "GOWORK",
		"GOOS", "GOCACHEPROG", "GOTELEMETRY",
	} {
		environment = append(environment, key+"="+overrides[key])
	}
	return environment
}

func toolAssemblyRun(t *testing.T, directory, name string, args ...string) string {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s fixture command failed: %v: %s", name, err, output)
	}
	return string(output)
}

func toolAssemblyCopyDirectory(t *testing.T, source, destination string) {
	t.Helper()
	toolAssemblyMkdirPrivate(t, destination)
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("read tool assembly package fixture: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("package fixture unexpectedly contains directory %q", entry.Name())
		}
		toolAssemblyCopyPrivateFile(t, filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name()))
	}
}

func toolAssemblyCopyPrivateFile(t *testing.T, source, destination string) {
	t.Helper()
	toolAssemblyWritePrivate(t, destination, toolAssemblyRead(t, source), false)
}

func toolAssemblyMkdirPrivate(t *testing.T, path string) {
	t.Helper()
	if err := toolAssemblyCreatePrivateDirectory(path); err != nil {
		t.Fatalf("create private tool assembly directory: %v", err)
	}
}

func toolAssemblyWritePrivate(t *testing.T, path string, raw []byte, directory bool) {
	t.Helper()
	if directory {
		t.Fatal("toolAssemblyWritePrivate only writes regular files")
	}
	if err := toolAssemblyCreatePrivateFile(path, raw); err != nil {
		t.Fatalf("write private tool assembly fixture %q: %v", filepath.Base(path), err)
	}
}

func toolAssemblyWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write tool assembly fixture %q: %v", filepath.Base(path), err)
	}
}

func toolAssemblyRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tool assembly fixture %q: %v", filepath.Base(path), err)
	}
	return raw
}

func toolAssemblyRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove tool assembly fixture %q: %v", filepath.Base(path), err)
	}
}

func toolAssemblyReplaceWithHardLink(t *testing.T, path, root string) {
	t.Helper()
	external := filepath.Join(root, "hardlink-target-"+filepath.Base(path))
	if err := os.Rename(path, external); err != nil {
		t.Fatalf("move hard-link target: %v", err)
	}
	if err := os.Link(external, path); err != nil {
		t.Skipf("hard links unavailable on this runner: %v", err)
	}
}

func toolAssemblyReplaceWithSymlink(t *testing.T, path, root string) {
	t.Helper()
	external := filepath.Join(root, "symlink-target-"+filepath.Base(path))
	if err := os.Rename(path, external); err != nil {
		t.Fatalf("move symbolic-link target: %v", err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Skipf("symbolic links unavailable on this runner: %v", err)
	}
}

func toolAssemblyRequireBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got := toolAssemblyRead(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("retained tool assembly path %q was modified", filepath.Base(path))
	}
}
