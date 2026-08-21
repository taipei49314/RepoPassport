package sourcequalification

// Exported internal-only controller facade under test:
//
//	type ControllerResult struct {
//		Code                string
//		QualificationStatus string
//		SHA256              string
//		TestedRevision      string
//		TreeSHA             string
//	}
//	type AssembleRequest struct {
//		LinuxDir                   string
//		WindowsDir                 string
//		ExpectedBaseRevision       string
//		ExpectedTestedRevision     string
//		ExpectedTreeSHA            string
//		ExpectedQualificationRunID string
//		ExpectedWorkflowRunID      string
//		ExpectedWorkflowRunAttempt int64
//		OutputDir                  string
//	}
//	func Assemble(AssembleRequest) (ControllerResult, error)
//	type AssembleToolsRequest struct {
//		PackageDir        string
//		LinuxController   string
//		WindowsController string
//		OutputDir         string
//	}
//	func AssembleTools(AssembleToolsRequest) (ControllerResult, error)
//	type VerifyIntegrityRequest struct { PackageDir string }
//	func VerifyIntegrity(VerifyIntegrityRequest) (ControllerResult, error)
//	type VerifySubjectRequest struct {
//		PackageDir                 string
//		ExpectedRepository         string
//		ExpectedBaseRevision       string
//		ExpectedTestedRevision     string
//		ExpectedTreeSHA            string
//		ExpectedQualificationRunID string
//		ExpectedWorkflowRunID      string
//		ExpectedWorkflowRunAttempt int64
//		ExpectedPackageDigest      string
//		ToolManifestPath           string
//		ExpectedToolManifestDigest string
//		ExpectedExecutableDigest   string
//	}
//	func VerifySubject(VerifySubjectRequest) (ControllerResult, error)
//
// The facade exposes one typed operation per frozen command. It deliberately
// has no caller-selected command name, registry, result status, diagnostic
// code, executable path, or arbitrary operation callback.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestControllerFacadeExactTypedSurface(t *testing.T) {
	var _ int64 = AssembleRequest{}.ExpectedWorkflowRunAttempt
	var _ int64 = VerifySubjectRequest{}.ExpectedWorkflowRunAttempt

	controllerFacadeRequireFields(t, ControllerResult{}, []string{
		"Code",
		"QualificationStatus",
		"SHA256",
		"TestedRevision",
		"TreeSHA",
	})
	controllerFacadeRequireFields(t, AssembleRequest{}, []string{
		"LinuxDir",
		"WindowsDir",
		"ExpectedBaseRevision",
		"ExpectedTestedRevision",
		"ExpectedTreeSHA",
		"ExpectedQualificationRunID",
		"ExpectedWorkflowRunID",
		"ExpectedWorkflowRunAttempt",
		"OutputDir",
	})
	controllerFacadeRequireFields(t, AssembleToolsRequest{}, []string{
		"PackageDir",
		"LinuxController",
		"WindowsController",
		"OutputDir",
	})
	controllerFacadeRequireFields(t, VerifyIntegrityRequest{}, []string{
		"PackageDir",
	})
	controllerFacadeRequireFields(t, VerifySubjectRequest{}, []string{
		"PackageDir",
		"ExpectedRepository",
		"ExpectedBaseRevision",
		"ExpectedTestedRevision",
		"ExpectedTreeSHA",
		"ExpectedQualificationRunID",
		"ExpectedWorkflowRunID",
		"ExpectedWorkflowRunAttempt",
		"ExpectedPackageDigest",
		"ToolManifestPath",
		"ExpectedToolManifestDigest",
		"ExpectedExecutableDigest",
	})
}

func TestControllerFacadeAssembleChecksEveryExpectedIdentityBeforePublication(t *testing.T) {
	t.Run("success reports only fixed public facts", func(t *testing.T) {
		fixture := newPackageFilesFixture(t)
		request, subject := controllerFacadeAssembleRequest(t, fixture)
		wantDigest := qualificationPackageDigest(
			fixture.archive,
			fixture.manifest,
			fixture.linuxReceipt,
			fixture.windowsReceipt,
		)

		result, err := Assemble(request)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		controllerFacadeRequireResult(t, result, ControllerResult{
			Code:                "SOURCE_QUAL_OK",
			QualificationStatus: "PASS",
			SHA256:              wantDigest,
			TestedRevision:      subject.TestedRevision,
			TreeSHA:             subject.TreeSHA,
		})
	})

	mutations := []struct {
		name   string
		mutate func(*AssembleRequest)
	}{
		{"base revision", func(request *AssembleRequest) {
			request.ExpectedBaseRevision = strings.Repeat("a", 40)
		}},
		{"tested revision", func(request *AssembleRequest) {
			request.ExpectedTestedRevision = strings.Repeat("b", 40)
		}},
		{"tree", func(request *AssembleRequest) {
			request.ExpectedTreeSHA = strings.Repeat("c", 40)
		}},
		{"qualification run", func(request *AssembleRequest) {
			request.ExpectedQualificationRunID = "sha256:" + strings.Repeat("1", 64)
		}},
		{"workflow run", func(request *AssembleRequest) {
			request.ExpectedWorkflowRunID = "987654321"
		}},
		{"workflow attempt", func(request *AssembleRequest) {
			request.ExpectedWorkflowRunAttempt = 2
		}},
	}
	for _, test := range mutations {
		t.Run("mismatch/"+test.name, func(t *testing.T) {
			fixture := newPackageFilesFixture(t)
			request, _ := controllerFacadeAssembleRequest(t, fixture)
			test.mutate(&request)
			beforeLinux := controllerFacadeSnapshotTree(t, fixture.linuxDir)
			beforeWindows := controllerFacadeSnapshotTree(t, fixture.windowsDir)

			published := false
			originalSync := syncPublishedPackageParent
			syncPublishedPackageParent = func(*os.File) error {
				published = true
				return nil
			}
			t.Cleanup(func() { syncPublishedPackageParent = originalSync })

			result, err := Assemble(request)
			controllerFacadeRequireFailure(
				t,
				result,
				err,
				"SOURCE_QUAL_SUBJECT_MISMATCH",
				fixture.root,
				request.OutputDir,
			)
			if published {
				t.Fatal("identity mismatch reached package publication")
			}
			controllerFacadeRequireAbsent(t, request.OutputDir)
			controllerFacadeRequireSnapshot(t, fixture.linuxDir, beforeLinux)
			controllerFacadeRequireSnapshot(t, fixture.windowsDir, beforeWindows)
		})
	}

	t.Run("preexisting output is never replaced", func(t *testing.T) {
		fixture := newPackageFilesFixture(t)
		request, _ := controllerFacadeAssembleRequest(t, fixture)
		if err := os.Mkdir(request.OutputDir, 0o700); err != nil {
			t.Fatalf("create preexisting output: %v", err)
		}
		sentinel := filepath.Join(request.OutputDir, "operator-owned.txt")
		packageFilesWrite(t, sentinel, []byte("retain me\n"))
		beforeLinux := controllerFacadeSnapshotTree(t, fixture.linuxDir)
		beforeWindows := controllerFacadeSnapshotTree(t, fixture.windowsDir)

		result, err := Assemble(request)
		controllerFacadeRequireFailure(
			t,
			result,
			err,
			"SOURCE_QUAL_DESTINATION_EXISTS",
			fixture.root,
			request.OutputDir,
		)
		packageFilesRequireBytes(t, sentinel, []byte("retain me\n"))
		entries, readErr := os.ReadDir(request.OutputDir)
		if readErr != nil || len(entries) != 1 || entries[0].Name() != "operator-owned.txt" {
			t.Fatalf("preexisting output changed: entries=%v err=%v", entries, readErr)
		}
		controllerFacadeRequireSnapshot(t, fixture.linuxDir, beforeLinux)
		controllerFacadeRequireSnapshot(t, fixture.windowsDir, beforeWindows)
	})
}

func TestControllerFacadeToolsAndOfflineOperations(t *testing.T) {
	fixture := newControllerFacadeToolFixture(t)

	t.Run("assemble tools success", func(t *testing.T) {
		outputDir := filepath.Join(fixture.root, "tools-success")
		result, err := AssembleTools(AssembleToolsRequest{
			PackageDir:        fixture.packageDir,
			LinuxController:   fixture.linuxController,
			WindowsController: fixture.windowsController,
			OutputDir:         outputDir,
		})
		if err != nil {
			t.Fatalf("AssembleTools: %v", err)
		}
		manifest := toolAssemblyRead(t, filepath.Join(outputDir, qualificationToolManifestFilename))
		controllerFacadeRequireResult(t, result, ControllerResult{
			Code:                "SOURCE_QUAL_OK",
			QualificationStatus: "PASS",
			SHA256:              sha256Digest(manifest),
			TestedRevision:      fixture.subject.TestedRevision,
			TreeSHA:             fixture.subject.TreeSHA,
		})
	})

	t.Run("assemble tools preserves preexisting output and inputs", func(t *testing.T) {
		outputDir := filepath.Join(fixture.root, "tools-preexisting-private-marker")
		toolAssemblyMkdirPrivate(t, outputDir)
		sentinel := filepath.Join(outputDir, "operator-owned.txt")
		toolAssemblyWritePrivate(t, sentinel, []byte("retain tools\n"), false)
		beforePackage := controllerFacadeSnapshotTree(t, fixture.packageDir)
		beforeLinux := toolAssemblyRead(t, fixture.linuxController)
		beforeWindows := toolAssemblyRead(t, fixture.windowsController)

		result, err := AssembleTools(AssembleToolsRequest{
			PackageDir:        fixture.packageDir,
			LinuxController:   fixture.linuxController,
			WindowsController: fixture.windowsController,
			OutputDir:         outputDir,
		})
		controllerFacadeRequireFailure(
			t,
			result,
			err,
			"SOURCE_QUAL_DESTINATION_EXISTS",
			fixture.root,
			outputDir,
		)
		entries, readErr := os.ReadDir(outputDir)
		if readErr != nil || len(entries) != 1 || entries[0].Name() != "operator-owned.txt" {
			t.Fatalf("preexisting tool output changed: entries=%v err=%v", entries, readErr)
		}
		toolAssemblyRequireBytes(t, sentinel, []byte("retain tools\n"))
		controllerFacadeRequireSnapshot(t, fixture.packageDir, beforePackage)
		controllerFacadeRequireBytes(t, fixture.linuxController, beforeLinux)
		controllerFacadeRequireBytes(t, fixture.windowsController, beforeWindows)
	})

	t.Run("verify integrity success", func(t *testing.T) {
		result, err := VerifyIntegrity(VerifyIntegrityRequest{PackageDir: fixture.packageDir})
		if err != nil {
			t.Fatalf("VerifyIntegrity: %v", err)
		}
		report, err := inspectQualificationPackage(fixture.packageDir)
		if err != nil {
			t.Fatalf("inspect expected package: %v", err)
		}
		controllerFacadeRequireResult(t, result, ControllerResult{
			Code:                "SOURCE_QUAL_OK",
			QualificationStatus: "HISTORICAL_INTEGRITY",
			SHA256:              report.PackageDigest,
			TestedRevision:      report.Subject.TestedRevision,
			TreeSHA:             report.Subject.TreeSHA,
		})
	})

	t.Run("verify integrity failure is stable private and read only", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-facade-integrity")
		toolAssemblyMkdirPrivate(t, root)
		packageDir := filepath.Join(root, "package-private-marker")
		toolAssemblyCopyDirectory(t, fixture.packageDir, packageDir)
		archivePath := filepath.Join(packageDir, packageFilesArchiveName)
		toolAssemblyWritePrivate(t, archivePath, []byte("not canonical ustar"), false)
		before := controllerFacadeSnapshotTree(t, packageDir)

		result, err := VerifyIntegrity(VerifyIntegrityRequest{PackageDir: packageDir})
		controllerFacadeRequireFailure(
			t,
			result,
			err,
			"SOURCE_QUAL_ARCHIVE_INVALID",
			root,
			packageDir,
		)
		controllerFacadeRequireSnapshot(t, packageDir, before)
	})

	t.Run("verify subject matches every explicit expected identity", func(t *testing.T) {
		request, packageDir, toolManifestPath := controllerFacadeSubjectRequest(t, fixture)
		beforePackage := controllerFacadeSnapshotTree(t, packageDir)
		beforeManifest := toolAssemblyRead(t, toolManifestPath)

		result, err := VerifySubject(request)
		if err != nil {
			t.Fatalf("VerifySubject: %v", err)
		}
		controllerFacadeRequireResult(t, result, ControllerResult{
			Code:                "SOURCE_QUAL_OK",
			QualificationStatus: "SUBJECT_MATCH",
			SHA256:              request.ExpectedPackageDigest,
			TestedRevision:      request.ExpectedTestedRevision,
			TreeSHA:             request.ExpectedTreeSHA,
		})
		controllerFacadeRequireSnapshot(t, packageDir, beforePackage)
		controllerFacadeRequireBytes(t, toolManifestPath, beforeManifest)

		mismatch := request
		mismatch.ExpectedBaseRevision = strings.Repeat("d", 40)
		result, err = VerifySubject(mismatch)
		controllerFacadeRequireFailure(
			t,
			result,
			err,
			"SOURCE_QUAL_SUBJECT_MISMATCH",
			fixture.root,
			packageDir,
			toolManifestPath,
		)
		controllerFacadeRequireSnapshot(t, packageDir, beforePackage)
		controllerFacadeRequireBytes(t, toolManifestPath, beforeManifest)
	})
}

type controllerFacadeToolFixture struct {
	root              string
	subject           Subject
	archive           []byte
	manifest          []byte
	packageDir        string
	linuxController   string
	windowsController string
}

func newControllerFacadeToolFixture(t *testing.T) *controllerFacadeToolFixture {
	t.Helper()
	requireHostFilesystem(t)
	if runtime.Version() != toolManifestGoVersion {
		t.Fatalf("controller facade fixtures require %s, running %s", toolManifestGoVersion, runtime.Version())
	}
	root := filepath.Join(t.TempDir(), "controller-facade-tools")
	toolAssemblyMkdirPrivate(t, root)
	outputs := filepath.Join(root, "controller-outputs")
	toolAssemblyMkdirPrivate(t, outputs)
	sourceRoot := filepath.Join(root, "canonical-source")
	toolAssemblyCreateModule(t, sourceRoot, canonicalModulePath)
	testedRevision := toolAssemblyCommit(t, sourceRoot, "controller facade")
	linuxController := filepath.Join(outputs, "controller-linux")
	windowsController := filepath.Join(outputs, "controller-windows.exe")
	toolAssemblyBuildController(t, sourceRoot, linuxController, "linux")
	toolAssemblyBuildController(t, sourceRoot, windowsController, "windows")
	subject, archive, manifest := toolAssemblySourcePackage(t, testedRevision)
	packageDir := filepath.Join(root, "package")
	toolAssemblyWriteQualificationPackage(
		t,
		packageDir,
		subject,
		archive,
		manifest,
		toolAssemblyRead(t, linuxController),
		toolAssemblyRead(t, windowsController),
	)
	return &controllerFacadeToolFixture{
		root:              root,
		subject:           subject,
		archive:           archive,
		manifest:          manifest,
		packageDir:        packageDir,
		linuxController:   linuxController,
		windowsController: windowsController,
	}
}

func controllerFacadeAssembleRequest(
	t *testing.T,
	fixture *packageFilesFixture,
) (AssembleRequest, Subject) {
	t.Helper()
	linux, err := parseCanonicalReceipt(fixture.linuxReceipt, LaneLinuxAMD64)
	if err != nil {
		t.Fatalf("parse Linux facade receipt: %v", err)
	}
	windows, err := parseCanonicalReceipt(fixture.windowsReceipt, LaneWindowsAMD64)
	if err != nil {
		t.Fatalf("parse Windows facade receipt: %v", err)
	}
	if linux.Subject != windows.Subject ||
		linux.Run.QualificationRunID != windows.Run.QualificationRunID ||
		linux.Run.WorkflowRunID != windows.Run.WorkflowRunID ||
		linux.Run.WorkflowRunAttempt != windows.Run.WorkflowRunAttempt {
		t.Fatal("facade assembly fixture is not cross-lane bound")
	}
	subject := sourceSubjectFromReceipt(linux.Subject)
	return AssembleRequest{
		LinuxDir:                   fixture.linuxDir,
		WindowsDir:                 fixture.windowsDir,
		ExpectedBaseRevision:       subject.BaseRevision,
		ExpectedTestedRevision:     subject.TestedRevision,
		ExpectedTreeSHA:            subject.TreeSHA,
		ExpectedQualificationRunID: linux.Run.QualificationRunID,
		ExpectedWorkflowRunID:      linux.Run.WorkflowRunID,
		ExpectedWorkflowRunAttempt: linux.Run.WorkflowRunAttempt,
		OutputDir:                  fixture.outputDir,
	}, subject
}

func controllerFacadeSubjectRequest(
	t *testing.T,
	fixture *controllerFacadeToolFixture,
) (VerifySubjectRequest, string, string) {
	t.Helper()
	selfPath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve facade test executable: %v", err)
	}
	self := toolAssemblyRead(t, selfPath)
	linuxController := toolAssemblyRead(t, fixture.linuxController)
	windowsController := toolAssemblyRead(t, fixture.windowsController)
	if runtime.GOOS == "linux" {
		linuxController = self
	} else if runtime.GOOS == "windows" {
		windowsController = self
	} else {
		t.Fatalf("controller facade subject fixture requires Linux or Windows, got %s", runtime.GOOS)
	}

	root := filepath.Join(t.TempDir(), "controller-facade-subject")
	toolAssemblyMkdirPrivate(t, root)
	packageDir := filepath.Join(root, "subject-package-private-marker")
	toolAssemblyWriteQualificationPackage(
		t,
		packageDir,
		fixture.subject,
		fixture.archive,
		fixture.manifest,
		linuxController,
		windowsController,
	)
	manifest := offlineVerificationMarshalToolManifest(
		t,
		fixture.subject,
		linuxController,
		windowsController,
	)
	toolManifestPath := filepath.Join(root, qualificationToolManifestFilename)
	toolAssemblyWritePrivate(t, toolManifestPath, manifest, false)
	report, err := inspectQualificationPackage(packageDir)
	if err != nil {
		t.Fatalf("inspect facade subject fixture: %v", err)
	}
	return VerifySubjectRequest{
		PackageDir:                 packageDir,
		ExpectedRepository:         report.Subject.Repository,
		ExpectedBaseRevision:       report.Subject.BaseRevision,
		ExpectedTestedRevision:     report.Subject.TestedRevision,
		ExpectedTreeSHA:            report.Subject.TreeSHA,
		ExpectedQualificationRunID: report.LinuxRun.QualificationRunID,
		ExpectedWorkflowRunID:      report.LinuxRun.WorkflowRunID,
		ExpectedWorkflowRunAttempt: report.LinuxRun.WorkflowRunAttempt,
		ExpectedPackageDigest:      report.PackageDigest,
		ToolManifestPath:           toolManifestPath,
		ExpectedToolManifestDigest: sha256Digest(manifest),
		ExpectedExecutableDigest:   sha256Digest(self),
	}, packageDir, toolManifestPath
}

func controllerFacadeRequireFields(t *testing.T, value any, want []string) {
	t.Helper()
	typeOf := reflect.TypeOf(value)
	if typeOf.Kind() != reflect.Struct || typeOf.NumField() != len(want) {
		t.Fatalf("%T fields = %d, want exact %d-field contract", value, typeOf.NumField(), len(want))
	}
	for index, name := range want {
		if typeOf.Field(index).Name != name {
			t.Fatalf("%T field[%d] = %q, want %q", value, index, typeOf.Field(index).Name, name)
		}
	}
}

func controllerFacadeRequireResult(t *testing.T, got, want ControllerResult) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("controller facade result mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func controllerFacadeRequireFailure(
	t *testing.T,
	result ControllerResult,
	err error,
	wantCode string,
	private ...string,
) {
	t.Helper()
	want := ControllerResult{
		Code:                wantCode,
		QualificationStatus: "FAIL",
		SHA256:              "NOT_APPLICABLE",
		TestedRevision:      "NOT_APPLICABLE",
		TreeSHA:             "NOT_APPLICABLE",
	}
	controllerFacadeRequireResult(t, result, want)
	if err == nil || err.Error() != wantCode {
		t.Fatalf("controller facade error = %v, want fixed code-only error %q", err, wantCode)
	}
	public := fmt.Sprintf("%#v %v", result, err)
	for _, value := range private {
		if value != "" && strings.Contains(public, value) {
			t.Fatalf("controller facade failure exposed private value %q in %q", value, public)
		}
	}
}

func controllerFacadeSnapshotTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = bytes.Clone(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot facade input tree: %v", err)
	}
	return result
}

func controllerFacadeRequireSnapshot(t *testing.T, root string, want map[string][]byte) {
	t.Helper()
	got := controllerFacadeSnapshotTree(t, root)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("controller facade modified input tree %q", filepath.Base(root))
	}
}

func controllerFacadeRequireBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read facade input %q: %v", filepath.Base(path), err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("controller facade modified input %q", filepath.Base(path))
	}
}

func controllerFacadeRequireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed facade operation left an output path: %v", err)
	}
}
