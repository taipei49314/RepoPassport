package sourcequalification

// Production contract under test:
//
//	type qualificationPackageReport struct {
//		PackageDigest    string
//		Subject          Subject
//		LinuxRun         receiptRun
//		WindowsRun       receiptRun
//		LinuxController  receiptController
//		WindowsController receiptController
//	}
//	func inspectQualificationPackage(directory string) (qualificationPackageReport, error)
//
//	type qualificationSubjectRequest struct {
//		PackageDir                       string
//		ExpectedRepository               string
//		ExpectedBaseRevision             string
//		ExpectedTestedRevision           string
//		ExpectedTreeSHA                  string
//		ExpectedQualificationRunID       string
//		ExpectedWorkflowRunID            string
//		ExpectedWorkflowRunAttempt       int64
//		ExpectedPackageDigest            string
//		ToolManifestPath                 string
//		ExpectedToolManifestDigest       string
//		ExpectedExecutableDigest         string
//	}
//	func verifyQualificationSubject(request qualificationSubjectRequest) (qualificationPackageReport, error)
//
// The subject API deliberately has no caller-selected executable path. It must
// hash the running executable through one fixed handle before reading untrusted
// package claims, bind its runtime lane to both receipts and the strict tool
// manifest, and hash the same handle again before success.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

type offlineVerificationFixture struct {
	packageDir        string
	toolManifestPath  string
	toolManifest      []byte
	linuxController   []byte
	windowsController []byte
	request           qualificationSubjectRequest
	wantReport        qualificationPackageReport
}

func TestOfflineVerificationAPISurface(t *testing.T) {
	offlineVerificationRequireFields(t, qualificationPackageReport{}, []string{
		"PackageDigest",
		"Subject",
		"LinuxRun",
		"WindowsRun",
		"LinuxController",
		"WindowsController",
	})
	offlineVerificationRequireFields(t, qualificationSubjectRequest{}, []string{
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

func TestOfflineQualificationVerificationContract(t *testing.T) {
	fixture := newOfflineVerificationFixture(t)

	t.Run("reports exact historical integrity facts", func(t *testing.T) {
		report, err := inspectQualificationPackage(fixture.packageDir)
		if err != nil {
			t.Fatalf("inspectQualificationPackage: %v", err)
		}
		if !reflect.DeepEqual(report, fixture.wantReport) {
			t.Fatalf("historical integrity report mismatch\n got: %#v\nwant: %#v", report, fixture.wantReport)
		}
	})

	t.Run("rejects non-exact tampered and non-PASS packages", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*testing.T, string)
		}{
			{
				name: "extra package member",
				mutate: func(t *testing.T, directory string) {
					toolAssemblyWritePrivate(t, filepath.Join(directory, "unexpected.json"), []byte("{}"), false)
				},
			},
			{
				name: "tampered archive",
				mutate: func(t *testing.T, directory string) {
					toolAssemblyWrite(t, filepath.Join(directory, packageFilesArchiveName), []byte("not canonical ustar"))
				},
			},
			{
				name: "structurally valid non-PASS receipt",
				mutate: func(t *testing.T, directory string) {
					path := filepath.Join(directory, packageFilesLinuxReceiptName)
					raw := offlineVerificationFailReceipt(t, toolAssemblyRead(t, path))
					parsed, err := parseCanonicalReceipt(raw, LaneLinuxAMD64)
					if err != nil || parsed.QualificationStatus != StatusFail {
						t.Fatalf("non-PASS receipt fixture is not structurally valid: status=%q err=%v", parsed.QualificationStatus, err)
					}
					toolAssemblyWritePrivate(t, path, raw, false)
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				packageDir := offlineVerificationCopyPackage(t, fixture.packageDir)
				test.mutate(t, packageDir)
				if report, err := inspectQualificationPackage(packageDir); err == nil {
					t.Fatalf("inspectQualificationPackage accepted invalid input: %#v", report)
				}
			})
		}
	})

	t.Run("matches every explicit subject input and the actual self executable", func(t *testing.T) {
		beforeManifest := bytes.Clone(fixture.toolManifest)
		beforePackage := offlineVerificationPackageBytes(t, fixture.packageDir)
		report, err := verifyQualificationSubject(fixture.request)
		if err != nil {
			t.Fatalf("verifyQualificationSubject: %v", err)
		}
		if !reflect.DeepEqual(report, fixture.wantReport) {
			t.Fatalf("subject verification report mismatch\n got: %#v\nwant: %#v", report, fixture.wantReport)
		}
		if !bytes.Equal(toolAssemblyRead(t, fixture.toolManifestPath), beforeManifest) ||
			!bytes.Equal(offlineVerificationPackageBytes(t, fixture.packageDir), beforePackage) {
			t.Fatal("offline verification modified its package or tool-manifest inputs")
		}
	})

	t.Run("rejects every explicit expected-value substitution", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*qualificationSubjectRequest)
		}{
			{"repository", func(request *qualificationSubjectRequest) {
				request.ExpectedRepository = "https://github.com/example/RepoPassport"
			}},
			{"base revision", func(request *qualificationSubjectRequest) {
				request.ExpectedBaseRevision = strings.Repeat("a", 40)
			}},
			{"tested revision", func(request *qualificationSubjectRequest) {
				request.ExpectedTestedRevision = strings.Repeat("b", 40)
			}},
			{"tree", func(request *qualificationSubjectRequest) {
				request.ExpectedTreeSHA = strings.Repeat("c", 40)
			}},
			{"qualification run", func(request *qualificationSubjectRequest) {
				request.ExpectedQualificationRunID = "sha256:" + strings.Repeat("1", 64)
			}},
			{"workflow run", func(request *qualificationSubjectRequest) {
				request.ExpectedWorkflowRunID = "987654321"
			}},
			{"workflow attempt", func(request *qualificationSubjectRequest) {
				request.ExpectedWorkflowRunAttempt = 2
			}},
			{"package digest", func(request *qualificationSubjectRequest) {
				request.ExpectedPackageDigest = "sha256:" + strings.Repeat("2", 64)
			}},
			{"tool manifest digest", func(request *qualificationSubjectRequest) {
				request.ExpectedToolManifestDigest = "sha256:" + strings.Repeat("3", 64)
			}},
			{"self executable digest", func(request *qualificationSubjectRequest) {
				request.ExpectedExecutableDigest = "sha256:" + strings.Repeat("4", 64)
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				request := fixture.request
				test.mutate(&request)
				if report, err := verifyQualificationSubject(request); err == nil {
					t.Fatalf("verifyQualificationSubject accepted substituted expectation: %#v", report)
				}
			})
		}
	})

	t.Run("rejects strict manifest and two-lane controller substitution", func(t *testing.T) {
		tests := []struct {
			name     string
			manifest func(*testing.T) []byte
			hardlink bool
		}{
			{
				name: "noncanonical manifest",
				manifest: func(t *testing.T) []byte {
					return append(bytes.Clone(fixture.toolManifest), '\n')
				},
			},
			{
				name: "manifest subject substitution",
				manifest: func(t *testing.T) []byte {
					subject := fixture.wantReport.Subject
					subject.BaseRevision = strings.Repeat("d", 40)
					return offlineVerificationMarshalToolManifest(
						t,
						subject,
						fixture.linuxController,
						fixture.windowsController,
					)
				},
			},
			{
				name: "non-selected lane controller substitution",
				manifest: func(t *testing.T) []byte {
					linuxController := bytes.Clone(fixture.linuxController)
					windowsController := bytes.Clone(fixture.windowsController)
					if runtime.GOOS == "linux" {
						windowsController = append(windowsController, '!')
					} else {
						linuxController = append(linuxController, '!')
					}
					return offlineVerificationMarshalToolManifest(
						t,
						fixture.wantReport.Subject,
						linuxController,
						windowsController,
					)
				},
			},
			{
				name: "selected self lane controller substitution",
				manifest: func(t *testing.T) []byte {
					linuxController := bytes.Clone(fixture.linuxController)
					windowsController := bytes.Clone(fixture.windowsController)
					if runtime.GOOS == "linux" {
						linuxController = append(linuxController, '!')
					} else {
						windowsController = append(windowsController, '!')
					}
					return offlineVerificationMarshalToolManifest(
						t,
						fixture.wantReport.Subject,
						linuxController,
						windowsController,
					)
				},
			},
			{
				name: "hard-linked manifest path",
				manifest: func(t *testing.T) []byte {
					return bytes.Clone(fixture.toolManifest)
				},
				hardlink: true,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "offline-manifest")
				toolAssemblyMkdirPrivate(t, root)
				manifest := test.manifest(t)
				path := filepath.Join(root, qualificationToolManifestFilename)
				toolAssemblyWritePrivate(t, path, manifest, false)
				if test.hardlink {
					toolAssemblyReplaceWithHardLink(t, path, root)
				}
				request := fixture.request
				request.ToolManifestPath = path
				request.ExpectedToolManifestDigest = sha256Digest(manifest)
				if report, err := verifyQualificationSubject(request); err == nil {
					t.Fatalf("verifyQualificationSubject accepted substituted tool manifest: %#v", report)
				}
			})
		}
	})
}

func newOfflineVerificationFixture(t *testing.T) *offlineVerificationFixture {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Fatalf("offline verification fixture requires a supported OS, got %s", runtime.GOOS)
	}
	if runtime.GOARCH != "amd64" {
		t.Fatalf("offline verification fixture requires amd64, got %s", runtime.GOARCH)
	}
	tools := newToolAssemblyFixture(t)
	selfPath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// RFC-0002 requires verify-subject to re-hash the selected executable and
	// cross-bind its digest/size to already inspected tool and receipt claims;
	// it does not re-establish BuildInfo (assemble-tools already did that). Using
	// the real test executable here therefore exercises self selection without
	// incorrectly requiring the test binary to have the controller main package.
	selfExecutable := toolAssemblyRead(t, selfPath)
	linuxController := toolAssemblyRead(t, tools.linuxController)
	windowsController := toolAssemblyRead(t, tools.windowsController)
	if runtime.GOOS == "linux" {
		linuxController = selfExecutable
	} else {
		windowsController = selfExecutable
	}

	root := filepath.Join(t.TempDir(), "offline-verification")
	toolAssemblyMkdirPrivate(t, root)
	packageDir := filepath.Join(root, "package")
	toolAssemblyWriteQualificationPackage(
		t,
		packageDir,
		tools.subject,
		tools.archive,
		tools.manifest,
		linuxController,
		windowsController,
	)
	toolManifest := offlineVerificationMarshalToolManifest(
		t,
		tools.subject,
		linuxController,
		windowsController,
	)
	toolManifestPath := filepath.Join(root, qualificationToolManifestFilename)
	toolAssemblyWritePrivate(t, toolManifestPath, toolManifest, false)

	linuxReceiptBytes := toolAssemblyRead(t, filepath.Join(packageDir, packageFilesLinuxReceiptName))
	windowsReceiptBytes := toolAssemblyRead(t, filepath.Join(packageDir, packageFilesWindowsReceiptName))
	linuxReceipt, err := parseCanonicalReceipt(linuxReceiptBytes, LaneLinuxAMD64)
	if err != nil {
		t.Fatalf("parse Linux offline receipt fixture: %v", err)
	}
	windowsReceipt, err := parseCanonicalReceipt(windowsReceiptBytes, LaneWindowsAMD64)
	if err != nil {
		t.Fatalf("parse Windows offline receipt fixture: %v", err)
	}
	packageDigest := qualificationPackageDigest(
		tools.archive,
		tools.manifest,
		linuxReceiptBytes,
		windowsReceiptBytes,
	)
	wantReport := qualificationPackageReport{
		PackageDigest:     packageDigest,
		Subject:           tools.subject,
		LinuxRun:          linuxReceipt.Run,
		WindowsRun:        windowsReceipt.Run,
		LinuxController:   linuxReceipt.Controller,
		WindowsController: windowsReceipt.Controller,
	}
	return &offlineVerificationFixture{
		packageDir:        packageDir,
		toolManifestPath:  toolManifestPath,
		toolManifest:      toolManifest,
		linuxController:   linuxController,
		windowsController: windowsController,
		request: qualificationSubjectRequest{
			PackageDir:                 packageDir,
			ExpectedRepository:         tools.subject.Repository,
			ExpectedBaseRevision:       tools.subject.BaseRevision,
			ExpectedTestedRevision:     tools.subject.TestedRevision,
			ExpectedTreeSHA:            tools.subject.TreeSHA,
			ExpectedQualificationRunID: linuxReceipt.Run.QualificationRunID,
			ExpectedWorkflowRunID:      linuxReceipt.Run.WorkflowRunID,
			ExpectedWorkflowRunAttempt: linuxReceipt.Run.WorkflowRunAttempt,
			ExpectedPackageDigest:      packageDigest,
			ToolManifestPath:           toolManifestPath,
			ExpectedToolManifestDigest: sha256Digest(toolManifest),
			ExpectedExecutableDigest:   sha256Digest(selfExecutable),
		},
		wantReport: wantReport,
	}
}

func offlineVerificationRequireFields(t *testing.T, value any, want []string) {
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

func offlineVerificationCopyPackage(t *testing.T, source string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "offline-package-copy")
	toolAssemblyMkdirPrivate(t, root)
	destination := filepath.Join(root, "package")
	toolAssemblyCopyDirectory(t, source, destination)
	return destination
}

func offlineVerificationFailReceipt(t *testing.T, raw []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode non-PASS receipt fixture: %v", err)
	}
	gates := document["gates"].([]any)
	firstGate := gates[0].(map[string]any)
	firstGate["exitCode"] = json.Number("1")
	firstGate["status"] = "FAIL"
	for _, value := range gates[1:] {
		gate := value.(map[string]any)
		gate["exitCode"] = nil
		gate["finishedAt"] = nil
		gate["startedAt"] = nil
		gate["status"] = "NOT_RUN"
	}
	document["execution"].(map[string]any)["skippedGateCount"] = json.Number(
		strconv.Itoa(len(gates) - 1),
	)
	document["qualificationStatus"] = "FAIL"
	result, err := canonicaljson.Marshal(document)
	if err != nil {
		t.Fatalf("marshal non-PASS receipt fixture: %v", err)
	}
	return result
}

func offlineVerificationMarshalToolManifest(
	t *testing.T,
	subject Subject,
	linuxController, windowsController []byte,
) []byte {
	t.Helper()
	raw, err := marshalToolManifest(subject, linuxController, windowsController)
	if err != nil {
		t.Fatalf("marshal offline tool manifest fixture: %v", err)
	}
	return raw
}

func offlineVerificationPackageBytes(t *testing.T, directory string) []byte {
	t.Helper()
	var result []byte
	for _, name := range []string{
		packageFilesArchiveName,
		packageFilesManifestName,
		packageFilesLinuxReceiptName,
		packageFilesWindowsReceiptName,
	} {
		raw := toolAssemblyRead(t, filepath.Join(directory, name))
		result = append(result, []byte(name)...)
		result = append(result, 0)
		result = append(result, raw...)
		result = append(result, 0)
	}
	return result
}
