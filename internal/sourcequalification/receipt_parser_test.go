// The strict receipt/package-binding implementation is expected to expose:
//
//	type qualificationReceipt struct { ... }
//	func parseCanonicalReceipt(raw []byte, expectedLane Lane) (qualificationReceipt, error)
//	func verifyReceiptPackageBindings(archive, manifest, linuxReceipt, windowsReceipt []byte) error
//
// Source-manifest, USTAR, Git-tree, and workflow semantics remain covered by
// manifest.go, archive.go, git_test.go, and workflow_contract_test.go. The
// package-binding helper here only binds two strict receipts to each other and
// to the exact archive/manifest bytes supplied by their caller.
package sourcequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestParseCanonicalReceiptAcceptsExactLaneContracts(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	for _, lane := range []Lane{LaneLinuxAMD64, LaneWindowsAMD64} {
		raw := receiptParserCanonical(t, lane, archive, manifest, nil)
		if _, err := parseCanonicalReceipt(raw, lane); err != nil {
			t.Fatalf("parseCanonicalReceipt(%s) rejected exact receipt: %v", lane, err)
		}
	}
	windows := receiptParserCanonical(t, LaneWindowsAMD64, archive, manifest, nil)
	if _, err := parseCanonicalReceipt(windows, LaneLinuxAMD64); err == nil {
		t.Fatal("parseCanonicalReceipt accepted a Windows receipt as the Linux lane")
	}
}

func TestParseCanonicalReceiptRejectsNonCanonicalJSON(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	canonical := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, nil)

	duplicateTop := append([]byte(`{"artifactType":"repopass-source-qualification-receipt",`), canonical[1:]...)
	duplicateNested := bytes.Replace(
		canonical,
		[]byte(`"manualActionCount":0`),
		[]byte(`"manualActionCount":0,"manualActionCount":0`),
		1,
	)
	tests := map[string][]byte{
		"trailing newline": append(bytes.Clone(canonical), '\n'),
		"leading BOM":      append([]byte{0xef, 0xbb, 0xbf}, canonical...),
		"insignificant space": append(
			[]byte("{ "), canonical[1:]...,
		),
		"duplicate top-level key": duplicateTop,
		"duplicate nested key":    duplicateNested,
		"invalid UTF-8":           append([]byte{0xff}, canonical...),
		"over byte limit":         bytes.Repeat([]byte{' '}, (1<<20)+1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCanonicalReceipt(raw, LaneLinuxAMD64); err == nil {
				t.Fatal("parseCanonicalReceipt accepted noncanonical receipt bytes")
			}
		})
	}
}

func TestParseCanonicalReceiptRejectsCanonicalContractTampering(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "unknown top-level key",
			mutate: func(document map[string]any) {
				document["unexpected"] = true
			},
		},
		{
			name: "unknown nested key",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "execution")["unexpected"] = 0
			},
		},
		{
			name: "wrong predicate version",
			mutate: func(document map[string]any) {
				document["predicateType"] = "https://repopass.dev/source-qualification/v2"
			},
		},
		{
			name: "dirty subject",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "subject")["dirty"] = true
			},
		},
		{
			name: "limitations reordered",
			mutate: func(document map[string]any) {
				limitations := document["limitations"].([]string)
				limitations[0], limitations[1] = limitations[1], limitations[0]
			},
		},
		{
			name: "not-applicable value changed",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "notApplicable")["runtimeVersion"] = "PASS"
			},
		},
		{
			name: "product dimension changed",
			mutate: func(document map[string]any) {
				dimensions := receiptParserObject(document, "productDimensions")
				receiptParserObject(dimensions, "overall")["evaluationStatus"] = "PASS"
			},
		},
		{
			name: "platform lane mismatch",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "platform")["goos"] = "windows"
			},
		},
		{
			name: "platform private path",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "platform")["runnerImage"] = `C:\Users\private-user\runner-image`
			},
		},
		{
			name: "platform credential candidate",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "platform")["runnerImageVersion"] = "ghp_0123456789abcdefghijklmnop"
			},
		},
		{
			name: "gate argv changed",
			mutate: func(document map[string]any) {
				gate := receiptParserArray(document, "gates")[0].(map[string]any)
				gate["argv"] = []string{"go", "env"}
			},
		},
		{
			name: "release argv retains template token",
			mutate: func(document map[string]any) {
				for _, rawGate := range receiptParserArray(document, "gates") {
					gate := rawGate.(map[string]any)
					if gate["id"] != "RP-M0-QUAL-RELEASE-BUILD" {
						continue
					}
					argv := gate["argv"].([]string)
					argv[len(argv)-1] = "{testedRevision}"
					return
				}
				t.Fatal("release gate missing from fixture")
			},
		},
		{
			name: "gate order changed",
			mutate: func(document map[string]any) {
				gates := receiptParserArray(document, "gates")
				gates[0], gates[1] = gates[1], gates[0]
			},
		},
		{
			name: "status does not aggregate gates",
			mutate: func(document map[string]any) {
				document["qualificationStatus"] = "FAIL"
			},
		},
		{
			name: "attempt ID mismatch",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "attempt")["attemptId"] = "sha256:" + strings.Repeat("0", 64) + ":linux-amd64:1"
			},
		},
		{
			name: "qualification run ID mismatch",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "run")["qualificationRunId"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name: "source role mismatch",
			mutate: func(document map[string]any) {
				source := receiptParserObject(document, "source")
				receiptParserObject(source, "manifest")["role"] = "source-payload"
			},
		},
		{
			name: "oversized string",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "platform")["kernelVersion"] = strings.Repeat("x", 4097)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, test.mutate)
			if _, err := parseCanonicalReceipt(raw, LaneLinuxAMD64); err == nil {
				t.Fatal("parseCanonicalReceipt accepted canonical contract tampering")
			}
		})
	}
}

func TestParseCanonicalReceiptAcceptsBlockedGateWithObservedTimes(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
		gates := receiptParserArray(document, "gates")
		blocked := gates[0].(map[string]any)
		blocked["exitCode"] = nil
		blocked["status"] = "BLOCKED"
		for _, value := range gates[1:] {
			gate := value.(map[string]any)
			gate["exitCode"] = nil
			gate["finishedAt"] = nil
			gate["startedAt"] = nil
			gate["status"] = "NOT_RUN"
		}
		document["qualificationStatus"] = "BLOCKED"
		receiptParserObject(document, "execution")["skippedGateCount"] = int64(len(gates) - 1)
	})
	if _, err := parseCanonicalReceipt(raw, LaneLinuxAMD64); err != nil {
		t.Fatalf("parseCanonicalReceipt rejected RFC BLOCKED gate: %v", err)
	}
}

func TestVerifyReceiptPackageBindingsRejectsByteAndCrossLaneSubstitution(t *testing.T) {
	archive, manifest, tree := receiptParserValidSourcePackage(t)
	linux := receiptParserCanonicalWithTree(t, LaneLinuxAMD64, archive, manifest, tree, nil)
	windows := receiptParserCanonicalWithTree(t, LaneWindowsAMD64, archive, manifest, tree, nil)
	if err := verifyReceiptPackageBindings(archive, manifest, linux, windows); err != nil {
		t.Fatalf("verifyReceiptPackageBindings rejected exact pair: %v", err)
	}

	tests := []struct {
		name     string
		archive  []byte
		manifest []byte
		linux    []byte
		windows  []byte
	}{
		{
			name:     "archive bytes changed",
			archive:  append(bytes.Clone(archive), '!'),
			manifest: manifest,
			linux:    linux,
			windows:  windows,
		},
		{
			name:     "manifest bytes changed",
			archive:  archive,
			manifest: append(bytes.Clone(manifest), ' '),
			linux:    linux,
			windows:  windows,
		},
		{
			name:     "cross-run windows receipt",
			archive:  archive,
			manifest: manifest,
			linux:    linux,
			windows: receiptParserCanonicalWithTree(t, LaneWindowsAMD64, archive, manifest, tree, func(document map[string]any) {
				receiptParserSetWorkflowRunID(document, "987654321")
			}),
		},
		{
			name:     "cross-subject windows receipt",
			archive:  archive,
			manifest: manifest,
			linux:    linux,
			windows: receiptParserCanonicalWithTree(t, LaneWindowsAMD64, archive, manifest, tree, func(document map[string]any) {
				receiptParserObject(document, "subject")["baseRevision"] = strings.Repeat("a", 40)
			}),
		},
		{
			name:     "receipt claims other archive",
			archive:  archive,
			manifest: manifest,
			linux: receiptParserCanonicalWithTree(t, LaneLinuxAMD64, archive, manifest, tree, func(document map[string]any) {
				source := receiptParserObject(document, "source")
				receiptParserObject(source, "archive")["sha256"] = receiptParserSHA256([]byte("other archive"))
			}),
			windows: windows,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyReceiptPackageBindings(test.archive, test.manifest, test.linux, test.windows); err == nil {
				t.Fatal("verifyReceiptPackageBindings accepted substituted package inputs")
			}
		})
	}
}

func receiptParserValidSourcePackage(t *testing.T) ([]byte, []byte, string) {
	t.Helper()
	files := []archiveFile{
		{Path: "go.mod", GitMode: "100644", Data: []byte("module github.com/taipei49314/RepoPassport\n")},
	}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{
		Repository:      canonicalRepositoryURL,
		ModulePath:      canonicalModulePath,
		ModuleVersion:   canonicalModuleVersion,
		GitObjectFormat: "sha1",
		BaseRevision:    "0123456789abcdef0123456789abcdef01234567",
		TestedRevision:  "89abcdef0123456789abcdef0123456789abcdef",
		TreeSHA:         tree,
	}
	archive, manifest, err := buildSourcePackage(subject, files)
	if err != nil {
		t.Fatal(err)
	}
	return archive, manifest, tree
}

func receiptParserCanonicalWithTree(
	t *testing.T,
	lane Lane,
	archive, manifest []byte,
	tree string,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	return receiptParserCanonical(t, lane, archive, manifest, func(document map[string]any) {
		receiptParserObject(document, "subject")["treeSHA"] = tree
		if mutate != nil {
			mutate(document)
		}
	})
}

func TestVerifyReceiptPackageBindingsRejectsManifestReceiptSubjectSplit(t *testing.T) {
	files := []archiveFile{
		{Path: "go.mod", GitMode: "100644", Data: []byte("module github.com/taipei49314/RepoPassport\n")},
	}
	tree, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatal(err)
	}
	manifestSubject := Subject{
		Repository:      canonicalRepositoryURL,
		ModulePath:      canonicalModulePath,
		ModuleVersion:   canonicalModuleVersion,
		GitObjectFormat: "sha1",
		BaseRevision:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TestedRevision:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TreeSHA:         tree,
	}
	archive, manifest, err := buildSourcePackage(manifestSubject, files)
	if err != nil {
		t.Fatal(err)
	}
	linux := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, nil)
	windows := receiptParserCanonical(t, LaneWindowsAMD64, archive, manifest, nil)
	if err := verifyReceiptPackageBindings(archive, manifest, linux, windows); err == nil {
		t.Fatal("receipt subject split from the parsed source manifest was accepted")
	}
}

func receiptParserCanonical(t *testing.T, lane Lane, archive, manifest []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	document := receiptParserDocument(lane, archive, manifest)
	if mutate != nil {
		mutate(document)
	}
	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		t.Fatalf("marshal receipt fixture: %v", err)
	}
	return raw
}

func receiptParserDocument(lane Lane, archive, manifest []byte) map[string]any {
	const (
		baseRevision   = "0123456789abcdef0123456789abcdef01234567"
		testedRevision = "89abcdef0123456789abcdef0123456789abcdef"
		treeSHA        = "fedcba9876543210fedcba9876543210fedcba98"
		workflowRunID  = "123456789"
	)
	runIdentity := RunIdentity{
		WorkflowRepository: "taipei49314/RepoPassport",
		WorkflowPath:       ".github/workflows/source-qualification.yml",
		Event:              "push",
		Ref:                "refs/heads/main",
		WorkflowRunID:      workflowRunID,
		WorkflowRunAttempt: 1,
		TestedRevision:     testedRevision,
	}
	qualificationRunID := QualificationRunID(runIdentity)

	platform := map[string]any{
		"gitVersion":         "git version 2.50.1",
		"goVersion":          "go1.26.5",
		"goarch":             "amd64",
		"goos":               "linux",
		"kernelVersion":      "6.11.0",
		"powerShellVersion":  "7.5.2",
		"runnerArch":         "X64",
		"runnerImage":        "ubuntu-24.04",
		"runnerImageVersion": "20260810.1",
		"runnerOS":           "Linux",
	}
	if lane == LaneWindowsAMD64 {
		platform["goos"] = "windows"
		platform["kernelVersion"] = "10.0.26100"
		platform["powerShellVersion"] = "5.1.26100.1"
		platform["runnerImage"] = "windows-2025"
		platform["runnerOS"] = "Windows"
	}

	gates := make([]any, 0, len(RequiredGates(lane)))
	for _, spec := range RequiredGates(lane) {
		argv := append([]string(nil), spec.Argv...)
		for index, token := range argv {
			if token == "{testedRevision}" {
				argv[index] = testedRevision
			}
		}
		gates = append(gates, map[string]any{
			"argv":           argv,
			"attempt":        1,
			"exitCode":       0,
			"finishedAt":     "2026-08-11T00:00:01Z",
			"id":             spec.ID,
			"network":        string(spec.Network),
			"startedAt":      "2026-08-11T00:00:00Z",
			"status":         "PASS",
			"timeoutSeconds": spec.TimeoutSeconds,
		})
	}

	notApplicable := map[string]any{}
	for _, key := range []string{
		"cgroupVersion", "containerEngineVersion", "engineProviderVersion",
		"imageDigests", "observerSetDigest", "planDigest", "policyDigest",
		"runtimeVersion", "sbomDigest", "signatureDigest", "trustPolicyDigest",
	} {
		notApplicable[key] = "NOT_APPLICABLE"
	}
	dimensions := map[string]any{}
	for _, key := range []string{
		"capability", "cleanup", "coverage", "evidence", "freshness",
		"functional", "overall", "reproducibility",
	} {
		dimensions[key] = map[string]any{
			"evaluationStatus": "NOT_RUN",
			"reason":           "not-evaluated-by-source-qualification",
			"value":            nil,
		}
	}
	subject := map[string]any{
		"baseRevision":    baseRevision,
		"dirty":           false,
		"gitObjectFormat": "sha1",
		"modulePath":      "github.com/taipei49314/RepoPassport",
		"moduleVersion":   "0.1.0-alpha.33",
		"repository":      "https://github.com/taipei49314/RepoPassport",
		"testedRevision":  testedRevision,
		"treeSHA":         treeSHA,
	}

	return map[string]any{
		"artifactType": "repopass-source-qualification-receipt",
		"attempt": map[string]any{
			"attemptId":     AttemptID(qualificationRunID, lane, 1),
			"finishedAt":    "2026-08-11T00:00:01Z",
			"ordinal":       1,
			"priorAttempts": []any{},
			"retryOf":       nil,
			"startedAt":     "2026-08-11T00:00:00Z",
		},
		"controller": map[string]any{
			"goVersion":   "go1.26.5",
			"mainPackage": "github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify",
			"modulePath":  "github.com/taipei49314/RepoPassport",
			"sha256":      receiptParserSHA256([]byte("controller-" + string(lane))),
			"vcsModified": false,
			"vcsRevision": testedRevision,
		},
		"execution": map[string]any{
			"manualActionCount": 0,
			"rawLogsPublished":  false,
			"retryCount":        0,
			"skippedGateCount":  0,
		},
		"gates":               gates,
		"limitations":         FixedLimitations(),
		"notApplicable":       notApplicable,
		"platform":            platform,
		"predicateType":       "https://repopass.dev/source-qualification/v1",
		"productDimensions":   dimensions,
		"qualificationStatus": "PASS",
		"run": map[string]any{
			"event":              "push",
			"headSHA":            testedRevision,
			"issuer":             "NOT_ESTABLISHED",
			"lane":               string(lane),
			"qualificationRunId": qualificationRunID,
			"ref":                "refs/heads/main",
			"workflowPath":       ".github/workflows/source-qualification.yml",
			"workflowRepository": "taipei49314/RepoPassport",
			"workflowRunAttempt": 1,
			"workflowRunId":      workflowRunID,
			"workflowURL":        "https://github.com/taipei49314/RepoPassport/actions/runs/" + workflowRunID,
		},
		"schemaVersion": "1",
		"source": map[string]any{
			"archive": map[string]any{
				"name":   "repopass-source.tar",
				"role":   "source-payload",
				"sha256": receiptParserSHA256(archive),
				"size":   int64(len(archive)),
			},
			"manifest": map[string]any{
				"name":   "source-archive-manifest-v1.json",
				"role":   "source-archive-manifest",
				"sha256": receiptParserSHA256(manifest),
				"size":   int64(len(manifest)),
			},
		},
		"subject": subject,
	}
}

func receiptParserSetWorkflowRunID(document map[string]any, workflowRunID string) {
	run := receiptParserObject(document, "run")
	run["workflowRunId"] = workflowRunID
	run["workflowURL"] = "https://github.com/taipei49314/RepoPassport/actions/runs/" + workflowRunID
	identity := RunIdentity{
		WorkflowRepository: run["workflowRepository"].(string),
		WorkflowPath:       run["workflowPath"].(string),
		Event:              run["event"].(string),
		Ref:                run["ref"].(string),
		WorkflowRunID:      workflowRunID,
		WorkflowRunAttempt: run["workflowRunAttempt"].(int),
		TestedRevision:     run["headSHA"].(string),
	}
	qualificationRunID := QualificationRunID(identity)
	run["qualificationRunId"] = qualificationRunID
	attempt := receiptParserObject(document, "attempt")
	attempt["attemptId"] = AttemptID(qualificationRunID, Lane(run["lane"].(string)), attempt["ordinal"].(int))
}

func receiptParserObject(document map[string]any, key string) map[string]any {
	return document[key].(map[string]any)
}

func receiptParserArray(document map[string]any, key string) []any {
	return document[key].([]any)
}

func receiptParserSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}
