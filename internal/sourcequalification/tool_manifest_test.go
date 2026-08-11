// The offline tool-manifest implementation is expected to expose:
//
//	type sourceQualificationToolManifest struct { ... }
//	type sourceQualificationTool struct { ... }
//	func marshalToolManifest(subject Subject, linuxController, windowsController []byte) ([]byte, error)
//	func parseCanonicalToolManifest(raw []byte, expected Subject, linuxController, windowsController []byte) (sourceQualificationToolManifest, error)
//
// The byte inputs keep SHA-256 and size bindings out of caller-controlled
// manifest metadata. Build-information inspection, receipt cross-binding, and
// package-digest verification are separate contracts and are not exercised
// here.
package sourcequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestToolManifestCanonicalExactContract(t *testing.T) {
	subject := toolManifestSubject()
	linuxController, windowsController := toolManifestControllers()

	raw, err := marshalToolManifest(subject, linuxController, windowsController)
	if err != nil {
		t.Fatalf("marshalToolManifest: %v", err)
	}
	if len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] == '\n' || bytes.Contains(raw, []byte("\r")) {
		t.Fatalf("tool manifest is not bounded canonical JSON: %d bytes", len(raw))
	}

	expected, err := canonicaljson.Marshal(toolManifestDocument(subject, linuxController, windowsController))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("tool manifest contract mismatch\n got: %s\nwant: %s", raw, expected)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode tool manifest: %v", err)
	}
	toolManifestAssertExactKeys(t, decoded, []string{"artifactType", "schemaVersion", "subject", "tools"})
	toolManifestAssertExactKeys(t, toolManifestObject(decoded, "subject"), []string{
		"baseRevision", "dirty", "gitObjectFormat", "modulePath", "moduleVersion",
		"repository", "testedRevision", "treeSHA",
	})
	tools := toolManifestArray(decoded, "tools")
	if len(tools) != 2 {
		t.Fatalf("tool count = %d, want 2", len(tools))
	}
	for index, value := range tools {
		entry, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("tools[%d] is %T, want object", index, value)
		}
		toolManifestAssertExactKeys(t, entry, []string{
			"goarch", "goos", "goVersion", "mainPackage", "modulePath", "path",
			"sha256", "size", "vcsModified", "vcsRevision",
		})
	}
	if got := tools[0].(map[string]any)["goos"]; got != "linux" {
		t.Fatalf("tools[0].goos = %v, want linux", got)
	}
	if got := tools[1].(map[string]any)["goos"]; got != "windows" {
		t.Fatalf("tools[1].goos = %v, want windows", got)
	}

	parsed, err := parseCanonicalToolManifest(raw, subject, linuxController, windowsController)
	if err != nil {
		t.Fatalf("parseCanonicalToolManifest rejected exact manifest: %v", err)
	}
	if parsed.Subject != subject || len(parsed.Tools) != 2 {
		t.Fatalf("parsed manifest lost its subject or tools: %#v", parsed)
	}
}

func TestToolManifestRejectsNonCanonicalAndBoundedInput(t *testing.T) {
	subject := toolManifestSubject()
	linuxController, windowsController := toolManifestControllers()
	canonical := toolManifestCanonical(t, subject, linuxController, windowsController, nil)

	duplicateTop := append([]byte(`{"artifactType":"repopass-source-qualification-toolset",`), canonical[1:]...)
	duplicateNested := bytes.Replace(
		canonical,
		[]byte(`"goarch":"amd64"`),
		[]byte(`"goarch":"amd64","goarch":"amd64"`),
		1,
	)
	tooDeep, err := canonicaljson.Marshal(map[string]any{
		"artifactType":  "repopass-source-qualification-toolset",
		"schemaVersion": "1",
		"subject":       []any{[]any{[]any{[]any{[]any{[]any{[]any{[]any{[]any{"too-deep"}}}}}}}}},
		"tools":         []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"trailing newline":         append(bytes.Clone(canonical), '\n'),
		"leading BOM":              append([]byte{0xef, 0xbb, 0xbf}, canonical...),
		"insignificant whitespace": append([]byte("{ "), canonical[1:]...),
		"duplicate top-level key":  duplicateTop,
		"duplicate nested key":     duplicateNested,
		"invalid UTF-8":            append([]byte{0xff}, canonical...),
		"over 64 KiB":              bytes.Repeat([]byte{' '}, (64<<10)+1),
		"over depth eight":         tooDeep,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCanonicalToolManifest(raw, subject, linuxController, windowsController); err == nil {
				t.Fatal("parseCanonicalToolManifest accepted noncanonical or out-of-bounds bytes")
			}
		})
	}
}

func TestToolManifestRejectsCanonicalContractTampering(t *testing.T) {
	subject := toolManifestSubject()
	linuxController, windowsController := toolManifestControllers()
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
			name: "unknown tool key",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["unexpected"] = true
			},
		},
		{
			name: "wrong artifact type",
			mutate: func(document map[string]any) {
				document["artifactType"] = "repopass-source-qualification-toolset-v2"
			},
		},
		{
			name: "wrong schema version",
			mutate: func(document map[string]any) {
				document["schemaVersion"] = "2"
			},
		},
		{
			name: "dirty subject",
			mutate: func(document map[string]any) {
				toolManifestObject(document, "subject")["dirty"] = true
			},
		},
		{
			name: "subject substitution",
			mutate: func(document map[string]any) {
				toolManifestObject(document, "subject")["testedRevision"] = strings.Repeat("a", 40)
			},
		},
		{
			name: "missing Windows tool",
			mutate: func(document map[string]any) {
				document["tools"] = toolManifestArray(document, "tools")[:1]
			},
		},
		{
			name: "third tool",
			mutate: func(document map[string]any) {
				tools := toolManifestArray(document, "tools")
				document["tools"] = append(tools, tools[0])
			},
		},
		{
			name: "Windows then Linux",
			mutate: func(document map[string]any) {
				tools := toolManifestArray(document, "tools")
				tools[0], tools[1] = tools[1], tools[0]
			},
		},
		{
			name: "wrong Linux goos",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["goos"] = "windows"
			},
		},
		{
			name: "wrong architecture",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["goarch"] = "arm64"
			},
		},
		{
			name: "wrong Linux path",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["path"] = "repopass-source-qualify-windows-amd64.exe"
			},
		},
		{
			name: "wrong Windows path",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 1)["path"] = "repopass-source-qualify-linux-amd64"
			},
		},
		{
			name: "wrong Go version",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["goVersion"] = "go1.26.4"
			},
		},
		{
			name: "wrong main package",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["mainPackage"] = "github.com/taipei49314/RepoPassport/cmd/repopass"
			},
		},
		{
			name: "wrong module path",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["modulePath"] = "github.com/example/fork"
			},
		},
		{
			name: "modified build",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["vcsModified"] = true
			},
		},
		{
			name: "VCS revision substitution",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["vcsRevision"] = strings.Repeat("b", 40)
			},
		},
		{
			name: "valid-looking digest substitution",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["sha256"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name: "uppercase digest",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 0)["sha256"] = "sha256:" + strings.Repeat("A", 64)
			},
		},
		{
			name: "size substitution",
			mutate: func(document map[string]any) {
				entry := toolManifestTool(document, 1)
				entry["size"] = entry["size"].(int64) + 1
			},
		},
		{
			name: "zero size",
			mutate: func(document map[string]any) {
				toolManifestTool(document, 1)["size"] = int64(0)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := toolManifestCanonical(t, subject, linuxController, windowsController, test.mutate)
			if _, err := parseCanonicalToolManifest(raw, subject, linuxController, windowsController); err == nil {
				t.Fatal("parseCanonicalToolManifest accepted canonical contract tampering")
			}
		})
	}
}

func TestToolManifestRejectsExternalSubstitution(t *testing.T) {
	subject := toolManifestSubject()
	linuxController, windowsController := toolManifestControllers()
	raw := toolManifestCanonical(t, subject, linuxController, windowsController, nil)

	changedSubject := subject
	changedSubject.BaseRevision = strings.Repeat("c", 40)
	tests := []struct {
		name              string
		expected          Subject
		linuxController   []byte
		windowsController []byte
	}{
		{
			name:              "expected subject",
			expected:          changedSubject,
			linuxController:   linuxController,
			windowsController: windowsController,
		},
		{
			name:              "Linux controller bytes",
			expected:          subject,
			linuxController:   append(bytes.Clone(linuxController), '!'),
			windowsController: windowsController,
		},
		{
			name:              "Windows controller bytes",
			expected:          subject,
			linuxController:   linuxController,
			windowsController: append(bytes.Clone(windowsController), '!'),
		},
		{
			name:              "cross-lane controller bytes",
			expected:          subject,
			linuxController:   windowsController,
			windowsController: linuxController,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseCanonicalToolManifest(
				raw,
				test.expected,
				test.linuxController,
				test.windowsController,
			); err == nil {
				t.Fatal("parseCanonicalToolManifest accepted external substitution")
			}
		})
	}
}

func TestMarshalToolManifestRejectsInvalidInputs(t *testing.T) {
	subject := toolManifestSubject()
	linuxController, windowsController := toolManifestControllers()
	invalidSubject := subject
	invalidSubject.Dirty = true

	tests := []struct {
		name              string
		subject           Subject
		linuxController   []byte
		windowsController []byte
	}{
		{"invalid subject", invalidSubject, linuxController, windowsController},
		{"empty Linux controller", subject, nil, windowsController},
		{"empty Windows controller", subject, linuxController, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := marshalToolManifest(test.subject, test.linuxController, test.windowsController); err == nil {
				t.Fatal("marshalToolManifest accepted an invalid input")
			}
		})
	}
}

func toolManifestSubject() Subject {
	return Subject{
		BaseRevision:    "0123456789abcdef0123456789abcdef01234567",
		Dirty:           false,
		GitObjectFormat: "sha1",
		ModulePath:      "github.com/taipei49314/RepoPassport",
		ModuleVersion:   "0.1.0-alpha.33",
		Repository:      "https://github.com/taipei49314/RepoPassport",
		TestedRevision:  "89abcdef0123456789abcdef0123456789abcdef",
		TreeSHA:         "fedcba9876543210fedcba9876543210fedcba98",
	}
}

func toolManifestControllers() ([]byte, []byte) {
	return []byte("exact linux-amd64 controller bytes\n"), []byte("exact windows-amd64 controller bytes\r\n")
}

func toolManifestDocument(subject Subject, linuxController, windowsController []byte) map[string]any {
	tool := func(goos, path string, controller []byte) map[string]any {
		return map[string]any{
			"goarch":      "amd64",
			"goos":        goos,
			"goVersion":   "go1.26.5",
			"mainPackage": "github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify",
			"modulePath":  "github.com/taipei49314/RepoPassport",
			"path":        path,
			"sha256":      toolManifestSHA256(controller),
			"size":        int64(len(controller)),
			"vcsModified": false,
			"vcsRevision": subject.TestedRevision,
		}
	}
	return map[string]any{
		"artifactType":  "repopass-source-qualification-toolset",
		"schemaVersion": "1",
		"subject": map[string]any{
			"baseRevision":    subject.BaseRevision,
			"dirty":           subject.Dirty,
			"gitObjectFormat": subject.GitObjectFormat,
			"modulePath":      subject.ModulePath,
			"moduleVersion":   subject.ModuleVersion,
			"repository":      subject.Repository,
			"testedRevision":  subject.TestedRevision,
			"treeSHA":         subject.TreeSHA,
		},
		"tools": []any{
			tool("linux", "repopass-source-qualify-linux-amd64", linuxController),
			tool("windows", "repopass-source-qualify-windows-amd64.exe", windowsController),
		},
	}
}

func toolManifestCanonical(
	t *testing.T,
	subject Subject,
	linuxController, windowsController []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	document := toolManifestDocument(subject, linuxController, windowsController)
	if mutate != nil {
		mutate(document)
	}
	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		t.Fatalf("marshal tool manifest fixture: %v", err)
	}
	return raw
}

func toolManifestObject(document map[string]any, key string) map[string]any {
	return document[key].(map[string]any)
}

func toolManifestArray(document map[string]any, key string) []any {
	return document[key].([]any)
}

func toolManifestTool(document map[string]any, index int) map[string]any {
	return toolManifestArray(document, "tools")[index].(map[string]any)
}

func toolManifestAssertExactKeys(t *testing.T, object map[string]any, expected []string) {
	t.Helper()
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	sortedExpected := append([]string(nil), expected...)
	sort.Strings(sortedExpected)
	if !reflect.DeepEqual(actual, sortedExpected) {
		t.Fatalf("keys = %v, want %v", actual, sortedExpected)
	}
}

func toolManifestSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
