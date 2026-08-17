package sourcequalification

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	toolManifestArtifactType  = "repopass-source-qualification-toolset"
	toolManifestSchemaVersion = "2"
	toolManifestGoVersion     = "go1.26.6"
	toolManifestMainPackage   = "github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify"
	toolManifestModulePath    = "github.com/taipei49314/RepoPassport"
	toolManifestLinuxPath     = "repopass-source-qualify-linux-amd64"
	toolManifestWindowsPath   = "repopass-source-qualify-windows-amd64.exe"
	toolManifestMaxBytes      = 64 << 10
	toolManifestMaxDepth      = 8
	toolManifestMaxNodes      = 128
)

var (
	errToolManifestInput     = errors.New("source qualification tool manifest input is invalid")
	errToolManifestBytes     = errors.New("source qualification tool manifest bytes are invalid")
	errToolManifestJSON      = errors.New("source qualification tool manifest JSON is invalid")
	errToolManifestCanonical = errors.New("source qualification tool manifest JSON is not canonical")
	errToolManifestShape     = errors.New("source qualification tool manifest shape is invalid")
	errToolManifestContract  = errors.New("source qualification tool manifest contract is invalid")
	errToolManifestEncoding  = errors.New("source qualification tool manifest encoding failed")
)

type sourceQualificationToolManifest struct {
	ArtifactType  string                    `json:"artifactType"`
	SchemaVersion string                    `json:"schemaVersion"`
	Subject       Subject                   `json:"subject"`
	Tools         []sourceQualificationTool `json:"tools"`
}

type sourceQualificationTool struct {
	GOARCH      string `json:"goarch"`
	GOOS        string `json:"goos"`
	GoVersion   string `json:"goVersion"`
	MainPackage string `json:"mainPackage"`
	ModulePath  string `json:"modulePath"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	VCSModified bool   `json:"vcsModified"`
	VCSRevision string `json:"vcsRevision"`
}

func marshalToolManifest(subject Subject, linuxController, windowsController []byte) ([]byte, error) {
	if validateSourceSubject(subject) != nil || len(linuxController) == 0 || len(windowsController) == 0 {
		return nil, errToolManifestInput
	}
	document := expectedToolManifest(subject, linuxController, windowsController)
	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		return nil, errToolManifestEncoding
	}
	if len(raw) == 0 || len(raw) > toolManifestMaxBytes {
		return nil, errToolManifestBytes
	}
	return raw, nil
}

func parseCanonicalToolManifest(
	raw []byte,
	expected Subject,
	linuxController, windowsController []byte,
) (sourceQualificationToolManifest, error) {
	if validateSourceSubject(expected) != nil || len(linuxController) == 0 || len(windowsController) == 0 {
		return sourceQualificationToolManifest{}, errToolManifestInput
	}
	result, err := decodeCanonicalToolManifest(raw)
	if err != nil {
		return sourceQualificationToolManifest{}, err
	}
	want := expectedToolManifest(expected, linuxController, windowsController)
	if result.ArtifactType != want.ArtifactType ||
		result.SchemaVersion != want.SchemaVersion ||
		result.Subject != want.Subject ||
		len(result.Tools) != len(want.Tools) {
		return sourceQualificationToolManifest{}, errToolManifestContract
	}
	for index := range want.Tools {
		if result.Tools[index] != want.Tools[index] {
			return sourceQualificationToolManifest{}, errToolManifestContract
		}
	}
	return result, nil
}

func decodeCanonicalToolManifest(raw []byte) (sourceQualificationToolManifest, error) {
	var result sourceQualificationToolManifest
	if len(raw) == 0 || len(raw) > toolManifestMaxBytes {
		return result, errToolManifestBytes
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: toolManifestMaxBytes,
		MaxDepth: toolManifestMaxDepth,
		MaxNodes: toolManifestMaxNodes,
	})
	if err != nil {
		return result, errToolManifestJSON
	}
	canonical, err := canonicaljson.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return result, errToolManifestCanonical
	}
	if !validToolManifestShape(value) {
		return result, errToolManifestShape
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return sourceQualificationToolManifest{}, errToolManifestShape
	}
	return result, nil
}

func expectedToolManifest(
	subject Subject,
	linuxController, windowsController []byte,
) sourceQualificationToolManifest {
	return sourceQualificationToolManifest{
		ArtifactType:  toolManifestArtifactType,
		SchemaVersion: toolManifestSchemaVersion,
		Subject:       subject,
		Tools: []sourceQualificationTool{
			expectedTool("linux", toolManifestLinuxPath, subject.TestedRevision, linuxController),
			expectedTool("windows", toolManifestWindowsPath, subject.TestedRevision, windowsController),
		},
	}
}

func expectedTool(goos, path, testedRevision string, controller []byte) sourceQualificationTool {
	return sourceQualificationTool{
		GOARCH:      "amd64",
		GOOS:        goos,
		GoVersion:   toolManifestGoVersion,
		MainPackage: toolManifestMainPackage,
		ModulePath:  toolManifestModulePath,
		Path:        path,
		SHA256:      sha256Digest(controller),
		Size:        int64(len(controller)),
		VCSModified: false,
		VCSRevision: testedRevision,
	}
}

func validToolManifestShape(value any) bool {
	root, ok := value.(map[string]any)
	if !ok || !hasExactToolManifestKeys(root, []string{"artifactType", "schemaVersion", "subject", "tools"}) {
		return false
	}
	subject, ok := root["subject"].(map[string]any)
	if !ok || !hasExactToolManifestKeys(subject, []string{
		"baseRevision", "dirty", "gitObjectFormat", "modulePath", "moduleVersion",
		"repository", "testedRevision", "treeSHA",
	}) {
		return false
	}
	tools, ok := root["tools"].([]any)
	if !ok || len(tools) != 2 {
		return false
	}
	for _, value := range tools {
		tool, ok := value.(map[string]any)
		if !ok || !hasExactToolManifestKeys(tool, []string{
			"goarch", "goos", "goVersion", "mainPackage", "modulePath", "path",
			"sha256", "size", "vcsModified", "vcsRevision",
		}) {
			return false
		}
	}
	return true
}

func hasExactToolManifestKeys(object map[string]any, expected []string) bool {
	if len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	return true
}
