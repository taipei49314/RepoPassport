package sourcequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
	"golang.org/x/mod/modfile"
)

const (
	canonicalRepositoryURL = "https://github.com/taipei49314/RepoPassport"
	canonicalModulePath    = "github.com/taipei49314/RepoPassport"
	canonicalModuleVersion = "0.1.0-alpha.33"
	legacyModulePath       = "github.com/repopass/repopass"

	manifestArtifactType  = "repopass-source-archive-manifest"
	manifestSchemaVersion = "1"
	archiveFormat         = "ustar-v1"
	archiveFilename       = "repopass-source.tar"
	maxManifestBytes      = 16 << 20
	maxManifestDepth      = 16
	maxManifestNodes      = 200_000
)

// Subject binds source qualification to one exact public repository object.
type Subject struct {
	BaseRevision    string `json:"baseRevision"`
	Dirty           bool   `json:"dirty"`
	GitObjectFormat string `json:"gitObjectFormat"`
	ModulePath      string `json:"modulePath"`
	ModuleVersion   string `json:"moduleVersion"`
	Repository      string `json:"repository"`
	TestedRevision  string `json:"testedRevision"`
	TreeSHA         string `json:"treeSHA"`
}

type sourceArchiveManifest struct {
	Archive       sourceArchiveBinding `json:"archive"`
	ArtifactType  string               `json:"artifactType"`
	Files         []sourceManifestFile `json:"files"`
	SchemaVersion string               `json:"schemaVersion"`
	Subject       Subject              `json:"subject"`
}

type sourceArchiveBinding struct {
	Format string `json:"format"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type sourceManifestFile struct {
	GitBlobSHA1 string `json:"gitBlobSHA1"`
	GitMode     string `json:"gitMode"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
}

func buildSourcePackage(subject Subject, files []archiveFile) ([]byte, []byte, error) {
	if err := validateSourceSubject(subject); err != nil {
		return nil, nil, err
	}
	ordered, _, err := normalizeArchiveFiles(files)
	if err != nil {
		return nil, nil, err
	}
	if err := validateSourceModule(ordered); err != nil {
		return nil, nil, err
	}
	treeSHA, err := reconstructGitTreeSHA1(ordered)
	if err != nil {
		return nil, nil, err
	}
	if treeSHA != subject.TreeSHA {
		return nil, nil, errors.New("source files do not reproduce the subject tree")
	}
	archive, err := buildCanonicalArchive(ordered)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := marshalSourceManifest(subject, ordered, archive)
	if err != nil {
		return nil, nil, err
	}
	return archive, manifest, nil
}

func verifySourcePackage(archive, manifest []byte, expected Subject) error {
	if err := validateSourceSubject(expected); err != nil {
		return err
	}
	parsed, err := parseCanonicalSourceManifest(manifest)
	if err != nil {
		return err
	}
	if parsed.Subject != expected {
		return errors.New("source manifest subject does not match the expected subject")
	}
	files, err := parseCanonicalArchiveFiles(archive)
	if err != nil {
		return err
	}
	if err := validateSourceModule(files); err != nil {
		return err
	}
	if err := verifyCanonicalArchive(archive, files, expected.TreeSHA); err != nil {
		return err
	}
	rebuilt, err := marshalSourceManifest(expected, files, archive)
	if err != nil {
		return err
	}
	if !bytes.Equal(rebuilt, manifest) {
		return errors.New("source manifest does not reproduce the archive")
	}
	return nil
}

func marshalSourceManifest(subject Subject, files []archiveFile, archive []byte) ([]byte, error) {
	records := make([]sourceManifestFile, len(files))
	for index, file := range files {
		records[index] = sourceManifestFile{
			GitBlobSHA1: gitBlobSHA1(file.Data),
			GitMode:     file.GitMode,
			Path:        file.Path,
			SHA256:      sha256Digest(file.Data),
			Size:        int64(len(file.Data)),
		}
	}
	document := sourceArchiveManifest{
		Archive: sourceArchiveBinding{
			Format: archiveFormat,
			Name:   archiveFilename,
			SHA256: sha256Digest(archive),
			Size:   int64(len(archive)),
		},
		ArtifactType:  manifestArtifactType,
		Files:         records,
		SchemaVersion: manifestSchemaVersion,
		Subject:       subject,
	}
	raw, err := canonicaljson.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("marshal source manifest: %w", err)
	}
	if len(raw) > maxManifestBytes {
		return nil, errors.New("source manifest exceeds the byte limit")
	}
	return raw, nil
}

func parseCanonicalSourceManifest(raw []byte) (sourceArchiveManifest, error) {
	var result sourceArchiveManifest
	if len(raw) == 0 || len(raw) > maxManifestBytes || !utf8.Valid(raw) {
		return result, errors.New("source manifest bytes are invalid")
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: maxManifestBytes,
		MaxDepth: maxManifestDepth,
		MaxNodes: maxManifestNodes,
	})
	if err != nil {
		return result, errors.New("source manifest JSON is invalid")
	}
	canonical, err := canonicaljson.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return result, errors.New("source manifest JSON is not canonical")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return sourceArchiveManifest{}, errors.New("source manifest shape is invalid")
	}
	if result.ArtifactType != manifestArtifactType ||
		result.SchemaVersion != manifestSchemaVersion ||
		result.Archive.Format != archiveFormat ||
		result.Archive.Name != archiveFilename ||
		result.Archive.Size < 0 || result.Archive.Size > maxArchiveBytes ||
		!validSHA256Digest(result.Archive.SHA256) ||
		len(result.Files) == 0 || len(result.Files) > maxArchiveFiles ||
		validateSourceSubject(result.Subject) != nil {
		return sourceArchiveManifest{}, errors.New("source manifest contract is invalid")
	}
	return result, nil
}

func parseCanonicalArchiveFiles(archive []byte) ([]archiveFile, error) {
	if len(archive) < int(archiveTrailerSize) ||
		len(archive)%int(archiveBlockSize) != 0 ||
		int64(len(archive)) > maxArchiveBytes {
		return nil, errors.New("source archive length is invalid")
	}
	files := make([]archiveFile, 0)
	offset := 0
	trailerOffset := len(archive) - int(archiveTrailerSize)
	for offset < trailerOffset {
		if len(files) >= maxArchiveFiles || offset > trailerOffset-int(archiveBlockSize) {
			return nil, errors.New("source archive inventory is invalid")
		}
		header := archive[offset : offset+int(archiveBlockSize)]
		if zeroBytes(header) {
			return nil, errors.New("source archive terminates before the canonical trailer")
		}
		name, err := parseUSTARTextField(header[0:100])
		if err != nil {
			return nil, err
		}
		prefix, err := parseUSTARTextField(header[345:500])
		if err != nil {
			return nil, err
		}
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		mode := ""
		switch string(header[100:108]) {
		case "0000644\x00":
			mode = "100644"
		case "0000755\x00":
			mode = "100755"
		default:
			return nil, errors.New("source archive mode is invalid")
		}
		size, err := parseUSTARSize(header[124:136])
		if err != nil || size > maxArchiveFileBytes {
			return nil, errors.New("source archive member size is invalid")
		}
		offset += int(archiveBlockSize)
		if size > int64(trailerOffset-offset) {
			return nil, errors.New("source archive member is truncated")
		}
		dataEnd := offset + int(size)
		data := archive[offset:dataEnd]
		padding := (int(archiveBlockSize) - int(size)%int(archiveBlockSize)) % int(archiveBlockSize)
		if dataEnd > trailerOffset-padding || !zeroBytes(archive[dataEnd:dataEnd+padding]) {
			return nil, errors.New("source archive member padding is invalid")
		}
		files = append(files, archiveFile{Path: path, GitMode: mode, Data: data})
		offset = dataEnd + padding
	}
	if offset != trailerOffset || !zeroBytes(archive[trailerOffset:]) {
		return nil, errors.New("source archive trailer is invalid")
	}
	return files, nil
}

func parseUSTARTextField(field []byte) (string, error) {
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = len(field)
	} else if !zeroBytes(field[end:]) {
		return "", errors.New("source archive text field has trailing bytes")
	}
	return string(field[:end]), nil
}

func parseUSTARSize(field []byte) (int64, error) {
	if len(field) != 12 || field[11] != 0 {
		return 0, errors.New("source archive size field is invalid")
	}
	for _, digit := range field[:11] {
		if digit < '0' || digit > '7' {
			return 0, errors.New("source archive size is not canonical octal")
		}
	}
	return strconv.ParseInt(string(field[:11]), 8, 64)
}

func validateSourceSubject(subject Subject) error {
	if subject.Repository != canonicalRepositoryURL ||
		subject.ModulePath != canonicalModulePath ||
		subject.ModuleVersion != canonicalModuleVersion ||
		subject.GitObjectFormat != "sha1" || subject.Dirty ||
		!validGitSHA1(subject.BaseRevision) ||
		!validGitSHA1(subject.TestedRevision) ||
		!validGitSHA1(subject.TreeSHA) {
		return errors.New("source subject is invalid")
	}
	return nil
}

func validateSourceModule(files []archiveFile) error {
	var moduleData []byte
	for _, file := range files {
		switch file.Path {
		case "go.mod":
			if file.GitMode != "100644" || moduleData != nil {
				return errors.New("source module file is invalid")
			}
			moduleData = file.Data
		case "go.work":
			return errors.New("committed Go workspaces are not supported")
		}
	}
	if moduleData == nil || !utf8.Valid(moduleData) {
		return errors.New("source module file is missing or invalid")
	}
	parsed, err := modfile.Parse("go.mod", moduleData, nil)
	if err != nil || parsed.Module == nil || parsed.Module.Mod.Path != canonicalModulePath {
		return errors.New("source module path is not canonical")
	}
	for _, replacement := range parsed.Replace {
		if moduleNamespaceInvolved(replacement.Old.Path) ||
			moduleNamespaceInvolved(replacement.New.Path) {
			return errors.New("source module namespace replacement is forbidden")
		}
	}
	return nil
}

func moduleNamespaceInvolved(path string) bool {
	for _, namespace := range []string{canonicalModulePath, legacyModulePath} {
		if strings.EqualFold(path, namespace) ||
			len(path) > len(namespace) && path[len(namespace)] == '/' &&
				strings.EqualFold(path[:len(namespace)], namespace) {
			return true
		}
	}
	return false
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, current := range value[len("sha256:"):] {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}
