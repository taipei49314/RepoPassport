// Package spdx implements RepoPassport's bounded SPDX 2.3 JSON attachment
// profile. It validates and canonicalizes caller-supplied documents; it does
// not generate an SBOM or assert that an attachment is complete or correct.
package spdx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	MaxBytes   = 1 << 20
	Format     = "SPDX-2.3"
	MediaType  = "application/spdx+json"
	BundlePath = "payload/sbom.spdx.json"
)

var (
	elementIDPattern  = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)
	utcSecondsPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// Error is a fixed, non-sensitive validation or file-read classification.
type Error struct{ kind string }

func (e *Error) Error() string { return "SPDX attachment does not satisfy the bounded public profile" }
func (e *Error) Kind() string  { return e.kind }

func invalid(kind string) error { return &Error{kind: kind} }

type Document struct {
	SPDXID            string       `json:"SPDXID"`
	CreationInfo      CreationInfo `json:"creationInfo"`
	DataLicense       string       `json:"dataLicense"`
	DocumentDescribes []string     `json:"documentDescribes"`
	DocumentNamespace string       `json:"documentNamespace"`
	Name              string       `json:"name"`
	Packages          []Package    `json:"packages"`
	SPDXVersion       string       `json:"spdxVersion"`
}

type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type Package struct {
	SPDXID           string `json:"SPDXID"`
	CopyrightText    string `json:"copyrightText"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
}

type Metadata struct {
	Present bool   `json:"present"`
	Format  string `json:"format,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

func MetadataFor(canonical []byte) Metadata {
	if len(canonical) == 0 {
		return Metadata{}
	}
	sum := sha256.Sum256(canonical)
	return Metadata{Present: true, Format: Format, Digest: "sha256:" + hex.EncodeToString(sum[:])}
}

// Canonicalize validates exactly one bounded JSON document and returns the
// deterministic canonical derivative. Raw transport bytes are not retained.
func Canonicalize(raw []byte) (Document, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return Document{}, nil, invalid("transport")
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: MaxBytes, MaxDepth: 64, MaxNodes: 65_536,
	})
	if err != nil {
		return Document{}, nil, invalid("decode")
	}
	root, ok := value.(map[string]any)
	if !ok || !exactKeys(root, "SPDXID", "creationInfo", "dataLicense", "documentDescribes", "documentNamespace", "name", "packages", "spdxVersion") {
		return Document{}, nil, invalid("root")
	}
	var document Document
	if document.SPDXID, ok = stringField(root, "SPDXID"); !ok || document.SPDXID != "SPDXRef-DOCUMENT" {
		return Document{}, nil, invalid("document-id")
	}
	if document.SPDXVersion, ok = stringField(root, "spdxVersion"); !ok || document.SPDXVersion != Format {
		return Document{}, nil, invalid("version")
	}
	if document.DataLicense, ok = stringField(root, "dataLicense"); !ok || document.DataLicense != "CC0-1.0" {
		return Document{}, nil, invalid("data-license")
	}
	if document.Name, ok = stringField(root, "name"); !ok || !publicString(document.Name, 256) {
		return Document{}, nil, invalid("name")
	}
	if document.DocumentNamespace, ok = stringField(root, "documentNamespace"); !ok || len(document.DocumentNamespace) > 1024 || !safeHTTPS(document.DocumentNamespace) {
		return Document{}, nil, invalid("namespace")
	}
	creation, ok := root["creationInfo"].(map[string]any)
	if !ok || !exactKeys(creation, "created", "creators") {
		return Document{}, nil, invalid("creation-info")
	}
	if document.CreationInfo.Created, ok = stringField(creation, "created"); !ok || !canonicalUTCSeconds(document.CreationInfo.Created) {
		return Document{}, nil, invalid("created")
	}
	creatorValues, ok := creation["creators"].([]any)
	if !ok || len(creatorValues) < 1 || len(creatorValues) > 32 {
		return Document{}, nil, invalid("creators")
	}
	creatorSet := make(map[string]struct{}, len(creatorValues))
	for _, value := range creatorValues {
		creator, ok := value.(string)
		if !ok || !publicString(creator, 256) || !validCreator(creator) {
			return Document{}, nil, invalid("creator")
		}
		if _, duplicate := creatorSet[creator]; duplicate {
			return Document{}, nil, invalid("creator-duplicate")
		}
		creatorSet[creator] = struct{}{}
		document.CreationInfo.Creators = append(document.CreationInfo.Creators, creator)
	}
	packageValues, ok := root["packages"].([]any)
	if !ok || len(packageValues) < 1 || len(packageValues) > 512 {
		return Document{}, nil, invalid("packages")
	}
	packageIDs := make(map[string]struct{}, len(packageValues))
	packageNames := make(map[string]struct{}, len(packageValues))
	for _, value := range packageValues {
		object, ok := value.(map[string]any)
		if !ok || !optionalExactKeys(object, "versionInfo", "SPDXID", "copyrightText", "downloadLocation", "filesAnalyzed", "licenseConcluded", "licenseDeclared", "name") {
			return Document{}, nil, invalid("package-shape")
		}
		var item Package
		if item.SPDXID, ok = stringField(object, "SPDXID"); !ok || !elementID(item.SPDXID) || item.SPDXID == "SPDXRef-DOCUMENT" {
			return Document{}, nil, invalid("package-id")
		}
		if _, duplicate := packageIDs[item.SPDXID]; duplicate {
			return Document{}, nil, invalid("package-id-duplicate")
		}
		packageIDs[item.SPDXID] = struct{}{}
		if item.Name, ok = stringField(object, "name"); !ok || !publicString(item.Name, 256) {
			return Document{}, nil, invalid("package-name")
		}
		if _, duplicate := packageNames[item.Name]; duplicate {
			return Document{}, nil, invalid("package-name-duplicate")
		}
		packageNames[item.Name] = struct{}{}
		if version, exists := object["versionInfo"]; exists {
			item.VersionInfo, ok = version.(string)
			if !ok || !publicString(item.VersionInfo, 128) {
				return Document{}, nil, invalid("package-version")
			}
		}
		if item.FilesAnalyzed, ok = object["filesAnalyzed"].(bool); !ok || item.FilesAnalyzed {
			return Document{}, nil, invalid("files-analyzed")
		}
		for field, destination := range map[string]*string{
			"copyrightText":    &item.CopyrightText,
			"licenseConcluded": &item.LicenseConcluded,
			"licenseDeclared":  &item.LicenseDeclared,
		} {
			*destination, ok = stringField(object, field)
			if !ok || !sentinel(*destination) {
				return Document{}, nil, invalid("package-sentinel")
			}
		}
		if item.DownloadLocation, ok = stringField(object, "downloadLocation"); !ok ||
			!(sentinel(item.DownloadLocation) || len(item.DownloadLocation) <= 1024 && safeHTTPS(item.DownloadLocation)) {
			return Document{}, nil, invalid("download-location")
		}
		document.Packages = append(document.Packages, item)
	}
	describedValues, ok := root["documentDescribes"].([]any)
	if !ok || len(describedValues) < 1 || len(describedValues) > 512 || len(describedValues) != len(packageIDs) {
		return Document{}, nil, invalid("document-describes")
	}
	described := make(map[string]struct{}, len(describedValues))
	for _, value := range describedValues {
		identifier, ok := value.(string)
		if !ok || !elementID(identifier) {
			return Document{}, nil, invalid("described-id")
		}
		if _, duplicate := described[identifier]; duplicate {
			return Document{}, nil, invalid("described-duplicate")
		}
		if _, exists := packageIDs[identifier]; !exists {
			return Document{}, nil, invalid("described-reference")
		}
		described[identifier] = struct{}{}
		document.DocumentDescribes = append(document.DocumentDescribes, identifier)
	}
	canonical, err := canonicaljson.Marshal(document)
	if err != nil || len(canonical) == 0 || len(canonical) > MaxBytes {
		return Document{}, nil, invalid("canonical")
	}
	return document, canonical, nil
}

func exactKeys(object map[string]any, required ...string) bool {
	if len(object) != len(required) {
		return false
	}
	for _, key := range required {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	return true
}

func optionalExactKeys(object map[string]any, optional string, required ...string) bool {
	if len(object) != len(required) && len(object) != len(required)+1 {
		return false
	}
	for _, key := range required {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	_, hasOptional := object[optional]
	return len(object) == len(required) || hasOptional
}

func stringField(object map[string]any, key string) (string, bool) {
	value, ok := object[key].(string)
	return value, ok
}

func publicString(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func validCreator(value string) bool {
	for _, prefix := range []string{"Person: ", "Organization: ", "Tool: "} {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimSpace(value[len(prefix):]) != ""
		}
	}
	return false
}

func canonicalUTCSeconds(value string) bool {
	if !utcSecondsPattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05Z") == value
}

func safeHTTPS(value string) bool {
	if len(value) == 0 || len(value) > 1024 || strings.ContainsAny(value, "?#") || !strings.HasPrefix(value, "https:") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && !parsed.ForceQuery && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.RawFragment == "" && parsed.Opaque == ""
}

func elementID(value string) bool {
	return len(value) <= 128 && elementIDPattern.MatchString(value)
}

func sentinel(value string) bool { return value == "NONE" || value == "NOASSERTION" }

// SortedPackageIDs is used only by deterministic tests and evidence tooling.
func SortedPackageIDs(document Document) []string {
	result := make([]string, 0, len(document.Packages))
	for _, item := range document.Packages {
		result = append(result, item.SPDXID)
	}
	sort.Strings(result)
	return result
}

func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
}
