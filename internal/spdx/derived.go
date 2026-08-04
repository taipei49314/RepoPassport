package spdx

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

const (
	DerivedProfile        = "npm-package-lock-v1"
	DerivedSourceProfile  = "local-snapshot-v1"
	DerivedOrigin         = "repository-derived"
	DerivedScope          = "locked-packages"
	DerivedCompleteness   = "lockfile-only"
	DerivedProvenancePath = "payload/sbom-provenance.json"
	DerivedRulesetDigest  = "sha256:c73397279cfd48a8a1331a49ceeac90882ae7649b6c279ff0d10830252aceb5e"
	MaxDerivedPackages    = 2048
	MaxDerivedRelations   = 8192
)

const derivedRulesetDescriptor = `{"alternateRootLockfiles":["bun.lock","bun.lockb","npm-shrinkwrap.json","pnpm-lock.yaml","yarn.lock"],"canonicalOrdering":{"packages":"spdx-id-ascending","relationships":"source-nul-target-ascending"},"creationTime":"1970-01-01T00:00:00Z","dependencyFields":{"nested":["dependencies","optionalDependencies"],"root":["dependencies","devDependencies","optionalDependencies"]},"dependencySpec":"strict-semver2-exact-target-version","descriptorFlags":["dev","devOptional","hasInstallScript","hasShrinkwrap","optional"],"descriptorLicense":"bounded-public-string","documentNamespace":"https://repopass.dev/spdx/npm-package-lock-v1/<derivation-input-sha256>","documentProfile":"spdx-2.3-repopass-derived-v1","edgeResolution":"location/node_modules/name-then-ascend-package-boundaries-to-root","id":"SPDXRef-Root-or-SPDXRef-Package-full-sha256-install-location","inputFiles":["package-lock.json","package.json"],"inputRead":"unlinked-parents-no-reparse-single-link-same-handle-double-read-matches-snapshot","installPathGrammar":"(node_modules/npm-name)(/node_modules/npm-name)*","integrity":"nonroot-single-exact-sha512-standard-base64-64-byte","lockfileVersion":3,"maxBytes":1048576,"maxDepth":64,"maxNodes":65536,"maxPackages":2048,"maxRelations":8192,"packageReachability":"all-packages-from-root","profile":"npm-package-lock-v1","registry":"nonroot-https://registry.npmjs.org/<exact-full-name>/-/<base>-<version>.tgz","relationships":["DEPENDS_ON"],"rootTransportFields":"resolved-and-integrity-presence-rejected","sourceProfile":"local-snapshot-v1","spdxChecksum":"SHA512-lowerhex","unknownFieldPolicy":{"lockDescriptor":"reject-unknown","lockRoot":"reject-unknown","packageJSON":"ignore-nonsemantic"},"unsupportedSemantics":["bin","bundle","cpu","engines","file","funding","git","link","npm-alias","os","overrides","peer","workspace"],"version":"1"}`

var derivedAlternateRootLockfiles = map[string]struct{}{
	"bun.lock":            {},
	"bun.lockb":           {},
	"npm-shrinkwrap.json": {},
	"pnpm-lock.yaml":      {},
	"yarn.lock":           {},
}

var (
	derivedPackageNamePattern = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	derivedPackageIDPattern   = regexp.MustCompile(`^SPDXRef-Package-[0-9a-f]{64}$`)
)

// DerivedError deliberately carries only a fixed classification. Repository
// paths, package names, versions, URLs, and lockfile content never cross the
// public error boundary.
type DerivedError struct{ kind string }

func (e *DerivedError) Error() string {
	return "repository inputs do not satisfy the bounded derived SPDX profile"
}
func (e *DerivedError) Kind() string { return e.kind }

func invalidDerived(kind string) error { return &DerivedError{kind: kind} }

type DerivedInputRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// DerivedProvenance is the exact signed repository-derivation claim. It does
// not contain repository paths, registry identities, or producer identities.
type DerivedProvenance struct {
	Origin                string               `json:"origin"`
	Profile               string               `json:"profile"`
	RulesetDigest         string               `json:"rulesetDigest"`
	SourceProfile         string               `json:"sourceProfile"`
	SourceTreeDigest      string               `json:"sourceTreeDigest"`
	Inputs                []DerivedInputRecord `json:"inputs"`
	DerivationInputDigest string               `json:"derivationInputDigest"`
	Scope                 string               `json:"scope"`
	Completeness          string               `json:"completeness"`
}

type DerivedDocument struct {
	SPDXID            string                `json:"SPDXID"`
	CreationInfo      CreationInfo          `json:"creationInfo"`
	DataLicense       string                `json:"dataLicense"`
	DocumentDescribes []string              `json:"documentDescribes"`
	DocumentNamespace string                `json:"documentNamespace"`
	Name              string                `json:"name"`
	Packages          []DerivedPackage      `json:"packages"`
	Relationships     []DerivedRelationship `json:"relationships"`
	SPDXVersion       string                `json:"spdxVersion"`
}

type DerivedPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Checksums        []DerivedChecksum `json:"checksums,omitempty"`
	CopyrightText    string            `json:"copyrightText"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
}

type DerivedChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type DerivedRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

type DerivedArtifact struct {
	Document            DerivedDocument
	SPDX                []byte
	Provenance          DerivedProvenance
	ProvenanceCanonical []byte
}

type derivationInputs struct {
	Profile          string               `json:"profile"`
	RulesetDigest    string               `json:"rulesetDigest"`
	SourceProfile    string               `json:"sourceProfile"`
	SourceTreeDigest string               `json:"sourceTreeDigest"`
	Inputs           []DerivedInputRecord `json:"inputs"`
}

type acceptedLockPackage struct {
	installPath  string
	name         string
	version      string
	checksum     DerivedChecksum
	dependencies map[string]string
	spdxID       string
}

// DerivePackageLockV3 statically derives a bounded SPDX 2.3 document from the
// exact two root inputs recorded by a previously stable source snapshot. Each
// file is independently read with the no-link same-handle double-read profile
// and its bytes must match the snapshot path, size, and SHA-256 record.
func DerivePackageLockV3(snapshot domain.SourceSnapshot) (DerivedArtifact, error) {
	if validateDerivedSnapshot(snapshot) != nil {
		return DerivedArtifact{}, invalidDerived("source")
	}
	records, raw, err := readDerivedInputs(snapshot)
	if err != nil {
		return DerivedArtifact{}, err
	}
	defer func() {
		clear(raw["package.json"])
		clear(raw["package-lock.json"])
	}()

	inputDigest, err := canonicaljson.Digest(derivationInputs{
		Profile:          DerivedProfile,
		RulesetDigest:    DerivedRulesetDigest,
		SourceProfile:    DerivedSourceProfile,
		SourceTreeDigest: snapshot.TreeDigest,
		Inputs:           records,
	})
	if err != nil {
		return DerivedArtifact{}, invalidDerived("input-digest")
	}
	packages, relations, rootID, err := parsePackageLockV3(raw["package.json"], raw["package-lock.json"])
	if err != nil {
		return DerivedArtifact{}, err
	}
	document := DerivedDocument{
		SPDXID: "SPDXRef-DOCUMENT",
		CreationInfo: CreationInfo{
			Created:  "1970-01-01T00:00:00Z",
			Creators: []string{"Tool: RepoPassport/npm-package-lock-v1"},
		},
		DataLicense:       "CC0-1.0",
		DocumentDescribes: []string{rootID},
		DocumentNamespace: "https://repopass.dev/spdx/npm-package-lock-v1/" + strings.TrimPrefix(inputDigest, "sha256:"),
		Name:              "RepoPassport repository-derived npm lock SBOM",
		Packages:          packages,
		Relationships:     relations,
		SPDXVersion:       Format,
	}
	spdxJSON, err := canonicaljson.Marshal(document)
	if err != nil || len(spdxJSON) == 0 || len(spdxJSON) > MaxBytes {
		return DerivedArtifact{}, invalidDerived("spdx-size")
	}
	validated, canonical, err := CanonicalizeDerived(spdxJSON)
	if err != nil || !bytes.Equal(canonical, spdxJSON) {
		return DerivedArtifact{}, invalidDerived("spdx")
	}
	provenance := DerivedProvenance{
		Origin: DerivedOrigin, Profile: DerivedProfile,
		RulesetDigest: DerivedRulesetDigest, SourceProfile: DerivedSourceProfile,
		SourceTreeDigest: snapshot.TreeDigest, Inputs: records,
		DerivationInputDigest: inputDigest, Scope: DerivedScope,
		Completeness: DerivedCompleteness,
	}
	provenanceJSON, err := canonicaljson.Marshal(provenance)
	if err != nil {
		return DerivedArtifact{}, invalidDerived("provenance")
	}
	return DerivedArtifact{
		Document: validated, SPDX: spdxJSON,
		Provenance: provenance, ProvenanceCanonical: provenanceJSON,
	}, nil
}

func validateDerivedSnapshot(snapshot domain.SourceSnapshot) error {
	if snapshot.Root == "" || snapshot.Commit != "" || snapshot.Identity != snapshot.TreeDigest ||
		!validSHA256(snapshot.TreeDigest) || snapshot.FileCount != len(snapshot.Inventory) ||
		len(snapshot.Inventory) < 2 || snapshot.TotalSize < 0 {
		return invalidDerived("source-snapshot")
	}
	var total int64
	previousPath := ""
	for _, entry := range snapshot.Inventory {
		if entry.Path == "" || entry.Path <= previousPath || entry.Size < 0 || !validSHA256(entry.Digest) ||
			(entry.Mode != "0644" && entry.Mode != "0755") || entry.Size > snapshot.TotalSize-total {
			return invalidDerived("source-inventory")
		}
		if _, alternate := derivedAlternateRootLockfiles[entry.Path]; alternate {
			return invalidDerived("alternate-lockfile")
		}
		total += entry.Size
		previousPath = entry.Path
	}
	if total != snapshot.TotalSize {
		return invalidDerived("source-total")
	}
	digest, err := canonicaljson.Digest(snapshot.Inventory)
	if err != nil || digest != snapshot.TreeDigest {
		return invalidDerived("source-tree")
	}
	return nil
}

func readDerivedInputs(snapshot domain.SourceSnapshot) ([]DerivedInputRecord, map[string][]byte, error) {
	wanted := map[string]domain.FileEntry{}
	for _, entry := range snapshot.Inventory {
		if entry.Path != "package.json" && entry.Path != "package-lock.json" {
			continue
		}
		if _, duplicate := wanted[entry.Path]; duplicate || entry.Size < 1 || entry.Size > MaxBytes || !validSHA256(entry.Digest) {
			return nil, nil, invalidDerived("inventory")
		}
		wanted[entry.Path] = entry
	}
	if len(wanted) != 2 {
		return nil, nil, invalidDerived("inventory")
	}
	paths := []string{"package-lock.json", "package.json"}
	records := make([]DerivedInputRecord, 0, len(paths))
	raw := make(map[string][]byte, len(paths))
	for _, relative := range paths {
		entry := wanted[relative]
		content, err := ReadDerivedFile(filepath.Join(snapshot.Root, relative))
		if err != nil || int64(len(content)) != entry.Size || Digest(content) != entry.Digest {
			clear(content)
			for _, previous := range raw {
				clear(previous)
			}
			return nil, nil, invalidDerived("input-read")
		}
		raw[relative] = content
		records = append(records, DerivedInputRecord{Path: relative, SHA256: entry.Digest, Size: entry.Size})
	}
	return records, raw, nil
}

func parsePackageLockV3(packageJSON, lockJSON []byte) ([]DerivedPackage, []DerivedRelationship, string, error) {
	packageRoot, err := decodeJSONObject(packageJSON)
	if err != nil || hasAnyKey(packageRoot, "workspaces", "bundledDependencies", "bundleDependencies", "peerDependencies", "peerDependenciesMeta", "overrides") {
		return nil, nil, "", invalidDerived("package-json")
	}
	rootName, ok := requiredPackageName(packageRoot, "name")
	if !ok {
		return nil, nil, "", invalidDerived("package-json-name")
	}
	rootVersion, ok := requiredVersion(packageRoot, "version")
	if !ok {
		return nil, nil, "", invalidDerived("package-json-version")
	}

	lockRoot, err := decodeJSONObject(lockJSON)
	if err != nil || !onlyKeys(lockRoot, "name", "version", "lockfileVersion", "requires", "packages") {
		return nil, nil, "", invalidDerived("lock-root")
	}
	versionNumber, ok := lockRoot["lockfileVersion"].(json.Number)
	if !ok || versionNumber.String() != "3" {
		return nil, nil, "", invalidDerived("lock-version")
	}
	if value, exists := lockRoot["requires"]; exists {
		requires, valid := value.(bool)
		if !valid || !requires {
			return nil, nil, "", invalidDerived("lock-requires")
		}
	}
	if value, exists := lockRoot["name"]; !exists || value != rootName {
		return nil, nil, "", invalidDerived("lock-name")
	}
	if value, exists := lockRoot["version"]; !exists || value != rootVersion {
		return nil, nil, "", invalidDerived("lock-version-info")
	}
	packageValues, ok := lockRoot["packages"].(map[string]any)
	if !ok || len(packageValues) < 1 || len(packageValues) > MaxDerivedPackages {
		return nil, nil, "", invalidDerived("lock-packages")
	}
	rootValue, ok := packageValues[""].(map[string]any)
	if !ok || hasAnyKey(rootValue,
		"workspaces", "bundledDependencies", "bundleDependencies", "peerDependencies", "peerDependenciesMeta", "overrides",
		"resolved", "integrity",
	) {
		return nil, nil, "", invalidDerived("lock-root-package")
	}
	if value, exists := rootValue["name"]; !exists || value != rootName {
		return nil, nil, "", invalidDerived("lock-root-name")
	}
	if value, exists := rootValue["version"]; !exists || value != rootVersion {
		return nil, nil, "", invalidDerived("lock-root-version")
	}
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		packageMap, packageErr := optionalStringMap(packageRoot, field)
		lockMap, lockErr := optionalStringMap(rootValue, field)
		if packageErr != nil || lockErr != nil || !equalStringMaps(packageMap, lockMap) {
			return nil, nil, "", invalidDerived("root-dependencies")
		}
	}

	installPaths := make([]string, 0, len(packageValues))
	for installPath := range packageValues {
		installPaths = append(installPaths, installPath)
	}
	sort.Strings(installPaths)
	accepted := make(map[string]*acceptedLockPackage, len(installPaths))
	for _, installPath := range installPaths {
		object, ok := packageValues[installPath].(map[string]any)
		if !ok {
			return nil, nil, "", invalidDerived("lock-package-shape")
		}
		if !onlyKeys(object,
			"name", "version", "resolved", "integrity", "dependencies", "devDependencies", "optionalDependencies",
			"peerDependencies", "peerDependenciesMeta", "dev", "optional", "devOptional", "inBundle", "hasInstallScript",
			"hasShrinkwrap", "license", "engines", "bin", "funding", "cpu", "os", "link", "bundleDependencies",
			"bundledDependencies", "overrides",
		) {
			return nil, nil, "", invalidDerived("lock-package-field")
		}
		name, pathOK := packageNameFromInstallPath(installPath)
		if !pathOK {
			return nil, nil, "", invalidDerived("lock-package-path")
		}
		if installPath == "" {
			name = rootName
		}
		if declared, exists := object["name"]; exists && declared != name {
			return nil, nil, "", invalidDerived("lock-package-name")
		}
		version, ok := requiredVersion(object, "version")
		if !ok {
			return nil, nil, "", invalidDerived("lock-package-version")
		}
		unsupportedFields := []string{"bundledDependencies", "bundleDependencies", "peerDependencies", "peerDependenciesMeta", "overrides", "link", "inBundle"}
		unsupportedFields = append(unsupportedFields, "engines", "bin", "funding", "cpu", "os")
		if installPath != "" {
			unsupportedFields = append(unsupportedFields, "devDependencies")
		}
		if hasAnyKey(object, unsupportedFields...) {
			return nil, nil, "", invalidDerived("lock-package-unsupported")
		}
		if !validOptionalBooleans(object, "dev", "optional", "devOptional", "hasInstallScript", "hasShrinkwrap") {
			return nil, nil, "", invalidDerived("lock-package-flag")
		}
		if license, exists := object["license"]; exists {
			value, valid := license.(string)
			if !valid || !publicString(value, 256) {
				return nil, nil, "", invalidDerived("lock-package-license")
			}
		}
		dependencies, err := acceptedDependencies(object, installPath == "")
		if err != nil {
			return nil, nil, "", err
		}
		checksum := DerivedChecksum{}
		if installPath != "" {
			resolved, valid := object["resolved"].(string)
			if !valid || !validRegistryResolution(resolved, name, version) {
				return nil, nil, "", invalidDerived("lock-package-resolution")
			}
			integrity, valid := object["integrity"].(string)
			if !valid {
				return nil, nil, "", invalidDerived("lock-package-integrity")
			}
			checksum, err = sriChecksum(integrity)
			if err != nil {
				return nil, nil, "", err
			}
		}
		identifier := derivedPackageID(installPath)
		accepted[installPath] = &acceptedLockPackage{
			installPath: installPath, name: name, version: version,
			checksum: checksum, dependencies: dependencies, spdxID: identifier,
		}
	}

	type edge struct{ from, to string }
	edges := make([]edge, 0)
	adjacency := make(map[string][]string, len(accepted))
	for _, installPath := range installPaths {
		item := accepted[installPath]
		dependencyNames := make([]string, 0, len(item.dependencies))
		for dependency := range item.dependencies {
			dependencyNames = append(dependencyNames, dependency)
		}
		sort.Strings(dependencyNames)
		for _, dependency := range dependencyNames {
			targetPath, found := resolveLockDependency(installPath, dependency, accepted)
			if !found || accepted[targetPath].version != item.dependencies[dependency] {
				return nil, nil, "", invalidDerived("lock-dependency-missing")
			}
			edges = append(edges, edge{from: item.spdxID, to: accepted[targetPath].spdxID})
			adjacency[installPath] = append(adjacency[installPath], targetPath)
		}
	}
	if len(edges) > MaxDerivedRelations || !allReachable(installPaths, adjacency) {
		return nil, nil, "", invalidDerived("lock-graph")
	}

	packages := make([]DerivedPackage, 0, len(accepted))
	for _, item := range accepted {
		pkg := DerivedPackage{
			SPDXID: item.spdxID, CopyrightText: "NOASSERTION",
			DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
			LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION",
			Name: item.name, VersionInfo: item.version,
		}
		if item.installPath != "" {
			pkg.Checksums = []DerivedChecksum{item.checksum}
		}
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].SPDXID < packages[j].SPDXID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].from == edges[j].from {
			return edges[i].to < edges[j].to
		}
		return edges[i].from < edges[j].from
	})
	relations := make([]DerivedRelationship, 0, len(edges))
	for index, item := range edges {
		if index != 0 && edges[index-1] == item {
			continue
		}
		relations = append(relations, DerivedRelationship{
			SPDXElementID: item.from, RelatedSPDXElement: item.to,
			RelationshipType: "DEPENDS_ON",
		})
	}
	return packages, relations, accepted[""].spdxID, nil
}

func decodeJSONObject(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, invalidDerived("transport")
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{MaxBytes: MaxBytes, MaxDepth: 64, MaxNodes: 65_536})
	if err != nil {
		return nil, invalidDerived("decode")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalidDerived("object")
	}
	return object, nil
}

func onlyKeys(object map[string]any, allowed ...string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		set[key] = struct{}{}
	}
	for key := range object {
		if _, ok := set[key]; !ok {
			return false
		}
	}
	return true
}

func hasNonEmpty(object map[string]any, fields ...string) bool {
	for _, field := range fields {
		value, exists := object[field]
		if !exists || value == nil {
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) != 0 {
				return true
			}
		case []any:
			if len(typed) != 0 {
				return true
			}
		case bool:
			if typed {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func hasAnyKey(object map[string]any, fields ...string) bool {
	for _, field := range fields {
		if _, exists := object[field]; exists {
			return true
		}
	}
	return false
}

func validOptionalBooleans(object map[string]any, fields ...string) bool {
	for _, field := range fields {
		if value, exists := object[field]; exists {
			if _, ok := value.(bool); !ok {
				return false
			}
		}
	}
	return true
}

func requiredPackageName(object map[string]any, field string) (string, bool) {
	value, ok := object[field].(string)
	return value, ok && len(value) <= 214 && derivedPackageNamePattern.MatchString(value)
}

func requiredVersion(object map[string]any, field string) (string, bool) {
	value, ok := object[field].(string)
	return value, ok && validSemVer(value)
}

func optionalStringMap(object map[string]any, field string) (map[string]string, error) {
	value, exists := object[field]
	if !exists {
		return map[string]string{}, nil
	}
	values, ok := value.(map[string]any)
	if !ok || len(values) > MaxDerivedPackages {
		return nil, invalidDerived("dependency-map")
	}
	result := make(map[string]string, len(values))
	for name, item := range values {
		spec, ok := item.(string)
		if !ok || len(spec) == 0 || len(spec) > 128 || len(name) > 214 || !derivedPackageNamePattern.MatchString(name) || unsafeDependencySpec(spec) {
			return nil, invalidDerived("dependency-map")
		}
		result[name] = spec
	}
	return result, nil
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func unsafeDependencySpec(value string) bool {
	return strings.TrimSpace(value) != value || !validSemVer(value)
}

func acceptedDependencies(object map[string]any, includeDev bool) (map[string]string, error) {
	merged := make(map[string]string)
	fields := []string{"dependencies", "optionalDependencies"}
	if includeDev {
		fields = []string{"dependencies", "devDependencies", "optionalDependencies"}
	}
	for _, field := range fields {
		values, err := optionalStringMap(object, field)
		if err != nil {
			return nil, err
		}
		for name, spec := range values {
			if previous, duplicate := merged[name]; duplicate && previous != spec {
				return nil, invalidDerived("dependency-conflict")
			}
			merged[name] = spec
		}
	}
	return merged, nil
}

func packageNameFromInstallPath(installPath string) (string, bool) {
	if installPath == "" {
		return "", true
	}
	if installPath != path.Clean(installPath) || strings.ContainsAny(installPath, "\\:") || strings.HasPrefix(installPath, "/") {
		return "", false
	}
	segments := strings.Split(installPath, "/")
	if len(segments) < 2 {
		return "", false
	}
	for index := 0; index < len(segments); {
		if segments[index] != "node_modules" || index+1 >= len(segments) {
			return "", false
		}
		index++
		name := segments[index]
		if strings.HasPrefix(name, "@") {
			if index+1 >= len(segments) {
				return "", false
			}
			name += "/" + segments[index+1]
			index += 2
		} else {
			index++
		}
		if len(name) > 214 || !derivedPackageNamePattern.MatchString(name) {
			return "", false
		}
		if index == len(segments) {
			return name, true
		}
	}
	return "", false
}

func validRegistryResolution(value, packageName, version string) bool {
	if len(value) == 0 || len(value) > 1024 || strings.ContainsAny(value, "?#") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "registry.npmjs.org" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.Opaque != "" {
		return false
	}
	baseName := packageName
	if slash := strings.LastIndex(baseName, "/"); slash >= 0 {
		baseName = baseName[slash+1:]
	}
	wantPath := "/" + packageName + "/-/" + baseName + "-" + version + ".tgz"
	return parsed.Path == wantPath
}

func sriChecksum(value string) (DerivedChecksum, error) {
	if strings.TrimSpace(value) != value || strings.Count(value, "-") != 1 || strings.ContainsAny(value, " \t\r\n?") {
		return DerivedChecksum{}, invalidDerived("sri")
	}
	parts := strings.SplitN(value, "-", 2)
	algorithm := ""
	expected := 0
	switch parts[0] {
	case "sha512":
		algorithm, expected = "SHA512", 64
	default:
		return DerivedChecksum{}, invalidDerived("sri-algorithm")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(decoded) != expected || base64.StdEncoding.EncodeToString(decoded) != parts[1] {
		return DerivedChecksum{}, invalidDerived("sri-value")
	}
	return DerivedChecksum{Algorithm: algorithm, ChecksumValue: hex.EncodeToString(decoded)}, nil
}

func derivedPackageID(installPath string) string {
	if installPath == "" {
		return "SPDXRef-Root"
	}
	digest := sha256.Sum256([]byte(installPath))
	return "SPDXRef-Package-" + hex.EncodeToString(digest[:])
}

func resolveLockDependency(currentPath, dependency string, packages map[string]*acceptedLockPackage) (string, bool) {
	if currentPath != "" {
		candidate := currentPath + "/node_modules/" + dependency
		if _, ok := packages[candidate]; ok {
			return candidate, true
		}
		ancestor := currentPath
		for {
			index := strings.LastIndex(ancestor, "/node_modules/")
			if index < 0 {
				break
			}
			ancestor = ancestor[:index]
			candidate = ancestor + "/node_modules/" + dependency
			if _, ok := packages[candidate]; ok {
				return candidate, true
			}
		}
	}
	candidate := "node_modules/" + dependency
	_, ok := packages[candidate]
	return candidate, ok
}

func allReachable(paths []string, adjacency map[string][]string) bool {
	seen := map[string]struct{}{"": {}}
	queue := []string{""}
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range adjacency[current] {
			if _, exists := seen[next]; exists {
				continue
			}
			seen[next] = struct{}{}
			queue = append(queue, next)
		}
	}
	return len(seen) == len(paths)
}

// CanonicalizeDerived validates only the repository-derived SPDX profile. It
// intentionally does not call or widen Canonicalize's caller-supplied profile.
func CanonicalizeDerived(raw []byte) (DerivedDocument, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return DerivedDocument{}, nil, invalidDerived("derived-transport")
	}
	if _, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{MaxBytes: MaxBytes, MaxDepth: 64, MaxNodes: 65_536}); err != nil {
		return DerivedDocument{}, nil, invalidDerived("derived-decode")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document DerivedDocument
	if err := decoder.Decode(&document); err != nil {
		return DerivedDocument{}, nil, invalidDerived("derived-shape")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || validateDerivedDocument(document) != nil {
		return DerivedDocument{}, nil, invalidDerived("derived-profile")
	}
	canonical, err := canonicaljson.Marshal(document)
	if err != nil || len(canonical) == 0 || len(canonical) > MaxBytes {
		return DerivedDocument{}, nil, invalidDerived("derived-canonical")
	}
	return document, canonical, nil
}

func validateDerivedDocument(document DerivedDocument) error {
	if document.SPDXID != "SPDXRef-DOCUMENT" || document.SPDXVersion != Format || document.DataLicense != "CC0-1.0" ||
		document.Name != "RepoPassport repository-derived npm lock SBOM" ||
		document.CreationInfo.Created != "1970-01-01T00:00:00Z" ||
		len(document.CreationInfo.Creators) != 1 || document.CreationInfo.Creators[0] != "Tool: RepoPassport/npm-package-lock-v1" ||
		len(document.DocumentDescribes) != 1 || document.DocumentDescribes[0] != "SPDXRef-Root" ||
		!validDerivedNamespace(document.DocumentNamespace) || len(document.Packages) < 1 || len(document.Packages) > MaxDerivedPackages ||
		len(document.Relationships) > MaxDerivedRelations {
		return invalidDerived("derived-document")
	}
	ids := make(map[string]struct{}, len(document.Packages))
	previousID := ""
	rootFound := false
	for _, item := range document.Packages {
		if item.SPDXID <= previousID || !validDerivedPackageID(item.SPDXID) {
			return invalidDerived("derived-package-order")
		}
		previousID = item.SPDXID
		if _, duplicate := ids[item.SPDXID]; duplicate || len(item.Name) == 0 || len(item.Name) > 214 ||
			!derivedPackageNamePattern.MatchString(item.Name) || !validSemVer(item.VersionInfo) ||
			item.FilesAnalyzed || item.DownloadLocation != "NOASSERTION" ||
			item.CopyrightText != "NOASSERTION" || item.LicenseConcluded != "NOASSERTION" || item.LicenseDeclared != "NOASSERTION" {
			return invalidDerived("derived-package")
		}
		ids[item.SPDXID] = struct{}{}
		if item.SPDXID == "SPDXRef-Root" {
			rootFound = true
			if len(item.Checksums) != 0 {
				return invalidDerived("derived-root-checksum")
			}
		} else if len(item.Checksums) != 1 || !validDerivedChecksum(item.Checksums[0]) {
			return invalidDerived("derived-checksum")
		}
	}
	if !rootFound {
		return invalidDerived("derived-root")
	}
	previousRelation := ""
	adjacency := make(map[string][]string, len(document.Packages))
	for _, relation := range document.Relationships {
		key := relation.SPDXElementID + "\x00" + relation.RelatedSPDXElement
		if key <= previousRelation || relation.RelationshipType != "DEPENDS_ON" || relation.SPDXElementID == relation.RelatedSPDXElement {
			return invalidDerived("derived-relationship-order")
		}
		if _, ok := ids[relation.SPDXElementID]; !ok {
			return invalidDerived("derived-relationship-source")
		}
		if _, ok := ids[relation.RelatedSPDXElement]; !ok {
			return invalidDerived("derived-relationship-target")
		}
		adjacency[relation.SPDXElementID] = append(adjacency[relation.SPDXElementID], relation.RelatedSPDXElement)
		previousRelation = key
	}
	seen := map[string]struct{}{"SPDXRef-Root": {}}
	queue := []string{"SPDXRef-Root"}
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range adjacency[current] {
			if _, exists := seen[next]; exists {
				continue
			}
			seen[next] = struct{}{}
			queue = append(queue, next)
		}
	}
	if len(seen) != len(document.Packages) {
		return invalidDerived("derived-reachability")
	}
	return nil
}

func validDerivedPackageID(value string) bool {
	return value == "SPDXRef-Root" || derivedPackageIDPattern.MatchString(value)
}

func validDerivedNamespace(value string) bool {
	const prefix = "https://repopass.dev/spdx/npm-package-lock-v1/"
	return strings.HasPrefix(value, prefix) && len(value) == len(prefix)+64 && validLowerHex(value[len(prefix):], 64)
}

func validDerivedChecksum(value DerivedChecksum) bool {
	if value.Algorithm != "SHA512" {
		return false
	}
	return validLowerHex(value.ChecksumValue, 128)
}

func validSemVer(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value || strings.Count(value, "+") > 1 {
		return false
	}
	coreAndPre := value
	if plus := strings.IndexByte(value, '+'); plus >= 0 {
		if plus == len(value)-1 || !validSemVerIdentifiers(value[plus+1:], false) {
			return false
		}
		coreAndPre = value[:plus]
	}
	core := coreAndPre
	if dash := strings.IndexByte(coreAndPre, '-'); dash >= 0 {
		if dash == len(coreAndPre)-1 || !validSemVerIdentifiers(coreAndPre[dash+1:], true) {
			return false
		}
		core = coreAndPre[:dash]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validSemVerIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, character := range identifier {
			if !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') ||
				(character >= 'a' && character <= 'z') || character == '-') {
				return false
			}
			if character < '0' || character > '9' {
				numeric = false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func validNumericIdentifier(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// CanonicalizeDerivedProvenance validates the exact frozen provenance claim.
func CanonicalizeDerivedProvenance(raw []byte) (DerivedProvenance, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxJSONBytesForDerived() || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return DerivedProvenance{}, nil, invalidDerived("provenance-transport")
	}
	if _, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{MaxBytes: MaxJSONBytesForDerived(), MaxDepth: 16, MaxNodes: 128}); err != nil {
		return DerivedProvenance{}, nil, invalidDerived("provenance-decode")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var provenance DerivedProvenance
	if err := decoder.Decode(&provenance); err != nil {
		return DerivedProvenance{}, nil, invalidDerived("provenance-shape")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || validateDerivedProvenance(provenance) != nil {
		return DerivedProvenance{}, nil, invalidDerived("provenance-profile")
	}
	canonical, err := canonicaljson.Marshal(provenance)
	if err != nil {
		return DerivedProvenance{}, nil, invalidDerived("provenance-canonical")
	}
	return provenance, canonical, nil
}

func MaxJSONBytesForDerived() int { return 16 << 10 }

func validateDerivedProvenance(provenance DerivedProvenance) error {
	if provenance.Origin != DerivedOrigin || provenance.Profile != DerivedProfile ||
		provenance.RulesetDigest != DerivedRulesetDigest || provenance.SourceProfile != DerivedSourceProfile ||
		!validSHA256(provenance.SourceTreeDigest) || provenance.Scope != DerivedScope ||
		provenance.Completeness != DerivedCompleteness || len(provenance.Inputs) != 2 ||
		provenance.Inputs[0].Path != "package-lock.json" || provenance.Inputs[1].Path != "package.json" {
		return invalidDerived("provenance-fields")
	}
	for _, input := range provenance.Inputs {
		if input.Size < 1 || input.Size > MaxBytes || !validSHA256(input.SHA256) {
			return invalidDerived("provenance-input")
		}
	}
	expected, err := canonicaljson.Digest(derivationInputs{
		Profile: provenance.Profile, RulesetDigest: provenance.RulesetDigest,
		SourceProfile: provenance.SourceProfile, SourceTreeDigest: provenance.SourceTreeDigest,
		Inputs: provenance.Inputs,
	})
	if err != nil || expected != provenance.DerivationInputDigest {
		return invalidDerived("provenance-input-digest")
	}
	return nil
}

// ValidateDerivedPair validates both canonical payloads and their direct
// derivation-input namespace binding. It performs no repository access.
func ValidateDerivedPair(spdxRaw, provenanceRaw []byte) (DerivedDocument, DerivedProvenance, error) {
	document, canonicalSPDX, err := CanonicalizeDerived(spdxRaw)
	if err != nil || !bytes.Equal(canonicalSPDX, spdxRaw) {
		return DerivedDocument{}, DerivedProvenance{}, invalidDerived("pair-spdx")
	}
	provenance, canonicalProvenance, err := CanonicalizeDerivedProvenance(provenanceRaw)
	if err != nil || !bytes.Equal(canonicalProvenance, provenanceRaw) {
		return DerivedDocument{}, DerivedProvenance{}, invalidDerived("pair-provenance")
	}
	wantNamespace := "https://repopass.dev/spdx/npm-package-lock-v1/" + strings.TrimPrefix(provenance.DerivationInputDigest, "sha256:")
	if document.DocumentNamespace != wantNamespace {
		return DerivedDocument{}, DerivedProvenance{}, invalidDerived("pair-binding")
	}
	return document, provenance, nil
}

func validSHA256(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validLowerHex(strings.TrimPrefix(value, "sha256:"), 64)
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func init() {
	if Digest([]byte(derivedRulesetDescriptor)) != DerivedRulesetDigest {
		panic(fmt.Sprintf("derived SPDX ruleset descriptor digest mismatch"))
	}
}
