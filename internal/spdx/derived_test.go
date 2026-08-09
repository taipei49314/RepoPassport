package spdx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestDerivePackageLockV3DeterministicMultiVersionGraphAndBindings(t *testing.T) {
	directory := writeDerivedFixture(t, validDerivedPackageJSON(), validDerivedLock())
	snapshot := derivedSnapshot(t, directory)
	first, err := DerivePackageLockV3(snapshot)
	if err != nil {
		t.Fatalf("derive first: %v", err)
	}
	second, err := DerivePackageLockV3(snapshot)
	if err != nil {
		t.Fatalf("derive second: %v", err)
	}
	if !bytes.Equal(first.SPDX, second.SPDX) || !bytes.Equal(first.ProvenanceCanonical, second.ProvenanceCanonical) {
		t.Fatal("same stable snapshot did not produce byte-identical artifacts")
	}
	if len(first.Document.Packages) != 5 || len(first.Document.Relationships) != 4 {
		t.Fatalf("unexpected graph size: packages=%d relationships=%d", len(first.Document.Packages), len(first.Document.Relationships))
	}
	versions := map[string]int{}
	for _, item := range first.Document.Packages {
		if item.Name == "b" {
			versions[item.VersionInfo]++
		}
		if item.SPDXID != "SPDXRef-Root" {
			if len(item.Checksums) != 1 || item.Checksums[0].Algorithm != "SHA512" || len(item.Checksums[0].ChecksumValue) != 128 {
				t.Fatalf("unexpected checksum for %s", item.SPDXID)
			}
		}
	}
	if versions["1.0.0"] != 1 || versions["2.0.0"] != 1 {
		t.Fatalf("multiple versions were not preserved: %#v", versions)
	}
	if first.Provenance.Origin != DerivedOrigin || first.Provenance.RulesetDigest != DerivedRulesetDigest ||
		first.Provenance.SourceTreeDigest != snapshot.TreeDigest ||
		len(first.Provenance.Inputs) != 2 || first.Provenance.Inputs[0].Path != "package-lock.json" ||
		first.Provenance.Inputs[1].Path != "package.json" {
		t.Fatalf("unexpected provenance: %#v", first.Provenance)
	}
	if _, _, err := ValidateDerivedPair(first.SPDX, first.ProvenanceCanonical); err != nil {
		t.Fatalf("validate pair: %v", err)
	}
}

func TestDerivePackageLockV3RejectsForgedSnapshotAndInputDrift(t *testing.T) {
	directory := writeDerivedFixture(t, validDerivedPackageJSON(), validDerivedLock())
	valid := derivedSnapshot(t, directory)
	cases := map[string]func(*domain.SourceSnapshot){
		"commit":     func(value *domain.SourceSnapshot) { value.Commit = strings.Repeat("a", 40) },
		"identity":   func(value *domain.SourceSnapshot) { value.Identity = strings.Replace(value.Identity, "a", "b", 1) },
		"file-count": func(value *domain.SourceSnapshot) { value.FileCount++ },
		"total-size": func(value *domain.SourceSnapshot) { value.TotalSize++ },
		"inventory": func(value *domain.SourceSnapshot) {
			value.Inventory[0], value.Inventory[1] = value.Inventory[1], value.Inventory[0]
		},
		"tree-digest": func(value *domain.SourceSnapshot) {
			value.TreeDigest = "sha256:" + strings.Repeat("0", 64)
			value.Identity = value.TreeDigest
		},
		"entry-digest": func(value *domain.SourceSnapshot) { value.Inventory[0].Digest = "sha256:" + strings.Repeat("1", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			forged := cloneDerivedSnapshot(valid)
			mutate(&forged)
			if _, err := DerivePackageLockV3(forged); err == nil {
				t.Fatal("forged snapshot accepted")
			}
		})
	}

	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"name":"changed","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DerivePackageLockV3(valid); err == nil {
		t.Fatal("post-snapshot input drift accepted")
	}
}

func TestDerivePackageLockV3RejectsAlternateRootLockfilesFromCompleteSnapshot(t *testing.T) {
	for _, alternate := range []string{
		"bun.lock",
		"bun.lockb",
		"npm-shrinkwrap.json",
		"pnpm-lock.yaml",
		"yarn.lock",
	} {
		t.Run(alternate, func(t *testing.T) {
			directory := writeDerivedFixture(t, validDerivedPackageJSON(), validDerivedLock())
			if err := os.WriteFile(filepath.Join(directory, alternate), []byte("alternate lockfile"), 0o600); err != nil {
				t.Fatal(err)
			}
			provider := acquisition.NewLocalProvider()
			resolved, err := provider.ResolveCommandFree(context.Background(), domain.SourceRef{
				Kind: "local", Value: directory,
			})
			if err != nil {
				t.Fatalf("resolve complete fixture: %v", err)
			}
			snapshot, err := provider.Fetch(context.Background(), resolved)
			if err != nil {
				t.Fatalf("fetch complete fixture: %v", err)
			}
			if snapshot.FileCount != 3 {
				t.Fatalf("complete fixture file count = %d", snapshot.FileCount)
			}
			if _, err := DerivePackageLockV3(snapshot); err == nil {
				t.Fatal("alternate root lockfile was accepted")
			}
		})
	}
}

func TestPackageLockV3StrictTransportSemanticsSRIAndGraph(t *testing.T) {
	validPackage := validDerivedPackageJSON()
	validLock := validDerivedLock()
	if _, _, _, err := parsePackageLockV3(mustJSONBytes(t, validPackage), mustJSONBytes(t, validLock)); err != nil {
		t.Fatalf("valid baseline: %v", err)
	}

	cases := map[string]func(map[string]any, map[string]any){
		"lock-v2":              func(_ map[string]any, lock map[string]any) { lock["lockfileVersion"] = 2 },
		"workspace-even-empty": func(pkg map[string]any, _ map[string]any) { pkg["workspaces"] = []any{} },
		"top-level-legacy":     func(_ map[string]any, lock map[string]any) { lock["dependencies"] = map[string]any{} },
		"root-peer-even-empty": func(_ map[string]any, lock map[string]any) {
			lockPackages(lock)[""].(map[string]any)["peerDependencies"] = map[string]any{}
		},
		"root-resolved-value": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "")["resolved"] = "https://registry.npmjs.org/root/-/root-1.0.0.tgz"
		},
		"root-resolved-type": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "")["resolved"] = true
		},
		"root-integrity-value": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "")["integrity"] = derivedSRI(8)
		},
		"root-integrity-type": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "")["integrity"] = 8
		},
		"nested-dev": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["devDependencies"] = map[string]any{"b": "1.0.0"}
		},
		"nested-override": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["overrides"] = map[string]any{}
		},
		"flag-type-confusion": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["optional"] = "false"
		},
		"license-type-confusion": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["license"] = true
		},
		"license-oversize": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["license"] = strings.Repeat("a", 257)
		},
		"unsupported-inert-even-empty": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["engines"] = map[string]any{}
		},
		"in-bundle-even-false": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["inBundle"] = false
		},
		"link": func(_ map[string]any, lock map[string]any) { lockPackage(lock, "node_modules/a")["link"] = true },
		"range-spec": func(pkg map[string]any, lock map[string]any) {
			pkg["dependencies"].(map[string]any)["a"] = "^1.0.0"
			lockPackage(lock, "")["dependencies"].(map[string]any)["a"] = "^1.0.0"
		},
		"target-version-mismatch": func(pkg map[string]any, lock map[string]any) {
			pkg["dependencies"].(map[string]any)["a"] = "1.1.0"
			lockPackage(lock, "")["dependencies"].(map[string]any)["a"] = "1.1.0"
		},
		"sha256-sri": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["integrity"] = "sha256-" + base64.StdEncoding.EncodeToString(make([]byte, 32))
		},
		"multi-token-sri": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["integrity"] = derivedSRI(1) + " " + derivedSRI(2)
		},
		"short-sha512": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["integrity"] = "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 63))
		},
		"missing-edge": func(_ map[string]any, lock map[string]any) {
			delete(lockPackages(lock), "node_modules/a/node_modules/b")
		},
		"bad-location": func(_ map[string]any, lock map[string]any) {
			lockPackages(lock)["vendor/a"] = lockPackage(lock, "node_modules/a")
			delete(lockPackages(lock), "node_modules/a")
		},
		"name-mismatch": func(_ map[string]any, lock map[string]any) { lockPackage(lock, "node_modules/a")["name"] = "wrong" },
		"resolved-suffix-only": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["resolved"] = "https://registry.npmjs.org/other/-/a-1.0.0.tgz"
		},
		"unreachable": func(_ map[string]any, lock map[string]any) {
			lockPackages(lock)["node_modules/orphan"] = map[string]any{"version": "9.0.0", "resolved": "https://registry.npmjs.org/orphan/-/orphan-9.0.0.tgz", "integrity": derivedSRI(9)}
		},
		"unknown-descriptor-field": func(_ map[string]any, lock map[string]any) {
			lockPackage(lock, "node_modules/a")["futureSemantic"] = true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			pkg := cloneJSONMap(t, validPackage)
			lock := cloneJSONMap(t, validLock)
			mutate(pkg, lock)
			if _, _, _, err := parsePackageLockV3(mustJSONBytes(t, pkg), mustJSONBytes(t, lock)); err == nil {
				t.Fatal("unsupported input accepted")
			}
		})
	}

	transport := [][]byte{
		append([]byte{0xef, 0xbb, 0xbf}, mustJSONBytes(t, validLock)...),
		append(mustJSONBytes(t, validLock), []byte(" true")...),
		[]byte(`{"name":"root","name":"duplicate","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{}}`),
		{0xff},
	}
	for index, lockRaw := range transport {
		if _, _, _, err := parsePackageLockV3(mustJSONBytes(t, validPackage), lockRaw); err == nil {
			t.Fatalf("transport case %d accepted", index)
		}
	}
}

func TestStrictSemVerSRIResolutionAndConsumerBoundaries(t *testing.T) {
	validVersions := []string{"0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3+build.7", "1.2.3-rc.1+build-9"}
	for _, value := range validVersions {
		if !validSemVer(value) {
			t.Fatalf("valid SemVer rejected: %q", value)
		}
	}
	invalidVersions := []string{"", "01.0.0", "1.02.0", "1.2.03", "1.2", "1.2.3-", "1.2.3-alpha..1", "1.2.3-01", "1.2.3+", "1.2.3+build..1", "v1.2.3", "latest", "^1.2.3"}
	for _, value := range invalidVersions {
		if validSemVer(value) {
			t.Fatalf("invalid SemVer accepted: %q", value)
		}
	}

	validSRI := derivedSRI(251)
	if checksum, err := sriChecksum(validSRI); err != nil || checksum.Algorithm != "SHA512" || len(checksum.ChecksumValue) != 128 {
		t.Fatalf("valid SRI rejected: %#v %v", checksum, err)
	}
	standard := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{251}, 64))
	invalidSRI := []string{
		"SHA512-" + standard,
		"sha512-" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{251}, 64)),
		"sha512-" + base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{251}, 64)),
		"sha512-" + standard + "?foo",
		"sha512-" + standard + " " + validSRI,
		"sha384-" + base64.StdEncoding.EncodeToString(make([]byte, 48)),
		"sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 63)),
	}
	for _, value := range invalidSRI {
		if _, err := sriChecksum(value); err == nil {
			t.Fatalf("invalid SRI accepted: %q", value)
		}
	}

	packages := map[string]*acceptedLockPackage{
		"":                                 {version: "1.0.0"},
		"node_modules/x":                   {version: "1.0.0"},
		"node_modules/a":                   {version: "1.0.0"},
		"node_modules/a/node_modules/x":    {version: "2.0.0"},
		"node_modules/a/node_modules/@s/c": {version: "3.0.0"},
		"node_modules/a/node_modules/@s/c/node_modules/x": {version: "4.0.0"},
	}
	if got, ok := resolveLockDependency("node_modules/a/node_modules/@s/c", "x", packages); !ok || got != "node_modules/a/node_modules/@s/c/node_modules/x" {
		t.Fatalf("scoped nearest resolution = %q, %v", got, ok)
	}
	delete(packages, "node_modules/a/node_modules/@s/c/node_modules/x")
	if got, ok := resolveLockDependency("node_modules/a/node_modules/@s/c", "x", packages); !ok || got != "node_modules/a/node_modules/x" {
		t.Fatalf("scoped hoist resolution = %q, %v", got, ok)
	}
	delete(packages, "node_modules/a/node_modules/x")
	if got, ok := resolveLockDependency("node_modules/a/node_modules/@s/c", "x", packages); !ok || got != "node_modules/x" {
		t.Fatalf("root hoist resolution = %q, %v", got, ok)
	}

	directory := writeDerivedFixture(t, validDerivedPackageJSON(), validDerivedLock())
	artifact, err := DerivePackageLockV3(derivedSnapshot(t, directory))
	if err != nil {
		t.Fatal(err)
	}
	sha256Document := artifact.Document
	sha256Document.Packages = append([]DerivedPackage(nil), sha256Document.Packages...)
	for index := range sha256Document.Packages {
		if sha256Document.Packages[index].SPDXID != "SPDXRef-Root" {
			sha256Document.Packages[index].Checksums = []DerivedChecksum{{Algorithm: "SHA256", ChecksumValue: strings.Repeat("0", 64)}}
			break
		}
	}
	if _, _, err := CanonicalizeDerived(mustJSONBytes(t, sha256Document)); err == nil {
		t.Fatal("consumer accepted SHA256 checksum")
	}
	orphanDocument := artifact.Document
	orphanDocument.Packages = append([]DerivedPackage(nil), orphanDocument.Packages...)
	orphan := DerivedPackage{
		SPDXID:        "SPDXRef-Package-" + strings.Repeat("f", 64),
		Checksums:     []DerivedChecksum{{Algorithm: "SHA512", ChecksumValue: strings.Repeat("0", 128)}},
		CopyrightText: "NOASSERTION", DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
		LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", Name: "orphan", VersionInfo: "1.0.0",
	}
	orphanDocument.Packages = append(orphanDocument.Packages, orphan)
	if _, _, err := CanonicalizeDerived(mustJSONBytes(t, orphanDocument)); err == nil {
		t.Fatal("consumer accepted unreachable package")
	}
}

func TestDerivedJSONExactLimitsDepthNodesAndPackageCount(t *testing.T) {
	lockRaw := mustJSONBytes(t, validDerivedLock())
	prefix := `{"dependencies":{"a":"1.0.0"},"devDependencies":{"b":"2.0.0"},"name":"root","optionalDependencies":{"@s/c":"3.0.0"},"padding":"`
	suffix := `","version":"1.0.0"}`
	padding := MaxBytes - len(prefix) - len(suffix)
	exact := []byte(prefix + strings.Repeat("x", padding) + suffix)
	if len(exact) != MaxBytes {
		t.Fatalf("exact input size = %d", len(exact))
	}
	if _, _, _, err := parsePackageLockV3(exact, lockRaw); err != nil {
		kind := ""
		if typed, ok := err.(*DerivedError); ok {
			kind = typed.Kind()
		}
		t.Fatalf("exact byte limit rejected: %v (%s)", err, kind)
	}
	if _, _, _, err := parsePackageLockV3(append(exact, ' '), lockRaw); err == nil {
		t.Fatal("byte limit +1 accepted")
	}

	deep := []byte(`{"dependencies":{"a":"1.0.0"},"name":"root","nested":` + strings.Repeat("[", 65) + `null` + strings.Repeat("]", 65) + `,"version":"1.0.0"}`)
	if _, _, _, err := parsePackageLockV3(deep, lockRaw); err == nil {
		t.Fatal("depth limit +1 accepted")
	}
	nodes := []byte(`{"dependencies":{"a":"1.0.0"},"name":"root","nodes":[` + strings.Repeat("null,", 65_536) + `null],"version":"1.0.0"}`)
	if len(nodes) > MaxBytes {
		t.Fatalf("node fixture unexpectedly exceeds byte limit: %d", len(nodes))
	}
	if _, _, _, err := parsePackageLockV3(nodes, lockRaw); err == nil {
		t.Fatal("node limit +1 accepted")
	}

	tooMany := validDerivedLock()
	packages := lockPackages(tooMany)
	for index := 0; index < MaxDerivedPackages; index++ {
		packages["node_modules/x"+strings.Repeat("a", index%10)+string(rune('a'+index%26))+strings.Repeat("b", index/26%5)] = map[string]any{}
	}
	// Generate guaranteed unique portable names until root + entries exceeds the bound.
	for index := 0; len(packages) <= MaxDerivedPackages; index++ {
		packages["node_modules/pkg"+decimalString(index)] = map[string]any{}
	}
	if _, _, _, err := parsePackageLockV3(mustJSONBytes(t, validDerivedPackageJSON()), mustJSONBytes(t, tooMany)); err == nil {
		t.Fatal("package count +1 accepted")
	}
}

func decimalString(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func TestDerivedPairRejectsDirectTamperAndUnknownRuleset(t *testing.T) {
	directory := writeDerivedFixture(t, validDerivedPackageJSON(), validDerivedLock())
	artifact, err := DerivePackageLockV3(derivedSnapshot(t, directory))
	if err != nil {
		t.Fatal(err)
	}

	tamperedSPDX := append([]byte(nil), artifact.SPDX...)
	tamperedSPDX[len(tamperedSPDX)-2] ^= 1
	if _, _, err := ValidateDerivedPair(tamperedSPDX, artifact.ProvenanceCanonical); err == nil {
		t.Fatal("direct SPDX tamper accepted")
	}

	provenance := artifact.Provenance
	provenance.RulesetDigest = "sha256:" + strings.Repeat("0", 64)
	unknownRuleset := mustJSONBytes(t, provenance)
	if _, _, err := ValidateDerivedPair(artifact.SPDX, unknownRuleset); err == nil {
		t.Fatal("unknown ruleset accepted")
	}

}

func TestReadDerivedFileRejectsHardlinkWithoutChangingLegacyReader(t *testing.T) {
	directory := t.TempDir()
	original := filepath.Join(directory, "original.json")
	linked := filepath.Join(directory, "linked.json")
	if err := os.WriteFile(original, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, linked); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := ReadFile(original); err != nil {
		t.Fatalf("legacy reader compatibility changed: %v", err)
	}
	if _, err := ReadDerivedFile(original); err == nil {
		t.Fatal("derived reader accepted a multiply-linked input")
	}
}

func FuzzCanonicalizeDerived(f *testing.F) {
	directory := f.TempDir()
	packageRaw := mustJSONBytes(f, validDerivedPackageJSON())
	lockRaw := mustJSONBytes(f, validDerivedLock())
	if err := os.WriteFile(filepath.Join(directory, "package.json"), packageRaw, 0o600); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "package-lock.json"), lockRaw, 0o600); err != nil {
		f.Fatal(err)
	}
	artifact, err := DerivePackageLockV3(derivedSnapshot(f, directory))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(artifact.SPDX)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _, _ = CanonicalizeDerived(raw)
	})
}

func FuzzCanonicalizeDerivedProvenance(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _, _ = CanonicalizeDerivedProvenance(raw)
	})
}

func FuzzPackageLockV3(f *testing.F) {
	packageSeed := mustJSONBytes(f, validDerivedPackageJSON())
	lockSeed := mustJSONBytes(f, validDerivedLock())
	f.Add(packageSeed, lockSeed)
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, packageRaw, lockRaw []byte) {
		_, _, _, _ = parsePackageLockV3(packageRaw, lockRaw)
	})
}

func validDerivedPackageJSON() map[string]any {
	return map[string]any{
		"name": "root", "version": "1.0.0",
		"dependencies":         map[string]any{"a": "1.0.0"},
		"devDependencies":      map[string]any{"b": "2.0.0"},
		"optionalDependencies": map[string]any{"@s/c": "3.0.0"},
	}
}

func validDerivedLock() map[string]any {
	return map[string]any{
		"name": "root", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{
				"name": "root", "version": "1.0.0",
				"dependencies":         map[string]any{"a": "1.0.0"},
				"devDependencies":      map[string]any{"b": "2.0.0"},
				"optionalDependencies": map[string]any{"@s/c": "3.0.0"},
			},
			"node_modules/a": map[string]any{
				"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": derivedSRI(1),
				"dependencies": map[string]any{"b": "1.0.0"},
			},
			"node_modules/a/node_modules/b": map[string]any{
				"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz", "integrity": derivedSRI(2),
			},
			"node_modules/b": map[string]any{
				"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz", "integrity": derivedSRI(3), "dev": true,
			},
			"node_modules/@s/c": map[string]any{
				"version": "3.0.0", "resolved": "https://registry.npmjs.org/@s/c/-/c-3.0.0.tgz", "integrity": derivedSRI(4), "optional": true,
			},
		},
	}
}

func derivedSRI(value byte) string {
	return "sha512-" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 64))
}

func writeDerivedFixture(t testing.TB, packageJSON, lock map[string]any) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "package.json"), mustJSONBytes(t, packageJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "package-lock.json"), mustJSONBytes(t, lock), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func derivedSnapshot(t testing.TB, directory string) domain.SourceSnapshot {
	t.Helper()
	paths := []string{"package-lock.json", "package.json"}
	entries := make([]domain.FileEntry, 0, len(paths))
	var total int64
	for _, name := range paths {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, domain.FileEntry{Path: name, Mode: "0644", Size: int64(len(raw)), Digest: Digest(raw)})
		total += int64(len(raw))
	}
	tree, err := canonicaljson.Digest(entries)
	if err != nil {
		t.Fatal(err)
	}
	return domain.SourceSnapshot{Identity: tree, TreeDigest: tree, Root: directory, Inventory: entries, TotalSize: total, FileCount: len(entries)}
}

func cloneDerivedSnapshot(value domain.SourceSnapshot) domain.SourceSnapshot {
	value.Inventory = append([]domain.FileEntry(nil), value.Inventory...)
	return value
}

func mustJSONBytes(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func cloneJSONMap(t testing.TB, value map[string]any) map[string]any {
	t.Helper()
	var clone map[string]any
	if err := json.Unmarshal(mustJSONBytes(t, value), &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func lockPackages(lock map[string]any) map[string]any { return lock["packages"].(map[string]any) }
func lockPackage(lock map[string]any, location string) map[string]any {
	return lockPackages(lock)[location].(map[string]any)
}
