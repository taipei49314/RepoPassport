package spdx

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalizeAcceptsStrictProfileAndIsDeterministic(t *testing.T) {
	raw := mustJSON(t, validDocument())
	document, canonical, err := Canonicalize(raw)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if document.SPDXVersion != Format || len(document.Packages) != 1 || bytes.HasSuffix(canonical, []byte{'\n'}) {
		t.Fatalf("canonical document = %#v bytes=%q", document, canonical)
	}
	_, second, err := Canonicalize(canonical)
	if err != nil || !bytes.Equal(canonical, second) {
		t.Fatalf("canonical idempotence: %v equal=%v", err, bytes.Equal(canonical, second))
	}
	reordered := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"demo","licenseDeclared":"NOASSERTION","licenseConcluded":"NOASSERTION","filesAnalyzed":false,"downloadLocation":"NOASSERTION","copyrightText":"NOASSERTION","SPDXID":"SPDXRef-demo"}],"name":"demo-sbom","documentNamespace":"https://example.invalid/spdx/demo","documentDescribes":["SPDXRef-demo"],"dataLicense":"CC0-1.0","creationInfo":{"creators":["Tool: RepoPassport synthetic fixture"],"created":"2026-08-01T00:00:00Z"},"SPDXID":"SPDXRef-DOCUMENT"}`)
	_, other, err := Canonicalize(reordered)
	if err != nil || !bytes.Equal(canonical, other) {
		t.Fatalf("insertion-order determinism: %v\n%s\n%s", err, canonical, other)
	}
	metadata := MetadataFor(canonical)
	if !metadata.Present || metadata.Format != Format || metadata.Digest != Digest(canonical) {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestCanonicalizeAndReadFileAcceptExactTransportLimit(t *testing.T) {
	valid := mustJSON(t, validDocument())
	_, wantCanonical, err := Canonicalize(valid)
	if err != nil {
		t.Fatalf("canonicalize unpadded document: %v", err)
	}
	exact := append(append([]byte{}, valid...), bytes.Repeat([]byte{' '}, MaxBytes-len(valid))...)
	if len(exact) != MaxBytes {
		t.Fatalf("exact-bound fixture size = %d, want %d", len(exact), MaxBytes)
	}
	_, canonical, err := Canonicalize(exact)
	if err != nil {
		t.Fatalf("canonicalize exact-bound document: %v", err)
	}
	if !bytes.Equal(canonical, wantCanonical) {
		t.Fatal("transport padding changed the canonical derivative")
	}
	path := filepath.Join(t.TempDir(), "exact-bound.spdx.json")
	if err := os.WriteFile(path, exact, 0o600); err != nil {
		t.Fatalf("write exact-bound document: %v", err)
	}
	read, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile exact-bound document: %v", err)
	}
	if !bytes.Equal(read, exact) {
		t.Fatal("ReadFile changed exact-bound transport bytes")
	}
	_, fromFile, err := Canonicalize(read)
	if err != nil || !bytes.Equal(fromFile, wantCanonical) {
		t.Fatalf("canonicalize exact-bound file: %v equal=%v", err, bytes.Equal(fromFile, wantCanonical))
	}
}

func TestPublishedSyntheticFixtureMatchesBoundedProfile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(
		"..", "..", "testdata", "fixtures", "healthy", "minimal-public-spdx", "sbom.spdx.json",
	))
	if err != nil {
		t.Fatalf("read published synthetic SPDX fixture: %v", err)
	}
	document, canonical, err := Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize published synthetic SPDX fixture: %v", err)
	}
	if document.SPDXVersion != Format || len(document.Packages) != 1 ||
		MetadataFor(canonical).Digest != Digest(canonical) {
		t.Fatalf("published fixture derivative = %#v metadata=%#v", document, MetadataFor(canonical))
	}
}

func TestCanonicalizeRejectsTransportAndDecodeAmbiguity(t *testing.T) {
	valid := mustJSON(t, validDocument())
	deep := any(float64(0))
	for range 65 {
		deep = []any{deep}
	}
	deepRoot := validDocument()
	deepRoot["packages"] = deep
	nodeRoot := validDocument()
	nodeRoot["packages"] = make([]any, 65_537)
	cases := map[string]struct {
		raw  []byte
		kind string
	}{
		"empty":          {raw: []byte{}, kind: "transport"},
		"oversized":      {raw: bytes.Repeat([]byte{' '}, MaxBytes+1), kind: "transport"},
		"bom":            {raw: append([]byte{0xef, 0xbb, 0xbf}, valid...), kind: "transport"},
		"invalid utf8":   {raw: []byte{'{', '"', 0xff, '"', '}'}, kind: "decode"},
		"trailing":       {raw: append(append([]byte{}, valid...), []byte(` true`)...), kind: "decode"},
		"duplicate":      {raw: bytes.Replace(valid, []byte(`"SPDXID":"SPDXRef-DOCUMENT"`), []byte(`"SPDXID":"SPDXRef-DOCUMENT","SPDXID":"SPDXRef-DOCUMENT"`), 1), kind: "decode"},
		"invalid number": {raw: []byte(`1e1000001`), kind: "decode"},
		"depth":          {raw: mustJSON(t, deepRoot), kind: "decode"},
		"nodes":          {raw: mustJSON(t, nodeRoot), kind: "decode"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := Canonicalize(test.raw)
			if err == nil {
				t.Fatal("ambiguous input accepted")
			}
			typed, ok := err.(*Error)
			if !ok || typed.Kind() != test.kind {
				t.Fatalf("error = %#v, want fixed kind %q", err, test.kind)
			}
		})
	}
}

func TestCanonicalizeAcceptsExactCountAndByteBoundaries(t *testing.T) {
	tests := map[string]func(map[string]any){
		"document name 256 bytes": func(root map[string]any) { root["name"] = strings.Repeat("n", 256) },
		"namespace 1024 bytes":    func(root map[string]any) { root["documentNamespace"] = exactURI(1024) },
		"32 creators": func(root map[string]any) {
			creators := make([]any, 32)
			for index := range creators {
				creators[index] = "Tool: fixture-" + strconv.Itoa(index)
			}
			root["creationInfo"].(map[string]any)["creators"] = creators
		},
		"creator 256 bytes": func(root map[string]any) {
			root["creationInfo"].(map[string]any)["creators"] = []any{"Tool: " + strings.Repeat("c", 250)}
		},
		"all creator prefixes": func(root map[string]any) {
			root["creationInfo"].(map[string]any)["creators"] = []any{"Person: fixture", "Organization: fixture", "Tool: fixture"}
		},
		"512 packages and describes": func(root map[string]any) { setPackageCount(root, 512) },
		"package id 128 bytes":       func(root map[string]any) { replacePackageID(root, "SPDXRef-"+strings.Repeat("i", 120)) },
		"package name 256 bytes": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["name"] = strings.Repeat("p", 256)
		},
		"package version 128 bytes": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["versionInfo"] = strings.Repeat("v", 128)
		},
		"download URI 1024 bytes": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["downloadLocation"] = exactURI(1024)
		},
		"NONE sentinels": func(root map[string]any) {
			item := root["packages"].([]any)[0].(map[string]any)
			item["copyrightText"] = "NONE"
			item["licenseConcluded"] = "NONE"
			item["licenseDeclared"] = "NONE"
			item["downloadLocation"] = "NONE"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root := validDocument()
			mutate(root)
			if _, _, err := Canonicalize(mustJSON(t, root)); err != nil {
				t.Fatalf("exact boundary rejected: %v", err)
			}
		})
	}
}

func TestCanonicalizeRejectsEveryBoundedFieldEdge(t *testing.T) {
	tests := map[string]func(map[string]any){
		"unknown root":       func(root map[string]any) { root["relationships"] = []any{} },
		"missing root":       func(root map[string]any) { delete(root, "packages") },
		"document id":        func(root map[string]any) { root["SPDXID"] = "SPDXRef-other" },
		"version":            func(root map[string]any) { root["spdxVersion"] = "SPDX-2.2" },
		"data license":       func(root map[string]any) { root["dataLicense"] = "MIT" },
		"empty name":         func(root map[string]any) { root["name"] = "\u2003" },
		"name bytes":         func(root map[string]any) { root["name"] = strings.Repeat("界", 86) },
		"name control":       func(root map[string]any) { root["name"] = "demo\nname" },
		"namespace scheme":   func(root map[string]any) { root["documentNamespace"] = "HTTPS://example.invalid/sbom" },
		"namespace host":     func(root map[string]any) { root["documentNamespace"] = "https:/sbom" },
		"namespace user":     func(root map[string]any) { root["documentNamespace"] = "https://user@example.invalid/sbom" },
		"namespace query":    func(root map[string]any) { root["documentNamespace"] = "https://example.invalid/sbom?" },
		"namespace fragment": func(root map[string]any) { root["documentNamespace"] = "https://example.invalid/sbom#" },
		"namespace length": func(root map[string]any) {
			root["documentNamespace"] = "https://example.invalid/" + strings.Repeat("a", 1002)
		},
		"creation unknown": func(root map[string]any) { root["creationInfo"].(map[string]any)["comment"] = "x" },
		"created offset": func(root map[string]any) {
			root["creationInfo"].(map[string]any)["created"] = "2026-08-01T00:00:00+00:00"
		},
		"created fraction": func(root map[string]any) { root["creationInfo"].(map[string]any)["created"] = "2026-08-01T00:00:00.0Z" },
		"creator empty":    func(root map[string]any) { root["creationInfo"].(map[string]any)["creators"] = []any{} },
		"creator prefix":   func(root map[string]any) { root["creationInfo"].(map[string]any)["creators"] = []any{"Agent: demo"} },
		"creator identity": func(root map[string]any) { root["creationInfo"].(map[string]any)["creators"] = []any{"Tool: \u2003"} },
		"creator duplicate": func(root map[string]any) {
			root["creationInfo"].(map[string]any)["creators"] = []any{"Tool: demo", "Tool: demo"}
		},
		"creator bytes": func(root map[string]any) {
			root["creationInfo"].(map[string]any)["creators"] = []any{"Tool: " + strings.Repeat("c", 251)}
		},
		"creator max count": func(root map[string]any) {
			values := make([]any, 33)
			for i := range values {
				values[i] = "Tool: demo-" + string(rune('A'+i))
			}
			root["creationInfo"].(map[string]any)["creators"] = values
		},
		"describes empty":           func(root map[string]any) { root["documentDescribes"] = []any{} },
		"describes duplicate":       func(root map[string]any) { root["documentDescribes"] = []any{"SPDXRef-demo", "SPDXRef-demo"} },
		"describes missing package": func(root map[string]any) { root["documentDescribes"] = []any{"SPDXRef-other"} },
		"describes incomplete": func(root map[string]any) {
			root["packages"] = append(root["packages"].([]any), packageValue("SPDXRef-other", "other"))
		},
		"packages empty":      func(root map[string]any) { root["packages"] = []any{} },
		"packages max count":  func(root map[string]any) { setPackageCount(root, 513) },
		"package unknown":     func(root map[string]any) { root["packages"].([]any)[0].(map[string]any)["checksums"] = []any{} },
		"package id syntax":   func(root map[string]any) { replacePackageID(root, "bad/id") },
		"package document id": func(root map[string]any) { replacePackageID(root, "SPDXRef-DOCUMENT") },
		"package id bytes":    func(root map[string]any) { replacePackageID(root, "SPDXRef-"+strings.Repeat("a", 121)) },
		"package duplicate id": func(root map[string]any) {
			root["packages"] = append(root["packages"].([]any), packageValue("SPDXRef-demo", "other"))
			root["documentDescribes"] = []any{"SPDXRef-demo"}
		},
		"package duplicate name": func(root map[string]any) {
			root["packages"] = append(root["packages"].([]any), packageValue("SPDXRef-other", "demo"))
			root["documentDescribes"] = []any{"SPDXRef-demo", "SPDXRef-other"}
		},
		"package name empty": func(root map[string]any) { root["packages"].([]any)[0].(map[string]any)["name"] = " " },
		"package name bytes": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["name"] = strings.Repeat("p", 257)
		},
		"package version empty": func(root map[string]any) { root["packages"].([]any)[0].(map[string]any)["versionInfo"] = "\u2003" },
		"package version bytes": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["versionInfo"] = strings.Repeat("v", 129)
		},
		"package files analyzed": func(root map[string]any) { root["packages"].([]any)[0].(map[string]any)["filesAnalyzed"] = true },
		"package license":        func(root map[string]any) { root["packages"].([]any)[0].(map[string]any)["licenseDeclared"] = "MIT" },
		"package copyright": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["copyrightText"] = "Copyright demo"
		},
		"download query": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["downloadLocation"] = "https://example.invalid/a?"
		},
		"download relative": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["downloadLocation"] = "./archive"
		},
		"download bytes": func(root map[string]any) {
			root["packages"].([]any)[0].(map[string]any)["downloadLocation"] = exactURI(1025)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root := validDocument()
			mutate(root)
			if _, _, err := Canonicalize(mustJSON(t, root)); err == nil {
				t.Fatal("invalid field accepted")
			}
		})
	}
}

func TestReadFileRejectsLinksOversizeAndDeterministicMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sbom.json")
	valid := mustJSON(t, validDocument())
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadFile(path); err != nil || !bytes.Equal(raw, valid) {
		t.Fatalf("ReadFile: %v", err)
	}

	oversize := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(oversize, bytes.Repeat([]byte{'x'}, MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(oversize); err == nil {
		t.Fatal("oversized file accepted")
	}

	t.Run("final symlink", func(t *testing.T) {
		link := filepath.Join(root, "link.json")
		if err := os.Symlink(path, link); err != nil {
			t.Skipf("final symlink creation unavailable: %v", err)
		}
		if _, err := ReadFile(link); err == nil {
			t.Fatal("final symlink accepted")
		}
	})
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(realParent, "inside.json")
	if err := os.WriteFile(inside, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("parent symlink", func(t *testing.T) {
		linkedParent := filepath.Join(root, "linked-parent")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Skipf("parent symlink creation unavailable: %v", err)
		}
		if _, err := ReadFile(filepath.Join(linkedParent, "inside.json")); err == nil {
			t.Fatal("parent symlink accepted")
		}
	})

	mutations := map[string]func(string) error{
		"same-size": func(target string) error { return os.WriteFile(target, bytes.Repeat([]byte{'x'}, len(valid)), 0o600) },
		"truncate":  func(target string) error { return os.WriteFile(target, valid[:len(valid)/2], 0o600) },
		"grow":      func(target string) error { return os.WriteFile(target, append(append([]byte{}, valid...), 'x'), 0o600) },
		"rename-replace": func(target string) error {
			replacement := target + ".replacement"
			if err := os.WriteFile(replacement, valid, 0o600); err != nil {
				return err
			}
			return os.Rename(replacement, target)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(root, name+".json")
			if err := os.WriteFile(target, valid, 0o600); err != nil {
				t.Fatal(err)
			}
			var hookErr error
			_, readErr := readFileWithHook(target, func() { hookErr = mutate(target) })
			if hookErr != nil && name == "rename-replace" && runtime.GOOS == "windows" && errors.Is(hookErr, os.ErrPermission) {
				t.Skipf("Windows open-handle sharing prevented rename-replace exercise: %v", hookErr)
			}
			if hookErr != nil {
				t.Fatalf("mutation: %v", hookErr)
			}
			if readErr == nil {
				t.Fatal("changed file accepted")
			}
		})
	}
}

func FuzzCanonicalize(f *testing.F) {
	f.Add(mustJSON(f, validDocument()))
	f.Add([]byte(`{"SPDXID":"SPDXRef-DOCUMENT"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, canonical, err := Canonicalize(raw)
		if err != nil {
			return
		}
		_, again, err := Canonicalize(canonical)
		if err != nil || !bytes.Equal(canonical, again) {
			t.Fatalf("non-idempotent canonicalization: %v", err)
		}
	})
}

type testingFatal interface {
	Helper()
	Fatal(...any)
}

func mustJSON(t testingFatal, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validDocument() map[string]any {
	return map[string]any{
		"SPDXID":            "SPDXRef-DOCUMENT",
		"creationInfo":      map[string]any{"created": "2026-08-01T00:00:00Z", "creators": []any{"Tool: RepoPassport synthetic fixture"}},
		"dataLicense":       "CC0-1.0",
		"documentDescribes": []any{"SPDXRef-demo"},
		"documentNamespace": "https://example.invalid/spdx/demo",
		"name":              "demo-sbom",
		"packages":          []any{packageValue("SPDXRef-demo", "demo")},
		"spdxVersion":       "SPDX-2.3",
	}
}

func packageValue(id, name string) map[string]any {
	return map[string]any{"SPDXID": id, "copyrightText": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "name": name}
}

func replacePackageID(root map[string]any, id string) {
	root["packages"].([]any)[0].(map[string]any)["SPDXID"] = id
	root["documentDescribes"] = []any{id}
}

func exactURI(size int) string {
	const prefix = "https://example.invalid/"
	if size < len(prefix) {
		panic("URI size below fixed prefix")
	}
	return prefix + strings.Repeat("u", size-len(prefix))
}

func setPackageCount(root map[string]any, count int) {
	packages := make([]any, count)
	describes := make([]any, count)
	for index := range count {
		identifier := "SPDXRef-p" + strconv.Itoa(index)
		packages[index] = packageValue(identifier, "package-"+strconv.Itoa(index))
		describes[index] = identifier
	}
	root["packages"] = packages
	root["documentDescribes"] = describes
}
