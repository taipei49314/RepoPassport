package sourcequalification

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
)

func TestPortableSourcePathProfile(t *testing.T) {
	maxPath := strings.Repeat("a", 154) + "/" + strings.Repeat("b", 100)
	valid := []string{
		"README.md",
		".github/workflows/ci.yml",
		"dir/space name.txt",
		maxPath,
	}
	for _, path := range valid {
		if err := validatePortablePath(path); err != nil {
			t.Errorf("validatePortablePath(%q) rejected a portable path: %v", path, err)
		}
	}

	invalid := []string{
		"", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b",
		`a\b`, "C:/a", "a:b", "a*", `a?`, `a"b`, "a<b", "a>b", "a|b",
		"a\n", "caf\u00e9", "trailing.", "trailing ",
		strings.Repeat("a", 155) + "/" + strings.Repeat("b", 100),
	}
	reserved := []string{
		"CON", "prn.txt", "Aux.json", "nul", "CONIN$", "conout$.log", "Clock$",
		"COM1", "com9.txt", "LPT1", "lpt9.ext",
	}
	invalid = append(invalid, reserved...)
	for _, path := range invalid {
		if err := validatePortablePath(path); err == nil {
			t.Errorf("validatePortablePath(%q) accepted a non-portable path", path)
		}
	}
}

func TestSplitUSTARPathIsUniqueAndRightmost(t *testing.T) {
	tests := []struct {
		path       string
		wantPrefix string
		wantName   string
		wantError  bool
	}{
		{path: strings.Repeat("a", 100), wantName: strings.Repeat("a", 100)},
		{path: strings.Repeat("a", 75) + "/" + strings.Repeat("b", 25), wantPrefix: strings.Repeat("a", 75), wantName: strings.Repeat("b", 25)},
		{path: strings.Repeat("a", 40) + "/" + strings.Repeat("b", 70) + "/tail", wantPrefix: strings.Repeat("a", 40) + "/" + strings.Repeat("b", 70), wantName: "tail"},
		{path: strings.Repeat("a", 101), wantError: true},
		{path: "p/" + strings.Repeat("n", 101), wantError: true},
	}
	for _, test := range tests {
		prefix, name, err := splitUSTARPath(test.path)
		if test.wantError {
			if err == nil {
				t.Errorf("splitUSTARPath(%q) unexpectedly succeeded", test.path)
			}
			continue
		}
		if err != nil || prefix != test.wantPrefix || name != test.wantName {
			t.Errorf("splitUSTARPath(%q) = (%q, %q, %v), want (%q, %q, nil)", test.path, prefix, name, err, test.wantPrefix, test.wantName)
		}
	}
}

func TestCanonicalArchiveRawUSTARBytes(t *testing.T) {
	longPath := "testdata/fixtures/malicious/alpha25-undeclared-port-python/.repopass/schemas/echo-response.schema.json"
	files := []archiveFile{
		{Path: longPath, GitMode: "100755", Data: bytes.Repeat([]byte{0xa5}, 513)},
		{Path: "a.txt", GitMode: "100644", Data: nil},
	}

	got, err := buildCanonicalArchive(files)
	if err != nil {
		t.Fatalf("buildCanonicalArchive: %v", err)
	}
	want := testCanonicalArchive(files)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical USTAR bytes differ at offset %d (got %d bytes, want %d)", firstDifferentByte(got, want), len(got), len(want))
	}
	if len(got) != 3072 {
		t.Fatalf("archive length = %d, want 3072", len(got))
	}
	if got[156] != '0' || !bytes.Equal(got[257:265], []byte("ustar\x0000")) {
		t.Fatal("first member is not the exact regular-file USTAR profile")
	}
	if !allZero(got[len(got)-1024:]) {
		t.Fatal("archive does not end in exactly two zero blocks")
	}
}

func TestCanonicalArchiveRejectsAmbiguousInventory(t *testing.T) {
	tests := []struct {
		name  string
		files []archiveFile
	}{
		{name: "duplicate", files: []archiveFile{{Path: "a", GitMode: "100644"}, {Path: "a", GitMode: "100644"}}},
		{name: "case collision", files: []archiveFile{{Path: "README", GitMode: "100644"}, {Path: "readme", GitMode: "100644"}}},
		{name: "file directory collision", files: []archiveFile{{Path: "a", GitMode: "100644"}, {Path: "a/b", GitMode: "100644"}}},
		{name: "unsupported mode", files: []archiveFile{{Path: "link", GitMode: "120000", Data: []byte("target")}}},
		{name: "unsplittable path", files: []archiveFile{{Path: strings.Repeat("x", 101), GitMode: "100644"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildCanonicalArchive(test.files); err == nil {
				t.Fatal("buildCanonicalArchive unexpectedly accepted invalid input")
			}
		})
	}
}

func TestCanonicalArchiveVerifierRejectsNonCanonicalRawBytes(t *testing.T) {
	files := []archiveFile{{Path: "x", GitMode: "100644", Data: []byte("x")}}
	canonical, err := buildCanonicalArchive(files)
	if err != nil {
		t.Fatalf("buildCanonicalArchive: %v", err)
	}
	tree := "f115c6d5cfb15ca1a72429900dcaca0fd1057951"
	if err := verifyCanonicalArchive(canonical, files, tree); err != nil {
		t.Fatalf("verifyCanonicalArchive rejected canonical bytes: %v", err)
	}

	mutations := map[string]func([]byte) []byte{
		"bad checksum":          func(in []byte) []byte { in[148] ^= 1; return in },
		"pax type":              func(in []byte) []byte { in[156] = 'x'; rewriteTestChecksum(in[:512]); return in },
		"nonzero data padding":  func(in []byte) []byte { in[513] = 1; return in },
		"base256 size":          func(in []byte) []byte { in[124] = 0x80; rewriteTestChecksum(in[:512]); return in },
		"truncated":             func(in []byte) []byte { return in[:len(in)-1] },
		"additional zero block": func(in []byte) []byte { return append(in, make([]byte, 512)...) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(bytes.Clone(canonical))
			if err := verifyCanonicalArchive(candidate, files, tree); err == nil {
				t.Fatal("verifyCanonicalArchive unexpectedly accepted non-canonical bytes")
			}
		})
	}
}

func TestCanonicalArchiveBounds(t *testing.T) {
	const maxFile = int64(128 << 20)
	if got, err := canonicalArchiveSize([]int64{0, 511, 512, 513}); err != nil || got != 5120 {
		t.Fatalf("canonicalArchiveSize boundaries = (%d, %v), want (5120, nil)", got, err)
	}
	if _, err := canonicalArchiveSize(make([]int64, 16384)); err != nil {
		t.Fatalf("canonicalArchiveSize rejected 16,384 files: %v", err)
	}
	invalid := [][]int64{
		make([]int64, 16385),
		{-1},
		{maxFile + 1},
		{maxFile, maxFile, maxFile, maxFile},
		{math.MaxInt64},
	}
	for _, sizes := range invalid {
		if _, err := canonicalArchiveSize(sizes); err == nil {
			t.Errorf("canonicalArchiveSize accepted invalid sizes (count=%d first=%d)", len(sizes), sizes[0])
		}
	}
}

func TestGitBlobAndTreeReconstructionGoldens(t *testing.T) {
	if got := gitBlobSHA1(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("empty blob SHA-1 = %s", got)
	}
	if got := gitBlobSHA1([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatalf("hello blob SHA-1 = %s", got)
	}

	files := []archiveFile{
		{Path: "a.txt", GitMode: "100644", Data: []byte("alpha\n")},
		{Path: "dir/run.sh", GitMode: "100755", Data: []byte("#!/bin/sh\nexit 0\n")},
	}
	got, err := reconstructGitTreeSHA1(files)
	if err != nil {
		t.Fatalf("reconstructGitTreeSHA1: %v", err)
	}
	if want := "7d372f1e4b5f5bfb1f336ff0cea098f76c4b4d9e"; got != want {
		t.Fatalf("root tree SHA-1 = %s, want %s", got, want)
	}

	ordering := []archiveFile{
		{Path: "foo/z", GitMode: "100644", Data: []byte("z\n")},
		{Path: "foo.bar", GitMode: "100644", Data: []byte("bar\n")},
	}
	got, err = reconstructGitTreeSHA1(ordering)
	if err != nil {
		t.Fatalf("reconstructGitTreeSHA1 ordering fixture: %v", err)
	}
	if want := "be421049a230315b65b355e8ab8785e950c2eff4"; got != want {
		t.Fatalf("Git file/directory ordering tree = %s, want %s", got, want)
	}
}

func testCanonicalArchive(files []archiveFile) []byte {
	ordered := append([]archiveFile(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	var out bytes.Buffer
	for _, file := range ordered {
		out.Write(testUSTARHeader(file.Path, file.GitMode, int64(len(file.Data))))
		out.Write(file.Data)
		out.Write(make([]byte, (512-len(file.Data)%512)%512))
	}
	out.Write(make([]byte, 1024))
	return out.Bytes()
}

func testUSTARHeader(path, mode string, size int64) []byte {
	prefix, name := "", path
	if len(path) > 100 {
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '/' && i >= 1 && i <= 155 && len(path)-i-1 >= 1 && len(path)-i-1 <= 100 {
				prefix, name = path[:i], path[i+1:]
				break
			}
		}
	}
	header := make([]byte, 512)
	copy(header[0:100], name)
	if mode == "100755" {
		copy(header[100:108], "0000755\x00")
	} else {
		copy(header[100:108], "0000644\x00")
	}
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	copy(header[124:136], fmt.Sprintf("%011o\x00", size))
	copy(header[136:148], "00000000000\x00")
	copy(header[148:156], "        ")
	header[156] = '0'
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	copy(header[329:337], "0000000\x00")
	copy(header[337:345], "0000000\x00")
	copy(header[345:500], prefix)
	rewriteTestChecksum(header)
	return header
}

func rewriteTestChecksum(header []byte) {
	copy(header[148:156], "        ")
	sum := 0
	for _, value := range header[:512] {
		sum += int(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func firstDifferentByte(left, right []byte) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

func allZero(data []byte) bool {
	return bytes.Equal(data, make([]byte, len(data)))
}

func testRawObjectID(hexID string) [sha1.Size]byte {
	raw, err := hex.DecodeString(hexID)
	if err != nil || len(raw) != sha1.Size {
		panic("invalid test object ID")
	}
	var result [sha1.Size]byte
	copy(result[:], raw)
	return result
}
