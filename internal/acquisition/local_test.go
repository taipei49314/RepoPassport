package acquisition

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestFetchBuildsStableInventoryAndSkipsInternalState(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "z.txt"), "z")
	writeFile(t, filepath.Join(root, "a.txt"), "alpha")
	writeFile(t, filepath.Join(root, ".GIT", "config"), "untrusted git state")
	writeFile(t, filepath.Join(root, ".RepoPass", "state.json"), "{}")
	writeFile(t, filepath.Join(root, ".RepoPass", "evidence", "old.json"), "{}")
	writeFile(
		t,
		filepath.Join(root, ".RepoPass", "schemas", "result.schema.json"),
		`{"type":"object"}`,
	)
	writeFile(t, filepath.Join(root, "Passport.Lock.Json"), "{}")

	provider := NewLocalProvider()
	source := domain.ResolvedSource{Kind: "local", LocalPath: root}
	first, err := provider.Fetch(context.Background(), source)
	if err != nil {
		t.Fatalf("Fetch(first): %v", err)
	}
	second, err := provider.Fetch(context.Background(), source)
	if err != nil {
		t.Fatalf("Fetch(second): %v", err)
	}

	var paths []string
	for _, entry := range first.Inventory {
		paths = append(paths, entry.Path)
	}
	if want := []string{
		".RepoPass/schemas/result.schema.json",
		"a.txt",
		"z.txt",
	}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("inventory paths = %#v, want %#v", paths, want)
	}
	if first.FileCount != 3 || first.TotalSize != 23 {
		t.Fatalf("snapshot counts = files:%d bytes:%d, want files:3 bytes:23", first.FileCount, first.TotalSize)
	}
	if first.TreeDigest != second.TreeDigest {
		t.Fatalf("stable source changed tree digest: %q != %q", first.TreeDigest, second.TreeDigest)
	}
}

func TestFetchRejectsNestedSymlinkWhenSupported(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, outside, "outside")
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation is unavailable on this platform: %v", err)
	}

	_, err := NewLocalProvider().Fetch(
		context.Background(),
		domain.ResolvedSource{Kind: "local", LocalPath: root},
	)
	if err == nil {
		t.Fatal("Fetch unexpectedly accepted a nested symlink")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeSourceSymlinkEscape {
		t.Fatalf("Fetch symlink error code = %q, want %q: %v", got, domain.CodeSourceSymlinkEscape, err)
	}
}

func TestFetchRejectsSourceRootChangedToSymlinkWhenSupported(t *testing.T) {
	parent := t.TempDir()
	sourceRoot := filepath.Join(parent, "source")
	originalRoot := filepath.Join(parent, "source-original")
	outsideRoot := filepath.Join(parent, "outside")
	if err := os.MkdirAll(sourceRoot, 0o700); err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := os.MkdirAll(outsideRoot, 0o700); err != nil {
		t.Fatalf("create outside: %v", err)
	}
	writeFile(t, filepath.Join(sourceRoot, "inside.txt"), "inside")
	writeFile(t, filepath.Join(outsideRoot, "outside.txt"), "outside")

	provider := NewLocalProvider()
	resolved, err := provider.Resolve(context.Background(), domain.SourceRef{Kind: "local", Value: sourceRoot})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := os.Rename(sourceRoot, originalRoot); err != nil {
		t.Fatalf("move original source: %v", err)
	}
	if err := os.Symlink(outsideRoot, sourceRoot); err != nil {
		t.Skipf("directory symlink creation is unavailable on this platform: %v", err)
	}

	_, err = provider.Fetch(context.Background(), resolved)
	if err == nil {
		t.Fatal("Fetch accepted a source root replaced by a symlink after Resolve")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeSourceSymlinkEscape {
		t.Fatalf("Fetch replaced-root code = %q, want %q: %v", got, domain.CodeSourceSymlinkEscape, err)
	}
}

func TestFetchRejectsNonPortablePath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "résumé.txt"), "content")
	_, err := NewLocalProvider().Fetch(
		context.Background(),
		domain.ResolvedSource{Kind: "local", LocalPath: root},
	)
	if err == nil {
		t.Fatal("Fetch unexpectedly accepted a non-portable path")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeSourcePathTraversal {
		t.Fatalf("Fetch non-portable path code = %q, want %q: %v", got, domain.CodeSourcePathTraversal, err)
	}
}

func TestValidatePortablePathRejectsWindowsReservedDeviceNames(t *testing.T) {
	for _, value := range []string{
		"CON",
		"con.txt",
		"nested/PrN.json",
		"aux",
		"NUL.log",
		"COM1",
		"com9.data",
		"LPT1",
		"nested/lpt9.txt",
		"CONIN$",
		"conout$.txt",
		"nested/CLOCK$",
	} {
		t.Run(value, func(t *testing.T) {
			err := validatePortablePath(value)
			if got := domain.ErrorCodeOf(err); got != domain.CodeSourcePathTraversal {
				t.Fatalf(
					"validatePortablePath(%q) code = %q, want %q: %v",
					value,
					got,
					domain.CodeSourcePathTraversal,
					err,
				)
			}
		})
	}
}

func TestValidatePortablePathAcceptsDeviceNameLookalikes(t *testing.T) {
	for _, value := range []string{
		"CONSOLE.txt",
		"COM0",
		"COM10",
		"LPT0",
		"LPT10",
		"nested/auxiliary.json",
	} {
		t.Run(value, func(t *testing.T) {
			if err := validatePortablePath(value); err != nil {
				t.Fatalf("validatePortablePath(%q): %v", value, err)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create parent for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
