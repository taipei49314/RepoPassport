//go:build windows

package sourcequalification

import (
	"path/filepath"
	"testing"
)

func TestWindowsExecutableTreeIncludesGoRoot(t *testing.T) {
	t.Parallel()
	application := `C:\hostedtoolcache\windows\go\1.26.6\x64\bin\go.exe`
	tree := windowsExecutableTree(application)
	want := []string{
		application,
		`C:\hostedtoolcache\windows\go\1.26.6\x64\bin`,
		`C:\hostedtoolcache\windows\go\1.26.6\x64`,
	}
	for _, path := range want {
		found := false
		for _, got := range tree {
			if filepath.Clean(got) == filepath.Clean(path) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("windowsExecutableTree(%q) = %q, missing %q", application, tree, path)
		}
	}
}

func TestWindowsNewAppContainerNameFormat(t *testing.T) {
	t.Parallel()
	name, err := windowsNewAppContainerName()
	if err != nil {
		t.Fatal(err)
	}
	if len(name) < 12 || len(name) > 64 || name[:12] != "RepoPass.sq." {
		t.Fatalf("app container name = %q", name)
	}
	for _, r := range name {
		if r != '.' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			t.Fatalf("app container name %q has invalid rune %q", name, r)
		}
	}
}
