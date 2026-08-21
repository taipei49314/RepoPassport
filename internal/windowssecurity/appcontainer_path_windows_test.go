//go:build windows

package windowssecurity

import "testing"

func TestCleanAbsoluteDOSPathRejectsAliasesAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		path string
		ok   bool
	}{
		{`C:\qualification\state`, true},
		{`c:\qualification\state`, true},
		{`C:\qualification\.\state`, false},
		{`C:\qualification\state\..\other`, false},
		{`C:\qualification\state:stream`, false},
		{`\\server\share\state`, false},
		{`\\?\C:\qualification\state`, false},
		{`\Device\HarddiskVolume3\state`, false},
		{`qualification\state`, false},
	} {
		_, _, ok := cleanAbsoluteDOSPath(test.path)
		if ok != test.ok {
			t.Fatalf("cleanAbsoluteDOSPath(%q) accepted=%v, want %v", test.path, ok, test.ok)
		}
	}
}

func TestAppContainerPathBoundaryRejectsEscapes(t *testing.T) {
	const boundary = `C:\qualification\tmp`
	for _, test := range []struct {
		path string
		ok   bool
	}{
		{`C:\qualification\tmp`, true},
		{`C:\qualification\tmp\case\state`, true},
		{`C:\qualification\tmp-other\state`, false},
		{`C:\qualification\outside`, false},
		{`D:\qualification\tmp\state`, false},
		{`C:\qualification\tmp\case\..\outside`, false},
	} {
		got, err := AppContainerPathBoundary(test.path, boundary)
		if (err == nil) != test.ok || (test.ok && got != boundary) {
			t.Fatalf("AppContainerPathBoundary(%q) = %q, %v; ok=%v", test.path, got, err, test.ok)
		}
	}
}
