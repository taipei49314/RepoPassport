//go:build windows

package pathsecurity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestQualificationEnvironmentValuesAcceptOnlyIdenticalWindowsAliases(t *testing.T) {
	environment := []string{
		`HOME=C:\private\home`,
		`GOCACHE=C:\private\cache`,
		`GOMODCACHE=C:\private\modules`,
		`GOTMPDIR=C:\private\tmp`,
		`PATH=C:\tools`,
		`SYSTEMROOT=C:\Windows`,
		`SystemRoot=C:\Windows`,
	}
	values, ok := qualificationEnvironmentValues(environment)
	if !ok || values["SYSTEMROOT"] != `C:\Windows` {
		t.Fatalf("identical Windows aliases = (%#v, %t), want accepted", values, ok)
	}

	conflicting := append([]string(nil), environment...)
	conflicting[len(conflicting)-1] = `SystemRoot=D:\Windows`
	if _, ok := qualificationEnvironmentValues(conflicting); ok {
		t.Fatal("conflicting Windows aliases were accepted")
	}
}

func TestQualificationDescriptorRequiresDistinctSingleRoleRoots(t *testing.T) {
	valid := testQualificationDescriptor()
	if !validQualificationDescriptor(valid) {
		t.Fatal("valid single-role descriptor was rejected")
	}

	tests := map[string]func(*qualificationRootsDescriptor){
		"unknown role": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[0].Role = "other"
		},
		"duplicate singleton role": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[3].Role = "repo"
		},
		"missing tool role": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots = descriptor.Roots[:3]
		},
		"duplicate path": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[3].Path = descriptor.Roots[1].Path
			testSortQualificationRoots(descriptor.Roots)
		},
		"case-folded duplicate path": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[3].Path = strings.ToUpper(descriptor.Roots[1].Path)
			testSortQualificationRoots(descriptor.Roots)
		},
		"duplicate filesystem identity": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[3].VolumeSerial = descriptor.Roots[1].VolumeSerial
			descriptor.Roots[3].FileIndexHigh = descriptor.Roots[1].FileIndexHigh
			descriptor.Roots[3].FileIndexLow = descriptor.Roots[1].FileIndexLow
		},
		"nested path": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[0].Path = filepath.Join(descriptor.Roots[1].Path, "private")
			testSortQualificationRoots(descriptor.Roots)
		},
		"unsorted roots": func(descriptor *qualificationRootsDescriptor) {
			descriptor.Roots[0], descriptor.Roots[1] = descriptor.Roots[1], descriptor.Roots[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			descriptor := testCloneQualificationDescriptor(valid)
			mutate(&descriptor)
			if validQualificationDescriptor(descriptor) {
				t.Fatal("ambiguous qualification descriptor was accepted")
			}
		})
	}
}

func TestDecodeQualificationDescriptorRequiresCanonicalSingleRoleSchema(t *testing.T) {
	descriptor := testQualificationDescriptor()
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	decoded, err := decodeQualificationDescriptor(encoded)
	if err != nil || !reflect.DeepEqual(decoded, descriptor) {
		t.Fatalf("canonical descriptor = (%#v, %v), want original", decoded, err)
	}

	legacy := strings.Replace(string(raw), `"role":"private"`, `"roles":["private"]`, 1)
	unknown := strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`
	for name, candidate := range map[string]string{
		"legacy multi-role field": base64.RawURLEncoding.EncodeToString([]byte(legacy)),
		"unknown top-level field": base64.RawURLEncoding.EncodeToString([]byte(unknown)),
		"non-canonical JSON":      base64.RawURLEncoding.EncodeToString(append(raw, '\n')),
		"padded base64":           encoded + "=",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeQualificationDescriptor(candidate); err == nil {
				t.Fatal("non-canonical or multi-role descriptor was accepted")
			}
		})
	}
}

func TestWindowsQualificationAdapterRetainsRootIdentity(t *testing.T) {
	adapter, roots := testWindowsQualificationAdapter(t)
	root := testQualificationRootByRole(t, roots, "repo")
	renamed := root.Path + "-renamed"

	renameErr := os.Rename(root.Path, renamed)
	if renameErr == nil {
		if err := os.Mkdir(root.Path, 0o700); err != nil {
			adapter.closeRetainedRoots()
			t.Fatal(err)
		}
		if err := adapter.validateRoot(root); err == nil {
			adapter.closeRetainedRoots()
			t.Fatal("renamed qualification root retained its stale textual identity")
		}
		adapter.closeRetainedRoots()
		return
	}
	if err := adapter.validateRoot(root); err != nil {
		adapter.closeRetainedRoots()
		t.Fatalf("retained qualification root validation: %v", err)
	}
	adapter.closeRetainedRoots()
	if err := os.Rename(root.Path, renamed); err != nil {
		t.Fatalf("rename after releasing retained root: %v", err)
	}
}

func TestWindowsQualificationAdapterRetainsAncestorChain(t *testing.T) {
	adapter, roots := testWindowsQualificationAdapter(t)
	defer adapter.closeRetainedRoots()
	root := testQualificationRootByRole(t, roots, "repo")
	ancestor := filepath.Join(root.Path, "one")
	target := filepath.Join(ancestor, "two", "target.txt")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("bound"), 0o600); err != nil {
		t.Fatal(err)
	}

	identity, err := adapter.openRetainedQualificationPath(root, target)
	if err != nil {
		t.Fatalf("open retained target identity: %v", err)
	}
	renamed := ancestor + "-renamed"
	renameErr := os.Rename(ancestor, renamed)
	if renameErr == nil {
		if err := validateVolumeRelativeFinalPath(identity.handle, target); err == nil {
			identity.close()
			_ = os.Rename(renamed, ancestor)
			t.Fatal("renamed ancestor retained a stale textual target identity")
		}
		identity.close()
		if err := os.Rename(renamed, ancestor); err != nil {
			t.Fatalf("restore renamed ancestor: %v", err)
		}
		return
	}
	identity.close()
	if err := os.Rename(ancestor, renamed); err != nil {
		t.Fatalf("rename after releasing ancestor chain: %v", err)
	}
}

func TestWindowsQualificationRelativeOpenStaysOnFrozenRoot(t *testing.T) {
	adapter, roots := testWindowsQualificationAdapter(t)
	defer adapter.closeRetainedRoots()
	root := testQualificationRootByRole(t, roots, "repo")
	originalPath := filepath.Join(root.Path, "marker.txt")
	if err := os.WriteFile(originalPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := testWindowsPathInformation(t, originalPath)
	rootHandle, _, err := adapter.retainedRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	displaced := root.Path + "-displaced"
	renamed := os.Rename(root.Path, displaced) == nil
	var replacement windows.ByHandleFileInformation
	if renamed {
		if err := os.Mkdir(root.Path, 0o700); err != nil {
			t.Fatal(err)
		}
		replacementPath := filepath.Join(root.Path, "marker.txt")
		if err := os.WriteFile(replacementPath, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		replacement = testWindowsPathInformation(t, replacementPath)
	}

	handle, information, err := openRetainedRelativePathIdentity(rootHandle, "marker.txt")
	if err != nil {
		t.Fatalf("open marker relative to frozen root: %v", err)
	}
	_ = windows.CloseHandle(handle)
	if !sameWindowsPathInformation(information, original) {
		t.Fatal("handle-relative walk did not remain on the frozen root")
	}
	if renamed && sameWindowsPathInformation(information, replacement) {
		t.Fatal("handle-relative walk followed the textual replacement root")
	}
}

func TestQualificationRoleAPIsRejectCrossRolePaths(t *testing.T) {
	adapter, roots := testWindowsQualificationAdapter(t)
	defer adapter.closeRetainedRoots()
	repository := testQualificationRootByRole(t, roots, "repo")
	tool := testQualificationRootByRole(t, roots, "tool")
	repositoryChild := filepath.Join(repository.Path, "child")
	toolChild := filepath.Join(tool.Path, "child")
	for _, path := range []string{repositoryChild, toolChild} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	previous := qualificationAdapter
	qualificationAdapter = adapter
	defer func() { qualificationAdapter = previous }()
	if boundary, handled, err := QualificationPathBoundary(repositoryChild, "repo"); err != nil || !handled || !strings.EqualFold(boundary, repository.Path) {
		t.Fatalf("repository boundary = (%q, %t, %v)", boundary, handled, err)
	}
	if _, handled, err := QualificationPathBoundary(repositoryChild, "tool"); !handled || err == nil {
		t.Fatalf("cross-role boundary = (handled %t, err %v), want handled error", handled, err)
	}
	if contains, handled, err := QualificationPathContains(repository.Path, repositoryChild); err != nil || !handled || !contains {
		t.Fatalf("same-role containment = (%t, %t, %v)", contains, handled, err)
	}
	missingChild := filepath.Join(repository.Path, "future", "child")
	if contains, handled, err := QualificationPathContains(repository.Path, missingChild); err != nil || !handled || !contains {
		t.Fatalf("same-role missing containment = (%t, %t, %v)", contains, handled, err)
	}
	if contains, handled, err := QualificationPathContains(repository.Path, toolChild); err != nil || !handled || contains {
		t.Fatalf("cross-role containment = (%t, %t, %v)", contains, handled, err)
	}
}

func TestWindowsQualificationAdapterRejectsSwappedRoot(t *testing.T) {
	_, roots := testWindowsQualificationPaths(t)
	repository := testQualificationRootByRole(t, roots, "repo")
	displaced := repository.Path + "-displaced"
	if err := os.Rename(repository.Path, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(repository.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter, err := newWindowsQualificationAdapter("test", roots)
	if adapter != nil {
		adapter.closeRetainedRoots()
	}
	if !errors.Is(err, errQualificationRootIdentity) {
		t.Fatalf("swapped root adapter error = %v, want %v", err, errQualificationRootIdentity)
	}
}

func testQualificationDescriptor() qualificationRootsDescriptor {
	descriptor := qualificationRootsDescriptor{
		Version: qualificationDescriptorVersion,
		Roots: []qualificationRootDescriptor{
			{Path: `C:\private`, Role: "private", VolumeSerial: 1, FileIndexLow: 1},
			{Path: `C:\repo`, Role: "repo", VolumeSerial: 1, FileIndexLow: 2},
			{Path: `C:\system`, Role: "system", VolumeSerial: 1, FileIndexLow: 3},
			{Path: `C:\tools`, Role: "tool", VolumeSerial: 1, FileIndexLow: 4},
		},
	}
	testSortQualificationRoots(descriptor.Roots)
	return descriptor
}

func testCloneQualificationDescriptor(source qualificationRootsDescriptor) qualificationRootsDescriptor {
	return qualificationRootsDescriptor{
		Version: source.Version,
		Roots:   append([]qualificationRootDescriptor(nil), source.Roots...),
	}
}

func testSortQualificationRoots(roots []qualificationRootDescriptor) {
	sort.Slice(roots, func(left, right int) bool {
		return strings.ToLower(roots[left].Path) < strings.ToLower(roots[right].Path)
	})
}

func testWindowsQualificationAdapter(
	t *testing.T,
) (*windowsQualificationAdapter, []qualificationRootDescriptor) {
	t.Helper()
	_, roots := testWindowsQualificationPaths(t)
	adapter, err := newWindowsQualificationAdapter("test", roots)
	if err != nil {
		t.Fatalf("create qualification adapter: %v", err)
	}
	return adapter, roots
}

func testWindowsQualificationPaths(t *testing.T) (string, []qualificationRootDescriptor) {
	t.Helper()
	base := t.TempDir()
	roots := make([]qualificationRootDescriptor, 0, 4)
	for _, item := range []struct {
		name string
		role string
	}{
		{"private", "private"},
		{"repo", "repo"},
		{"system", "system"},
		{"tool", "tool"},
	} {
		path := filepath.Join(base, item.name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		handle, information, err := openPathIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateVolumeRelativeFinalPath(handle, path); err != nil {
			_ = windows.CloseHandle(handle)
			t.Fatalf("fixture final path %q: %v", path, err)
		}
		_ = windows.CloseHandle(handle)
		roots = append(roots, qualificationRootDescriptor{
			Path:          path,
			Role:          item.role,
			VolumeSerial:  information.VolumeSerialNumber,
			FileIndexHigh: information.FileIndexHigh,
			FileIndexLow:  information.FileIndexLow,
		})
	}
	testSortQualificationRoots(roots)
	return base, roots
}

func testQualificationRootByRole(
	t *testing.T,
	roots []qualificationRootDescriptor,
	role string,
) qualificationRootDescriptor {
	t.Helper()
	for _, root := range roots {
		if root.Role == role {
			return root
		}
	}
	t.Fatalf("qualification root role %q is missing", role)
	return qualificationRootDescriptor{}
}

func testWindowsPathInformation(t *testing.T, path string) windows.ByHandleFileInformation {
	t.Helper()
	handle, information, err := openPathIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = windows.CloseHandle(handle)
	return information
}

func sameWindowsPathInformation(left, right windows.ByHandleFileInformation) bool {
	return left.VolumeSerialNumber == right.VolumeSerialNumber &&
		left.FileIndexHigh == right.FileIndexHigh &&
		left.FileIndexLow == right.FileIndexLow
}
