package qualificationfixture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBuildHostBuildsBoundFixtureAndRemovesScratch(t *testing.T) {
	if os.Getenv(ImportRootEnv) != "" {
		t.Skip("host fixture builder does not run inside the contained import path")
	}
	goPath := requireHostBuildTestTool(t, "go")
	gitPath := requireHostBuildTestTool(t, "git")
	parent := t.TempDir()
	root := filepath.Join(parent, "fixture")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fixture, err := BuildHost(ctx, HostBuildRequest{
		Root:          root,
		GoExecutable:  goPath,
		GitExecutable: gitPath,
		Environment:   hostBuildTestEnvironment(gitPath),
	})
	if err != nil || fixture == nil {
		t.Fatalf("BuildHost fixture=%v err=%v", fixture != nil, err)
	}
	if fixture.Root != root || !validDigest(fixture.ManifestDigest) ||
		!validObjectID(fixture.Manifest.Revision) || !validObjectID(fixture.Manifest.Tree) ||
		!validObjectID(fixture.Manifest.LegacyRevision) || len(fixture.Files) != 6 {
		t.Fatalf("BuildHost returned invalid fixture metadata: %+v", fixture)
	}

	expected := map[string]struct {
		mainPath, module, target, revision string
	}{
		hostFullLinuxName: {
			hostCanonicalModule + "/cmd/repopass", hostCanonicalModule, "linux/amd64", fixture.Manifest.Revision,
		},
		hostFullWindowsName: {
			hostCanonicalModule + "/cmd/repopass", hostCanonicalModule, "windows/amd64", fixture.Manifest.Revision,
		},
		hostVerifierLinuxName: {
			hostCanonicalModule + "/cmd/repopass-verify", hostCanonicalModule, "linux/amd64", fixture.Manifest.Revision,
		},
		hostVerifierWindowsName: {
			hostCanonicalModule + "/cmd/repopass-verify", hostCanonicalModule, "windows/amd64", fixture.Manifest.Revision,
		},
		hostHelperName: {
			hostCanonicalModule + "/cmd/repopass-kit", hostCanonicalModule, runtime.GOOS + "/amd64", fixture.Manifest.Revision,
		},
		hostLegacyVerifierName: {
			hostLegacyModule + "/cmd/repopass-verify", hostLegacyModule, "linux/amd64", fixture.Manifest.LegacyRevision,
		},
	}
	for _, file := range fixture.Files {
		want, ok := expected[file.RelativePath]
		information := file.BuildInfo
		if !ok || information.MainPath != want.mainPath || information.MainModulePath != want.module ||
			information.GOOS+"/"+information.GOARCH != want.target ||
			file.SourceRevision != want.revision || information.VCSRevision != want.revision ||
			information.VCSModified || information.CGOEnabled || !information.Trimpath {
			t.Fatalf("BuildHost binary %q is not bound: %+v", file.RelativePath, file)
		}
	}
	loaded, err := Load(root, fixture.ManifestDigest)
	if err != nil || loaded == nil || len(loaded.Files) != len(fixture.Files) {
		t.Fatalf("Load(BuildHost) fixture=%v err=%v", loaded != nil, err)
	}

	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(root) || !entries[0].IsDir() {
		t.Fatalf("host-build scratch survived cleanup: %#v", entries)
	}
}

func TestHostBuildEnvironmentOverridesBuildIdentityWithoutDuplicates(t *testing.T) {
	gitPath := filepath.Join(t.TempDir(), hostBuildTestExecutableName("git"))
	base, err := hostBuildBaseEnvironment([]string{
		"PATH=" + filepath.Dir(gitPath),
		"GOOS=caller",
		"GOARCH=caller",
		"CGO_ENABLED=1",
		"GOWORK=caller",
		"KEEP=value",
	}, gitPath)
	if err != nil {
		t.Fatal(err)
	}
	got := hostBuildEnvironmentWithOverrides(base, map[string]string{
		"GOOS":        "linux",
		"GOARCH":      "amd64",
		"CGO_ENABLED": "0",
		"GOWORK":      "off",
	})
	want := map[string]string{
		"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOWORK": "off",
	}
	counts := make(map[string]int)
	for _, entry := range got {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("invalid environment entry %q", entry)
		}
		name = strings.ToUpper(name)
		counts[name]++
		if expected, identity := want[name]; identity && value != expected {
			t.Fatalf("environment %s=%q, want %q", name, value, expected)
		}
	}
	for name := range want {
		if counts[name] != 1 {
			t.Fatalf("environment %s count=%d, want 1", name, counts[name])
		}
	}
}

func requireHostBuildTestTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is unavailable: %v", name, err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(path)
}

func hostBuildTestEnvironment(gitPath string) []string {
	path := filepath.Dir(gitPath)
	if runtime.GOOS == "windows" {
		if systemRoot := os.Getenv("SYSTEMROOT"); systemRoot != "" {
			path += string(os.PathListSeparator) + filepath.Join(systemRoot, "System32")
		}
	}
	result := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(name, "PATH") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "PATH="+path)
}

func hostBuildTestExecutableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
