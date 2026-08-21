//go:build windows

package sourcequalification

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/qualificationfixture"
)

func TestPrepareWindowsReleaseQualificationFixtureBuildsAndBinds(t *testing.T) {
	requireHostFilesystem(t)
	repository := workflowRepositoryRoot(t)
	application := requireTrustedWindowsGoApplication(t)
	privateRoot := t.TempDir()
	environment := windowsNetworkNoneGoVersionEnvironment(t, application, privateRoot)
	for index, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "GOPROXY":
			environment[index] = "GOPROXY=https://proxy.golang.org"
		case "GOSUMDB":
			environment[index] = "GOSUMDB=sum.golang.org"
		}
	}
	request := gateProcessRequest{
		Application:            application,
		ContainmentApplication: application,
		Args:                   []string{"test", "-count=1", "-timeout=30m", "./..."},
		Dir:                    repository,
		Env:                    environment,
		Network:                NetworkNone,
		Timeout:                35 * time.Minute,
		StdoutLimit:            maximumGateOutputBytes,
		StderrLimit:            maximumGateOutputBytes,
	}
	binding, err := prepareWindowsReleaseQualificationFixture(context.Background(), &request)
	if err != nil || binding == nil {
		t.Fatalf("prepare host release-qualification fixture: binding=%v err=%v", binding != nil, err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			_ = binding.Release()
		}
	})
	root := windowsEnvironmentLookup(request.Env, qualificationfixture.ImportRootEnv)
	digest := windowsEnvironmentLookup(request.Env, qualificationfixture.ManifestDigestEnv)
	loaded, err := qualificationfixture.Load(root, digest)
	if err != nil || loaded == nil {
		t.Fatalf("load bound host release-qualification fixture: err=%v", err)
	}
	if len(loaded.Files) != 6 {
		t.Fatalf("load bound host release-qualification fixture: files=%d, want 6", len(loaded.Files))
	}
	if writable, err := os.OpenFile(loaded.Files[0].Path, os.O_WRONLY, 0); err == nil {
		_ = writable.Close()
		t.Fatal("share-read fixture binding admitted a writer")
	}
	if err := binding.Verify(context.Background()); err != nil {
		t.Fatalf("verify held release-qualification fixture: %v", err)
	}
	if err := binding.Release(); err != nil {
		t.Fatalf("release held release-qualification fixture: %v", err)
	}
	released = true
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("release fixture staging survived binding release: %v", err)
	}
}

func TestWindowsReleaseQualificationFixtureTargetIsExact(t *testing.T) {
	request := gateProcessRequest{
		Application:            `C:\Go\bin\go.exe`,
		ContainmentApplication: `C:\tools\repopass-source-qualify.exe`,
		Args:                   []string{"test", "-count=1", "-timeout=30m", "./..."},
		Network:                NetworkNone,
	}
	if !windowsReleaseQualificationFixtureTarget(request) {
		t.Fatal("exact Windows qualification test gate did not select the host fixture boundary")
	}
	tests := map[string]func(*gateProcessRequest){
		"host network":        func(value *gateProcessRequest) { value.Network = NetworkGoModules },
		"no containment":      func(value *gateProcessRequest) { value.ContainmentApplication = "" },
		"different tool":      func(value *gateProcessRequest) { value.Application = `C:\Go\bin\gofmt.exe` },
		"different arguments": func(value *gateProcessRequest) { value.Args[2] = "-timeout=29m" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.Args = append([]string(nil), request.Args...)
			mutate(&candidate)
			if windowsReleaseQualificationFixtureTarget(candidate) {
				t.Fatal("noncanonical gate selected the host fixture boundary")
			}
		})
	}
}

func TestWindowsGateEnvironmentWithReplacementsIsCanonical(t *testing.T) {
	input := []string{"PATH=old", "GOFLAGS=", "HOME=C:\\private"}
	got, ok := windowsGateEnvironmentWithReplacements(input, map[string]string{
		"path":    "new",
		"GOFLAGS": "-buildvcs=false",
		"GOWORK":  "off",
	})
	if !ok {
		t.Fatal("valid host fixture environment replacement was rejected")
	}
	want := []string{
		"HOME=C:\\private",
		"GOFLAGS=-buildvcs=false",
		"GOWORK=off",
		"PATH=new",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("host fixture environment = %#v, want %#v", got, want)
	}
	if _, ok := windowsGateEnvironmentWithReplacements(
		input,
		map[string]string{"BAD": "line\nbreak"},
	); ok {
		t.Fatal("invalid host fixture environment replacement was accepted")
	}
}

func TestWindowsReleaseQualificationHostPathExcludesOuterPath(t *testing.T) {
	goPath := filepath.Join(`C:\Pinned Go`, "bin", "go.exe")
	gitPath := filepath.Join(`C:\Program Files\Git`, "cmd", "git.exe")
	got := windowsReleaseQualificationHostPath(goPath, gitPath, `C:\Windows`)
	parts := filepath.SplitList(got)
	want := []string{
		filepath.Dir(gitPath),
		filepath.Join(`C:\Windows`, "System32"),
	}
	if len(parts) != len(want) {
		t.Fatalf("host fixture PATH is not the exact bounded set: %q", got)
	}
	for index := range want {
		if !sameCanonicalPath(parts[index], want[index]) {
			t.Fatalf("host fixture PATH[%d] = %q, want %q", index, parts[index], want[index])
		}
	}
	if controllerRuntimeToolPathContainsApplication(got, goPath) || got == os.Getenv("PATH") {
		t.Fatalf("host fixture PATH exposed the Go directory or outer PATH: %q", got)
	}
}
