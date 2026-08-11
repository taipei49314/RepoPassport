//go:build windows

package sourcequalification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPackagePathContainmentRecognizesDistinctNTFSShortAlias(t *testing.T) {
	root := t.TempDir()
	repository := filepath.Join(root, "repository-with-a-deliberately-long-component-name")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(repository, "existing-child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}

	shortRepository := packageContainmentWindowsShortPath(t, repository)
	if strings.EqualFold(filepath.Clean(shortRepository), filepath.Clean(repository)) {
		t.Skip("NTFS short-name generation is disabled or did not produce a distinct alias")
	}
	shortExistingChild := filepath.Join(shortRepository, filepath.Base(child))
	shortFutureChild := filepath.Join(shortRepository, "future-output")

	for name, candidate := range map[string]string{
		"existing child": shortExistingChild,
		"absent child":   shortFutureChild,
	} {
		t.Run(name, func(t *testing.T) {
			contains, err := securePackagePathContains(repository, candidate)
			if err != nil || !contains {
				t.Fatalf("identity containment = (%t, %v), want true", contains, err)
			}
			if !packagePathContains(repository, candidate) {
				t.Fatalf("long repository %q did not contain short-alias candidate %q",
					repository, candidate)
			}
			if !pathWithinRepository(repository, candidate) {
				t.Fatalf("repository containment missed short-alias candidate %q", candidate)
			}
		})
	}
}

func TestQualificationLaneRejectsOutputThroughDistinctNTFSShortAlias(t *testing.T) {
	fixture := newLaneProducerFixture(t, LaneWindowsAMD64)
	root := filepath.Dir(fixture.request.Repository.Root)
	repository := filepath.Join(root, "repository-with-a-deliberately-long-component-name")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	shortRepository := packageContainmentWindowsShortPath(t, repository)
	if strings.EqualFold(filepath.Clean(shortRepository), filepath.Clean(repository)) {
		t.Skip("NTFS short-name generation is disabled or did not produce a distinct alias")
	}

	fixture.request.Repository.Root = repository
	fixture.request.Gate.RepositoryRoot = repository
	fixture.request.OutputDir = filepath.Join(shortRepository, "future-output")
	status, err := produceQualificationLane(
		context.Background(),
		fixture.request,
		fixture.dependencies,
	)
	if status != StatusFail || !errors.Is(err, errQualificationLaneInvalidInput) {
		t.Fatalf("short-alias output result = (%s, %v), want FAIL/invalid input", status, err)
	}
	if len(fixture.history.scopes) != 0 || len(fixture.inspector.requests) != 0 {
		t.Fatalf("rejected request reached history/source: history=%d source=%d",
			len(fixture.history.scopes), len(fixture.inspector.requests))
	}
}

func packageContainmentWindowsShortPath(t *testing.T, path string) string {
	t.Helper()
	longPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	required, err := windows.GetShortPathName(longPath, nil, 0)
	if err != nil || required == 0 {
		t.Skipf("NTFS short path unavailable: %v", err)
	}
	buffer := make([]uint16, required+1)
	written, err := windows.GetShortPathName(longPath, &buffer[0], uint32(len(buffer)))
	if err != nil || written == 0 || written >= uint32(len(buffer)) {
		t.Skipf("NTFS short path unavailable: %v", err)
	}
	return filepath.Clean(windows.UTF16ToString(buffer[:written]))
}
