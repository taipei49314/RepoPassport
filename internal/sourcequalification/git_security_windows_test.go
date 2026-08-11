//go:build windows

package sourcequalification

import (
	"os"
	"testing"
)

func TestInspectRepositoryRejectsAlternateDataStream(t *testing.T) {
	fixture := newGitRepositoryFixture(t)
	stream := fixture.root + `\README.md:repopass-security-test`
	if err := os.WriteFile(stream, []byte("private alternate stream\n"), 0o600); err != nil {
		t.Skipf("NTFS alternate data streams are unavailable on this runner: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(stream) })

	requireRepositoryInspectionRejected(t, fixture.request())
}

func TestValidateWindowsMetadataRejectsEveryReparsePoint(t *testing.T) {
	const (
		fileAttributeReparsePoint = uint32(0x00000400)
		ioReparseTagSymlink       = uint32(0xa000000c)
		ioReparseTagMountPoint    = uint32(0xa0000003)
		ioReparseTagDedup         = uint32(0x80000013)
	)
	for _, test := range []struct {
		name string
		tag  uint32
	}{
		{name: "symlink", tag: ioReparseTagSymlink},
		{name: "mount_point", tag: ioReparseTagMountPoint},
		{name: "dedup_regular_mode", tag: ioReparseTagDedup},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateWindowsFileMetadata(fileAttributeReparsePoint, test.tag, 1); err == nil {
				t.Fatal("Windows reparse metadata was accepted")
			}
		})
	}
}

func TestValidateWindowsMetadataRejectsMultipleLinks(t *testing.T) {
	if err := validateWindowsFileMetadata(0, 0, 2); err == nil {
		t.Fatal("Windows metadata with an external hard-link alias was accepted")
	}
}
