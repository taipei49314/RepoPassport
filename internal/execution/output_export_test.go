package execution

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestExtractOutputArchiveAcceptsGNUStyleNestedDirectoryAndPadding(t *testing.T) {
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	writeTarHeader(t, writer, &tar.Header{
		Name:     "./nested/",
		Typeflag: tar.TypeDir,
		Mode:     0o000,
	})
	payload := []byte("trusted-output\n")
	writeTarHeader(t, writer, &tar.Header{
		Name:     "./nested/result.txt",
		Typeflag: tar.TypeReg,
		Mode:     0o000,
		Size:     int64(len(payload)),
	})
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write tar payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	stream.Write(make([]byte, 10<<10))

	root := t.TempDir()
	runner := testRunner(&fakeExecutor{})
	summary, extractErr := runner.extractOutputArchive(
		bytes.NewReader(stream.Bytes()),
		root,
		1<<20,
		int64(stream.Len()+1),
	)
	if extractErr != nil {
		t.Fatalf("extractOutputArchive: %v", extractErr)
	}
	if summary.FileCount != 2 || summary.TotalBytes != int64(len(payload)) {
		t.Fatalf("summary = %#v", summary)
	}
	actual, err := os.ReadFile(filepath.Join(root, "nested", "result.txt"))
	if err != nil {
		t.Fatalf("read extracted output: %v", err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("extracted output = %q, want %q", actual, payload)
	}
}

func TestPortableArchivePathRejectsWindowsAndTraversalHazards(t *testing.T) {
	for _, value := range []string{
		"../escape",
		`..\escape`,
		"C:",
		"a:stream",
		"CON",
		"prn.json",
		"AUX",
		"nul.txt",
		"COM1",
		"com9.data",
		"LPT1",
		"nested/lpt9.txt",
		"CONIN$.log",
		"conout$",
		"CLOCK$.txt",
		"trailing.",
		"trailing ",
		"control\nname",
		"caf\u00e9",
		".home/cache",
		".tmp/data",
	} {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			if _, err := portableArchivePath(value); err == nil {
				t.Fatalf("portableArchivePath(%q) unexpectedly succeeded", value)
			}
		})
	}
}

func TestPortableArchivePathAcceptsDeviceNameLookalikes(t *testing.T) {
	for _, value := range []string{
		"CONSOLE.txt",
		"COM0",
		"COM10",
		"LPT0",
		"LPT10",
		"nested/auxiliary.json",
	} {
		t.Run(value, func(t *testing.T) {
			if normalized, err := portableArchivePath(value); err != nil ||
				normalized != value {
				t.Fatalf(
					"portableArchivePath(%q) = %q, %v",
					value,
					normalized,
					err,
				)
			}
		})
	}
}

func TestExtractOutputArchiveRejectsLinksSpecialsAndCaseCollisions(t *testing.T) {
	tests := []struct {
		name    string
		headers []*tar.Header
	}{
		{
			name: "symlink",
			headers: []*tar.Header{{
				Name:     "./link",
				Typeflag: tar.TypeSymlink,
				Linkname: "/etc/passwd",
			}},
		},
		{
			name: "hardlink",
			headers: []*tar.Header{{
				Name:     "./hard",
				Typeflag: tar.TypeLink,
				Linkname: "./target",
			}},
		},
		{
			name: "fifo",
			headers: []*tar.Header{{
				Name:     "./pipe",
				Typeflag: tar.TypeFifo,
			}},
		},
		{
			name: "device",
			headers: []*tar.Header{{
				Name:     "./device",
				Typeflag: tar.TypeChar,
			}},
		},
		{
			name: "case collision",
			headers: []*tar.Header{
				{Name: "./Result.txt", Typeflag: tar.TypeReg},
				{Name: "./result.txt", Typeflag: tar.TypeReg},
			},
		},
		{
			name: "pax metadata",
			headers: []*tar.Header{{
				Name:       "./result.txt",
				Typeflag:   tar.TypeReg,
				Format:     tar.FormatPAX,
				PAXRecords: map[string]string{"comment": "untrusted"},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := make([]any, len(test.headers))
			for index, header := range test.headers {
				values[index] = header
			}
			stream := tarStream(t, values...)
			_, extractErr := testRunner(&fakeExecutor{}).extractOutputArchive(
				bytes.NewReader(stream),
				t.TempDir(),
				1<<20,
				int64(len(stream)+1),
			)
			if got := domain.ErrorCodeOf(extractErr); got !=
				domain.CodeForbiddenFilesystemAccess {
				t.Fatalf(
					"extract error code = %q, want %q: %v",
					got,
					domain.CodeForbiddenFilesystemAccess,
					extractErr,
				)
			}
		})
	}
}

func TestExtractOutputArchiveRejectsLogicalAndArchiveByteOverflow(t *testing.T) {
	logical := tarStream(t, &tar.Header{
		Name:     "./too-large.bin",
		Typeflag: tar.TypeReg,
		Size:     2,
	}, []byte("xx"))
	_, logicalErr := testRunner(&fakeExecutor{}).extractOutputArchive(
		bytes.NewReader(logical),
		t.TempDir(),
		1,
		int64(len(logical)+1),
	)
	if got := domain.ErrorCodeOf(logicalErr); got !=
		domain.CodeResourceLimitExceeded {
		t.Fatalf("logical overflow code = %q: %v", got, logicalErr)
	}

	padding := make([]byte, 2048)
	_, archiveErr := testRunner(&fakeExecutor{}).extractOutputArchive(
		bytes.NewReader(padding),
		t.TempDir(),
		1,
		1024,
	)
	if got := domain.ErrorCodeOf(archiveErr); got !=
		domain.CodeResourceLimitExceeded {
		t.Fatalf("archive overflow code = %q: %v", got, archiveErr)
	}
}

func TestExtractOutputArchiveRejectsTruncatedRegularFile(t *testing.T) {
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	writeTarHeader(t, writer, &tar.Header{
		Name:     "./partial.bin",
		Typeflag: tar.TypeReg,
		Size:     4,
	})
	if _, err := writer.Write([]byte("xx")); err != nil {
		t.Fatalf("write partial body: %v", err)
	}
	_ = writer.Flush()

	_, extractErr := testRunner(&fakeExecutor{}).extractOutputArchive(
		bytes.NewReader(stream.Bytes()),
		t.TempDir(),
		1<<20,
		int64(stream.Len()+1),
	)
	if got := domain.ErrorCodeOf(extractErr); got != domain.CodeCleanupFailed {
		t.Fatalf("truncated archive code = %q: %v", got, extractErr)
	}
}

func tarStream(t *testing.T, values ...any) []byte {
	t.Helper()
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	for index := 0; index < len(values); index++ {
		header, ok := values[index].(*tar.Header)
		if !ok {
			t.Fatalf("tarStream value %d is %T, want *tar.Header", index, values[index])
		}
		writeTarHeader(t, writer, header)
		if header.Size > 0 && index+1 < len(values) {
			if payload, ok := values[index+1].([]byte); ok {
				if _, err := writer.Write(payload); err != nil {
					t.Fatalf("write tar body: %v", err)
				}
				index++
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar stream: %v", err)
	}
	return stream.Bytes()
}

func writeTarHeader(t *testing.T, writer *tar.Writer, header *tar.Header) {
	t.Helper()
	if err := writer.WriteHeader(header); err != nil {
		t.Fatalf("write tar header %#v: %v", header, err)
	}
}
