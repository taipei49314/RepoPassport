//go:build linux

package sourcequalification

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadStablePackageFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "untrusted-fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := readStablePackageFile(path, 1024, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO was accepted as a regular package file")
		}
	case <-time.After(500 * time.Millisecond):
		// Release an implementation that incorrectly used a blocking open so
		// the test process does not retain a stuck goroutine after reporting it.
		writer, _ := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if writer >= 0 {
			_ = unix.Close(writer)
		}
		t.Fatal("FIFO inspection blocked before regular-file metadata rejection")
	}
}
