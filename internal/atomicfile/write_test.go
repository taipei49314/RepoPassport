package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCreatesAndReplacesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "passport.lock.json")
	if err := Write(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("Write(first): %v", err)
	}
	if err := Write(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("Write(second): %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("contents = %q, want second", got)
	}
}
