package releaseindex

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseArtifactRejectsAlternateDataStream(t *testing.T) {
	root := artifactFixture(t)
	artifact := filepath.Join(root, "repopass-linux")
	if err := os.WriteFile(artifact+":hidden", []byte("unlisted"), 0o600); err != nil {
		t.Fatalf("create alternate data stream: %v", err)
	}
	if _, err := BuildIndex(root, ProductVersion, 1); !errors.Is(err, ErrArtifactsInvalid) {
		t.Fatalf("alternate data stream accepted: %v", err)
	}
}

func TestStableFileRejectsPostReadAlternateDataStreamRace(t *testing.T) {
	root := artifactFixture(t)
	artifact := filepath.Join(root, "repopass-linux")
	var hookErr error
	_, _, err := stableFileWithPostReadHook(artifact, MaxArtifactBytes, false, func() {
		hookErr = os.WriteFile(artifact+":late", []byte("late"), 0o600)
	})
	if hookErr != nil {
		t.Fatalf("create alternate data stream: %v", hookErr)
	}
	if !errors.Is(err, ErrReadFailed) {
		t.Fatalf("post-read alternate data stream race accepted: %v", err)
	}
}

func TestPublishedSidecarsRetainPrivateWindowsDACL(t *testing.T) {
	root := artifactFixture(t)
	index := mustIndex(t, root, 1)
	private, spki := keyPair(t)
	envelopeRaw, _, err := SignIndex(index, private)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "private-sidecars")
	if err := PublishSignedSidecars(output, index, envelopeRaw, spki); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := validatePublicationDirectory(output); err != nil {
		t.Fatalf("final directory DACL: %v", err)
	}
	for _, name := range []string{"release-index.json", "signature.dsse.json", "signer-public-key.pem"} {
		if err := validatePublicationFile(filepath.Join(output, name)); err != nil {
			t.Fatalf("%s DACL: %v", name, err)
		}
	}
}
