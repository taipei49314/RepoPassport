package sourcequalification

import "testing"

func TestQualificationPackageDigestGoldenAndSubstitution(t *testing.T) {
	archive := []byte("archive")
	manifest := []byte("manifest")
	linux := []byte("linux")
	windows := []byte("windows")

	const want = "sha256:c3beae119db12de51c9f3afce28a1dd2aae5798c274dff13feb6d15f80a63bc1"
	got := qualificationPackageDigest(archive, manifest, linux, windows)
	if got != want {
		t.Fatalf("qualificationPackageDigest = %q, want frozen domain-separated digest %q", got, want)
	}

	mutated := append([]byte(nil), windows...)
	mutated[0] ^= 1
	if qualificationPackageDigest(archive, manifest, linux, mutated) == got {
		t.Fatal("qualification package digest did not bind Windows receipt bytes")
	}
}

func TestQualificationPackageContractOrderIsExact(t *testing.T) {
	want := []string{
		"repopass-source.tar",
		"source-archive-manifest-v1.json",
		"source-qualification-linux-amd64-v1.json",
		"source-qualification-windows-amd64-v1.json",
	}
	got := qualificationPackageFilenames()
	if len(got) != len(want) {
		t.Fatalf("qualification package filenames = %q, want %q", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("qualification package filenames = %q, want exact order %q", got, want)
		}
	}
	got[0] = "mutated"
	if qualificationPackageFilenames()[0] != want[0] {
		t.Fatal("qualification package filename contract leaked mutable backing storage")
	}
}
