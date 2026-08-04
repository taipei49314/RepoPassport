package releasekit

import (
	"bytes"
	"testing"
)

func TestBuildIsDeterministicAndBindsManifest(t *testing.T) {
	target := Target{OS: "linux", Arch: "amd64"}
	first, err := Build(target, "0.1.0-alpha.33", []byte("portable verifier\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(target, "0.1.0-alpha.33", []byte("portable verifier\n"))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("kit is not deterministic: %v", err)
	}
	if err := Validate(first, target, "0.1.0-alpha.33"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsMutationAndTrailingBytes(t *testing.T) {
	target := Target{OS: "windows", Arch: "amd64"}
	kit, err := Build(target, "0.1.0-alpha.33", []byte("portable verifier\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutated := range [][]byte{
		append(append([]byte(nil), kit...), 0),
		append([]byte(nil), kit[:len(kit)-1]...),
		func() []byte { value := append([]byte(nil), kit...); value[100] ^= 1; return value }(),
		func() []byte {
			value := append([]byte(nil), kit...)
			offset := bytes.Index(value, []byte("portable verifier\n"))
			value[offset] ^= 1
			return value
		}(),
	} {
		if err := Validate(mutated, target, "0.1.0-alpha.33"); err == nil {
			t.Fatal("non-canonical archive was accepted")
		}
	}
}

func TestBuildRejectsUnsupportedTarget(t *testing.T) {
	if _, err := Build(Target{OS: "darwin", Arch: "arm64"}, "0.1.0-alpha.33", []byte("x")); err == nil {
		t.Fatal("unsupported target was accepted")
	}
}

func TestBuildRejectsVersionOutsideContract(t *testing.T) {
	if _, err := Build(Target{OS: "linux", Arch: "amd64"}, "0.1.0-alpha.27", []byte("x")); err == nil {
		t.Fatal("version outside the frozen Alpha.33 contract was accepted")
	}
}

func TestBuildRejectsBinaryAboveAggregateMemoryBudget(t *testing.T) {
	if _, err := Build(
		Target{OS: "linux", Arch: "amd64"}, ProductVersion, make([]byte, MaxBinaryBytes+1),
	); err == nil {
		t.Fatal("binary above the 32 MiB kit budget was accepted")
	}
}

func TestAlpha33PortableKitDeclaresChainBoundary(t *testing.T) {
	kit, err := Build(Target{OS: "linux", Arch: "amd64"}, ProductVersion, []byte("portable verifier\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(kit, []byte("verify-release-index")) ||
		!bytes.Contains(kit, []byte("rootKeyIncluded=false")) ||
		!bytes.Contains(kit, []byte("offlineTrustPolicySidecarsIncluded=false")) ||
		!bytes.Contains(kit, []byte("offlineTrustPolicyAuthorityTransitionSidecarsIncluded=false")) ||
		!bytes.Contains(kit, []byte("offlineTrustPolicyAuthorityTransitionChainSidecarsIncluded=false")) ||
		!bytes.Contains(kit, []byte("releaseIndexSidecarsIncluded=false")) ||
		!bytes.Contains(kit, []byte("authorityTransitionSidecarsIncluded=false")) ||
		!bytes.Contains(kit, []byte("signed-offline-policy-v2-explicit-root-authority-transition-chain-v1")) ||
		!bytes.Contains(kit, []byte("release-index-explicit-root-authority-transition-chain-v1")) {
		t.Fatal("portable kit did not declare the Alpha.33 trust boundary")
	}
}

func TestValidateAcceptsBinaryWhoseFinalDataBlockIsZero(t *testing.T) {
	binary := append([]byte("non-zero-first-block"), make([]byte, 1024-len("non-zero-first-block"))...)
	kit, err := Build(Target{OS: "linux", Arch: "amd64"}, ProductVersion, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(kit, Target{OS: "linux", Arch: "amd64"}, ProductVersion); err != nil {
		t.Fatalf("canonical kit with zero final binary block rejected: %v", err)
	}
}
