// Package releasekit builds and validates the self-contained Alpha.33
// portable verifier kit. It deliberately carries no attestation, policy,
// release-index, authority-transition, or authority-transition-chain sidecar,
// or trust key: explicit caller trust inputs remain required.
package releasekit

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ProductVersion = "0.1.0-alpha.33"
	SchemaVersion  = "1"
	// MaxBinaryBytes bounds an untrusted verifier input before any package
	// materializes it in memory more than once during canonical validation.
	// The 32 MiB ceiling bounds aggregate builder memory while remaining well
	// above the supported verifier binaries.
	MaxBinaryBytes int64 = 32 << 20
	maxBinaryBytes       = MaxBinaryBytes
	maxTextBytes   int64 = 64 << 10
	maxKitBytes    int64 = maxBinaryBytes + (1 << 20)
)

var epoch = time.Unix(0, 0).UTC()

// Target is the exact Go release tuple represented by a kit.
type Target struct {
	OS   string
	Arch string
}

func (t Target) String() string { return t.OS + "/" + t.Arch }

func (t Target) binaryName() (string, error) {
	if t.Arch != "amd64" || (t.OS != "linux" && t.OS != "windows") {
		return "", errors.New("unsupported release-kit target")
	}
	if t.OS == "windows" {
		return "repopass-verify.exe", nil
	}
	return "repopass-verify", nil
}

func usage(target Target) string {
	return "RepoPassport portable offline verifier (" + target.String() + ")\n" +
		"Commands: help, version, verify-attestation, verify-release-index\n" +
		"Acceptance is relative to explicit caller-supplied trust roots and policies.\n"
}

func trustBoundary() string {
	return "embeddedKeyIsTrustAnchor=false\nformalClaim=false\ncapability=incomplete\noverall=inconclusive\nidentityAttestation=none\ntimeAttestation=none\nofflineTrustPolicySidecarsIncluded=false\nofflineTrustPolicyAuthorityTransitionSidecarsIncluded=false\nofflineTrustPolicyAuthorityTransitionChainSidecarsIncluded=false\nreleaseIndexSidecarsIncluded=false\nauthorityTransitionSidecarsIncluded=false\nevidenceIncluded=false\nprivateKeyIncluded=false\nrootKeyIncluded=false\n"
}

func manifest(target Target, version string, binary []byte) ([]byte, error) {
	name, err := target.binaryName()
	if err != nil || version != ProductVersion || len(binary) == 0 || int64(len(binary)) > maxBinaryBytes {
		return nil, errors.New("invalid release-kit manifest input")
	}
	digest := sha256.Sum256(binary)
	text := "{" +
		"\"artifactType\":\"repopass-portable-offline-verifier\"," +
		"\"binary\":{\"path\":" + strconv.Quote(name) + "," +
		"\"sha256\":" + strconv.Quote("sha256:"+hex.EncodeToString(digest[:])) + "," +
		fmt.Sprintf("\"size\":%d},", len(binary)) +
		"\"capabilities\":{\"commands\":[\"verify-attestation\",\"verify-release-index\"],\"bundleVersions\":[\"1\",\"2\"]," +
		"\"currentness\":\"optional-current-manifest\",\"historicalReplayRequiresWorktree\":false," +
		"\"networkRequired\":false,\"trustModes\":[\"explicit-spki\",\"offline-policy-v1\",\"signed-offline-policy-v2\",\"signed-offline-policy-v2-explicit-old-root-authority-transition-v1\",\"signed-offline-policy-v2-explicit-root-authority-transition-chain-v1\",\"release-index-explicit-root-policy\",\"release-index-explicit-old-root-authority-transition-v1\",\"release-index-explicit-root-authority-transition-chain-v1\"]}," +
		"\"productVersion\":" + strconv.Quote(version) + "," +
		"\"schemaVersion\":\"1\"," +
		"\"target\":{\"goarch\":\"amd64\",\"goos\":" + strconv.Quote(target.OS) + "}," +
		"\"trustBoundary\":{\"capability\":\"incomplete\",\"embeddedKeyIsTrustAnchor\":false,\"formalClaim\":false,\"identityAttestation\":\"none\",\"overall\":\"inconclusive\",\"timeAttestation\":\"none\"}}\n"
	return []byte(text), nil
}

// Build returns a canonical USTAR archive with the exact documented inventory.
func Build(target Target, version string, binary []byte) ([]byte, error) {
	kit, err := buildRaw(target, version, binary)
	if err != nil {
		return nil, err
	}
	if err := Validate(kit, target, version); err != nil {
		return nil, err
	}
	return kit, nil
}

func buildRaw(target Target, version string, binary []byte) ([]byte, error) {
	name, err := target.binaryName()
	if err != nil {
		return nil, err
	}
	manifestBytes, err := manifest(target, version, binary)
	if err != nil {
		return nil, err
	}
	files := []struct {
		name string
		data []byte
		mode int64
	}{
		{"PORTABLE_VERIFIER_MANIFEST.json", manifestBytes, 0o644},
		{"TRUST_BOUNDARY.txt", []byte(trustBoundary()), 0o644},
		{"USAGE.txt", []byte(usage(target)), 0o644},
		{name, binary, 0o755},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, file := range files {
		header := &tar.Header{
			Name: file.name, Mode: file.mode, Size: int64(len(file.data)), Typeflag: tar.TypeReg,
			Format: tar.FormatUSTAR, ModTime: epoch,
			Uid: 0, Gid: 0, Uname: "", Gname: "",
		}
		if err := w.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := w.Write(file.data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	kit := out.Bytes()
	return kit, nil
}

// Validate rejects a malformed or non-canonical release kit before accepting
// its manifest/binary binding.
func Validate(kit []byte, target Target, version string) error {
	name, err := target.binaryName()
	if err != nil || version != ProductVersion || len(kit) < 1536 || int64(len(kit)) > maxKitBytes || len(kit)%512 != 0 || !twoZeroBlocksOnly(kit) {
		return errors.New("invalid release-kit archive shape")
	}
	wantNames := []string{"PORTABLE_VERIFIER_MANIFEST.json", "TRUST_BOUNDARY.txt", "USAGE.txt", name}
	r := tar.NewReader(bytes.NewReader(kit))
	contents := make(map[string][]byte, len(wantNames))
	prior := ""
	memberIndex := 0
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("non-canonical release-kit member")
		}
		maxMemberBytes := maxTextBytes
		if h.Name == name {
			maxMemberBytes = maxBinaryBytes
		}
		if memberIndex >= len(wantNames) || h.Name != wantNames[memberIndex] ||
			h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg || h.Linkname != "" || h.Size < 1 || h.Size > maxMemberBytes ||
			h.PAXRecords != nil || h.Xattrs != nil || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" ||
			!h.ModTime.Equal(epoch) || h.Mode != modeFor(h.Name, name) || h.Name <= prior || !portableName(h.Name) {
			return errors.New("non-canonical release-kit member")
		}
		memberIndex++
		prior = h.Name
		if _, duplicate := contents[h.Name]; duplicate {
			return errors.New("duplicate release-kit member")
		}
		data, readErr := io.ReadAll(io.LimitReader(r, h.Size+1))
		if readErr != nil || int64(len(data)) != h.Size {
			return errors.New("truncated release-kit member")
		}
		contents[h.Name] = data
	}
	if len(contents) != len(wantNames) {
		return errors.New("release-kit inventory mismatch")
	}
	for _, member := range wantNames {
		if _, ok := contents[member]; !ok {
			return errors.New("release-kit member missing")
		}
	}
	wantManifest, err := manifest(target, version, contents[name])
	if err != nil || !bytes.Equal(contents["PORTABLE_VERIFIER_MANIFEST.json"], wantManifest) ||
		!bytes.Equal(contents["TRUST_BOUNDARY.txt"], []byte(trustBoundary())) ||
		!bytes.Equal(contents["USAGE.txt"], []byte(usage(target))) {
		return errors.New("release-kit content binding mismatch")
	}
	canonical, err := buildRaw(target, version, contents[name])
	if err != nil || !bytes.Equal(kit, canonical) {
		return errors.New("release-kit raw bytes are not canonical")
	}
	return nil
}

func modeFor(name, binary string) int64 {
	if name == binary {
		return 0o755
	}
	return 0o644
}

func portableName(name string) bool {
	return name != "" && len(name) <= 100 && !strings.ContainsAny(name, "\\/") &&
		!strings.Contains(name, "..") && name == strings.TrimSpace(name)
}

func twoZeroBlocksOnly(data []byte) bool {
	if len(data) < 1536 {
		return false
	}
	last := data[len(data)-1024:]
	for _, b := range last {
		if b != 0 {
			return false
		}
	}
	return true
}
