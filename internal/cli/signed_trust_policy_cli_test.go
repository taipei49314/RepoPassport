package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
)

func TestSignedTrustPolicyFlagsAreExactAndMutuallyExclusive(t *testing.T) {
	valid := []string{
		"--trust-policy-envelope=policy.dsse",
		"--trust-policy-authority-key", "authority.pem",
		"--minimum-trust-policy-generation", "42",
	}
	options, err := validateSignedTrustPolicyArgs(valid)
	if err != nil || !options.Enabled || options.MinimumGeneration != 42 {
		t.Fatalf("valid signed policy flags = %#v, %v", options, err)
	}
	for name, args := range map[string][]string{
		"missing authority":       {"--trust-policy-envelope", "a", "--minimum-trust-policy-generation", "1"},
		"duplicate envelope":      {"--trust-policy-envelope", "a", "--trust-policy-envelope", "b", "--trust-policy-authority-key", "k", "--minimum-trust-policy-generation", "1"},
		"legacy policy conflict":  {"--trust-policy-envelope", "a", "--trust-policy-authority-key", "k", "--minimum-trust-policy-generation", "1", "--trust-policy", "legacy", "--expect-trust-policy-digest", "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		"trust key conflict":      {"--trust-policy-envelope", "a", "--trust-policy-authority-key", "k", "--minimum-trust-policy-generation", "1", "--trust-key", "key"},
		"near prefix":             {"--trust-policy-envelope-file", "a", "--trust-policy-authority-key", "k", "--minimum-trust-policy-generation", "1"},
		"noncanonical generation": {"--trust-policy-envelope", "a", "--trust-policy-authority-key", "k", "--minimum-trust-policy-generation", "01"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSignedTrustPolicyArgs(args); err == nil {
				t.Fatal("expected strict signed-policy flag rejection")
			}
		})
	}
}

func TestSignedTrustPolicyStrictFlagSpellingsBeforeBundleIO(t *testing.T) {
	missingBundle := filepath.Join(t.TempDir(), "must-not-be-read.tar")
	triple := []string{
		"--trust-policy-envelope", "policy.dsse",
		"--trust-policy-authority-key", "authority.pem",
		"--minimum-trust-policy-generation", "1",
	}
	invalid := map[string][]string{
		"single dash trust key":     append(append([]string{}, triple...), "-trust-key", "key.pem"),
		"single dash policy":        append(append([]string{}, triple...), "-trust-policy", "policy.json", "--expect-trust-policy-digest", "sha256:"+strings.Repeat("1", 64)),
		"single dash triple":        {"-trust-policy-envelope", "policy.dsse", "-trust-policy-authority-key", "authority.pem", "-minimum-trust-policy-generation", "1"},
		"multiple dash trust key":   append(append([]string{}, triple...), "---trust-key", "key.pem"),
		"case alias":                append(append([]string{}, triple...), "--Trust-key", "key.pem"),
		"near prefix authority key": append(append([]string{}, triple...), "--trust-policy-authority-key-file", "authority.pem"),
	}
	for name, flags := range invalid {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--json", "verify-attestation", missingBundle}, flags...)
			envelope, _, _, exitCode := runAttestationCLI(t, args...)
			if exitCode != 2 || envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("exit=%d envelope=%#v", exitCode, envelope)
			}
		})
	}

	for name, flags := range map[string][]string{
		"equals dash leading paths":    {"--trust-policy-envelope=-policy.dsse", "--trust-policy-authority-key=-authority.pem", "--minimum-trust-policy-generation=1"},
		"separated dash leading paths": {"--trust-policy-envelope", "-policy.dsse", "--trust-policy-authority-key", "-authority.pem", "--minimum-trust-policy-generation", "1"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--json", "verify-attestation", missingBundle}, flags...)
			_, _, _, exitCode := runAttestationCLI(t, args...)
			if exitCode != 7 {
				t.Fatalf("dash-leading path flag shape exit=%d, want bundle I/O failure", exitCode)
			}
		})
	}
}

func TestPersistTrustPolicyStateFlagsAreExactBeforeBundleIO(t *testing.T) {
	missingBundle := filepath.Join(t.TempDir(), "must-not-be-read.tar")
	triple := []string{
		"--trust-policy-envelope", "policy.dsse",
		"--trust-policy-authority-key", "authority.pem",
		"--minimum-trust-policy-generation", "1",
	}
	valid, err := validatePersistTrustPolicyStateArgs(append(append([]string{}, triple...), "--persist-trust-policy-state"), true)
	if err != nil || !valid.Enabled {
		t.Fatalf("valid persistent state flag = %#v, %v", valid, err)
	}
	for name, flags := range map[string][]string{
		"without signed policy": {"--persist-trust-policy-state"},
		"duplicate":             append(append([]string{}, triple...), "--persist-trust-policy-state", "--persist-trust-policy-state"),
		"equals true":           append(append([]string{}, triple...), "--persist-trust-policy-state=true"),
		"single dash":           append(append([]string{}, triple...), "-persist-trust-policy-state"),
		"multiple dash":         append(append([]string{}, triple...), "---persist-trust-policy-state"),
		"case alias":            append(append([]string{}, triple...), "--Persist-trust-policy-state"),
		"near prefix":           append(append([]string{}, triple...), "--persist-trust-policy-state-file"),
		"v1 mixed":              {"--trust-policy", "legacy.json", "--expect-trust-policy-digest", "sha256:" + strings.Repeat("1", 64), "--persist-trust-policy-state"},
		"partial signed":        {"--trust-policy-envelope", "policy.dsse", "--persist-trust-policy-state"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--json", "verify-attestation", missingBundle}, flags...)
			envelope, _, _, exitCode := runAttestationCLI(t, args...)
			if exitCode != 2 || envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("exit=%d envelope=%#v", exitCode, envelope)
			}
		})
	}

	// A separated value remains a second positional argument and is rejected
	// before the missing bundle is opened.
	envelope, _, _, exitCode := runAttestationCLI(t, append(
		[]string{"--json", "verify-attestation", missingBundle},
		append(triple, "--persist-trust-policy-state", "true")...,
	)...)
	if exitCode != 2 || envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("separated boolean value exit=%d envelope=%#v", exitCode, envelope)
	}

	envelope, _, _, exitCode = runAttestationCLI(t,
		"--json", "verify-attestation", missingBundle, "--", "--persist-trust-policy-state",
	)
	if exitCode != 2 || envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
		t.Fatalf("post-double-dash state flag exit=%d envelope=%#v", exitCode, envelope)
	}
}

type cliSignedTrustPolicy struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	Generation     uint64                     `json:"generation"`
	KeyAlgorithm   string                     `json:"keyAlgorithm"`
	KeyIDAlgorithm string                     `json:"keyIdAlgorithm"`
	Keys           []cliOfflineTrustPolicyKey `json:"keys"`
}

type cliSignedTrustEnvelope struct {
	PayloadType string               `json:"payloadType"`
	Payload     string               `json:"payload"`
	Signatures  []cliSignedSignature `json:"signatures"`
}

type cliSignedSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

func TestSignedTrustPolicyCLIEndToEndDecisionsAndMetadata(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	authorityPrivate, _, authorityPEM := writeCLIKeyPair(t, root, "authority")
	authorityPath := filepath.Join(root, "authority-public.pem")
	block, rest := pem.Decode(authorityPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("test authority PEM is not canonical")
	}
	authorityID := cliSHA256Digest(block.Bytes)
	policy := func(name string, generation uint64, statuses map[string]string, private ed25519.PrivateKey, keyID string) string {
		return writeCLISignedTrustPolicy(t, root, name, generation, statuses, private, keyID)
	}
	run := func(bundle, envelope string, minimum uint64) (attestation.VerificationReport, testEnvelope, int) {
		envelopeResponse, _, stderr, exitCode := runAttestationCLI(t,
			"--json", "verify-attestation", bundle,
			"--trust-policy-envelope", envelope,
			"--trust-policy-authority-key", authorityPath,
			"--minimum-trust-policy-generation", strconv.FormatUint(minimum, 10),
		)
		if stderr != "" {
			t.Fatalf("unexpected stderr: %s", stderr)
		}
		var report attestation.VerificationReport
		decodeJSON(t, envelopeResponse.Data, &report)
		return report, envelopeResponse, exitCode
	}

	acceptedPath := policy("accepted.dsse", 7, map[string]string{fixture.KeyIDA: "trusted"}, authorityPrivate, authorityID)
	accepted, acceptedEnvelope, exitCode := run(fixture.BundleA, acceptedPath, 7)
	if exitCode != 0 || acceptedEnvelope.Error != nil || accepted.TrustDecision != "accepted" || accepted.TrustReason != "trusted" ||
		accepted.TrustPolicySignatureValidity != "valid" || accepted.TrustPolicyDigest == "" || accepted.TrustPolicyEnvelopeDigest == "" ||
		accepted.TrustPolicyAuthorityKeyID != authorityID || accepted.TrustPolicyGeneration != 7 || accepted.MinimumTrustPolicyGeneration != 7 {
		t.Fatalf("accepted signed policy exit=%d report=%#v envelope=%#v", exitCode, accepted, acceptedEnvelope)
	}
	var acceptedRaw map[string]any
	decodeJSON(t, acceptedEnvelope.Data, &acceptedRaw)
	for _, key := range []string{"trustPolicyStateEvaluation", "trustPolicyStateGeneration"} {
		if _, present := acceptedRaw[key]; present {
			t.Fatalf("stateless signed policy unexpectedly contains %s: %#v", key, acceptedRaw)
		}
	}

	for _, test := range []struct {
		name     string
		statuses map[string]string
		gen      uint64
		minimum  uint64
		reason   string
	}{
		{"revoked", map[string]string{fixture.KeyIDA: "revoked"}, 7, 7, "revoked"},
		{"not listed", map[string]string{fixture.KeyIDB: "trusted"}, 7, 7, "not-listed"},
		{"below floor", map[string]string{fixture.KeyIDA: "trusted"}, 6, 7, "generation-below-minimum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := policy(test.name+".dsse", test.gen, test.statuses, authorityPrivate, authorityID)
			report, response, code := run(fixture.BundleA, path, test.minimum)
			if code != 7 || response.Error == nil || response.Error.Code != domain.CodeAttestationUntrusted ||
				report.TrustDecision != "rejected" || report.TrustReason != test.reason || report.TrustPolicySignatureValidity != "valid" ||
				report.TrustPolicyEnvelopeDigest == "" || report.TrustPolicyAuthorityKeyID != authorityID {
				t.Fatalf("%s exit=%d report=%#v response=%#v", test.name, code, report, response)
			}
		})
	}

	wrongPrivate, _, _ := writeCLIKeyPair(t, root, "wrong-authority")
	mismatchPath := policy("mismatch.dsse", 7, map[string]string{fixture.KeyIDA: "trusted"}, wrongPrivate, authorityID)
	mismatch, mismatchEnvelope, code := run(fixture.BundleA, mismatchPath, 7)
	if code != 7 || mismatchEnvelope.Error == nil || mismatch.TrustReason != "invalid-or-unavailable" || mismatch.MinimumTrustPolicyGeneration != 7 ||
		mismatch.TrustPolicyDigest != "" || mismatch.TrustPolicyEnvelopeDigest != "" || mismatch.TrustPolicyAuthorityKeyID != "" ||
		mismatch.TrustPolicyGeneration != 0 || mismatch.TrustPolicySignatureValidity != "" {
		t.Fatalf("authority mismatch exit=%d report=%#v response=%#v", code, mismatch, mismatchEnvelope)
	}
}

func TestSignedTrustPolicyLegacyOmission(t *testing.T) {
	fixture := newCLITrustFixture(t)
	policyPath, policyDigest := writeCLIOfflineTrustPolicy(t, t.TempDir(), "legacy-policy.json", map[string]string{
		fixture.KeyIDA: "trusted",
	})
	modes := []struct {
		name     string
		args     []string
		wantExit int
	}{
		{name: "no trust", args: []string{"--json", "verify-attestation", fixture.BundleA}, wantExit: 7},
		{name: "trust key", args: []string{"--json", "verify-attestation", fixture.BundleA, "--trust-key", fixture.PublicA}, wantExit: 0},
		{name: "digest pinned v1 policy", args: []string{
			"--json", "verify-attestation", fixture.BundleA,
			"--trust-policy", policyPath,
			"--expect-trust-policy-digest", policyDigest,
		}, wantExit: 0},
	}

	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			envelope, _, stderr, exitCode := runAttestationCLI(t, mode.args...)
			if exitCode != mode.wantExit || stderr != "" {
				t.Fatalf("exit=%d want=%d stderr=%q envelope=%#v", exitCode, mode.wantExit, stderr, envelope)
			}
			var report map[string]any
			decodeJSON(t, envelope.Data, &report)
			for _, key := range []string{
				"trustPolicyEnvelopeDigest",
				"trustPolicyAuthorityKeyId",
				"trustPolicyGeneration",
				"minimumTrustPolicyGeneration",
				"trustPolicySignatureValidity",
				"trustPolicyStateEvaluation",
				"trustPolicyStateGeneration",
			} {
				if _, present := report[key]; present {
					t.Fatalf("legacy mode unexpectedly contains signed-policy field %s: %#v", key, report)
				}
			}
		})
	}
}

func TestPersistentSignedTrustPolicyStateBootstrapIdempotentHigherGenerationRevokedAndNotListedAdvanceThenRollbackAndEquivocation(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	dataRoot := filepath.Join(root, "controller-data")
	authorityPrivate, _, authorityPEM := writeCLIKeyPair(t, root, "authority")
	authorityPath := filepath.Join(root, "authority-public.pem")
	block, rest := pem.Decode(authorityPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("test authority PEM is not canonical")
	}
	authorityID := cliSHA256Digest(block.Bytes)
	policy := func(name string, generation uint64, statuses map[string]string) string {
		return writeCLISignedTrustPolicy(t, root, name, generation, statuses, authorityPrivate, authorityID)
	}
	run := func(envelope string, minimum uint64) (attestation.VerificationReport, testEnvelope, int) {
		response, _, stderr, code := runAttestationCLI(t,
			"--json", "--data-dir", dataRoot, "verify-attestation", fixture.BundleA,
			"--trust-policy-envelope", envelope,
			"--trust-policy-authority-key", authorityPath,
			"--minimum-trust-policy-generation", strconv.FormatUint(minimum, 10),
			"--persist-trust-policy-state",
		)
		if stderr != "" {
			t.Fatalf("unexpected stderr: %s", stderr)
		}
		var report attestation.VerificationReport
		decodeJSON(t, response.Data, &report)
		return report, response, code
	}

	trusted7 := policy("trusted-7.dsse", 7, map[string]string{fixture.KeyIDA: "trusted"})
	report, response, code := run(trusted7, 7)
	if code != 0 || response.Error != nil || report.TrustPolicyStateEvaluation != "initialized" || report.TrustPolicyStateGeneration != 7 || report.TrustDecision != "accepted" {
		t.Fatalf("initial state exit=%d report=%#v response=%#v", code, report, response)
	}

	report, response, code = run(trusted7, 7)
	if code != 0 || response.Error != nil || report.TrustPolicyStateEvaluation != "matched" || report.TrustPolicyStateGeneration != 7 {
		t.Fatalf("matched state exit=%d report=%#v response=%#v", code, report, response)
	}

	revoked8 := policy("revoked-8.dsse", 8, map[string]string{fixture.KeyIDA: "revoked"})
	report, response, code = run(revoked8, 7)
	if code != 7 || response.Error == nil || report.TrustReason != "revoked" || report.TrustPolicyStateEvaluation != "advanced" || report.TrustPolicyStateGeneration != 8 {
		t.Fatalf("revoked policy must still advance state: exit=%d report=%#v response=%#v", code, report, response)
	}

	notListed9 := policy("not-listed-9.dsse", 9, map[string]string{fixture.KeyIDB: "trusted"})
	report, response, code = run(notListed9, 7)
	if code != 7 || response.Error == nil || report.TrustReason != "not-listed" || report.TrustPolicyStateEvaluation != "advanced" || report.TrustPolicyStateGeneration != 9 {
		t.Fatalf("not-listed policy must still advance state: exit=%d report=%#v response=%#v", code, report, response)
	}

	report, response, code = run(trusted7, 7)
	if code != 7 || response.Error == nil || report.TrustReason != "state-generation-rollback" || report.TrustPolicyStateEvaluation != "rollback-rejected" || report.TrustPolicyStateGeneration != 9 {
		t.Fatalf("rollback exit=%d report=%#v response=%#v", code, report, response)
	}

	trusted9 := policy("trusted-9.dsse", 9, map[string]string{fixture.KeyIDA: "trusted"})
	report, response, code = run(trusted9, 7)
	if code != 7 || response.Error == nil || report.TrustReason != "state-generation-equivocation" || report.TrustPolicyStateEvaluation != "equivocation-rejected" || report.TrustPolicyStateGeneration != 9 {
		t.Fatalf("equivocation exit=%d report=%#v response=%#v", code, report, response)
	}
}

func TestPersistentSignedTrustPolicyBelowFloorDoesNotCreateState(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	dataRoot := filepath.Join(root, "must-not-exist")
	authorityPrivate, _, authorityPEM := writeCLIKeyPair(t, root, "authority")
	authorityPath := filepath.Join(root, "authority-public.pem")
	block, _ := pem.Decode(authorityPEM)
	if block == nil {
		t.Fatal("test authority PEM is not canonical")
	}
	policy := writeCLISignedTrustPolicy(t, root, "below-floor.dsse", 6, map[string]string{fixture.KeyIDA: "trusted"}, authorityPrivate, cliSHA256Digest(block.Bytes))
	response, _, _, code := runAttestationCLI(t,
		"--json", "--data-dir", dataRoot, "verify-attestation", fixture.BundleA,
		"--trust-policy-envelope", policy,
		"--trust-policy-authority-key", authorityPath,
		"--minimum-trust-policy-generation", "7",
		"--persist-trust-policy-state",
	)
	if code != 7 || response.Error == nil {
		t.Fatalf("below floor exit=%d response=%#v", code, response)
	}
	var report attestation.VerificationReport
	decodeJSON(t, response.Data, &report)
	if report.TrustReason != "generation-below-minimum" || report.TrustPolicyStateEvaluation != "" || report.TrustPolicyStateGeneration != 0 {
		t.Fatalf("below floor report=%#v", report)
	}
	if _, err := os.Stat(dataRoot); !os.IsNotExist(err) {
		t.Fatalf("below-floor policy touched state root: %v", err)
	}
}

func TestPersistentSignedTrustPolicyInvalidEvidenceOrAuthorityDoesNotCreateState(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	invalidBundle := filepath.Join(root, "invalid.tar")
	if err := os.WriteFile(invalidBundle, []byte("not a canonical bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"invalid bundle": {
			"--json", "--data-dir", filepath.Join(root, "invalid-bundle-state"), "verify-attestation", invalidBundle,
			"--trust-policy-envelope", filepath.Join(root, "missing.dsse"),
			"--trust-policy-authority-key", filepath.Join(root, "missing.pem"),
			"--minimum-trust-policy-generation", "1", "--persist-trust-policy-state",
		},
		"unavailable authority": {
			"--json", "--data-dir", filepath.Join(root, "invalid-authority-state"), "verify-attestation", fixture.BundleA,
			"--trust-policy-envelope", filepath.Join(root, "missing.dsse"),
			"--trust-policy-authority-key", filepath.Join(root, "missing.pem"),
			"--minimum-trust-policy-generation", "1", "--persist-trust-policy-state",
		},
	} {
		t.Run(name, func(t *testing.T) {
			response, _, _, code := runAttestationCLI(t, args...)
			if code != 7 || response.Error == nil {
				t.Fatalf("exit=%d response=%#v", code, response)
			}
			dataRoot := args[2]
			if _, err := os.Stat(dataRoot); !os.IsNotExist(err) {
				t.Fatalf("rejected input touched persistent state root: %v", err)
			}
		})
	}
}

func TestPersistentSignedTrustPolicyRejectedAuthenticatedEnvelopeDoesNotCreateState(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	authorityPrivate, _, authorityPEM := writeCLIKeyPair(t, root, "authority")
	authorityPath := filepath.Join(root, "authority-public.pem")
	block, rest := pem.Decode(authorityPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("test authority PEM is not canonical")
	}
	authorityID := cliSHA256Digest(block.Bytes)
	valid := writeCLISignedTrustPolicy(t, root, "valid.dsse", 7, map[string]string{fixture.KeyIDA: "trusted"}, authorityPrivate, authorityID)
	validRaw, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	var invalidSignature cliSignedTrustEnvelope
	if err := json.Unmarshal(validRaw, &invalidSignature); err != nil {
		t.Fatal(err)
	}
	invalidSignature.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	badSignatureRaw, err := canonicaljson.Marshal(invalidSignature)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := filepath.Join(root, "bad-signature.dsse")
	if err := os.WriteFile(badSignature, badSignatureRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	invalidPayload, err := canonicaljson.Marshal(cliSignedTrustPolicy{
		SchemaVersion: "2", Generation: 7, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256",
		Keys: []cliOfflineTrustPolicyKey{},
	})
	if err != nil {
		t.Fatal(err)
	}
	badCanonicalPayload := writeCLISignedTrustEnvelope(t, root, "bad-canonical-payload.dsse", invalidPayload, authorityPrivate, authorityID)

	for name, envelopePath := range map[string]string{
		"bad signature":         badSignature,
		"bad canonical payload": badCanonicalPayload,
	} {
		t.Run(name, func(t *testing.T) {
			dataRoot := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+"-state")
			response, _, _, code := runAttestationCLI(t,
				"--json", "--data-dir", dataRoot, "verify-attestation", fixture.BundleA,
				"--trust-policy-envelope", envelopePath,
				"--trust-policy-authority-key", authorityPath,
				"--minimum-trust-policy-generation", "7",
				"--persist-trust-policy-state",
			)
			if code != 7 || response.Error == nil || response.Error.Code != domain.CodeAttestationUntrusted {
				t.Fatalf("exit=%d response=%#v", code, response)
			}
			if _, err := os.Stat(dataRoot); !os.IsNotExist(err) {
				t.Fatalf("rejected authenticated envelope touched persistent state root: %v", err)
			}
		})
	}
}

func TestPersistentSignedTrustPolicyStateFailuresAreRedactedAndCorruptionIsNotRepaired(t *testing.T) {
	fixture := newCLITrustFixture(t)
	root := t.TempDir()
	dataRoot := filepath.Join(root, "controller-data")
	authorityPrivate, _, authorityPEM := writeCLIKeyPair(t, root, "authority")
	authorityPath := filepath.Join(root, "authority-public.pem")
	block, rest := pem.Decode(authorityPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("test authority PEM is not canonical")
	}
	authorityID := cliSHA256Digest(block.Bytes)
	policy := func(name string, generation uint64, statuses map[string]string) string {
		return writeCLISignedTrustPolicy(t, root, name, generation, statuses, authorityPrivate, authorityID)
	}
	run := func(envelope string, extra ...string) (testEnvelope, string, string, int) {
		args := []string{
			"--json", "--data-dir", dataRoot, "verify-attestation", fixture.BundleA,
			"--trust-policy-envelope", envelope,
			"--trust-policy-authority-key", authorityPath,
			"--minimum-trust-policy-generation", "7",
			"--persist-trust-policy-state",
		}
		args = append(args, extra...)
		return runAttestationCLI(t, args...)
	}

	trusted8 := policy("trusted-8.dsse", 8, map[string]string{fixture.KeyIDA: "trusted"})
	response, _, stderr, code := run(trusted8)
	if code != 0 || response.Error != nil || stderr != "" {
		t.Fatalf("initial state exit=%d response=%#v stderr=%q", code, response, stderr)
	}
	var initialized attestation.VerificationReport
	decodeJSON(t, response.Data, &initialized)
	storedDigest := initialized.TrustPolicyDigest
	if storedDigest == "" {
		t.Fatalf("initialized state lacks policy digest: %#v", initialized)
	}

	stateFile := filepath.Join(dataRoot, "trust-policy-state", "v1", strings.TrimPrefix(authorityID, "sha256:")+".json")
	assertRedacted := func(t *testing.T, response testEnvelope, stdout, stderr, forbiddenStoredDigest string) {
		t.Helper()
		if response.Error == nil || response.Error.Code != domain.CodeAttestationUntrusted {
			t.Fatalf("expected redacted state rejection: %#v", response)
		}
		output := strings.ToLower(stdout + stderr)
		forbiddenValues := []string{
			strings.ToLower(dataRoot), strings.ToLower(stateFile), strings.ToLower(filepath.Base(stateFile)),
			".lock", "lock file", "lock timeout", "lock owner",
			"parser", "permission denied", "errno", "windows", "linux",
		}
		if forbiddenStoredDigest != "" {
			forbiddenValues = append(forbiddenValues, strings.ToLower(forbiddenStoredDigest))
		}
		for _, forbidden := range forbiddenValues {
			if strings.Contains(output, forbidden) {
				t.Fatalf("state rejection leaks %q: %s", forbidden, stdout+stderr)
			}
		}
	}

	rollback := policy("rollback-7.dsse", 7, map[string]string{fixture.KeyIDA: "trusted"})
	response, stdout, stderr, code := run(rollback)
	if code != 7 {
		t.Fatalf("rollback exit=%d response=%#v", code, response)
	}
	var rollbackReport attestation.VerificationReport
	decodeJSON(t, response.Data, &rollbackReport)
	if rollbackReport.TrustReason != "state-generation-rollback" {
		t.Fatalf("rollback report=%#v", rollbackReport)
	}
	assertRedacted(t, response, stdout, stderr, storedDigest)

	equivocation := policy("equivocation-8.dsse", 8, map[string]string{fixture.KeyIDA: "trusted", fixture.KeyIDB: "trusted"})
	response, stdout, stderr, code = run(equivocation)
	if code != 7 {
		t.Fatalf("equivocation exit=%d response=%#v", code, response)
	}
	var equivocationReport attestation.VerificationReport
	decodeJSON(t, response.Data, &equivocationReport)
	if equivocationReport.TrustReason != "state-generation-equivocation" {
		t.Fatalf("equivocation report=%#v", equivocationReport)
	}
	assertRedacted(t, response, stdout, stderr, storedDigest)

	corrupt := []byte(`{"schemaVersion":"1","generation":8}`)
	if err := os.WriteFile(stateFile, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	probes := 0
	var corruptStdout bytes.Buffer
	var corruptStderr bytes.Buffer
	app := App{
		Deps: Dependencies{
			FreshnessSnapshot: func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error) {
				probes++
				return domain.SourceSnapshot{}, nil
			},
		},
		Stdin: strings.NewReader(""), Stdout: &corruptStdout, Stderr: &corruptStderr,
	}
	code = app.Run(context.Background(), []string{
		"--json", "--data-dir", dataRoot, "verify-attestation", fixture.BundleA,
		"--trust-policy-envelope", trusted8,
		"--trust-policy-authority-key", authorityPath,
		"--minimum-trust-policy-generation", "7",
		"--persist-trust-policy-state",
		"--expect-bundle-digest", cliSHA256Digest(fixture.BundleABytes),
		"--current-manifest", fixture.CurrentSource,
	})
	corruptResponse := decodeEnvelope(t, corruptStdout.Bytes())
	if code != 7 || probes != 0 {
		t.Fatalf("corrupt state exit=%d probes=%d stdout=%s stderr=%s", code, probes, corruptStdout.String(), corruptStderr.String())
	}
	// The candidate is the same authenticated policy that originally created
	// the now-corrupt record, so its report-level policy digest is expected.
	// Only a distinct stored digest would be private state metadata.
	assertRedacted(t, corruptResponse, corruptStdout.String(), corruptStderr.String(), "")
	after, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatalf("corrupt state was repaired or replaced: got %q want %q", after, corrupt)
	}
}

func writeCLISignedTrustPolicy(t *testing.T, directory, name string, generation uint64, statuses map[string]string, authority ed25519.PrivateKey, authorityID string) string {
	t.Helper()
	keys := make([]cliOfflineTrustPolicyKey, 0, len(statuses))
	for keyID, status := range statuses {
		keys = append(keys, cliOfflineTrustPolicyKey{KeyID: keyID, Status: status})
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	payload, err := canonicaljson.Marshal(cliSignedTrustPolicy{
		SchemaVersion: "2", Generation: generation, KeyAlgorithm: "ed25519", KeyIDAlgorithm: "spki-sha256", Keys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadType := attestation.SignedOfflineTrustPolicyPayloadType
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len([]byte(payloadType)), payloadType, len(payload), payload))
	raw, err := canonicaljson.Marshal(cliSignedTrustEnvelope{
		PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []cliSignedSignature{{KeyID: authorityID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(authority, pae))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLISignedTrustEnvelope(t *testing.T, directory, name string, payload []byte, authority ed25519.PrivateKey, authorityID string) string {
	t.Helper()
	payloadType := attestation.SignedOfflineTrustPolicyPayloadType
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len([]byte(payloadType)), payloadType, len(payload), payload))
	raw, err := canonicaljson.Marshal(cliSignedTrustEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []cliSignedSignature{{KeyID: authorityID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(authority, pae))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
