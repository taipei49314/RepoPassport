package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
)

type alpha32CLIRotationFixture struct {
	evidence cliTrustFixture
	dir      string

	rootPrivate ed25519.PrivateKey
	rootPath    string
	rootPEM     []byte
	rootID      string

	terminalPrivate ed25519.PrivateKey
	terminalPath    string
	terminalPEM     []byte
	terminalID      string

	otherRootPath     string
	otherTerminalPath string
}

func TestAlpha32AuthorityRotationCLICompleteFlagGroupFailsBeforeIO(t *testing.T) {
	root := t.TempDir()
	missingBundle := filepath.Join(root, "MUST-NOT-BE-READ-BUNDLE.tar")
	marker := filepath.Join(root, "MUST-NOT-BE-READ-TRUST-INPUT")
	dataRoot := filepath.Join(root, "MUST-NOT-BE-CREATED-STATE")
	signed := []string{
		"--trust-policy-envelope", marker,
		"--trust-policy-authority-key", marker,
		"--minimum-trust-policy-generation", "1",
	}
	rotation := []string{
		"--trust-policy-authority-transition", marker,
		"--trust-policy-authority-trust-root", marker,
		"--minimum-trust-policy-authority-generation", "1",
	}
	invalid := map[string][]string{
		"transition only": append(append([]string{}, signed...), rotation[:2]...),
		"root only":       append(append([]string{}, signed...), rotation[2:4]...),
		"floor only":      append(append([]string{}, signed...), rotation[4:]...),
		"duplicate transition": append(append(append([]string{}, signed...), rotation...),
			"--trust-policy-authority-transition", marker+"-again"),
		"empty root": append(append([]string{}, signed...),
			"--trust-policy-authority-transition", marker,
			"--trust-policy-authority-trust-root=",
			"--minimum-trust-policy-authority-generation", "1"),
		"noncanonical floor": append(append([]string{}, signed...),
			"--trust-policy-authority-transition", marker,
			"--trust-policy-authority-trust-root", marker,
			"--minimum-trust-policy-authority-generation", "01"),
		"legacy policy conflict": append(append(append([]string{}, signed...), rotation...),
			"--trust-policy", marker, "--expect-trust-policy-digest", "sha256:"+strings.Repeat("1", 64)),
		"trust key conflict": append(append(append([]string{}, signed...), rotation...), "--trust-key", marker),
		"chain flag": append(append(append([]string{}, signed...), rotation...),
			"--trust-policy-authority-transition-chain", marker),
		"post separator": append(append(append([]string{}, signed...), "--"), rotation...),
	}

	for name, flags := range invalid {
		t.Run(name, func(t *testing.T) {
			args := []string{"--json", "--data-dir", dataRoot, "verify-attestation", missingBundle}
			response, _, stderr, code := runAttestationCLI(t, append(args, flags...)...)
			if code != 2 || response.Error == nil || response.Error.Code != domain.CodeManifestInvalid || stderr != "" {
				t.Fatalf("pre-I/O flag rejection exit=%d response=%#v stderr=%q", code, response, stderr)
			}
			if _, err := os.Lstat(dataRoot); !os.IsNotExist(err) {
				t.Fatalf("flag rejection touched state root: %v", err)
			}
		})
	}

	t.Run("root and terminal canonicalize before transition probe", func(t *testing.T) {
		rootPrivate, _, rootPEM := writeCLIKeyPair(t, root, "input-order-root")
		terminalPrivate, _, terminalPEM := writeCLIKeyPair(t, root, "input-order-terminal")
		t.Cleanup(func() {
			clear(rootPrivate)
			clear(terminalPrivate)
		})
		sequence := make([]string, 0, 3)
		readers := rotatedSignedOfflineTrustPolicyReaders{
			readRoot: func(string) ([]byte, error) {
				sequence = append(sequence, "root")
				return rootPEM, nil
			},
			readTerminal: func(string) ([]byte, error) {
				sequence = append(sequence, "terminal")
				return terminalPEM, nil
			},
			readTransition: func(string) ([]byte, error) {
				sequence = append(sequence, "transition")
				return []byte("invalid transition"), nil
			},
			readPolicy: func(string) ([]byte, error) {
				t.Fatal("policy probed after invalid transition")
				return nil, nil
			},
		}
		_, _, err := (App{}).verifyWithRotatedSignedOfflineTrustPolicyReaders(
			context.Background(), globalOptions{}, nil, attestation.VerificationReport{},
			signedTrustPolicyCLIOptions{AuthorityKeyPath: "terminal", MinimumGeneration: 1},
			signedTrustPolicyAuthorityRotationCLIOptions{TransitionPath: "transition", TrustRootPath: "root", MinimumGeneration: 1},
			persistTrustPolicyStateCLIOptions{}, false, readers,
		)
		if err == nil || strings.Join(sequence, ",") != "root,terminal,transition" {
			t.Fatalf("distinct input order = %q, err=%v", sequence, err)
		}

		sequence = sequence[:0]
		readers.readTerminal = func(string) ([]byte, error) {
			sequence = append(sequence, "terminal")
			return rootPEM, nil
		}
		_, _, err = (App{}).verifyWithRotatedSignedOfflineTrustPolicyReaders(
			context.Background(), globalOptions{}, nil, attestation.VerificationReport{},
			signedTrustPolicyCLIOptions{AuthorityKeyPath: "terminal", MinimumGeneration: 1},
			signedTrustPolicyAuthorityRotationCLIOptions{TransitionPath: "transition", TrustRootPath: "root", MinimumGeneration: 1},
			persistTrustPolicyStateCLIOptions{}, false, readers,
		)
		if err == nil || strings.Join(sequence, ",") != "root,terminal" {
			t.Fatalf("same-key input order = %q, err=%v", sequence, err)
		}
	})
}

func TestAlpha32AuthorityRotationCLIEndToEndAndCryptographicRejections(t *testing.T) {
	fixture := newAlpha32CLIRotationFixture(t)
	transition7 := fixture.transition(t, "transition-7.dsse.json", 7, fixture.terminalPEM)
	trusted7 := fixture.policy(t, "trusted-7.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})

	accepted, acceptedEnvelope, acceptedCode := fixture.run(t, fixture.evidence.BundleA, trusted7, fixture.terminalPath, transition7, fixture.rootPath, 7, 7, "", false)
	if acceptedCode != 0 || acceptedEnvelope.Error != nil || accepted.TrustDecision != "accepted" || accepted.TrustReason != "trusted" ||
		accepted.TrustBasis != rotatedSignedOfflineTrustPolicyBasis || accepted.SignatureValidity != "valid" ||
		accepted.TrustPolicySignatureValidity != "valid" || accepted.TrustPolicyAuthorityKeyID != fixture.terminalID ||
		accepted.TrustPolicyGeneration != 7 || accepted.MinimumTrustPolicyGeneration != 7 ||
		accepted.TrustPolicyAuthorityTransitionDigest == "" || accepted.TrustPolicyAuthorityTransitionEnvelopeDigest == "" ||
		accepted.TrustPolicyAuthorityTrustRootKeyID != fixture.rootID || accepted.TrustPolicyAuthorityTransitionGeneration != 7 ||
		accepted.MinimumTrustPolicyAuthorityGeneration != 7 || accepted.TrustPolicyAuthorityStateEvaluation != "" {
		t.Fatalf("trusted rotation exit=%d report=%#v response=%#v", acceptedCode, accepted, acceptedEnvelope)
	}

	for _, test := range []struct {
		name     string
		statuses map[string]string
		reason   string
	}{
		{name: "revoked", statuses: map[string]string{fixture.evidence.KeyIDA: "revoked"}, reason: "revoked"},
		{name: "not listed", statuses: map[string]string{fixture.evidence.KeyIDB: "trusted"}, reason: "not-listed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := fixture.policy(t, strings.ReplaceAll(test.name, " ", "-")+".dsse.json", 7, test.statuses)
			report, response, code := fixture.run(t, fixture.evidence.BundleA, policy, fixture.terminalPath, transition7, fixture.rootPath, 7, 7, "", false)
			if code != 7 || response.Error == nil || response.Error.Code != domain.CodeAttestationUntrusted ||
				report.TrustDecision != "rejected" || report.TrustReason != test.reason ||
				report.TrustPolicyAuthorityTransitionGeneration != 7 || report.TrustPolicyAuthorityTrustRootKeyID != fixture.rootID {
				t.Fatalf("%s exit=%d report=%#v response=%#v", test.name, code, report, response)
			}
		})
	}

	policy6 := fixture.policy(t, "policy-below-floor.dsse.json", 6, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	tamperedTransition := alpha32TamperCLIEnvelopeSignature(t, transition7, filepath.Join(fixture.dir, "tampered-transition.dsse.json"))
	tamperedPolicy := alpha32TamperCLIEnvelopeSignature(t, trusted7, filepath.Join(fixture.dir, "tampered-policy.dsse.json"))
	rootRolePolicy := fixture.policy(t, "root-role-conflict.dsse.json", 7, map[string]string{
		fixture.evidence.KeyIDA: "trusted",
		fixture.rootID:          "trusted",
	})

	for _, test := range []struct {
		name           string
		policy         string
		terminal       string
		transition     string
		root           string
		policyFloor    uint64
		authorityFloor uint64
		wantReason     string
	}{
		{name: "wrong root", policy: trusted7, terminal: fixture.terminalPath, transition: transition7, root: fixture.otherRootPath, policyFloor: 7, authorityFloor: 7, wantReason: "invalid-or-unavailable"},
		{name: "wrong terminal", policy: trusted7, terminal: fixture.otherTerminalPath, transition: transition7, root: fixture.rootPath, policyFloor: 7, authorityFloor: 7, wantReason: "invalid-or-unavailable"},
		{name: "transition tamper", policy: trusted7, terminal: fixture.terminalPath, transition: tamperedTransition, root: fixture.rootPath, policyFloor: 7, authorityFloor: 7, wantReason: "invalid-or-unavailable"},
		{name: "policy tamper", policy: tamperedPolicy, terminal: fixture.terminalPath, transition: transition7, root: fixture.rootPath, policyFloor: 7, authorityFloor: 7, wantReason: "invalid-or-unavailable"},
		{name: "authority floor", policy: trusted7, terminal: fixture.terminalPath, transition: transition7, root: fixture.rootPath, policyFloor: 7, authorityFloor: 8, wantReason: "invalid-or-unavailable"},
		{name: "policy floor", policy: policy6, terminal: fixture.terminalPath, transition: transition7, root: fixture.rootPath, policyFloor: 7, authorityFloor: 7, wantReason: "generation-below-minimum"},
		{name: "cross protocol", policy: trusted7, terminal: fixture.terminalPath, transition: trusted7, root: fixture.rootPath, policyFloor: 7, authorityFloor: 7, wantReason: "invalid-or-unavailable"},
		{name: "root role", policy: rootRolePolicy, terminal: fixture.terminalPath, transition: transition7, root: fixture.rootPath, policyFloor: 7, authorityFloor: 7, wantReason: "authority-role-conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, response, code := fixture.run(t, fixture.evidence.BundleA, test.policy, test.terminal, test.transition, test.root, test.policyFloor, test.authorityFloor, "", false)
			if code != 7 || response.Error == nil || response.Error.Code != domain.CodeAttestationUntrusted ||
				report.TrustDecision != "rejected" || report.TrustReason != test.wantReason || report.TrustBasis != rotatedSignedOfflineTrustPolicyBasis {
				t.Fatalf("%s exit=%d report=%#v response=%#v", test.name, code, report, response)
			}
		})
	}
}

func TestAlpha32AuthorityRotationCLICombinedStateLifecycleAndNegativeCases(t *testing.T) {
	fixture := newAlpha32CLIRotationFixture(t)
	dataRoot := filepath.Join(t.TempDir(), "controller-data")
	transition7 := fixture.transition(t, "state-transition-7.dsse.json", 7, fixture.terminalPEM)
	transition8 := fixture.transition(t, "state-transition-8.dsse.json", 8, fixture.terminalPEM)
	policy7 := fixture.policy(t, "state-policy-7.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	policy8 := fixture.policy(t, "state-policy-8.dsse.json", 8, map[string]string{fixture.evidence.KeyIDA: "trusted"})

	run := func(transition, policy, terminal string) (attestation.VerificationReport, testEnvelope, int) {
		return fixture.run(t, fixture.evidence.BundleA, policy, terminal, transition, fixture.rootPath, 1, 1, dataRoot, true)
	}
	assertState := func(stage string, report attestation.VerificationReport, response testEnvelope, code int, wantCode int, evaluation string, transitionGeneration, policyGeneration uint64, reason string) {
		t.Helper()
		if code != wantCode || (wantCode == 0 && response.Error != nil) || (wantCode != 0 && (response.Error == nil || response.Error.Code != domain.CodeAttestationUntrusted)) ||
			report.TrustPolicyAuthorityStateEvaluation != evaluation ||
			report.TrustPolicyAuthorityStateTransitionGeneration != transitionGeneration ||
			report.TrustPolicyAuthorityStatePolicyGeneration != policyGeneration ||
			(reason != "" && report.TrustReason != reason) {
			t.Fatalf("%s exit=%d report=%#v response=%#v", stage, code, report, response)
		}
	}

	report, response, code := run(transition7, policy7, fixture.terminalPath)
	assertState("initialized", report, response, code, 0, "initialized", 7, 7, "trusted")
	report, response, code = run(transition7, policy7, fixture.terminalPath)
	assertState("matched", report, response, code, 0, "matched", 7, 7, "trusted")
	report, response, code = run(transition8, policy8, fixture.terminalPath)
	assertState("advanced", report, response, code, 0, "advanced", 8, 8, "trusted")

	report, response, code = run(transition7, policy8, fixture.terminalPath)
	assertState("transition rollback", report, response, code, 7, "rollback-rejected", 8, 8, "state-generation-rollback")
	report, response, code = run(transition8, policy7, fixture.terminalPath)
	assertState("policy rollback", report, response, code, 7, "rollback-rejected", 8, 8, "state-generation-rollback")

	otherTerminalPrivate, _, otherTerminalPEM := writeCLIKeyPair(t, fixture.dir, "state-other-terminal")
	t.Cleanup(func() { clear(otherTerminalPrivate) })
	otherTerminalPath := filepath.Join(fixture.dir, "state-other-terminal-public.pem")
	otherTerminalID := alpha32CLIKeyID(t, otherTerminalPEM)
	authorityFork := fixture.transition(t, "state-authority-fork-8.dsse.json", 8, otherTerminalPEM)
	policyForAuthorityFork := writeCLISignedTrustPolicy(t, fixture.dir, "state-authority-fork-policy-8.dsse.json", 8,
		map[string]string{fixture.evidence.KeyIDA: "trusted"}, otherTerminalPrivate, otherTerminalID)
	report, response, code = run(authorityFork, policyForAuthorityFork, otherTerminalPath)
	assertState("authority equivocation", report, response, code, 7, "authority-equivocation-rejected", 8, 8, "state-generation-equivocation")

	policyFork := fixture.policy(t, "state-policy-fork-8.dsse.json", 8, map[string]string{
		fixture.evidence.KeyIDA: "trusted",
		fixture.evidence.KeyIDB: "trusted",
	})
	report, response, code = run(transition8, policyFork, fixture.terminalPath)
	assertState("policy equivocation", report, response, code, 7, "policy-equivocation-rejected", 8, 8, "state-generation-equivocation")

	statePath := filepath.Join(dataRoot, "trust-policy-state", "v1", "rotated", strings.TrimPrefix(fixture.rootID, "sha256:")+".json")
	before := mustReadFile(t, statePath)
	transition9 := fixture.transition(t, "state-transition-9.dsse.json", 9, fixture.terminalPEM)
	invalidPolicy9 := fixture.policy(t, "state-invalid-policy-9.dsse.json", 9, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	invalidPolicy9 = alpha32TamperCLIEnvelopeSignature(t, invalidPolicy9, filepath.Join(fixture.dir, "state-invalid-policy-9-tampered.dsse.json"))

	probes := 0
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := App{
		Deps: Dependencies{FreshnessSnapshot: func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error) {
			probes++
			return domain.SourceSnapshot{}, nil
		}},
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
	}
	args := fixture.args(fixture.evidence.BundleA, invalidPolicy9, fixture.terminalPath, transition9, fixture.rootPath, 1, 1, dataRoot, true)
	args = append(args,
		"--expect-bundle-digest", cliSHA256Digest(fixture.evidence.BundleABytes),
		"--current-manifest", fixture.evidence.CurrentSource,
	)
	code = app.Run(context.Background(), args)
	invalidResponse := decodeEnvelope(t, stdout.Bytes())
	var invalidReport attestation.VerificationReport
	decodeJSON(t, invalidResponse.Data, &invalidReport)
	if code != 7 || probes != 0 || invalidResponse.Error == nil || invalidResponse.Error.Code != domain.CodeAttestationUntrusted ||
		invalidReport.TrustReason != "invalid-or-unavailable" || stderr.String() != "" {
		t.Fatalf("invalid tuple exit=%d probes=%d report=%#v response=%#v stderr=%q", code, probes, invalidReport, invalidResponse, stderr.String())
	}
	after := mustReadFile(t, statePath)
	if !bytes.Equal(after, before) {
		t.Fatalf("invalid tuple changed combined state\nbefore=%s\nafter=%s", before, after)
	}
	report, response, code = run(transition8, policy8, fixture.terminalPath)
	assertState("matched after invalid tuple", report, response, code, 0, "matched", 8, 8, "trusted")
}

func TestAlpha32AuthorityRotationCLIDirectOmissionAndFullPortableByteParity(t *testing.T) {
	fixture := newAlpha32CLIRotationFixture(t)
	transition := fixture.transition(t, "parity-transition.dsse.json", 7, fixture.terminalPEM)
	policy := fixture.policy(t, "parity-policy.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})

	directArgs := []string{
		"--json", "verify-attestation", fixture.evidence.BundleA,
		"--trust-policy-envelope", policy,
		"--trust-policy-authority-key", fixture.terminalPath,
		"--minimum-trust-policy-generation", "7",
	}
	directResponse, _, directStderr, directCode := runAttestationCLI(t, directArgs...)
	if directCode != 0 || directResponse.Error != nil || directStderr != "" {
		t.Fatalf("direct signed policy exit=%d response=%#v stderr=%q", directCode, directResponse, directStderr)
	}
	var directRaw map[string]json.RawMessage
	decodeJSON(t, directResponse.Data, &directRaw)
	for _, field := range []string{
		"trustPolicyAuthorityTransitionDigest",
		"trustPolicyAuthorityTransitionEnvelopeDigest",
		"trustPolicyAuthorityTrustRootKeyId",
		"trustPolicyAuthorityTransitionGeneration",
		"minimumTrustPolicyAuthorityGeneration",
		"trustPolicyAuthorityStateEvaluation",
		"trustPolicyAuthorityStateTransitionGeneration",
		"trustPolicyAuthorityStatePolicyGeneration",
	} {
		if _, present := directRaw[field]; present {
			t.Fatalf("direct signed-policy JSON contains Alpha.32 field %q: %s", field, directResponse.Data)
		}
	}

	validArgs := fixture.args(fixture.evidence.BundleA, policy, fixture.terminalPath, transition, fixture.rootPath, 7, 7, "", false)
	negativeArgs := fixture.args(fixture.evidence.BundleA, policy, fixture.terminalPath, transition, fixture.otherRootPath, 7, 7, "", false)
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "accepted", args: validArgs},
		{name: "wrong root", args: negativeArgs},
	} {
		t.Run(test.name, func(t *testing.T) {
			fullExit, fullStdout, fullStderr := runPortableVerifierComparison(t, false, test.args)
			portableExit, portableStdout, portableStderr := runPortableVerifierComparison(t, true, test.args)
			if portableExit != fullExit || portableStdout != fullStdout || portableStderr != fullStderr {
				t.Fatalf("full/verifier mismatch\nfull: exit=%d stdout=%q stderr=%q\nverifier: exit=%d stdout=%q stderr=%q",
					fullExit, fullStdout, fullStderr, portableExit, portableStdout, portableStderr)
			}
		})
	}
}

func newAlpha32CLIRotationFixture(t *testing.T) alpha32CLIRotationFixture {
	t.Helper()
	directory := t.TempDir()
	rootPrivate, _, rootPEM := writeCLIKeyPair(t, directory, "rotation-root")
	terminalPrivate, _, terminalPEM := writeCLIKeyPair(t, directory, "rotation-terminal")
	otherRootPrivate, _, _ := writeCLIKeyPair(t, directory, "rotation-other-root")
	otherTerminalPrivate, _, _ := writeCLIKeyPair(t, directory, "rotation-other-terminal")
	t.Cleanup(func() {
		clear(rootPrivate)
		clear(terminalPrivate)
		clear(otherRootPrivate)
		clear(otherTerminalPrivate)
	})
	return alpha32CLIRotationFixture{
		evidence:          newCLITrustFixture(t),
		dir:               directory,
		rootPrivate:       rootPrivate,
		rootPath:          filepath.Join(directory, "rotation-root-public.pem"),
		rootPEM:           rootPEM,
		rootID:            alpha32CLIKeyID(t, rootPEM),
		terminalPrivate:   terminalPrivate,
		terminalPath:      filepath.Join(directory, "rotation-terminal-public.pem"),
		terminalPEM:       terminalPEM,
		terminalID:        alpha32CLIKeyID(t, terminalPEM),
		otherRootPath:     filepath.Join(directory, "rotation-other-root-public.pem"),
		otherTerminalPath: filepath.Join(directory, "rotation-other-terminal-public.pem"),
	}
}

func (fixture alpha32CLIRotationFixture) transition(t *testing.T, name string, generation uint64, terminalPEM []byte) string {
	t.Helper()
	raw, previousSPKI, verified, err := attestation.SignOfflineTrustPolicyAuthorityTransition(terminalPEM, generation, fixture.rootPrivate)
	if err != nil || verified == nil || !bytes.Equal(previousSPKI, fixture.rootPEM) {
		t.Fatalf("sign transition generation %d: verified=%#v err=%v", generation, verified, err)
	}
	path := filepath.Join(fixture.dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (fixture alpha32CLIRotationFixture) policy(t *testing.T, name string, generation uint64, statuses map[string]string) string {
	t.Helper()
	return writeCLISignedTrustPolicy(t, fixture.dir, name, generation, statuses, fixture.terminalPrivate, fixture.terminalID)
}

func (fixture alpha32CLIRotationFixture) args(bundle, policy, terminal, transition, root string, policyFloor, authorityFloor uint64, dataRoot string, persist bool) []string {
	args := []string{"--json"}
	if dataRoot != "" {
		args = append(args, "--data-dir", dataRoot)
	}
	args = append(args,
		"verify-attestation", bundle,
		"--trust-policy-envelope", policy,
		"--trust-policy-authority-key", terminal,
		"--minimum-trust-policy-generation", strconv.FormatUint(policyFloor, 10),
		"--trust-policy-authority-transition", transition,
		"--trust-policy-authority-trust-root", root,
		"--minimum-trust-policy-authority-generation", strconv.FormatUint(authorityFloor, 10),
	)
	if persist {
		args = append(args, "--persist-trust-policy-state")
	}
	return args
}

func (fixture alpha32CLIRotationFixture) run(t *testing.T, bundle, policy, terminal, transition, root string, policyFloor, authorityFloor uint64, dataRoot string, persist bool) (attestation.VerificationReport, testEnvelope, int) {
	t.Helper()
	response, _, stderr, code := runAttestationCLI(t, fixture.args(bundle, policy, terminal, transition, root, policyFloor, authorityFloor, dataRoot, persist)...)
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	var report attestation.VerificationReport
	decodeJSON(t, response.Data, &report)
	return report, response, code
}

func alpha32CLIKeyID(t *testing.T, publicPEM []byte) string {
	t.Helper()
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("test public key is not one canonical PEM block")
	}
	return cliSHA256Digest(block.Bytes)
}

func alpha32TamperCLIEnvelopeSignature(t *testing.T, source, target string) string {
	t.Helper()
	raw := mustReadFile(t, source)
	var envelope cliSignedTrustEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Signatures) != 1 {
		t.Fatalf("decode test DSSE envelope: signatures=%d err=%v", len(envelope.Signatures), err)
	}
	envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tampered, err := canonicaljson.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	return target
}
