package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/domain"
)

type alpha33CLIChainFixture struct {
	evidence     cliTrustFixture
	dir          string
	private      []ed25519.PrivateKey
	keyPEM       [][]byte
	keyPath      []string
	keyID        []string
	envelope     [][]byte
	envelopePath []string
	chainRaw     []byte
	chainPath    string
}

func newAlpha33CLIChainFixture(t *testing.T, hops int, name string) alpha33CLIChainFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := alpha33CLIChainFixture{evidence: newCLITrustFixture(t), dir: directory}
	for index := 0; index <= hops; index++ {
		private, _, publicPEM := writeCLIKeyPair(t, directory, name+"-authority-"+strconv.Itoa(index))
		fixture.private = append(fixture.private, private)
		fixture.keyPEM = append(fixture.keyPEM, publicPEM)
		fixture.keyPath = append(fixture.keyPath, filepath.Join(directory, name+"-authority-"+strconv.Itoa(index)+"-public.pem"))
		fixture.keyID = append(fixture.keyID, alpha32CLIKeyID(t, publicPEM))
	}
	t.Cleanup(func() {
		for _, private := range fixture.private {
			clear(private)
		}
	})
	fixture.writeChain(t, name+"-chain.json", alpha33SequentialGenerations(hops, 1))
	return fixture
}

func alpha33SequentialGenerations(hops int, start uint64) []uint64 {
	values := make([]uint64, hops)
	for index := range values {
		values[index] = start + uint64(index)
	}
	return values
}

func (fixture *alpha33CLIChainFixture) writeChain(t *testing.T, name string, generations []uint64) string {
	t.Helper()
	fixture.envelope = nil
	fixture.envelopePath = nil
	for index, generation := range generations {
		raw, _, _, err := attestation.SignOfflineTrustPolicyAuthorityTransition(fixture.keyPEM[index+1], generation, fixture.private[index])
		if err != nil {
			t.Fatalf("sign hop %d: %v", index, err)
		}
		path := filepath.Join(fixture.dir, strings.TrimSuffix(name, ".json")+"-hop-"+strconv.Itoa(index)+".dsse.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.envelope = append(fixture.envelope, raw)
		fixture.envelopePath = append(fixture.envelopePath, path)
	}
	chainRaw, err := attestation.BuildOfflineTrustPolicyAuthorityTransitionChain(fixture.envelope, fixture.keyPEM[1:], fixture.keyPEM[0])
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	fixture.chainRaw = chainRaw
	fixture.chainPath = filepath.Join(fixture.dir, name)
	if err := os.WriteFile(fixture.chainPath, chainRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return fixture.chainPath
}

func (fixture alpha33CLIChainFixture) policy(t *testing.T, name string, generation uint64, statuses map[string]string) string {
	t.Helper()
	terminal := len(fixture.private) - 1
	return writeCLISignedTrustPolicy(t, fixture.dir, name, generation, statuses, fixture.private[terminal], fixture.keyID[terminal])
}

func (fixture alpha33CLIChainFixture) verifyArgs(bundle, policy, chain, root, terminal string, policyFloor, authorityFloor uint64, dataRoot string, persist bool) []string {
	args := []string{"--json"}
	if dataRoot != "" {
		args = append(args, "--data-dir", dataRoot)
	}
	args = append(args,
		"verify-attestation", bundle,
		"--trust-policy-envelope", policy,
		"--trust-policy-authority-key", terminal,
		"--minimum-trust-policy-generation", strconv.FormatUint(policyFloor, 10),
		"--trust-policy-authority-transition-chain", chain,
		"--trust-policy-authority-trust-root", root,
		"--minimum-trust-policy-authority-generation", strconv.FormatUint(authorityFloor, 10),
	)
	if persist {
		args = append(args, "--persist-trust-policy-state")
	}
	return args
}

func (fixture alpha33CLIChainFixture) run(t *testing.T, args []string) (attestation.VerificationReport, testEnvelope, int) {
	t.Helper()
	response, _, stderr, code := runAttestationCLI(t, args...)
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	var report attestation.VerificationReport
	decodeJSON(t, response.Data, &report)
	return report, response, code
}

func (fixture alpha33CLIChainFixture) assemblerArgs(output string) []string {
	args := []string{"--json", "assemble-offline-trust-policy-authority-transition-chain"}
	for _, path := range fixture.envelopePath {
		args = append(args, "--hop-envelope", path)
	}
	for _, path := range fixture.keyPath[1:] {
		args = append(args, "--hop-next-authority-key", path)
	}
	return append(args,
		"--trust-policy-authority-trust-root", fixture.keyPath[0],
		"--minimum-trust-policy-authority-generation", strconv.Itoa(len(fixture.envelope)),
		"--out-dir", output,
	)
}

func TestAssembleOfflineTrustPolicyAuthorityTransitionChainFlagsFailBeforeIO(t *testing.T) {
	valid := []string{
		"--hop-envelope", "one", "--hop-envelope", "two",
		"--hop-next-authority-key", "middle", "--hop-next-authority-key", "terminal",
		"--trust-policy-authority-trust-root", "root",
		"--minimum-trust-policy-authority-generation", "2", "--out-dir", "output",
	}
	if options, err := validateAssembleOfflineTrustPolicyAuthorityTransitionChainArgs(valid); err != nil || len(options.HopEnvelopePaths) != 2 {
		t.Fatalf("valid flags rejected: %#v %v", options, err)
	}
	for name, args := range map[string][]string{
		"one hop": valid[2:], "mismatched pairs": append([]string{}, valid[:len(valid)-8]...),
		"duplicate root": append(append([]string{}, valid...), "--trust-policy-authority-trust-root", "other"),
		"leading zero":   append(append([]string{}, valid[:len(valid)-4]...), "--minimum-trust-policy-authority-generation", "02", "--out-dir", "output"),
		"separator":      append(append([]string{}, valid...), "--"),
		"single dash":    append([]string{"-hop-envelope", "one"}, valid[2:]...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAssembleOfflineTrustPolicyAuthorityTransitionChainArgs(args); err == nil {
				t.Fatalf("invalid flags accepted: %v", args)
			}
		})
	}
}

func TestAssembleOfflineTrustPolicyAuthorityTransitionChainTwoAndEightHopEndToEnd(t *testing.T) {
	for _, hops := range []int{2, 8} {
		t.Run(strconv.Itoa(hops)+" hops", func(t *testing.T) {
			fixture := newAlpha33CLIChainFixture(t, hops, "assemble")
			output := filepath.Join(t.TempDir(), "sidecars")
			response, _, stderr, code := runAttestationCLI(t, fixture.assemblerArgs(output)...)
			if code != 0 || response.Error != nil || stderr != "" {
				t.Fatalf("assemble exit=%d response=%#v stderr=%q", code, response, stderr)
			}
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 3 {
				t.Fatalf("exact-three output entries=%v err=%v", entries, err)
			}
			published := mustReadFile(t, filepath.Join(output, "offline-trust-policy-authority-transition-chain.json"))
			if !bytes.Equal(published, fixture.chainRaw) {
				t.Fatal("published chain differs from authenticated authoring result")
			}
		})
	}
}

func TestAssembleOfflineTrustPolicyAuthorityTransitionChainRejectsDriftAndPortableBeforeIO(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "drift")
	output := filepath.Join(t.TempDir(), "drift-output")
	reads := map[string]int{}
	app := App{Deps: Dependencies{OfflineTrustPolicyAuthoritySnapshot: func(path string) ([]byte, error) {
		reads[path]++
		raw, err := os.ReadFile(path)
		if path == fixture.keyPath[2] && reads[path] > 1 && err == nil {
			return append(append([]byte(nil), raw...), '\n'), nil
		}
		return raw, err
	}}, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if code := app.Run(context.Background(), fixture.assemblerArgs(output)); code != 1 {
		t.Fatalf("drift exit=%d want 1", code)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("drift materialized output: %v", err)
	}

	portableOutput := filepath.Join(t.TempDir(), "portable-output")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	portable := App{Deps: Dependencies{OfflineTrustPolicyAuthoritySnapshot: func(string) ([]byte, error) {
		t.Fatal("portable producer probed input")
		return nil, nil
	}}, Stdin: strings.NewReader(""), Stdout: stdout, Stderr: stderr}
	args := fixture.assemblerArgs(portableOutput)
	if code := portable.RunVerifier(context.Background(), args); code != 2 || stderr.Len() != 0 {
		t.Fatalf("portable assembler exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestAssembleOfflineTrustPolicyAuthorityTransitionChainRejectsUnsafeOutputAndInputTopology(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "topology")
	existing := t.TempDir()
	response, _, _, code := runAttestationCLI(t, fixture.assemblerArgs(existing)...)
	if code != 1 || response.Error == nil || response.Error.Code != domain.CodeSigningFailed {
		t.Fatalf("existing destination exit=%d response=%#v", code, response)
	}
	link := filepath.Join(t.TempDir(), "linked-root.pem")
	if err := os.Symlink(fixture.keyPath[0], link); err == nil {
		args := fixture.assemblerArgs(filepath.Join(t.TempDir(), "linked-output"))
		for index := range args {
			if args[index] == fixture.keyPath[0] {
				args[index] = link
			}
		}
		response, _, _, code = runAttestationCLI(t, args...)
		if code != 1 || response.Error == nil {
			t.Fatalf("linked input exit=%d response=%#v", code, response)
		}
	}
}

func TestAlpha33AuthorityTransitionChainFlagsAreExactAndPreIO(t *testing.T) {
	valid := []string{"--trust-policy-authority-transition-chain", "chain", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "2"}
	options, err := validateSignedTrustPolicyAuthorityRotationArgs(valid, true)
	if err != nil || !options.Enabled || !options.Chain || options.TransitionChainPath != "chain" || options.TransitionPath != "" {
		t.Fatalf("valid chain flags=%#v err=%v", options, err)
	}
	for name, args := range map[string][]string{
		"mixed":   append(append([]string{}, valid...), "--trust-policy-authority-transition", "hop"),
		"partial": valid[:2], "duplicate": append(append([]string{}, valid...), "--trust-policy-authority-transition-chain", "other"),
		"case alias": {"--Trust-Policy-Authority-Transition-Chain", "chain", "--trust-policy-authority-trust-root", "root", "--minimum-trust-policy-authority-generation", "2"},
	} {
		t.Run(name, func(t *testing.T) {
			if value, err := validateSignedTrustPolicyAuthorityRotationArgs(args, true); err == nil || value.Enabled {
				t.Fatalf("invalid chain flags accepted: %#v %v", value, err)
			}
		})
	}
}

func TestAlpha33AuthorityTransitionChainCLICompleteFlagGroupFailsBeforeIO(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "MUST-NOT-BE-READ")
	signed := []string{"--trust-policy-envelope", marker, "--trust-policy-authority-key", marker, "--minimum-trust-policy-generation", "1"}
	chain := []string{"--trust-policy-authority-transition-chain", marker, "--trust-policy-authority-trust-root", marker, "--minimum-trust-policy-authority-generation", "1"}
	for name, flags := range map[string][]string{
		"chain only":    append(append([]string{}, signed...), chain[:2]...),
		"root only":     append(append([]string{}, signed...), chain[2:4]...),
		"floor only":    append(append([]string{}, signed...), chain[4:]...),
		"mixed one hop": append(append(append([]string{}, signed...), chain...), "--trust-policy-authority-transition", marker),
	} {
		t.Run(name, func(t *testing.T) {
			response, _, stderr, code := runAttestationCLI(t, append([]string{"--json", "verify-attestation", filepath.Join(root, "missing.tar")}, flags...)...)
			if code != 2 || response.Error == nil || response.Error.Code != domain.CodeManifestInvalid || stderr != "" {
				t.Fatalf("pre-I/O rejection exit=%d response=%#v stderr=%q", code, response, stderr)
			}
		})
	}
}

func TestAlpha33AuthorityTransitionChainCLITwoAndEightHopEndToEnd(t *testing.T) {
	for _, hops := range []int{2, 8} {
		t.Run(strconv.Itoa(hops)+" hops", func(t *testing.T) {
			fixture := newAlpha33CLIChainFixture(t, hops, "verify")
			policy := fixture.policy(t, "trusted.dsse.json", 9, map[string]string{fixture.evidence.KeyIDA: "trusted"})
			args := fixture.verifyArgs(fixture.evidence.BundleA, policy, fixture.chainPath, fixture.keyPath[0], fixture.keyPath[hops], 9, uint64(hops), "", false)
			report, response, code := fixture.run(t, args)
			if code != 0 || response.Error != nil || report.TrustBasis != chainedSignedOfflineTrustPolicyBasis || report.TrustDecision != "accepted" ||
				report.TrustPolicyAuthorityTransitionChainHopCount != uint64(hops) || report.TrustPolicyAuthorityTransitionChainGeneration != uint64(hops) ||
				report.TrustPolicyAuthorityTransitionChainRootKeyID != fixture.keyID[0] || report.TrustPolicyAuthorityTransitionChainTerminalKeyID != fixture.keyID[hops] {
				t.Fatalf("chain verification exit=%d report=%#v response=%#v", code, report, response)
			}
		})
	}
}

func TestAlpha33AuthorityTransitionChainCLIRejectsCryptographicOrderingCycleAndFloor(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "negative")
	policy := fixture.policy(t, "trusted.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	wrong := newAlpha33CLIChainFixture(t, 2, "wrong")
	tampered := filepath.Join(fixture.dir, "tampered-chain.json")
	if err := os.WriteFile(tampered, append(append([]byte(nil), fixture.chainRaw...), 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	var reorderedValue attestation.OfflineTrustPolicyAuthorityTransitionChain
	if err := json.Unmarshal(fixture.chainRaw, &reorderedValue); err != nil {
		t.Fatal(err)
	}
	reorderedValue.Hops[0], reorderedValue.Hops[1] = reorderedValue.Hops[1], reorderedValue.Hops[0]
	reorderedRaw, err := canonicaljson.Marshal(reorderedValue)
	if err != nil {
		t.Fatal(err)
	}
	reordered := filepath.Join(fixture.dir, "reordered-chain.json")
	if err := os.WriteFile(reordered, reorderedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	cycleValue := reorderedValue
	if err := json.Unmarshal(fixture.chainRaw, &cycleValue); err != nil {
		t.Fatal(err)
	}
	cycleValue.Hops[1].NextAuthoritySPKI = base64.StdEncoding.EncodeToString(fixture.keyPEM[0])
	cycleRaw, err := canonicaljson.Marshal(cycleValue)
	if err != nil {
		t.Fatal(err)
	}
	cycle := filepath.Join(fixture.dir, "cycle-chain.json")
	if err := os.WriteFile(cycle, cycleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string]struct {
		chain, root, terminal string
		floor                 uint64
	}{
		"tamper":         {tampered, fixture.keyPath[0], fixture.keyPath[2], 2},
		"reordered":      {reordered, fixture.keyPath[0], fixture.keyPath[2], 2},
		"cycle":          {cycle, fixture.keyPath[0], fixture.keyPath[2], 2},
		"wrong root":     {fixture.chainPath, wrong.keyPath[0], fixture.keyPath[2], 2},
		"wrong terminal": {fixture.chainPath, fixture.keyPath[0], wrong.keyPath[2], 2},
		"floor":          {fixture.chainPath, fixture.keyPath[0], fixture.keyPath[2], 3},
	} {
		t.Run(name, func(t *testing.T) {
			args := fixture.verifyArgs(fixture.evidence.BundleA, policy, values.chain, values.root, values.terminal, 7, values.floor, "", false)
			report, response, code := fixture.run(t, args)
			if code != 7 || response.Error == nil || report.TrustReason != "invalid-or-unavailable" || report.TrustPolicyAuthorityTransitionChainDigest != "" {
				t.Fatalf("negative exit=%d report=%#v response=%#v", code, report, response)
			}
		})
	}
}

func TestAlpha33AuthorityTransitionChainCLIRejectsEveryAuthorityRoleConflict(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "role")
	for index := range fixture.keyID {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			policy := fixture.policy(t, "role-"+strconv.Itoa(index)+".dsse.json", 7, map[string]string{
				fixture.evidence.KeyIDA: "trusted", fixture.keyID[index]: "revoked",
			})
			args := fixture.verifyArgs(fixture.evidence.BundleA, policy, fixture.chainPath, fixture.keyPath[0], fixture.keyPath[2], 7, 2, "", false)
			report, response, code := fixture.run(t, args)
			if code != 7 || response.Error == nil || report.TrustPolicyAuthorityTransitionChainDigest != "" ||
				report.TrustReason != "authority-role-conflict" {
				t.Fatalf("authority role exit=%d report=%#v response=%#v", code, report, response)
			}
		})
	}
}

func TestAlpha33AuthorityTransitionChainCLIStateLifecycleAndNegativeCases(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "state")
	policy7 := fixture.policy(t, "policy-7.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	dataRoot := filepath.Join(t.TempDir(), "controller")
	run := func(chain, policy string) (attestation.VerificationReport, testEnvelope, int) {
		return fixture.run(t, fixture.verifyArgs(fixture.evidence.BundleA, policy, chain, fixture.keyPath[0], fixture.keyPath[2], 1, 1, dataRoot, true))
	}
	originalChain := fixture.chainPath
	report, response, code := run(originalChain, policy7)
	if code != 0 || response.Error != nil || report.TrustPolicyAuthorityTransitionChainStateEvaluation != "initialized" {
		t.Fatalf("initialized exit=%d report=%#v", code, report)
	}
	report, _, code = run(originalChain, policy7)
	if code != 0 || report.TrustPolicyAuthorityTransitionChainStateEvaluation != "matched" {
		t.Fatalf("matched exit=%d report=%#v", code, report)
	}
	advanced := fixture.writeChain(t, "advanced.json", []uint64{1, 3})
	policy8 := fixture.policy(t, "policy-8.dsse.json", 8, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	report, _, code = run(advanced, policy8)
	if code != 0 || report.TrustPolicyAuthorityTransitionChainStateEvaluation != "advanced" || report.TrustPolicyAuthorityTransitionChainStateGeneration != 3 {
		t.Fatalf("advanced exit=%d report=%#v", code, report)
	}
	report, response, code = run(originalChain, policy8)
	if code != 7 || response.Error == nil || report.TrustReason != "state-generation-rollback" {
		t.Fatalf("rollback exit=%d report=%#v", code, report)
	}
	equivocation := fixture.writeChain(t, "equivocation.json", []uint64{2, 3})
	report, response, code = run(equivocation, policy8)
	if code != 7 || response.Error == nil || report.TrustReason != "state-generation-equivocation" {
		t.Fatalf("equivocation exit=%d report=%#v", code, report)
	}
	policyFork := fixture.policy(t, "policy-fork-8.dsse.json", 8, map[string]string{
		fixture.evidence.KeyIDA: "trusted", fixture.evidence.KeyIDB: "trusted",
	})
	report, response, code = run(advanced, policyFork)
	if code != 7 || response.Error == nil || report.TrustReason != "state-generation-equivocation" {
		t.Fatalf("policy equivocation exit=%d report=%#v", code, report)
	}
}

func TestAlpha33AuthorityTransitionChainCLIFullPortableByteParityAndNoProbe(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "parity")
	policy := fixture.policy(t, "policy.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	valid := fixture.verifyArgs(fixture.evidence.BundleA, policy, fixture.chainPath, fixture.keyPath[0], fixture.keyPath[2], 7, 2, "", false)
	invalid := append([]string{}, valid...)
	invalid[2] = filepath.Join(fixture.dir, "missing-bundle.tar")
	for name, args := range map[string][]string{"valid": valid, "invalid bundle": invalid} {
		t.Run(name, func(t *testing.T) {
			fullExit, fullOut, fullErr := runPortableVerifierComparison(t, false, args)
			portableExit, portableOut, portableErr := runPortableVerifierComparison(t, true, args)
			if fullExit != portableExit || fullOut != portableOut || fullErr != portableErr {
				t.Fatalf("full/portable mismatch full=(%d,%q,%q) portable=(%d,%q,%q)", fullExit, fullOut, fullErr, portableExit, portableOut, portableErr)
			}
		})
	}
}

func TestAlpha33PortableRejectsChainAssemblerBeforeIO(t *testing.T) {
	output := filepath.Join(t.TempDir(), "must-not-exist")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := App{Deps: Dependencies{OfflineTrustPolicyAuthoritySnapshot: func(string) ([]byte, error) {
		t.Fatal("portable assembler performed input I/O")
		return nil, nil
	}}, Stdin: strings.NewReader(""), Stdout: stdout, Stderr: stderr}
	code := app.RunVerifier(context.Background(), []string{"--json", "assemble-offline-trust-policy-authority-transition-chain", "--out-dir", output})
	if code != 2 || stderr.Len() != 0 {
		t.Fatalf("portable producer exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("portable producer created output: %v", err)
	}
}

func TestAlpha33PortableChainVerificationRetainsNoSidecars(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "portable")
	policy := fixture.policy(t, "policy.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	before, err := os.ReadDir(fixture.dir)
	if err != nil {
		t.Fatal(err)
	}
	args := fixture.verifyArgs(fixture.evidence.BundleA, policy, fixture.chainPath, fixture.keyPath[0], fixture.keyPath[2], 7, 2, "", false)
	exit, _, stderr := runPortableVerifierComparison(t, true, args)
	after, readErr := os.ReadDir(fixture.dir)
	if exit != 0 || stderr != "" || readErr != nil || len(before) != len(after) {
		t.Fatalf("portable retained sidecars exit=%d before=%d after=%d stderr=%q err=%v", exit, len(before), len(after), stderr, readErr)
	}
}

func TestAlpha33DirectSignedPolicyOutputCompatibility(t *testing.T) {
	fixture := newAlpha33CLIChainFixture(t, 2, "direct")
	policy := fixture.policy(t, "policy.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	args := []string{"--json", "verify-attestation", fixture.evidence.BundleA,
		"--trust-policy-envelope", policy, "--trust-policy-authority-key", fixture.keyPath[2], "--minimum-trust-policy-generation", "7"}
	response, _, stderr, code := runAttestationCLI(t, args...)
	if code != 0 || response.Error != nil || stderr != "" {
		t.Fatalf("direct exit=%d response=%#v stderr=%q", code, response, stderr)
	}
	var fields map[string]json.RawMessage
	decodeJSON(t, response.Data, &fields)
	for name := range fields {
		if strings.Contains(name, "TransitionChain") {
			t.Fatalf("direct output contains chain field %q", name)
		}
	}
}

func TestAlpha33OneHopAuthorityRotationOutputCompatibility(t *testing.T) {
	fixture := newAlpha32CLIRotationFixture(t)
	transition := fixture.transition(t, "compat-transition.dsse.json", 7, fixture.terminalPEM)
	policy := fixture.policy(t, "compat-policy.dsse.json", 7, map[string]string{fixture.evidence.KeyIDA: "trusted"})
	report, response, code := fixture.run(t, fixture.evidence.BundleA, policy, fixture.terminalPath, transition, fixture.rootPath, 7, 7, "", false)
	if code != 0 || response.Error != nil || report.TrustBasis != rotatedSignedOfflineTrustPolicyBasis || report.TrustPolicyAuthorityTransitionDigest == "" {
		t.Fatalf("one-hop compatibility exit=%d report=%#v response=%#v", code, report, response)
	}
	var fields map[string]json.RawMessage
	decodeJSON(t, response.Data, &fields)
	for name := range fields {
		if strings.Contains(name, "TransitionChain") {
			t.Fatalf("one-hop output contains chain field %q", name)
		}
	}
}
