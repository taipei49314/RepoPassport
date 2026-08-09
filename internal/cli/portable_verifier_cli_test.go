package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestPortableVerifierDispatchAllowsOnlyHelpVersionAndVerifyAttestation(t *testing.T) {
	for _, helpArg := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		if exitCode := app.RunVerifier(context.Background(), helpArg); exitCode != 0 {
			t.Fatalf("help %q exit code = %d, stderr = %q", helpArg, exitCode, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("help %q stderr = %q", helpArg, stderr.String())
		}
		help := stdout.String()
		for _, required := range []string{
			"repopass-verify [global options] <command> [options]",
			"verify-attestation FILE",
			"verify-release-index",
			"version                  Print the verifier version",
		} {
			if !strings.Contains(help, required) {
				t.Fatalf("help %q is missing %q: %s", helpArg, required, help)
			}
		}
		for _, forbidden := range []string{
			"\n  attest --run", "\n  inspect ", "\n  init ", "\n  validate ",
			"\n  plan ", "\n  verify --scenario", "\n  report ", "\n  doctor ", "\n  capabilities ",
			"\n  sign-release-index", "\n  sign-release-policy",
		} {
			if strings.Contains(help, forbidden) {
				t.Fatalf("verifier help exposes forbidden command %q: %s", forbidden, help)
			}
		}
	}

	var textStdout bytes.Buffer
	var textStderr bytes.Buffer
	textApp := App{Stdin: strings.NewReader(""), Stdout: &textStdout, Stderr: &textStderr}
	if exitCode := textApp.RunVerifier(context.Background(), []string{"version"}); exitCode != 0 {
		t.Fatalf("text version exit code = %d, stderr = %q", exitCode, textStderr.String())
	}
	if want := "repopass-verify " + Version + "\n"; textStdout.String() != want {
		t.Fatalf("text version = %q, want %q", textStdout.String(), want)
	}

	var jsonStdout bytes.Buffer
	var jsonStderr bytes.Buffer
	jsonApp := App{Stdin: strings.NewReader(""), Stdout: &jsonStdout, Stderr: &jsonStderr}
	globalRoot := t.TempDir()
	jsonArgs := []string{
		"--config", filepath.Join(globalRoot, "config.json"),
		"--data-dir", filepath.Join(globalRoot, "data"),
		"--cache-dir", filepath.Join(globalRoot, "cache"),
		"--log-level", "debug", "--log-format", "json", "--no-color",
		"--offline", "--non-interactive", "--json", "--version",
	}
	if exitCode := jsonApp.RunVerifier(context.Background(), jsonArgs); exitCode != 0 {
		t.Fatalf("JSON version exit code = %d, stderr = %q", exitCode, jsonStderr.String())
	}
	response := decodeEnvelope(t, jsonStdout.Bytes())
	if response.Command != "version" || response.Status != "ok" || response.Error != nil {
		t.Fatalf("JSON version envelope = %#v", response)
	}
	var versionData map[string]string
	decodeJSON(t, response.Data, &versionData)
	if versionData["version"] != Version {
		t.Fatalf("JSON version = %q, want %q", versionData["version"], Version)
	}

	var commandSpecificCalls int
	for _, command := range []string{
		"inspect", "init", "validate", "plan", "verify", "report", "attest",
		"sign-release-index", "sign-release-policy", "doctor", "capabilities", "Verify-Attestation", "verify_attestation",
		"verify-attestation.exe", "va", "-version",
	} {
		commandSpecificCalls = 0
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := App{
			Deps: Dependencies{
				ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
					commandSpecificCalls++
					return nil, nil
				},
				ProbeBackend: func(context.Context, string) ([]domain.RunnerFeatures, error) {
					commandSpecificCalls++
					return nil, nil
				},
				Execute: func(context.Context, domain.ResolvedPlan, string, string, string) (RunnerOutcome, error) {
					commandSpecificCalls++
					return RunnerOutcome{}, nil
				},
			},
			Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		}
		sentinel := filepath.Join(globalRoot, "must-not-be-opened-or-created")
		configSentinel := sentinel + "-config"
		dataSentinel := sentinel + "-data"
		cacheSentinel := sentinel + "-cache"
		exitCode := app.RunVerifier(context.Background(), []string{
			"--config", configSentinel,
			"--data-dir", dataSentinel,
			"--cache-dir", cacheSentinel,
			"--offline", "--non-interactive",
			command, sentinel,
		})
		if exitCode != 2 {
			t.Fatalf("forbidden command %q exit code = %d, want 2", command, exitCode)
		}
		if commandSpecificCalls != 0 {
			t.Fatalf("forbidden command %q made %d command-specific calls", command, commandSpecificCalls)
		}
		if stdout.Len() != 0 {
			t.Fatalf("forbidden command %q stdout = %q", command, stdout.String())
		}
		wantStderr := "MANIFEST_INVALID: Unknown verifier command.\nSuggestion: Run repopass-verify --help.\n"
		if stderr.String() != wantStderr {
			t.Fatalf("forbidden command %q stderr = %q, want %q", command, stderr.String(), wantStderr)
		}
		for _, path := range []string{sentinel, configSentinel, dataSentinel, cacheSentinel} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("forbidden command %q accessed or created sentinel %q: %v", command, path, err)
			}
		}
	}
}

func TestPortableVerifierMatchesFullCLITrustTamperAndOutputSemantics(t *testing.T) {
	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	privateKey, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "portable")
	defer clear(privateKey)
	defer clear(privatePEM)
	keyPath := filepath.Join(keyRoot, "portable-private.pem")
	trustPath := filepath.Join(keyRoot, "portable-public.pem")
	bundlePath := filepath.Join(outputRoot, "portable.tar")

	attestEnvelope, _, attestStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID, "--key", keyPath, "--out", bundlePath,
	)
	if exitCode != 0 || attestEnvelope.Status != "ok" || attestEnvelope.Error != nil {
		t.Fatalf("fixture attest exit=%d envelope=%#v stderr=%s", exitCode, attestEnvelope, attestStderr)
	}
	tamperedBundlePath := filepath.Join(outputRoot, "tampered.tar")
	tamperedBundle := append([]byte(nil), mustReadFile(t, bundlePath)...)
	tamperedBundle[0] ^= 0x01
	if err := os.WriteFile(tamperedBundlePath, tamperedBundle, 0o600); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{name: "command help", args: []string{"verify-attestation", "--help"}},
		{name: "signature valid but unknown trust", args: []string{"--json", "verify-attestation", bundlePath}},
		{name: "explicit trust accepted", args: []string{"--json", "verify-attestation", bundlePath, "--trust-key", trustPath}},
		{name: "tampered bundle rejected before trust", args: []string{
			"--json", "verify-attestation", tamperedBundlePath,
			"--trust-key", filepath.Join(keyRoot, "must-not-be-read.pem"),
		}},
		{name: "malformed digest rejected before trust", args: []string{
			"--json", "verify-attestation", bundlePath,
			"--expect-bundle-digest", "sha256:not-a-canonical-digest",
			"--trust-key", filepath.Join(keyRoot, "must-not-be-read.pem"),
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fullExit, fullStdout, fullStderr := runPortableVerifierComparison(t, false, testCase.args)
			portableExit, portableStdout, portableStderr := runPortableVerifierComparison(t, true, testCase.args)
			if portableExit != fullExit || portableStdout != fullStdout || portableStderr != fullStderr {
				t.Fatalf(
					"full/verifier mismatch\nfull: exit=%d stdout=%q stderr=%q\nverifier: exit=%d stdout=%q stderr=%q",
					fullExit, fullStdout, fullStderr, portableExit, portableStdout, portableStderr,
				)
			}
		})
	}
}

func TestPortableVerifierBuiltBinaryOutsideWorktree(t *testing.T) {
	binaryPath := os.Getenv("REPOPASS_PORTABLE_VERIFIER_BINARY")
	if binaryPath == "" {
		t.Skip("set REPOPASS_PORTABLE_VERIFIER_BINARY for extracted-binary E2E")
	}
	absoluteBinary, err := filepath.Abs(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(absoluteBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("portable verifier binary is not a regular no-link file: info=%v err=%v", info, err)
	}

	dataRoot := t.TempDir()
	runID := createBlockedAuthoritativeRun(t, dataRoot)
	keyRoot := t.TempDir()
	outputRoot := t.TempDir()
	privateKey, privatePEM, _ := writeCLIKeyPair(t, keyRoot, "portable-external")
	defer clear(privateKey)
	defer clear(privatePEM)
	bundlePath := filepath.Join(outputRoot, "portable-external.tar")
	trustPath := filepath.Join(keyRoot, "portable-external-public.pem")
	attestEnvelope, _, attestStderr, exitCode := runAttestationCLI(
		t,
		"--json", "--data-dir", dataRoot,
		"attest", "--run", runID,
		"--key", filepath.Join(keyRoot, "portable-external-private.pem"),
		"--out", bundlePath,
	)
	if exitCode != 0 || attestEnvelope.Status != "ok" || attestEnvelope.Error != nil {
		t.Fatalf("external fixture attest exit=%d envelope=%#v stderr=%s", exitCode, attestEnvelope, attestStderr)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bundle)
	expectedDigest := fmt.Sprintf("sha256:%x", digest)

	for _, testCase := range []struct {
		name string
		args []string
	}{
		{name: "version", args: []string{"version"}},
		{name: "signature valid trust unknown", args: []string{
			"--json", "--data-dir", t.TempDir(), "verify-attestation", bundlePath,
		}},
		{name: "explicit pinned key accepted", args: []string{
			"--json", "--data-dir", t.TempDir(), "verify-attestation", bundlePath,
			"--expect-bundle-digest", expectedDigest, "--trust-key", trustPath,
		}},
		{name: "digest mismatch before missing trust key", args: []string{
			"--json", "--data-dir", t.TempDir(), "verify-attestation", bundlePath,
			"--expect-bundle-digest", "sha256:" + strings.Repeat("0", 64),
			"--trust-key", filepath.Join(keyRoot, "must-not-be-read.pem"),
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			wantExit, wantStdout, wantStderr := runPortableVerifierComparison(t, true, testCase.args)
			gotExit, gotStdout, gotStderr := runExternalPortableVerifier(
				t, absoluteBinary, t.TempDir(), testCase.args,
			)
			if gotExit != wantExit || gotStdout != wantStdout || gotStderr != wantStderr {
				t.Fatalf(
					"in-process/extracted mismatch\nin-process: exit=%d stdout=%q stderr=%q\nextracted: exit=%d stdout=%q stderr=%q",
					wantExit, wantStdout, wantStderr, gotExit, gotStdout, gotStderr,
				)
			}
		})
	}
}

func runExternalPortableVerifier(
	t *testing.T,
	binaryPath string,
	workingDirectory string,
	args []string,
) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, args...)
	command.Dir = workingDirectory
	command.Env = os.Environ()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("extracted verifier exceeded the 30-second E2E deadline")
	}
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("run extracted verifier: %v", err)
		}
		exitCode = exitError.ExitCode()
	}
	return exitCode, stdout.String(), stderr.String()
}

func runPortableVerifierComparison(t *testing.T, verifierOnly bool, args []string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	if verifierOnly {
		return app.RunVerifier(context.Background(), args), stdout.String(), stderr.String()
	}
	return app.Run(context.Background(), args), stdout.String(), stderr.String()
}
