package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/acquisition"
	"github.com/repopass/repopass/internal/attestation"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/spdx"
	"github.com/repopass/repopass/internal/storage"
)

func TestMain(m *testing.M) {
	if marker := os.Getenv("REPOPASS_TEST_FAKE_DERIVE_COMMAND_MARKER"); marker != "" {
		name := strings.ToLower(strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe"))
		if name == "git" || name == "npm" || name == "node" {
			_ = os.WriteFile(marker, []byte(name), 0o600)
			os.Exit(97)
		}
	}
	os.Exit(m.Run())
}

func TestAttestDerivedSPDXSyntaxIsStrictPreAccessAndNonEchoing(t *testing.T) {
	marker := "synthetic-derived-value-never-echo.invalid"
	tests := []struct {
		name string
		args []string
	}{
		{name: "derive without current", args: []string{"--derive-spdx"}},
		{name: "current without derive", args: []string{"--current-manifest", marker}},
		{name: "duplicate derive", args: []string{"--derive-spdx", "--derive-spdx", "--current-manifest", marker}},
		{name: "duplicate current", args: []string{"--derive-spdx", "--current-manifest", marker, "--current-manifest=" + marker}},
		{name: "empty current", args: []string{"--derive-spdx", "--current-manifest="}},
		{name: "boolean assignment", args: []string{"--derive-spdx=false", "--current-manifest", marker}},
		{name: "case variant", args: []string{"--Derive-SPDX", "--current-manifest", marker}},
		{name: "current suffix", args: []string{"--derive-spdx", "--current-manifest-file=" + marker}},
		{name: "mutually exclusive", args: []string{"--spdx", marker, "--derive-spdx", "--current-manifest", marker}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			var stdout, stderr bytes.Buffer
			app := App{
				Deps: Dependencies{DerivedSnapshot: func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error) {
					calls++
					return domain.SourceSnapshot{}, nil
				}},
				Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
			}
			args := append([]string{"--json", "--data-dir", filepath.Join(t.TempDir(), "missing"), "attest"}, test.args...)
			exitCode := app.Run(context.Background(), args)
			if exitCode != 2 || calls != 0 {
				t.Fatalf("exit=%d calls=%d stdout=%s stderr=%s", exitCode, calls, stdout.String(), stderr.String())
			}
			envelope := decodeEnvelope(t, stdout.Bytes())
			if envelope.Error == nil || envelope.Error.Code != domain.CodeManifestInvalid {
				t.Fatalf("syntax envelope=%#v", envelope)
			}
			if strings.Contains(stdout.String()+stderr.String(), marker) {
				t.Fatalf("syntax error echoed derived value: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestAttestDerivedSPDXCommandFreeSourceBeforeKeyAndV2Replay(t *testing.T) {
	fixture := newDerivedCLIFixture(t, "derived-fixture", "1.3.0", "1.3.0")
	fakeMarker := filepath.Join(t.TempDir(), "command-executed")
	fakePath := installDerivedFakeCommands(t)
	t.Setenv("PATH", fakePath)
	t.Setenv("REPOPASS_TEST_FAKE_DERIVE_COMMAND_MARKER", fakeMarker)

	callCount := 0
	var stdout, stderr bytes.Buffer
	app := App{
		Deps: Dependencies{DerivedSnapshot: func(ctx context.Context, resolved domain.ResolvedSource) (domain.SourceSnapshot, error) {
			callCount++
			return acquisition.NewLocalProvider().Fetch(ctx, resolved)
		}},
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
	}
	exitCode := app.Run(context.Background(), []string{
		"--json", "--data-dir", fixture.dataRoot, "attest",
		"--run", fixture.result.RunID,
		"--derive-spdx", "--current-manifest", fixture.manifestPath,
		"--key", fixture.keyPath, "--out", fixture.bundlePath,
	})
	if exitCode != 0 || callCount != 3 {
		t.Fatalf("derived attest exit=%d calls=%d stdout=%s stderr=%s", exitCode, callCount, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(fakeMarker); !os.IsNotExist(err) {
		t.Fatalf("derived flow executed a forbidden command: %v", err)
	}
	if strings.Contains(stdout.String()+stderr.String(), fixture.manifestPath) {
		t.Fatal("derived attest output echoed current manifest path")
	}
	envelope := decodeEnvelope(t, stdout.Bytes())
	var built struct {
		SchemaVersion      string `json:"schemaVersion"`
		BundleDigest       string `json:"bundleDigest"`
		SBOMOrigin         string `json:"sbomOrigin"`
		SBOMProfile        string `json:"sbomProfile"`
		SBOMRulesetDigest  string `json:"sbomRulesetDigest"`
		ProvenanceDigest   string `json:"sbomProvenanceDigest"`
		SBOMPrivacyProfile string `json:"sbomPrivacyProfile"`
		SBOMPrivacyResult  string `json:"sbomPrivacyEvaluation"`
	}
	decodeJSON(t, envelope.Data, &built)
	if built.SchemaVersion != attestation.BundleVersionV2 || built.SBOMOrigin != spdx.DerivedOrigin ||
		built.SBOMProfile != spdx.DerivedProfile || built.SBOMRulesetDigest != spdx.DerivedRulesetDigest ||
		built.ProvenanceDigest == "" || built.SBOMPrivacyProfile == "" || built.SBOMPrivacyResult != "passed" {
		t.Fatalf("derived attest metadata=%#v", built)
	}

	callCount = 0
	stdout.Reset()
	stderr.Reset()
	exitCode = app.Run(context.Background(), []string{
		"--json", "verify-attestation", fixture.bundlePath,
		"--trust-key", fixture.trustPath,
		"--expect-bundle-digest", built.BundleDigest,
		"--current-manifest", fixture.manifestPath,
	})
	if exitCode != 0 || callCount != 3 {
		t.Fatalf("derived fresh replay exit=%d calls=%d stdout=%s stderr=%s", exitCode, callCount, stdout.String(), stderr.String())
	}
	verified := decodeEnvelope(t, stdout.Bytes())
	var report attestation.VerificationReport
	decodeJSON(t, verified.Data, &report)
	if report.SchemaVersion != attestation.BundleVersionV2 || report.TrustDecision != "accepted" ||
		report.FreshnessEvaluation != attestation.FreshnessNotEvaluated || report.Freshness != nil ||
		report.SBOMCurrentnessEvaluation != attestation.SBOMCurrentnessFresh || report.SBOMCurrentness == nil ||
		report.SBOMCurrentness.Status != attestation.SBOMCurrentnessFresh {
		t.Fatalf("derived fresh report=%#v", report)
	}
	if report.OriginalResults != fixture.result.Results {
		t.Fatalf("currentness rewrote historical verdicts: got=%#v want=%#v", report.OriginalResults, fixture.result.Results)
	}
}

func TestAttestDerivedSPDXFailurePrecedenceBeforeKey(t *testing.T) {
	t.Run("subject mismatch stops after two observations", func(t *testing.T) {
		fixture := newDerivedCLIFixture(t, "derived-fixture", "1.3.0", "1.3.0")
		missingKey := filepath.Join(t.TempDir(), "missing-private.pem")
		calls := 0
		app, stdout, stderr := derivedCLIApp(func(ctx context.Context, resolved domain.ResolvedSource) (domain.SourceSnapshot, error) {
			calls++
			snapshot, err := acquisition.NewLocalProvider().Fetch(ctx, resolved)
			if err == nil {
				snapshot.TreeDigest = "sha256:" + strings.Repeat("a", 64)
				snapshot.Identity = snapshot.TreeDigest
			}
			return snapshot, err
		})
		exitCode := app.Run(context.Background(), fixture.attestArgs(missingKey, fixture.bundlePath))
		assertDerivedPreKeyFailure(t, exitCode, calls, 2, stdout, stderr, missingKey, fixture.bundlePath, domain.CodeEvidenceBuildFailed)
	})

	t.Run("third observation drift stops before key", func(t *testing.T) {
		fixture := newDerivedCLIFixture(t, "derived-fixture", "1.3.0", "1.3.0")
		missingKey := filepath.Join(t.TempDir(), "missing-private.pem")
		calls := 0
		app, stdout, stderr := derivedCLIApp(func(ctx context.Context, resolved domain.ResolvedSource) (domain.SourceSnapshot, error) {
			calls++
			snapshot, err := acquisition.NewLocalProvider().Fetch(ctx, resolved)
			if err == nil && calls == 3 {
				snapshot.TreeDigest = "sha256:" + strings.Repeat("b", 64)
				snapshot.Identity = snapshot.TreeDigest
			}
			return snapshot, err
		})
		exitCode := app.Run(context.Background(), fixture.attestArgs(missingKey, fixture.bundlePath))
		assertDerivedPreKeyFailure(t, exitCode, calls, 3, stdout, stderr, missingKey, fixture.bundlePath, domain.CodeEvidenceBuildFailed)
	})

	t.Run("privacy stops before third observation and key", func(t *testing.T) {
		fixture := newDerivedCLIFixture(t, "npm_"+strings.Repeat("a", 40), "1.3.0", "1.3.0")
		missingKey := filepath.Join(t.TempDir(), "missing-private.pem")
		calls := 0
		app, stdout, stderr := derivedCLIApp(func(ctx context.Context, resolved domain.ResolvedSource) (domain.SourceSnapshot, error) {
			calls++
			return acquisition.NewLocalProvider().Fetch(ctx, resolved)
		})
		exitCode := app.Run(context.Background(), fixture.attestArgs(missingKey, fixture.bundlePath))
		assertDerivedPreKeyFailure(t, exitCode, calls, 2, stdout, stderr, missingKey, fixture.bundlePath, domain.CodeEvidencePrivacyBlocked)
	})
}

func TestVerifyDerivedCurrentnessTrustAndPinPrecedeRepositoryAccess(t *testing.T) {
	fixture := newDerivedCLIFixture(t, "derived-fixture", "1.3.0", "1.3.0")
	_, _, _, exitCode := runAttestationCLI(t, fixture.attestArgs(fixture.keyPath, fixture.bundlePath)...)
	if exitCode != 0 {
		t.Fatalf("build derived fixture bundle exit=%d", exitCode)
	}
	bundle := mustReadFile(t, fixture.bundlePath)
	digest := cliSHA256Digest(bundle)
	_, _, wrongTrust := writeCLIKeyPair(t, t.TempDir(), "wrong-derived-trust")
	wrongTrustPath := filepath.Join(t.TempDir(), "wrong.pem")
	if err := os.WriteFile(wrongTrustPath, wrongTrust, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		digest   string
		trust    string
		wantCode domain.ErrorCode
	}{
		{name: "wrong raw bundle pin", digest: "sha256:" + strings.Repeat("0", 64), trust: fixture.trustPath, wantCode: domain.CodeEvidenceDigestMismatch},
		{name: "wrong trusted SPKI", digest: digest, trust: wrongTrustPath, wantCode: domain.CodeAttestationUntrusted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			app, stdout, stderr := derivedCLIApp(func(ctx context.Context, resolved domain.ResolvedSource) (domain.SourceSnapshot, error) {
				calls++
				return acquisition.NewLocalProvider().Fetch(ctx, resolved)
			})
			exitCode := app.Run(context.Background(), []string{
				"--json", "verify-attestation", fixture.bundlePath,
				"--trust-key", test.trust,
				"--expect-bundle-digest", test.digest,
				"--current-manifest", fixture.manifestPath,
			})
			if calls != 0 {
				t.Fatalf("repository accessed before trust+pin: calls=%d", calls)
			}
			envelope := decodeEnvelope(t, stdout.Bytes())
			if envelope.Error == nil || envelope.Error.Code != test.wantCode {
				t.Fatalf("exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr.String())
			}
		})
	}
}

func TestVerifyDerivedSBOMCurrentnessStaleAndUnknownRemainSeparate(t *testing.T) {
	fixture := newDerivedCLIFixture(t, "derived-fixture", "1.3.0", "1.3.0")
	_, _, stderr, exitCode := runAttestationCLI(t, fixture.attestArgs(fixture.keyPath, fixture.bundlePath)...)
	if exitCode != 0 {
		t.Fatalf("build derived currentness fixture exit=%d stderr=%s", exitCode, stderr)
	}
	digest := cliSHA256Digest(mustReadFile(t, fixture.bundlePath))
	repositoryRoot := filepath.Dir(fixture.manifestPath)

	writeDerivedNPMFixture(t, repositoryRoot, "derived-fixture", "1.3.1", "1.3.1")
	stale, _, staleStderr, exitCode := runAttestationCLI(t,
		"--json", "verify-attestation", fixture.bundlePath,
		"--trust-key", fixture.trustPath,
		"--expect-bundle-digest", digest,
		"--current-manifest", fixture.manifestPath,
	)
	if stale.Error == nil || stale.Error.Code != domain.CodeEvidenceStale {
		t.Fatalf("stale exit=%d envelope=%#v stderr=%s", exitCode, stale, staleStderr)
	}
	var staleReport attestation.VerificationReport
	decodeJSON(t, stale.Data, &staleReport)
	if staleReport.SBOMCurrentnessEvaluation != attestation.SBOMCurrentnessStale ||
		staleReport.SBOMCurrentness == nil || staleReport.SBOMCurrentness.Status != attestation.SBOMCurrentnessStale ||
		staleReport.FreshnessEvaluation != attestation.FreshnessNotEvaluated || staleReport.Freshness != nil ||
		staleReport.OriginalResults != fixture.result.Results {
		t.Fatalf("stale report=%#v", staleReport)
	}

	writeDerivedNPMFixture(t, repositoryRoot, "derived-fixture", "1.3.1", "^1.3.1")
	unknown, _, unknownStderr, exitCode := runAttestationCLI(t,
		"--json", "verify-attestation", fixture.bundlePath,
		"--trust-key", fixture.trustPath,
		"--expect-bundle-digest", digest,
		"--current-manifest", fixture.manifestPath,
	)
	if unknown.Error == nil || unknown.Error.Code != domain.CodeEvidenceBuildFailed {
		t.Fatalf("unknown exit=%d envelope=%#v stderr=%s", exitCode, unknown, unknownStderr)
	}
	var unknownReport attestation.VerificationReport
	decodeJSON(t, unknown.Data, &unknownReport)
	if unknownReport.SBOMCurrentnessEvaluation != attestation.SBOMCurrentnessUnknown ||
		unknownReport.SBOMCurrentness == nil || unknownReport.SBOMCurrentness.Status != attestation.SBOMCurrentnessUnknown ||
		unknownReport.SBOMCurrentness.Reason != attestation.SBOMCurrentnessReasonUnsupported ||
		unknownReport.FreshnessEvaluation != attestation.FreshnessNotEvaluated || unknownReport.Freshness != nil ||
		unknownReport.OriginalResults != fixture.result.Results {
		t.Fatalf("unknown report=%#v", unknownReport)
	}
}

func TestAttestDerivedSPDXRejectsOutputsInsideTargetRepository(t *testing.T) {
	fixture := newDerivedCLIFixture(t, "derived-fixture", "1.3.0", "1.3.0")
	repositoryRoot := filepath.Dir(fixture.manifestPath)
	for _, test := range []struct {
		name       string
		bundlePath string
		publicPath string
	}{
		{name: "bundle", bundlePath: filepath.Join(repositoryRoot, "derived-v2.tar")},
		{name: "public key", bundlePath: filepath.Join(t.TempDir(), "derived-v2.tar"), publicPath: filepath.Join(repositoryRoot, "derived-public.pem")},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := fixture.attestArgs(fixture.keyPath, test.bundlePath)
			if test.publicPath != "" {
				args = append(args, "--public-key-out", test.publicPath)
			}
			envelope, stdout, stderr, exitCode := runAttestationCLI(t, args...)
			if envelope.Error == nil || envelope.Error.Code != domain.CodeSigningFailed {
				t.Fatalf("exit=%d envelope=%#v stderr=%s", exitCode, envelope, stderr)
			}
			if strings.Contains(stdout+stderr, repositoryRoot) {
				t.Fatal("target-repository isolation error echoed repository path")
			}
			for _, path := range []string{test.bundlePath, test.publicPath} {
				if path == "" {
					continue
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("target isolation published %s: %v", filepath.Base(path), err)
				}
			}
		})
	}
}

type derivedCLIFixture struct {
	dataRoot     string
	manifestPath string
	keyPath      string
	trustPath    string
	bundlePath   string
	result       domain.VerificationResult
}

func newDerivedCLIFixture(t *testing.T, rootName, dependencyVersion, dependencySpec string) derivedCLIFixture {
	t.Helper()
	dataRoot := t.TempDir()
	baseRunID := createBlockedAuthoritativeRun(t, dataRoot)
	store := storage.RunStore{Root: filepath.Join(dataRoot, "runs")}
	base, err := store.Read(baseRunID)
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot := t.TempDir()
	manifestPath := filepath.Join(repositoryRoot, "repo-passport.yml")
	manifestRaw, err := os.ReadFile(healthyNodeManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	writeDerivedNPMFixture(t, repositoryRoot, rootName, dependencyVersion, dependencySpec)
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.ResolveCommandFree(context.Background(), domain.SourceRef{Kind: "local", Value: repositoryRoot})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.Fetch(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}
	base.Subject = planSourceForSnapshot(snapshot)
	result := rebuildCLISBOMRun(t, base)
	if _, err := store.Write(result); err != nil {
		t.Fatal(err)
	}
	keyRoot := t.TempDir()
	_, _, _ = writeCLIKeyPair(t, keyRoot, "derived-signer")
	return derivedCLIFixture{
		dataRoot: dataRoot, manifestPath: manifestPath,
		keyPath:    filepath.Join(keyRoot, "derived-signer-private.pem"),
		trustPath:  filepath.Join(keyRoot, "derived-signer-public.pem"),
		bundlePath: filepath.Join(t.TempDir(), "derived-v2.tar"),
		result:     result,
	}
}

func (fixture derivedCLIFixture) attestArgs(keyPath, bundlePath string) []string {
	return []string{
		"--json", "--data-dir", fixture.dataRoot, "attest",
		"--run", fixture.result.RunID,
		"--derive-spdx", "--current-manifest", fixture.manifestPath,
		"--key", keyPath, "--out", bundlePath,
	}
}

func writeDerivedNPMFixture(t *testing.T, root, rootName, dependencyVersion, dependencySpec string) {
	t.Helper()
	packageJSON := map[string]any{
		"name": rootName, "version": "1.0.0",
		"dependencies": map[string]string{"left-pad": dependencySpec},
	}
	lockJSON := map[string]any{
		"name": rootName, "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{
				"name": rootName, "version": "1.0.0",
				"dependencies": map[string]string{"left-pad": dependencySpec},
			},
			"node_modules/left-pad": map[string]any{
				"name": "left-pad", "version": dependencyVersion,
				"resolved":  "https://registry.npmjs.org/left-pad/-/left-pad-" + dependencyVersion + ".tgz",
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64)),
			},
		},
	}
	for name, value := range map[string]any{"package.json": packageJSON, "package-lock.json": lockJSON} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func installDerivedFakeCommands(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"git", "npm", "node"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func derivedCLIApp(
	snapshot func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error),
) (App, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return App{
		Deps:  Dependencies{DerivedSnapshot: snapshot},
		Stdin: strings.NewReader(""), Stdout: stdout, Stderr: stderr,
	}, stdout, stderr
}

func assertDerivedPreKeyFailure(
	t *testing.T,
	exitCode, calls, wantCalls int,
	stdout, stderr *bytes.Buffer,
	missingKey, bundlePath string,
	wantCode domain.ErrorCode,
) {
	t.Helper()
	envelope := decodeEnvelope(t, stdout.Bytes())
	if calls != wantCalls || envelope.Error == nil || envelope.Error.Code != wantCode {
		t.Fatalf("exit=%d calls=%d envelope=%#v stderr=%s", exitCode, calls, envelope, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), missingKey) {
		t.Fatal("pre-key failure echoed missing private-key path")
	}
	if _, err := os.Lstat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("pre-key failure published bundle: %v", err)
	}
}
