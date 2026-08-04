package planner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/acquisition"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/manifest"
	"github.com/repopass/repopass/internal/runtimepolicy"
	"github.com/repopass/repopass/internal/structuredjson"
	"gopkg.in/yaml.v3"
)

func TestResolveRejectsMutableImage(t *testing.T) {
	document := validPlannerDocument()
	environment := document.Manifest.Spec.Environments["linux-node"]
	environment.BaseImage.Reference = "ghcr.io/repopass/fixtures/node:22"
	document.Manifest.Spec.Environments["linux-node"] = environment

	_, err := Resolve(document, plannerSnapshot(), "quickstart")
	if err == nil {
		t.Fatal("Resolve unexpectedly accepted a mutable base image")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeMutableBaseImage {
		t.Fatalf("Resolve error code = %q, want %q: %v", got, domain.CodeMutableBaseImage, err)
	}
}

func TestCheckLockDetectsSemanticDrift(t *testing.T) {
	document := validPlannerDocument()
	plan, err := Resolve(document, plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	lockPath := filepath.Join(t.TempDir(), "passport.lock.json")
	if err := WriteLock(lockPath, plan); err != nil {
		t.Fatalf("WriteLock: %v", err)
	}
	if err := CheckLock(lockPath, plan); err != nil {
		t.Fatalf("CheckLock(same plan): %v", err)
	}

	changed := plan
	changed.RuntimeVersion = "22.0.1"
	err = CheckLock(lockPath, changed)
	if err == nil {
		t.Fatal("CheckLock unexpectedly accepted a semantically changed plan")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanDrift {
		t.Fatalf("CheckLock error code = %q, want %q: %v", got, domain.CodePlanDrift, err)
	}
}

func TestCheckLockRejectsHistoricalResolvedPlanSchemas(t *testing.T) {
	plan, err := Resolve(
		validPlannerDocument(),
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.SchemaVersion != ResolvedPlanSchemaVersion {
		t.Fatalf(
			"resolved plan schemaVersion = %q, want %s",
			plan.SchemaVersion,
			ResolvedPlanSchemaVersion,
		)
	}
	if plan.Cleanup.ClassifierVersion != CleanupClassifierVersion ||
		plan.Cleanup.AllowedResidue == nil ||
		len(plan.Cleanup.AllowedResidue) != 0 {
		t.Fatalf("resolved cleanup contract = %#v", plan.Cleanup)
	}

	tests := []struct {
		name                 string
		file                 string
		schemaVersion        string
		driverVersion        string
		planDigest           string
		manifestDigest       string
		sourceIdentity       string
		journeyAssertionSize int
		cleanupPresent       bool
	}{
		{
			name:                 "Alpha.8 v1",
			file:                 "healthy-node-cli-alpha.8-v1.lock.json",
			schemaVersion:        "1",
			driverVersion:        "0.1.0",
			planDigest:           "sha256:4066c8f0cd5caf17473677ce4e8955c6c9c76d4a2dd5ba5dbfc94dcd0461390a",
			manifestDigest:       "sha256:3d80dea31aaab384a31b0197a8837eb4d164e4e2bdba3e591be16243d3c89115",
			sourceIdentity:       "sha256:4792433eed36ac2b686717262ac7b0e4054fb9f979d8f93990ce00324881461a",
			journeyAssertionSize: 3,
		},
		{
			name:                 "Alpha.9 v2",
			file:                 "healthy-node-cli-alpha.9-v2.lock.json",
			schemaVersion:        "2",
			driverVersion:        "0.2.0",
			planDigest:           "sha256:f6c0a4b7e8fb1659a93f2852c72280d54d96befcbd7cd8a210be74443ca8c1ca",
			manifestDigest:       "sha256:8cd5e43876b4c84c83649427205ec6ead04546effed0a60ead7497d8bb220c69",
			sourceIdentity:       "sha256:ec4cbdc096c7a56ea990f003f49b258cc482a8cb3865c4681e2f480a28adc011",
			journeyAssertionSize: 4,
		},
		{
			name:                 "Alpha.10 v3",
			file:                 "healthy-node-cli-alpha.10-v3.lock.json",
			schemaVersion:        "3",
			driverVersion:        "0.2.0",
			planDigest:           "sha256:60282529738d5591dc3b090e21879ff4050d7a689ac3f6ff9c42385d94075785",
			manifestDigest:       "sha256:8cd5e43876b4c84c83649427205ec6ead04546effed0a60ead7497d8bb220c69",
			sourceIdentity:       "sha256:ec4cbdc096c7a56ea990f003f49b258cc482a8cb3865c4681e2f480a28adc011",
			journeyAssertionSize: 4,
			cleanupPresent:       true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			historicalBytes, readErr := os.ReadFile(filepath.Join(
				"testdata",
				test.file,
			))
			if readErr != nil {
				t.Fatalf("read fixed %s lock: %v", test.name, readErr)
			}
			var historical struct {
				SchemaVersion        string            `json:"schemaVersion"`
				JourneyDriver        string            `json:"journeyDriver"`
				JourneyDriverVersion string            `json:"journeyDriverVersion"`
				ManifestDigest       string            `json:"manifestDigest"`
				PlanDigest           string            `json:"planDigest"`
				Source               domain.PlanSource `json:"source"`
				JourneyAssertions    []json.RawMessage `json:"journeyAssertions"`
				Cleanup              json.RawMessage   `json:"cleanup"`
			}
			if decodeErr := json.Unmarshal(
				historicalBytes,
				&historical,
			); decodeErr != nil {
				t.Fatalf("decode fixed %s lock: %v", test.name, decodeErr)
			}
			if historical.SchemaVersion != test.schemaVersion ||
				historical.JourneyDriver != "cli" ||
				historical.JourneyDriverVersion != test.driverVersion ||
				historical.ManifestDigest != test.manifestDigest ||
				historical.PlanDigest != test.planDigest ||
				historical.Source.Identity != test.sourceIdentity ||
				len(historical.JourneyAssertions) != test.journeyAssertionSize ||
				(historical.Cleanup != nil) != test.cleanupPresent {
				t.Fatalf(
					"fixed %s lock contract drifted: %#v",
					test.name,
					historical,
				)
			}

			var semantic map[string]any
			decoder := json.NewDecoder(
				strings.NewReader(string(historicalBytes)),
			)
			decoder.UseNumber()
			if decodeErr := decoder.Decode(&semantic); decodeErr != nil {
				t.Fatalf(
					"decode fixed %s semantic plan: %v",
					test.name,
					decodeErr,
				)
			}
			delete(semantic, "planDigest")
			computedDigest, digestErr := canonicaljson.Digest(semantic)
			if digestErr != nil {
				t.Fatalf("digest fixed %s lock: %v", test.name, digestErr)
			}
			if computedDigest != test.planDigest {
				t.Fatalf(
					"fixed %s semantic digest = %q, want %q",
					test.name,
					computedDigest,
					test.planDigest,
				)
			}

			lockPath := filepath.Join(t.TempDir(), "passport.lock.json")
			if writeErr := os.WriteFile(
				lockPath,
				historicalBytes,
				0o600,
			); writeErr != nil {
				t.Fatalf("write fixed %s lock: %v", test.name, writeErr)
			}
			for checkName, checkedPlan := range map[string]domain.ResolvedPlan{
				"current plan": plan,
				"historical plan": {
					SchemaVersion: historical.SchemaVersion,
				},
			} {
				checkErr := CheckLock(lockPath, checkedPlan)
				if got := domain.ErrorCodeOf(checkErr); got !=
					domain.CodePlanDrift {
					t.Fatalf(
						"CheckLock(%s) error code = %q, want %q: %v",
						checkName,
						got,
						domain.CodePlanDrift,
						checkErr,
					)
				}
			}
		})
	}
}

func TestCurrentAlpha25V4GoldenLockContract(t *testing.T) {
	const (
		wantSchemaVersion  = "4"
		wantManifestDigest = "sha256:8cd5e43876b4c84c83649427205ec6ead04546effed0a60ead7497d8bb220c69"
		wantSourceDigest   = "sha256:ec4cbdc096c7a56ea990f003f49b258cc482a8cb3865c4681e2f480a28adc011"
		wantPlanDigest     = "sha256:adced65f4677ecd2f7bc8f24ce063212e63a8bf74a4ffedd769afb540d1a94bc"
	)
	manifestPath, err := filepath.Abs(filepath.Join(
		"..",
		"..",
		"testdata",
		"fixtures",
		"healthy",
		"healthy-node-cli",
		"repo-passport.yml",
	))
	if err != nil {
		t.Fatalf("resolve healthy manifest: %v", err)
	}
	document, err := manifest.Load(manifestPath)
	if err != nil {
		t.Fatalf("load healthy manifest: %v", err)
	}
	if document.Digest != wantManifestDigest {
		t.Fatalf(
			"healthy manifest digest = %q, want %q",
			document.Digest,
			wantManifestDigest,
		)
	}
	sourceRoot := filepath.Dir(manifestPath)
	provider := acquisition.NewLocalProvider()
	// This golden locks directory-source content semantics. Ignore any ambient
	// parent Git checkout so the lock remains stable across repository commits.
	resolved, err := provider.ResolveCommandFree(
		context.Background(),
		domain.SourceRef{Kind: "local", Value: sourceRoot},
	)
	if err != nil {
		t.Fatalf("resolve healthy source: %v", err)
	}
	snapshot, err := provider.Fetch(context.Background(), resolved)
	if err != nil {
		t.Fatalf("snapshot healthy source: %v", err)
	}
	if snapshot.Identity != wantSourceDigest ||
		snapshot.TreeDigest != wantSourceDigest {
		t.Fatalf("healthy source digest drifted: %#v", snapshot)
	}
	plan, err := Resolve(
		document,
		snapshot,
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve healthy Alpha.25 plan: %v", err)
	}
	if plan.SchemaVersion != wantSchemaVersion ||
		plan.ManifestDigest != wantManifestDigest ||
		plan.Source.Identity != wantSourceDigest ||
		plan.Source.TreeDigest != wantSourceDigest ||
		plan.PlanDigest != wantPlanDigest {
		t.Fatalf("current Alpha.25 plan identity drifted: %#v", plan)
	}
	if plan.Cleanup.ClassifierVersion != CleanupClassifierVersion ||
		len(plan.Cleanup.AllowedResidue) != 1 ||
		plan.Cleanup.AllowedResidue[0] != "/outputs/**" ||
		!containsExactString(
			plan.RequiredRunnerFeatures,
			"cleanup-residue-classification",
		) {
		t.Fatalf("current Alpha.25 cleanup contract drifted: %#v", plan)
	}

	goldenPath := filepath.Join(
		"testdata",
		"healthy-node-cli-alpha.25-v4.lock.json",
	)
	if err := CheckLock(goldenPath, plan); err != nil {
		t.Fatalf("CheckLock current Alpha.25 golden: %v", err)
	}
	goldenBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read current Alpha.25 golden: %v", err)
	}
	var semantic map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(goldenBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&semantic); err != nil {
		t.Fatalf("decode current Alpha.25 golden: %v", err)
	}
	delete(semantic, "planDigest")
	computedDigest, err := canonicaljson.Digest(semantic)
	if err != nil {
		t.Fatalf("digest current Alpha.25 golden: %v", err)
	}
	if computedDigest != wantPlanDigest {
		t.Fatalf(
			"current Alpha.25 golden digest = %q, want %q",
			computedDigest,
			wantPlanDigest,
		)
	}
	legacyV4 := filepath.Join(
		"testdata",
		"healthy-node-cli-alpha.15-v4.lock.json",
	)
	if err := CheckLock(legacyV4, plan); domain.ErrorCodeOf(err) !=
		domain.CodePlanDrift {
		t.Fatalf("Alpha.15 observer lock did not drift: %v", err)
	}
}

func TestExecutableMinimalPublicSPDXFixtureValidatesAndPlans(t *testing.T) {
	manifestPath, err := filepath.Abs(filepath.Join(
		"..", "..", "testdata", "fixtures", "healthy", "minimal-public-spdx", "repo-passport.yml",
	))
	if err != nil {
		t.Fatalf("resolve SPDX-selected fixture manifest: %v", err)
	}
	document, err := manifest.Load(manifestPath)
	if err != nil {
		t.Fatalf("validate SPDX-selected fixture manifest: %v", err)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.Resolve(context.Background(), domain.SourceRef{
		Kind: "local", Value: filepath.Dir(manifestPath),
	})
	if err != nil {
		t.Fatalf("resolve SPDX-selected fixture source: %v", err)
	}
	snapshot, err := provider.Fetch(context.Background(), resolved)
	if err != nil {
		t.Fatalf("inventory SPDX-selected fixture source: %v", err)
	}
	hasSPDX := false
	for _, entry := range snapshot.Inventory {
		if entry.Path == "sbom.spdx.json" {
			hasSPDX = true
			break
		}
	}
	if !hasSPDX {
		t.Fatal("SPDX-selected executable fixture source omits sbom.spdx.json")
	}
	plan, err := Resolve(document, snapshot, "quickstart")
	if err != nil {
		t.Fatalf("plan SPDX-selected fixture: %v", err)
	}
	wantInclude := []string{"normalized-observations", "sbom", "verification-summary"}
	if plan.SchemaVersion != "4" || plan.Evidence.Profile != "minimal-public" ||
		!slices.Equal(plan.Evidence.Include, wantInclude) ||
		!slices.Equal(plan.Evidence.Exclude, []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"}) {
		t.Fatalf("SPDX-selected fixture plan evidence = %#v", plan.Evidence)
	}
}

func TestResolveBindsCleanupContractIntoPlanDigest(t *testing.T) {
	emptyPlan, err := Resolve(
		validPlannerDocument(),
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve empty cleanup contract: %v", err)
	}
	if emptyPlan.Cleanup.ClassifierVersion != CleanupClassifierVersion ||
		emptyPlan.Cleanup.AllowedResidue == nil ||
		len(emptyPlan.Cleanup.AllowedResidue) != 0 {
		t.Fatalf("empty resolved cleanup contract = %#v", emptyPlan.Cleanup)
	}
	if !containsExactString(
		emptyPlan.RequiredRunnerFeatures,
		"cleanup-residue-classification",
	) {
		t.Fatalf(
			"cleanup classification feature is absent: %v",
			emptyPlan.RequiredRunnerFeatures,
		)
	}

	outputsDocument := validPlannerDocument()
	outputsScenario := outputsDocument.Manifest.Spec.Scenarios["quickstart"]
	outputsScenario.Verification.Cleanup.AllowedResidue =
		[]string{"/outputs/**"}
	outputsDocument.Manifest.Spec.Scenarios["quickstart"] = outputsScenario
	outputsPlan, err := Resolve(
		outputsDocument,
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve /outputs cleanup contract: %v", err)
	}
	if outputsPlan.Cleanup.ClassifierVersion != CleanupClassifierVersion ||
		len(outputsPlan.Cleanup.AllowedResidue) != 1 ||
		outputsPlan.Cleanup.AllowedResidue[0] != "/outputs/**" {
		t.Fatalf("resolved /outputs cleanup contract = %#v", outputsPlan.Cleanup)
	}
	if outputsPlan.PlanDigest == emptyPlan.PlanDigest {
		t.Fatal("allowed residue did not change the canonical plan digest")
	}
	lockPath := filepath.Join(t.TempDir(), "passport.lock.json")
	if err := WriteLock(lockPath, outputsPlan); err != nil {
		t.Fatalf("WriteLock cleanup contract: %v", err)
	}
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read cleanup lock: %v", err)
	}
	var locked struct {
		Cleanup *domain.PlanCleanup `json:"cleanup"`
	}
	if err := json.Unmarshal(lockBytes, &locked); err != nil {
		t.Fatalf("decode cleanup lock: %v", err)
	}
	if locked.Cleanup == nil ||
		locked.Cleanup.ClassifierVersion != CleanupClassifierVersion ||
		len(locked.Cleanup.AllowedResidue) != 1 ||
		locked.Cleanup.AllowedResidue[0] != "/outputs/**" {
		t.Fatalf("locked cleanup contract = %#v", locked.Cleanup)
	}
	if err := CheckLock(lockPath, outputsPlan); err != nil {
		t.Fatalf("CheckLock current cleanup contract: %v", err)
	}

	classifierDrift := emptyPlan
	classifierDrift.Cleanup.ClassifierVersion = "0.1.1"
	classifierDigest, err := digestPlan(classifierDrift)
	if err != nil {
		t.Fatalf("digest classifier drift: %v", err)
	}
	if classifierDigest == emptyPlan.PlanDigest {
		t.Fatal("cleanup classifier version did not change the plan digest")
	}
}

func TestResolveBindsJourneyAssertionsAndThreshold(t *testing.T) {
	plan, err := Resolve(validPlannerDocument(), plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if plan.SuccessThreshold != 1 {
		t.Fatalf("SuccessThreshold = %d, want 1", plan.SuccessThreshold)
	}
	if plan.JourneyDriverVersion != CLIJourneyDriverVersion {
		t.Fatalf(
			"CLI journeyDriverVersion = %q, want %q",
			plan.JourneyDriverVersion,
			CLIJourneyDriverVersion,
		)
	}
	if len(plan.JourneyAssertions) != 1 {
		t.Fatalf("JourneyAssertions length = %d, want 1", len(plan.JourneyAssertions))
	}
	assertion := plan.JourneyAssertions[0]
	if assertion.ID != "version-exited" || assertion.ExitCode == nil || *assertion.ExitCode != 0 {
		t.Fatalf("unexpected resolved assertion: %#v", assertion)
	}
}

func TestResolveBindsResourceObserverImplementationVersion(t *testing.T) {
	document := validPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Verification.RequiredObservers = append(
		scenario.Verification.RequiredObservers,
		"resource-usage",
	)
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	plan, err := Resolve(document, plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := plan.ObserverVersions["resource-usage"]; got != ResourceObserverVersion {
		t.Fatalf(
			"resource observer version = %q, want %q",
			got,
			ResourceObserverVersion,
		)
	}
	if got := plan.ObserverVersions["filesystem-write"]; got !=
		FilesystemObserverVersion {
		t.Fatalf(
			"filesystem observer version = %q, want %q",
			got,
			FilesystemObserverVersion,
		)
	}
	if got := plan.ObserverVersions["process-exec"]; got != ObserverVersion {
		t.Fatalf(
			"unchanged process observer version = %q, want %q",
			got,
			ObserverVersion,
		)
	}
}

func TestResolveBindsPortObserverImplementationVersion(t *testing.T) {
	plan, err := Resolve(
		validHTTPPlannerDocument(),
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve HTTP journey: %v", err)
	}
	if got := plan.ObserverVersions["port-listen"]; got != PortObserverVersion {
		t.Fatalf(
			"port observer version = %q, want %q",
			got,
			PortObserverVersion,
		)
	}
}

func TestResolveBindsApprovedWorkloadArchitectureAndRejectsUnapprovedPlatform(t *testing.T) {
	amd64Plan, err := Resolve(validPlannerDocument(), plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve(amd64): %v", err)
	}
	if !containsExactString(
		amd64Plan.RequiredRunnerFeatures,
		"platform:linux/amd64",
	) {
		t.Fatalf(
			"amd64 platform feature is absent: %v",
			amd64Plan.RequiredRunnerFeatures,
		)
	}

	arm64Document := validPlannerDocument()
	environment := arm64Document.Manifest.Spec.Environments["linux-node"]
	environment.Platform.Architecture = "arm64"
	arm64Document.Manifest.Spec.Environments["linux-node"] = environment
	arm64Plan, err := Resolve(
		arm64Document,
		plannerSnapshot(),
		"quickstart",
	)
	if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf(
			"Resolve(arm64) error code = %q, want %q: %v",
			got,
			domain.CodeRunnerFeatureUnavailable,
			err,
		)
	}
	if arm64Plan.PlanDigest != "" {
		t.Fatalf("unapproved arm64 tuple produced a plan: %#v", arm64Plan)
	}
}

func TestResolveRejectsUnapprovedPinnedRuntimeTuple(t *testing.T) {
	document := validPlannerDocument()
	environment := document.Manifest.Spec.Environments["linux-node"]
	environment.BaseImage.Reference = "docker.io/library/node:22.23.1-bookworm-slim@sha256:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	document.Manifest.Spec.Environments["linux-node"] = environment

	plan, err := Resolve(document, plannerSnapshot(), "quickstart")
	if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf(
			"Resolve error code = %q, want %q: %v",
			got,
			domain.CodeRunnerFeatureUnavailable,
			err,
		)
	}
	if plan.PlanDigest != "" {
		t.Fatalf("unapproved runtime tuple produced a plan: %#v", plan)
	}
}

func TestPolicyBundleDigestBindsApprovedRuntimePolicy(t *testing.T) {
	plan, err := Resolve(validPlannerDocument(), plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	expected, err := canonicaljson.Digest(map[string]any{
		"id": "baseline-v1", "version": "1", "rules": []string{
			"runtime-network-deny",
			"read-only-source",
			"no-host-secrets",
			"required-observer-coverage",
			"resource-limit-enforcement",
		},
		"runtimePolicy": runtimepolicy.Binding(),
	})
	if err != nil {
		t.Fatalf("canonical policy digest: %v", err)
	}
	if plan.PolicyBundleDigest != expected {
		t.Fatalf(
			"PolicyBundleDigest = %q, want runtime-policy-bound %q",
			plan.PolicyBundleDigest,
			expected,
		)
	}
}

func TestOverrideRepeatsCannotWeakenManifestPolicy(t *testing.T) {
	plan, err := Resolve(validPlannerDocument(), plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	originalDigest := plan.PlanDigest
	extended, err := OverrideRepeats(plan, 3)
	if err != nil {
		t.Fatalf("OverrideRepeats(3): %v", err)
	}
	if extended.RepeatCount != 3 || extended.SuccessThreshold != 3 {
		t.Fatalf("extended repeat policy = %d/%d, want 3/3", extended.SuccessThreshold, extended.RepeatCount)
	}
	if extended.PlanDigest == originalDigest {
		t.Fatal("repeat override did not change the bound plan digest")
	}

	strict := plan
	strict.RepeatCount = 3
	strict.SuccessThreshold = 3
	if _, err := OverrideRepeats(strict, 1); err == nil {
		t.Fatal("OverrideRepeats unexpectedly weakened a 3/3 manifest to 1 run")
	}
}

func TestResolveRejectsRecognizedButUnimplementedCLIProfileFeatures(t *testing.T) {
	required := false
	tests := []struct {
		name   string
		mutate func(*manifest.DriverSpec)
	}{
		{
			name: "stdin fixture",
			mutate: func(driver *manifest.DriverSpec) {
				driver.StdinFixture = "fixtures/stdin.txt"
			},
		},
		{
			name: "optional assertion",
			mutate: func(driver *manifest.DriverSpec) {
				driver.Assertions[0].Required = &required
			},
		},
		{
			name: "json file assertion",
			mutate: func(driver *manifest.DriverSpec) {
				driver.Assertions[0].ExitCode = nil
				driver.Assertions[0].JSONFile = &manifest.JSONFileAssertion{
					Path:   "/outputs/result.json",
					Schema: "schemas/result.schema.json",
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			test.mutate(&scenario.Phases.Exercise.Driver)
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			_, err := Resolve(document, plannerSnapshot(), "quickstart")
			if err == nil {
				t.Fatal("Resolve unexpectedly ignored an unavailable CLI feature")
			}
			if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
				t.Fatalf("Resolve error code = %q, want %q: %v", got, domain.CodeRunnerFeatureUnavailable, err)
			}
		})
	}
}

func TestResolveMaterializesHTTPServiceJourney(t *testing.T) {
	plan, err := Resolve(
		validHTTPPlannerDocument(),
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve HTTP journey: %v", err)
	}
	if plan.HTTPJourney == nil || plan.HTTPJourney.ServiceID != "app" {
		t.Fatalf("HTTPJourney service binding = %#v", plan.HTTPJourney)
	}
	if plan.JourneyDriverVersion != HTTPJourneyDriverVersion {
		t.Fatalf(
			"HTTP journeyDriverVersion = %q, want %q",
			plan.JourneyDriverVersion,
			HTTPJourneyDriverVersion,
		)
	}
	if len(plan.HTTPJourney.Steps) != 3 {
		t.Fatalf("HTTPJourney steps = %d, want 3", len(plan.HTTPJourney.Steps))
	}
	request := plan.HTTPJourney.Steps[0].Request
	if request == nil ||
		request.ID != "echo" ||
		request.Method != "post" ||
		request.URL != "http://127.0.0.1:8080/echo" ||
		request.Timeout != "5s" ||
		request.Headers["x-trace"] != "alpha-two" ||
		string(request.JSON) != `{"message":"hello"}` ||
		request.Body != nil {
		t.Fatalf("resolved HTTP request = %#v", request)
	}
	if plan.HTTPJourney.Steps[1].AssertionID != "echo-ok" ||
		plan.HTTPJourney.Steps[2].AssertionID != "output-created" {
		t.Fatalf("ordered assertion references = %#v", plan.HTTPJourney.Steps)
	}
	if len(plan.JourneyAssertions) != 2 {
		t.Fatalf("JourneyAssertions = %d, want 2", len(plan.JourneyAssertions))
	}
	response := plan.JourneyAssertions[0].Response
	if response == nil ||
		response.RequestID != "echo" ||
		response.Status == nil ||
		*response.Status != 200 ||
		response.BodyContains == nil ||
		*response.BodyContains != `"received"` {
		t.Fatalf("resolved response assertion = %#v", response)
	}
	if plan.JourneyAssertions[1].FileExists != "/outputs/request.json" {
		t.Fatalf("resolved file assertion = %#v", plan.JourneyAssertions[1])
	}

	var service, signal *domain.PlanCommand
	for index := range plan.Commands {
		command := &plan.Commands[index]
		switch command.Role {
		case "service":
			service = command
		case "signal":
			signal = command
		}
	}
	if service == nil ||
		service.ID != "app" ||
		service.Readiness == nil ||
		service.Readiness.URL != "http://127.0.0.1:8080/health" ||
		service.Readiness.Status != 200 ||
		service.Readiness.Timeout != "10s" {
		t.Fatalf("resolved service command = %#v", service)
	}
	if signal == nil ||
		signal.Signal == nil ||
		signal.Signal.Target != "app" ||
		signal.Signal.Type != "term" ||
		signal.Signal.GracePeriod != "2s" {
		t.Fatalf("resolved service signal = %#v", signal)
	}
	for _, feature := range []string{
		"background-service",
		"loopback-http-driver",
		"service-signal",
	} {
		if !containsExactString(plan.RequiredRunnerFeatures, feature) {
			t.Fatalf("required feature %q is absent: %v", feature, plan.RequiredRunnerFeatures)
		}
	}
	listeners := plan.Capabilities[domain.PhaseRun].Ports.Listen
	if len(listeners) != 1 || listeners[0].Protocol != "tcp" {
		t.Fatalf("resolved HTTP listener = %#v", listeners)
	}
}

func TestResolvePreservesExplicitEmptyHTTPBodyAndNullJSON(t *testing.T) {
	empty := ""
	tests := []struct {
		name         string
		requestYAML  string
		wantBody     *string
		wantJSONText string
	}{
		{
			name: "null JSON",
			requestYAML: `
id: echo
method: post
url: http://127.0.0.1:8080/echo
json: null
timeout: 5s
`,
			wantJSONText: "null",
		},
		{
			name: "empty text body",
			requestYAML: `
id: echo
method: post
url: http://127.0.0.1:8080/echo
body: ""
timeout: 5s
`,
			wantBody: &empty,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request manifest.HTTPRequest
			if err := yaml.Unmarshal(
				[]byte(test.requestYAML),
				&request,
			); err != nil {
				t.Fatalf("decode HTTP request: %v", err)
			}
			document := validHTTPPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			scenario.Phases.Exercise.Driver.Steps[0].Request = &request
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			plan, err := Resolve(document, plannerSnapshot(), "quickstart")
			if err != nil {
				t.Fatalf("Resolve explicit request presence: %v", err)
			}
			resolved := plan.HTTPJourney.Steps[0].Request
			if resolved == nil {
				t.Fatal("resolved HTTP request is absent")
			}
			if test.wantBody == nil {
				if resolved.Body != nil {
					t.Fatalf("resolved body = %#v, want absent", resolved.Body)
				}
			} else if resolved.Body == nil ||
				*resolved.Body != *test.wantBody {
				t.Fatalf(
					"resolved body = %#v, want %q",
					resolved.Body,
					*test.wantBody,
				)
			}
			if string(resolved.JSON) != test.wantJSONText {
				t.Fatalf(
					"resolved JSON = %q, want %q",
					resolved.JSON,
					test.wantJSONText,
				)
			}
		})
	}
}

func TestValidateHTTPAlphaExecutionContractRejectsFreezeDrift(
	t *testing.T,
) {
	document := validHTTPPlannerDocument()
	base := document.Manifest.Spec.Scenarios["quickstart"]
	if err := validateHTTPAlphaExecutionContract(
		"quickstart",
		base,
	); err != nil {
		t.Fatalf("valid HTTP contract was rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*manifest.ScenarioSpec)
	}{
		{
			name: "file assertion outside outputs",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[2].
					Assert.FileExists = "/workspace/late.json"
			},
		},
		{
			name: "signal is not final",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Cleanup.Steps = append(
					scenario.Phases.Cleanup.Steps,
					manifest.PhaseStep{
						ID: "after-signal",
						Run: &manifest.RunAction{
							Command: []string{"node", "-e", "0"},
						},
					},
				)
			},
		},
		{
			name: "grace exceeds alpha limit",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].
					Signal.GracePeriod = "10s1ns"
			},
		},
		{
			name: "URL exceeds 2048 bytes",
			mutate: func(scenario *manifest.ScenarioSpec) {
				prefix := "http://127.0.0.1:8080/"
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					prefix + strings.Repeat(
						"a",
						domain.AlphaHTTPMaxURLBytes-len(prefix)+1,
					)
			},
		},
		{
			name: "leading zero URL port",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL =
					"http://127.0.0.1:08080/echo"
			},
		},
		{
			name: "129 journey steps",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					plannerHTTPBoundarySteps(1, domain.AlphaHTTPMaxJourneySteps+1)
			},
		},
		{
			name: "33 request steps",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					plannerHTTPBoundarySteps(domain.AlphaHTTPMaxRequestSteps+1, 34)
			},
		},
		{
			name: "65 effective JSON headers",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					plannerHTTPHeaderSet(64)
			},
		},
		{
			name: "header aggregate exceeds 65536 bytes",
			mutate: func(scenario *manifest.ScenarioSpec) {
				headers := plannerExactHTTPHeaderAggregate()
				headers["h"] += "x"
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					headers
			},
		},
		{
			name: "Unicode request body exceeds 1 MiB",
			mutate: func(scenario *manifest.ScenarioSpec) {
				request := scenario.Phases.Exercise.Driver.Steps[0].Request
				request.JSON = nil
				request.Body = strings.Repeat("界", 349525) + "xx"
			},
		},
		{
			name: "canonical JSON exceeds 1 MiB",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.JSON =
					map[string]any{
						"value": strings.Repeat(
							"x",
							domain.AlphaHTTPMaxRequestBodyBytes-11,
						),
					}
			},
		},
		{
			name: "response body match exceeds 1 MiB",
			mutate: func(scenario *manifest.ScenarioSpec) {
				body := strings.Repeat(
					"x",
					domain.AlphaHTTPMaxResponseMatchBytes+1,
				)
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.BodyContains = &body
			},
		},
		{
			name: "response header match exceeds 8192 bytes",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.Header = &manifest.HeaderAssertion{
					Name: "x-result",
					Contains: strings.Repeat(
						"x",
						domain.AlphaHTTPMaxHeaderValueBytes+1,
					),
				}
			},
		},
		{
			name: "output path exceeds 4096 bytes",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[2].Assert.FileExists =
					"/outputs/" + strings.Repeat("界", 1362) + "xx"
			},
		},
		{
			name: "readiness timeout uses nanoseconds",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Timeout = "1ns"
			},
		},
		{
			name: "request timeout uses fractional millisecond",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Timeout =
					"1.5ms"
			},
		},
		{
			name: "kill signal omits grace",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].Signal.Type = "kill"
				scenario.Phases.Cleanup.Steps[0].Signal.GracePeriod = ""
			},
		},
		{
			name: "readiness status 199",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Status = 199
			},
		},
		{
			name: "response status 199",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.Status = 199
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := validHTTPPlannerDocument().
				Manifest.Spec.Scenarios["quickstart"]
			test.mutate(&scenario)
			err := validateHTTPAlphaExecutionContract(
				"quickstart",
				scenario,
			)
			if got := domain.ErrorCodeOf(err); got !=
				domain.CodePlanUnresolved {
				t.Fatalf(
					"contract error code = %q, want %q: %v",
					got,
					domain.CodePlanUnresolved,
					err,
				)
			}
		})
	}
}

func TestValidateHTTPAlphaExecutionContractAcceptsBoundaries(t *testing.T) {
	prefix := "http://127.0.0.1:8080/"
	exactURL := prefix + strings.Repeat(
		"a",
		domain.AlphaHTTPMaxURLBytes-len(prefix),
	)
	exactOutput := "/outputs/" + strings.Repeat("界", 1362) + "x"
	tests := []struct {
		name   string
		mutate func(*manifest.ScenarioSpec)
	}{
		{
			name: "2048 byte URL and explicit status 200",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.URL = exactURL
				scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response.Status = 200
			},
		},
		{
			name: "128 steps",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					plannerHTTPBoundarySteps(1, domain.AlphaHTTPMaxJourneySteps)
			},
		},
		{
			name: "32 requests",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps =
					plannerHTTPBoundarySteps(domain.AlphaHTTPMaxRequestSteps, 33)
			},
		},
		{
			name: "64 effective JSON headers",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					plannerHTTPHeaderSet(63)
			},
		},
		{
			name: "65536 aggregate bytes",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers =
					plannerExactHTTPHeaderAggregate()
			},
		},
		{
			name: "request and response byte boundaries",
			mutate: func(scenario *manifest.ScenarioSpec) {
				request := scenario.Phases.Exercise.Driver.Steps[0].Request
				request.JSON = nil
				request.Body = strings.Repeat("界", 349525) + "x"
				response := scenario.Phases.Exercise.Driver.Steps[1].
					Assert.Response
				body := strings.Repeat(
					"x",
					domain.AlphaHTTPMaxResponseMatchBytes,
				)
				response.BodyContains = &body
				response.Header = &manifest.HeaderAssertion{
					Name: "x-result",
					Contains: strings.Repeat(
						"x",
						domain.AlphaHTTPMaxHeaderValueBytes,
					),
				}
			},
		},
		{
			name: "canonical JSON byte boundary",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.JSON =
					map[string]any{
						"value": strings.Repeat(
							"x",
							domain.AlphaHTTPMaxRequestBodyBytes-12,
						),
					}
			},
		},
		{
			name: "4096 byte Unicode output and 1ms durations",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[2].Assert.FileExists =
					exactOutput
				scenario.Phases.Run.Service.Readiness.HTTP.Timeout = "1ms"
				scenario.Phases.Exercise.Driver.Steps[0].Request.Timeout = "1ms"
				scenario.Phases.Cleanup.Steps[0].Signal.GracePeriod = "1ms"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := validHTTPPlannerDocument().
				Manifest.Spec.Scenarios["quickstart"]
			test.mutate(&scenario)
			if err := validateHTTPAlphaExecutionContract(
				"quickstart",
				scenario,
			); err != nil {
				t.Fatalf("valid boundary was rejected: %v", err)
			}
		})
	}
}

func TestResolveHTTPPlanDigestBindsEveryExecutionContract(t *testing.T) {
	baseline, err := Resolve(
		validHTTPPlannerDocument(),
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve baseline HTTP journey: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*manifest.ScenarioSpec)
	}{
		{
			name: "service argv",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Run.Service.Command =
					[]string{"node", "/workspace/other-server.mjs"}
			},
		},
		{
			name: "readiness",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Run.Service.Readiness.HTTP.Status = 204
			},
		},
		{
			name: "request",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[0].Request.Headers["X-Trace"] =
					"changed"
			},
		},
		{
			name: "response assertion",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.Status = 201
			},
		},
		{
			name: "ordered assertion step",
			mutate: func(scenario *manifest.ScenarioSpec) {
				steps := scenario.Phases.Exercise.Driver.Steps
				steps[1], steps[2] = steps[2], steps[1]
			},
		},
		{
			name: "cleanup signal",
			mutate: func(scenario *manifest.ScenarioSpec) {
				scenario.Phases.Cleanup.Steps[0].Signal.Type = "int"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validHTTPPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			test.mutate(&scenario)
			document.Manifest.Spec.Scenarios["quickstart"] = scenario
			changed, resolveErr := Resolve(
				document,
				plannerSnapshot(),
				"quickstart",
			)
			if resolveErr != nil {
				t.Fatalf("Resolve changed HTTP journey: %v", resolveErr)
			}
			if changed.PlanDigest == baseline.PlanDigest {
				t.Fatal("HTTP semantic change did not alter planDigest")
			}
		})
	}
}

func TestResolveFailsClosedForOptionalHTTPAssertion(t *testing.T) {
	required := false
	document := validHTTPPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Phases.Exercise.Driver.Steps[1].Assert.Required = &required
	document.Manifest.Spec.Scenarios["quickstart"] = scenario
	plan, resolveErr := Resolve(
		document,
		plannerSnapshot(),
		"quickstart",
	)
	if got := domain.ErrorCodeOf(resolveErr); got != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf(
			"Resolve error code = %q, want %q: %v",
			got,
			domain.CodeRunnerFeatureUnavailable,
			resolveErr,
		)
	}
	if plan.PlanDigest != "" {
		t.Fatalf("unsupported HTTP assertion produced a plan: %#v", plan)
	}
}

func TestResolveBindsStructuredHTTPAssertions(t *testing.T) {
	const schemaPath = "schemas/response.schema.json"
	schemaRaw := []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["received"],
  "properties": {"received": {"type": "integer"}}
}`)
	snapshot := plannerSchemaSnapshot(t, schemaPath, schemaRaw)
	document := validHTTPPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	response := scenario.Phases.Exercise.Driver.Steps[1].Assert.Response
	response.JSONPath = &manifest.JSONPathAssertion{
		Path:   `$.received`,
		Equals: json.Number("9007199254740993"),
	}
	response.JSONSchema = schemaPath
	fileAssertion := scenario.Phases.Exercise.Driver.Steps[2].Assert
	fileAssertion.FileExists = ""
	fileAssertion.JSONFile = &manifest.JSONFileAssertion{
		Path:   "/outputs/request.json",
		Schema: schemaPath,
	}
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	plan, err := Resolve(document, snapshot, "quickstart")
	if err != nil {
		t.Fatalf("Resolve structured HTTP assertions: %v", err)
	}
	if len(plan.JourneyAssertions) != 2 {
		t.Fatalf(
			"JourneyAssertions length = %d, want 2",
			len(plan.JourneyAssertions),
		)
	}
	responsePlan := plan.JourneyAssertions[0].Response
	if responsePlan == nil || responsePlan.JSONPath == nil {
		t.Fatalf("resolved JSONPath is absent: %#v", responsePlan)
	}
	if got := string(responsePlan.JSONPath.Equals); got != "9007199254740993" {
		t.Fatalf("resolved JSONPath equals = %q, want exact large integer", got)
	}
	if responsePlan.JSONSchema == nil {
		t.Fatalf("resolved response schema is absent: %#v", responsePlan)
	}
	jsonFile := plan.JourneyAssertions[1].JSONFile
	if jsonFile == nil || jsonFile.Path != "/outputs/request.json" {
		t.Fatalf("resolved JSON-file assertion = %#v", jsonFile)
	}
	wantDigest := plannerSchemaDigest(schemaRaw)
	for name, resolved := range map[string]domain.PlanJSONSchemaRef{
		"response": *responsePlan.JSONSchema,
		"jsonFile": jsonFile.Schema,
	} {
		if resolved.Path != schemaPath ||
			resolved.Digest != wantDigest ||
			resolved.Dialect != domain.AlphaJSONSchemaDialect ||
			resolved.ValidatorVersion != domain.AlphaJSONValidatorVersion {
			t.Fatalf("%s schema binding = %#v", name, resolved)
		}
	}

	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal resolved plan: %v", err)
	}
	if !strings.Contains(string(rawPlan), `"equals":9007199254740993`) {
		t.Fatalf("resolved plan lost exact large integer: %s", rawPlan)
	}
}

func TestResolveBindsCLIStdoutJSONSchema(t *testing.T) {
	const schemaPath = ".repopass/schemas/stdout.schema.json"
	schemaRaw := []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["message"],
  "properties": {"message": {"type": "string"}}
}`)
	snapshot := plannerSchemaSnapshot(t, schemaPath, schemaRaw)
	document := validPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	assertion := &scenario.Phases.Exercise.Driver.Assertions[0]
	assertion.ExitCode = nil
	assertion.StdoutJSONSchema = schemaPath
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	plan, err := Resolve(document, snapshot, "quickstart")
	if err != nil {
		t.Fatalf("Resolve CLI stdout JSON Schema assertion: %v", err)
	}
	if plan.SchemaVersion != ResolvedPlanSchemaVersion {
		t.Fatalf(
			"resolved plan schemaVersion = %q, want %s",
			plan.SchemaVersion,
			ResolvedPlanSchemaVersion,
		)
	}
	if len(plan.JourneyAssertions) != 1 {
		t.Fatalf(
			"JourneyAssertions length = %d, want 1",
			len(plan.JourneyAssertions),
		)
	}
	resolved := plan.JourneyAssertions[0].StdoutJSONSchema
	if resolved == nil {
		t.Fatalf(
			"resolved stdout JSON Schema binding is absent: %#v",
			plan.JourneyAssertions[0],
		)
	}
	if resolved.Path != schemaPath ||
		resolved.Digest != plannerSchemaDigest(schemaRaw) ||
		resolved.Dialect != domain.AlphaJSONSchemaDialect ||
		resolved.ValidatorVersion != domain.AlphaJSONValidatorVersion {
		t.Fatalf("stdout JSON Schema binding = %#v", resolved)
	}

	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal resolved plan: %v", err)
	}
	if !strings.Contains(string(rawPlan), `"stdoutJsonSchema"`) {
		t.Fatalf("resolved plan omitted stdout JSON Schema binding: %s", rawPlan)
	}
}

func TestResolveRejectsUnsafeCLIStdoutJSONSchema(t *testing.T) {
	const schemaPath = "schemas/stdout.schema.json"
	validSchema := []byte(`{"type":"object"}`)
	tests := []struct {
		name     string
		wantCode domain.ErrorCode
		snapshot func(*testing.T) domain.SourceSnapshot
	}{
		{
			name:     "missing inventory entry",
			wantCode: domain.CodeSourceNotFound,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				return domain.SourceSnapshot{Root: t.TempDir()}
			},
		},
		{
			name:     "source digest mismatch",
			wantCode: domain.CodeSourceDigestMismatch,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				result := plannerSchemaSnapshot(t, schemaPath, validSchema)
				result.Inventory[0].Digest =
					plannerSchemaDigest([]byte(`{"type":"array"}`))
				return result
			},
		},
		{
			name:     "external schema reference",
			wantCode: domain.CodePlanUnresolved,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				return plannerSchemaSnapshot(
					t,
					schemaPath,
					[]byte(`{"$ref":"https://example.com/schema.json"}`),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			assertion := &scenario.Phases.Exercise.Driver.Assertions[0]
			assertion.ExitCode = nil
			assertion.StdoutJSONSchema = schemaPath
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			plan, err := Resolve(document, test.snapshot(t), "quickstart")
			if got := domain.ErrorCodeOf(err); got != test.wantCode {
				t.Fatalf(
					"Resolve error code = %q, want %q: %v",
					got,
					test.wantCode,
					err,
				)
			}
			if plan.PlanDigest != "" {
				t.Fatalf("unsafe stdout schema produced a plan: %#v", plan)
			}
		})
	}
}

func TestValidSchemaRepositoryPathRejectsOverlongSegment(t *testing.T) {
	if !validSchemaRepositoryPath(
		"schemas/" + strings.Repeat("a", 255),
	) {
		t.Fatal("validSchemaRepositoryPath rejected a 255-byte segment")
	}
	if validSchemaRepositoryPath(
		"schemas/" + strings.Repeat("a", 256),
	) {
		t.Fatal("validSchemaRepositoryPath accepted a 256-byte segment")
	}
}

func TestResolvePreservesJSONPathNull(t *testing.T) {
	document := validHTTPPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.JSONPath =
		&manifest.JSONPathAssertion{
			Path:   "$.optional",
			Equals: nil,
		}
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	plan, err := Resolve(document, plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve JSON null equality: %v", err)
	}
	got := plan.JourneyAssertions[0].Response.JSONPath.Equals
	if string(got) != "null" {
		t.Fatalf("resolved JSONPath equals = %q, want null", got)
	}
}

func TestResolveAppliesExecutionLimitsToJSONPathExpectedValue(t *testing.T) {
	limits := structuredjson.DefaultInstanceDecodeLimits()
	nestedArray := func(depth int) any {
		var value any
		for range depth {
			value = []any{value}
		}
		return value
	}
	arrayItems := func(count int) any {
		return make([]any, count)
	}
	tests := []struct {
		name   string
		value  any
		wantOK bool
	}{
		{
			name:   "exact byte limit",
			value:  strings.Repeat("x", limits.MaxBytes-2),
			wantOK: true,
		},
		{
			name:  "over byte limit",
			value: strings.Repeat("x", limits.MaxBytes-1),
		},
		{
			name:   "exact depth limit",
			value:  nestedArray(limits.MaxDepth),
			wantOK: true,
		},
		{
			name:  "over depth limit",
			value: nestedArray(limits.MaxDepth + 1),
		},
		{
			name:   "exact node limit",
			value:  arrayItems(limits.MaxNodes - 1),
			wantOK: true,
		},
		{
			name:  "over node limit",
			value: arrayItems(limits.MaxNodes),
		},
		{
			name: "exact number exponent limit",
			value: json.Number(fmt.Sprintf(
				"1e%d",
				structuredjson.MaxJSONNumberExponent,
			)),
			wantOK: true,
		},
		{
			name: "over number exponent limit",
			value: json.Number(fmt.Sprintf(
				"1e%d",
				structuredjson.MaxJSONNumberExponent+1,
			)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validHTTPPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.JSONPath =
				&manifest.JSONPathAssertion{
					Path:   "$.value",
					Equals: test.value,
				}
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			plan, err := Resolve(
				document,
				plannerSnapshot(),
				"quickstart",
			)
			if test.wantOK {
				if err != nil {
					t.Fatalf("Resolve boundary value: %v", err)
				}
				if plan.PlanDigest == "" {
					t.Fatal("boundary value did not produce a resolved plan")
				}
				return
			}
			if got := domain.ErrorCodeOf(err); got !=
				domain.CodePlanUnresolved {
				t.Fatalf(
					"Resolve error code = %q, want %q: %v",
					got,
					domain.CodePlanUnresolved,
					err,
				)
			}
			if plan.PlanDigest != "" {
				t.Fatalf("unbounded JSONPath value produced a plan: %#v", plan)
			}
		})
	}
}

func TestResolveRejectsUnsafeStructuredHTTPContracts(t *testing.T) {
	const schemaPath = "schemas/response.schema.json"
	validSchema := []byte(`{"type":"object"}`)
	tests := []struct {
		name     string
		wantCode domain.ErrorCode
		snapshot func(*testing.T) domain.SourceSnapshot
	}{
		{
			name:     "missing inventory entry",
			wantCode: domain.CodeSourceNotFound,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				return domain.SourceSnapshot{Root: t.TempDir()}
			},
		},
		{
			name:     "nonregular inventory mode",
			wantCode: domain.CodeSourcePathTraversal,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				result := plannerSchemaSnapshot(t, schemaPath, validSchema)
				result.Inventory[0].Mode = "040000"
				return result
			},
		},
		{
			name:     "inventory path is a directory",
			wantCode: domain.CodeSourcePathTraversal,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				root := t.TempDir()
				if err := os.MkdirAll(
					filepath.Join(root, filepath.FromSlash(schemaPath)),
					0o755,
				); err != nil {
					t.Fatalf("Create schema directory target: %v", err)
				}
				return domain.SourceSnapshot{
					Root: root,
					Inventory: []domain.FileEntry{{
						Path:   schemaPath,
						Mode:   "0644",
						Size:   0,
						Digest: plannerSchemaDigest(nil),
					}},
				}
			},
		},
		{
			name:     "oversize inventory entry",
			wantCode: domain.CodeSourceTooLarge,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				result := plannerSchemaSnapshot(t, schemaPath, validSchema)
				result.Inventory[0].Size = domain.AlphaJSONSchemaMaxBytes + 1
				return result
			},
		},
		{
			name:     "invalid inventory digest",
			wantCode: domain.CodeSourceDigestMismatch,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				result := plannerSchemaSnapshot(t, schemaPath, validSchema)
				result.Inventory[0].Digest = "sha256:INVALID"
				return result
			},
		},
		{
			name:     "source digest mismatch",
			wantCode: domain.CodeSourceDigestMismatch,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				result := plannerSchemaSnapshot(t, schemaPath, validSchema)
				result.Inventory[0].Digest =
					plannerSchemaDigest([]byte(`{"type":"array"}`))
				return result
			},
		},
		{
			name:     "invalid schema",
			wantCode: domain.CodePlanUnresolved,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				return plannerSchemaSnapshot(t, schemaPath, []byte(`{`))
			},
		},
		{
			name:     "external schema reference",
			wantCode: domain.CodePlanUnresolved,
			snapshot: func(t *testing.T) domain.SourceSnapshot {
				return plannerSchemaSnapshot(
					t,
					schemaPath,
					[]byte(`{"$ref":"https://example.com/schema.json"}`),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validHTTPPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.
				JSONSchema = schemaPath
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			plan, err := Resolve(
				document,
				test.snapshot(t),
				"quickstart",
			)
			if got := domain.ErrorCodeOf(err); got != test.wantCode {
				t.Fatalf(
					"Resolve error code = %q, want %q: %v",
					got,
					test.wantCode,
					err,
				)
			}
			if plan.PlanDigest != "" {
				t.Fatalf("invalid schema produced a plan: %#v", plan)
			}
		})
	}
}

func TestSchemaResolverDetectsSourceChangeAfterCachedBinding(t *testing.T) {
	const schemaPath = "schemas/response.schema.json"
	snapshot := plannerSchemaSnapshot(
		t,
		schemaPath,
		[]byte(`{"type":"object"}`),
	)
	resolver := newSchemaResolver(snapshot)
	if _, err := resolver.resolve(schemaPath); err != nil {
		t.Fatalf("Resolve initial schema: %v", err)
	}
	absolutePath := filepath.Join(
		snapshot.Root,
		filepath.FromSlash(schemaPath),
	)
	if err := os.WriteFile(
		absolutePath,
		[]byte(`{"type":"array"}`),
		0o644,
	); err != nil {
		t.Fatalf("Replace schema after initial binding: %v", err)
	}
	if _, err := resolver.resolve(schemaPath); domain.ErrorCodeOf(err) !=
		domain.CodeSourceDigestMismatch {
		t.Fatalf(
			"Resolve changed source error = %v, want %s",
			err,
			domain.CodeSourceDigestMismatch,
		)
	}
}

func TestResolveRejectsUnsupportedJSONPath(t *testing.T) {
	for _, expression := range []string{"$..secret", "$[*]", "$[0:2]"} {
		t.Run(expression, func(t *testing.T) {
			document := validHTTPPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			scenario.Phases.Exercise.Driver.Steps[1].Assert.Response.JSONPath =
				&manifest.JSONPathAssertion{
					Path:   expression,
					Equals: true,
				}
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			plan, err := Resolve(document, plannerSnapshot(), "quickstart")
			if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
				t.Fatalf(
					"Resolve error code = %q, want %q: %v",
					got,
					domain.CodeManifestInvalid,
					err,
				)
			}
			if plan.PlanDigest != "" {
				t.Fatalf("invalid JSONPath produced a plan: %#v", plan)
			}
		})
	}
}

func TestResolveCLIPlanOmitsHTTPOnlyFields(t *testing.T) {
	plan, err := Resolve(
		validPlannerDocument(),
		plannerSnapshot(),
		"quickstart",
	)
	if err != nil {
		t.Fatalf("Resolve CLI plan: %v", err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal CLI plan: %v", err)
	}
	for _, forbidden := range []string{`"httpJourney"`, `"readiness"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("CLI plan unexpectedly contains %s: %s", forbidden, raw)
		}
	}
}

func TestResolveRejectsNetworkAllowlistBeforeProducingPlan(t *testing.T) {
	document := validPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Capabilities[domain.PhaseSetup] = domain.CapabilitySet{
		Network: domain.NetworkCapability{
			Allow: []domain.NetworkDestination{{
				Host: "registry.npmjs.org",
				Port: 443,
			}},
		},
	}
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	plan, err := Resolve(document, plannerSnapshot(), "quickstart")
	if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf(
			"Resolve error code = %q, want %q: %v",
			got,
			domain.CodeRunnerFeatureUnavailable,
			err,
		)
	}
	if plan.PlanDigest != "" || len(plan.Commands) != 0 {
		t.Fatalf("unsupported allowlist produced a partial plan: %#v", plan)
	}
}

func TestResolveRejectsFilesystemWriteOutsideOutputsBeforeProducingPlan(t *testing.T) {
	for _, writablePath := range []string{"/workspace", "/tmp/cache", "/output"} {
		t.Run(writablePath, func(t *testing.T) {
			document := validPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			capability := scenario.Capabilities[domain.PhaseExercise]
			capability.Filesystem.Write = []string{writablePath}
			scenario.Capabilities[domain.PhaseExercise] = capability
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			plan, err := Resolve(document, plannerSnapshot(), "quickstart")
			if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
				t.Fatalf(
					"Resolve error code = %q, want %q: %v",
					got,
					domain.CodeRunnerFeatureUnavailable,
					err,
				)
			}
			if plan.PlanDigest != "" || len(plan.Commands) != 0 {
				t.Fatalf("out-of-scope writable path produced a partial plan: %#v", plan)
			}
		})
	}
}

func TestResolveAcceptsFilesystemWriteWithinOutputs(t *testing.T) {
	document := validPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	capability := scenario.Capabilities[domain.PhaseExercise]
	capability.Filesystem.Write = []string{"/outputs/**", "/outputs/result.json"}
	scenario.Capabilities[domain.PhaseExercise] = capability
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	if _, err := Resolve(document, plannerSnapshot(), "quickstart"); err != nil {
		t.Fatalf("Resolve rejected /outputs-scoped writes: %v", err)
	}
}

func TestResolveRejectsDanglingProjectEntrypoint(t *testing.T) {
	document := validPlannerDocument()
	document.Manifest.Spec.Project.Entrypoints = []string{"missing-scenario"}

	_, err := Resolve(document, plannerSnapshot(), "quickstart")
	if got := domain.ErrorCodeOf(err); got != domain.CodeManifestInvalid {
		t.Fatalf("Resolve error code = %q, want %q: %v", got, domain.CodeManifestInvalid, err)
	}
}

func TestResolveRejectsOptionalInputWithoutTreatingItAsRequired(t *testing.T) {
	document := validPlannerDocument()
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Inputs = map[string]manifest.InputSpec{
		"message": {
			Type:     "file",
			Required: false,
			Fixture:  "fixtures/message.txt",
			Mount: manifest.MountSpec{
				Path:     "/inputs/message.txt",
				ReadOnly: true,
			},
		},
	}
	document.Manifest.Spec.Scenarios["quickstart"] = scenario

	_, err := Resolve(document, plannerSnapshot(), "quickstart")
	if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
		t.Fatalf("Resolve error code = %q, want %q: %v", got, domain.CodeRunnerFeatureUnavailable, err)
	}
}

func TestResolveRejectsFileAndDirectoryChoicesWithoutDroppingPresence(t *testing.T) {
	tests := []struct {
		name  string
		input manifest.InputSpec
	}{
		{
			name: "nonempty file choices",
			input: manifest.InputSpec{
				Type:     "file",
				Required: true,
				Fixture:  "fixture.txt",
				Mount: manifest.MountSpec{
					Path:     "/inputs/fixture.txt",
					ReadOnly: true,
				},
				Choices: []any{"first", "second"},
			},
		},
		{
			name: "explicit empty directory choices",
			input: manifest.InputSpec{
				Type:     "directory",
				Required: true,
				Fixture:  "fixtures",
				Mount: manifest.MountSpec{
					Path:     "/inputs/fixtures",
					ReadOnly: true,
				},
				Choices: []any{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.input.Choices == nil {
				t.Fatal("test lost explicit choices presence")
			}
			document := validPlannerDocument()
			scenario := document.Manifest.Spec.Scenarios["quickstart"]
			scenario.Inputs = map[string]manifest.InputSpec{
				"fixture": test.input,
			}
			document.Manifest.Spec.Scenarios["quickstart"] = scenario

			_, err := Resolve(document, plannerSnapshot(), "quickstart")
			if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
				t.Fatalf(
					"Resolve error code = %q, want %q: %v",
					got,
					domain.CodeRunnerFeatureUnavailable,
					err,
				)
			}
		})
	}
}

func TestResolveRejectsUnsupportedEvidenceSelection(t *testing.T) {
	tests := []struct {
		name     string
		evidence manifest.EvidenceSpec
	}{
		{
			name: "local full profile",
			evidence: manifest.EvidenceSpec{
				Profile: "local-full",
				Include: []string{"verification-summary", "normalized-observations"},
				Exclude: []string{"raw-stdout", "raw-stderr", "raw-syscall-trace"},
			},
		},
		{
			name: "partial fixed selection",
			evidence: manifest.EvidenceSpec{
				Profile: "minimal-public",
				Include: []string{"verification-summary"},
				Exclude: []string{"raw-stdout"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validPlannerDocument()
			document.Manifest.Spec.Evidence = test.evidence
			_, err := Resolve(document, plannerSnapshot(), "quickstart")
			if got := domain.ErrorCodeOf(err); got != domain.CodeRunnerFeatureUnavailable {
				t.Fatalf("Resolve error code = %q, want %q: %v", got, domain.CodeRunnerFeatureUnavailable, err)
			}
		})
	}
}

func TestResolveAcceptsAndBindsBoundedSBOMEvidenceSelection(t *testing.T) {
	document := validPlannerDocument()
	document.Manifest.Spec.Evidence.Include = []string{
		"verification-summary", "sbom", "normalized-observations",
	}
	plan, err := Resolve(document, plannerSnapshot(), "quickstart")
	if err != nil {
		t.Fatalf("Resolve SBOM evidence: %v", err)
	}
	want := []string{"normalized-observations", "sbom", "verification-summary"}
	if !slices.Equal(plan.Evidence.Include, want) || plan.SchemaVersion != "4" {
		t.Fatalf("resolved SBOM evidence = %#v", plan.Evidence)
	}
}

func TestResolveFailsClosedForDeferredSchemaExecutionFeatures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*manifest.Document)
	}{
		{
			name: "environment runner feature",
			mutate: func(document *manifest.Document) {
				environment := document.Manifest.Spec.Environments["linux-node"]
				environment.RequiredRunnerFeatures = []string{"network-deny"}
				document.Manifest.Spec.Environments["linux-node"] = environment
			},
		},
		{
			name: "phase outputs",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Phases.Exercise.Outputs = []string{"/outputs/result.json"}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "phase observer requirements",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Phases.Exercise.ObserverRequirements = []manifest.ObserverRequirement{{
					Observer:        "process-exec",
					MinimumCoverage: "full",
				}}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "command working directory",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Phases.Prepare = &manifest.CommandPhase{
					Steps: []manifest.PhaseStep{{
						ID: "prepare",
						Run: &manifest.RunAction{
							Command:          []string{"node", "--version"},
							WorkingDirectory: "/workspace",
						},
					}},
				}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "shell command",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Phases.Prepare = &manifest.CommandPhase{
					Steps: []manifest.PhaseStep{{
						ID: "prepare",
						Run: &manifest.RunAction{
							Shell: &manifest.ShellCommand{
								Executable: "/bin/sh",
								Command:    "echo ready",
							},
						},
					}},
				}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "hup signal",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Phases.Setup = &manifest.CommandPhase{
					Steps: []manifest.PhaseStep{{
						ID: "reload",
						Signal: &manifest.SignalAction{
							Target:      "app",
							Type:        "hup",
							GracePeriod: "1s",
						},
					}},
				}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "required choice input",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Inputs = map[string]manifest.InputSpec{
					"mode": {
						Type:     "choice",
						Required: true,
						Choices:  []any{"fast", 2, true},
					},
				}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "stderr regex assertion",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				expression := "warning"
				scenario.Phases.Exercise.Driver.Assertions[0].ExitCode = nil
				scenario.Phases.Exercise.Driver.Assertions[0].StderrRegex = &expression
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "environment capability",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				capability := scenario.Capabilities[domain.PhaseExercise]
				capability.Environment = &domain.EnvironmentCapability{
					Read: []string{"LANG"},
				}
				scenario.Capabilities[domain.PhaseExercise] = capability
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "threshold success policy",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Verification.Repeats = 3
				scenario.Verification.SuccessThreshold = 2
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
		{
			name: "custom cleanup residue",
			mutate: func(document *manifest.Document) {
				scenario := document.Manifest.Spec.Scenarios["quickstart"]
				scenario.Verification.Cleanup.AllowedResidue = []string{"/workspace/**"}
				document.Manifest.Spec.Scenarios["quickstart"] = scenario
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validPlannerDocument()
			test.mutate(document)
			_, err := Resolve(document, plannerSnapshot(), "quickstart")
			wantCode := domain.CodeRunnerFeatureUnavailable
			if test.name == "shell command" {
				wantCode = domain.CodeManifestUnsafeShell
			} else if test.name == "hup signal" {
				wantCode = domain.CodeManifestInvalid
			}
			if got := domain.ErrorCodeOf(err); got != wantCode {
				t.Fatalf("Resolve error code = %q, want %q: %v", got, wantCode, err)
			}
		})
	}
}

func validPlannerDocument() *manifest.Document {
	exitCode := 0
	return &manifest.Document{
		Digest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Manifest: &manifest.Manifest{
			APIVersion: manifest.APIVersion,
			Kind:       manifest.Kind,
			Metadata:   manifest.Metadata{Name: "planner-test"},
			Spec: manifest.Spec{
				Project: manifest.ProjectSpec{
					Kind: "cli", Audiences: []string{"developer"}, Entrypoints: []string{"quickstart"},
				},
				Environments: map[string]manifest.EnvironmentSpec{
					"linux-node": {
						Platform: manifest.PlatformSpec{OS: "linux", Architecture: "amd64"},
						Runtime: manifest.RuntimeSpec{
							Adapter: "node",
							Version: runtimepolicy.NodeVersion,
						},
						BaseImage: manifest.BaseImageSpec{
							Reference: runtimepolicy.NodeReference,
						},
						Resources: manifest.ResourceSpec{CPU: 1, Memory: "256MiB", Disk: "1GiB", PIDs: 64},
					},
				},
				Scenarios: map[string]manifest.ScenarioSpec{
					"quickstart": {
						Environment: "linux-node",
						Phases: manifest.PhaseSet{
							Exercise: &manifest.ExercisePhase{
								Timeout: "30s",
								Driver: manifest.DriverSpec{
									Type: "cli", Command: []string{"node", "--version"},
									Assertions: []manifest.DriverAssertion{
										{ID: "version-exited", ExitCode: &exitCode},
									},
								},
							},
						},
						Capabilities: map[domain.Phase]domain.CapabilitySet{
							domain.PhaseExercise: {
								Network: domain.NetworkCapability{Deny: true},
							},
						},
						Verification: manifest.VerificationSpec{
							Repeats: 1, SuccessThreshold: 1,
							RequiredObservers: []string{"network-enforcement"},
							Cleanup:           manifest.CleanupSpec{AllowedResidue: []string{}},
						},
					},
				},
				Policies: manifest.PolicySpec{Profile: "baseline-v1"},
				Evidence: manifest.EvidenceSpec{
					Profile: "minimal-public",
					Include: []string{"verification-summary", "normalized-observations"},
					Exclude: []string{"raw-stdout", "raw-stderr", "raw-syscall-trace"},
				},
			},
		},
	}
}

func validHTTPPlannerDocument() *manifest.Document {
	document := validPlannerDocument()
	document.Manifest.Spec.Project.Kind = "web-app"
	bodyContains := `"received"`
	scenario := document.Manifest.Spec.Scenarios["quickstart"]
	scenario.Phases = manifest.PhaseSet{
		Run: &manifest.RunPhase{
			Timeout: "1m",
			Service: &manifest.ServiceSpec{
				ID:      "app",
				Command: []string{"node", "/workspace/server.mjs"},
				Readiness: manifest.ReadinessSpec{
					HTTP: &manifest.HTTPReadiness{
						URL:     "http://127.0.0.1:8080/health",
						Status:  200,
						Timeout: "10s",
					},
				},
			},
		},
		Exercise: &manifest.ExercisePhase{
			Timeout: "30s",
			Driver: manifest.DriverSpec{
				Type: "http",
				Steps: []manifest.DriverStep{
					{
						Request: &manifest.HTTPRequest{
							ID:      "echo",
							Method:  "post",
							URL:     "http://127.0.0.1:8080/echo",
							Headers: map[string]string{"X-Trace": "alpha-two"},
							JSON:    map[string]any{"message": "hello"},
							Timeout: "5s",
						},
					},
					{
						Assert: &manifest.DriverAssertion{
							ID: "echo-ok",
							Response: &manifest.ResponseAssertion{
								RequestID:    "echo",
								Status:       200,
								BodyContains: &bodyContains,
							},
						},
					},
					{
						Assert: &manifest.DriverAssertion{
							ID:         "output-created",
							FileExists: "/outputs/request.json",
						},
					},
				},
			},
		},
		Cleanup: &manifest.CommandPhase{
			Timeout: "10s",
			Steps: []manifest.PhaseStep{{
				ID: "stop-service",
				Signal: &manifest.SignalAction{
					Target:      "app",
					Type:        "term",
					GracePeriod: "2s",
				},
			}},
		},
	}
	scenario.Capabilities = map[domain.Phase]domain.CapabilitySet{
		domain.PhaseRun: {
			Network: domain.NetworkCapability{Deny: true},
			Filesystem: domain.FilesystemCapability{
				Read:  []string{"/workspace/**"},
				Write: []string{"/outputs/**"},
			},
			Ports: domain.PortCapability{
				Listen: []domain.PortBinding{{
					Host: "127.0.0.1",
					Port: 8080,
				}},
			},
		},
		domain.PhaseExercise: {
			Network: domain.NetworkCapability{Deny: true},
			Filesystem: domain.FilesystemCapability{
				Read:  []string{"/workspace/**", "/outputs/**"},
				Write: []string{"/outputs/**"},
			},
		},
		domain.PhaseCleanup: {
			Network: domain.NetworkCapability{Deny: true},
			Filesystem: domain.FilesystemCapability{
				Write: []string{"/outputs/**"},
			},
		},
	}
	scenario.Verification = manifest.VerificationSpec{
		Repeats:          1,
		SuccessThreshold: 1,
		RequiredObservers: []string{
			"network-enforcement",
			"port-listen",
		},
		Cleanup: manifest.CleanupSpec{
			AllowedResidue: []string{"/outputs/**"},
		},
	}
	document.Manifest.Spec.Scenarios["quickstart"] = scenario
	return document
}

func plannerHTTPBoundarySteps(
	requestCount int,
	total int,
) []manifest.DriverStep {
	steps := make([]manifest.DriverStep, 0, total)
	for index := 0; index < requestCount; index++ {
		steps = append(steps, manifest.DriverStep{
			Request: &manifest.HTTPRequest{
				ID:      fmt.Sprintf("request-%d", index),
				Method:  "get",
				URL:     fmt.Sprintf("http://127.0.0.1:8080/request/%d", index),
				Timeout: "1ms",
			},
		})
	}
	for index := requestCount; index < total; index++ {
		steps = append(steps, manifest.DriverStep{
			Assert: &manifest.DriverAssertion{
				ID:         fmt.Sprintf("assertion-%d", index),
				FileExists: "/outputs/request.json",
			},
		})
	}
	return steps
}

func plannerHTTPHeaderSet(count int) map[string]string {
	headers := make(map[string]string, count)
	for index := 0; index < count; index++ {
		headers[fmt.Sprintf("x-%02d", index)] = "ok"
	}
	return headers
}

func plannerExactHTTPHeaderAggregate() map[string]string {
	headers := map[string]string{
		domain.AlphaHTTPContentTypeName: domain.AlphaHTTPJSONContentType,
	}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		headers[name] = strings.Repeat(
			"x",
			domain.AlphaHTTPMaxHeaderValueBytes,
		)
	}
	headers["h"] = strings.Repeat("x", 8120)
	return headers
}

func plannerSnapshot() domain.SourceSnapshot {
	return domain.SourceSnapshot{
		Identity:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TreeDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func plannerSchemaSnapshot(
	t *testing.T,
	portablePath string,
	raw []byte,
) domain.SourceSnapshot {
	t.Helper()
	root := t.TempDir()
	absolutePath := filepath.Join(root, filepath.FromSlash(portablePath))
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o755); err != nil {
		t.Fatalf("Create schema directory: %v", err)
	}
	if err := os.WriteFile(absolutePath, raw, 0o644); err != nil {
		t.Fatalf("Write schema: %v", err)
	}
	digest := plannerSchemaDigest(raw)
	return domain.SourceSnapshot{
		Identity:   digest,
		TreeDigest: digest,
		Root:       root,
		Inventory: []domain.FileEntry{{
			Path:   portablePath,
			Mode:   "0644",
			Size:   int64(len(raw)),
			Digest: digest,
		}},
		TotalSize: int64(len(raw)),
		FileCount: 1,
	}
}

func plannerSchemaDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", digest)
}

func containsExactString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
