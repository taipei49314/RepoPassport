package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/attestation"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/controllerfs"
	"github.com/taipei49314/RepoPassport/internal/discovery"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/manifest"
	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
	"github.com/taipei49314/RepoPassport/internal/planner"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/rendering"
	"github.com/taipei49314/RepoPassport/internal/spdx"
	"github.com/taipei49314/RepoPassport/internal/storage"
	"github.com/taipei49314/RepoPassport/internal/truststate"
	"github.com/taipei49314/RepoPassport/internal/verification"
)

var Version = "0.1.0-alpha.33"

type RunnerOutcome struct {
	Runner       domain.RunnerFeatures
	Observations []domain.ObservationEvent
	Assertions   []domain.AssertionResult
	Errors       []*domain.Error
	Resources    domain.ResourceSummary
	Completed    bool
	Cleanup      domain.CleanupVerdict
}

type Dependencies struct {
	ProbeAll     func(context.Context) ([]domain.RunnerFeatures, error)
	ProbeBackend func(context.Context, string) ([]domain.RunnerFeatures, error)
	// FreshnessSnapshot is an internal deterministic observation seam. The
	// production binary leaves it nil and uses the bounded LocalProvider.
	FreshnessSnapshot func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error)
	// DerivedSnapshot is an internal deterministic observation seam for the
	// command-free repository-derived SPDX producer and currentness paths.
	// Production leaves it nil and uses the bounded LocalProvider directly.
	DerivedSnapshot func(context.Context, domain.ResolvedSource) (domain.SourceSnapshot, error)
	Execute         func(context.Context, domain.ResolvedPlan, string, string, string) (RunnerOutcome, error)
	// OfflineTrustPolicySignerSnapshot is an internal deterministic test seam
	// for proving the required pre-publication signer-key drift check. The
	// production binary leaves it nil and uses attestation.ReadTrustKey.
	OfflineTrustPolicySignerSnapshot func(string) ([]byte, error)
	// OfflineTrustPolicyAuthoritySnapshot is an internal deterministic test
	// seam for the authority-transition producer's required stable next-key
	// snapshot. Production leaves it nil and uses attestation.ReadTrustPolicyAuthorityKey.
	OfflineTrustPolicyAuthoritySnapshot func(string) ([]byte, error)
}

type App struct {
	Deps   Dependencies
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type globalOptions struct {
	Config         string
	DataDir        string
	CacheDir       string
	LogLevel       string
	LogFormat      string
	NoColor        bool
	Offline        bool
	NonInteractive bool
	Output         string
}

type envelope struct {
	SchemaVersion string        `json:"schemaVersion"`
	Command       string        `json:"command"`
	Status        string        `json:"status"`
	Data          any           `json:"data,omitempty"`
	Error         *domain.Error `json:"error,omitempty"`
	Warnings      []string      `json:"warnings,omitempty"`
}

func (a App) Run(ctx context.Context, args []string) int {
	global, remaining, failureCode, ok := a.prepareInvocation(args)
	if !ok {
		return failureCode
	}
	if topLevelHelpRequested(remaining) {
		fmt.Fprint(a.Stdout, topHelp())
		return 0
	}
	if topLevelVersionRequested(remaining) {
		return a.writeVersion(global, "repopass")
	}
	command, commandArgs := remaining[0], remaining[1:]
	switch command {
	case "inspect":
		return a.runInspect(ctx, global, commandArgs)
	case "init":
		return a.runInit(ctx, global, commandArgs)
	case "validate":
		return a.runValidate(global, commandArgs)
	case "plan":
		return a.runPlan(ctx, global, commandArgs)
	case "verify":
		return a.runVerify(ctx, global, commandArgs)
	case "report":
		return a.runReport(global, commandArgs)
	case "attest":
		return a.runAttest(ctx, global, commandArgs)
	case "sign-release-index":
		return a.runSignReleaseIndex(ctx, global, commandArgs)
	case "sign-release-policy":
		return a.runSignReleasePolicy(ctx, global, commandArgs)
	case "sign-offline-trust-policy":
		return a.runSignOfflineTrustPolicy(ctx, global, commandArgs)
	case "sign-offline-trust-policy-authority-transition":
		return a.runSignOfflineTrustPolicyAuthorityTransition(ctx, global, commandArgs)
	case "assemble-offline-trust-policy-authority-transition-chain":
		return a.runAssembleOfflineTrustPolicyAuthorityTransitionChain(ctx, global, commandArgs)
	case "sign-release-authority-transition":
		return a.runSignReleaseAuthorityTransition(ctx, global, commandArgs)
	case "assemble-release-authority-transition-chain":
		return a.runAssembleReleaseAuthorityTransitionChain(ctx, global, commandArgs)
	case "verify-attestation":
		return a.runVerifyAttestation(ctx, global, commandArgs)
	case "verify-release-index":
		return a.runVerifyReleaseIndex(ctx, global, commandArgs)
	case "doctor":
		return a.runDoctor(ctx, global, commandArgs)
	case "capabilities":
		return a.runCapabilities(global, commandArgs)
	default:
		e := domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Unknown command.")
		e.Details = map[string]any{"command": command}
		e.Suggestion = "Run repopass --help."
		return a.fail(command, global, e)
	}
}

// RunVerifier executes the verifier-only product surface. It deliberately
// shares global parsing and the complete verify-attestation implementation
// with Run while rejecting every other command before command-specific I/O.
func (a App) RunVerifier(ctx context.Context, args []string) int {
	global, remaining, failureCode, ok := a.prepareInvocation(args)
	if !ok {
		return failureCode
	}
	if topLevelHelpRequested(remaining) {
		fmt.Fprint(a.Stdout, verifierHelp())
		return 0
	}
	if topLevelVersionRequested(remaining) {
		return a.writeVersion(global, "repopass-verify")
	}

	command, commandArgs := remaining[0], remaining[1:]
	if command == "verify-attestation" {
		return a.runVerifyAttestation(ctx, global, commandArgs)
	}
	if command == "verify-release-index" {
		return a.runVerifyReleaseIndex(ctx, global, commandArgs)
	}
	e := domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Unknown verifier command.")
	e.Details = map[string]any{"command": command}
	e.Suggestion = "Run repopass-verify --help."
	return a.fail(command, global, e)
}

func (a *App) prepareInvocation(args []string) (globalOptions, []string, int, bool) {
	if a.Stdin == nil {
		a.Stdin = os.Stdin
	}
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	global, remaining, err := parseGlobal(args)
	if err != nil {
		failureCode := a.fail("", global, domain.WrapError(domain.CodeManifestInvalid, domain.SeverityHigh, err.Error(), err))
		return global, nil, failureCode, false
	}
	if global.Output != "text" && global.Output != "json" {
		failureCode := a.fail("", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "--output must be text or json."))
		return global, nil, failureCode, false
	}
	return global, remaining, 0, true
}

func topLevelHelpRequested(remaining []string) bool {
	return len(remaining) == 0 || remaining[0] == "help" || remaining[0] == "--help" || remaining[0] == "-h"
}

func topLevelVersionRequested(remaining []string) bool {
	return remaining[0] == "version" || remaining[0] == "--version"
}

func (a App) writeVersion(global globalOptions, product string) int {
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "version", Status: "ok", Data: map[string]string{"version": Version}})
	}
	fmt.Fprintf(a.Stdout, "%s %s\n", product, Version)
	return 0
}

func (a App) runInspect(ctx context.Context, global globalOptions, args []string) int {
	flags := newFlagSet("inspect", a.Stderr)
	limit := flags.Int("limit", 200, "maximum inventory entries to include (1-5000)")
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("inspect", global, err)
	}
	if *limit < 1 || *limit > 5000 {
		return a.fail("inspect", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "--limit must be between 1 and 5000."))
	}
	if flags.NArg() > 1 {
		return a.fail("inspect", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "inspect accepts at most one path or URL."))
	}
	sourceValue := "."
	if flags.NArg() == 1 {
		sourceValue = flags.Arg(0)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.Resolve(ctx, domain.SourceRef{Kind: "local", Value: sourceValue})
	if err != nil {
		return a.fail("inspect", global, err)
	}
	snapshot, err := provider.Fetch(ctx, resolved)
	if err != nil {
		return a.fail("inspect", global, err)
	}
	descriptor, err := discovery.Inspect(ctx, snapshot)
	if err != nil {
		return a.fail("inspect", global, err)
	}
	inventory := snapshot.Inventory
	truncated := false
	if len(inventory) > *limit {
		inventory = inventory[:*limit]
		truncated = true
	}
	data := struct {
		Source    domain.ResolvedSource    `json:"source"`
		Snapshot  domain.SourceSnapshot    `json:"snapshot"`
		Project   domain.ProjectDescriptor `json:"project"`
		Inventory []domain.FileEntry       `json:"inventory"`
		Truncated bool                     `json:"truncated"`
	}{
		Source: resolved, Snapshot: snapshot, Project: descriptor,
		Inventory: inventory, Truncated: truncated,
	}
	data.Snapshot.Inventory = nil
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "inspect", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Source: %s\nTree digest: %s\nFiles: %d (%d bytes)\nProject kind: %s\nLanguages: %s\nRuntime hints: %s\n",
		resolved.Canonical, snapshot.TreeDigest, snapshot.FileCount, snapshot.TotalSize,
		descriptor.ProjectKind, strings.Join(descriptor.Languages, ", "), strings.Join(descriptor.RuntimeHints, ", "))
	if len(descriptor.Entrypoints) > 0 {
		fmt.Fprintf(a.Stdout, "Entrypoint candidates: %s\n", strings.Join(descriptor.Entrypoints, "; "))
	}
	for _, warning := range descriptor.Warnings {
		fmt.Fprintf(a.Stdout, "Warning: %s\n", warning)
	}
	return 0
}

func (a App) runInit(ctx context.Context, global globalOptions, args []string) int {
	flags := newFlagSet("init", a.Stderr)
	force := flags.Bool("force", false, "replace an existing candidate manifest")
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("init", global, err)
	}
	if flags.NArg() > 1 {
		return a.fail("init", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "init accepts at most one path."))
	}
	root := "."
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.Resolve(ctx, domain.SourceRef{Kind: "local", Value: root})
	if err != nil {
		return a.fail("init", global, err)
	}
	snapshot, err := provider.Fetch(ctx, resolved)
	if err != nil {
		return a.fail("init", global, err)
	}
	project, err := discovery.Inspect(ctx, snapshot)
	if err != nil {
		return a.fail("init", global, err)
	}
	candidate, provenance := manifest.Candidate(project, filepath.Base(resolved.LocalPath))
	manifestPath, provenancePath, err := manifest.WriteCandidate(resolved.LocalPath, candidate, provenance, *force)
	if err != nil {
		return a.fail("init", global, err)
	}
	data := map[string]any{
		"manifest": manifestPath, "provenance": provenancePath,
		"status": "inferred", "verificationReady": false,
	}
	warning := manifest.CandidateWarning()
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "init", Status: "ok", Data: data, Warnings: []string{warning}})
	}
	fmt.Fprintf(a.Stdout, "Created %s\nCreated %s\nWarning: %s\n", manifestPath, provenancePath, warning)
	return 0
}

func (a App) runValidate(global globalOptions, args []string) int {
	flags := newFlagSet("validate", a.Stderr)
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("validate", global, err)
	}
	if flags.NArg() > 1 {
		return a.fail("validate", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "validate accepts at most one manifest path."))
	}
	path := "repo-passport.yml"
	if flags.NArg() == 1 {
		path = flags.Arg(0)
	}
	doc, err := manifest.Load(path)
	if err != nil {
		return a.fail("validate", global, err)
	}
	findings := manifest.Validate(doc)
	if findings == nil {
		findings = []*domain.Error{}
	}
	data := map[string]any{"valid": len(findings) == 0, "manifestDigest": doc.Digest, "errors": findings}
	if global.Output == "json" {
		code := a.writeJSON(envelope{SchemaVersion: "1", Command: "validate", Status: statusFor(len(findings) == 0), Data: data})
		if len(findings) > 0 {
			return 2
		}
		return code
	}
	if len(findings) == 0 {
		fmt.Fprintf(a.Stdout, "VALID %s\nManifest digest: %s\n", path, doc.Digest)
		return 0
	}
	fmt.Fprintf(a.Stdout, "INVALID %s\n", path)
	for _, finding := range findings {
		fmt.Fprintf(a.Stdout, "- %s: %s\n", finding.Code, finding.Message)
	}
	return 2
}

func (a App) runPlan(ctx context.Context, global globalOptions, args []string) int {
	flags := newFlagSet("plan", a.Stderr)
	scenario := flags.String("scenario", "quickstart", "scenario name")
	manifestPath := flags.String("manifest", "repo-passport.yml", "manifest path")
	lockPath := flags.String("lock", "passport.lock.json", "lockfile path")
	writeLock := flags.Bool("write-lock", false, "write the resolved lockfile")
	check := flags.Bool("check", false, "compare with the existing lockfile")
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("plan", global, err)
	}
	if flags.NArg() != 0 || (*writeLock && *check) {
		return a.fail("plan", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "plan accepts no positional arguments, and --write-lock conflicts with --check."))
	}
	plan, _, _, err := loadPlan(ctx, *manifestPath, *scenario)
	if err != nil {
		return a.fail("plan", global, err)
	}
	absoluteLock := resolveSibling(*manifestPath, *lockPath)
	if *check {
		if err := planner.CheckLock(absoluteLock, plan); err != nil {
			return a.fail("plan", global, err)
		}
	}
	if *writeLock {
		if err := planner.WriteLock(absoluteLock, plan); err != nil {
			return a.fail("plan", global, err)
		}
	}
	data := map[string]any{"plan": plan, "lockfile": absoluteLock, "written": *writeLock, "checked": *check}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "plan", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "Plan digest: %s\nSource: %s\nScenario: %s\nEnvironment: %s\nImage: %s\nPolicy: %s\nCommands: %d\nObservers: %s\n",
		plan.PlanDigest, plan.Source.TreeDigest, plan.Scenario, plan.Environment,
		plan.BaseImageReference, plan.PolicyBundleDigest, len(plan.Commands), strings.Join(plan.ObserverSet, ", "))
	if *writeLock {
		fmt.Fprintf(a.Stdout, "Wrote %s\n", absoluteLock)
	} else if *check {
		fmt.Fprintln(a.Stdout, "Lockfile matches.")
	} else {
		fmt.Fprintln(a.Stdout, "Preview only; use --write-lock to persist.")
	}
	return 0
}

func (a App) runVerify(ctx context.Context, global globalOptions, args []string) int {
	flags := newFlagSet("verify", a.Stderr)
	scenario := flags.String("scenario", "quickstart", "scenario name")
	manifestPath := flags.String("manifest", "repo-passport.yml", "manifest path")
	runnerName := flags.String("runner", "auto", "auto, docker, or podman")
	repeats := flags.Int("repeats", 0, "override manifest repeat count (1-10)")
	failOn := flags.String("fail-on", "", "comma-separated: functional-fail,blocked,nonconforming,inconclusive")
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("verify", global, err)
	}
	if flags.NArg() != 0 || (*runnerName != "auto" && *runnerName != "docker" && *runnerName != "podman") {
		return a.fail("verify", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "verify accepts no positional arguments and --runner must be auto, docker, or podman."))
	}
	if err := validateFailOn(*failOn); err != nil {
		return a.fail("verify", global, err)
	}
	plan, _, snapshot, err := loadPlan(ctx, *manifestPath, *scenario)
	if err != nil {
		return a.fail("verify", global, err)
	}
	requested := plan.RepeatCount
	if *repeats != 0 {
		plan, err = planner.OverrideRepeats(plan, *repeats)
		if err != nil {
			return a.fail("verify", global, err)
		}
		requested = plan.RepeatCount
	}
	if requested < 1 || requested > 10 {
		return a.fail("verify", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Repeat count must be between 1 and 10."))
	}
	runID := newRunID()
	verificationID := newVerificationID()
	dataRoot := global.DataDir
	if dataRoot == "" {
		dataRoot, err = defaultDataDir()
		if err != nil {
			return a.fail("verify", global, err)
		}
	}
	absoluteDataRoot, err := filepath.Abs(dataRoot)
	if err != nil {
		return a.fail("verify", global, err)
	}
	if err := os.MkdirAll(absoluteDataRoot, 0o700); err != nil {
		return a.fail("verify", global, err)
	}
	resolvedDataRoot, err := pathsecurity.Resolve(absoluteDataRoot)
	if err != nil {
		return a.fail("verify", global, err)
	}
	if !sameFilesystemPath(absoluteDataRoot, resolvedDataRoot) {
		return a.fail("verify", global, domain.NewError(
			domain.CodeEvidenceDigestMismatch,
			domain.SeverityCritical,
			"Controller data directory must not resolve through a symlink or reparse point.",
		))
	}
	absoluteDataRoot = resolvedDataRoot
	if pathsOverlap(snapshot.Root, absoluteDataRoot) {
		return a.fail("verify", global, domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Controller data directory must be outside the untrusted source tree.",
		))
	}
	workRoot := filepath.Join(absoluteDataRoot, "work", runID)
	runsRoot := filepath.Join(absoluteDataRoot, "runs")
	started := time.Now().UTC()

	features, probeError := a.probe(ctx, *runnerName)
	var findings []*domain.Error
	if probeError != nil {
		findings = append(findings, asDomainError(probeError, domain.CodeRunnerUnavailable, "Runner preflight failed."))
	}
	if !features.Available {
		e := domain.NewError(domain.CodeRunnerUnavailable, domain.SeverityHigh, "No compatible Linux container runner is available.")
		e.Details = map[string]any{"runner": features.Backend, "reason": features.Reason}
		e.Suggestion = "Install Docker or Podman with a Linux engine, then rerun repopass doctor."
		findings = append(findings, e)
	}

	var allObservations []domain.ObservationEvent
	var allAssertions []domain.AssertionResult
	var completed, matching int
	cleanup := domain.CleanupClean
	fingerprintCounts := map[string]int{}
	resources := domain.ResourceSummary{}
	runnerFromExecution := false
	resourcesFromExecution := false
	if features.Available && a.Deps.Execute != nil {
		if err := os.MkdirAll(workRoot, 0o700); err != nil {
			return a.fail("verify", global, err)
		}
		for repeat := 1; repeat <= requested; repeat++ {
			repeatRoot := filepath.Join(workRoot, fmt.Sprintf("repeat-%02d", repeat))
			outcome, executeErr := a.Deps.Execute(ctx, plan, snapshot.Root, repeatRoot, features.Backend)
			if outcome.Runner.Backend != "" {
				if !runnerFromExecution {
					features = outcome.Runner
					runnerFromExecution = true
				} else {
					features = mergeRunnerFeatures(features, outcome.Runner)
				}
			}
			for _, finding := range outcome.Errors {
				findings = appendUniqueFinding(findings, finding)
			}
			digest, digestErr := assertionFingerprint(
				outcome.Assertions,
				outcome.Cleanup,
			)
			if digestErr == nil && outcome.Completed {
				fingerprintCounts[digest]++
				if fingerprintCounts[digest] > matching {
					matching = fingerprintCounts[digest]
				}
			}
			for index := range outcome.Assertions {
				outcome.Assertions[index].Repeat = repeat
			}
			allAssertions = append(allAssertions, outcome.Assertions...)
			for index := range outcome.Observations {
				outcome.Observations[index].Sequence = uint64(len(allObservations) + index + 1)
			}
			allObservations = append(allObservations, outcome.Observations...)
			if outcome.Completed {
				completed++
			}
			cleanup = aggregateCleanupVerdict(cleanup, outcome.Cleanup)
			if !resourcesFromExecution {
				resources = cloneResourceSummary(outcome.Resources)
				resourcesFromExecution = true
			} else {
				resources = mergeResources(resources, outcome.Resources)
			}
			if executeErr != nil {
				findings = appendUniqueFinding(
					findings,
					asDomainError(executeErr, domain.CodeSandboxStartFailed, "Sandbox execution failed."),
				)
				break
			}
		}
	} else if features.Available {
		findings = append(findings, domain.NewError(
			domain.CodeRunnerUnavailable,
			domain.SeverityHigh,
			"Runner execution integration is unavailable.",
		))
	}
	if _, statErr := os.Stat(workRoot); statErr == nil {
		if cleanupErr := removeWorkRoot(absoluteDataRoot, workRoot, runID); cleanupErr != nil {
			cleanup = aggregateCleanupVerdict(
				cleanup,
				domain.CleanupNotTested,
			)
			findings = appendUniqueFinding(
				findings,
				asDomainError(cleanupErr, domain.CodeCleanupFailed, "Controller work directory cleanup failed."),
			)
		}
	} else if !os.IsNotExist(statErr) {
		cleanup = aggregateCleanupVerdict(
			cleanup,
			domain.CleanupNotTested,
		)
		findings = appendUniqueFinding(
			findings,
			asDomainError(statErr, domain.CodeCleanupFailed, "Controller work directory could not be inspected."),
		)
	}
	provider := acquisition.NewLocalProvider()
	resolved, resolveErr := provider.Resolve(ctx, domain.SourceRef{Kind: "local", Value: snapshot.Root})
	if resolveErr != nil {
		findings = appendUniqueFinding(
			findings,
			asDomainError(resolveErr, domain.CodeSourceDigestMismatch, "Source could not be re-resolved after verification."),
		)
	} else {
		after, fetchErr := provider.Fetch(ctx, resolved)
		if fetchErr != nil {
			findings = appendUniqueFinding(
				findings,
				asDomainError(fetchErr, domain.CodeSourceDigestMismatch, "Source could not be re-snapshotted after verification."),
			)
		} else if after.TreeDigest != snapshot.TreeDigest {
			e := domain.NewError(domain.CodeSourceDigestMismatch, domain.SeverityCritical, "Source changed during verification.")
			e.Details = map[string]any{"before": snapshot.TreeDigest, "after": after.TreeDigest}
			findings = append(findings, e)
		}
	}
	if completed == 0 {
		cleanup = domain.CleanupNotTested
	}
	result, err := verification.Build(verification.Input{
		RunID: runID, VerificationID: verificationID,
		Plan: plan, Runner: features, StartedAt: started, CompletedAt: time.Now().UTC(),
		Observations: allObservations, Assertions: allAssertions, Errors: findings,
		Requested: requested, Completed: completed, Matching: matching,
		SuccessThreshold: plan.SuccessThreshold,
		Cleanup:          cleanup, Resources: resources,
	})
	if err != nil {
		return a.fail("verify", global, err)
	}
	store := storage.RunStore{Root: runsRoot}
	artifactDirectory, err := store.Write(result)
	if err != nil {
		return a.fail("verify", global, domain.WrapError(domain.CodeEvidenceBuildFailed, domain.SeverityHigh, "Authoritative run artifacts could not be written.", err))
	}
	data := map[string]any{"verification": result, "artifactDirectory": artifactDirectory}
	if global.Output == "json" {
		if code := a.writeJSON(envelope{SchemaVersion: "1", Command: "verify", Status: "ok", Data: data}); code != 0 {
			return code
		}
	} else {
		fmt.Fprint(a.Stdout, rendering.Text(result))
		fmt.Fprintf(a.Stdout, "\nArtifacts: %s\n", artifactDirectory)
	}
	return failOnExit(result, *failOn)
}

func (a App) runReport(global globalOptions, args []string) int {
	flags := newFlagSet("report", a.Stderr)
	runID := flags.String("run", "", "verification run ID")
	format := flags.String("format", "text", "text, json, or html")
	out := flags.String("out", "", "optional output file")
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("report", global, err)
	}
	if flags.NArg() != 0 || *runID == "" || (*format != "text" && *format != "json" && *format != "html") {
		return a.fail("report", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "report requires --run and --format text|json|html."))
	}
	dataRoot := global.DataDir
	if dataRoot == "" {
		defaultRoot, resolveErr := defaultDataDir()
		if resolveErr != nil {
			return a.fail("report", global, resolveErr)
		}
		dataRoot = defaultRoot
	}
	if err := rejectRepositoryLocalDataRoot(dataRoot); err != nil {
		return a.fail("report", global, err)
	}
	store := storage.RunStore{Root: filepath.Join(dataRoot, "runs")}
	result, err := store.Read(*runID)
	if err != nil {
		return a.fail("report", global, err)
	}
	var content []byte
	switch *format {
	case "text":
		content = []byte(rendering.Text(result))
	case "json":
		content, err = rendering.JSON(result)
	case "html":
		content, err = rendering.HTML(result)
	}
	if err != nil {
		return a.fail("report", global, err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, content, 0o600); err != nil {
			return a.fail("report", global, err)
		}
		if global.Output == "json" {
			return a.writeJSON(envelope{SchemaVersion: "1", Command: "report", Status: "ok", Data: map[string]any{"run": *runID, "format": *format, "path": *out, "bytes": len(content)}})
		}
		fmt.Fprintf(a.Stdout, "Wrote %s\n", *out)
		return 0
	}
	if _, err := a.Stdout.Write(content); err != nil {
		return 1
	}
	if len(content) == 0 || content[len(content)-1] != '\n' {
		fmt.Fprintln(a.Stdout)
	}
	return 0
}

func (a App) runAttest(ctx context.Context, global globalOptions, args []string) int {
	cleanArgs, spdxInput, spdxArgErr := extractSPDXFlag(args)
	if spdxArgErr != nil {
		return a.fail("attest", global, spdxArgErr)
	}
	cleanArgs, derivedInput, derivedArgErr := extractDerivedSPDXFlags(cleanArgs)
	if derivedArgErr != nil {
		return a.fail("attest", global, derivedArgErr)
	}
	if spdxInput.set && derivedInput.enabled {
		return a.fail("attest", global, domain.NewError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"attest accepts exactly one SPDX evidence source: --spdx FILE or --derive-spdx with --current-manifest FILE.",
		))
	}
	flags := newFlagSet("attest", a.Stderr)
	runID := flags.String("run", "", "authoritative verification run ID")
	keyPath := flags.String("key", "", "canonical Ed25519 private PKCS#8 PEM file")
	outputPath := flags.String("out", "", "new deterministic USTAR bundle path")
	_ = flags.String("spdx", "", "selected bounded SPDX 2.3 JSON attachment")
	_ = flags.Bool("derive-spdx", false, "derive the bounded SPDX profile from a stable local source")
	_ = flags.String("current-manifest", "", "local manifest locating the repository-derived SPDX source root")
	var publicKeyOutput nonEmptyStringFlag
	flags.Var(&publicKeyOutput, "public-key-out", "optional new canonical Ed25519 public SPKI PEM companion")
	if err := flags.Parse(normalizeAttestArgs(cleanArgs)); err != nil {
		return a.flagFailure("attest", global, err)
	}
	if flags.NArg() != 0 || *runID == "" || *keyPath == "" || *outputPath == "" {
		return a.fail("attest", global, domain.NewError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"attest requires --run, --key, and --out and accepts no positional arguments.",
		))
	}
	dataRoot := global.DataDir
	if dataRoot == "" {
		defaultRoot, err := defaultDataDir()
		if err != nil {
			return a.fail("attest", global, err)
		}
		dataRoot = defaultRoot
	}
	if err := rejectRepositoryLocalDataRoot(dataRoot); err != nil {
		return a.fail("attest", global, err)
	}
	store := storage.RunStore{Root: filepath.Join(dataRoot, "runs")}
	result, err := store.Read(*runID)
	if err != nil {
		return a.fail("attest", global, err)
	}
	if err := verification.VerifyIntegrity(result); err != nil {
		return a.fail("attest", global, err)
	}
	if _, err := attestation.EvaluatePrivacy(result); err != nil {
		return a.fail("attest", global, err)
	}
	wantsSBOM := verificationSelectsSBOM(result)
	hasSBOMEvidence := spdxInput.set || derivedInput.enabled
	if wantsSBOM != hasSBOMEvidence {
		return a.fail("attest", global, domain.NewError(
			domain.CodeEvidenceBuildFailed,
			domain.SeverityHigh,
			"The SPDX attachment does not match the sealed evidence selection.",
		))
	}
	var canonicalSBOM []byte
	var canonicalProvenance []byte
	derivedRoot := ""
	if spdxInput.set {
		raw, readErr := spdx.ReadFile(spdxInput.value)
		if readErr != nil {
			return a.fail("attest", global, domain.NewError(
				domain.CodeEvidenceBuildFailed,
				domain.SeverityHigh,
				"The SPDX attachment cannot be read as a bounded unlinked regular file.",
			))
		}
		defer clear(raw)
		_, canonicalSBOM, err = spdx.Canonicalize(raw)
		if err != nil {
			return a.fail("attest", global, domain.NewError(
				domain.CodeEvidenceBuildFailed,
				domain.SeverityHigh,
				"The SPDX attachment does not satisfy the bounded public profile.",
			))
		}
		if _, err := privacy.Evaluate(canonicalSBOM); err != nil {
			return a.fail("attest", global, err)
		}
	} else if derivedInput.enabled {
		artifact, root, deriveErr := a.deriveSPDXForAttestation(
			ctx,
			derivedInput.currentManifest,
			result,
		)
		if deriveErr != nil {
			return a.fail("attest", global, deriveErr)
		}
		canonicalSBOM = artifact.SPDX
		canonicalProvenance = artifact.ProvenanceCanonical
		derivedRoot = root
		defer clear(canonicalSBOM)
		defer clear(canonicalProvenance)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return a.fail("attest", global, domain.NewError(
			domain.CodeSigningFailed,
			domain.SeverityHigh,
			"The working directory cannot be resolved for private-key safety checks.",
		))
	}
	var privateKey []byte
	if derivedInput.enabled {
		privateKey, err = attestation.LoadPrivateKeyForDerivedArtifacts(
			*keyPath,
			dataRoot,
			*outputPath,
			publicKeyOutput.value,
			derivedRoot,
			workingDirectory,
		)
	} else {
		privateKey, err = attestation.LoadPrivateKeyForArtifacts(
			*keyPath,
			dataRoot,
			*outputPath,
			publicKeyOutput.value,
			workingDirectory,
		)
	}
	if err != nil {
		return a.fail("attest", global, err)
	}
	defer clear(privateKey)
	var built attestation.BuildResult
	if derivedInput.enabled {
		built, err = attestation.BuildWithDerivedSPDX(
			result,
			canonicalSBOM,
			canonicalProvenance,
			privateKey,
		)
	} else {
		built, err = attestation.BuildWithSPDX(result, canonicalSBOM, privateKey)
	}
	if err != nil {
		return a.fail("attest", global, err)
	}
	if err := attestation.WriteSigningArtifacts(
		*outputPath,
		built.Bundle,
		publicKeyOutput.value,
		built.PublicKeyPEM,
	); err != nil {
		return a.fail("attest", global, err)
	}
	data := map[string]any{
		"runId":                built.RunID,
		"verificationId":       built.VerificationID,
		"signerKeyId":          built.SignerKeyID,
		"manifestDigest":       built.ManifestDigest,
		"bundleDigest":         built.BundleDigest,
		"publicKeyDigest":      built.PublicKeyDigest,
		"bundlePath":           *outputPath,
		"originalResults":      result.Results,
		"privacyProfile":       built.PrivacyProfile,
		"privacyPolicy":        built.PrivacyPolicy,
		"privacyRulesetDigest": built.PrivacyRulesetDigest,
		"privacyEvaluation":    built.PrivacyEvaluation,
		"sbomPresent":          built.SBOMPresent,
		"sbomFormat":           built.SBOMFormat,
		"sbomDigest":           built.SBOMDigest,
	}
	if derivedInput.enabled {
		data["schemaVersion"] = attestation.BundleVersionV2
		data["sbomOrigin"] = built.SBOMOrigin
		data["sbomProfile"] = built.SBOMProfile
		data["sbomRulesetDigest"] = built.SBOMRulesetDigest
		data["sbomProvenanceDigest"] = built.SBOMProvenanceDigest
		data["sbomPrivacyProfile"] = built.SBOMPrivacyProfile
		data["sbomPrivacyPolicy"] = built.SBOMPrivacyPolicy
		data["sbomPrivacyRulesetDigest"] = built.SBOMPrivacyRulesetDigest
		data["sbomPrivacyEvaluation"] = built.SBOMPrivacyEvaluation
	}
	if publicKeyOutput.set {
		data["publicKeyPath"] = publicKeyOutput.value
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{
			SchemaVersion: "1",
			Command:       "attest",
			Status:        "ok",
			Data:          data,
		})
	}
	fmt.Fprintf(a.Stdout, "Wrote offline attestation bundle: %s\n", *outputPath)
	fmt.Fprintf(a.Stdout, "Run:             %s\n", built.RunID)
	fmt.Fprintf(a.Stdout, "Verification:    %s\n", built.VerificationID)
	fmt.Fprintf(a.Stdout, "Signer key ID:   %s\n", built.SignerKeyID)
	fmt.Fprintf(a.Stdout, "Manifest digest: %s\n", built.ManifestDigest)
	fmt.Fprintf(a.Stdout, "Bundle digest:   %s\n", built.BundleDigest)
	fmt.Fprintf(a.Stdout, "Public key digest: %s\n", built.PublicKeyDigest)
	fmt.Fprintf(a.Stdout, "Privacy profile:     %s\n", built.PrivacyProfile)
	fmt.Fprintf(a.Stdout, "Privacy policy:      %s\n", built.PrivacyPolicy)
	fmt.Fprintf(a.Stdout, "Privacy ruleset:     %s\n", built.PrivacyRulesetDigest)
	fmt.Fprintf(a.Stdout, "Privacy evaluation:  %s\n", strings.ToUpper(built.PrivacyEvaluation))
	fmt.Fprintf(a.Stdout, "SPDX attachment:     %s\n", presenceText(built.SBOMPresent))
	if built.SBOMPresent {
		fmt.Fprintf(a.Stdout, "SPDX format:         %s\n", built.SBOMFormat)
		fmt.Fprintf(a.Stdout, "SPDX digest:         %s\n", built.SBOMDigest)
	}
	if derivedInput.enabled {
		fmt.Fprintf(a.Stdout, "SPDX origin:         %s\n", built.SBOMOrigin)
		fmt.Fprintf(a.Stdout, "SPDX profile:        %s\n", built.SBOMProfile)
		fmt.Fprintf(a.Stdout, "SPDX ruleset:        %s\n", built.SBOMRulesetDigest)
		fmt.Fprintf(a.Stdout, "SPDX provenance:     %s\n", built.SBOMProvenanceDigest)
		fmt.Fprintf(a.Stdout, "SPDX privacy profile: %s\n", built.SBOMPrivacyProfile)
		fmt.Fprintf(a.Stdout, "SPDX privacy ruleset: %s\n", built.SBOMPrivacyRulesetDigest)
		fmt.Fprintf(a.Stdout, "SPDX privacy evaluation: %s\n", strings.ToUpper(built.SBOMPrivacyEvaluation))
	}
	if publicKeyOutput.set {
		fmt.Fprintf(a.Stdout, "Wrote public-key companion: %s\n", publicKeyOutput.value)
	}
	fmt.Fprintln(a.Stdout, "Original evidence state remains UNSIGNED; no verdict was upgraded.")
	return 0
}

func (a App) deriveSPDXForAttestation(
	ctx context.Context,
	currentManifest string,
	result domain.VerificationResult,
) (spdx.DerivedArtifact, string, error) {
	absoluteManifest, err := filepath.Abs(currentManifest)
	if err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX manifest location cannot be resolved safely.",
		)
	}
	if _, err := manifest.Load(absoluteManifest); err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX manifest cannot be read and validated.",
		)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.ResolveCommandFree(
		ctx,
		domain.SourceRef{Kind: "local", Value: filepath.Dir(absoluteManifest)},
	)
	if err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source root cannot be resolved safely.",
		)
	}
	first, err := a.fetchDerivedSnapshot(ctx, provider, resolved)
	if err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source cannot be observed reliably.",
		)
	}
	second, err := a.fetchDerivedSnapshot(ctx, provider, resolved)
	if err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source cannot be observed reliably.",
		)
	}
	if !sameSnapshotIdentity(first, second) {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source changed before derivation.",
		)
	}
	currentSubject := planSourceForSnapshot(second)
	if currentSubject != result.Subject {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source does not match the authoritative verification subject.",
		)
	}
	artifact, err := spdx.DerivePackageLockV3(second)
	if err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX inputs do not satisfy the frozen package-lock profile.",
		)
	}
	if _, err := privacy.EvaluateDerivedPair(artifact.SPDX, artifact.ProvenanceCanonical); err != nil {
		return spdx.DerivedArtifact{}, "", err
	}
	third, err := a.fetchDerivedSnapshot(ctx, provider, resolved)
	if err != nil {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source cannot be re-observed before signing.",
		)
	}
	if !sameSnapshotIdentity(first, third) {
		return spdx.DerivedArtifact{}, "", derivedEvidenceError(
			"The repository-derived SPDX source changed before signing.",
		)
	}
	return artifact, resolved.LocalPath, nil
}

func (a App) fetchDerivedSnapshot(
	ctx context.Context,
	provider *acquisition.LocalProvider,
	resolved domain.ResolvedSource,
) (domain.SourceSnapshot, error) {
	if a.Deps.DerivedSnapshot != nil {
		return a.Deps.DerivedSnapshot(ctx, resolved)
	}
	return provider.Fetch(ctx, resolved)
}

func derivedEvidenceError(message string) error {
	return domain.NewError(domain.CodeEvidenceBuildFailed, domain.SeverityHigh, message)
}

func (a App) runVerifyAttestation(ctx context.Context, global globalOptions, args []string) int {
	signedTrustPolicy, signedPolicyArgErr := validateSignedTrustPolicyArgs(args)
	if signedPolicyArgErr != nil {
		return a.fail("verify-attestation", global, signedPolicyArgErr)
	}
	trustPolicyAuthorityRotation, rotationArgErr := validateSignedTrustPolicyAuthorityRotationArgs(args, signedTrustPolicy.Enabled)
	if rotationArgErr != nil {
		return a.fail("verify-attestation", global, rotationArgErr)
	}
	trustPolicy, policyArgErr := validateTrustPolicyArgs(args)
	if policyArgErr != nil {
		return a.fail("verify-attestation", global, policyArgErr)
	}
	persistTrustPolicyState, persistPolicyStateArgErr := validatePersistTrustPolicyStateArgs(args, signedTrustPolicy.Enabled)
	if persistPolicyStateArgErr != nil {
		return a.fail("verify-attestation", global, persistPolicyStateArgErr)
	}
	cleanArgs, currentManifest, freshnessRequested, strictErr := extractFreshnessArgs(args, trustPolicy.Enabled || signedTrustPolicy.Enabled)
	if strictErr != nil {
		return a.fail("verify-attestation", global, strictErr)
	}
	flags := newFlagSet("verify-attestation", a.Stderr)
	trustKeyPath := flags.String("trust-key", "", "explicitly trusted canonical Ed25519 public SPKI PEM file")
	trustPolicyPath := flags.String("trust-policy", "", "digest-pinned canonical offline trust policy v1")
	expectedTrustPolicyDigest := flags.String("expect-trust-policy-digest", "", "expected sha256 digest of the exact trust policy bytes")
	trustPolicyEnvelopePath := flags.String("trust-policy-envelope", "", "signed canonical offline trust policy v2 DSSE envelope (requires separate authority key and generation floor)")
	trustPolicyAuthorityKeyPath := flags.String("trust-policy-authority-key", "", "separate canonical Ed25519 authority SPKI PEM for signed-policy verification")
	minimumTrustPolicyGeneration := flags.String("minimum-trust-policy-generation", "", "canonical signed trust-policy generation floor; --persist-trust-policy-state optionally adds local monotonic state")
	_ = minimumTrustPolicyGeneration // strict pre-I/O validation owns this value.
	_ = flags.String("trust-policy-authority-transition", "", "one-hop signed policy-authority transition DSSE envelope")
	_ = flags.String("trust-policy-authority-transition-chain", "", "bounded signed policy-authority transition chain")
	_ = flags.String("trust-policy-authority-trust-root", "", "independently accepted previous policy-authority Ed25519 SPKI PEM")
	_ = flags.String("minimum-trust-policy-authority-generation", "", "canonical one-hop policy-authority transition generation floor")
	_ = flags.Bool("persist-trust-policy-state", false, "persist signed-policy generation and equivocation state below the controller data directory")
	_ = flags.String("current-manifest", "", "trusted local manifest for bounded point-in-time freshness re-observation")
	var expectedBundleDigest nonEmptyStringFlag
	flags.Var(&expectedBundleDigest, "expect-bundle-digest", "expected sha256 digest of the complete raw bundle")
	if err := flags.Parse(normalizeVerifyAttestationArgs(cleanArgs)); err != nil {
		return a.flagFailure("verify-attestation", global, err)
	}
	if flags.NArg() != 1 {
		return a.fail("verify-attestation", global, domain.NewError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"verify-attestation requires exactly one bundle path.",
		))
	}
	if expectedBundleDigest.set {
		if err := attestation.ValidateExpectedBundleDigest(expectedBundleDigest.value); err != nil {
			return a.fail("verify-attestation", global, err)
		}
	}
	bundle, err := attestation.ReadBundle(flags.Arg(0))
	if err != nil {
		return a.fail("verify-attestation", global, err)
	}
	if err := attestation.CheckExpectedBundleDigest(bundle, expectedBundleDigest.value); err != nil {
		return a.fail("verify-attestation", global, err)
	}
	report, verifyErr := attestation.Verify(bundle, nil)
	if verifyErr != nil && domain.ErrorCodeOf(verifyErr) != domain.CodeAttestationUntrusted {
		return a.fail("verify-attestation", global, verifyErr)
	}
	var acceptedClaims attestation.AcceptedClaims
	if *trustKeyPath != "" {
		trustKey, trustReadErr := attestation.ReadTrustKey(*trustKeyPath)
		if trustReadErr != nil {
			report.TrustDecision = "rejected"
			verifyErr = unavailableTrustKeyError()
		} else if freshnessRequested {
			report, acceptedClaims, verifyErr = attestation.VerifyAccepted(bundle, trustKey)
		} else {
			report, verifyErr = attestation.Verify(bundle, trustKey)
		}
	} else if trustPolicy.Enabled {
		report.TrustBasis = "offline-policy-v1"
		report.TrustDecision = "rejected"
		report.TrustReason = "invalid-or-unavailable"
		policyRaw, policyReadErr := attestation.ReadOfflineTrustPolicy(*trustPolicyPath)
		if policyReadErr != nil {
			verifyErr = offlineTrustPolicyUnavailableError()
		} else if digestErr := attestation.CheckExpectedTrustPolicyDigest(
			policyRaw,
			*expectedTrustPolicyDigest,
		); digestErr != nil {
			verifyErr = digestErr
		} else {
			report.TrustPolicyDigest = *expectedTrustPolicyDigest
			policy, parseErr := attestation.ParseOfflineTrustPolicy(policyRaw)
			if parseErr != nil {
				verifyErr = offlineTrustPolicyUnavailableError()
			} else if freshnessRequested {
				report, acceptedClaims, verifyErr = attestation.VerifyAcceptedWithOfflineTrustPolicy(bundle, policy)
			} else {
				report, verifyErr = attestation.VerifyWithOfflineTrustPolicy(bundle, policy)
			}
		}
	} else if signedTrustPolicy.Enabled {
		if trustPolicyAuthorityRotation.Enabled {
			if trustPolicyAuthorityRotation.Chain {
				report, acceptedClaims, verifyErr = a.verifyWithChainedSignedOfflineTrustPolicy(
					ctx, global, bundle, report, signedTrustPolicy, trustPolicyAuthorityRotation,
					persistTrustPolicyState, freshnessRequested,
				)
			} else {
				report, acceptedClaims, verifyErr = a.verifyWithRotatedSignedOfflineTrustPolicy(
					ctx, global, bundle, report, signedTrustPolicy, trustPolicyAuthorityRotation,
					persistTrustPolicyState, freshnessRequested,
				)
			}
		} else {
			report.TrustBasis = "signed-offline-policy-v2"
			report.TrustDecision = "rejected"
			report.TrustReason = "invalid-or-unavailable"
			// The caller supplied this floor, rather than the signed policy. It is
			// therefore safe to expose even when the authority or envelope cannot be
			// read, but no signature-authenticated metadata is exposed until Parse
			// has succeeded.
			report.MinimumTrustPolicyGeneration = signedTrustPolicy.MinimumGeneration
			authorityKey, authorityReadErr := attestation.ReadTrustPolicyAuthorityKey(*trustPolicyAuthorityKeyPath)
			if authorityReadErr != nil {
				verifyErr = signedOfflineTrustPolicyUnavailableError()
			} else if attestation.ValidateTrustPolicyAuthorityKey(authorityKey) != nil {
				verifyErr = signedOfflineTrustPolicyUnavailableError()
			} else {
				envelopeRaw, envelopeReadErr := attestation.ReadSignedOfflineTrustPolicyEnvelope(*trustPolicyEnvelopePath)
				if envelopeReadErr != nil {
					verifyErr = signedOfflineTrustPolicyUnavailableError()
				} else {
					policy, parseErr := attestation.ParseSignedOfflineTrustPolicy(envelopeRaw, authorityKey)
					if parseErr != nil {
						verifyErr = signedOfflineTrustPolicyUnavailableError()
					} else {
						report, verifyErr = attestation.VerifySignedOfflineTrustPolicyFloor(report, policy, signedTrustPolicy.MinimumGeneration)
						if verifyErr == nil && persistTrustPolicyState.Enabled {
							dataRoot := global.DataDir
							if dataRoot == "" {
								dataRoot, verifyErr = defaultDataDir()
							}
							if verifyErr == nil {
								verifyErr = rejectRepositoryLocalDataRoot(dataRoot)
							}
							if verifyErr != nil {
								report.TrustPolicyStateEvaluation = string(truststate.EvaluationUnavailable)
								report, verifyErr = attestation.RejectSignedOfflineTrustPolicyState(report, "state-unavailable")
							} else {
								state, observeErr := truststate.Observe(
									ctx,
									dataRoot,
									policy.AuthorityKeyID(),
									policy.Generation(),
									policy.PayloadDigest(),
								)
								report.TrustPolicyStateEvaluation = string(state.Evaluation)
								report.TrustPolicyStateGeneration = state.Generation
								if observeErr != nil {
									report, verifyErr = attestation.RejectSignedOfflineTrustPolicyState(report, trustPolicyStateFailureReason(observeErr))
								} else if !acceptedTrustPolicyStateEvaluation(state.Evaluation) {
									report.TrustPolicyStateEvaluation = string(truststate.EvaluationUnavailable)
									report.TrustPolicyStateGeneration = 0
									report, verifyErr = attestation.RejectSignedOfflineTrustPolicyState(report, "state-unavailable")
								}
							}
						}
						if verifyErr == nil {
							if freshnessRequested {
								report, acceptedClaims, verifyErr = attestation.VerifyAcceptedSignedOfflineTrustPolicySigner(bundle, report, policy)
							} else {
								report, verifyErr = attestation.VerifySignedOfflineTrustPolicySigner(report, policy)
							}
						}
					}
				}
			}
		}
	}
	if freshnessRequested && verifyErr == nil {
		if acceptedClaims.Derived != nil {
			evaluation, currentness, currentnessErr := a.evaluateCurrentSBOMCurrentness(
				ctx,
				currentManifest,
				*acceptedClaims.Derived,
			)
			report.SBOMCurrentnessEvaluation = evaluation
			report.SBOMCurrentness = &currentness
			verifyErr = currentnessErr
		} else {
			evaluation, freshness, freshnessErr := a.evaluateCurrentFreshness(
				ctx,
				currentManifest,
				acceptedClaims,
			)
			report.FreshnessEvaluation = evaluation
			report.Freshness = &freshness
			verifyErr = freshnessErr
		}
	}
	if global.Output == "json" {
		status := "ok"
		var typed *domain.Error
		if verifyErr != nil {
			status = "error"
			typed = asDomainError(verifyErr, domain.CodeAttestationUntrusted, "The signer is not trusted.")
		}
		if code := a.writeJSON(envelope{
			SchemaVersion: "1",
			Command:       "verify-attestation",
			Status:        status,
			Data:          report,
			Error:         typed,
		}); code != 0 {
			return code
		}
		if typed != nil {
			return exitForError(typed)
		}
		return 0
	}
	writeAttestationReport(a.Stdout, report)
	if verifyErr != nil {
		return a.fail("verify-attestation", global, verifyErr)
	}
	return 0
}

func unavailableTrustKeyError() error {
	err := domain.NewError(
		domain.CodeAttestationUntrusted,
		domain.SeverityHigh,
		"The signature is valid, but the explicitly trusted public key cannot be read safely.",
	)
	err.Details = map[string]any{
		"signatureValid": true,
		"trustDecision":  "rejected",
	}
	return err
}

func offlineTrustPolicyUnavailableError() error {
	err := domain.NewError(
		domain.CodeAttestationUntrusted,
		domain.SeverityHigh,
		"The verified signature cannot be authorized by the offline trust policy.",
	)
	err.Details = map[string]any{
		"signatureValid": true,
		"trustDecision":  "rejected",
		"trustBasis":     "offline-policy-v1",
		"trustReason":    "invalid-or-unavailable",
	}
	return err
}

func signedOfflineTrustPolicyUnavailableError() error {
	err := domain.NewError(
		domain.CodeAttestationUntrusted,
		domain.SeverityHigh,
		"The signed offline trust policy is invalid or unavailable.",
	)
	err.Details = map[string]any{
		"signatureValid": true,
		"trustDecision":  "rejected",
		"trustBasis":     "signed-offline-policy-v2",
		"trustReason":    "invalid-or-unavailable",
	}
	return err
}

func (a App) evaluateCurrentSBOMCurrentness(
	ctx context.Context,
	currentManifest string,
	historical attestation.AcceptedDerivedClaims,
) (string, attestation.SBOMCurrentnessReport, error) {
	absoluteManifest, err := filepath.Abs(currentManifest)
	if err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnavailable,
			false,
		)
	}
	if _, err := manifest.Load(absoluteManifest); err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnavailable,
			false,
		)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.ResolveCommandFree(
		ctx,
		domain.SourceRef{Kind: "local", Value: filepath.Dir(absoluteManifest)},
	)
	if err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnavailable,
			isCancellation(ctx, err),
		)
	}
	first, err := a.fetchDerivedSnapshot(ctx, provider, resolved)
	if err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnavailable,
			isCancellation(ctx, err),
		)
	}
	second, err := a.fetchDerivedSnapshot(ctx, provider, resolved)
	if err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnavailable,
			isCancellation(ctx, err),
		)
	}
	if !sameSnapshotIdentity(first, second) {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnstable,
			false,
		)
	}
	artifact, err := spdx.DerivePackageLockV3(second)
	if err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonUnsupported,
			isCancellation(ctx, err),
		)
	}
	if _, err := privacy.EvaluateDerivedPair(artifact.SPDX, artifact.ProvenanceCanonical); err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonPrivacyBlocked,
			false,
		)
	}
	third, err := a.fetchDerivedSnapshot(ctx, provider, resolved)
	if err != nil {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnavailable,
			isCancellation(ctx, err),
		)
	}
	if !sameSnapshotIdentity(first, third) {
		return sbomCurrentnessUnknown(
			historical,
			attestation.SBOMCurrentnessReasonSourceUnstable,
			false,
		)
	}
	evaluation, currentness := attestation.EvaluateSBOMCurrentness(historical, &artifact, "")
	return evaluation, currentness, sbomCurrentnessEvaluationError(evaluation, currentness, false)
}

func sbomCurrentnessUnknown(
	historical attestation.AcceptedDerivedClaims,
	reason string,
	cancelled bool,
) (string, attestation.SBOMCurrentnessReport, error) {
	evaluation, currentness := attestation.EvaluateSBOMCurrentness(historical, nil, reason)
	return evaluation, currentness, sbomCurrentnessEvaluationError(evaluation, currentness, cancelled)
}

func sbomCurrentnessEvaluationError(
	evaluation string,
	currentness attestation.SBOMCurrentnessReport,
	cancelled bool,
) error {
	if evaluation == attestation.SBOMCurrentnessFresh {
		return nil
	}
	if cancelled {
		return fixedSBOMCurrentnessError(
			domain.CodeCancelled,
			domain.SeverityWarning,
			"Repository-derived SPDX currentness evaluation was cancelled.",
			currentness,
		)
	}
	if evaluation == attestation.SBOMCurrentnessStale {
		return fixedSBOMCurrentnessError(
			domain.CodeEvidenceStale,
			domain.SeverityHigh,
			"The trusted repository-derived SPDX evidence is stale for the current source.",
			currentness,
		)
	}
	switch currentness.Reason {
	case attestation.SBOMCurrentnessReasonSourceUnavailable,
		attestation.SBOMCurrentnessReasonSourceUnstable:
		return fixedSBOMCurrentnessError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"The current source could not be re-observed reliably for repository-derived SPDX currentness.",
			currentness,
		)
	case attestation.SBOMCurrentnessReasonPrivacyBlocked:
		return fixedSBOMCurrentnessError(
			domain.CodeEvidencePrivacyBlocked,
			domain.SeverityCritical,
			"The current repository-derived SPDX public projection was blocked by privacy policy.",
			currentness,
		)
	case attestation.SBOMCurrentnessReasonUnknownRuleset:
		return fixedSBOMCurrentnessError(
			domain.CodeAttestationInvalid,
			domain.SeverityHigh,
			"The signed repository-derived SPDX ruleset is not supported by this verifier.",
			currentness,
		)
	default:
		return fixedSBOMCurrentnessError(
			domain.CodeEvidenceBuildFailed,
			domain.SeverityHigh,
			"The current repository-derived SPDX inputs are unsupported or could not be derived reliably.",
			currentness,
		)
	}
}

func fixedSBOMCurrentnessError(
	code domain.ErrorCode,
	severity domain.Severity,
	message string,
	currentness attestation.SBOMCurrentnessReport,
) error {
	err := domain.NewError(code, severity, message)
	err.Details = map[string]any{"profile": currentness.Profile, "reason": currentness.Reason}
	return err
}

func (a App) evaluateCurrentFreshness(
	ctx context.Context,
	currentManifest string,
	historical attestation.AcceptedClaims,
) (string, attestation.FreshnessReport, error) {
	preflightEvaluation, preflightFreshness := attestation.EvaluateFreshness(
		historical,
		attestation.CurrentFreshnessObservation{},
	)
	if preflightEvaluation == attestation.FreshnessUnknown &&
		preflightFreshness.Reason == attestation.FreshnessReasonSourceIdentityUnavailable {
		return preflightEvaluation, preflightFreshness, freshnessEvaluationError(
			preflightEvaluation,
			preflightFreshness,
			false,
		)
	}
	absoluteManifest, err := filepath.Abs(currentManifest)
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnavailable},
			false,
		)
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.Resolve(ctx, domain.SourceRef{Kind: "local", Value: filepath.Dir(absoluteManifest)})
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnavailable},
			isCancellation(ctx, err),
		)
	}
	first, err := a.fetchFreshnessSnapshot(ctx, provider, resolved)
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnavailable},
			isCancellation(ctx, err),
		)
	}
	second, err := a.fetchFreshnessSnapshot(ctx, provider, resolved)
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnavailable},
			isCancellation(ctx, err),
		)
	}
	if !sameSnapshotIdentity(first, second) {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnstable},
			false,
		)
	}
	currentSource := planSourceForSnapshot(second)
	evaluation, freshness := attestation.EvaluateFreshness(
		historical,
		attestation.CurrentFreshnessObservation{Source: &currentSource},
	)
	if evaluation != attestation.FreshnessUnknown || freshness.Reason != attestation.FreshnessReasonPlanUnavailable {
		return evaluation, freshness, freshnessEvaluationError(evaluation, freshness, false)
	}

	doc, err := manifest.Load(absoluteManifest)
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{
				Source:            &currentSource,
				UnavailableReason: attestation.FreshnessReasonPlanUnavailable,
			},
			false,
		)
	}
	plan, err := planner.Resolve(doc, second, historical.Plan.Scenario)
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{
				Source:            &currentSource,
				UnavailableReason: attestation.FreshnessReasonPlanUnavailable,
			},
			isCancellation(ctx, err),
		)
	}
	third, err := a.fetchFreshnessSnapshot(ctx, provider, resolved)
	if err != nil {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnavailable},
			isCancellation(ctx, err),
		)
	}
	if !sameSnapshotIdentity(first, third) {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{UnavailableReason: attestation.FreshnessReasonSourceUnstable},
			false,
		)
	}
	currentPolicyDigest := plan.PolicyBundleDigest
	currentPlanDigest := plan.PlanDigest
	current := attestation.CurrentFreshnessObservation{
		Source:             &currentSource,
		PolicyBundleDigest: &currentPolicyDigest,
		PlanDigest:         &currentPlanDigest,
	}
	evaluation, freshness = attestation.EvaluateFreshness(historical, current)
	if evaluation != attestation.FreshnessUnknown || freshness.Reason != attestation.FreshnessReasonRunnerUnavailable {
		return evaluation, freshness, freshnessEvaluationError(evaluation, freshness, false)
	}
	if _, comparable := attestation.RunnerStableDigest(historical.Runner); !comparable {
		return evaluation, freshness, freshnessEvaluationError(evaluation, freshness, false)
	}
	runner, cancelled, available := a.probeFreshnessRunner(ctx, historical.Runner.Backend)
	if !available {
		return freshnessUnknown(
			historical,
			attestation.CurrentFreshnessObservation{
				Source:             &currentSource,
				PolicyBundleDigest: &currentPolicyDigest,
				PlanDigest:         &currentPlanDigest,
				UnavailableReason:  attestation.FreshnessReasonRunnerUnavailable,
			},
			cancelled,
		)
	}
	current.Runner = &runner
	evaluation, freshness = attestation.EvaluateFreshness(historical, current)
	return evaluation, freshness, freshnessEvaluationError(evaluation, freshness, false)
}

func (a App) fetchFreshnessSnapshot(
	ctx context.Context,
	provider *acquisition.LocalProvider,
	resolved domain.ResolvedSource,
) (domain.SourceSnapshot, error) {
	if a.Deps.FreshnessSnapshot != nil {
		return a.Deps.FreshnessSnapshot(ctx, resolved)
	}
	return provider.Fetch(ctx, resolved)
}

func (a App) probeFreshnessRunner(ctx context.Context, backend string) (domain.RunnerFeatures, bool, bool) {
	if backend != "docker" && backend != "podman" || a.Deps.ProbeBackend == nil {
		return domain.RunnerFeatures{}, false, false
	}
	all, err := a.Deps.ProbeBackend(ctx, backend)
	if err != nil {
		return domain.RunnerFeatures{}, isCancellation(ctx, err), false
	}
	matches := make([]domain.RunnerFeatures, 0, 1)
	for _, candidate := range all {
		if candidate.Backend == backend {
			matches = append(matches, candidate)
		}
	}
	if len(matches) != 1 {
		return domain.RunnerFeatures{}, false, false
	}
	if _, comparable := attestation.RunnerStableDigest(matches[0]); !comparable {
		return domain.RunnerFeatures{}, false, false
	}
	return matches[0], false, true
}

func freshnessUnknown(
	historical attestation.AcceptedClaims,
	current attestation.CurrentFreshnessObservation,
	cancelled bool,
) (string, attestation.FreshnessReport, error) {
	evaluation, freshness := attestation.EvaluateFreshness(historical, current)
	return evaluation, freshness, freshnessEvaluationError(evaluation, freshness, cancelled)
}

func freshnessEvaluationError(
	evaluation string,
	freshness attestation.FreshnessReport,
	cancelled bool,
) error {
	if evaluation == attestation.FreshnessCurrent {
		return nil
	}
	if evaluation == attestation.FreshnessStale {
		err := domain.NewError(
			domain.CodeEvidenceStale,
			domain.SeverityHigh,
			"The accepted evidence does not match the bounded current observation.",
		)
		err.Details = map[string]any{"profile": freshness.Profile, "reason": freshness.Reason}
		return err
	}
	if cancelled {
		return fixedFreshnessError(
			domain.CodeCancelled,
			domain.SeverityWarning,
			"The bounded freshness observation was cancelled.",
			freshness,
		)
	}
	switch freshness.Reason {
	case attestation.FreshnessReasonSourceUnavailable,
		attestation.FreshnessReasonSourceUnstable,
		attestation.FreshnessReasonSourceIdentityUnavailable:
		return fixedFreshnessError(
			domain.CodeSourceDigestMismatch,
			domain.SeverityHigh,
			"The bounded current source identity could not be established reliably.",
			freshness,
		)
	case attestation.FreshnessReasonPlanUnavailable:
		return fixedFreshnessError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"The bounded current plan could not be resolved reliably.",
			freshness,
		)
	default:
		return fixedFreshnessError(
			domain.CodeRunnerUnavailable,
			domain.SeverityHigh,
			"The bounded current runner profile could not be observed reliably.",
			freshness,
		)
	}
}

func fixedFreshnessError(
	code domain.ErrorCode,
	severity domain.Severity,
	message string,
	freshness attestation.FreshnessReport,
) error {
	err := domain.NewError(code, severity, message)
	err.Details = map[string]any{"profile": freshness.Profile, "reason": freshness.Reason}
	return err
}

func isCancellation(ctx context.Context, err error) bool {
	return ctx.Err() != nil || domain.ErrorCodeOf(err) == domain.CodeCancelled ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func sameSnapshotIdentity(left, right domain.SourceSnapshot) bool {
	return left.Identity == right.Identity && left.Commit == right.Commit && left.TreeDigest == right.TreeDigest
}

func planSourceForSnapshot(snapshot domain.SourceSnapshot) domain.PlanSource {
	return domain.PlanSource{
		Identity: snapshot.Identity, Commit: snapshot.Commit, TreeDigest: snapshot.TreeDigest,
	}
}

func normalizeAttestArgs(args []string) []string {
	return normalizeCommandArgs(args, "--run", "--key", "--out", "--public-key-out")
}

type spdxFlagValue struct {
	value string
	set   bool
}

type derivedSPDXFlagValue struct {
	enabled         bool
	currentManifest string
}

func extractSPDXFlag(args []string) ([]string, spdxFlagValue, error) {
	clean := make([]string, 0, len(args))
	var result spdxFlagValue
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			clean = append(clean, args[index:]...)
			break
		}
		if malformedSPDXFlag(argument) {
			return nil, spdxFlagValue{}, invalidSPDXFlag()
		}
		if argument != "--spdx" && !strings.HasPrefix(argument, "--spdx=") {
			clean = append(clean, argument)
			continue
		}
		if result.set {
			return nil, spdxFlagValue{}, invalidSPDXFlag()
		}
		var value string
		if argument == "--spdx" {
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				return nil, spdxFlagValue{}, invalidSPDXFlag()
			}
			index++
			value = args[index]
		} else {
			value = strings.TrimPrefix(argument, "--spdx=")
		}
		if value == "" {
			return nil, spdxFlagValue{}, invalidSPDXFlag()
		}
		result = spdxFlagValue{value: value, set: true}
	}
	return clean, result, nil
}

func malformedSPDXFlag(argument string) bool {
	if !strings.HasPrefix(argument, "-") {
		return false
	}
	trimmed := strings.TrimLeft(argument, "-")
	name, _, _ := strings.Cut(trimmed, "=")
	if !strings.HasPrefix(strings.ToLower(name), "spdx") {
		return false
	}
	return argument != "--spdx" && !strings.HasPrefix(argument, "--spdx=")
}

func invalidSPDXFlag() error {
	return domain.NewError(
		domain.CodeManifestInvalid,
		domain.SeverityHigh,
		"attest accepts --spdx FILE at most once with a non-empty value.",
	)
}

func extractDerivedSPDXFlags(args []string) ([]string, derivedSPDXFlagValue, error) {
	clean := make([]string, 0, len(args))
	result := derivedSPDXFlagValue{}
	deriveCount := 0
	manifestCount := 0
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			clean = append(clean, args[index:]...)
			break
		}
		if malformedDerivedSPDXFlag(argument) {
			return nil, derivedSPDXFlagValue{}, invalidDerivedSPDXFlags()
		}
		switch {
		case argument == "--derive-spdx":
			deriveCount++
			result.enabled = true
		case argument == "--current-manifest":
			manifestCount++
			if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") {
				return nil, derivedSPDXFlagValue{}, invalidDerivedSPDXFlags()
			}
			index++
			result.currentManifest = args[index]
		case strings.HasPrefix(argument, "--current-manifest="):
			manifestCount++
			result.currentManifest = strings.TrimPrefix(argument, "--current-manifest=")
			if result.currentManifest == "" {
				return nil, derivedSPDXFlagValue{}, invalidDerivedSPDXFlags()
			}
		default:
			clean = append(clean, argument)
		}
	}
	if deriveCount > 1 || manifestCount > 1 || (deriveCount == 1) != (manifestCount == 1) {
		return nil, derivedSPDXFlagValue{}, invalidDerivedSPDXFlags()
	}
	return clean, result, nil
}

func malformedDerivedSPDXFlag(argument string) bool {
	if !strings.HasPrefix(argument, "-") {
		return false
	}
	trimmed := strings.TrimLeft(argument, "-")
	name, _, _ := strings.Cut(trimmed, "=")
	name = strings.ToLower(name)
	switch {
	case strings.HasPrefix(name, "derive-spdx"):
		return argument != "--derive-spdx"
	case strings.HasPrefix(name, "current-manifest"):
		return argument != "--current-manifest" && !strings.HasPrefix(argument, "--current-manifest=")
	default:
		return false
	}
}

func invalidDerivedSPDXFlags() error {
	return domain.NewError(
		domain.CodeManifestInvalid,
		domain.SeverityHigh,
		"Repository-derived SPDX mode requires exactly one --derive-spdx and one non-empty --current-manifest FILE.",
	)
}

func verificationSelectsSBOM(result domain.VerificationResult) bool {
	for _, value := range result.Plan.Evidence.Include {
		if value == "sbom" {
			return true
		}
	}
	return false
}

func presenceText(present bool) string {
	if present {
		return "PRESENT"
	}
	return "ABSENT"
}

type nonEmptyStringFlag struct {
	value string
	set   bool
}

func (value *nonEmptyStringFlag) String() string {
	return value.value
}

func (value *nonEmptyStringFlag) Set(raw string) error {
	if raw == "" {
		return errors.New("value must not be empty")
	}
	value.value = raw
	value.set = true
	return nil
}

type trustPolicyCLIOptions struct {
	Enabled bool
	Path    string
	Digest  string
}

type signedTrustPolicyCLIOptions struct {
	Enabled           bool
	EnvelopePath      string
	AuthorityKeyPath  string
	MinimumGeneration uint64
}

type persistTrustPolicyStateCLIOptions struct {
	Enabled bool
}

func validatePersistTrustPolicyStateArgs(args []string, signedPolicyEnabled bool) (persistTrustPolicyStateCLIOptions, error) {
	count, valid := strictBooleanFlag(args, "persist-trust-policy-state")
	if !valid || count > 1 || (count == 1 && !signedPolicyEnabled) {
		return persistTrustPolicyStateCLIOptions{}, invalidPersistTrustPolicyStateFlags()
	}
	return persistTrustPolicyStateCLIOptions{Enabled: count == 1}, nil
}

func strictBooleanFlag(args []string, name string) (int, bool) {
	wanted := "--" + name
	count := 0
	afterDoubleDash := false
	for _, argument := range args {
		if afterDoubleDash {
			continue
		}
		if argument == "--" {
			afterDoubleDash = true
			continue
		}
		if malformedFreshnessFlag(argument, name) {
			return count, false
		}
		if argument == wanted {
			count++
			continue
		}
		if strings.HasPrefix(argument, wanted+"=") {
			return count, false
		}
	}
	return count, true
}

func invalidPersistTrustPolicyStateFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"Persistent signed trust-policy state requires exactly one valueless --persist-trust-policy-state with the complete signed offline trust-policy triple.")
}

func acceptedTrustPolicyStateEvaluation(evaluation truststate.Evaluation) bool {
	switch evaluation {
	case truststate.EvaluationInitialized, truststate.EvaluationMatched, truststate.EvaluationAdvanced:
		return true
	default:
		return false
	}
}

func trustPolicyStateFailureReason(err error) string {
	switch {
	case errors.Is(err, truststate.ErrGenerationRollback):
		return "state-generation-rollback"
	case errors.Is(err, truststate.ErrGenerationEquivocation):
		return "state-generation-equivocation"
	case errors.Is(err, truststate.ErrUnavailable):
		return "state-unavailable"
	default:
		return "state-unavailable"
	}
}

func validateSignedTrustPolicyArgs(args []string) (signedTrustPolicyCLIOptions, error) {
	envelopeCount, envelopePath, envelopeOK := strictValueFlag(args, "trust-policy-envelope")
	authorityCount, authorityPath, authorityOK := strictValueFlag(args, "trust-policy-authority-key")
	minimumCount, minimumRaw, minimumOK := strictValueFlag(args, "minimum-trust-policy-generation")
	if !envelopeOK || !authorityOK || !minimumOK {
		return signedTrustPolicyCLIOptions{}, invalidSignedTrustPolicyFlags()
	}
	if envelopeCount == 0 && authorityCount == 0 && minimumCount == 0 {
		return signedTrustPolicyCLIOptions{}, nil
	}
	trustKeyCount, _, trustKeyOK := strictValueFlag(args, "trust-key")
	legacyPolicyCount, _, legacyPolicyOK := strictValueFlag(args, "trust-policy")
	legacyDigestCount, _, legacyDigestOK := strictValueFlag(args, "expect-trust-policy-digest")
	if envelopeCount != 1 || authorityCount != 1 || minimumCount != 1 || envelopePath == "" || authorityPath == "" ||
		trustKeyCount != 0 || legacyPolicyCount != 0 || legacyDigestCount != 0 || !trustKeyOK || !legacyPolicyOK || !legacyDigestOK {
		return signedTrustPolicyCLIOptions{}, invalidSignedTrustPolicyFlags()
	}
	if minimumRaw == "" || strings.HasPrefix(minimumRaw, "+") || strings.HasPrefix(minimumRaw, "-") ||
		strings.TrimSpace(minimumRaw) != minimumRaw || (len(minimumRaw) > 1 && minimumRaw[0] == '0') {
		return signedTrustPolicyCLIOptions{}, invalidSignedTrustPolicyFlags()
	}
	minimum, err := strconv.ParseUint(minimumRaw, 10, 64)
	if err != nil || minimum == 0 || minimum > attestation.MaxTrustPolicyGeneration || strconv.FormatUint(minimum, 10) != minimumRaw {
		return signedTrustPolicyCLIOptions{}, invalidSignedTrustPolicyFlags()
	}
	return signedTrustPolicyCLIOptions{Enabled: true, EnvelopePath: envelopePath, AuthorityKeyPath: authorityPath, MinimumGeneration: minimum}, nil
}

func invalidSignedTrustPolicyFlags() error {
	return domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh,
		"Signed offline trust-policy mode requires exactly one non-empty --trust-policy-envelope, --trust-policy-authority-key, and canonical --minimum-trust-policy-generation, with no other trust mechanism.")
}

func validateTrustPolicyArgs(args []string) (trustPolicyCLIOptions, error) {
	policyCount, policyPath, policyOK := strictValueFlag(args, "trust-policy")
	digestCount, digest, digestOK := strictValueFlag(args, "expect-trust-policy-digest")
	if !policyOK || !digestOK {
		return trustPolicyCLIOptions{}, invalidTrustPolicyFlags()
	}
	if policyCount == 0 && digestCount == 0 {
		return trustPolicyCLIOptions{}, nil
	}
	trustKeyCount, _, trustKeyOK := strictValueFlag(args, "trust-key")
	if policyCount != 1 || digestCount != 1 || policyPath == "" || digest == "" ||
		trustKeyCount != 0 || !trustKeyOK {
		return trustPolicyCLIOptions{}, invalidTrustPolicyFlags()
	}
	if err := attestation.ValidateExpectedTrustPolicyDigest(digest); err != nil {
		return trustPolicyCLIOptions{}, invalidTrustPolicyFlags()
	}
	return trustPolicyCLIOptions{Enabled: true, Path: policyPath, Digest: digest}, nil
}

func invalidTrustPolicyFlags() error {
	return domain.NewError(
		domain.CodeManifestInvalid,
		domain.SeverityHigh,
		"Offline trust-policy mode requires exactly one non-empty --trust-policy, exactly one canonical --expect-trust-policy-digest, and no --trust-key.",
	)
}

func extractFreshnessArgs(args []string, trustPolicyEnabled bool) ([]string, string, bool, error) {
	clean := make([]string, 0, len(args))
	currentManifest := ""
	currentOccurrences := 0
	afterDoubleDash := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if afterDoubleDash {
			clean = append(clean, argument)
			continue
		}
		if argument == "--" {
			afterDoubleDash = true
			clean = append(clean, argument)
			continue
		}
		if malformedFreshnessFlag(argument, "current-manifest") {
			return nil, "", true, invalidFreshnessFlags()
		}
		if argument != "--current-manifest" && !strings.HasPrefix(argument, "--current-manifest=") {
			clean = append(clean, argument)
			continue
		}
		currentOccurrences++
		if argument == "--current-manifest" {
			if index+1 >= len(args) || args[index+1] == "" || isRecognizedFreshnessFlag(args[index+1]) {
				return nil, "", true, invalidFreshnessFlags()
			}
			index++
			currentManifest = args[index]
		} else {
			currentManifest = strings.TrimPrefix(argument, "--current-manifest=")
			if currentManifest == "" {
				return nil, "", true, invalidFreshnessFlags()
			}
		}
	}
	if currentOccurrences == 0 {
		return clean, "", false, nil
	}
	if currentOccurrences != 1 {
		return nil, "", true, invalidFreshnessFlags()
	}
	trustCount, trustValue, trustOK := strictValueFlag(args, "trust-key")
	digestCount, digestValue, digestOK := strictValueFlag(args, "expect-bundle-digest")
	trustMechanismValid := trustCount == 1 && trustOK && trustValue != ""
	if trustPolicyEnabled {
		trustMechanismValid = trustCount == 0 && trustOK
	}
	if !trustMechanismValid || digestCount != 1 || !digestOK || digestValue == "" {
		return nil, "", true, invalidFreshnessFlags()
	}
	if err := attestation.ValidateExpectedBundleDigest(digestValue); err != nil {
		return nil, "", true, invalidFreshnessFlags()
	}
	return clean, currentManifest, true, nil
}

func strictValueFlag(args []string, name string) (int, string, bool) {
	wanted := "--" + name
	count := 0
	value := ""
	afterDoubleDash := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if afterDoubleDash {
			continue
		}
		if argument == "--" {
			afterDoubleDash = true
			continue
		}
		if malformedFreshnessFlag(argument, name) {
			return count, "", false
		}
		if argument == wanted {
			count++
			if index+1 >= len(args) || args[index+1] == "" || isRecognizedFreshnessFlag(args[index+1]) {
				return count, "", false
			}
			index++
			value = args[index]
			continue
		}
		if strings.HasPrefix(argument, wanted+"=") {
			count++
			value = strings.TrimPrefix(argument, wanted+"=")
			if value == "" {
				return count, "", false
			}
		}
	}
	return count, value, true
}

func isRecognizedFreshnessFlag(argument string) bool {
	if !strings.HasPrefix(argument, "-") {
		return false
	}
	trimmed := strings.TrimLeft(argument, "-")
	name, _, _ := strings.Cut(trimmed, "=")
	name = strings.ToLower(name)
	for _, known := range verifyAttestationValueFlagNames() {
		if name == known || strings.HasPrefix(name, known+"-") {
			return true
		}
	}
	return false
}

func malformedFreshnessFlag(argument, name string) bool {
	if !strings.HasPrefix(argument, "-") {
		return false
	}
	// Recognize every canonical long-form verify-attestation value flag before
	// looking for prefixes. This avoids treating --trust-policy-envelope as a
	// malformed --trust-policy while still leaving the strict per-flag counter
	// responsible for mode shape and duplication.
	for _, known := range verifyAttestationValueFlagNames() {
		if argument == "--"+known || strings.HasPrefix(argument, "--"+known+"=") {
			return false
		}
	}
	trimmed := strings.TrimLeft(argument, "-")
	flagName, _, _ := strings.Cut(trimmed, "=")
	// Known verify-attestation value flags are deliberately long-form only. A
	// single/multiple dash spelling or a case/near-prefix alias must be rejected
	// by strict pre-I/O validation instead of being reinterpreted by flag.FlagSet.
	return strings.HasPrefix(strings.ToLower(flagName), name)
}

func verifyAttestationValueFlagNames() []string {
	return []string{
		"current-manifest", "trust-key", "expect-bundle-digest",
		"trust-policy", "expect-trust-policy-digest",
		"trust-policy-envelope", "trust-policy-authority-key", "minimum-trust-policy-generation",
		"trust-policy-authority-transition", "trust-policy-authority-transition-chain", "trust-policy-authority-trust-root", "minimum-trust-policy-authority-generation",
		"persist-trust-policy-state",
	}
}

func invalidFreshnessFlags() error {
	return domain.NewError(
		domain.CodeManifestInvalid,
		domain.SeverityHigh,
		"Freshness mode requires exactly one non-empty --current-manifest, canonical --expect-bundle-digest, and exactly one accepted trust mechanism.",
	)
}

func normalizeVerifyAttestationArgs(args []string) []string {
	return normalizeCommandArgs(
		args,
		"--trust-key",
		"--expect-bundle-digest",
		"--trust-policy",
		"--expect-trust-policy-digest",
		"--trust-policy-envelope",
		"--trust-policy-authority-key",
		"--minimum-trust-policy-generation",
		"--trust-policy-authority-transition",
		"--trust-policy-authority-transition-chain",
		"--trust-policy-authority-trust-root",
		"--minimum-trust-policy-authority-generation",
	)
}

func normalizeCommandArgs(args []string, valueFlagNames ...string) []string {
	valueFlags := make(map[string]struct{}, len(valueFlagNames))
	for _, name := range valueFlagNames {
		valueFlags[name] = struct{}{}
	}
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if _, acceptsValue := valueFlags[argument]; acceptsValue {
			flags = append(flags, argument)
			if index+1 < len(args) {
				index++
				flags = append(flags, args[index])
			}
			continue
		}
		isValueFlag := false
		for name := range valueFlags {
			if strings.HasPrefix(argument, name+"=") {
				isValueFlag = true
				break
			}
		}
		if isValueFlag || strings.HasPrefix(argument, "-") {
			flags = append(flags, argument)
			continue
		}
		positionals = append(positionals, argument)
	}
	if len(positionals) == 0 {
		return flags
	}
	flags = append(flags, "--")
	return append(flags, positionals...)
}

func writeAttestationReport(output io.Writer, report attestation.VerificationReport) {
	fmt.Fprintf(output, "Artifact integrity:   %s\n", strings.ToUpper(report.ArtifactIntegrity))
	fmt.Fprintf(output, "Signature validity:   %s\n", strings.ToUpper(report.SignatureValidity))
	fmt.Fprintf(output, "Bundle digest:        %s\n", report.BundleDigest)
	fmt.Fprintf(output, "Public key digest:    %s\n", report.PublicKeyDigest)
	fmt.Fprintf(output, "Signer key ID:        %s\n", report.SignerKeyID)
	fmt.Fprintf(output, "Trust decision:       %s\n", strings.ToUpper(report.TrustDecision))
	if report.TrustBasis != "" {
		fmt.Fprintf(output, "Trust basis:          %s\n", report.TrustBasis)
		if report.TrustPolicyDigest != "" {
			fmt.Fprintf(output, "Trust policy digest:  %s\n", report.TrustPolicyDigest)
		}
		if report.TrustPolicyEnvelopeDigest != "" {
			fmt.Fprintf(output, "Policy envelope:      %s\n", report.TrustPolicyEnvelopeDigest)
		}
		if report.TrustPolicyAuthorityKeyID != "" {
			fmt.Fprintf(output, "Policy authority ID:  %s\n", report.TrustPolicyAuthorityKeyID)
		}
		if report.TrustPolicyGeneration != 0 {
			fmt.Fprintf(output, "Policy generation:    %d\n", report.TrustPolicyGeneration)
		}
		if report.MinimumTrustPolicyGeneration != 0 {
			fmt.Fprintf(output, "Policy minimum:       %d\n", report.MinimumTrustPolicyGeneration)
		}
		if report.TrustPolicySignatureValidity != "" {
			fmt.Fprintf(output, "Policy signature:     %s\n", strings.ToUpper(report.TrustPolicySignatureValidity))
		}
		if report.TrustPolicyStateEvaluation != "" {
			fmt.Fprintf(output, "Policy state:         %s\n", strings.ToUpper(report.TrustPolicyStateEvaluation))
			if report.TrustPolicyStateGeneration != 0 {
				fmt.Fprintf(output, "Policy state generation: %d\n", report.TrustPolicyStateGeneration)
			}
		}
		if report.TrustPolicyAuthorityTransitionDigest != "" {
			fmt.Fprintf(output, "Authority transition: %s\n", report.TrustPolicyAuthorityTransitionDigest)
			fmt.Fprintf(output, "Authority envelope:   %s\n", report.TrustPolicyAuthorityTransitionEnvelopeDigest)
			fmt.Fprintf(output, "Authority trust root: %s\n", report.TrustPolicyAuthorityTrustRootKeyID)
			fmt.Fprintf(output, "Authority generation: %d\n", report.TrustPolicyAuthorityTransitionGeneration)
		}
		if report.TrustPolicyAuthorityTransitionChainDigest != "" {
			fmt.Fprintf(output, "Authority chain:      %s\n", report.TrustPolicyAuthorityTransitionChainDigest)
			fmt.Fprintf(output, "Authority chain hops: %d\n", report.TrustPolicyAuthorityTransitionChainHopCount)
			fmt.Fprintf(output, "Authority chain root: %s\n", report.TrustPolicyAuthorityTransitionChainRootKeyID)
			fmt.Fprintf(output, "Authority chain terminal: %s\n", report.TrustPolicyAuthorityTransitionChainTerminalKeyID)
			fmt.Fprintf(output, "Authority chain generation: %d\n", report.TrustPolicyAuthorityTransitionChainGeneration)
		}
		if report.MinimumTrustPolicyAuthorityGeneration != 0 {
			fmt.Fprintf(output, "Authority minimum:    %d\n", report.MinimumTrustPolicyAuthorityGeneration)
		}
		if report.TrustPolicyAuthorityStateEvaluation != "" {
			fmt.Fprintf(output, "Authority state:      %s\n", strings.ToUpper(report.TrustPolicyAuthorityStateEvaluation))
			fmt.Fprintf(output, "Authority state transition: %d\n", report.TrustPolicyAuthorityStateTransitionGeneration)
			fmt.Fprintf(output, "Authority state policy: %d\n", report.TrustPolicyAuthorityStatePolicyGeneration)
		}
		if report.TrustPolicyAuthorityTransitionChainStateEvaluation != "" {
			fmt.Fprintf(output, "Authority chain state: %s\n", strings.ToUpper(report.TrustPolicyAuthorityTransitionChainStateEvaluation))
			fmt.Fprintf(output, "Authority chain state generation: %d\n", report.TrustPolicyAuthorityTransitionChainStateGeneration)
			fmt.Fprintf(output, "Authority chain state policy: %d\n", report.TrustPolicyAuthorityTransitionChainStatePolicyGeneration)
		}
		fmt.Fprintf(output, "Trust reason:         %s\n", strings.ToUpper(report.TrustReason))
	}
	fmt.Fprintf(output, "Freshness evaluation: %s\n", strings.ToUpper(report.FreshnessEvaluation))
	if report.Freshness != nil {
		fmt.Fprintf(output, "Freshness profile:    %s\n", report.Freshness.Profile)
		fmt.Fprintf(output, "Freshness runner:     %s\n", report.Freshness.RunnerProfile)
		fmt.Fprintf(output, "Freshness reason:     %s\n", strings.ToUpper(report.Freshness.Reason))
		fmt.Fprintln(output, "Freshness checks:")
		for _, check := range report.Freshness.Checks {
			fmt.Fprintf(output, "  %s: %s", strings.ToUpper(check.Dimension), strings.ToUpper(check.Status))
			if check.HistoricalDigest != "" {
				fmt.Fprintf(output, " historical=%s", check.HistoricalDigest)
			}
			if check.CurrentDigest != "" {
				fmt.Fprintf(output, " current=%s", check.CurrentDigest)
			}
			fmt.Fprintln(output)
		}
	}
	fmt.Fprintf(output, "Privacy profile:      %s\n", report.PrivacyProfile)
	fmt.Fprintf(output, "Privacy policy:       %s\n", report.PrivacyPolicy)
	fmt.Fprintf(output, "Privacy ruleset:      %s\n", report.PrivacyRulesetDigest)
	fmt.Fprintf(output, "Privacy evaluation:   %s\n", strings.ToUpper(report.PrivacyEvaluation))
	fmt.Fprintf(output, "SPDX attachment:      %s\n", presenceText(report.SBOMPresent))
	if report.SBOMPresent {
		fmt.Fprintf(output, "SPDX format:          %s\n", report.SBOMFormat)
		fmt.Fprintf(output, "SPDX digest:          %s\n", report.SBOMDigest)
	}
	if report.SBOMOrigin != "" {
		fmt.Fprintf(output, "SPDX origin:          %s\n", report.SBOMOrigin)
		fmt.Fprintf(output, "SPDX profile:         %s\n", report.SBOMProfile)
		fmt.Fprintf(output, "SPDX ruleset:         %s\n", report.SBOMRulesetDigest)
		fmt.Fprintf(output, "SPDX provenance:      %s\n", report.SBOMProvenanceDigest)
		fmt.Fprintf(output, "SPDX privacy profile: %s\n", report.SBOMPrivacyProfile)
		fmt.Fprintf(output, "SPDX privacy policy:  %s\n", report.SBOMPrivacyPolicy)
		fmt.Fprintf(output, "SPDX privacy ruleset: %s\n", report.SBOMPrivacyRulesetDigest)
		fmt.Fprintf(output, "SPDX privacy result:  %s\n", strings.ToUpper(report.SBOMPrivacyEvaluation))
		fmt.Fprintf(output, "SPDX currentness:     %s\n", strings.ToUpper(report.SBOMCurrentnessEvaluation))
	}
	if report.SBOMCurrentness != nil {
		fmt.Fprintf(output, "SPDX current profile: %s\n", report.SBOMCurrentness.Profile)
		fmt.Fprintf(output, "SPDX current reason:  %s\n", strings.ToUpper(report.SBOMCurrentness.Reason))
		fmt.Fprintln(output, "SPDX current checks:")
		for _, check := range report.SBOMCurrentness.Checks {
			fmt.Fprintf(output, "  %s: %s", strings.ToUpper(check.Dimension), strings.ToUpper(check.Status))
			if check.HistoricalDigest != "" {
				fmt.Fprintf(output, " historical=%s", check.HistoricalDigest)
			}
			if check.CurrentDigest != "" {
				fmt.Fprintf(output, " current=%s", check.CurrentDigest)
			}
			fmt.Fprintln(output)
		}
	}
	fmt.Fprintf(output, "Run:                  %s\n", report.RunID)
	fmt.Fprintf(output, "Verification:         %s\n", report.VerificationID)
	fmt.Fprintln(output, "Original results:")
	fmt.Fprintf(output, "  Functional:       %s\n", strings.ToUpper(string(report.OriginalResults.Functional)))
	fmt.Fprintf(output, "  Capability:       %s\n", strings.ToUpper(string(report.OriginalResults.Capability)))
	fmt.Fprintf(output, "  Reproducibility:  %s\n", strings.ToUpper(string(report.OriginalResults.Reproducibility)))
	fmt.Fprintf(output, "  Cleanup:          %s\n", strings.ToUpper(string(report.OriginalResults.Cleanup)))
	fmt.Fprintf(output, "  Evidence:         %s\n", strings.ToUpper(string(report.OriginalResults.Evidence)))
	fmt.Fprintf(output, "  Stored freshness: %s\n", strings.ToUpper(string(report.OriginalResults.Freshness)))
	fmt.Fprintf(output, "  Overall:          %s\n", strings.ToUpper(string(report.OriginalResults.Overall)))
}

func (a App) runDoctor(ctx context.Context, global globalOptions, args []string) int {
	flags := newFlagSet("doctor", a.Stderr)
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("doctor", global, err)
	}
	if flags.NArg() != 0 {
		return a.fail("doctor", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "doctor accepts no positional arguments."))
	}
	var features []domain.RunnerFeatures
	var err error
	if a.Deps.ProbeAll != nil {
		features, err = a.Deps.ProbeAll(ctx)
	}
	if err != nil {
		return a.fail("doctor", global, err)
	}
	if len(features) == 0 {
		features = []domain.RunnerFeatures{
			unavailableRunnerFeatures("none", "unknown", "No runner probe is linked."),
		}
	}
	data := map[string]any{
		"version": Version, "controllerOS": runtime.GOOS, "controllerArch": runtime.GOARCH,
		"runners": features, "offline": global.Offline,
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "doctor", Status: "ok", Data: data})
	}
	fmt.Fprintf(a.Stdout, "RepoPassport %s\nController: %s/%s\n", Version, runtime.GOOS, runtime.GOARCH)
	for _, feature := range features {
		fmt.Fprintf(a.Stdout, "\nRunner: %-8s Available: %-3s Linux workload: %s\n", feature.Backend, yesNo(feature.Available), feature.WorkloadOS)
		fmt.Fprintf(a.Stdout, "  Rootless                       %s\n", strings.ToUpper(feature.Rootless))
		fmt.Fprintf(a.Stdout, "  Network deny enforcement       %s\n", yesNo(feature.NetworkDeny))
		fmt.Fprintf(a.Stdout, "  Network attempt observation    %s\n", strings.ToUpper(feature.NetworkAttemptObservation))
		fmt.Fprintf(a.Stdout, "  Filesystem write observation   %s\n", strings.ToUpper(feature.FilesystemWriteObservation))
		fmt.Fprintf(a.Stdout, "  Filesystem read observation    %s\n", strings.ToUpper(feature.FilesystemReadObservation))
		fmt.Fprintf(a.Stdout, "  Process exec observation       %s\n", strings.ToUpper(feature.ProcessExecObservation))
		fmt.Fprintf(a.Stdout, "  Port observation               %s\n", strings.ToUpper(feature.PortObservation))
		fmt.Fprintf(a.Stdout, "  Resource limit enforcement     %s\n", yesNo(feature.ResourceLimitEnforcement))
		fmt.Fprintf(a.Stdout, "  Resource usage                 %s\n", strings.ToUpper(feature.ResourceUsage))
		if feature.Reason != "" {
			fmt.Fprintf(a.Stdout, "  Note: %s\n", feature.Reason)
		}
	}
	return 0
}

func (a App) runCapabilities(global globalOptions, args []string) int {
	flags := newFlagSet("capabilities", a.Stderr)
	if err := flags.Parse(args); err != nil {
		return a.flagFailure("capabilities", global, err)
	}
	if flags.NArg() != 0 {
		return a.fail("capabilities", global, domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "capabilities accepts no positional arguments."))
	}
	data := map[string]any{
		"implemented": []string{
			"local-source", "node-static-discovery", "python-static-discovery",
			"strict-v1alpha1-manifest", "deterministic-plan", "lock-drift",
			"docker-cli-runner", "podman-cli-runner", "cli-journey",
			"http-service-journey", "http-structured-json-assertions",
			"filesystem-retained-state-observation",
			"docker-engine-filesystem-diff-observation",
			"docker-outputs-activity-trace-observation",
			"versioned-json", "offline-static-html",
			"local-ed25519-attestation", "offline-attestation-verification",
			"portable-offline-trust-policy",
			"authenticated-offline-trust-policy-floor",
			"local-monotonic-trust-policy-state",
			"offline-trust-policy-authority-rotation",
			"local-combined-trust-policy-authority-state",
			"offline-trust-policy-authority-transition-chain",
			"local-combined-trust-policy-authority-chain-state",
			"trusted-pinned-local-freshness-reobservation",
			"purpose-separated-signed-release-index",
			"release-signer-rotation-revocation",
			"local-monotonic-release-state",
			"offline-release-policy-authority-rotation",
			"local-monotonic-release-authority-state",
		},
		"recognizedButUnsupported": []string{
			"remote-git-acquisition", "setup-domain-allowlist", "filesystem-read-observation",
			"filesystem-write-observation", "synthetic-secret-injection",
			"non-file-input-injection", "denied-network-destination-observation",
			"full-process-exec-observation", "port-listen-observation", "resource-usage-observation",
			"sigstore-attestation", "oidc-attestation", "kms-attestation",
			"tamper-resistant-trust-policy-state",
			"distributed-trust-policy-state",
			"trusted-policy-time",
			"offline-trust-policy-authority-compromise-recovery",
			"publisher-identity-attestation",
			"trusted-release-time",
			"release-authority-root-lifecycle",
			"trial", "publish",
		},
	}
	if global.Output == "json" {
		return a.writeJSON(envelope{SchemaVersion: "1", Command: "capabilities", Status: "ok", Data: data})
	}
	fmt.Fprintln(a.Stdout, "Implemented:")
	for _, item := range data["implemented"].([]string) {
		fmt.Fprintf(a.Stdout, "  YES  %s\n", item)
	}
	fmt.Fprintln(a.Stdout, "Recognized but unsupported:")
	for _, item := range data["recognizedButUnsupported"].([]string) {
		fmt.Fprintf(a.Stdout, "  NO   %s\n", item)
	}
	return 0
}

func (a App) probe(ctx context.Context, preferred string) (domain.RunnerFeatures, error) {
	if a.Deps.ProbeAll == nil {
		return unavailableRunnerFeatures(preferred, "unknown", "Runner integration is not linked."), nil
	}
	all, err := a.Deps.ProbeAll(ctx)
	if err != nil {
		return domain.RunnerFeatures{}, err
	}
	if preferred != "auto" {
		for _, item := range all {
			if item.Backend == preferred {
				return item, nil
			}
		}
		return unavailableRunnerFeatures(preferred, "unknown", "Runner command was not found."), nil
	}
	for _, item := range all {
		if item.Available {
			return item, nil
		}
	}
	if len(all) > 0 {
		return all[0], nil
	}
	return unavailableRunnerFeatures("none", "unknown", "No runner command was found."), nil
}

func unavailableRunnerFeatures(backend, workloadOS, reason string) domain.RunnerFeatures {
	return domain.RunnerFeatures{
		Backend:                    backend,
		Available:                  false,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 workloadOS,
		Rootless:                   "unknown",
		NetworkAttemptObservation:  "unavailable",
		ProcessExecObservation:     "unavailable",
		FilesystemWriteObservation: "unavailable",
		FilesystemReadObservation:  "unavailable",
		PortObservation:            "unavailable",
		ResourceUsage:              "unavailable",
		Reason:                     reason,
	}
}

func loadPlan(ctx context.Context, manifestPath, scenario string) (domain.ResolvedPlan, *manifest.Document, domain.SourceSnapshot, error) {
	absoluteManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return domain.ResolvedPlan{}, nil, domain.SourceSnapshot{}, err
	}
	doc, err := manifest.Load(absoluteManifest)
	if err != nil {
		return domain.ResolvedPlan{}, nil, domain.SourceSnapshot{}, err
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.Resolve(ctx, domain.SourceRef{Kind: "local", Value: filepath.Dir(absoluteManifest)})
	if err != nil {
		return domain.ResolvedPlan{}, nil, domain.SourceSnapshot{}, err
	}
	snapshot, err := provider.Fetch(ctx, resolved)
	if err != nil {
		return domain.ResolvedPlan{}, nil, domain.SourceSnapshot{}, err
	}
	plan, err := planner.Resolve(doc, snapshot, scenario)
	return plan, doc, snapshot, err
}

func parseGlobal(args []string) (globalOptions, []string, error) {
	options := globalOptions{Output: "text", LogLevel: "info", LogFormat: "text"}
	var remaining []string
	valueFlags := map[string]*string{
		"--config": &options.Config, "--data-dir": &options.DataDir, "--cache-dir": &options.CacheDir,
		"--log-level": &options.LogLevel, "--log-format": &options.LogFormat, "--output": &options.Output,
	}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "--json":
			options.Output = "json"
			continue
		case "--no-color":
			options.NoColor = true
			continue
		case "--offline":
			options.Offline = true
			continue
		case "--non-interactive":
			options.NonInteractive = true
			continue
		}
		if destination, ok := valueFlags[arg]; ok {
			if index+1 >= len(args) {
				return options, nil, fmt.Errorf("%s requires a value", arg)
			}
			index++
			*destination = args[index]
			continue
		}
		handled := false
		for name, destination := range valueFlags {
			prefix := name + "="
			if strings.HasPrefix(arg, prefix) {
				*destination = strings.TrimPrefix(arg, prefix)
				handled = true
				break
			}
		}
		if handled {
			continue
		}
		remaining = append(remaining, arg)
	}
	if options.LogFormat != "text" && options.LogFormat != "json" {
		return options, nil, errors.New("--log-format must be text or json")
	}
	return options, remaining, nil
}

func (a App) fail(command string, global globalOptions, err error) int {
	typed := asDomainError(err, domain.CodeInternal, "Command failed.")
	if global.Output == "json" {
		_ = a.writeJSON(envelope{SchemaVersion: "1", Command: command, Status: "error", Error: typed})
	} else {
		fmt.Fprintf(a.Stderr, "%s: %s\n", typed.Code, typed.Message)
		if typed.Suggestion != "" {
			fmt.Fprintf(a.Stderr, "Suggestion: %s\n", typed.Suggestion)
		}
	}
	return exitForError(typed)
}

func (a App) flagFailure(command string, global globalOptions, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	typed := domain.WrapError(domain.CodeManifestInvalid, domain.SeverityHigh, err.Error(), err)
	return a.fail(command, global, typed)
}

func (a App) writeJSON(value any) int {
	data, err := canonicaljson.Indent(value)
	if err != nil {
		fmt.Fprintf(a.Stderr, "INTERNAL_ERROR: structured output failed: %v\n", err)
		return 1
	}
	if _, err := a.Stdout.Write(data); err != nil {
		return 1
	}
	return 0
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	return set
}

func asDomainError(err error, fallback domain.ErrorCode, message string) *domain.Error {
	if err == nil {
		return nil
	}
	var typed *domain.Error
	if errors.As(err, &typed) {
		return typed
	}
	return domain.WrapError(fallback, domain.SeverityHigh, message, err)
}

func exitForError(err *domain.Error) int {
	switch err.Code {
	case domain.CodeManifestNotFound, domain.CodeManifestInvalid,
		domain.CodeManifestUnknownField, domain.CodeManifestLiteralSecret,
		domain.CodeManifestUnsafeShell, domain.CodePlanUnresolved,
		domain.CodePlanDrift, domain.CodeMutableBaseImage,
		domain.CodeRuntimeVersionUnresolved, domain.CodePolicyBundleUnresolved:
		return 2
	case domain.CodeRunnerUnavailable, domain.CodeRunnerFeatureUnavailable:
		return 3
	case domain.CodeEvidenceDigestMismatch, domain.CodeAttestationInvalid,
		domain.CodeAttestationUntrusted, domain.CodeEvidenceStale,
		domain.CodeEvidencePrivacyBlocked:
		return 7
	default:
		return 1
	}
}

func validateFailOn(value string) error {
	allowed := map[string]struct{}{
		"functional-fail": {}, "blocked": {}, "nonconforming": {}, "inconclusive": {},
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := allowed[item]; !ok {
			err := domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Unknown --fail-on verdict.")
			err.Details = map[string]any{"value": item}
			err.Suggestion = "Use functional-fail, blocked, nonconforming, or inconclusive."
			return err
		}
	}
	return nil
}

func failOnExit(result domain.VerificationResult, value string) int {
	if strings.TrimSpace(value) == "" {
		return 0
	}
	selected := map[string]struct{}{}
	for _, item := range strings.Split(value, ",") {
		selected[strings.TrimSpace(item)] = struct{}{}
	}
	if _, ok := selected["nonconforming"]; ok && result.Results.Overall == domain.OverallNonconforming {
		return 5
	}
	if _, ok := selected["functional-fail"]; ok && result.Results.Functional == domain.FunctionalFail {
		return 4
	}
	if _, ok := selected["blocked"]; ok && result.Results.Functional == domain.FunctionalBlocked {
		return 3
	}
	if _, ok := selected["inconclusive"]; ok && result.Results.Overall == domain.OverallInconclusive {
		return 6
	}
	return 0
}

func resolveSibling(manifestPath, target string) string {
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	absoluteManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return filepath.Clean(target)
	}
	return filepath.Join(filepath.Dir(absoluteManifest), target)
}

func statusFor(ok bool) string {
	if ok {
		return "ok"
	}
	return "invalid"
}

func yesNo(value bool) string {
	if value {
		return "YES"
	}
	return "NO"
}

func newRunID() string {
	return newOpaqueID("run")
}

func newVerificationID() string {
	return newOpaqueID("vrf")
}

func newOpaqueID(prefix string) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err == nil {
		return prefix + "_" + hex.EncodeToString(random)
	}
	return prefix + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func appendUniqueFinding(values []*domain.Error, value *domain.Error) []*domain.Error {
	if value == nil {
		return values
	}
	for _, existing := range values {
		if existing != nil && existing.Code == value.Code &&
			existing.Phase == value.Phase && existing.Message == value.Message {
			return values
		}
	}
	return append(values, value)
}

func removeWorkRoot(dataRoot, workRoot, runID string) error {
	absoluteDataRoot, err := filepath.Abs(dataRoot)
	if err != nil {
		return err
	}
	absoluteWorkRoot, err := filepath.Abs(workRoot)
	if err != nil {
		return err
	}
	expected := filepath.Join(absoluteDataRoot, "work", runID)
	if filepath.Clean(absoluteWorkRoot) != filepath.Clean(expected) ||
		filepath.Base(absoluteWorkRoot) != runID ||
		!strings.HasPrefix(runID, "run_") {
		return domain.NewError(
			domain.CodeSourcePathTraversal,
			domain.SeverityCritical,
			"Refusing to remove an unexpected controller work directory.",
		)
	}
	if err := controllerfs.RemoveTree(absoluteWorkRoot); err != nil {
		return err
	}
	if _, err := os.Lstat(absoluteWorkRoot); err == nil {
		return errors.New("controller work directory still exists after cleanup")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func defaultDataDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", domain.WrapError(
			domain.CodeInternal,
			domain.SeverityHigh,
			"Default controller data directory could not be resolved; pass --data-dir explicitly.",
			err,
		)
	}
	return filepath.Join(root, "repopass", "data"), nil
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(parent, candidate string) bool {
	parentAbsolute, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	candidateAbsolute, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(parentAbsolute, candidateAbsolute)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func sameFilesystemPath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(first, second)
	}
	return first == second
}

func rejectRepositoryLocalDataRoot(value string) error {
	current, err := filepath.Abs(value)
	if err != nil {
		return err
	}
	for {
		for _, marker := range []string{"repo-passport.yml", ".git"} {
			if _, statErr := os.Lstat(filepath.Join(current, marker)); statErr == nil {
				err := domain.NewError(
					domain.CodeEvidenceDigestMismatch,
					domain.SeverityCritical,
					"Refusing to trust a report store located inside a repository.",
				)
				err.Details = map[string]any{"dataRoot": value, "repositoryRoot": current}
				err.Suggestion = "Use the controller data directory or pass an external --data-dir."
				return err
			} else if !os.IsNotExist(statErr) {
				return statErr
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func mergeResources(left, right domain.ResourceSummary) domain.ResourceSummary {
	if right.PeakMemoryBytes > left.PeakMemoryBytes {
		left.PeakMemoryBytes = right.PeakMemoryBytes
	}
	left.CPUTimeMillis += right.CPUTimeMillis
	left.DurationMillis += right.DurationMillis
	if right.MaxProcesses > left.MaxProcesses {
		left.MaxProcesses = right.MaxProcesses
	}
	left.LogBytes += right.LogBytes
	if right.SandboxPeakMemoryBytes > left.SandboxPeakMemoryBytes {
		left.SandboxPeakMemoryBytes = right.SandboxPeakMemoryBytes
	}
	left.SandboxCPUTimeMillis += right.SandboxCPUTimeMillis
	if right.MaxTasks > left.MaxTasks {
		left.MaxTasks = right.MaxTasks
	}
	if right.WritableBytes > left.WritableBytes {
		left.WritableBytes = right.WritableBytes
	}
	left.OutputBytes += right.OutputBytes
	left.ObservedFields = intersectObservedResourceFields(
		left.ObservedFields,
		right.ObservedFields,
	)
	clearUnobservedResourceMetrics(&left)
	return left
}

func cloneResourceSummary(value domain.ResourceSummary) domain.ResourceSummary {
	value.ObservedFields = append(
		[]domain.ResourceObservedField(nil),
		value.ObservedFields...,
	)
	return value
}

func intersectObservedResourceFields(
	left []domain.ResourceObservedField,
	right []domain.ResourceObservedField,
) []domain.ResourceObservedField {
	rightSet := make(map[domain.ResourceObservedField]struct{}, len(right))
	for _, field := range right {
		rightSet[field] = struct{}{}
	}
	result := make([]domain.ResourceObservedField, 0, len(left))
	for _, field := range left {
		if _, ok := rightSet[field]; ok {
			result = append(result, field)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})
	return result
}

func clearUnobservedResourceMetrics(value *domain.ResourceSummary) {
	if value == nil {
		return
	}
	observed := make(
		map[domain.ResourceObservedField]struct{},
		len(value.ObservedFields),
	)
	for _, field := range value.ObservedFields {
		observed[field] = struct{}{}
	}
	if _, ok := observed[domain.ResourceObservedSandboxPeakMemoryBytes]; !ok {
		value.SandboxPeakMemoryBytes = 0
	}
	if _, ok := observed[domain.ResourceObservedSandboxCPUTimeMillis]; !ok {
		value.SandboxCPUTimeMillis = 0
	}
	if _, ok := observed[domain.ResourceObservedMaxTasks]; !ok {
		value.MaxTasks = 0
	}
	if _, ok := observed[domain.ResourceObservedWritableBytes]; !ok {
		value.WritableBytes = 0
	}
	if _, ok := observed[domain.ResourceObservedOutputBytes]; !ok {
		value.OutputBytes = 0
	}
}

func mergeRunnerFeatures(
	left domain.RunnerFeatures,
	right domain.RunnerFeatures,
) domain.RunnerFeatures {
	if left.Backend != right.Backend ||
		left.ControllerOS != right.ControllerOS ||
		left.WorkloadOS != right.WorkloadOS ||
		left.Rootless != right.Rootless ||
		left.EngineVersion != right.EngineVersion {
		left.Available = false
		left.NetworkDeny = false
		left.ResourceLimitEnforcement = false
		left.NetworkAttemptObservation = "unavailable"
		left.ProcessExecObservation = "unavailable"
		left.FilesystemWriteObservation = "unavailable"
		left.FilesystemReadObservation = "unavailable"
		left.PortObservation = "unavailable"
		left.ResourceUsage = "unavailable"
		left.EngineVersion = ""
		left.Reason = "Runner identity changed across repeats."
		return left
	}
	left.Available = left.Available && right.Available
	left.NetworkDeny = left.NetworkDeny && right.NetworkDeny
	left.ResourceLimitEnforcement =
		left.ResourceLimitEnforcement && right.ResourceLimitEnforcement
	left.NetworkAttemptObservation = minimumCoverage(
		left.NetworkAttemptObservation,
		right.NetworkAttemptObservation,
	)
	left.ProcessExecObservation = minimumCoverage(
		left.ProcessExecObservation,
		right.ProcessExecObservation,
	)
	left.FilesystemWriteObservation = minimumCoverage(
		left.FilesystemWriteObservation,
		right.FilesystemWriteObservation,
	)
	left.FilesystemReadObservation = minimumCoverage(
		left.FilesystemReadObservation,
		right.FilesystemReadObservation,
	)
	left.PortObservation = minimumCoverage(
		left.PortObservation,
		right.PortObservation,
	)
	left.ResourceUsage = minimumCoverage(
		left.ResourceUsage,
		right.ResourceUsage,
	)
	if !left.Available {
		left.Reason = "Runner became unavailable during repeated execution."
	}
	return left
}

func minimumCoverage(left, right string) string {
	rank := func(value string) int {
		switch value {
		case "full":
			return 4
		case "high":
			return 3
		case "best-effort":
			return 2
		case "enforcement-only":
			return 1
		default:
			return 0
		}
	}
	if rank(right) < rank(left) {
		return right
	}
	return left
}

func aggregateCleanupVerdict(
	left domain.CleanupVerdict,
	right domain.CleanupVerdict,
) domain.CleanupVerdict {
	rank := func(value domain.CleanupVerdict) int {
		switch value {
		case domain.CleanupUndeclaredResidue:
			return 4
		case domain.CleanupNotTested:
			return 3
		case domain.CleanupAllowedResidue:
			return 2
		case domain.CleanupClean:
			return 1
		default:
			return 3
		}
	}
	if rank(right) > rank(left) {
		return normalizedCleanupVerdict(right)
	}
	return normalizedCleanupVerdict(left)
}

func normalizedCleanupVerdict(
	value domain.CleanupVerdict,
) domain.CleanupVerdict {
	switch value {
	case domain.CleanupClean,
		domain.CleanupAllowedResidue,
		domain.CleanupUndeclaredResidue,
		domain.CleanupNotTested:
		return value
	default:
		return domain.CleanupNotTested
	}
}

func assertionFingerprint(
	assertions []domain.AssertionResult,
	cleanup domain.CleanupVerdict,
) (string, error) {
	type semanticAssertion struct {
		ID       string `json:"assertionId"`
		Type     string `json:"type"`
		Required bool   `json:"required"`
		Expected any    `json:"expected"`
		Actual   any    `json:"actual"`
		Status   string `json:"status"`
	}
	semantic := make([]semanticAssertion, 0, len(assertions))
	for _, assertion := range assertions {
		status := assertion.Status
		switch status {
		case "pass":
			status = "passed"
		case "fail":
			status = "failed"
		}
		semantic = append(semantic, semanticAssertion{
			ID:       assertion.ID,
			Type:     assertion.Type,
			Required: assertion.Required,
			Expected: assertion.Expected,
			Actual:   assertion.Actual,
			Status:   status,
		})
	}
	return canonicaljson.Digest(struct {
		Assertions []semanticAssertion   `json:"assertions"`
		Cleanup    domain.CleanupVerdict `json:"cleanup"`
	}{
		Assertions: semantic,
		Cleanup:    normalizedCleanupVerdict(cleanup),
	})
}

func topHelp() string {
	commands := []string{
		"attest --run ID          Sign a run; optionally publish --public-key-out FILE",
		"inspect [path-or-url]     Static source inventory and runtime discovery",
		"init [path]               Write an inferred manifest candidate and provenance",
		"validate [manifest]       Strict schema and semantic validation",
		"plan --scenario NAME     Resolve a deterministic plan; preview by default",
		"verify --scenario NAME   Execute a fixed journey in an isolated container",
		"verify-attestation FILE  Verify offline; optionally use an authenticated trust policy and local state",
		"report --run ID          Read an authoritative JSON/HTML/text report",
		"sign-release-index       Build and sign an exact external release index",
		"sign-release-policy      Sign a purpose-separated release-key policy",
		"sign-offline-trust-policy  Sign a purpose-separated offline verifier trust policy",
		"sign-offline-trust-policy-authority-transition  Sign a one-hop offline verifier policy-authority rotation",
		"assemble-offline-trust-policy-authority-transition-chain  Assemble an offline policy-authority rotation chain",
		"sign-release-authority-transition  Sign a one-hop release policy authority rotation",
		"assemble-release-authority-transition-chain  Assemble an offline authority rotation chain",
		"verify-release-index     Verify an exact release relative to an explicit root",
		"doctor                   Probe container runner and observer features",
		"capabilities             Show implemented and unsupported features",
		"version                  Print the CLI version",
	}
	sort.Strings(commands)
	return `RepoPassport - repository consumption contract and reference verifier

Usage:
  repopass [global options] <command> [options]

Commands:
  ` + strings.Join(commands, "\n  ") + `

Global options:
  --output text|json        Stable human or machine output
  --json                    Shorthand for --output json
  --data-dir PATH           Run artifacts and ephemeral work
  --cache-dir PATH          Reserved local content-addressed cache
  --config PATH             Reserved configuration file
  --offline                 Forbid optional remote resolution
  --non-interactive         Never prompt
  --log-level LEVEL         error, warn, info, or debug
  --log-format text|json    Diagnostic format
  --no-color                Disable ANSI color

Safety:
  inspect, init, validate, and plan never execute repository code.
  verify requires a compatible Linux Docker/Podman engine; missing coverage
  produces BLOCKED or INCONCLUSIVE, never a guessed PASS.
	  signing and verification commands are offline, local-key operations. A valid
	  signature, matching bundle digest, or companion is not trusted unless an
	  explicit --trust-key matches or a digest-pinned offline policy authorizes
	  the verifier-computed signer key ID. The complete signed-policy triple may
	  opt into --persist-trust-policy-state for controller-local monotonic state.
`
}

func verifierHelp() string {
	return `RepoPassport - portable offline attestation verifier

Usage:
  repopass-verify [global options] <command> [options]

Commands:
  verify-attestation FILE  Verify offline; optionally use an authenticated trust policy and local state
  verify-release-index     Verify an exact release relative to an explicit authority root
  version                  Print the verifier version

Global options:
  --output text|json        Stable human or machine output
  --json                    Shorthand for --output json
  --data-dir PATH           Controller-local trust-policy state
  --cache-dir PATH          Reserved local content-addressed cache
  --config PATH             Reserved configuration file
  --offline                 Forbid optional remote resolution
  --non-interactive         Never prompt
  --log-level LEVEL         error, warn, info, or debug
  --log-format text|json    Diagnostic format
  --no-color                Disable ANSI color

Trust boundary:
  Historical replay requires no worktree and no network. A valid signature,
  matching bundle digest, embedded key, or companion key does not establish
  trust. Acceptance requires an independently supplied exact trust key, a
  digest-pinned offline policy, or an authenticated signed policy.
  Release-index acceptance is purpose-separated and relative only to the
  explicit authority root supplied for that invocation. Publisher identity and
  trusted time remain unattested.
`
}
