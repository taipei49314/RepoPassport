package planner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/repopass/repopass/internal/atomicfile"
	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/manifest"
	"github.com/repopass/repopass/internal/runtimepolicy"
	"github.com/repopass/repopass/internal/structuredjson"
)

const (
	NodeAdapterVersion        = "0.1.0"
	PythonAdapterVersion      = "0.1.0"
	ObserverVersion           = "0.1.0"
	FilesystemObserverVersion = "0.6.0"
	ResourceObserverVersion   = "0.2.0"
	PortObserverVersion       = "0.3.0"
	CLIJourneyDriverVersion   = "0.2.0"
	HTTPJourneyDriverVersion  = "0.1.0"
	ResolvedPlanSchemaVersion = "4"
	CleanupClassifierVersion  = "0.1.0"
)

func Resolve(doc *manifest.Document, snapshot domain.SourceSnapshot, scenarioName string) (domain.ResolvedPlan, error) {
	if validationErrors := manifest.Validate(doc); len(validationErrors) > 0 {
		first := validationErrors[0]
		first.Details = mergeDetails(first.Details, map[string]any{"validationErrorCount": len(validationErrors)})
		return domain.ResolvedPlan{}, first
	}
	scenario, ok := doc.Manifest.Spec.Scenarios[scenarioName]
	if !ok {
		e := domain.NewError(domain.CodePlanUnresolved, domain.SeverityHigh, "Requested scenario was not found.")
		e.Details = map[string]any{"scenario": scenarioName}
		return domain.ResolvedPlan{}, e
	}
	if err := validateExecutableProfile(scenarioName, scenario); err != nil {
		return domain.ResolvedPlan{}, err
	}
	if err := validateEvidenceProfile(doc.Manifest.Spec.Evidence); err != nil {
		return domain.ResolvedPlan{}, err
	}
	environment := doc.Manifest.Spec.Environments[scenario.Environment]
	if err := validateSchemaExecutionFeatures(scenarioName, environment, scenario); err != nil {
		return domain.ResolvedPlan{}, err
	}
	if len(scenario.Secrets) > 0 {
		e := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Synthetic secret injection is recognized but not implemented by the v0.1 local runner.",
		)
		e.Details = map[string]any{"scenario": scenarioName, "secretCount": len(scenario.Secrets)}
		return domain.ResolvedPlan{}, e
	}
	if err := validateResolvedInputs(snapshot, scenario); err != nil {
		return domain.ResolvedPlan{}, err
	}
	if !manifest.IsPinnedImage(environment.BaseImage.Reference) {
		e := domain.NewError(domain.CodeMutableBaseImage, domain.SeverityHigh, "Plan requires a digest-pinned base image.")
		e.Details = map[string]any{"reference": environment.BaseImage.Reference}
		e.Suggestion = "Replace the mutable tag with registry/repository@sha256:<64 hex>."
		return domain.ResolvedPlan{}, e
	}
	if !manifest.IsExactRuntimeVersion(environment.Runtime.Version) {
		e := domain.NewError(domain.CodeRuntimeVersionUnresolved, domain.SeverityHigh, "Plan requires an exact runtime version.")
		e.Details = map[string]any{"version": environment.Runtime.Version}
		e.Suggestion = "Resolve the version range to an exact version before planning."
		return domain.ResolvedPlan{}, e
	}
	imageDigest := environment.BaseImage.Reference[strings.LastIndex(environment.BaseImage.Reference, "@")+1:]
	if err := runtimepolicy.Validate(
		environment.Runtime.Adapter,
		environment.Runtime.Version,
		environment.BaseImage.Reference,
		imageDigest,
		"linux/"+environment.Platform.Architecture,
	); err != nil {
		err.Details["scenario"] = scenarioName
		err.Details["environment"] = scenario.Environment
		return domain.ResolvedPlan{}, err
	}
	if doc.Manifest.Spec.Policies.Profile != "baseline-v1" {
		e := domain.NewError(domain.CodePolicyBundleUnresolved, domain.SeverityHigh, "Only the built-in baseline-v1 policy is pinned in this release.")
		e.Details = map[string]any{"profile": doc.Manifest.Spec.Policies.Profile}
		return domain.ResolvedPlan{}, e
	}

	policyDigest, err := canonicaljson.Digest(map[string]any{
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
		return domain.ResolvedPlan{}, domain.WrapError(domain.CodePolicyBundleUnresolved, domain.SeverityHigh, "Policy bundle could not be canonicalized.", err)
	}

	capabilities := resolvedCapabilities(scenario)
	commands := resolvedCommands(scenario)
	httpJourney, err := resolvedHTTPJourney(scenario)
	if err != nil {
		return domain.ResolvedPlan{}, domain.WrapError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"HTTP journey could not be materialized.",
			err,
		)
	}
	journeyAssertions, err := resolvedAssertions(scenario, snapshot)
	if err != nil {
		return domain.ResolvedPlan{}, err
	}
	observers := sortedUnique(append(
		append([]string{}, scenario.Verification.RequiredObservers...),
		"filesystem-write",
		"network-enforcement",
		"port-listen",
		"process-exec",
	))
	features := []string{
		"linux-container",
		"platform:linux/" + environment.Platform.Architecture,
		"read-only-source",
		"isolated-workspace",
		"network-deny",
		"bounded-logs",
		"process-cleanup",
		"cleanup-residue-classification",
	}
	for _, observer := range observers {
		features = append(features, "observer:"+observer)
	}
	for phase, capability := range capabilities {
		if len(capability.Network.Allow) > 0 {
			features = append(features, "network-allowlist:"+string(phase))
		}
	}
	if httpJourney != nil {
		features = append(
			features,
			"background-service",
			"loopback-http-driver",
			"service-signal",
		)
	}
	features = sortedUnique(features)
	adapterVersion := NodeAdapterVersion
	if environment.Runtime.Adapter == "python" {
		adapterVersion = PythonAdapterVersion
	}
	plan := domain.ResolvedPlan{
		SchemaVersion: ResolvedPlanSchemaVersion,
		Source: domain.PlanSource{
			Identity: snapshot.Identity, Commit: snapshot.Commit, TreeDigest: snapshot.TreeDigest,
		},
		ManifestDigest:     doc.Digest,
		Scenario:           scenarioName,
		Environment:        scenario.Environment,
		RuntimeAdapter:     environment.Runtime.Adapter,
		RuntimeVersion:     environment.Runtime.Version,
		BaseImageReference: environment.BaseImage.Reference,
		BaseImageDigest:    imageDigest,
		Resources: domain.ResourceLimits{
			CPUMillis:   parseCPU(environment.Resources.CPU),
			MemoryBytes: parseSize(environment.Resources.Memory),
			DiskBytes:   parseSize(environment.Resources.Disk),
			PIDs:        environment.Resources.PIDs,
		},
		Inputs:               resolvedInputs(scenario),
		AdapterVersions:      map[string]string{environment.Runtime.Adapter: adapterVersion},
		ObserverVersions:     resolvedObserverVersions(observers),
		JourneyDriver:        scenario.Phases.Exercise.Driver.Type,
		JourneyDriverVersion: JourneyDriverVersion(scenario.Phases.Exercise.Driver.Type),
		Commands:             commands,
		JourneyAssertions:    journeyAssertions,
		HTTPJourney:          httpJourney,
		Cleanup: domain.PlanCleanup{
			ClassifierVersion: CleanupClassifierVersion,
			AllowedResidue: append(
				[]string{},
				scenario.Verification.Cleanup.AllowedResidue...,
			),
		},
		Evidence: domain.PlanEvidence{
			Profile: doc.Manifest.Spec.Evidence.Profile,
			Include: sortedUnique(append([]string{}, doc.Manifest.Spec.Evidence.Include...)),
			Exclude: sortedUnique(append([]string{}, doc.Manifest.Spec.Evidence.Exclude...)),
		},
		Capabilities:           capabilities,
		RequiredRunnerFeatures: features,
		ObserverSet:            observers,
		RepeatCount:            scenario.Verification.Repeats,
		SuccessThreshold:       scenario.Verification.SuccessThreshold,
		PolicyBundleDigest:     policyDigest,
	}
	plan.PlanDigest, err = digestPlan(plan)
	if err != nil {
		return domain.ResolvedPlan{}, domain.WrapError(domain.CodePlanUnresolved, domain.SeverityHigh, "Plan digest could not be computed.", err)
	}
	return plan, nil
}

func JourneyDriverVersion(driver string) string {
	switch driver {
	case "cli":
		return CLIJourneyDriverVersion
	case "http":
		return HTTPJourneyDriverVersion
	default:
		return ""
	}
}

func validateExecutableProfile(scenarioName string, scenario manifest.ScenarioSpec) error {
	exercise := scenario.Phases.Exercise
	for inputName, input := range scenario.Inputs {
		if (input.Type == "file" || input.Type == "directory") &&
			input.Choices != nil {
			err := domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityHigh,
				"Input choices are recognized but unavailable for executable file and directory inputs.",
			)
			err.Details = map[string]any{
				"scenario":    scenarioName,
				"input":       inputName,
				"feature":     "executable-input-choices",
				"choiceCount": len(input.Choices),
			}
			return err
		}
		if input.Required {
			continue
		}
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Optional inputs are recognized but unavailable in the v0.1 local runner.",
		)
		err.Details = map[string]any{
			"scenario": scenarioName,
			"input":    inputName,
			"feature":  "optional-input",
		}
		return err
	}
	if exercise == nil {
		return nil
	}
	if exercise.Driver.Type == "http" {
		if err := validateHTTPAlphaExecutionContract(
			scenarioName,
			scenario,
		); err != nil {
			return err
		}
		for _, step := range exercise.Driver.Steps {
			if step.Assert == nil {
				continue
			}
			assertion := step.Assert
			if assertion.Required != nil && !*assertion.Required {
				err := domain.NewError(
					domain.CodeRunnerFeatureUnavailable,
					domain.SeverityHigh,
					"Optional HTTP assertions are recognized but unavailable in the alpha runner.",
				)
				err.Details = map[string]any{
					"scenario":  scenarioName,
					"assertion": assertion.ID,
					"feature":   "optional-http-assertion",
				}
				return err
			}
		}
		return nil
	}
	if exercise.Driver.Type != "cli" {
		return nil
	}
	if exercise.Driver.StdinFixture != "" {
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"CLI stdin fixtures are recognized by the public schema but unavailable in the v0.1 local runner.",
		)
		err.Details = map[string]any{"scenario": scenarioName, "feature": "cli-stdin-fixture"}
		return err
	}
	for _, assertion := range exercise.Driver.Assertions {
		if assertion.Required != nil && !*assertion.Required {
			err := domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityHigh,
				"Optional CLI assertions are recognized but unavailable in the v0.1 local runner.",
			)
			err.Details = map[string]any{
				"scenario":  scenarioName,
				"assertion": assertion.ID,
				"feature":   "optional-cli-assertion",
			}
			return err
		}
		if assertion.JSONFile != nil || assertion.Response != nil {
			err := domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityHigh,
				"Schema-backed CLI assertions are recognized but unavailable in the v0.1 local runner.",
			)
			err.Details = map[string]any{
				"scenario":  scenarioName,
				"assertion": assertion.ID,
				"feature":   "schema-backed-cli-assertion",
			}
			return err
		}
	}
	return nil
}

func validateHTTPAlphaExecutionContract(
	scenarioName string,
	scenario manifest.ScenarioSpec,
) error {
	exercise := scenario.Phases.Exercise
	if exercise == nil || exercise.Driver.Type != "http" {
		return nil
	}
	fail := func(message, field string) error {
		err := domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			message,
		)
		err.Details = map[string]any{
			"scenario": scenarioName,
			"field":    field,
		}
		return err
	}
	if len(exercise.Driver.Steps) > domain.AlphaHTTPMaxJourneySteps {
		return fail(
			"HTTP execution contract exceeds 128 ordered steps.",
			"phases.exercise.driver.steps",
		)
	}
	if scenario.Phases.Run == nil ||
		scenario.Phases.Run.Service == nil ||
		scenario.Phases.Cleanup == nil {
		return fail(
			"HTTP execution contract has no service cleanup signal.",
			"phases.cleanup.steps",
		)
	}
	service := scenario.Phases.Run.Service
	declaredPort := 0
	listeners := scenario.Capabilities[domain.PhaseRun].Ports.Listen
	if len(listeners) == 1 {
		declaredPort = listeners[0].Port
	}
	readiness := service.Readiness.HTTP
	if readiness == nil {
		return fail(
			"HTTP execution contract has no readiness probe.",
			"phases.run.service.readiness.http",
		)
	}
	if _, port, err := domain.ParseAlphaHTTPURL(readiness.URL); err != nil ||
		declaredPort == 0 ||
		port != declaredPort {
		return fail(
			"HTTP readiness URL must use the canonical declared loopback port.",
			"phases.run.service.readiness.http.url",
		)
	}
	if readiness.Status < domain.AlphaHTTPMinimumStatus ||
		readiness.Status > domain.AlphaHTTPMaximumStatus {
		return fail(
			"HTTP readiness status must be between 200 and 599.",
			"phases.run.service.readiness.http.status",
		)
	}
	if _, err := domain.ParseAlphaHTTPDuration(
		readiness.Timeout,
		domain.AlphaHTTPMaxReadinessTime,
	); err != nil {
		return fail(
			"HTTP readiness timeout must be a whole-millisecond value between 1ms and 2m.",
			"phases.run.service.readiness.http.timeout",
		)
	}

	requestFallback := exercise.Timeout
	if requestFallback == "" {
		requestFallback = time.Minute.String()
	}
	if _, err := domain.ParseAlphaHTTPDuration(
		requestFallback,
		domain.AlphaHTTPMaxRequestTime,
	); err != nil {
		return fail(
			"HTTP request timeout fallback must use whole milliseconds.",
			"phases.exercise.timeout",
		)
	}
	requestCount := 0
	for index, step := range exercise.Driver.Steps {
		if step.Request != nil {
			requestCount++
			request := step.Request
			if _, port, err := domain.ParseAlphaHTTPURL(request.URL); err != nil ||
				port != declaredPort {
				return fail(
					"HTTP request URL must use the canonical declared loopback port.",
					fmt.Sprintf(
						"phases.exercise.driver.steps[%d].request.url",
						index,
					),
				)
			}
			requestTimeout := request.Timeout
			if requestTimeout == "" {
				requestTimeout = requestFallback
			}
			if _, err := domain.ParseAlphaHTTPDuration(
				requestTimeout,
				domain.AlphaHTTPMaxRequestTime,
			); err != nil {
				return fail(
					"HTTP request timeout must use whole milliseconds.",
					fmt.Sprintf(
						"phases.exercise.driver.steps[%d].request.timeout",
						index,
					),
				)
			}
			if err := domain.ValidateAlphaHTTPHeaders(
				request.Headers,
				request.HasJSON(),
			); err != nil {
				return fail(
					"HTTP effective headers exceed the alpha limits.",
					fmt.Sprintf(
						"phases.exercise.driver.steps[%d].request.headers",
						index,
					),
				)
			}
			if request.HasBody() && request.HasJSON() {
				return fail(
					"HTTP request body and JSON are mutually exclusive.",
					fmt.Sprintf(
						"phases.exercise.driver.steps[%d].request",
						index,
					),
				)
			}
			if len([]byte(request.Body)) >
				domain.AlphaHTTPMaxRequestBodyBytes {
				return fail(
					"HTTP request body exceeds the 1 MiB byte limit.",
					fmt.Sprintf(
						"phases.exercise.driver.steps[%d].request.body",
						index,
					),
				)
			}
			if request.HasJSON() {
				encoded, err := canonicaljson.Marshal(request.JSON)
				if err != nil ||
					len(encoded) >
						domain.AlphaHTTPMaxRequestBodyBytes {
					return fail(
						"HTTP request JSON exceeds the canonical 1 MiB byte limit.",
						fmt.Sprintf(
							"phases.exercise.driver.steps[%d].request.json",
							index,
						),
					)
				}
			}
			continue
		}
		if step.Assert != nil {
			if step.Assert.FileExists != "" {
				if err := domain.ValidateAlphaHTTPOutputPath(
					step.Assert.FileExists,
				); err != nil {
					return fail(
						"HTTP file assertions must remain within bounded normalized /outputs paths.",
						fmt.Sprintf(
							"phases.exercise.driver.steps[%d].assert.fileExists",
							index,
						),
					)
				}
			}
			if response := step.Assert.Response; response != nil &&
				response.Status != 0 &&
				(response.Status < domain.AlphaHTTPMinimumStatus ||
					response.Status > domain.AlphaHTTPMaximumStatus) {
				return fail(
					"HTTP response status must be between 200 and 599.",
					fmt.Sprintf(
						"phases.exercise.driver.steps[%d].assert.response.status",
						index,
					),
				)
			}
			if response := step.Assert.Response; response != nil {
				if response.BodyContains != nil &&
					(*response.BodyContains == "" ||
						len([]byte(*response.BodyContains)) >
							domain.AlphaHTTPMaxResponseMatchBytes) {
					return fail(
						"HTTP response bodyContains is empty or exceeds the 1 MiB byte limit.",
						fmt.Sprintf(
							"phases.exercise.driver.steps[%d].assert.response.bodyContains",
							index,
						),
					)
				}
				if response.Header != nil &&
					(strings.ContainsAny(
						response.Header.Contains,
						"\r\n\x00",
					) ||
						len([]byte(response.Header.Contains)) >
							domain.AlphaHTTPMaxHeaderValueBytes) {
					return fail(
						"HTTP response header match exceeds the alpha limits.",
						fmt.Sprintf(
							"phases.exercise.driver.steps[%d].assert.response.header.contains",
							index,
						),
					)
				}
			}
		}
	}
	if requestCount > domain.AlphaHTTPMaxRequestSteps {
		return fail(
			"HTTP execution contract exceeds 32 request steps.",
			"phases.exercise.driver.steps",
		)
	}
	serviceID := service.ID
	signalIndex := -1
	var signal *manifest.SignalAction
	for index := range scenario.Phases.Cleanup.Steps {
		step := &scenario.Phases.Cleanup.Steps[index]
		if step.Signal != nil &&
			step.Signal.Target == serviceID {
			if signal != nil {
				return fail(
					"HTTP execution contract has more than one service signal.",
					"phases.cleanup.steps",
				)
			}
			signal = step.Signal
			signalIndex = index
		}
	}
	if signal == nil ||
		signalIndex != len(scenario.Phases.Cleanup.Steps)-1 {
		return fail(
			"HTTP service signal must be the final cleanup step.",
			"phases.cleanup.steps",
		)
	}
	if _, err := domain.ParseAlphaHTTPDuration(
		signal.GracePeriod,
		domain.AlphaHTTPMaxSignalGrace,
	); err != nil {
		return fail(
			"HTTP service signal gracePeriod is required and must be a whole-millisecond value between 1ms and 10s.",
			fmt.Sprintf(
				"phases.cleanup.steps[%d].signal.gracePeriod",
				signalIndex,
			),
		)
	}
	return nil
}

func validateEvidenceProfile(evidence manifest.EvidenceSpec) error {
	expectedInclude := []string{"normalized-observations", "verification-summary"}
	expectedSBOMInclude := []string{"normalized-observations", "sbom", "verification-summary"}
	expectedExclude := []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"}
	if evidence.Profile == "minimal-public" &&
		(exactStringSet(evidence.Include, expectedInclude) ||
			exactStringSet(evidence.Include, expectedSBOMInclude)) &&
		exactStringSet(evidence.Exclude, expectedExclude) {
		return nil
	}
	err := domain.NewError(
		domain.CodeRunnerFeatureUnavailable,
		domain.SeverityHigh,
		"Custom evidence profiles and attachment selection are recognized but unavailable in the v0.1 local runner.",
	)
	err.Details = map[string]any{
		"feature":          "evidence-profile-selection",
		"profile":          evidence.Profile,
		"include":          evidence.Include,
		"exclude":          evidence.Exclude,
		"supportedProfile": "minimal-public",
		"supportedInclude": []any{expectedInclude, expectedSBOMInclude},
		"supportedExclude": expectedExclude,
	}
	return err
}

func exactStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	counts := make(map[string]int, len(actual))
	for _, value := range actual {
		counts[value]++
	}
	for _, value := range expected {
		if counts[value] != 1 {
			return false
		}
		delete(counts, value)
	}
	return len(counts) == 0
}

func OverrideRepeats(plan domain.ResolvedPlan, requested int) (domain.ResolvedPlan, error) {
	if requested < plan.RepeatCount {
		err := domain.NewError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"--repeats cannot weaken the manifest repeat policy.",
		)
		err.Details = map[string]any{
			"manifestRepeats": plan.RepeatCount,
			"requested":       requested,
		}
		return domain.ResolvedPlan{}, err
	}
	if requested > 10 {
		return domain.ResolvedPlan{}, domain.NewError(
			domain.CodeManifestInvalid,
			domain.SeverityHigh,
			"--repeats must not exceed 10.",
		)
	}
	if requested == plan.RepeatCount {
		return plan, nil
	}
	allowedFailures := plan.RepeatCount - plan.SuccessThreshold
	plan.RepeatCount = requested
	plan.SuccessThreshold = requested - allowedFailures
	digest, err := digestPlan(plan)
	if err != nil {
		return domain.ResolvedPlan{}, domain.WrapError(
			domain.CodePlanUnresolved,
			domain.SeverityHigh,
			"Effective repeat policy could not be bound into the plan digest.",
			err,
		)
	}
	plan.PlanDigest = digest
	return plan, nil
}

func WriteLock(path string, plan domain.ResolvedPlan) error {
	data, err := canonicaljson.Indent(plan)
	if err != nil {
		return domain.WrapError(domain.CodePlanUnresolved, domain.SeverityHigh, "Lockfile could not be encoded.", err)
	}
	if err := atomicfile.Write(path, data, 0o644); err != nil {
		return domain.WrapError(domain.CodePlanUnresolved, domain.SeverityHigh, "Lockfile could not be written.", err)
	}
	return nil
}

func CheckLock(path string, plan domain.ResolvedPlan) error {
	if plan.SchemaVersion != ResolvedPlanSchemaVersion {
		err := domain.NewError(
			domain.CodePlanDrift,
			domain.SeverityHigh,
			"Current lock check requires the current resolved-plan schema.",
		)
		err.Details = map[string]any{
			"expectedSchemaVersion": ResolvedPlanSchemaVersion,
			"actualSchemaVersion":   plan.SchemaVersion,
		}
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.WrapError(domain.CodePlanDrift, domain.SeverityHigh, "Committed lockfile could not be read.", err)
	}
	var existing domain.ResolvedPlan
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&existing); err != nil {
		return domain.WrapError(domain.CodePlanDrift, domain.SeverityHigh, "Committed lockfile is invalid.", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return domain.WrapError(
			domain.CodePlanDrift,
			domain.SeverityHigh,
			"Committed lockfile contains trailing data.",
			err,
		)
	}
	if existing.SchemaVersion != ResolvedPlanSchemaVersion {
		err := domain.NewError(
			domain.CodePlanDrift,
			domain.SeverityHigh,
			"Committed lockfile uses a non-current resolved-plan schema.",
		)
		err.Details = map[string]any{
			"expectedSchemaVersion": ResolvedPlanSchemaVersion,
			"actualSchemaVersion":   existing.SchemaVersion,
		}
		err.Suggestion = "Review the schema upgrade, then regenerate passport.lock.json."
		return err
	}
	currentCanonical, err := canonicaljson.Marshal(plan)
	if err != nil {
		return err
	}
	existingCanonical, err := canonicaljson.Marshal(existing)
	if err != nil {
		return err
	}
	if string(currentCanonical) != string(existingCanonical) {
		e := domain.NewError(domain.CodePlanDrift, domain.SeverityHigh, "Manifest resolves to a different plan than the committed lockfile.")
		e.Details = map[string]any{"expectedPlanDigest": existing.PlanDigest, "actualPlanDigest": plan.PlanDigest}
		e.Suggestion = "Review the semantic change, then regenerate passport.lock.json."
		return e
	}
	return nil
}

func digestPlan(plan domain.ResolvedPlan) (string, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	var semantic map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&semantic); err != nil {
		return "", err
	}
	delete(semantic, "planDigest")
	return canonicaljson.Digest(semantic)
}

func resolvedCapabilities(scenario manifest.ScenarioSpec) map[domain.Phase]domain.CapabilitySet {
	result := make(map[domain.Phase]domain.CapabilitySet)
	for _, phase := range domain.OrderedPhases {
		capability, ok := scenario.Capabilities[phase]
		if !ok {
			capability = domain.CapabilitySet{
				Network: domain.NetworkCapability{Deny: true},
			}
		}
		capability.Filesystem.Read = sortedUnique(capability.Filesystem.Read)
		capability.Filesystem.Write = sortedUnique(capability.Filesystem.Write)
		capability.Process.Exec = sortedUnique(capability.Process.Exec)
		sort.Slice(capability.Network.Allow, func(i, j int) bool {
			left := fmt.Sprintf("%s:%05d", capability.Network.Allow[i].Host, capability.Network.Allow[i].Port)
			right := fmt.Sprintf("%s:%05d", capability.Network.Allow[j].Host, capability.Network.Allow[j].Port)
			return left < right
		})
		sort.Slice(capability.Ports.Listen, func(i, j int) bool {
			left := fmt.Sprintf("%s:%05d", capability.Ports.Listen[i].Host, capability.Ports.Listen[i].Port)
			right := fmt.Sprintf("%s:%05d", capability.Ports.Listen[j].Host, capability.Ports.Listen[j].Port)
			return left < right
		})
		if scenario.Phases.Exercise != nil &&
			scenario.Phases.Exercise.Driver.Type == "http" &&
			phase == domain.PhaseRun {
			for index := range capability.Ports.Listen {
				if capability.Ports.Listen[index].Protocol == "" {
					capability.Ports.Listen[index].Protocol = "tcp"
				}
			}
		}
		result[phase] = capability
	}
	return result
}

func resolvedInputs(scenario manifest.ScenarioSpec) []domain.PlanInput {
	names := make([]string, 0, len(scenario.Inputs))
	for name := range scenario.Inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]domain.PlanInput, 0, len(names))
	for _, name := range names {
		input := scenario.Inputs[name]
		mountPath := input.Mount.Path
		if mountPath == "" {
			mountPath = "/inputs/" + name
		}
		result = append(result, domain.PlanInput{
			Name: name, Type: input.Type, Fixture: input.Fixture,
			MountPath: mountPath, ReadOnly: input.Mount.ReadOnly,
		})
	}
	return result
}

func validateResolvedInputs(snapshot domain.SourceSnapshot, scenario manifest.ScenarioSpec) error {
	files := make(map[string]struct{}, len(snapshot.Inventory))
	for _, entry := range snapshot.Inventory {
		files[entry.Path] = struct{}{}
	}
	mounts := make(map[string]string, len(scenario.Inputs))
	for name, input := range scenario.Inputs {
		if input.Type != "file" && input.Type != "directory" {
			e := domain.NewError(
				domain.CodeRunnerFeatureUnavailable,
				domain.SeverityHigh,
				"The v0.1 local plan resolver supports only file and directory inputs.",
			)
			e.Details = map[string]any{"input": name, "type": input.Type}
			return e
		}
		fixture := strings.TrimPrefix(strings.ReplaceAll(input.Fixture, "\\", "/"), "./")
		found := false
		switch input.Type {
		case "file":
			_, found = files[fixture]
		case "directory":
			prefix := strings.TrimSuffix(fixture, "/") + "/"
			for candidate := range files {
				if strings.HasPrefix(candidate, prefix) {
					found = true
					break
				}
			}
		default:
			found = true
		}
		if !found {
			e := domain.NewError(domain.CodeSourceNotFound, domain.SeverityHigh, "Declared verification fixture was not found in the source snapshot.")
			e.Details = map[string]any{"input": name, "fixture": fixture}
			return e
		}
		mountPath := input.Mount.Path
		if mountPath == "" {
			mountPath = "/inputs/" + name
		}
		for existingMount, previous := range mounts {
			if mountPath == existingMount ||
				strings.HasPrefix(mountPath, strings.TrimSuffix(existingMount, "/")+"/") ||
				strings.HasPrefix(existingMount, strings.TrimSuffix(mountPath, "/")+"/") {
				e := domain.NewError(domain.CodePlanUnresolved, domain.SeverityHigh, "Two inputs resolve to overlapping sandbox mount paths.")
				e.Details = map[string]any{
					"first": previous, "second": name,
					"firstMountPath": existingMount, "secondMountPath": mountPath,
				}
				return e
			}
		}
		mounts[mountPath] = name
	}
	return nil
}

func resolvedCommands(scenario manifest.ScenarioSpec) []domain.PlanCommand {
	var commands []domain.PlanCommand
	appendCommandPhase := func(phase domain.Phase, value *manifest.CommandPhase, fallback time.Duration) {
		if value == nil {
			return
		}
		timeout := normalizedTimeout(value.Timeout, fallback)
		for _, step := range value.Steps {
			if step.Run != nil && len(step.Run.Command) > 0 {
				commands = append(commands, domain.PlanCommand{Phase: phase, ID: step.ID, Argv: step.Run.Command, Timeout: timeout, Role: "foreground"})
			} else if step.Signal != nil {
				commands = append(commands, domain.PlanCommand{
					Phase: phase, ID: step.ID, Timeout: timeout, Role: "signal",
					Signal: &domain.PlanSignal{
						Target: step.Signal.Target, Type: step.Signal.Type,
						GracePeriod: step.Signal.GracePeriod,
					},
				})
			}
		}
	}
	appendCommandPhase(domain.PhasePrepare, scenario.Phases.Prepare, 2*time.Minute)
	appendCommandPhase(domain.PhaseSetup, scenario.Phases.Setup, 5*time.Minute)
	appendCommandPhase(domain.PhaseBuild, scenario.Phases.Build, 5*time.Minute)
	if run := scenario.Phases.Run; run != nil {
		timeout := normalizedTimeout(run.Timeout, 2*time.Minute)
		for _, step := range run.Steps {
			if step.Run != nil && len(step.Run.Command) > 0 {
				commands = append(commands, domain.PlanCommand{Phase: domain.PhaseRun, ID: step.ID, Argv: step.Run.Command, Timeout: timeout, Role: "foreground"})
			} else if step.Signal != nil {
				commands = append(commands, domain.PlanCommand{
					Phase: domain.PhaseRun, ID: step.ID, Timeout: timeout, Role: "signal",
					Signal: &domain.PlanSignal{
						Target: step.Signal.Target, Type: step.Signal.Type,
						GracePeriod: step.Signal.GracePeriod,
					},
				})
			}
		}
		if run.Service != nil {
			readiness := run.Service.Readiness.HTTP
			command := domain.PlanCommand{
				Phase:   domain.PhaseRun,
				ID:      run.Service.ID,
				Argv:    run.Service.Command,
				Timeout: timeout,
				Role:    "service",
			}
			if readiness != nil {
				command.Readiness = &domain.PlanHTTPReadiness{
					URL:     readiness.URL,
					Status:  readiness.Status,
					Timeout: normalizedTimeout(readiness.Timeout, 30*time.Second),
				}
			}
			commands = append(commands, command)
		}
	}
	if exercise := scenario.Phases.Exercise; exercise != nil && len(exercise.Driver.Command) > 0 {
		commands = append(commands, domain.PlanCommand{
			Phase: domain.PhaseExercise, ID: "journey-cli", Argv: exercise.Driver.Command,
			Timeout: normalizedTimeout(exercise.Timeout, time.Minute), Role: "journey",
		})
	}
	appendCommandPhase(domain.PhaseCleanup, scenario.Phases.Cleanup, 30*time.Second)
	if commands == nil {
		return []domain.PlanCommand{}
	}
	return commands
}

func resolvedObserverVersions(observers []string) map[string]string {
	result := make(map[string]string, len(observers))
	for _, observer := range observers {
		version := ObserverVersion
		switch observer {
		case "filesystem-write":
			version = FilesystemObserverVersion
		case "resource-usage":
			version = ResourceObserverVersion
		case "port-listen":
			version = PortObserverVersion
		}
		result[observer] = version
	}
	return result
}

func resolvedAssertions(
	scenario manifest.ScenarioSpec,
	snapshot domain.SourceSnapshot,
) ([]domain.PlanAssertion, error) {
	exercise := scenario.Phases.Exercise
	if exercise == nil {
		return []domain.PlanAssertion{}, nil
	}
	schemas := newSchemaResolver(snapshot)
	if exercise.Driver.Type == "http" {
		result := make([]domain.PlanAssertion, 0, len(exercise.Driver.Steps))
		for _, step := range exercise.Driver.Steps {
			if step.Assert == nil {
				continue
			}
			assertion := step.Assert
			resolved := domain.PlanAssertion{
				ID:         assertion.ID,
				FileExists: assertion.FileExists,
			}
			if assertion.Response != nil {
				response := assertion.Response
				resolvedResponse := &domain.PlanHTTPResponseAssertion{
					RequestID:    response.RequestID,
					BodyContains: cloneStringPointer(response.BodyContains),
				}
				if response.Status != 0 {
					status := response.Status
					resolvedResponse.Status = &status
				}
				if response.Header != nil {
					resolvedResponse.Header = &domain.PlanHTTPHeaderAssertion{
						Name:     response.Header.Name,
						Contains: response.Header.Contains,
					}
				}
				if response.JSONPath != nil {
					equals, err := canonicaljson.Marshal(
						response.JSONPath.Equals,
					)
					if err != nil {
						return nil, domain.WrapError(
							domain.CodePlanUnresolved,
							domain.SeverityHigh,
							"HTTP JSONPath equality value could not be canonicalized.",
							err,
						)
					}
					if _, err := structuredjson.Decode(
						equals,
						structuredjson.DefaultInstanceDecodeLimits(),
					); err != nil {
						return nil, domain.WrapError(
							domain.CodePlanUnresolved,
							domain.SeverityHigh,
							"HTTP JSONPath equality value is outside the bounded strict JSON profile.",
							err,
						)
					}
					resolvedResponse.JSONPath = &domain.PlanJSONPathAssertion{
						Path: response.JSONPath.Path,
						Equals: append(
							json.RawMessage(nil),
							equals...,
						),
					}
				}
				if response.JSONSchema != "" {
					schema, err := schemas.resolve(response.JSONSchema)
					if err != nil {
						return nil, err
					}
					resolvedResponse.JSONSchema = &schema
				}
				resolved.Response = resolvedResponse
			}
			if assertion.JSONFile != nil {
				schema, err := schemas.resolve(assertion.JSONFile.Schema)
				if err != nil {
					return nil, err
				}
				resolved.JSONFile = &domain.PlanJSONFileAssertion{
					Path:   assertion.JSONFile.Path,
					Schema: schema,
				}
			}
			result = append(result, resolved)
		}
		return result, nil
	}
	if len(exercise.Driver.Assertions) == 0 {
		return []domain.PlanAssertion{}, nil
	}
	result := make([]domain.PlanAssertion, 0, len(exercise.Driver.Assertions))
	for index, assertion := range exercise.Driver.Assertions {
		var exitCode *int
		if assertion.ExitCode != nil {
			value := *assertion.ExitCode
			exitCode = &value
		}
		id := assertion.ID
		if id == "" {
			id = fmt.Sprintf("assertion-%d", index+1)
		}
		var stdoutJSONSchema *domain.PlanJSONSchemaRef
		if assertion.StdoutJSONSchema != "" {
			schema, err := schemas.resolve(assertion.StdoutJSONSchema)
			if err != nil {
				return nil, err
			}
			stdoutJSONSchema = &schema
		}
		result = append(result, domain.PlanAssertion{
			ID:               id,
			ExitCode:         exitCode,
			StdoutContains:   stringValue(assertion.StdoutContains),
			StderrContains:   stringValue(assertion.StderrContains),
			StdoutRegex:      stringValue(assertion.StdoutRegex),
			StdoutJSONSchema: stdoutJSONSchema,
			FileExists:       assertion.FileExists,
		})
	}
	return result, nil
}

func resolvedHTTPJourney(
	scenario manifest.ScenarioSpec,
) (*domain.PlanHTTPJourney, error) {
	exercise := scenario.Phases.Exercise
	if exercise == nil || exercise.Driver.Type != "http" {
		return nil, nil
	}
	run := scenario.Phases.Run
	if run == nil || run.Service == nil {
		return nil, fmt.Errorf("HTTP journey has no resolved service")
	}
	journey := &domain.PlanHTTPJourney{
		ServiceID: run.Service.ID,
		Steps:     make([]domain.PlanHTTPDriverStep, 0, len(exercise.Driver.Steps)),
	}
	requestTimeoutFallback, err := time.ParseDuration(exercise.Timeout)
	if err != nil || requestTimeoutFallback <= 0 {
		requestTimeoutFallback = time.Minute
	}
	for _, step := range exercise.Driver.Steps {
		switch {
		case step.Request != nil:
			request := step.Request
			resolved := &domain.PlanHTTPRequest{
				ID:      request.ID,
				Method:  request.Method,
				URL:     request.URL,
				Headers: normalizedHTTPHeaders(request.Headers),
				Timeout: normalizedTimeout(
					request.Timeout,
					requestTimeoutFallback,
				),
			}
			if request.HasBody() {
				body := request.Body
				resolved.Body = &body
			}
			if request.HasJSON() {
				encoded, encodeErr := canonicaljson.Marshal(request.JSON)
				if encodeErr != nil {
					return nil, encodeErr
				}
				resolved.JSON = json.RawMessage(encoded)
			}
			journey.Steps = append(
				journey.Steps,
				domain.PlanHTTPDriverStep{Request: resolved},
			)
		case step.Assert != nil:
			journey.Steps = append(
				journey.Steps,
				domain.PlanHTTPDriverStep{AssertionID: step.Assert.ID},
			)
		default:
			return nil, fmt.Errorf("HTTP journey contains an empty driver step")
		}
	}
	return journey, nil
}

func normalizedHTTPHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(headers))
	for name, value := range headers {
		result[strings.ToLower(name)] = value
	}
	return result
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func normalizedTimeout(value string, fallback time.Duration) string {
	if value == "" {
		return fallback.String()
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback.String()
	}
	return duration.String()
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func mergeDetails(left, right map[string]any) map[string]any {
	result := make(map[string]any, len(left)+len(right))
	for key, value := range left {
		result[key] = value
	}
	for key, value := range right {
		result[key] = value
	}
	return result
}

func parseCPU(value any) int64 {
	var amount float64
	switch typed := value.(type) {
	case int:
		amount = float64(typed)
	case int64:
		amount = float64(typed)
	case uint64:
		amount = float64(typed)
	case float64:
		amount = typed
	case string:
		amount, _ = strconv.ParseFloat(typed, 64)
	}
	if amount <= 0 {
		return 1000
	}
	return int64(amount * 1000)
}

func parseSize(value string) int64 {
	units := map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}
	for suffix, multiplier := range units {
		if strings.HasSuffix(value, suffix) {
			number, err := strconv.ParseInt(strings.TrimSuffix(value, suffix), 10, 64)
			if err == nil && number > 0 {
				return number * multiplier
			}
		}
	}
	return 0
}
