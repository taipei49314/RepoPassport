package manifest

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

var (
	namePattern          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	identifierPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	exactVersion         = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
	pinnedImage          = regexp.MustCompile(`^(?:[a-z0-9.-]+(?::[0-9]+)?/)?(?:[a-z0-9._-]+/)*[a-z0-9._-]+(?::[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$`)
	supportedKinds       = stringSet("cli", "web-app", "api", "library", "notebook", "model", "dataset", "documentation", "desktop-app", "mobile-app", "unknown")
	supportedInputs      = stringSet("string", "integer", "boolean", "file", "directory", "json", "secret-reference", "choice")
	supportedAdapters    = stringSet("node", "python")
	supportedDrivers     = stringSet("cli", "http")
	supportedObservers   = stringSet("process-exec", "filesystem-write", "port-listen", "network-enforcement", "resource-usage")
	supportedHTTPMethods = stringSet(
		"get",
		"head",
		"post",
		"put",
		"patch",
		"delete",
		"options",
	)
	forbiddenHTTPRequestHeaders = stringSet(
		"authorization",
		"connection",
		"content-length",
		"cookie",
		"host",
		"proxy-authorization",
		"transfer-encoding",
		"x-api-key",
	)
	httpHeaderNamePattern = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)
)

const (
	maxHTTPRequestBodyBytes   = domain.AlphaHTTPMaxRequestBodyBytes
	maxHTTPRequestHeaders     = domain.AlphaHTTPMaxHeaders
	maxHTTPHeaderValueBytes   = domain.AlphaHTTPMaxHeaderValueBytes
	maxHTTPResponseMatchBytes = domain.AlphaHTTPMaxResponseMatchBytes
	maxHTTPServiceSignalGrace = domain.AlphaHTTPMaxSignalGrace
)

func Validate(doc *Document) []*domain.Error {
	if doc == nil || doc.Manifest == nil {
		return []*domain.Error{domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "Manifest is empty.")}
	}
	m := doc.Manifest
	var errs []*domain.Error
	add := func(code domain.ErrorCode, message, field, suggestion string) {
		e := domain.NewError(code, domain.SeverityHigh, message)
		if field != "" {
			e.Details = map[string]any{"field": field}
		}
		e.Suggestion = suggestion
		errs = append(errs, e)
	}

	if m.APIVersion != APIVersion {
		add(domain.CodeManifestInvalid, "Unsupported apiVersion.", "apiVersion", "Use "+APIVersion+".")
	}
	if m.Kind != Kind {
		add(domain.CodeManifestInvalid, "Unsupported kind.", "kind", "Use "+Kind+".")
	}
	if !namePattern.MatchString(m.Metadata.Name) {
		add(domain.CodeManifestInvalid, "metadata.name must be a lowercase DNS-style name.", "metadata.name", "")
	}
	if _, ok := supportedKinds[m.Spec.Project.Kind]; !ok {
		add(domain.CodeManifestInvalid, "Unsupported project kind.", "spec.project.kind", "")
	}
	if len(m.Spec.Environments) == 0 {
		add(domain.CodeManifestInvalid, "At least one environment is required.", "spec.environments", "")
	}
	if len(m.Spec.Scenarios) == 0 {
		add(domain.CodeManifestInvalid, "At least one scenario is required.", "spec.scenarios", "")
	}
	for index, entrypoint := range m.Spec.Project.Entrypoints {
		if _, ok := m.Spec.Scenarios[entrypoint]; !ok {
			add(
				domain.CodeManifestInvalid,
				"Project entrypoint references an unknown scenario.",
				fmt.Sprintf("spec.project.entrypoints[%d]", index),
				"Declare the scenario or remove the dangling entrypoint.",
			)
		}
	}

	for name, env := range m.Spec.Environments {
		prefix := "spec.environments." + name
		if env.Platform.OS != "linux" {
			add(domain.CodeManifestInvalid, "v0.1 recognizes only Linux workload environments.", prefix+".platform.os", "")
		}
		if env.Platform.Architecture != "amd64" && env.Platform.Architecture != "arm64" {
			add(domain.CodeManifestInvalid, "Architecture must be amd64 or arm64.", prefix+".platform.architecture", "")
		}
		if _, ok := supportedAdapters[env.Runtime.Adapter]; !ok {
			add(domain.CodeManifestInvalid, "Runtime adapter is recognized but unsupported by this release.", prefix+".runtime.adapter", "Use node or python.")
		}
		if strings.TrimSpace(env.Runtime.Version) == "" {
			add(domain.CodeManifestInvalid, "Runtime version is required.", prefix+".runtime.version", "")
		}
		if strings.TrimSpace(env.BaseImage.Reference) == "" {
			add(domain.CodeManifestInvalid, "Base image reference is required.", prefix+".baseImage.reference", "")
		}
		if strings.Contains(strings.ToLower(env.BaseImage.Reference), ":latest") {
			add(domain.CodeMutableBaseImage, "The latest image tag is forbidden.", prefix+".baseImage.reference", "Pin the image by sha256 digest.")
		}
		if env.Resources.PIDs <= 0 || env.Resources.PIDs > 4096 {
			add(domain.CodeManifestInvalid, "resources.pids must be between 1 and 4096.", prefix+".resources.pids", "")
		}
		if !validCPU(env.Resources.CPU) {
			add(domain.CodeManifestInvalid, "resources.cpu must be between 0.001 and 64 cores.", prefix+".resources.cpu", "")
		}
		if !validSize(env.Resources.Memory) || !validSize(env.Resources.Disk) {
			add(domain.CodeManifestInvalid, "Memory and disk must use a positive KiB/MiB/GiB size.", prefix+".resources", "")
		}
	}

	for name, scenario := range m.Spec.Scenarios {
		prefix := "spec.scenarios." + name
		if _, ok := m.Spec.Environments[scenario.Environment]; !ok {
			add(domain.CodeManifestInvalid, "Scenario references an unknown environment.", prefix+".environment", "")
		}
		for inputName, input := range scenario.Inputs {
			inputPath := prefix + ".inputs." + inputName
			if !identifierPattern.MatchString(inputName) {
				add(domain.CodeManifestInvalid, "Input name must be a lowercase identifier.", inputPath, "")
			}
			if _, ok := supportedInputs[input.Type]; !ok {
				add(domain.CodeManifestInvalid, "Unsupported input type.", inputPath+".type", "")
			}
			if (input.Type == "file" || input.Type == "directory") && !input.Mount.ReadOnly {
				add(domain.CodeManifestInvalid, "Verification file and directory inputs must be read-only.", inputPath+".mount.readOnly", "")
			}
			if input.Type == "file" || input.Type == "directory" {
				cleanFixture := path.Clean(input.Fixture)
				if input.Fixture == "" || strings.Contains(input.Fixture, "\\") ||
					cleanFixture != input.Fixture || strings.HasPrefix(cleanFixture, "../") ||
					strings.HasPrefix(cleanFixture, "/") || cleanFixture == "." {
					add(domain.CodeSourcePathTraversal, "Fixture must be a normalized source-relative POSIX path that cannot escape the repository.", inputPath+".fixture", "")
				}
			}
			if input.Mount.Path != "" &&
				(!validSandboxPath(input.Mount.Path) || !strings.HasPrefix(input.Mount.Path, "/inputs/")) {
				add(domain.CodeSourcePathTraversal, "Input mount path must be a normalized path below /inputs.", inputPath+".mount.path", "")
			}
		}
		for secretName, secret := range scenario.Secrets {
			secretPath := prefix + ".secrets." + secretName
			if secret.Source != "synthetic" {
				add(domain.CodeManifestLiteralSecret, "v0.1 accepts only synthetic secret references.", secretPath+".source", "Use source: synthetic.")
			}
			if strings.TrimSpace(secret.ExposeAs.Env) == "" {
				add(domain.CodeManifestInvalid, "Synthetic secret must declare exposeAs.env.", secretPath+".exposeAs.env", "")
			}
			if len(secret.Scope.Phases) == 0 {
				add(domain.CodeManifestInvalid, "Synthetic secret must be scoped to at least one phase.", secretPath+".scope.phases", "")
			}
		}

		seenStepIDs := make(map[string]string)
		serviceID := ""
		validateCommandPhase := func(phase domain.Phase, p *CommandPhase) {
			if p == nil {
				return
			}
			validateTimeout(add, prefix+".phases."+string(phase)+".timeout", p.Timeout)
			validateSteps(add, prefix+".phases."+string(phase)+".steps", p.Steps, seenStepIDs)
		}
		validateCommandPhase(domain.PhasePrepare, scenario.Phases.Prepare)
		validateCommandPhase(domain.PhaseSetup, scenario.Phases.Setup)
		validateCommandPhase(domain.PhaseBuild, scenario.Phases.Build)

		if scenario.Phases.Run != nil {
			p := scenario.Phases.Run
			validateTimeout(add, prefix+".phases.run.timeout", p.Timeout)
			validateSteps(add, prefix+".phases.run.steps", p.Steps, seenStepIDs)
			if p.Service != nil {
				serviceID = p.Service.ID
				if p.Service.Shell != nil {
					add(
						domain.CodeManifestUnsafeShell,
						"Shell execution is not approved by the v0.1 safety policy.",
						prefix+".phases.run.service.shell",
						"Use an argument-array command.",
					)
				}
				if !identifierPattern.MatchString(p.Service.ID) {
					add(domain.CodeManifestInvalid, "Service id must be a lowercase identifier.", prefix+".phases.run.service.id", "")
				} else if _, exists := seenStepIDs[p.Service.ID]; exists {
					add(
						domain.CodeManifestInvalid,
						"Service id must be unique among scenario command ids.",
						prefix+".phases.run.service.id",
						"Use an id that differs from every phase step id.",
					)
				} else {
					seenStepIDs[p.Service.ID] = prefix + ".phases.run.service.id"
				}
				if (len(p.Service.Command) == 0) == (p.Service.Shell == nil) {
					add(domain.CodeManifestInvalid, "Service must define exactly one command or shell action.", prefix+".phases.run.service", "")
				} else if len(p.Service.Command) > 0 {
					validateArgv(add, prefix+".phases.run.service.command", p.Service.Command, false)
				}
				if p.Service.Readiness.HTTP == nil {
					add(
						domain.CodeManifestInvalid,
						"The supported service profile requires HTTP readiness.",
						prefix+".phases.run.service.readiness",
						"Declare readiness.http with url, status, and timeout.",
					)
				} else {
					validateHTTPURL(add, prefix+".phases.run.service.readiness.http.url", p.Service.Readiness.HTTP.URL)
					if p.Service.Readiness.HTTP.Status < domain.AlphaHTTPMinimumStatus ||
						p.Service.Readiness.HTTP.Status > domain.AlphaHTTPMaximumStatus {
						add(
							domain.CodeManifestInvalid,
							"HTTP readiness status must be between 200 and 599.",
							prefix+".phases.run.service.readiness.http.status",
							"",
						)
					}
					if p.Service.Readiness.HTTP.Timeout == "" {
						add(
							domain.CodeManifestInvalid,
							"HTTP readiness timeout is required.",
							prefix+".phases.run.service.readiness.http.timeout",
							"",
						)
					}
					validateHTTPDuration(
						add,
						prefix+".phases.run.service.readiness.http.timeout",
						p.Service.Readiness.HTTP.Timeout,
						domain.AlphaHTTPMaxReadinessTime,
					)
				}
			}
		}
		validateCommandPhase(domain.PhaseCleanup, scenario.Phases.Cleanup)
		validateSignalTargets(add, prefix, scenario, serviceID)
		if scenario.Phases.Exercise == nil {
			add(domain.CodeManifestInvalid, "Scenario must define an exercise phase.", prefix+".phases.exercise", "")
		} else {
			exercise := scenario.Phases.Exercise
			validateTimeout(add, prefix+".phases.exercise.timeout", exercise.Timeout)
			if _, ok := supportedDrivers[exercise.Driver.Type]; !ok {
				add(domain.CodeManifestInvalid, "Exercise driver must be cli or http.", prefix+".phases.exercise.driver.type", "")
			}
			if exercise.Driver.Type == "cli" {
				validateArgv(add, prefix+".phases.exercise.driver.command", exercise.Driver.Command, false)
				if len(exercise.Driver.Assertions) == 0 {
					add(domain.CodeManifestInvalid, "CLI driver requires at least one external assertion.", prefix+".phases.exercise.driver.assertions", "")
				}
				if len(exercise.Driver.Steps) > 0 {
					add(domain.CodeManifestInvalid, "CLI driver must not contain HTTP steps.", prefix+".phases.exercise.driver.steps", "")
				}
			}
			if exercise.Driver.Type == "http" {
				if len(exercise.Driver.Command) > 0 || len(exercise.Driver.Assertions) > 0 {
					add(domain.CodeManifestInvalid, "HTTP driver uses ordered steps, not command or top-level assertions.", prefix+".phases.exercise.driver", "")
				}
				validateHTTPProfile(add, prefix, scenario)
			} else if serviceID != "" {
				add(
					domain.CodeManifestInvalid,
					"The supported single-service profile requires an HTTP exercise driver.",
					prefix+".phases.exercise.driver.type",
					"Use type: http or remove the background service.",
				)
			}
			seenAssertionIDs := make(map[string]string)
			for i, assertion := range exercise.Driver.Assertions {
				assertionPath := fmt.Sprintf("%s.phases.exercise.driver.assertions[%d]", prefix, i)
				if identifierPattern.MatchString(assertion.ID) {
					if _, exists := seenAssertionIDs[assertion.ID]; exists {
						add(
							domain.CodeManifestInvalid,
							"CLI assertion ids must be unique within a scenario.",
							assertionPath+".id",
							"Use a unique assertion id.",
						)
					} else {
						seenAssertionIDs[assertion.ID] = assertionPath + ".id"
					}
				}
				validateAssertion(add, assertionPath, assertion)
			}
		}

		for phase, capability := range scenario.Capabilities {
			capPath := prefix + ".capabilities." + string(phase)
			if phase == domain.PhaseRun || phase == domain.PhaseExercise {
				if !capability.Network.Deny || len(capability.Network.Allow) > 0 {
					add(domain.CodeManifestInvalid, "Runtime and exercise network must be deny-all in v0.1.", capPath+".network", "")
				}
			}
			if capability.Network.Deny && len(capability.Network.Allow) > 0 {
				add(domain.CodeManifestInvalid, "network.deny and network.allow are mutually exclusive.", capPath+".network", "")
			}
			for i, destination := range capability.Network.Allow {
				if !validHostname(destination.Host) || destination.Port < 1 || destination.Port > 65535 {
					add(domain.CodeManifestInvalid, "Network allow entry has an invalid host or port.", fmt.Sprintf("%s.network.allow[%d]", capPath, i), "")
				}
			}
			for _, sandboxPath := range append(append([]string{}, capability.Filesystem.Read...), capability.Filesystem.Write...) {
				if !validSandboxGlob(sandboxPath) {
					add(domain.CodeSourcePathTraversal, "Capability path must be an absolute normalized sandbox path or glob.", capPath+".filesystem", "")
				}
			}
		}
		if scenario.Verification.Repeats <= 0 {
			add(domain.CodeManifestInvalid, "verification.repeats must be positive.", prefix+".verification.repeats", "")
		}
		if scenario.Verification.SuccessThreshold <= 0 || scenario.Verification.SuccessThreshold > scenario.Verification.Repeats {
			add(domain.CodeManifestInvalid, "successThreshold must be between 1 and repeats.", prefix+".verification.successThreshold", "")
		}
		for _, observer := range scenario.Verification.RequiredObservers {
			if _, ok := supportedObservers[observer]; !ok {
				add(domain.CodeManifestInvalid, "Unknown required observer.", prefix+".verification.requiredObservers", "")
			}
		}
		for _, residue := range scenario.Verification.Cleanup.AllowedResidue {
			if !validSandboxGlob(residue) {
				add(domain.CodeSourcePathTraversal, "Allowed residue must be an absolute normalized sandbox path or glob.", prefix+".verification.cleanup.allowedResidue", "")
			}
		}
	}

	if m.Spec.Policies.Profile == "" {
		add(domain.CodeManifestInvalid, "A policy profile is required.", "spec.policies.profile", "Use baseline-v1.")
	}
	return errs
}

func IsPinnedImage(reference string) bool {
	return pinnedImage.MatchString(reference)
}

func IsExactRuntimeVersion(version string) bool {
	return exactVersion.MatchString(version)
}

func validateArgv(add func(domain.ErrorCode, string, string, string), field string, argv []string, optional bool) {
	if len(argv) == 0 {
		if !optional {
			add(domain.CodeManifestInvalid, "Command argv must not be empty.", field, "")
		}
		return
	}
	for _, arg := range argv {
		if arg == "" || strings.ContainsRune(arg, 0) {
			add(domain.CodeManifestInvalid, "Command arguments must be non-empty and contain no NUL bytes.", field, "")
			return
		}
	}
}

func validateSteps(
	add func(domain.ErrorCode, string, string, string),
	field string,
	steps []PhaseStep,
	seenIDs map[string]string,
) {
	for i, step := range steps {
		stepPath := field + "[" + strconv.Itoa(i) + "]"
		if step.Run != nil && step.Run.Shell != nil {
			add(
				domain.CodeManifestUnsafeShell,
				"Shell execution is not approved by the v0.1 safety policy.",
				stepPath+".run.shell",
				"Use an argument-array command.",
			)
		}
		if !identifierPattern.MatchString(step.ID) {
			add(domain.CodeManifestInvalid, "Every phase step requires a lowercase identifier.", stepPath+".id", "")
		} else if _, exists := seenIDs[step.ID]; exists {
			add(
				domain.CodeManifestInvalid,
				"Phase step ids must be unique within a scenario.",
				stepPath+".id",
				"Use a unique step id.",
			)
		} else {
			seenIDs[step.ID] = stepPath + ".id"
		}
		if (step.Run == nil) == (step.Signal == nil) {
			add(domain.CodeManifestInvalid, "Phase step must contain exactly one run or signal action.", stepPath, "")
		}
		if step.Run != nil {
			if (len(step.Run.Command) == 0) == (step.Run.Shell == nil) {
				add(domain.CodeManifestInvalid, "Run action must define exactly one command or shell action.", stepPath+".run", "")
			} else if len(step.Run.Command) > 0 {
				validateArgv(add, stepPath+".run.command", step.Run.Command, false)
			}
		}
		if step.Signal != nil {
			if !identifierPattern.MatchString(step.Signal.Target) {
				add(domain.CodeManifestInvalid, "Signal target must be a lowercase service identifier.", stepPath+".signal.target", "")
			}
			if step.Signal.Type != "term" && step.Signal.Type != "kill" &&
				step.Signal.Type != "int" && step.Signal.Type != "hup" {
				add(domain.CodeManifestInvalid, "Signal type must be term, kill, int, or hup.", stepPath+".signal.type", "")
			}
			validateTimeout(add, stepPath+".signal.gracePeriod", step.Signal.GracePeriod)
		}
	}
}

func validateSignalTargets(
	add func(domain.ErrorCode, string, string, string),
	prefix string,
	scenario ScenarioSpec,
	serviceID string,
) {
	validate := func(phase domain.Phase, steps []PhaseStep) {
		for index, step := range steps {
			if step.Signal == nil {
				continue
			}
			field := fmt.Sprintf(
				"%s.phases.%s.steps[%d].signal.target",
				prefix,
				phase,
				index,
			)
			if serviceID == "" {
				add(
					domain.CodeManifestInvalid,
					"Signal target references a service that is not declared.",
					field,
					"Declare the service or remove the signal step.",
				)
				continue
			}
			if step.Signal.Target == serviceID && phase == domain.PhaseCleanup {
				continue
			}
			message := "Signal target must reference the scenario's declared service."
			suggestion := "Use target: " + serviceID + "."
			if step.Signal.Target == serviceID {
				message = "The single-service profile permits service signals only during cleanup."
				suggestion = "Move the signal step to phases.cleanup."
			}
			add(
				domain.CodeManifestInvalid,
				message,
				field,
				suggestion,
			)
		}
	}
	if phase := scenario.Phases.Prepare; phase != nil {
		validate(domain.PhasePrepare, phase.Steps)
	}
	if phase := scenario.Phases.Setup; phase != nil {
		validate(domain.PhaseSetup, phase.Steps)
	}
	if phase := scenario.Phases.Build; phase != nil {
		validate(domain.PhaseBuild, phase.Steps)
	}
	if phase := scenario.Phases.Run; phase != nil {
		validate(domain.PhaseRun, phase.Steps)
	}
	if phase := scenario.Phases.Cleanup; phase != nil {
		validate(domain.PhaseCleanup, phase.Steps)
	}
}

func validateHTTPProfile(
	add func(domain.ErrorCode, string, string, string),
	prefix string,
	scenario ScenarioSpec,
) {
	exercise := scenario.Phases.Exercise
	if exercise == nil || exercise.Driver.Type != "http" {
		return
	}

	serviceID := ""
	if scenario.Phases.Run == nil || scenario.Phases.Run.Service == nil {
		add(
			domain.CodeManifestInvalid,
			"The HTTP exercise driver requires exactly one declared run service.",
			prefix+".phases.run.service",
			"Declare phases.run.service with HTTP readiness.",
		)
	} else {
		serviceID = scenario.Phases.Run.Service.ID
	}

	declaredPort := 0
	listeners := scenario.Capabilities[domain.PhaseRun].Ports.Listen
	if len(listeners) != 1 {
		add(
			domain.CodeManifestInvalid,
			"The supported HTTP service profile requires exactly one declared listen port.",
			prefix+".capabilities.run.ports.listen",
			"Declare one loopback TCP listen endpoint.",
		)
	} else {
		declaredPort = listeners[0].Port
		if listeners[0].Host != "127.0.0.1" {
			add(
				domain.CodeManifestInvalid,
				"The executable HTTP profile requires a literal 127.0.0.1 listener.",
				prefix+".capabilities.run.ports.listen[0].host",
				"Use host: 127.0.0.1.",
			)
		}
		if listeners[0].Protocol != "" && listeners[0].Protocol != "tcp" {
			add(
				domain.CodeManifestInvalid,
				"HTTP services require a TCP listen declaration.",
				prefix+".capabilities.run.ports.listen[0].protocol",
				"Use protocol: tcp or omit it to select the TCP default.",
			)
		}
	}

	if serviceID != "" &&
		scenario.Phases.Run.Service.Readiness.HTTP != nil {
		validateHTTPURLPort(
			add,
			prefix+".phases.run.service.readiness.http.url",
			scenario.Phases.Run.Service.Readiness.HTTP.URL,
			declaredPort,
		)
	}

	driver := exercise.Driver
	if exercise.Timeout != "" {
		validateHTTPDuration(
			add,
			prefix+".phases.exercise.timeout",
			exercise.Timeout,
			domain.AlphaHTTPMaxRequestTime,
		)
	}
	cleanupSignalCount := 0
	if cleanup := scenario.Phases.Cleanup; cleanup != nil {
		for index, step := range cleanup.Steps {
			if step.Signal != nil && step.Signal.Target == serviceID {
				cleanupSignalCount++
				signalField := fmt.Sprintf(
					"%s.phases.cleanup.steps[%d].signal",
					prefix,
					index,
				)
				if index != len(cleanup.Steps)-1 {
					add(
						domain.CodeManifestInvalid,
						"The HTTP service signal must be the final cleanup step.",
						signalField,
						"Move the service signal to the end of cleanup.",
					)
				}
				if step.Signal.GracePeriod == "" {
					add(
						domain.CodeManifestInvalid,
						"Every HTTP service signal requires gracePeriod.",
						signalField+".gracePeriod",
						"Declare a duration between 1ms and 10s.",
					)
				}
				if step.Signal.GracePeriod != "" {
					validateHTTPDuration(
						add,
						signalField+".gracePeriod",
						step.Signal.GracePeriod,
						maxHTTPServiceSignalGrace,
					)
				}
			}
		}
	}
	if cleanupSignalCount != 1 {
		add(
			domain.CodeManifestInvalid,
			"The HTTP service profile requires exactly one cleanup signal for the declared service.",
			prefix+".phases.cleanup.steps",
			"Declare one signal step targeting "+serviceID+".",
		)
	}
	if len(driver.Steps) == 0 {
		add(
			domain.CodeManifestInvalid,
			"HTTP driver requires ordered request and assertion steps.",
			prefix+".phases.exercise.driver.steps",
			"",
		)
		return
	}
	if len(driver.Steps) > domain.AlphaHTTPMaxJourneySteps {
		add(
			domain.CodeManifestInvalid,
			"HTTP driver declares more than 128 ordered steps.",
			prefix+".phases.exercise.driver.steps",
			"Reduce the journey to at most 128 steps.",
		)
	}

	seenIDs := make(map[string]string)
	seenRequests := make(map[string]int)
	requestCount := 0
	assertionCount := 0
	for index, step := range driver.Steps {
		stepPath := fmt.Sprintf(
			"%s.phases.exercise.driver.steps[%d]",
			prefix,
			index,
		)
		if (step.Request == nil) == (step.Assert == nil) {
			add(
				domain.CodeManifestInvalid,
				"HTTP driver step must contain exactly one request or assert action.",
				stepPath,
				"",
			)
			continue
		}
		if step.Request != nil {
			requestCount++
			validateHTTPRequest(
				add,
				stepPath+".request",
				*step.Request,
				declaredPort,
				index,
				seenIDs,
				seenRequests,
			)
			continue
		}

		assertionCount++
		assertion := *step.Assert
		assertionPath := stepPath + ".assert"
		validateHTTPAssertionID(add, assertionPath, assertion.ID, seenIDs)
		validateAssertion(add, assertionPath, assertion)
		if assertion.FileExists != "" &&
			!validHTTPOutputPath(assertion.FileExists) {
			add(
				domain.CodeSourcePathTraversal,
				"HTTP fileExists must be a normalized path within /outputs.",
				assertionPath+".fileExists",
				"Write and assert only runner-owned output files.",
			)
		}
		if assertion.JSONFile != nil &&
			!validHTTPOutputPath(assertion.JSONFile.Path) {
			add(
				domain.CodeSourcePathTraversal,
				"HTTP jsonFile.path must be a normalized regular-file path within /outputs.",
				assertionPath+".jsonFile.path",
				"Write and validate only runner-owned output files.",
			)
		}
		if assertion.ExitCode != nil ||
			assertion.StdoutContains != nil ||
			assertion.StderrContains != nil ||
			assertion.StdoutRegex != nil ||
			assertion.StdoutJSONSchema != "" ||
			assertion.StderrRegex != nil {
			add(
				domain.CodeManifestInvalid,
				"HTTP assertion steps accept only response, fileExists, or jsonFile operations.",
				assertionPath,
				"",
			)
		}
		if assertion.Response != nil {
			validateHTTPResponseAssertion(
				add,
				assertionPath+".response",
				*assertion.Response,
				index,
				seenRequests,
			)
		}
	}
	if requestCount == 0 {
		add(
			domain.CodeManifestInvalid,
			"HTTP driver requires at least one request step.",
			prefix+".phases.exercise.driver.steps",
			"",
		)
	}
	if requestCount > domain.AlphaHTTPMaxRequestSteps {
		add(
			domain.CodeManifestInvalid,
			"HTTP driver declares more than 32 request steps.",
			prefix+".phases.exercise.driver.steps",
			"Reduce the journey to at most 32 requests.",
		)
	}
	if assertionCount == 0 {
		add(
			domain.CodeManifestInvalid,
			"HTTP driver requires at least one assertion step.",
			prefix+".phases.exercise.driver.steps",
			"",
		)
	}
}

func validateHTTPRequest(
	add func(domain.ErrorCode, string, string, string),
	field string,
	request HTTPRequest,
	declaredPort int,
	stepIndex int,
	seenIDs map[string]string,
	seenRequests map[string]int,
) {
	idValid := identifierPattern.MatchString(request.ID)
	if !idValid {
		add(
			domain.CodeManifestInvalid,
			"HTTP request id must be a lowercase identifier.",
			field+".id",
			"",
		)
	} else if previous, exists := seenIDs[request.ID]; exists {
		add(
			domain.CodeManifestInvalid,
			"HTTP request and assertion ids must be unique within a scenario.",
			field+".id",
			"Choose an id different from "+previous+".",
		)
	} else {
		seenIDs[request.ID] = field + ".id"
		seenRequests[request.ID] = stepIndex
	}

	if _, ok := supportedHTTPMethods[request.Method]; !ok {
		add(
			domain.CodeManifestInvalid,
			"HTTP request method is not supported by the alpha profile.",
			field+".method",
			"Use get, head, post, put, patch, delete, or options.",
		)
	}
	validateHTTPURL(add, field+".url", request.URL)
	validateHTTPURLPort(add, field+".url", request.URL, declaredPort)
	hasBody := request.HasBody()
	hasJSON := request.HasJSON()
	if request.Timeout != "" {
		validateHTTPDuration(
			add,
			field+".timeout",
			request.Timeout,
			domain.AlphaHTTPMaxRequestTime,
		)
	}
	validateHTTPRequestHeaders(
		add,
		field+".headers",
		request.Headers,
		hasJSON,
	)

	if hasBody && hasJSON {
		add(
			domain.CodeManifestInvalid,
			"HTTP request body and json are mutually exclusive.",
			field,
			"Declare only body or json.",
		)
	}
	if len([]byte(request.Body)) > maxHTTPRequestBodyBytes {
		add(
			domain.CodeManifestInvalid,
			"HTTP request body exceeds the 1 MiB profile limit.",
			field+".body",
			"",
		)
	}
	if hasJSON {
		encoded, err := canonicaljson.Marshal(request.JSON)
		if err != nil {
			add(
				domain.CodeManifestInvalid,
				"HTTP request json could not be encoded.",
				field+".json",
				"",
			)
		} else if len(encoded) > maxHTTPRequestBodyBytes {
			add(
				domain.CodeManifestInvalid,
				"HTTP request json exceeds the 1 MiB profile limit.",
				field+".json",
				"",
			)
		}
	}
}

func validateHTTPAssertionID(
	add func(domain.ErrorCode, string, string, string),
	field string,
	id string,
	seenIDs map[string]string,
) {
	if !identifierPattern.MatchString(id) {
		add(
			domain.CodeManifestInvalid,
			"HTTP assertion id must be a lowercase identifier.",
			field+".id",
			"",
		)
		return
	}
	if previous, exists := seenIDs[id]; exists {
		add(
			domain.CodeManifestInvalid,
			"HTTP request and assertion ids must be unique within a scenario.",
			field+".id",
			"Choose an id different from "+previous+".",
		)
		return
	}
	seenIDs[id] = field + ".id"
}

func validateHTTPResponseAssertion(
	add func(domain.ErrorCode, string, string, string),
	field string,
	assertion ResponseAssertion,
	stepIndex int,
	seenRequests map[string]int,
) {
	requestIndex, exists := seenRequests[assertion.RequestID]
	if !exists || requestIndex >= stepIndex {
		add(
			domain.CodeManifestInvalid,
			"HTTP response assertion must reference an earlier unique request.",
			field+".requestId",
			"Move the request before this assertion and reference its id.",
		)
	}

	operationCount := 0
	if assertion.Status != 0 {
		operationCount++
		if assertion.Status < domain.AlphaHTTPMinimumStatus ||
			assertion.Status > domain.AlphaHTTPMaximumStatus {
			add(
				domain.CodeManifestInvalid,
				"HTTP response status assertion must be between 200 and 599.",
				field+".status",
				"",
			)
		}
	}
	if assertion.Header != nil {
		operationCount++
		if !httpHeaderNamePattern.MatchString(assertion.Header.Name) {
			add(
				domain.CodeManifestInvalid,
				"HTTP response header assertion name is invalid.",
				field+".header.name",
				"",
			)
		}
		if strings.ContainsAny(assertion.Header.Contains, "\r\n\x00") ||
			len([]byte(assertion.Header.Contains)) > maxHTTPHeaderValueBytes {
			add(
				domain.CodeManifestInvalid,
				"HTTP response header assertion contains unsafe or oversized data.",
				field+".header.contains",
				"",
			)
		}
	}
	if assertion.BodyContains != nil {
		operationCount++
		if *assertion.BodyContains == "" {
			add(
				domain.CodeManifestInvalid,
				"HTTP response bodyContains must not be empty.",
				field+".bodyContains",
				"Declare a non-empty response substring.",
			)
		} else if len([]byte(*assertion.BodyContains)) > maxHTTPResponseMatchBytes {
			add(
				domain.CodeManifestInvalid,
				"HTTP response body assertion exceeds the 1 MiB profile limit.",
				field+".bodyContains",
				"",
			)
		}
	}
	if assertion.JSONPath != nil {
		operationCount++
		if _, err := structuredjson.CompilePath(assertion.JSONPath.Path); err != nil {
			add(
				domain.CodeManifestInvalid,
				"HTTP response jsonPath uses unsupported alpha grammar.",
				field+".jsonPath.path",
				"Use $, .ASCII_identifier, [index], or a quoted bracket member.",
			)
		}
	}
	if assertion.JSONSchema != "" {
		operationCount++
		if !validPortableRepositoryPath(assertion.JSONSchema) {
			add(
				domain.CodeSourcePathTraversal,
				"HTTP response jsonSchema must use a portable normalized repository path.",
				field+".jsonSchema",
				"",
			)
		}
	}
	if operationCount == 0 {
		add(
			domain.CodeManifestInvalid,
			"HTTP response assertion requires at least one response check.",
			field,
			"Declare status, header, bodyContains, jsonPath, or jsonSchema.",
		)
	}
}

func validateHTTPRequestHeaders(
	add func(domain.ErrorCode, string, string, string),
	field string,
	headers map[string]string,
	hasJSON bool,
) {
	if err := domain.ValidateAlphaHTTPHeaders(headers, hasJSON); err != nil {
		add(
			domain.CodeManifestInvalid,
			"HTTP request effective headers exceed the alpha safety limits.",
			field,
			"",
		)
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]string, len(names))
	for _, name := range names {
		value := headers[name]
		lowerName := strings.ToLower(name)
		switch {
		case !httpHeaderNamePattern.MatchString(name):
			add(
				domain.CodeManifestInvalid,
				"HTTP request header name is invalid.",
				field+"."+name,
				"",
			)
		case strings.ContainsAny(name, "\r\n\x00"):
			add(
				domain.CodeManifestInvalid,
				"HTTP request header name contains unsafe control data.",
				field+"."+name,
				"",
			)
		case func() bool {
			_, forbidden := forbiddenHTTPRequestHeaders[lowerName]
			return forbidden
		}():
			add(
				domain.CodeManifestInvalid,
				"HTTP request header is controlled by the trusted driver and cannot be overridden.",
				field+"."+name,
				"",
			)
		case seen[lowerName] != "":
			add(
				domain.CodeManifestInvalid,
				"HTTP request header names must be unique case-insensitively.",
				field+"."+name,
				"",
			)
		default:
			seen[lowerName] = name
		}
		if strings.ContainsAny(value, "\r\n\x00") ||
			len([]byte(value)) > maxHTTPHeaderValueBytes ||
			!printableASCII(value) {
			add(
				domain.CodeManifestInvalid,
				"HTTP request header value must be printable ASCII within the 8192-byte limit.",
				field+"."+name,
				"",
			)
		}
	}
}

func validateAssertion(add func(domain.ErrorCode, string, string, string), field string, assertion DriverAssertion) {
	if assertion.ID != "" && !identifierPattern.MatchString(assertion.ID) {
		add(domain.CodeManifestInvalid, "Assertion id must be a lowercase identifier.", field+".id", "")
	}
	count := 0
	if assertion.ExitCode != nil {
		count++
	}
	if assertion.StdoutContains != nil {
		count++
	}
	if assertion.StderrContains != nil {
		count++
	}
	if assertion.StdoutRegex != nil {
		count++
		if _, err := regexp.Compile(*assertion.StdoutRegex); err != nil {
			add(domain.CodeManifestInvalid, "stdoutRegex is invalid.", field+".stdoutRegex", "")
		}
	}
	if assertion.StdoutJSONSchema != "" {
		count++
		if !validPortableRepositoryPath(assertion.StdoutJSONSchema) {
			add(
				domain.CodeSourcePathTraversal,
				"stdoutJsonSchema must use a portable normalized repository path.",
				field+".stdoutJsonSchema",
				"",
			)
		}
	}
	if assertion.StderrRegex != nil {
		count++
		if _, err := regexp.Compile(*assertion.StderrRegex); err != nil {
			add(domain.CodeManifestInvalid, "stderrRegex is invalid.", field+".stderrRegex", "")
		}
	}
	if assertion.FileExists != "" {
		count++
		if !validSandboxPath(assertion.FileExists) {
			add(domain.CodeSourcePathTraversal, "fileExists must use an absolute normalized sandbox path.", field+".fileExists", "")
		}
	}
	if assertion.Response != nil {
		count++
	}
	if assertion.JSONFile != nil {
		count++
		if !validSandboxPath(assertion.JSONFile.Path) {
			add(domain.CodeSourcePathTraversal, "jsonFile.path must use an absolute normalized sandbox path.", field+".jsonFile.path", "")
		}
		if !validPortableRepositoryPath(assertion.JSONFile.Schema) {
			add(
				domain.CodeSourcePathTraversal,
				"jsonFile.schema must use a portable normalized repository path.",
				field+".jsonFile.schema",
				"",
			)
		}
	}
	if count != 1 {
		add(domain.CodeManifestInvalid, "Each assertion must define exactly one assertion operation.", field, "")
	}
}

func validateTimeout(add func(domain.ErrorCode, string, string, string), field, value string) {
	if value == "" {
		return
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 30*time.Minute {
		add(domain.CodeManifestInvalid, "Timeout must be a positive Go-style duration no greater than 30m.", field, "")
	}
}

func validateHTTPDuration(
	add func(domain.ErrorCode, string, string, string),
	field string,
	value string,
	maximum time.Duration,
) {
	if value == "" {
		return
	}
	if _, err := domain.ParseAlphaHTTPDuration(value, maximum); err != nil {
		message := "HTTP duration must be at least 1ms and use whole milliseconds."
		if maximum > 0 {
			message = fmt.Sprintf(
				"HTTP duration must be a whole-millisecond value between 1ms and %s.",
				maximum,
			)
		}
		add(domain.CodeManifestInvalid, message, field, "")
	}
}

func validateHTTPURL(add func(domain.ErrorCode, string, string, string), field, value string) {
	if _, _, err := domain.ParseAlphaHTTPURL(value); err != nil {
		add(
			domain.CodeManifestInvalid,
			"HTTP journey URL must be a canonical visible-ASCII loopback URL no longer than 2048 bytes.",
			field,
			"",
		)
	}
}

func validateHTTPURLPort(
	add func(domain.ErrorCode, string, string, string),
	field string,
	value string,
	declaredPort int,
) {
	if declaredPort == 0 {
		return
	}
	_, port, err := domain.ParseAlphaHTTPURL(value)
	if err != nil {
		return
	}
	if port != declaredPort {
		add(
			domain.CodeManifestInvalid,
			"HTTP URL port must match the scenario's unique declared listen port.",
			field,
			fmt.Sprintf("Use port %d.", declaredPort),
		)
	}
}

func validSandboxPath(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsRune(value, 0) {
		return false
	}
	clean := path.Clean(value)
	return clean == value && !strings.HasPrefix(clean, "/../")
}

func validHTTPOutputPath(value string) bool {
	return domain.ValidateAlphaHTTPOutputPath(value) == nil
}

func validPortableRepositoryPath(value string) bool {
	if value == "" || len([]byte(value)) > 4096 ||
		strings.Contains(value, "\\") ||
		path.IsAbs(value) ||
		path.Clean(value) != value ||
		value == "." {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || len([]byte(segment)) > 255 ||
			segment == "." || segment == ".." ||
			strings.HasSuffix(segment, ".") ||
			strings.HasSuffix(segment, " ") ||
			portableWindowsDeviceName(segment) {
			return false
		}
		for _, character := range segment {
			if character < 0x20 || character > 0x7e ||
				strings.ContainsRune(`\:*?"<>|`, character) {
				return false
			}
		}
	}
	return true
}

func portableWindowsDeviceName(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return true
	}
	if len(base) != 4 {
		return false
	}
	prefix := base[:3]
	return (prefix == "COM" || prefix == "LPT") &&
		base[3] >= '1' && base[3] <= '9'
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validSandboxGlob(value string) bool {
	base := strings.TrimSuffix(strings.TrimSuffix(value, "/**"), "/*")
	return validSandboxPath(base)
}

func validHostname(host string) bool {
	if host == "" || strings.ContainsAny(host, "/\\:@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`).MatchString(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validSize(value string) bool {
	match := regexp.MustCompile(`^([1-9][0-9]*)(KiB|MiB|GiB)$`).FindStringSubmatch(value)
	if len(match) != 3 {
		return false
	}
	amount, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return false
	}
	multiplier := int64(1 << 10)
	switch match[2] {
	case "MiB":
		multiplier = 1 << 20
	case "GiB":
		multiplier = 1 << 30
	}
	return amount <= (1<<50)/multiplier
}

func validCPU(value any) bool {
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
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return false
		}
		amount = parsed
	default:
		return false
	}
	return amount >= 0.001 && amount <= 64
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
