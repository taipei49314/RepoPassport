package planner

import (
	"fmt"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/manifest"
)

// validateSchemaExecutionFeatures keeps the public authoring schema broader
// than the alpha runner without silently erasing declarations during
// resolution. Every declaration rejected here must be implemented and bound
// into the resolved plan before it can be accepted.
func validateSchemaExecutionFeatures(
	scenarioName string,
	environment manifest.EnvironmentSpec,
	scenario manifest.ScenarioSpec,
) error {
	unavailable := func(feature, field string) error {
		err := domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			fmt.Sprintf("Manifest feature %q is recognized but unavailable in the v0.1 local runner.", feature),
		)
		err.Details = map[string]any{
			"scenario": scenarioName,
			"feature":  feature,
			"field":    field,
		}
		return err
	}

	if environment.RequiredServices != nil {
		return unavailable("environment-required-services", "spec.environments."+scenario.Environment+".requiredServices")
	}
	if environment.RequiredRunnerFeatures != nil {
		return unavailable("environment-required-runner-features", "spec.environments."+scenario.Environment+".requiredRunnerFeatures")
	}
	if environment.Resources.Time != "" {
		return unavailable("environment-time-limit", "spec.environments."+scenario.Environment+".resources.time")
	}
	if environment.Resources.LogBytes != nil {
		return unavailable("environment-log-byte-limit", "spec.environments."+scenario.Environment+".resources.logBytes")
	}

	type phaseFeatures struct {
		name                 domain.Phase
		steps                []manifest.PhaseStep
		observerRequirements []manifest.ObserverRequirement
		outputs              []string
	}
	phases := make([]phaseFeatures, 0, len(domain.OrderedPhases))
	appendCommandPhase := func(name domain.Phase, phase *manifest.CommandPhase) {
		if phase == nil {
			return
		}
		phases = append(phases, phaseFeatures{
			name:                 name,
			steps:                phase.Steps,
			observerRequirements: phase.ObserverRequirements,
			outputs:              phase.Outputs,
		})
	}
	appendCommandPhase(domain.PhasePrepare, scenario.Phases.Prepare)
	appendCommandPhase(domain.PhaseSetup, scenario.Phases.Setup)
	appendCommandPhase(domain.PhaseBuild, scenario.Phases.Build)
	httpServiceID := ""
	if scenario.Phases.Exercise != nil &&
		scenario.Phases.Exercise.Driver.Type == "http" &&
		scenario.Phases.Run != nil &&
		scenario.Phases.Run.Service != nil {
		httpServiceID = scenario.Phases.Run.Service.ID
	}
	if phase := scenario.Phases.Run; phase != nil {
		phases = append(phases, phaseFeatures{
			name:                 domain.PhaseRun,
			steps:                phase.Steps,
			observerRequirements: phase.ObserverRequirements,
			outputs:              phase.Outputs,
		})
		if phase.Service != nil {
			base := "spec.scenarios." + scenarioName + ".phases.run.service"
			switch {
			case httpServiceID == "":
				return unavailable("background-service", base)
			case phase.Service.WorkingDirectory != "":
				return unavailable(
					"service-working-directory",
					base+".workingDirectory",
				)
			case phase.Service.Environment != nil:
				return unavailable("service-environment", base+".environment")
			}
		}
	}
	if phase := scenario.Phases.Exercise; phase != nil {
		phases = append(phases, phaseFeatures{
			name:                 domain.PhaseExercise,
			observerRequirements: phase.ObserverRequirements,
			outputs:              phase.Outputs,
		})
	}
	appendCommandPhase(domain.PhaseCleanup, scenario.Phases.Cleanup)

	for _, phase := range phases {
		base := "spec.scenarios." + scenarioName + ".phases." + string(phase.name)
		if phase.observerRequirements != nil {
			return unavailable("phase-observer-requirements", base+".observerRequirements")
		}
		if phase.outputs != nil {
			return unavailable("phase-outputs", base+".outputs")
		}
		for index, step := range phase.steps {
			stepBase := fmt.Sprintf("%s.steps[%d]", base, index)
			if step.Signal != nil {
				if httpServiceID != "" &&
					phase.name == domain.PhaseCleanup &&
					step.Signal.Target == httpServiceID {
					continue
				}
				return unavailable("signal-step", stepBase+".signal")
			}
			if step.Run == nil {
				continue
			}
			switch {
			case step.Run.Shell != nil:
				return unavailable("shell-command", stepBase+".run.shell")
			case step.Run.WorkingDirectory != "":
				return unavailable("command-working-directory", stepBase+".run.workingDirectory")
			case step.Run.Environment != nil:
				return unavailable("command-environment", stepBase+".run.environment")
			case step.Run.Timeout != "":
				return unavailable("command-timeout", stepBase+".run.timeout")
			case step.Run.AllowedExitCodes != nil:
				return unavailable("allowed-exit-codes", stepBase+".run.allowedExitCodes")
			case step.Run.OutputMode != "":
				return unavailable("command-output-mode", stepBase+".run.outputMode")
			}
		}
	}

	if exercise := scenario.Phases.Exercise; exercise != nil {
		driver := exercise.Driver
		if driver.Timeout != "" {
			return unavailable("journey-driver-timeout", "spec.scenarios."+scenarioName+".phases.exercise.driver.timeout")
		}
		for index, assertion := range driver.Assertions {
			field := fmt.Sprintf(
				"spec.scenarios.%s.phases.exercise.driver.assertions[%d]",
				scenarioName,
				index,
			)
			switch {
			case assertion.StderrRegex != nil:
				return unavailable("stderr-regex-assertion", field+".stderrRegex")
			case assertion.StdoutContains != nil && *assertion.StdoutContains == "":
				return unavailable("empty-string-assertion", field+".stdoutContains")
			case assertion.StderrContains != nil && *assertion.StderrContains == "":
				return unavailable("empty-string-assertion", field+".stderrContains")
			case assertion.StdoutRegex != nil && *assertion.StdoutRegex == "":
				return unavailable("empty-regex-assertion", field+".stdoutRegex")
			}
		}
	}

	for _, phase := range domain.OrderedPhases {
		capability, ok := scenario.Capabilities[phase]
		if !ok {
			continue
		}
		base := "spec.scenarios." + scenarioName + ".capabilities." + string(phase)
		if len(capability.Network.Allow) > 0 {
			return unavailable("network-allowlist", base+".network.allow")
		}
		for index, destination := range capability.Network.Allow {
			if destination.Protocol != "" {
				return unavailable("network-protocol", fmt.Sprintf("%s.network.allow[%d].protocol", base, index))
			}
		}
		for index, writablePath := range capability.Filesystem.Write {
			if !pathWithinOutputs(writablePath) {
				return unavailable(
					"filesystem-write-outside-outputs",
					fmt.Sprintf("%s.filesystem.write[%d]", base, index),
				)
			}
		}
		switch {
		case capability.Filesystem.Create != nil:
			return unavailable("filesystem-create-capability", base+".filesystem.create")
		case capability.Filesystem.Delete != nil:
			return unavailable("filesystem-delete-capability", base+".filesystem.delete")
		case capability.Filesystem.Rename != nil:
			return unavailable("filesystem-rename-capability", base+".filesystem.rename")
		case capability.Filesystem.Chmod != nil:
			return unavailable("filesystem-chmod-capability", base+".filesystem.chmod")
		case capability.Filesystem.Symlink != nil:
			return unavailable("filesystem-symlink-capability", base+".filesystem.symlink")
		}
		for index, binding := range capability.Ports.Listen {
			if binding.Protocol != "" {
				if httpServiceID != "" &&
					phase == domain.PhaseRun &&
					binding.Protocol == "tcp" {
					continue
				}
				return unavailable("listen-protocol", fmt.Sprintf("%s.ports.listen[%d].protocol", base, index))
			}
		}
		switch {
		case capability.Process.ChildProcesses != nil:
			return unavailable("child-process-capability", base+".process.childProcesses")
		case capability.Process.Shell != nil:
			return unavailable("process-shell-capability", base+".process.shell")
		case capability.Process.BackgroundProcesses != nil:
			return unavailable("background-process-capability", base+".process.backgroundProcesses")
		case capability.Environment != nil:
			return unavailable("environment-capability", base+".environment")
		case capability.Secrets != nil:
			return unavailable("secret-capability", base+".secrets")
		case capability.Resources != nil:
			return unavailable("phase-resource-limits", base+".resources")
		case capability.Devices != nil:
			return unavailable("device-capability", base+".devices")
		case capability.HostIntegration != nil:
			return unavailable("host-integration-capability", base+".hostIntegration")
		}
	}

	if scenario.Verification.SuccessThreshold < scenario.Verification.Repeats {
		return unavailable(
			"threshold-success-policy",
			"spec.scenarios."+scenarioName+".verification.successThreshold",
		)
	}
	if scenario.Verification.StabilityRule != "" {
		return unavailable(
			"stability-rule",
			"spec.scenarios."+scenarioName+".verification.stabilityRule",
		)
	}
	if scenario.Verification.ResourceVariancePercent != nil {
		return unavailable(
			"resource-variance",
			"spec.scenarios."+scenarioName+".verification.resourceVariancePercent",
		)
	}
	residue := scenario.Verification.Cleanup.AllowedResidue
	if len(residue) > 1 || len(residue) == 1 && residue[0] != "/outputs/**" {
		return unavailable(
			"custom-cleanup-residue",
			"spec.scenarios."+scenarioName+".verification.cleanup.allowedResidue",
		)
	}

	return nil
}

func pathWithinOutputs(value string) bool {
	return value == "/outputs" || strings.HasPrefix(value, "/outputs/")
}
