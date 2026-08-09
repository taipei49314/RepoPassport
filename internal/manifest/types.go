package manifest

import (
	"github.com/taipei49314/RepoPassport/internal/domain"
	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "repopass.dev/v1alpha1"
	Kind       = "RepositoryPassport"
)

type Document struct {
	Manifest *Manifest
	Raw      any
	Digest   string
	Path     string
}

type Manifest struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name        string            `json:"name" yaml:"name"`
	DisplayName string            `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Maintainers []Maintainer      `json:"maintainers,omitempty" yaml:"maintainers,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

type Maintainer struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url,omitempty" yaml:"url,omitempty"`
}

type Spec struct {
	Project      ProjectSpec                `json:"project" yaml:"project"`
	Environments map[string]EnvironmentSpec `json:"environments" yaml:"environments"`
	Scenarios    map[string]ScenarioSpec    `json:"scenarios" yaml:"scenarios"`
	Policies     PolicySpec                 `json:"policies" yaml:"policies"`
	Evidence     EvidenceSpec               `json:"evidence" yaml:"evidence"`
}

type ProjectSpec struct {
	Kind        string   `json:"kind" yaml:"kind"`
	Audiences   []string `json:"audiences,omitempty" yaml:"audiences,omitempty"`
	Entrypoints []string `json:"entrypoints,omitempty" yaml:"entrypoints,omitempty"`
}

type EnvironmentSpec struct {
	Platform               PlatformSpec  `json:"platform" yaml:"platform"`
	Runtime                RuntimeSpec   `json:"runtime" yaml:"runtime"`
	BaseImage              BaseImageSpec `json:"baseImage" yaml:"baseImage"`
	Resources              ResourceSpec  `json:"resources" yaml:"resources"`
	RequiredServices       []string      `json:"requiredServices,omitempty" yaml:"requiredServices,omitempty"`
	RequiredRunnerFeatures []string      `json:"requiredRunnerFeatures,omitempty" yaml:"requiredRunnerFeatures,omitempty"`
}

type PlatformSpec struct {
	OS           string `json:"os" yaml:"os"`
	Architecture string `json:"architecture" yaml:"architecture"`
}

type RuntimeSpec struct {
	Adapter string `json:"adapter" yaml:"adapter"`
	Version string `json:"version" yaml:"version"`
}

type BaseImageSpec struct {
	Reference string `json:"reference" yaml:"reference"`
}

type ResourceSpec struct {
	CPU      any    `json:"cpu" yaml:"cpu"`
	Memory   string `json:"memory" yaml:"memory"`
	Disk     string `json:"disk" yaml:"disk"`
	PIDs     int    `json:"pids" yaml:"pids"`
	Time     string `json:"time,omitempty" yaml:"time,omitempty"`
	LogBytes *int64 `json:"logBytes,omitempty" yaml:"logBytes,omitempty"`
}

type ScenarioSpec struct {
	Title        string                                `json:"title,omitempty" yaml:"title,omitempty"`
	Description  string                                `json:"description,omitempty" yaml:"description,omitempty"`
	Purpose      string                                `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Audience     string                                `json:"audience,omitempty" yaml:"audience,omitempty"`
	Environment  string                                `json:"environment" yaml:"environment"`
	Inputs       map[string]InputSpec                  `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Phases       PhaseSet                              `json:"phases" yaml:"phases"`
	Capabilities map[domain.Phase]domain.CapabilitySet `json:"capabilities" yaml:"capabilities"`
	Secrets      map[string]SecretSpec                 `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Verification VerificationSpec                      `json:"verification" yaml:"verification"`
}

type InputSpec struct {
	Type     string    `json:"type" yaml:"type"`
	Required bool      `json:"required" yaml:"required"`
	Fixture  string    `json:"fixture,omitempty" yaml:"fixture,omitempty"`
	Mount    MountSpec `json:"mount,omitempty" yaml:"mount,omitempty"`
	Choices  []any     `json:"choices,omitempty" yaml:"choices,omitempty"`
}

type MountSpec struct {
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	ReadOnly bool   `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
}

type PhaseSet struct {
	Prepare  *CommandPhase  `json:"prepare,omitempty" yaml:"prepare,omitempty"`
	Setup    *CommandPhase  `json:"setup,omitempty" yaml:"setup,omitempty"`
	Build    *CommandPhase  `json:"build,omitempty" yaml:"build,omitempty"`
	Run      *RunPhase      `json:"run,omitempty" yaml:"run,omitempty"`
	Exercise *ExercisePhase `json:"exercise,omitempty" yaml:"exercise,omitempty"`
	Cleanup  *CommandPhase  `json:"cleanup,omitempty" yaml:"cleanup,omitempty"`
}

type CommandPhase struct {
	Timeout              string                `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Steps                []PhaseStep           `json:"steps,omitempty" yaml:"steps,omitempty"`
	ObserverRequirements []ObserverRequirement `json:"observerRequirements,omitempty" yaml:"observerRequirements,omitempty"`
	Outputs              []string              `json:"outputs,omitempty" yaml:"outputs,omitempty"`
}

type RunPhase struct {
	Timeout              string                `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Steps                []PhaseStep           `json:"steps,omitempty" yaml:"steps,omitempty"`
	Service              *ServiceSpec          `json:"service,omitempty" yaml:"service,omitempty"`
	ObserverRequirements []ObserverRequirement `json:"observerRequirements,omitempty" yaml:"observerRequirements,omitempty"`
	Outputs              []string              `json:"outputs,omitempty" yaml:"outputs,omitempty"`
}

type ExercisePhase struct {
	Timeout              string                `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Driver               DriverSpec            `json:"driver" yaml:"driver"`
	ObserverRequirements []ObserverRequirement `json:"observerRequirements,omitempty" yaml:"observerRequirements,omitempty"`
	Outputs              []string              `json:"outputs,omitempty" yaml:"outputs,omitempty"`
}

type ObserverRequirement struct {
	Observer        string `json:"observer" yaml:"observer"`
	MinimumCoverage string `json:"minimumCoverage" yaml:"minimumCoverage"`
}

type PhaseStep struct {
	ID     string        `json:"id" yaml:"id"`
	Run    *RunAction    `json:"run,omitempty" yaml:"run,omitempty"`
	Signal *SignalAction `json:"signal,omitempty" yaml:"signal,omitempty"`
}

type RunAction struct {
	Command          []string                        `json:"command,omitempty" yaml:"command,omitempty"`
	Shell            *ShellCommand                   `json:"shell,omitempty" yaml:"shell,omitempty"`
	WorkingDirectory string                          `json:"workingDirectory,omitempty" yaml:"workingDirectory,omitempty"`
	Environment      map[string]EnvironmentReference `json:"environment,omitempty" yaml:"environment,omitempty"`
	Timeout          string                          `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	AllowedExitCodes []int                           `json:"allowedExitCodes,omitempty" yaml:"allowedExitCodes,omitempty"`
	OutputMode       string                          `json:"outputMode,omitempty" yaml:"outputMode,omitempty"`
}

type ShellCommand struct {
	Executable string `json:"executable" yaml:"executable"`
	Command    string `json:"command" yaml:"command"`
}

type EnvironmentReference struct {
	Source string `json:"source" yaml:"source"`
	Name   string `json:"name" yaml:"name"`
}

type SignalAction struct {
	Target      string `json:"target" yaml:"target"`
	Type        string `json:"type" yaml:"type"`
	GracePeriod string `json:"gracePeriod,omitempty" yaml:"gracePeriod,omitempty"`
}

type ServiceSpec struct {
	ID               string                          `json:"id" yaml:"id"`
	Command          []string                        `json:"command,omitempty" yaml:"command,omitempty"`
	Shell            *ShellCommand                   `json:"shell,omitempty" yaml:"shell,omitempty"`
	WorkingDirectory string                          `json:"workingDirectory,omitempty" yaml:"workingDirectory,omitempty"`
	Environment      map[string]EnvironmentReference `json:"environment,omitempty" yaml:"environment,omitempty"`
	Readiness        ReadinessSpec                   `json:"readiness,omitempty" yaml:"readiness,omitempty"`
}

type ReadinessSpec struct {
	HTTP *HTTPReadiness `json:"http,omitempty" yaml:"http,omitempty"`
}

type HTTPReadiness struct {
	URL     string `json:"url" yaml:"url"`
	Status  int    `json:"status" yaml:"status"`
	Timeout string `json:"timeout" yaml:"timeout"`
}

type DriverSpec struct {
	Type         string            `json:"type" yaml:"type"`
	Command      []string          `json:"command,omitempty" yaml:"command,omitempty"`
	StdinFixture string            `json:"stdinFixture,omitempty" yaml:"stdinFixture,omitempty"`
	Timeout      string            `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Assertions   []DriverAssertion `json:"assertions,omitempty" yaml:"assertions,omitempty"`
	Steps        []DriverStep      `json:"steps,omitempty" yaml:"steps,omitempty"`
}

type DriverStep struct {
	Request *HTTPRequest     `json:"request,omitempty" yaml:"request,omitempty"`
	Assert  *DriverAssertion `json:"assert,omitempty" yaml:"assert,omitempty"`
}

type HTTPRequest struct {
	ID      string            `json:"id" yaml:"id"`
	Method  string            `json:"method" yaml:"method"`
	URL     string            `json:"url" yaml:"url"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	JSON    any               `json:"json,omitempty" yaml:"json,omitempty"`
	Body    string            `json:"body,omitempty" yaml:"body,omitempty"`
	Timeout string            `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	bodyPresent bool
	jsonPresent bool
}

func (request HTTPRequest) HasBody() bool {
	return request.bodyPresent || request.Body != ""
}

func (request HTTPRequest) HasJSON() bool {
	return request.jsonPresent || request.JSON != nil
}

func (request *HTTPRequest) UnmarshalYAML(value *yaml.Node) error {
	type plainHTTPRequest HTTPRequest
	var decoded plainHTTPRequest
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*request = HTTPRequest(decoded)
	if value.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(value.Content); index += 2 {
		switch value.Content[index].Value {
		case "body":
			request.bodyPresent = true
		case "json":
			request.jsonPresent = true
		}
	}
	return nil
}

type DriverAssertion struct {
	ID               string             `json:"id,omitempty" yaml:"id,omitempty"`
	Required         *bool              `json:"required,omitempty" yaml:"required,omitempty"`
	ExitCode         *int               `json:"exitCode,omitempty" yaml:"exitCode,omitempty"`
	StdoutContains   *string            `json:"stdoutContains,omitempty" yaml:"stdoutContains,omitempty"`
	StderrContains   *string            `json:"stderrContains,omitempty" yaml:"stderrContains,omitempty"`
	StdoutRegex      *string            `json:"stdoutRegex,omitempty" yaml:"stdoutRegex,omitempty"`
	StdoutJSONSchema string             `json:"stdoutJsonSchema,omitempty" yaml:"stdoutJsonSchema,omitempty"`
	StderrRegex      *string            `json:"stderrRegex,omitempty" yaml:"stderrRegex,omitempty"`
	FileExists       string             `json:"fileExists,omitempty" yaml:"fileExists,omitempty"`
	Response         *ResponseAssertion `json:"response,omitempty" yaml:"response,omitempty"`
	JSONFile         *JSONFileAssertion `json:"jsonFile,omitempty" yaml:"jsonFile,omitempty"`
}

type ResponseAssertion struct {
	RequestID    string             `json:"requestId" yaml:"requestId"`
	Status       int                `json:"status,omitempty" yaml:"status,omitempty"`
	Header       *HeaderAssertion   `json:"header,omitempty" yaml:"header,omitempty"`
	BodyContains *string            `json:"bodyContains,omitempty" yaml:"bodyContains,omitempty"`
	JSONPath     *JSONPathAssertion `json:"jsonPath,omitempty" yaml:"jsonPath,omitempty"`
	JSONSchema   string             `json:"jsonSchema,omitempty" yaml:"jsonSchema,omitempty"`
}

type HeaderAssertion struct {
	Name     string `json:"name" yaml:"name"`
	Contains string `json:"contains" yaml:"contains"`
}

type JSONPathAssertion struct {
	Path   string `json:"path" yaml:"path"`
	Equals any    `json:"equals" yaml:"equals"`
}

type JSONFileAssertion struct {
	Path   string `json:"path" yaml:"path"`
	Schema string `json:"schema" yaml:"schema"`
}

type SecretSpec struct {
	Source   string       `json:"source" yaml:"source"`
	Scope    SecretScope  `json:"scope" yaml:"scope"`
	ExposeAs SecretExpose `json:"exposeAs" yaml:"exposeAs"`
}

type SecretScope struct {
	Phases []domain.Phase `json:"phases" yaml:"phases"`
}

type SecretExpose struct {
	Env string `json:"env" yaml:"env"`
}

type VerificationSpec struct {
	Repeats                 int         `json:"repeats" yaml:"repeats"`
	SuccessThreshold        int         `json:"successThreshold" yaml:"successThreshold"`
	RequiredObservers       []string    `json:"requiredObservers" yaml:"requiredObservers"`
	Cleanup                 CleanupSpec `json:"cleanup" yaml:"cleanup"`
	StabilityRule           string      `json:"stabilityRule,omitempty" yaml:"stabilityRule,omitempty"`
	ResourceVariancePercent *float64    `json:"resourceVariancePercent,omitempty" yaml:"resourceVariancePercent,omitempty"`
}

type CleanupSpec struct {
	AllowedResidue []string `json:"allowedResidue,omitempty" yaml:"allowedResidue,omitempty"`
}

type PolicySpec struct {
	Profile string `json:"profile" yaml:"profile"`
}

type EvidenceSpec struct {
	Profile string   `json:"profile,omitempty" yaml:"profile,omitempty"`
	Include []string `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}
