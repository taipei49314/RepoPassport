package domain

import (
	"context"
	"encoding/json"
	"time"
)

type Phase string

const (
	PhasePrepare  Phase = "prepare"
	PhaseSetup    Phase = "setup"
	PhaseBuild    Phase = "build"
	PhaseRun      Phase = "run"
	PhaseExercise Phase = "exercise"
	PhaseCleanup  Phase = "cleanup"
)

var OrderedPhases = []Phase{
	PhasePrepare,
	PhaseSetup,
	PhaseBuild,
	PhaseRun,
	PhaseExercise,
	PhaseCleanup,
}

type SourceRef struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Ref   string `json:"ref,omitempty"`
}

type ResolvedSource struct {
	Kind         string `json:"kind"`
	Canonical    string `json:"canonical"`
	LocalPath    string `json:"-"`
	Commit       string `json:"commit,omitempty"`
	RetrievedVia string `json:"retrievedVia"`
}

type FileEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type SourceSnapshot struct {
	Identity    string      `json:"identity"`
	Commit      string      `json:"commit,omitempty"`
	TreeDigest  string      `json:"treeDigest"`
	Root        string      `json:"-"`
	Inventory   []FileEntry `json:"inventory,omitempty"`
	TotalSize   int64       `json:"totalSize"`
	FileCount   int         `json:"fileCount"`
	GeneratedAt time.Time   `json:"generatedAt,omitempty"`
}

type DetectionStatus string

const (
	StatusDeclared DetectionStatus = "declared"
	StatusInferred DetectionStatus = "inferred"
)

type DetectionSignal struct {
	Field      string          `json:"field"`
	Value      any             `json:"value"`
	Source     string          `json:"source"`
	Method     string          `json:"method"`
	Confidence float64         `json:"confidence"`
	Status     DetectionStatus `json:"status"`
}

type ProjectDescriptor struct {
	ProjectKind    string            `json:"projectKind"`
	Languages      []string          `json:"languages"`
	RuntimeHints   []string          `json:"runtimeHints"`
	PackageManager string            `json:"packageManager,omitempty"`
	Entrypoints    []string          `json:"entrypoints"`
	Signals        []DetectionSignal `json:"signals"`
	Warnings       []string          `json:"warnings,omitempty"`
}

type NetworkDestination struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
}

type NetworkCapability struct {
	Deny  bool                 `json:"deny" yaml:"deny"`
	Allow []NetworkDestination `json:"allow,omitempty" yaml:"allow,omitempty"`
}

type FilesystemCapability struct {
	Read    []string `json:"read,omitempty" yaml:"read,omitempty"`
	Write   []string `json:"write,omitempty" yaml:"write,omitempty"`
	Create  []string `json:"create,omitempty" yaml:"create,omitempty"`
	Delete  []string `json:"delete,omitempty" yaml:"delete,omitempty"`
	Rename  []string `json:"rename,omitempty" yaml:"rename,omitempty"`
	Chmod   []string `json:"chmod,omitempty" yaml:"chmod,omitempty"`
	Symlink []string `json:"symlink,omitempty" yaml:"symlink,omitempty"`
}

type PortBinding struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
}

type PortCapability struct {
	Listen []PortBinding `json:"listen,omitempty" yaml:"listen,omitempty"`
}

type ProcessCapability struct {
	Exec                []string `json:"exec,omitempty" yaml:"exec,omitempty"`
	Background          bool     `json:"background,omitempty" yaml:"-"`
	ChildProcesses      *bool    `json:"childProcesses,omitempty" yaml:"childProcesses,omitempty"`
	Shell               *bool    `json:"shell,omitempty" yaml:"shell,omitempty"`
	BackgroundProcesses *bool    `json:"backgroundProcesses,omitempty" yaml:"backgroundProcesses,omitempty"`
}

type EnvironmentCapability struct {
	Read     []string `json:"read,omitempty" yaml:"read,omitempty"`
	Write    []string `json:"write,omitempty" yaml:"write,omitempty"`
	Locale   string   `json:"locale,omitempty" yaml:"locale,omitempty"`
	Timezone string   `json:"timezone,omitempty" yaml:"timezone,omitempty"`
}

type DeclaredResourceLimits struct {
	CPU      any    `json:"cpu" yaml:"cpu"`
	Memory   string `json:"memory" yaml:"memory"`
	Disk     string `json:"disk" yaml:"disk"`
	PIDs     int    `json:"pids" yaml:"pids"`
	Time     string `json:"time,omitempty" yaml:"time,omitempty"`
	LogBytes *int64 `json:"logBytes,omitempty" yaml:"logBytes,omitempty"`
}

type CapabilitySet struct {
	Network         NetworkCapability       `json:"network" yaml:"network"`
	Filesystem      FilesystemCapability    `json:"filesystem" yaml:"filesystem"`
	Ports           PortCapability          `json:"ports" yaml:"ports"`
	Process         ProcessCapability       `json:"process" yaml:"process"`
	Environment     *EnvironmentCapability  `json:"environment,omitempty" yaml:"environment,omitempty"`
	Secrets         []string                `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Resources       *DeclaredResourceLimits `json:"resources,omitempty" yaml:"resources,omitempty"`
	Devices         *bool                   `json:"devices,omitempty" yaml:"devices,omitempty"`
	HostIntegration *bool                   `json:"hostIntegration,omitempty" yaml:"hostIntegration,omitempty"`
}

type PlanSource struct {
	Identity   string `json:"identity"`
	Commit     string `json:"commit,omitempty"`
	TreeDigest string `json:"treeDigest"`
}

type PlanCommand struct {
	Phase     Phase              `json:"phase"`
	ID        string             `json:"id"`
	Argv      []string           `json:"argv,omitempty"`
	Signal    *PlanSignal        `json:"signal,omitempty"`
	Readiness *PlanHTTPReadiness `json:"readiness,omitempty"`
	Timeout   string             `json:"timeout"`
	Role      string             `json:"role"`
}

type PlanSignal struct {
	Target      string `json:"target"`
	Type        string `json:"type"`
	GracePeriod string `json:"gracePeriod,omitempty"`
}

type PlanHTTPReadiness struct {
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Timeout string `json:"timeout"`
}

type PlanHTTPJourney struct {
	ServiceID string               `json:"serviceId"`
	Steps     []PlanHTTPDriverStep `json:"steps"`
}

type PlanHTTPDriverStep struct {
	Request     *PlanHTTPRequest `json:"request,omitempty"`
	AssertionID string           `json:"assertionId,omitempty"`
}

type PlanHTTPRequest struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *string           `json:"body,omitempty"`
	JSON    json.RawMessage   `json:"json,omitempty"`
	Timeout string            `json:"timeout"`
}

type PlanHTTPResponseAssertion struct {
	RequestID    string                   `json:"requestId"`
	Status       *int                     `json:"status,omitempty"`
	Header       *PlanHTTPHeaderAssertion `json:"header,omitempty"`
	BodyContains *string                  `json:"bodyContains,omitempty"`
	JSONPath     *PlanJSONPathAssertion   `json:"jsonPath,omitempty"`
	JSONSchema   *PlanJSONSchemaRef       `json:"jsonSchema,omitempty"`
}

type PlanHTTPHeaderAssertion struct {
	Name     string `json:"name"`
	Contains string `json:"contains"`
}

type PlanJSONPathAssertion struct {
	Path   string          `json:"path"`
	Equals json.RawMessage `json:"equals"`
}

type PlanJSONSchemaRef struct {
	Path             string `json:"path"`
	Digest           string `json:"digest"`
	Dialect          string `json:"dialect"`
	ValidatorVersion string `json:"validatorVersion"`
}

type PlanJSONFileAssertion struct {
	Path   string            `json:"path"`
	Schema PlanJSONSchemaRef `json:"schema"`
}

type PlanAssertion struct {
	ID               string                     `json:"id"`
	ExitCode         *int                       `json:"exitCode,omitempty"`
	StdoutContains   string                     `json:"stdoutContains,omitempty"`
	StderrContains   string                     `json:"stderrContains,omitempty"`
	StdoutRegex      string                     `json:"stdoutRegex,omitempty"`
	StdoutJSONSchema *PlanJSONSchemaRef         `json:"stdoutJsonSchema,omitempty"`
	FileExists       string                     `json:"fileExists,omitempty"`
	Response         *PlanHTTPResponseAssertion `json:"response,omitempty"`
	JSONFile         *PlanJSONFileAssertion     `json:"jsonFile,omitempty"`
}

type PlanCleanup struct {
	ClassifierVersion string   `json:"classifierVersion"`
	AllowedResidue    []string `json:"allowedResidue"`
}

type PlanEvidence struct {
	Profile string   `json:"profile"`
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type ResolvedPlan struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Source                 PlanSource              `json:"source"`
	ManifestDigest         string                  `json:"manifestDigest"`
	Scenario               string                  `json:"scenario"`
	Environment            string                  `json:"environment"`
	RuntimeAdapter         string                  `json:"runtimeAdapter"`
	RuntimeVersion         string                  `json:"runtimeVersion"`
	BaseImageReference     string                  `json:"baseImageReference"`
	BaseImageDigest        string                  `json:"baseImageDigest"`
	Resources              ResourceLimits          `json:"resources"`
	Inputs                 []PlanInput             `json:"inputs"`
	AdapterVersions        map[string]string       `json:"adapterVersions"`
	ObserverVersions       map[string]string       `json:"observerVersions"`
	JourneyDriver          string                  `json:"journeyDriver"`
	JourneyDriverVersion   string                  `json:"journeyDriverVersion"`
	Commands               []PlanCommand           `json:"commands"`
	JourneyAssertions      []PlanAssertion         `json:"journeyAssertions"`
	HTTPJourney            *PlanHTTPJourney        `json:"httpJourney,omitempty"`
	Cleanup                PlanCleanup             `json:"cleanup"`
	Evidence               PlanEvidence            `json:"evidence"`
	Capabilities           map[Phase]CapabilitySet `json:"capabilities"`
	RequiredRunnerFeatures []string                `json:"requiredRunnerFeatures"`
	ObserverSet            []string                `json:"observerSet"`
	RepeatCount            int                     `json:"repeatCount"`
	SuccessThreshold       int                     `json:"successThreshold"`
	PolicyBundleDigest     string                  `json:"policyBundleDigest"`
	PlanDigest             string                  `json:"planDigest"`
}

type ResourceLimits struct {
	CPUMillis   int64 `json:"cpuMillis"`
	MemoryBytes int64 `json:"memoryBytes"`
	DiskBytes   int64 `json:"diskBytes"`
	PIDs        int   `json:"pids"`
}

type PlanInput struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Fixture   string `json:"fixture"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}

type RunnerFeatures struct {
	Backend                    string `json:"backend"`
	Available                  bool   `json:"available"`
	ControllerOS               string `json:"controllerOS"`
	WorkloadOS                 string `json:"workloadOS"`
	Rootless                   string `json:"rootless"`
	NetworkDeny                bool   `json:"networkDeny"`
	NetworkAttemptObservation  string `json:"networkAttemptObservation"`
	ProcessExecObservation     string `json:"processExecObservation"`
	FilesystemWriteObservation string `json:"filesystemWriteObservation"`
	FilesystemReadObservation  string `json:"filesystemReadObservation"`
	PortObservation            string `json:"portObservation"`
	ResourceUsage              string `json:"resourceUsage"`
	ResourceLimitEnforcement   bool   `json:"resourceLimitEnforcement,omitempty"`
	EngineVersion              string `json:"engineVersion,omitempty"`
	Reason                     string `json:"reason,omitempty"`
}

type ObservationEvent struct {
	SchemaVersion string         `json:"schemaVersion"`
	Sequence      uint64         `json:"sequence"`
	Timestamp     time.Time      `json:"timestamp"`
	Phase         Phase          `json:"phase"`
	Actor         string         `json:"actor"`
	Operation     string         `json:"operation"`
	Resource      string         `json:"resource"`
	Result        string         `json:"result"`
	Observer      string         `json:"observer"`
	Coverage      string         `json:"coverage"`
	Confidence    string         `json:"confidence"`
	Details       map[string]any `json:"details,omitempty"`
}

type AssertionResult struct {
	SchemaVersion  string   `json:"schemaVersion"`
	ID             string   `json:"assertionId"`
	Type           string   `json:"type"`
	Required       bool     `json:"required"`
	Expected       any      `json:"expected"`
	Actual         any      `json:"actual"`
	Status         string   `json:"status"`
	EvidenceRefs   []string `json:"evidenceRefs"`
	Message        string   `json:"message,omitempty"`
	Repeat         int      `json:"repeat,omitempty"`
	DurationMillis int64    `json:"durationMillis,omitempty"`
}

type PolicyDecision struct {
	PolicyID           string   `json:"policyId"`
	PolicyBundleDigest string   `json:"policyBundleDigest"`
	Decision           string   `json:"decision"`
	Severity           Severity `json:"severity"`
	Message            string   `json:"message"`
	EvidenceRefs       []string `json:"evidenceRefs,omitempty"`
}

type FunctionalVerdict string
type CapabilityVerdict string
type ReproducibilityVerdict string
type CleanupVerdict string
type EvidenceState string
type FreshnessVerdict string
type OverallVerdict string

const (
	FunctionalPass         FunctionalVerdict = "pass"
	FunctionalFail         FunctionalVerdict = "fail"
	FunctionalBlocked      FunctionalVerdict = "blocked"
	FunctionalInconclusive FunctionalVerdict = "inconclusive"

	CapabilityConforming    CapabilityVerdict = "conforming"
	CapabilityNonconforming CapabilityVerdict = "nonconforming"
	CapabilityIncomplete    CapabilityVerdict = "incomplete"
	CapabilityWarning       CapabilityVerdict = "warning"

	ReproducibilityStable          ReproducibilityVerdict = "stable"
	ReproducibilityFlaky           ReproducibilityVerdict = "flaky"
	ReproducibilityNotReproducible ReproducibilityVerdict = "not-reproducible"
	ReproducibilityNotTested       ReproducibilityVerdict = "not-tested"
	ReproducibilityUnstable        ReproducibilityVerdict = ReproducibilityNotReproducible

	CleanupClean             CleanupVerdict = "clean"
	CleanupAllowedResidue    CleanupVerdict = "allowed-residue"
	CleanupUndeclaredResidue CleanupVerdict = "undeclared-residue"
	CleanupNotTested         CleanupVerdict = "not-tested"
	CleanupResidue           CleanupVerdict = CleanupUndeclaredResidue
	CleanupInconclusive      CleanupVerdict = CleanupNotTested

	EvidenceNone               EvidenceState = "none"
	EvidenceUnsigned           EvidenceState = "unsigned"
	EvidenceSelfSigned         EvidenceState = "self-signed"
	EvidenceMaintainerCISigned EvidenceState = "maintainer-ci-signed"
	EvidencePublicRunnerSigned EvidenceState = "public-runner-signed"
	EvidenceEnterpriseSigned   EvidenceState = "enterprise-signed"
	EvidenceTampered           EvidenceState = "tampered"
	EvidenceUntrustedSigner    EvidenceState = "untrusted-signer"
	EvidenceInvalid            EvidenceState = EvidenceTampered

	FreshnessCurrent       FreshnessVerdict = "current"
	FreshnessSourceChanged FreshnessVerdict = "source-changed"
	FreshnessPlanChanged   FreshnessVerdict = "plan-changed"
	FreshnessPolicyChanged FreshnessVerdict = "policy-changed"
	FreshnessRunnerChanged FreshnessVerdict = "runner-changed"
	FreshnessExpired       FreshnessVerdict = "expired"
	FreshnessStale         FreshnessVerdict = FreshnessSourceChanged

	OverallVerified             OverallVerdict = "verified"
	OverallVerifiedWithWarnings OverallVerdict = "verified-with-warnings"
	OverallNonconforming        OverallVerdict = "nonconforming"
	OverallFailed               OverallVerdict = "failed"
	OverallBlocked              OverallVerdict = "blocked"
	OverallInconclusive         OverallVerdict = "inconclusive"
	OverallStale                OverallVerdict = "stale"
)

type Verdicts struct {
	Functional      FunctionalVerdict      `json:"functional"`
	Capability      CapabilityVerdict      `json:"capability"`
	Reproducibility ReproducibilityVerdict `json:"reproducibility"`
	Cleanup         CleanupVerdict         `json:"cleanup"`
	Evidence        EvidenceState          `json:"evidence"`
	Freshness       FreshnessVerdict       `json:"freshness"`
	Overall         OverallVerdict         `json:"overall"`
}

type ObserverCoverage struct {
	Observer string `json:"observer"`
	Feature  string `json:"feature"`
	Coverage string `json:"coverage"`
	Required bool   `json:"required"`
	Reason   string `json:"reason,omitempty"`
}

type VerificationResult struct {
	SchemaVersion    string              `json:"schemaVersion"`
	VerificationID   string              `json:"verificationId"`
	RunID            string              `json:"runId"`
	StartedAt        time.Time           `json:"startedAt"`
	CompletedAt      time.Time           `json:"completedAt"`
	Subject          PlanSource          `json:"subject"`
	Plan             VerificationPlanRef `json:"plan"`
	Runner           RunnerFeatures      `json:"runner"`
	Results          Verdicts            `json:"results"`
	ObserverCoverage []ObserverCoverage  `json:"observerCoverage"`
	Observations     []ObservationEvent  `json:"observations"`
	Assertions       []AssertionResult   `json:"assertions"`
	PolicyDecisions  []PolicyDecision    `json:"policyDecisions"`
	Errors           []*Error            `json:"errors,omitempty"`
	Repeats          RepeatSummary       `json:"repeats"`
	Resources        ResourceSummary     `json:"resources"`
	Digests          VerificationDigests `json:"digests"`
}

type VerificationPlanRef struct {
	Scenario                  string       `json:"scenario"`
	Environment               string       `json:"environment"`
	PlanDigest                string       `json:"planDigest"`
	PolicyBundleDigest        string       `json:"policyBundleDigest"`
	RepeatCount               int          `json:"repeatCount"`
	SuccessThreshold          int          `json:"successThreshold"`
	ResolvedPlanSchemaVersion string       `json:"resolvedPlanSchemaVersion"`
	Evidence                  PlanEvidence `json:"evidence"`
}

type RepeatSummary struct {
	Requested int `json:"requested"`
	Completed int `json:"completed"`
	Matching  int `json:"matching"`
}

type ResourceObservedField string

const (
	ResourceObservedMaxTasks               ResourceObservedField = "maxTasks"
	ResourceObservedOutputBytes            ResourceObservedField = "outputBytes"
	ResourceObservedSandboxCPUTimeMillis   ResourceObservedField = "sandboxCPUTimeMillis"
	ResourceObservedSandboxPeakMemoryBytes ResourceObservedField = "sandboxPeakMemoryBytes"
	ResourceObservedWritableBytes          ResourceObservedField = "writableBytes"
)

type ResourceSummary struct {
	// Legacy fields retain the alpha.3 wire shape. Their scope is unspecified;
	// new observers must use the sandbox-scoped fields below instead.
	PeakMemoryBytes int64 `json:"peakMemoryBytes,omitempty"`
	CPUTimeMillis   int64 `json:"cpuTimeMillis,omitempty"`
	DurationMillis  int64 `json:"durationMillis"`
	MaxProcesses    int   `json:"maxProcesses,omitempty"`
	LogBytes        int64 `json:"logBytes,omitempty"`

	// SandboxPeakMemoryBytes is the cgroup-wide memory peak, including trusted
	// helpers in the sandbox. It is not workload RSS.
	SandboxPeakMemoryBytes int64 `json:"sandboxPeakMemoryBytes,omitempty"`
	// SandboxCPUTimeMillis is cumulative cgroup CPU time for the sandbox,
	// including trusted helpers.
	SandboxCPUTimeMillis int64 `json:"sandboxCPUTimeMillis,omitempty"`
	// MaxTasks is the cgroup peak task/TID count, not a process count.
	MaxTasks int `json:"maxTasks,omitempty"`
	// WritableBytes is a bounded current/final writable-storage snapshot. It
	// is not a peak or growth measurement.
	WritableBytes int64 `json:"writableBytes,omitempty"`
	// OutputBytes is the controller-verified size of accepted exported output.
	OutputBytes int64 `json:"outputBytes,omitempty"`
	// ObservedFields explicitly distinguishes an observed zero from an
	// unavailable measurement. Values must be unique and sorted.
	ObservedFields []ResourceObservedField `json:"observedFields,omitempty"`
}

type VerificationDigests struct {
	Observations    string `json:"observations"`
	Assertions      string `json:"assertions"`
	PolicyDecisions string `json:"policyDecisions"`
	Verification    string `json:"verification"`
}

type ExecRequest struct {
	Phase      Phase
	ID         string
	Argv       []string
	Timeout    time.Duration
	Stdin      []byte
	Background bool
}

type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration
}

type RunContext struct {
	Plan ResolvedPlan
}

type VerificationInput struct {
	Plan         ResolvedPlan
	Runner       RunnerFeatures
	Observations []ObservationEvent
	Assertions   []AssertionResult
	Errors       []*Error
}

// Ports are defined in the domain package, but concrete adapters must not leak
// engine-specific objects through them.
type SourceProvider interface {
	Resolve(context.Context, SourceRef) (ResolvedSource, error)
	Fetch(context.Context, ResolvedSource) (SourceSnapshot, error)
}

type Detector interface {
	Name() string
	Detect(context.Context, SourceSnapshot) ([]DetectionSignal, error)
}

type PlanResolver interface {
	Resolve(context.Context, any) (ResolvedPlan, error)
}

type SandboxBackend interface {
	Name() string
	Features(context.Context) (RunnerFeatures, error)
	Prepare(context.Context, ResolvedPlan) (Sandbox, error)
}

type Sandbox interface {
	Start(context.Context) error
	Exec(context.Context, ExecRequest) (ExecResult, error)
	Stop(context.Context) error
	Destroy(context.Context) error
}
