package acceptanceregistry

const (
	MaxRegistryBytes   = 256 << 10
	MaxEvaluationBytes = 1 << 20
)

type RowStatus string

const (
	StatusPass    RowStatus = "PASS"
	StatusFail    RowStatus = "FAIL"
	StatusNotRun  RowStatus = "NOT_RUN"
	StatusBlocked RowStatus = "BLOCKED"
)

type OverallStatus string

const (
	OverallPass       OverallStatus = "PASS"
	OverallFail       OverallStatus = "FAIL"
	OverallIncomplete OverallStatus = "INCOMPLETE"
)

type Registry struct {
	ArtifactType  string        `json:"artifactType"`
	Product       string        `json:"product"`
	Rows          []RegistryRow `json:"rows"`
	SchemaVersion string        `json:"schemaVersion"`
}

type RegistryRow struct {
	AppliesTo  []string         `json:"appliesTo"`
	Criterion  string           `json:"criterion"`
	Evaluation EvaluationPolicy `json:"evaluation"`
	ID         string           `json:"id"`
	Milestone  string           `json:"milestone"`
	Required   bool             `json:"required"`
}

type EvaluationPolicy struct {
	Kind           string   `json:"kind"`
	ReasonCode     string   `json:"reasonCode,omitempty"`
	RequiredChecks []string `json:"requiredChecks,omitempty"`
}

type Subject struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
	TreeSHA    string `json:"treeSHA"`
}

type Run struct {
	Attempt      int64  `json:"attempt"`
	Event        string `json:"event"`
	ID           int64  `json:"id"`
	Ref          string `json:"ref"`
	WorkflowPath string `json:"workflowPath"`
}

type CheckResults struct {
	Container  string
	Go         string
	SchemaJSON string
	WindowsGo  string
}

type EvaluationRequest struct {
	Subject Subject
	Run     Run
	Checks  CheckResults
}

type EvidenceRecord struct {
	CheckID string `json:"checkId"`
	Result  string `json:"result"`
}

type RowEvaluation struct {
	Evidence   []EvidenceRecord `json:"evidence"`
	ID         string           `json:"id"`
	ReasonCode string           `json:"reasonCode"`
	Status     RowStatus        `json:"status"`
}

type Evaluation struct {
	ArtifactType     string          `json:"artifactType"`
	EvaluationDigest string          `json:"evaluationDigest"`
	FormalClaim      bool            `json:"formalClaim"`
	OverallStatus    OverallStatus   `json:"overallStatus"`
	RegistryDigest   string          `json:"registryDigest"`
	Rows             []RowEvaluation `json:"rows"`
	Run              Run             `json:"run"`
	SchemaVersion    string          `json:"schemaVersion"`
	StableEligible   bool            `json:"stableEligible"`
	Subject          Subject         `json:"subject"`
	TrustBoundary    string          `json:"trustBoundary"`
}
