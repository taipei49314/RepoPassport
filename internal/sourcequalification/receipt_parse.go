package sourcequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	receiptArtifactType       = "repopass-source-qualification-receipt"
	receiptSchemaVersion      = "1"
	receiptPredicateType      = "https://repopass.dev/source-qualification/v1"
	receiptRepositoryURL      = "https://github.com/taipei49314/RepoPassport"
	receiptModulePath         = "github.com/taipei49314/RepoPassport"
	receiptModuleVersion      = "0.1.0-alpha.33"
	receiptControllerPackage  = "github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify"
	receiptGoVersion          = "go1.26.5"
	receiptArchiveName        = "repopass-source.tar"
	receiptManifestName       = "source-archive-manifest-v1.json"
	receiptArchiveRole        = "source-payload"
	receiptManifestRole       = "source-archive-manifest"
	receiptNotApplicableValue = "NOT_APPLICABLE"
	receiptDimensionReason    = "not-evaluated-by-source-qualification"
	receiptMaxBytes           = 1 << 20
	receiptMaxDepth           = 16
	receiptMaxNodes           = 32_768
	receiptMaxStringBytes     = 4_096
	receiptMaxPlatformBytes   = 128
	receiptMaxArchiveBytes    = int64(512 << 20)
	receiptMaxManifestBytes   = int64(16 << 20)
	receiptMaxInt32           = int64(1<<31 - 1)
	receiptMinInt32           = -receiptMaxInt32 - 1
	receiptTimestampLayout    = "2006-01-02T15:04:05Z"
)

type qualificationReceipt struct {
	ArtifactType        string                   `json:"artifactType"`
	Attempt             receiptAttempt           `json:"attempt"`
	Controller          receiptController        `json:"controller"`
	Execution           receiptExecution         `json:"execution"`
	Gates               []receiptGate            `json:"gates"`
	Limitations         []string                 `json:"limitations"`
	NotApplicable       receiptNotApplicable     `json:"notApplicable"`
	Platform            receiptPlatform          `json:"platform"`
	PredicateType       string                   `json:"predicateType"`
	ProductDimensions   receiptProductDimensions `json:"productDimensions"`
	QualificationStatus QualificationStatus      `json:"qualificationStatus"`
	Run                 receiptRun               `json:"run"`
	SchemaVersion       string                   `json:"schemaVersion"`
	Source              receiptSource            `json:"source"`
	Subject             receiptSubject           `json:"subject"`
}

type receiptAttempt struct {
	AttemptID     string                `json:"attemptId"`
	FinishedAt    string                `json:"finishedAt"`
	Ordinal       int64                 `json:"ordinal"`
	PriorAttempts []receiptPriorAttempt `json:"priorAttempts"`
	RetryOf       *string               `json:"retryOf"`
	StartedAt     string                `json:"startedAt"`
}

type receiptPriorAttempt struct {
	AttemptID           string              `json:"attemptId"`
	QualificationStatus QualificationStatus `json:"qualificationStatus"`
	ReceiptSHA256       *string             `json:"receiptSHA256"`
}

type receiptController struct {
	GoVersion   string `json:"goVersion"`
	MainPackage string `json:"mainPackage"`
	ModulePath  string `json:"modulePath"`
	SHA256      string `json:"sha256"`
	VCSModified bool   `json:"vcsModified"`
	VCSRevision string `json:"vcsRevision"`
}

type receiptExecution struct {
	ManualActionCount int64 `json:"manualActionCount"`
	RawLogsPublished  bool  `json:"rawLogsPublished"`
	RetryCount        int64 `json:"retryCount"`
	SkippedGateCount  int64 `json:"skippedGateCount"`
}

type receiptGate struct {
	Argv           []string            `json:"argv"`
	Attempt        int64               `json:"attempt"`
	ExitCode       *int64              `json:"exitCode"`
	FinishedAt     *string             `json:"finishedAt"`
	ID             string              `json:"id"`
	Network        NetworkMode         `json:"network"`
	StartedAt      *string             `json:"startedAt"`
	Status         QualificationStatus `json:"status"`
	TimeoutSeconds int64               `json:"timeoutSeconds"`
}

type receiptNotApplicable struct {
	CgroupVersion          string `json:"cgroupVersion"`
	ContainerEngineVersion string `json:"containerEngineVersion"`
	EngineProviderVersion  string `json:"engineProviderVersion"`
	ImageDigests           string `json:"imageDigests"`
	ObserverSetDigest      string `json:"observerSetDigest"`
	PlanDigest             string `json:"planDigest"`
	PolicyDigest           string `json:"policyDigest"`
	RuntimeVersion         string `json:"runtimeVersion"`
	SBOMDigest             string `json:"sbomDigest"`
	SignatureDigest        string `json:"signatureDigest"`
	TrustPolicyDigest      string `json:"trustPolicyDigest"`
}

type receiptPlatform struct {
	GitVersion         string `json:"gitVersion"`
	GoVersion          string `json:"goVersion"`
	GOARCH             string `json:"goarch"`
	GOOS               string `json:"goos"`
	KernelVersion      string `json:"kernelVersion"`
	PowerShellVersion  string `json:"powerShellVersion"`
	RunnerArch         string `json:"runnerArch"`
	RunnerImage        string `json:"runnerImage"`
	RunnerImageVersion string `json:"runnerImageVersion"`
	RunnerOS           string `json:"runnerOS"`
}

type receiptDimension struct {
	EvaluationStatus string `json:"evaluationStatus"`
	Reason           string `json:"reason"`
	Value            any    `json:"value"`
}

type receiptProductDimensions struct {
	Capability      receiptDimension `json:"capability"`
	Cleanup         receiptDimension `json:"cleanup"`
	Coverage        receiptDimension `json:"coverage"`
	Evidence        receiptDimension `json:"evidence"`
	Freshness       receiptDimension `json:"freshness"`
	Functional      receiptDimension `json:"functional"`
	Overall         receiptDimension `json:"overall"`
	Reproducibility receiptDimension `json:"reproducibility"`
}

type receiptRun struct {
	Event              string `json:"event"`
	HeadSHA            string `json:"headSHA"`
	Issuer             string `json:"issuer"`
	Lane               Lane   `json:"lane"`
	QualificationRunID string `json:"qualificationRunId"`
	Ref                string `json:"ref"`
	WorkflowPath       string `json:"workflowPath"`
	WorkflowRepository string `json:"workflowRepository"`
	WorkflowRunAttempt int64  `json:"workflowRunAttempt"`
	WorkflowRunID      string `json:"workflowRunId"`
	WorkflowURL        string `json:"workflowURL"`
}

type receiptBinding struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type receiptSource struct {
	Archive  receiptBinding `json:"archive"`
	Manifest receiptBinding `json:"manifest"`
}

type receiptSubject struct {
	BaseRevision    string `json:"baseRevision"`
	Dirty           bool   `json:"dirty"`
	GitObjectFormat string `json:"gitObjectFormat"`
	ModulePath      string `json:"modulePath"`
	ModuleVersion   string `json:"moduleVersion"`
	Repository      string `json:"repository"`
	TestedRevision  string `json:"testedRevision"`
	TreeSHA         string `json:"treeSHA"`
}

func parseCanonicalReceipt(raw []byte, expectedLane Lane) (qualificationReceipt, error) {
	var result qualificationReceipt
	if expectedLane != LaneLinuxAMD64 && expectedLane != LaneWindowsAMD64 {
		return result, errors.New("source qualification receipt lane is invalid")
	}
	if len(raw) == 0 || len(raw) > receiptMaxBytes {
		return result, errors.New("source qualification receipt bytes are invalid")
	}
	value, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: receiptMaxBytes,
		MaxDepth: receiptMaxDepth,
		MaxNodes: receiptMaxNodes,
	})
	if err != nil {
		return result, errors.New("source qualification receipt JSON is invalid")
	}
	canonical, err := canonicaljson.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return result, errors.New("source qualification receipt JSON is not canonical")
	}
	if !receiptStringsWithinLimit(value) {
		return result, errors.New("source qualification receipt string exceeds its limit")
	}
	if err := validateReceiptShape(value); err != nil {
		return result, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return qualificationReceipt{}, errors.New("source qualification receipt shape is invalid")
	}
	if err := validateQualificationReceipt(result, expectedLane); err != nil {
		return qualificationReceipt{}, err
	}
	return result, nil
}

func verifyReceiptPackageBindings(archive, manifest, linuxRaw, windowsRaw []byte) error {
	linux, err := parseCanonicalReceipt(linuxRaw, LaneLinuxAMD64)
	if err != nil {
		return err
	}
	windows, err := parseCanonicalReceipt(windowsRaw, LaneWindowsAMD64)
	if err != nil {
		return err
	}
	if linux.Subject != windows.Subject ||
		withoutReceiptLane(linux.Run) != withoutReceiptLane(windows.Run) ||
		linux.Source != windows.Source {
		return errors.New("source qualification receipts do not bind the same package run")
	}
	if !receiptBindingMatches(linux.Source.Archive, archive) ||
		!receiptBindingMatches(linux.Source.Manifest, manifest) {
		return errors.New("source qualification receipt package bytes do not match")
	}
	expected := sourceSubjectFromReceipt(linux.Subject)
	if err := verifySourcePackage(archive, manifest, expected); err != nil {
		return errors.New("source qualification manifest and receipt subjects do not match")
	}
	return nil
}

func validateQualificationReceipt(receipt qualificationReceipt, expectedLane Lane) error {
	if receipt.ArtifactType != receiptArtifactType ||
		receipt.SchemaVersion != receiptSchemaVersion ||
		receipt.PredicateType != receiptPredicateType {
		return errors.New("source qualification receipt version contract is invalid")
	}
	if err := validateReceiptSubject(receipt.Subject); err != nil {
		return err
	}
	if err := validateReceiptRun(receipt.Run, receipt.Subject, expectedLane); err != nil {
		return err
	}
	if err := validateReceiptAttempt(receipt.Attempt, receipt.Run); err != nil {
		return err
	}
	if err := validateReceiptController(receipt.Controller, receipt.Subject); err != nil {
		return err
	}
	if err := validateReceiptExecution(receipt.Execution); err != nil {
		return err
	}
	if err := validateReceiptPlatform(receipt.Platform, expectedLane); err != nil {
		return err
	}
	if err := validateReceiptPrivacy(receipt.Platform); err != nil {
		return err
	}
	if err := validateReceiptSource(receipt.Source); err != nil {
		return err
	}
	if !reflect.DeepEqual(receipt.Limitations, FixedLimitations()) ||
		!validateReceiptNotApplicable(receipt.NotApplicable) ||
		!validateReceiptProductDimensions(receipt.ProductDimensions) {
		return errors.New("source qualification receipt fixed facts are invalid")
	}
	if err := validateReceiptGates(
		receipt.Gates,
		expectedLane,
		receipt.Subject.TestedRevision,
		receipt.QualificationStatus,
		receipt.Execution,
	); err != nil {
		return err
	}
	return nil
}

func sourceSubjectFromReceipt(subject receiptSubject) Subject {
	return Subject{
		BaseRevision:    subject.BaseRevision,
		Dirty:           subject.Dirty,
		GitObjectFormat: subject.GitObjectFormat,
		ModulePath:      subject.ModulePath,
		ModuleVersion:   subject.ModuleVersion,
		Repository:      subject.Repository,
		TestedRevision:  subject.TestedRevision,
		TreeSHA:         subject.TreeSHA,
	}
}

func validateReceiptPrivacy(platform receiptPlatform) error {
	values := []string{
		platform.GitVersion,
		platform.GoVersion,
		platform.GOARCH,
		platform.GOOS,
		platform.KernelVersion,
		platform.PowerShellVersion,
		platform.RunnerArch,
		platform.RunnerImage,
		platform.RunnerImageVersion,
		platform.RunnerOS,
	}
	raw, err := canonicaljson.Marshal(map[string]any{"values": values})
	if err != nil {
		return errors.New("source qualification receipt privacy input is invalid")
	}
	if _, err := privacy.Evaluate(raw); err != nil {
		return errors.New("source qualification receipt privacy policy rejected platform metadata")
	}
	return nil
}

func validateReceiptSubject(subject receiptSubject) error {
	if subject.Repository != receiptRepositoryURL ||
		subject.ModulePath != receiptModulePath ||
		subject.ModuleVersion != receiptModuleVersion ||
		subject.GitObjectFormat != "sha1" || subject.Dirty ||
		!validReceiptGitSHA1(subject.BaseRevision) ||
		!validReceiptGitSHA1(subject.TestedRevision) ||
		!validReceiptGitSHA1(subject.TreeSHA) {
		return errors.New("source qualification receipt subject is invalid")
	}
	return nil
}

func validateReceiptRun(run receiptRun, subject receiptSubject, expectedLane Lane) error {
	if run.WorkflowRepository != canonicalWorkflowRepository ||
		run.WorkflowPath != canonicalWorkflowPath ||
		run.Issuer != "NOT_ESTABLISHED" ||
		run.Lane != expectedLane || run.HeadSHA != subject.TestedRevision ||
		run.WorkflowRunAttempt < 1 || run.WorkflowRunAttempt > receiptMaxInt32 ||
		!validReceiptPositiveDecimal(run.WorkflowRunID, 20) ||
		run.WorkflowURL != receiptRepositoryURL+"/actions/runs/"+run.WorkflowRunID ||
		!validReceiptEventRef(run.Event, run.Ref) {
		return errors.New("source qualification receipt run is invalid")
	}
	identity := RunIdentity{
		WorkflowRepository: run.WorkflowRepository,
		WorkflowPath:       run.WorkflowPath,
		Event:              run.Event,
		Ref:                run.Ref,
		WorkflowRunID:      run.WorkflowRunID,
		WorkflowRunAttempt: int(run.WorkflowRunAttempt),
		TestedRevision:     subject.TestedRevision,
	}
	if run.QualificationRunID != QualificationRunID(identity) {
		return errors.New("source qualification receipt run digest is invalid")
	}
	return nil
}

func validateReceiptAttempt(attempt receiptAttempt, run receiptRun) error {
	if attempt.Ordinal < 1 || attempt.Ordinal > receiptMaxInt32 ||
		attempt.Ordinal != int64(len(attempt.PriorAttempts))+1 ||
		attempt.AttemptID != AttemptID(run.QualificationRunID, run.Lane, int(attempt.Ordinal)) {
		return errors.New("source qualification receipt attempt is invalid")
	}
	started, startedOK := parseReceiptTimestamp(attempt.StartedAt)
	finished, finishedOK := parseReceiptTimestamp(attempt.FinishedAt)
	if !startedOK || !finishedOK || finished.Before(started) {
		return errors.New("source qualification receipt attempt time is invalid")
	}
	if attempt.Ordinal == 1 {
		if attempt.RetryOf != nil {
			return errors.New("source qualification receipt retry binding is invalid")
		}
	} else if attempt.RetryOf == nil ||
		*attempt.RetryOf != attempt.PriorAttempts[len(attempt.PriorAttempts)-1].AttemptID {
		return errors.New("source qualification receipt retry binding is invalid")
	}
	seen := make(map[string]struct{}, len(attempt.PriorAttempts))
	for index, prior := range attempt.PriorAttempts {
		if prior.QualificationStatus != StatusFail &&
			prior.QualificationStatus != StatusBlocked &&
			prior.QualificationStatus != StatusNotRun {
			return errors.New("source qualification receipt prior attempt status is invalid")
		}
		if !validReceiptAttemptID(prior.AttemptID, run.Lane, int64(index+1)) {
			return errors.New("source qualification receipt prior attempt ID is invalid")
		}
		if _, duplicate := seen[prior.AttemptID]; duplicate {
			return errors.New("source qualification receipt prior attempt is duplicated")
		}
		seen[prior.AttemptID] = struct{}{}
		if prior.ReceiptSHA256 != nil && !validReceiptSHA256(*prior.ReceiptSHA256) {
			return errors.New("source qualification receipt prior digest is invalid")
		}
	}
	return nil
}

func validateReceiptController(controller receiptController, subject receiptSubject) error {
	if controller.GoVersion != receiptGoVersion ||
		controller.MainPackage != receiptControllerPackage ||
		controller.ModulePath != receiptModulePath ||
		!validReceiptSHA256(controller.SHA256) || controller.VCSModified ||
		controller.VCSRevision != subject.TestedRevision {
		return errors.New("source qualification receipt controller is invalid")
	}
	return nil
}

func validateReceiptExecution(execution receiptExecution) error {
	for _, count := range []int64{
		execution.ManualActionCount,
		execution.RetryCount,
		execution.SkippedGateCount,
	} {
		if count < 0 || count > receiptMaxInt32 {
			return errors.New("source qualification receipt execution count is invalid")
		}
	}
	return nil
}

func validateReceiptPlatform(platform receiptPlatform, lane Lane) error {
	values := []string{
		platform.GitVersion,
		platform.GoVersion,
		platform.GOARCH,
		platform.GOOS,
		platform.KernelVersion,
		platform.PowerShellVersion,
		platform.RunnerArch,
		platform.RunnerImage,
		platform.RunnerImageVersion,
		platform.RunnerOS,
	}
	for _, value := range values {
		if !validReceiptPrintableASCII(value, receiptMaxPlatformBytes) {
			return errors.New("source qualification receipt platform fact is invalid")
		}
	}
	if platform.GoVersion != receiptGoVersion || platform.GOARCH != "amd64" ||
		platform.RunnerArch != "X64" {
		return errors.New("source qualification receipt platform identity is invalid")
	}
	switch lane {
	case LaneLinuxAMD64:
		if platform.GOOS != "linux" || platform.RunnerOS != "Linux" {
			return errors.New("source qualification receipt Linux platform is invalid")
		}
	case LaneWindowsAMD64:
		if platform.GOOS != "windows" || platform.RunnerOS != "Windows" {
			return errors.New("source qualification receipt Windows platform is invalid")
		}
	default:
		return errors.New("source qualification receipt platform lane is invalid")
	}
	return nil
}

func validateReceiptSource(source receiptSource) error {
	if source.Archive.Name != receiptArchiveName ||
		source.Archive.Role != receiptArchiveRole ||
		source.Archive.Size < 0 || source.Archive.Size > receiptMaxArchiveBytes ||
		!validReceiptSHA256(source.Archive.SHA256) ||
		source.Manifest.Name != receiptManifestName ||
		source.Manifest.Role != receiptManifestRole ||
		source.Manifest.Size <= 0 || source.Manifest.Size > receiptMaxManifestBytes ||
		!validReceiptSHA256(source.Manifest.SHA256) {
		return errors.New("source qualification receipt source binding is invalid")
	}
	return nil
}

func validateReceiptNotApplicable(value receiptNotApplicable) bool {
	for _, current := range []string{
		value.CgroupVersion,
		value.ContainerEngineVersion,
		value.EngineProviderVersion,
		value.ImageDigests,
		value.ObserverSetDigest,
		value.PlanDigest,
		value.PolicyDigest,
		value.RuntimeVersion,
		value.SBOMDigest,
		value.SignatureDigest,
		value.TrustPolicyDigest,
	} {
		if current != receiptNotApplicableValue {
			return false
		}
	}
	return true
}

func validateReceiptProductDimensions(value receiptProductDimensions) bool {
	for _, current := range []receiptDimension{
		value.Capability,
		value.Cleanup,
		value.Coverage,
		value.Evidence,
		value.Freshness,
		value.Functional,
		value.Overall,
		value.Reproducibility,
	} {
		if current.EvaluationStatus != string(StatusNotRun) ||
			current.Reason != receiptDimensionReason || current.Value != nil {
			return false
		}
	}
	return true
}

func validateReceiptGates(
	gates []receiptGate,
	lane Lane,
	testedRevision string,
	status QualificationStatus,
	execution receiptExecution,
) error {
	registry := RequiredGates(lane)
	if len(gates) != len(registry) {
		return errors.New("source qualification receipt gate count is invalid")
	}
	statuses := make([]QualificationStatus, len(gates))
	terminated := false
	skipped := int64(0)
	for index, gate := range gates {
		specification := registry[index]
		if gate.ID != specification.ID ||
			!reflect.DeepEqual(gate.Argv, receiptGateArgv(specification, testedRevision)) ||
			gate.TimeoutSeconds != int64(specification.TimeoutSeconds) ||
			gate.Network != specification.Network || gate.Attempt != 1 {
			return errors.New("source qualification receipt gate registry is invalid")
		}
		if terminated && gate.Status != StatusNotRun {
			return errors.New("source qualification receipt gate sequence is invalid")
		}
		if err := validateReceiptGateOutcome(gate); err != nil {
			return err
		}
		if gate.Status == StatusFail || gate.Status == StatusBlocked {
			terminated = true
		}
		if gate.Status == StatusNotRun {
			skipped++
		}
		statuses[index] = gate.Status
	}
	if status != AggregateQualificationStatus(statuses) || execution.SkippedGateCount != skipped {
		return errors.New("source qualification receipt gate aggregate is invalid")
	}
	return nil
}

func receiptGateArgv(specification GateSpec, testedRevision string) []string {
	result := append([]string(nil), specification.Argv...)
	for index, token := range result {
		if token == "{testedRevision}" {
			result[index] = testedRevision
		}
	}
	return result
}

func validateReceiptGateOutcome(gate receiptGate) error {
	if gate.ExitCode != nil && (*gate.ExitCode < receiptMinInt32 || *gate.ExitCode > receiptMaxInt32) {
		return errors.New("source qualification receipt gate exit code is invalid")
	}
	switch gate.Status {
	case StatusPass:
		if gate.ExitCode == nil || *gate.ExitCode != 0 || !validReceiptGateTimes(gate) {
			return errors.New("source qualification receipt PASS gate is invalid")
		}
	case StatusFail:
		if !validReceiptGateTimes(gate) {
			return errors.New("source qualification receipt FAIL gate is invalid")
		}
	case StatusBlocked:
		if gate.ExitCode != nil || !validReceiptGateTimes(gate) {
			return errors.New("source qualification receipt BLOCKED gate is invalid")
		}
	case StatusNotRun:
		if gate.ExitCode != nil || gate.StartedAt != nil || gate.FinishedAt != nil {
			return errors.New("source qualification receipt NOT_RUN gate is invalid")
		}
	default:
		return errors.New("source qualification receipt gate status is invalid")
	}
	return nil
}

func validReceiptGateTimes(gate receiptGate) bool {
	if gate.StartedAt == nil || gate.FinishedAt == nil {
		return false
	}
	started, startedOK := parseReceiptTimestamp(*gate.StartedAt)
	finished, finishedOK := parseReceiptTimestamp(*gate.FinishedAt)
	return startedOK && finishedOK && !finished.Before(started)
}

func validateReceiptShape(value any) error {
	root, ok := value.(map[string]any)
	if !ok || !hasExactReceiptKeys(root, ReceiptTopLevelKeys()) {
		return errors.New("source qualification receipt top-level shape is invalid")
	}
	objects := []struct {
		key  string
		keys []string
	}{
		{"attempt", []string{"attemptId", "finishedAt", "ordinal", "priorAttempts", "retryOf", "startedAt"}},
		{"controller", []string{"goVersion", "mainPackage", "modulePath", "sha256", "vcsModified", "vcsRevision"}},
		{"execution", []string{"manualActionCount", "rawLogsPublished", "retryCount", "skippedGateCount"}},
		{"notApplicable", []string{"cgroupVersion", "containerEngineVersion", "engineProviderVersion", "imageDigests", "observerSetDigest", "planDigest", "policyDigest", "runtimeVersion", "sbomDigest", "signatureDigest", "trustPolicyDigest"}},
		{"platform", []string{"gitVersion", "goVersion", "goarch", "goos", "kernelVersion", "powerShellVersion", "runnerArch", "runnerImage", "runnerImageVersion", "runnerOS"}},
		{"productDimensions", []string{"capability", "cleanup", "coverage", "evidence", "freshness", "functional", "overall", "reproducibility"}},
		{"run", []string{"event", "headSHA", "issuer", "lane", "qualificationRunId", "ref", "workflowPath", "workflowRepository", "workflowRunAttempt", "workflowRunId", "workflowURL"}},
		{"source", []string{"archive", "manifest"}},
		{"subject", []string{"baseRevision", "dirty", "gitObjectFormat", "modulePath", "moduleVersion", "repository", "testedRevision", "treeSHA"}},
	}
	for _, expected := range objects {
		object, ok := root[expected.key].(map[string]any)
		if !ok || !hasExactReceiptKeys(object, expected.keys) {
			return errors.New("source qualification receipt nested shape is invalid")
		}
	}

	attempt := root["attempt"].(map[string]any)
	priorAttempts, ok := attempt["priorAttempts"].([]any)
	if !ok {
		return errors.New("source qualification receipt attempt history shape is invalid")
	}
	for _, value := range priorAttempts {
		entry, ok := value.(map[string]any)
		if !ok || !hasExactReceiptKeys(entry, []string{"attemptId", "qualificationStatus", "receiptSHA256"}) {
			return errors.New("source qualification receipt prior attempt shape is invalid")
		}
	}

	gates, ok := root["gates"].([]any)
	if !ok {
		return errors.New("source qualification receipt gates shape is invalid")
	}
	for _, value := range gates {
		gate, ok := value.(map[string]any)
		if !ok || !hasExactReceiptKeys(gate, []string{"argv", "attempt", "exitCode", "finishedAt", "id", "network", "startedAt", "status", "timeoutSeconds"}) {
			return errors.New("source qualification receipt gate shape is invalid")
		}
	}

	dimensions := root["productDimensions"].(map[string]any)
	for _, key := range []string{"capability", "cleanup", "coverage", "evidence", "freshness", "functional", "overall", "reproducibility"} {
		dimension, ok := dimensions[key].(map[string]any)
		if !ok || !hasExactReceiptKeys(dimension, []string{"evaluationStatus", "reason", "value"}) {
			return errors.New("source qualification receipt dimension shape is invalid")
		}
	}

	source := root["source"].(map[string]any)
	for _, key := range []string{"archive", "manifest"} {
		binding, ok := source[key].(map[string]any)
		if !ok || !hasExactReceiptKeys(binding, []string{"name", "role", "sha256", "size"}) {
			return errors.New("source qualification receipt source shape is invalid")
		}
	}
	if _, ok := root["limitations"].([]any); !ok {
		return errors.New("source qualification receipt limitations shape is invalid")
	}
	return nil
}

func hasExactReceiptKeys(object map[string]any, expected []string) bool {
	if len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	return true
}

func receiptStringsWithinLimit(value any) bool {
	switch typed := value.(type) {
	case string:
		return len(typed) <= receiptMaxStringBytes
	case map[string]any:
		for key, child := range typed {
			if len(key) > receiptMaxStringBytes || !receiptStringsWithinLimit(child) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !receiptStringsWithinLimit(child) {
				return false
			}
		}
	}
	return true
}

func validReceiptEventRef(event, ref string) bool {
	switch event {
	case "push":
		return ref == canonicalMainRef
	case "pull_request":
		const prefix = "refs/pull/"
		const suffix = "/merge"
		return len(ref) > len(prefix)+len(suffix) &&
			strings.HasPrefix(ref, prefix) && strings.HasSuffix(ref, suffix) &&
			validReceiptPositiveDecimal(ref[len(prefix):len(ref)-len(suffix)], receiptMaxStringBytes)
	case "workflow_dispatch":
		const prefix = "refs/heads/"
		return len(ref) <= 255 && strings.HasPrefix(ref, prefix) && len(ref) > len(prefix) &&
			validReceiptPrintableASCII(ref, 255)
	default:
		return false
	}
}

func validReceiptPositiveDecimal(value string, maxDigits int) bool {
	if len(value) == 0 || len(value) > maxDigits || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validReceiptAttemptID(value string, lane Lane, ordinal int64) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 4 || parts[0] != "sha256" || len(parts[1]) != sha256.Size*2 ||
		parts[2] != string(lane) || parts[3] != strconv.FormatInt(ordinal, 10) {
		return false
	}
	for _, current := range parts[1] {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

func validReceiptGitSHA1(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

func validReceiptSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, current := range value[len("sha256:"):] {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

func validReceiptPrintableASCII(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, current := range []byte(value) {
		if current < 0x20 || current > 0x7e {
			return false
		}
	}
	return true
}

func parseReceiptTimestamp(value string) (time.Time, bool) {
	if len(value) != len(receiptTimestampLayout) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(receiptTimestampLayout, value)
	if err != nil || parsed.Format(receiptTimestampLayout) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func withoutReceiptLane(run receiptRun) receiptRun {
	run.Lane = ""
	return run
}

func receiptBindingMatches(binding receiptBinding, value []byte) bool {
	if binding.Size != int64(len(value)) {
		return false
	}
	digest := sha256.Sum256(value)
	return binding.SHA256 == "sha256:"+hex.EncodeToString(digest[:])
}
