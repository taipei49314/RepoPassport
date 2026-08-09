package schemas_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/taipei49314/RepoPassport/internal/cli"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/manifest"
	"github.com/taipei49314/RepoPassport/internal/privacy"
	schemavalidator "github.com/taipei49314/RepoPassport/schemas"
)

func TestPrivacyBlockedErrorMatchesPublicErrorSchema(t *testing.T) {
	schemas := compilePublicSchemas(t)
	_, err := privacy.Evaluate([]byte(`{"message":"synthetic.user@example.invalid"}`))
	if err == nil {
		t.Fatal("privacy attack passed")
	}
	raw, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	validateJSON(t, schemas["error.schema.json"], raw)
	if bytes.Contains(raw, []byte("synthetic.user@example.invalid")) {
		t.Fatalf("privacy error echoed blocked input: %s", raw)
	}
}

func TestRetainedFilesystemComparisonSchemasAreStrictAndPrivate(
	t *testing.T,
) {
	schemas := compilePublicSchemas(t)
	completedAt := time.Date(2026, time.August, 2, 4, 5, 6, 0, time.UTC)
	complete := domain.ObservationEvent{
		SchemaVersion: "1",
		Sequence:      1,
		Timestamp:     completedAt,
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "filesystem.retained-state.summary",
		Resource:      "redacted-container",
		Result:        "observed",
		Observer:      "docker-filesystem-retained-state",
		Coverage:      "high",
		Confidence:    "high",
		Details: map[string]any{
			"scope":                            "outputs-retained-state",
			"snapshotBoundary":                 "post-init-pre-workload-to-post-quiesce-pre-repair",
			"includesTrustedHelpers":           true,
			"includesRunnerManagedDirectories": true,
			"contentIncluded":                  false,
			"publicEvidence":                   "aggregate-only",
			"actorAttribution":                 "unavailable",
			"baselineIdentityVerified":         true,
			"finalIdentityVerified":            true,
			"workloadQuiescenceVerified":       true,
			"baselineReady":                    true,
			"finalReady":                       true,
			"retainedStateCoverage":            "high",
			"baselineDigest": "sha256:" +
				strings.Repeat("a", 64),
			"baselineEntryCount": 0,
			"finalDigest": "sha256:" +
				strings.Repeat("b", 64),
			"finalEntryCount":              2,
			"changeCount":                  2,
			"declarationComparisonScope":   "executed-phase-filesystem-write-union",
			"declarationComparisonVersion": "0.1.0",
			"declarationComparisonResult":  "nonconforming-retained-state",
			"declaredPatternCount":         1,
			"comparedChangeCount":          2,
			"allowedChangeCount":           1,
			"undeclaredChangeCount":        1,
			"createChangeCount":            2,
			"deleteChangeCount":            0,
			"modifyChangeCount":            0,
			"typeChangeCount":              0,
			"blindSpots": []string{
				"outside-outputs",
				"transient-create-delete",
				"operation-time",
			},
		},
	}
	notTested := domain.ObservationEvent{
		SchemaVersion: "1",
		Sequence:      2,
		Timestamp:     completedAt.Add(time.Second),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "filesystem.retained-state.summary",
		Resource:      "redacted-container",
		Result:        "unavailable",
		Observer:      "docker-filesystem-retained-state",
		Coverage:      "unavailable",
		Confidence:    "unknown",
		Details: map[string]any{
			"scope":                            "outputs-retained-state",
			"snapshotBoundary":                 "post-init-pre-workload-to-post-quiesce-pre-repair",
			"includesTrustedHelpers":           true,
			"includesRunnerManagedDirectories": true,
			"contentIncluded":                  false,
			"publicEvidence":                   "aggregate-only",
			"actorAttribution":                 "unavailable",
			"baselineIdentityVerified":         false,
			"finalIdentityVerified":            false,
			"workloadQuiescenceVerified":       false,
			"baselineReady":                    false,
			"finalReady":                       false,
			"retainedStateCoverage":            "unavailable",
			"declarationComparisonScope":       "executed-phase-filesystem-write-union",
			"declarationComparisonVersion":     "0.1.0",
			"declarationComparisonResult":      "not-tested",
			"declarationComparisonFailure":     "retained-state-prerequisite-unavailable",
			"blindSpots": []string{
				"outside-outputs",
				"transient-create-delete",
			},
		},
	}
	finding := domain.NewError(
		domain.CodeUndeclaredFilesystemWrite,
		domain.SeverityHigh,
		"Bounded retained output state contains changes outside every filesystem.write declaration granted during this run.",
	)
	finding.Details = map[string]any{
		"comparisonScope":          "executed-phase-filesystem-write-union",
		"comparisonVersion":        "0.1.0",
		"declaredPatternCount":     1,
		"comparedChangeCount":      2,
		"allowedChangeCount":       1,
		"undeclaredChangeCount":    1,
		"evidenceBasis":            "bounded-retained-state-delta",
		"operationHistoryCoverage": "unavailable",
		"actorAttribution":         "unavailable",
		"phaseAttribution":         "unavailable",
	}

	for _, test := range []struct {
		name              string
		value             any
		schema            *jsonschema.Schema
		privacyCollection string
	}{
		{
			name:              "complete retained comparison",
			value:             complete,
			schema:            schemas["observation.schema.json"],
			privacyCollection: "observations",
		},
		{
			name:              "not-tested retained comparison",
			value:             notTested,
			schema:            schemas["observation.schema.json"],
			privacyCollection: "observations",
		},
		{
			name:              "aggregate undeclared write finding",
			value:             finding,
			schema:            schemas["error.schema.json"],
			privacyCollection: "errors",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			validateJSON(t, test.schema, raw)
			privacyRaw, err := json.Marshal(map[string]any{
				test.privacyCollection: []any{test.value},
			})
			if err != nil {
				t.Fatalf("marshal privacy envelope: %v", err)
			}
			if _, err := privacy.Evaluate(privacyRaw); err != nil {
				t.Fatalf("valid aggregate evidence failed privacy: %v", err)
			}
		})
	}

	const rawMarker = "/outputs/RAW-ALPHA23-UNDECLARED-PATH-MARKER"
	for _, test := range []struct {
		name              string
		value             any
		schema            *jsonschema.Schema
		privacyCollection string
	}{
		{
			name:              "observation raw path",
			value:             complete,
			schema:            schemas["observation.schema.json"],
			privacyCollection: "observations",
		},
		{
			name:              "finding raw path",
			value:             finding,
			schema:            schemas["error.schema.json"],
			privacyCollection: "errors",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			unsafe := marshalJSONMap(t, test.value)
			details := rawMap(t, unsafe["details"])
			details["rawPath"] = rawMarker
			raw, err := json.Marshal(unsafe)
			if err != nil {
				t.Fatalf("marshal raw path injection: %v", err)
			}
			validateJSON(t, test.schema, raw)
			privacyRaw, err := json.Marshal(map[string]any{
				test.privacyCollection: []any{unsafe},
			})
			if err != nil {
				t.Fatalf("marshal privacy envelope: %v", err)
			}
			_, privacyErr := privacy.Evaluate(privacyRaw)
			if privacyErr == nil {
				t.Fatal("privacy gate accepted a raw path detail")
			}
			if strings.Contains(privacyErr.Error(), rawMarker) ||
				strings.Contains(privacyErr.Error(), "RAW-ALPHA23") {
				t.Fatalf("privacy error echoed raw path: %v", privacyErr)
			}

			nested := cloneJSONMap(t, unsafe)
			rawMap(t, nested["details"])["rawPath"] = map[string]any{
				"value": rawMarker,
			}
			assertSchemaRejects(
				t,
				test.schema,
				nested,
				test.name+" nested detail",
			)
		})
	}
}

func TestPortListenerComparisonSchemasAreAggregateOnlyAndPrivate(t *testing.T) {
	schemas := compilePublicSchemas(t)
	completedAt := time.Date(2026, time.August, 3, 0, 0, 0, 0, time.UTC)
	completeDetails := alpha25PortListenerSummaryDetails(
		"nonconforming-listeners",
	)
	completeDetails["baselineEndpointCount"] = 0
	completeDetails["declaredEndpointCount"] = 1
	completeDetails["sampledEndpointCount"] = 2
	completeDetails["undeclaredEndpointCount"] = 1
	complete := domain.ObservationEvent{
		SchemaVersion: "1", Sequence: 1, Timestamp: completedAt,
		Phase: domain.PhaseCleanup, Actor: "trusted-runner",
		Operation: "port.listener-trace.summary", Resource: "tcp-listeners",
		Result: "observed", Observer: "docker-peer-port-listener-trace",
		Coverage: "best-effort", Confidence: "high",
		Details: completeDetails,
	}
	notTested := domain.ObservationEvent{
		SchemaVersion: "1", Sequence: 2, Timestamp: completedAt.Add(time.Second),
		Phase: domain.PhaseCleanup, Actor: "trusted-runner",
		Operation: "port.listener-trace.summary", Resource: "tcp-listeners",
		Result: "unavailable", Observer: "docker-peer-port-listener-trace",
		Coverage: "unavailable", Confidence: "unknown",
		Details: alpha25PortListenerSummaryDetails("not-tested"),
	}
	finding := domain.NewError(
		domain.CodeUndeclaredPortListen,
		domain.SeverityHigh,
		"Bounded peer TCP samples observed one or more listeners outside the declared service endpoint.",
	)
	finding.Details = map[string]any{
		"observer":                "docker-peer-port-listener-trace",
		"evidenceBasis":           "aggregate-only",
		"undeclaredEndpointCount": 1,
	}

	for _, test := range []struct {
		name              string
		value             any
		schema            *jsonschema.Schema
		privacyCollection string
	}{
		{"complete aggregate comparison", complete, schemas["observation.schema.json"], "observations"},
		{"not-tested aggregate comparison", notTested, schemas["observation.schema.json"], "observations"},
		{"aggregate undeclared listener finding", finding, schemas["error.schema.json"], "errors"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			validateJSON(t, test.schema, raw)
			privacyRaw, err := json.Marshal(map[string]any{
				test.privacyCollection: []any{test.value},
			})
			if err != nil {
				t.Fatalf("marshal privacy envelope: %v", err)
			}
			if _, err := privacy.Evaluate(privacyRaw); err != nil {
				t.Fatalf("valid aggregate port evidence failed privacy: %v", err)
			}
		})
	}

	assertPortListenerAggregateDetails(t, complete.Details, true)
	assertPortListenerAggregateDetails(t, notTested.Details, false)
	unsafe := cloneJSONMap(t, complete.Details)
	unsafe["endpoint"] = "127.0.0.1:43123/tcp"
	if portListenerAggregateDetails(unsafe, true) {
		t.Fatal("raw endpoint detail was accepted by the Alpha.25 public contract")
	}
}

func assertPortListenerAggregateDetails(
	t *testing.T,
	details map[string]any,
	complete bool,
) {
	t.Helper()
	if !portListenerAggregateDetails(details, complete) {
		t.Fatalf("invalid aggregate port-listener details: %#v", details)
	}
}

func portListenerAggregateDetails(details map[string]any, complete bool) bool {
	keys := []string{
		"observerPlacement", "sharesTargetPIDNamespace",
		"sharesTargetMountNamespace", "sharesTargetIPCNamespace",
		"sharesTargetCgroup", "processAttribution", "lifetimeSemantics",
		"kernelEventCoverage", "shortLivedListenerGap", "udpUnavailable",
		"publicEvidence", "evidenceBasis", "comparisonResult", "sampleLimit",
		"intervalMillis", "maxAllowedGapMillis", "identityVerified",
		"namespaceIsolationVerified", "workloadQuiescenceVerified",
		"peerRemoveVerified", "canonicalDigestSemantics",
	}
	if complete {
		keys = append(keys,
			"observerAdapter", "baselineEndpointCount", "declaredEndpointCount",
			"sampledEndpointCount", "undeclaredEndpointCount", "sampleCount",
			"maxSampleGapMillis", "transitionCount", "canonicalSampleDigest",
		)
	}
	if len(details) != len(keys) ||
		details["observerPlacement"] !=
			"peer-container-shared-network-namespace" ||
		details["processAttribution"] != "unavailable" ||
		details["lifetimeSemantics"] != "sample-window-only" ||
		details["kernelEventCoverage"] != "unavailable" ||
		details["shortLivedListenerGap"] != true ||
		details["udpUnavailable"] != true ||
		details["publicEvidence"] != "aggregate-only" ||
		details["evidenceBasis"] != "aggregate-only" ||
		details["sampleLimit"] != 1200 ||
		details["intervalMillis"] != 100 ||
		details["maxAllowedGapMillis"] != 1000 ||
		details["canonicalDigestSemantics"] !=
			"helper-commitment-not-controller-recomputed" {
		return false
	}
	for _, key := range keys {
		if _, ok := details[key]; !ok {
			return false
		}
	}
	for _, key := range []string{
		"sharesTargetPIDNamespace", "sharesTargetMountNamespace",
		"sharesTargetIPCNamespace", "sharesTargetCgroup", "identityVerified",
		"namespaceIsolationVerified", "workloadQuiescenceVerified",
		"peerRemoveVerified",
	} {
		if _, ok := details[key].(bool); !ok {
			return false
		}
	}
	if !complete {
		return details["comparisonResult"] == "not-tested"
	}
	comparison, ok := details["comparisonResult"].(string)
	if !ok || (comparison != "nonconforming-listeners" &&
		comparison != "no-undeclared-observed") {
		return false
	}
	baseline, baselineOK := details["baselineEndpointCount"].(int)
	declared, declaredOK := details["declaredEndpointCount"].(int)
	sampled, sampledOK := details["sampledEndpointCount"].(int)
	undeclared, undeclaredOK := details["undeclaredEndpointCount"].(int)
	if !baselineOK || !declaredOK || !sampledOK || !undeclaredOK ||
		baseline != 0 || declared != 1 || sampled < 1 || sampled > 16 ||
		undeclared < 0 || undeclared > 15 || sampled != declared+undeclared {
		return false
	}
	if details["observerAdapter"] != "node-proc-net-tcp-linux" ||
		details["sampleCount"] != 3 ||
		details["maxSampleGapMillis"] != 100 ||
		details["transitionCount"] != 2 ||
		details["canonicalSampleDigest"] !=
			"sha256:"+strings.Repeat("d", 64) {
		return false
	}
	return comparison == "nonconforming-listeners" && undeclared > 0 ||
		comparison == "no-undeclared-observed" && undeclared == 0
}

func alpha25PortListenerSummaryDetails(comparison string) map[string]any {
	details := map[string]any{
		"observerPlacement":          "peer-container-shared-network-namespace",
		"sharesTargetPIDNamespace":   false,
		"sharesTargetMountNamespace": false,
		"sharesTargetIPCNamespace":   false,
		"sharesTargetCgroup":         false,
		"processAttribution":         "unavailable",
		"lifetimeSemantics":          "sample-window-only",
		"kernelEventCoverage":        "unavailable",
		"shortLivedListenerGap":      true,
		"udpUnavailable":             true,
		"publicEvidence":             "aggregate-only",
		"evidenceBasis":              "aggregate-only",
		"comparisonResult":           comparison,
		"sampleLimit":                1200,
		"intervalMillis":             100,
		"maxAllowedGapMillis":        1000,
		"identityVerified":           true,
		"namespaceIsolationVerified": true,
		"workloadQuiescenceVerified": true,
		"peerRemoveVerified":         true,
		"canonicalDigestSemantics":   "helper-commitment-not-controller-recomputed",
	}
	if comparison != "not-tested" {
		details["observerAdapter"] = "node-proc-net-tcp-linux"
		details["sampleCount"] = 3
		details["maxSampleGapMillis"] = 100
		details["transitionCount"] = 2
		details["canonicalSampleDigest"] = "sha256:" + strings.Repeat("d", 64)
	}
	return details
}

func TestOperationNotificationComparisonSchemasAreStrictAndPrivate(
	t *testing.T,
) {
	schemas := compilePublicSchemas(t)
	completedAt := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	baseDetails := map[string]any{
		"scope":                          "outputs-operation-notification-comparison",
		"publicEvidence":                 "aggregate-only",
		"rawPathIncluded":                false,
		"ruleTextIncluded":               false,
		"contentIncluded":                false,
		"actorAttribution":               "unavailable",
		"renamePairing":                  "unavailable",
		"preDispatchQuiescenceVerified":  true,
		"postDispatchQuiescenceVerified": true,
		"phaseAcknowledgementsComplete":  true,
		"notificationLimit":              4096,
		"ruleLimitPerWindow":             256,
		"windowLimit":                    128,
		"evidenceBasis":                  "aggregate-only",
		"blindSpots": []string{
			"outside-outputs", "read-and-syscall-history",
			"actor-and-process-attribution", "rename-pairing",
			"inotify-coalescing", "new-directory-watch-race",
		},
	}
	completeDetails := cloneJSONMap(t, baseDetails)
	completeDetails["comparisonResult"] = "nonconforming-notifications"
	completeDetails["windowCount"] = 1
	completeDetails["quiescenceWindowCount"] = 1
	completeDetails["declaredPatternCount"] = 1
	completeDetails["comparedNotificationCount"] = 2
	completeDetails["allowedNotificationCount"] = 1
	completeDetails["undeclaredNotificationCount"] = 1
	completeDetails["mutationCounts"] = []string{
		"create=1", "delete=0", "write=1", "rename=0", "metadata=0",
	}
	complete := domain.ObservationEvent{
		SchemaVersion: "1", Sequence: 1, Timestamp: completedAt,
		Phase: domain.PhaseCleanup, Actor: "trusted-runner",
		Operation: "filesystem.operation-notification.summary", Resource: "/outputs",
		Result: "observed", Observer: "docker-python-outputs-inotify-comparison",
		Coverage: "best-effort", Confidence: "high", Details: completeDetails,
	}
	unavailableDetails := cloneJSONMap(t, baseDetails)
	unavailableDetails["comparisonResult"] = "not-tested"
	unavailableDetails["failure"] = "unsupported-runtime-adapter"
	unavailable := domain.ObservationEvent{
		SchemaVersion: "1", Sequence: 2, Timestamp: completedAt.Add(time.Second),
		Phase: domain.PhaseCleanup, Actor: "trusted-runner",
		Operation: "filesystem.operation-notification.summary", Resource: "/outputs",
		Result: "unavailable", Observer: "docker-python-outputs-inotify-comparison",
		Coverage: "unavailable", Confidence: "unknown", Details: unavailableDetails,
	}
	for _, test := range []struct {
		name  string
		value domain.ObservationEvent
	}{
		{"complete aggregate operation notification", complete},
		{"unavailable aggregate operation notification", unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			validateJSON(t, schemas["observation.schema.json"], raw)
			if _, err := privacy.Evaluate([]byte(`{"observations":[` + string(raw) + `]}`)); err != nil {
				t.Fatalf("valid aggregate evidence failed privacy: %v", err)
			}
		})
	}

	for _, injection := range []struct {
		name  string
		key   string
		value string
	}{
		{"raw path", "rawPath", "/outputs/RAW-ALPHA24-OPERATION-PATH-MARKER"},
		{"rule text", "ruleText", "/home/RAW-ALPHA24-RULE-MARKER/**"},
		{"session token", "sessionToken", "RAW-ALPHA24-TOKEN-MARKER"},
	} {
		t.Run("privacy blocks "+injection.name, func(t *testing.T) {
			unsafe := marshalJSONMap(t, complete)
			rawMap(t, unsafe["details"])[injection.key] = injection.value
			raw, err := json.Marshal(unsafe)
			if err != nil {
				t.Fatalf("marshal unsafe observation: %v", err)
			}
			validateJSON(t, schemas["observation.schema.json"], raw)
			_, privacyErr := privacy.Evaluate(
				[]byte(`{"observations":[` + string(raw) + `]}`),
			)
			if privacyErr == nil {
				t.Fatalf("privacy accepted %s", injection.name)
			}
			if strings.Contains(privacyErr.Error(), injection.value) ||
				strings.Contains(privacyErr.Error(), "RAW-ALPHA24") {
				t.Fatalf("privacy error echoed %s: %v", injection.name, privacyErr)
			}
		})
	}

	nested := marshalJSONMap(t, complete)
	rawMap(t, nested["details"])["rawPath"] = map[string]any{
		"value": "/outputs/RAW-ALPHA24-NESTED-MARKER",
	}
	assertSchemaRejects(
		t,
		schemas["observation.schema.json"],
		nested,
		"operation notification nested raw path",
	)
}

const schemaBaseURL = "https://schemas.repopass.dev/v1alpha1/"

type emittedEnvelope struct {
	SchemaVersion string          `json:"schemaVersion"`
	Command       string          `json:"command"`
	Status        string          `json:"status"`
	Data          json.RawMessage `json:"data"`
	Error         *domain.Error   `json:"error"`
}

type emittedVerification struct {
	Verification json.RawMessage `json:"verification"`
}

func TestHealthyManifestsMatchPublicSchema(t *testing.T) {
	schemas := compilePublicSchemas(t)
	for _, fixture := range []string{"healthy-node-cli", "healthy-python-http"} {
		t.Run(fixture, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join(
				"..", "testdata", "fixtures", "healthy", fixture, "repo-passport.yml",
			))
			if err != nil {
				t.Fatalf("resolve fixture manifest: %v", err)
			}
			document, err := manifest.Load(path)
			if err != nil {
				t.Fatalf("load manifest: %v", err)
			}
			if findings := manifest.Validate(document); len(findings) != 0 {
				t.Fatalf("semantic validation findings: %v", findings)
			}
			raw, err := json.Marshal(document.Raw)
			if err != nil {
				t.Fatalf("marshal normalized manifest: %v", err)
			}
			validateJSON(t, schemas["repo-passport.schema.json"], raw)
		})
	}
}

func TestCLIEmittedArtifactsMatchPublicSchemas(t *testing.T) {
	schemas := compilePublicSchemas(t)
	manifestPath := healthyManifest(t)

	planEnvelope := runCLI(t, cli.Dependencies{}, "--json", "plan", "--manifest", manifestPath)
	var planData struct {
		Plan json.RawMessage `json:"plan"`
	}
	decodeJSON(t, planEnvelope.Data, &planData)
	validateJSON(t, schemas["resolved-plan.schema.json"], planData.Plan)
	var emittedPlan struct {
		SchemaVersion          string             `json:"schemaVersion"`
		RequiredRunnerFeatures []string           `json:"requiredRunnerFeatures"`
		Cleanup                domain.PlanCleanup `json:"cleanup"`
	}
	decodeJSON(t, planData.Plan, &emittedPlan)
	if emittedPlan.SchemaVersion != "4" {
		t.Fatalf(
			"resolved plan schemaVersion = %q, want 4",
			emittedPlan.SchemaVersion,
		)
	}
	if emittedPlan.Cleanup.ClassifierVersion != "0.1.0" ||
		len(emittedPlan.Cleanup.AllowedResidue) != 1 ||
		emittedPlan.Cleanup.AllowedResidue[0] != "/outputs/**" {
		t.Fatalf("resolved plan cleanup = %#v", emittedPlan.Cleanup)
	}
	for _, version := range []string{"1", "2"} {
		legacyPlan := map[string]any{}
		decodeJSON(t, planData.Plan, &legacyPlan)
		legacyPlan["schemaVersion"] = version
		assertSchemaRejects(
			t,
			schemas["resolved-plan.schema.json"],
			legacyPlan,
			"resolved plan schemaVersion "+version,
		)
	}
	var staleCLIDriver map[string]any
	decodeJSON(t, planData.Plan, &staleCLIDriver)
	staleCLIDriver["journeyDriverVersion"] = "0.1.0"
	assertSchemaRejects(
		t,
		schemas["resolved-plan.schema.json"],
		staleCLIDriver,
		"CLI resolved plan with stale journey driver",
	)
	if !containsString(
		emittedPlan.RequiredRunnerFeatures,
		"platform:linux/amd64",
	) {
		t.Fatalf(
			"resolved plan omitted architecture platform feature: %v",
			emittedPlan.RequiredRunnerFeatures,
		)
	}
	if !containsString(
		emittedPlan.RequiredRunnerFeatures,
		"cleanup-residue-classification",
	) {
		t.Fatalf(
			"resolved plan omitted cleanup classification feature: %v",
			emittedPlan.RequiredRunnerFeatures,
		)
	}
	var missingCleanupFeature map[string]any
	decodeJSON(t, planData.Plan, &missingCleanupFeature)
	features, ok := missingCleanupFeature["requiredRunnerFeatures"].([]any)
	if !ok {
		t.Fatalf(
			"requiredRunnerFeatures JSON type = %T",
			missingCleanupFeature["requiredRunnerFeatures"],
		)
	}
	filteredFeatures := make([]any, 0, len(features))
	for _, rawFeature := range features {
		feature, ok := rawFeature.(string)
		if !ok {
			t.Fatalf("required runner feature JSON type = %T", rawFeature)
		}
		if feature != "cleanup-residue-classification" {
			filteredFeatures = append(filteredFeatures, rawFeature)
		}
	}
	missingCleanupFeature["requiredRunnerFeatures"] = filteredFeatures
	assertSchemaRejects(
		t,
		schemas["resolved-plan.schema.json"],
		missingCleanupFeature,
		"resolved plan without cleanup classification feature",
	)

	healthyPortDetails := alpha25PortListenerSummaryDetails(
		"no-undeclared-observed",
	)
	healthyPortDetails["baselineEndpointCount"] = 0
	healthyPortDetails["declaredEndpointCount"] = 1
	healthyPortDetails["sampledEndpointCount"] = 1
	healthyPortDetails["undeclaredEndpointCount"] = 0
	successful := cli.Dependencies{
		ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
			return []domain.RunnerFeatures{fullyObservedRunner()}, nil
		},
		Execute: func(context.Context, domain.ResolvedPlan, string, string, string) (cli.RunnerOutcome, error) {
			return cli.RunnerOutcome{
				Runner: fullyObservedRunner(),
				Observations: []domain.ObservationEvent{{
					SchemaVersion: "1",
					Timestamp:     time.Date(2026, 7, 30, 4, 0, 0, 0, time.UTC),
					Phase:         domain.PhaseExercise,
					Actor:         "schema-contract-test",
					Operation:     "process-exec",
					Resource:      "node",
					Result:        "observed",
					Observer:      "process-exec",
					Coverage:      "full",
					Confidence:    "high",
					Details: map[string]any{
						"sharedBy": []string{"/outputs", "HOME", "TMPDIR"},
					},
				}, {
					SchemaVersion: "1",
					Timestamp:     time.Date(2026, 7, 30, 4, 0, 1, 0, time.UTC),
					Phase:         domain.PhaseCleanup,
					Actor:         "trusted-runner",
					Operation:     "filesystem.engine-diff.summary",
					Resource:      "repopass-schema-test",
					Result:        "observed",
					Observer:      "docker-container-diff",
					Coverage:      "best-effort",
					Confidence:    "high",
					Details: map[string]any{
						"scope":                       "docker-engine-filesystem-diff",
						"snapshotBoundary":            "image-to-post-quiesce-pre-repair",
						"engineSemantics":             "changes-since-container-create",
						"opaqueTranscript":            true,
						"transcriptParsed":            false,
						"baselineDiagnosticOnly":      true,
						"includesPreWorkloadChanges":  true,
						"includesTrustedObserverWork": true,
						"contentIncluded":             false,
						"pathsIncluded":               false,
						"publicEvidence":              "aggregate-only",
						"actorAttribution":            "unavailable",
						"baselineIdentityVerified":    true,
						"finalIdentityVerified":       true,
						"workloadQuiescenceVerified":  true,
						"baselineReady":               true,
						"finalReady":                  true,
						"engineDiffCoverage":          "best-effort",
						"mountedFilesystemCoverage":   "unavailable",
						"operationHistoryCoverage":    "unavailable",
						"pathClassificationAvailable": false,
						"blindSpots": []string{
							"outputs-tmpfs",
							"bind-and-other-mounts",
							"transient-create-delete",
						},
						"baselineDigest":                "sha256:" + strings.Repeat("a", 64),
						"baselineByteCount":             0,
						"baselineNonEmpty":              false,
						"finalDigest":                   "sha256:" + strings.Repeat("b", 64),
						"finalByteCount":                12,
						"finalNonEmpty":                 true,
						"transcriptChangedFromBaseline": true,
					},
				}, {
					SchemaVersion: "1",
					Timestamp: time.Date(
						2026, 7, 30, 4, 0, 1, 500_000_000, time.UTC,
					),
					Phase:      domain.PhaseCleanup,
					Actor:      "trusted-runner",
					Operation:  "port.listener-trace.summary",
					Resource:   "tcp-listeners",
					Result:     "observed",
					Observer:   "docker-peer-port-listener-trace",
					Coverage:   "best-effort",
					Confidence: "high",
					Details:    healthyPortDetails,
				}, {
					SchemaVersion: "1",
					Timestamp: time.Date(
						2026, 7, 30, 4, 0, 2, 0, time.UTC,
					),
					Phase:      domain.PhaseCleanup,
					Actor:      "trusted-runner",
					Operation:  "filesystem.activity-trace.summary",
					Resource:   "/outputs",
					Result:     "observed",
					Observer:   "docker-outputs-activity-trace",
					Coverage:   "best-effort",
					Confidence: "high",
					Details: map[string]any{
						"scope":                       "outputs-activity-notification-trace",
						"traceBoundary":               "post-preflight-pre-workload-to-post-quiesce-pre-retained-final",
						"notificationSemantics":       "runtime-filesystem-notification-hints",
						"rawPathIncluded":             false,
						"contentIncluded":             false,
						"publicEvidence":              "aggregate-only",
						"actorAttribution":            "unavailable",
						"phaseAttribution":            "controller-window-hint",
						"operationClassification":     "hint-only",
						"operationHistoryCoverage":    "unavailable",
						"observerPlacement":           "in-sandbox-trusted-helper",
						"sharesSandboxResourceBudget": true,
						"startIdentityVerified":       true,
						"readyIdentityVerified":       true,
						"stopIdentityVerified":        true,
						"finalIdentityVerified":       true,
						"workloadQuiescenceVerified":  true,
						"transport":                   "controller-stdin-stdout-jsonl",
						"transportBoundBytes":         16384,
						"notificationLimit":           4096,
						"watchLimit":                  2048,
						"activityTraceCoverage":       "best-effort",
						"blindSpots": []string{
							"outside-outputs",
							"exact-process-and-actor",
							"syscall-and-operation-history",
						},
						"observerAdapter":   "node-fs-watch-linux",
						"notificationCount": 2,
						"renameHintCount":   1,
						"changeHintCount":   1,
						"phaseCounts": []string{
							"setup=0",
							"build=0",
							"run=0",
							"exercise=2",
							"cleanup=0",
							"unknown=0",
						},
						"canonicalTranscriptDigest": "sha256:" +
							strings.Repeat("c", 64),
						"canonicalByteCount":      128,
						"kernelOverflowDetection": "unavailable",
					},
				}, {
					SchemaVersion: "1",
					Timestamp: time.Date(
						2026, 7, 30, 4, 0, 3, 0, time.UTC,
					),
					Phase:      domain.PhaseCleanup,
					Actor:      "trusted-runner",
					Operation:  "cleanup.residue.summary",
					Resource:   "/outputs",
					Result:     "succeeded",
					Observer:   "controller-cleanup-residue-classifier",
					Coverage:   "enforcement-only",
					Confidence: "high",
					Details: map[string]any{
						"allowedPatternCount":       1,
						"allowedProfile":            "outputs-descendants",
						"boundary":                  "post-quiescence-post-final-observers-post-disposable-pre-repair-pre-export-pre-destroy",
						"classifierVersion":         "0.1.0",
						"directoryCount":            0,
						"disposableCleanupVerified": true,
						"entryCount":                0,
						"identityVerified":          true,
						"inventoryComplete":         true,
						"maxControlBytes":           512 << 10,
						"maxDepth":                  64,
						"maxEntries":                2048,
						"maxPathBytes":              1024,
						"opaqueInventoryToken": "hmac-sha256:" +
							strings.Repeat("d", 64),
						"quiescenceConfirmed": true,
						"regularFileCount":    0,
						"scope":               "/outputs",
						"specialCount":        0,
						"symlinkCount":        0,
						"tokenScheme":         "ephemeral-keyed-hmac-sha256",
						"unmatchedCount":      0,
						"verdict":             "clean",
					},
				}},
				Assertions: []domain.AssertionResult{{
					SchemaVersion: "1",
					ID:            "process-exited",
					Type:          "exit-code",
					Required:      true,
					Expected:      0,
					Actual:        0,
					Status:        "pass",
					EvidenceRefs:  []string{"observation:process-exec"},
				}},
				Resources: domain.ResourceSummary{DurationMillis: 1},
				Completed: true,
				Cleanup:   domain.CleanupClean,
			}, nil
		},
	}
	successEnvelope := runCLI(
		t,
		successful,
		"--json",
		"--data-dir",
		t.TempDir(),
		"verify",
		"--manifest",
		manifestPath,
	)
	successRaw := verificationFromEnvelope(t, successEnvelope)
	if err := schemavalidator.ValidateVerificationJSON(successRaw); err != nil {
		t.Fatalf("runtime verification validation: %v", err)
	}
	validateJSON(t, schemas["verification.schema.json"], successRaw)
	duplicateKey := append(
		[]byte(`{"schemaVersion":"1",`),
		successRaw[1:]...,
	)
	if err := schemavalidator.ValidateVerificationJSON(duplicateKey); err == nil {
		t.Fatal("runtime verification validation accepted a duplicate object key")
	}
	var unknownField map[string]any
	decodeJSON(t, successRaw, &unknownField)
	unknownField["unexpected"] = true
	unknownRaw, err := json.Marshal(unknownField)
	if err != nil {
		t.Fatalf("marshal verification with unknown field: %v", err)
	}
	if err := schemavalidator.ValidateVerificationJSON(unknownRaw); err == nil {
		t.Fatal("runtime verification validation accepted an unknown field")
	}
	oversized := make([]byte, schemavalidator.MaxVerificationJSONBytes+1)
	if err := schemavalidator.ValidateVerificationJSON(oversized); err == nil {
		t.Fatal("runtime verification validation accepted an oversized artifact")
	}
	unsafeExport := domain.ObservationEvent{
		SchemaVersion: "1",
		Sequence:      5,
		Timestamp:     time.Date(2026, 7, 30, 4, 0, 4, 0, time.UTC),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "sandbox.outputs.export",
		Resource:      "/outputs",
		Result:        "denied",
		Observer:      "docker-cli",
		Coverage:      "enforcement-only",
		Confidence:    "high",
		Details: map[string]any{
			"reason":       "unsafe-residue",
			"specialCount": 0,
			"symlinkCount": 1,
		},
	}
	unsafeExportRaw, err := json.Marshal(unsafeExport)
	if err != nil {
		t.Fatalf("marshal unsafe export observation: %v", err)
	}
	validateJSON(
		t,
		schemas["observation.schema.json"],
		unsafeExportRaw,
	)
	var verificationWithDeniedExport map[string]any
	decodeJSON(t, successRaw, &verificationWithDeniedExport)
	rawObservations, ok := verificationWithDeniedExport["observations"].([]any)
	if !ok {
		t.Fatalf(
			"verification observations JSON type = %T",
			verificationWithDeniedExport["observations"],
		)
	}
	var unsafeExportValue any
	decodeJSON(t, unsafeExportRaw, &unsafeExportValue)
	verificationWithDeniedExport["observations"] = append(
		rawObservations,
		unsafeExportValue,
	)
	verificationWithDeniedExportRaw, err := json.Marshal(
		verificationWithDeniedExport,
	)
	if err != nil {
		t.Fatalf("marshal verification with denied export: %v", err)
	}
	validateJSON(
		t,
		schemas["verification.schema.json"],
		verificationWithDeniedExportRaw,
	)

	var evidence struct {
		Observations []json.RawMessage `json:"observations"`
		Assertions   []json.RawMessage `json:"assertions"`
	}
	decodeJSON(t, successRaw, &evidence)
	if len(evidence.Observations) == 0 || len(evidence.Assertions) == 0 {
		t.Fatal("successful verification did not emit observation and assertion evidence")
	}
	for _, item := range evidence.Observations {
		validateJSON(t, schemas["observation.schema.json"], item)
	}
	for _, item := range evidence.Assertions {
		validateJSON(t, schemas["assertion.schema.json"], item)
	}

	unavailable := unavailableRunner()
	blockedEnvelope := runCLI(
		t,
		cli.Dependencies{
			ProbeAll: func(context.Context) ([]domain.RunnerFeatures, error) {
				return []domain.RunnerFeatures{unavailable}, nil
			},
			Execute: func(context.Context, domain.ResolvedPlan, string, string, string) (cli.RunnerOutcome, error) {
				return cli.RunnerOutcome{}, errors.New("execute must not be called for an unavailable runner")
			},
		},
		"--json",
		"--data-dir",
		t.TempDir(),
		"verify",
		"--manifest",
		manifestPath,
	)
	blockedRaw := verificationFromEnvelope(t, blockedEnvelope)
	validateJSON(t, schemas["verification.schema.json"], blockedRaw)

	var findings struct {
		Errors []json.RawMessage `json:"errors"`
	}
	decodeJSON(t, blockedRaw, &findings)
	if len(findings.Errors) == 0 {
		t.Fatal("blocked verification did not emit a structured error")
	}
	for _, item := range findings.Errors {
		validateJSON(t, schemas["error.schema.json"], item)
	}
}

func TestResolvedPlanCleanupSchemaContract(t *testing.T) {
	schema := compilePublicSchemas(t)["resolved-plan.schema.json"]
	envelope := runCLI(
		t,
		cli.Dependencies{},
		"--json",
		"plan",
		"--manifest",
		healthyManifest(t),
	)
	var planData struct {
		Plan map[string]any `json:"plan"`
	}
	decodeJSON(t, envelope.Data, &planData)

	emptyResidue := cloneJSONMap(t, planData.Plan)
	rawMap(t, emptyResidue["cleanup"])["allowedResidue"] = []any{}
	assertSchemaAccepts(
		t,
		schema,
		emptyResidue,
		"resolved cleanup with no allowed residue",
	)

	rejections := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "missing cleanup",
			mutate: func(plan map[string]any) {
				delete(plan, "cleanup")
			},
		},
		{
			name: "null cleanup",
			mutate: func(plan map[string]any) {
				plan["cleanup"] = nil
			},
		},
		{
			name: "missing classifier version",
			mutate: func(plan map[string]any) {
				delete(rawMap(t, plan["cleanup"]), "classifierVersion")
			},
		},
		{
			name: "classifier version drift",
			mutate: func(plan map[string]any) {
				rawMap(t, plan["cleanup"])["classifierVersion"] = "0.1.1"
			},
		},
		{
			name: "missing allowed residue",
			mutate: func(plan map[string]any) {
				delete(rawMap(t, plan["cleanup"]), "allowedResidue")
			},
		},
		{
			name: "null allowed residue",
			mutate: func(plan map[string]any) {
				rawMap(t, plan["cleanup"])["allowedResidue"] = nil
			},
		},
		{
			name: "custom residue",
			mutate: func(plan map[string]any) {
				rawMap(t, plan["cleanup"])["allowedResidue"] =
					[]any{"/workspace/**"}
			},
		},
		{
			name: "additional residue",
			mutate: func(plan map[string]any) {
				rawMap(t, plan["cleanup"])["allowedResidue"] =
					[]any{"/outputs/**", "/workspace/**"}
			},
		},
		{
			name: "duplicate output residue",
			mutate: func(plan map[string]any) {
				rawMap(t, plan["cleanup"])["allowedResidue"] =
					[]any{"/outputs/**", "/outputs/**"}
			},
		},
		{
			name: "unknown cleanup property",
			mutate: func(plan map[string]any) {
				rawMap(t, plan["cleanup"])["classifier"] = "legacy"
			},
		},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			plan := cloneJSONMap(t, planData.Plan)
			test.mutate(plan)
			assertSchemaRejects(t, schema, plan, test.name)
		})
	}
}

func TestResolvedPlanCLIStdoutJSONSchemaContract(t *testing.T) {
	schema := compileSchemaDefinition(
		t,
		"resolved-plan.schema.json",
		"journeyAssertion",
	)
	binding := map[string]any{
		"path":             "schemas/stdout.schema.json",
		"digest":           "sha256:" + strings.Repeat("a", 64),
		"dialect":          domain.AlphaJSONSchemaDialect,
		"validatorVersion": domain.AlphaJSONValidatorVersion,
	}
	assertion := map[string]any{
		"id":               "stdout-schema",
		"stdoutJsonSchema": binding,
	}
	assertSchemaAccepts(
		t,
		schema,
		assertion,
		"CLI stdout JSON Schema assertion",
	)

	withSecondOperation := cloneJSONMap(t, assertion)
	withSecondOperation["exitCode"] = float64(0)
	assertSchemaRejects(
		t,
		schema,
		withSecondOperation,
		"CLI stdout JSON Schema assertion with a second operation",
	)

	withValidatorDrift := cloneJSONMap(t, assertion)
	rawMap(t, withValidatorDrift["stdoutJsonSchema"])["validatorVersion"] =
		"different-validator@v1"
	assertSchemaRejects(
		t,
		schema,
		withValidatorDrift,
		"CLI stdout JSON Schema assertion with validator drift",
	)

	responseAssertion := map[string]any{
		"id": "http-response",
		"response": map[string]any{
			"requestId": "request",
			"status":    float64(200),
		},
	}
	httpSchema := compileSchemaDefinition(
		t,
		"resolved-plan.schema.json",
		"httpJourneyAssertion",
	)
	assertSchemaAccepts(
		t,
		httpSchema,
		responseAssertion,
		"HTTP response assertion",
	)
	assertSchemaRejects(
		t,
		schema,
		responseAssertion,
		"CLI assertion with HTTP response operation",
	)

	assertSchemaRejects(
		t,
		httpSchema,
		assertion,
		"HTTP assertion with CLI stdout JSON Schema operation",
	)
	for name, cliOperation := range map[string]any{
		"exit code":       float64(0),
		"stdout contains": "ok",
	} {
		httpCLIAssertion := map[string]any{
			"id": "http-cli-operation",
		}
		if name == "exit code" {
			httpCLIAssertion["exitCode"] = cliOperation
		} else {
			httpCLIAssertion["stdoutContains"] = cliOperation
		}
		assertSchemaRejects(
			t,
			httpSchema,
			httpCLIAssertion,
			"HTTP assertion with CLI "+name+" operation",
		)
	}
}

func TestHTTPResolvedPlanMatchesPublicSchemaAndOneOfContracts(t *testing.T) {
	schemas := compilePublicSchemas(t)
	envelope := runCLI(
		t,
		cli.Dependencies{},
		"--json",
		"plan",
		"--manifest",
		healthyHTTPManifest(t),
	)
	var planData struct {
		Plan json.RawMessage `json:"plan"`
	}
	decodeJSON(t, envelope.Data, &planData)
	validateJSON(t, schemas["resolved-plan.schema.json"], planData.Plan)
	var staleHTTPDriver map[string]any
	decodeJSON(t, planData.Plan, &staleHTTPDriver)
	staleHTTPDriver["journeyDriverVersion"] = "0.2.0"
	assertSchemaRejects(
		t,
		schemas["resolved-plan.schema.json"],
		staleHTTPDriver,
		"HTTP resolved plan with CLI journey driver",
	)

	var plan domain.ResolvedPlan
	decodeJSON(t, planData.Plan, &plan)
	if plan.JourneyDriver != "http" ||
		plan.HTTPJourney == nil ||
		plan.HTTPJourney.ServiceID != "app" ||
		len(plan.HTTPJourney.Steps) != 6 {
		t.Fatalf("emitted HTTP plan lost journey contract: %#v", plan.HTTPJourney)
	}
	var service *domain.PlanCommand
	for index := range plan.Commands {
		if plan.Commands[index].Role == "service" {
			service = &plan.Commands[index]
			break
		}
	}
	if service == nil || service.Readiness == nil {
		t.Fatalf("emitted HTTP plan lost service readiness: %#v", plan.Commands)
	}
	if len(plan.JourneyAssertions) != 5 ||
		plan.JourneyAssertions[0].Response == nil ||
		plan.JourneyAssertions[1].Response == nil ||
		plan.JourneyAssertions[1].Response.JSONPath == nil ||
		plan.JourneyAssertions[2].Response == nil ||
		plan.JourneyAssertions[2].Response.JSONSchema == nil ||
		plan.JourneyAssertions[4].JSONFile == nil {
		t.Fatalf(
			"emitted HTTP plan lost structured assertions: %#v",
			plan.JourneyAssertions,
		)
	}

	var rawPlan map[string]any
	decodeJSON(t, planData.Plan, &rawPlan)
	delete(rawPlan, "httpJourney")
	assertSchemaRejects(
		t,
		schemas["resolved-plan.schema.json"],
		rawPlan,
		"HTTP plan without httpJourney",
	)

	decodeJSON(t, planData.Plan, &rawPlan)
	httpJourney := rawPlan["httpJourney"].(map[string]any)
	steps := httpJourney["steps"].([]any)
	firstStep := steps[0].(map[string]any)
	firstStep["assertionId"] = "echo-ok"
	assertSchemaRejects(
		t,
		schemas["resolved-plan.schema.json"],
		rawPlan,
		"HTTP step with request and assertionId",
	)
}

func TestHTTPPublicSchemasEnforceAlphaBoundaries(t *testing.T) {
	schemas := compilePublicSchemas(t)
	document, err := manifest.Load(healthyHTTPManifest(t))
	if err != nil {
		t.Fatalf("load healthy HTTP manifest: %v", err)
	}
	manifestRaw := marshalJSONMap(t, document.Manifest)

	envelope := runCLI(
		t,
		cli.Dependencies{},
		"--json",
		"plan",
		"--manifest",
		healthyHTTPManifest(t),
	)
	var planData struct {
		Plan json.RawMessage `json:"plan"`
	}
	decodeJSON(t, envelope.Data, &planData)
	var planRaw map[string]any
	decodeJSON(t, planData.Plan, &planRaw)

	t.Run("repository schema accepts exact limits and Unicode output", func(t *testing.T) {
		value := cloneJSONMap(t, manifestRaw)
		readiness, driver, _ := rawManifestHTTPParts(t, value)
		spec := rawMap(t, value["spec"])
		scenarios := rawMap(t, spec["scenarios"])
		scenario := rawMap(t, scenarios["quickstart"])
		phases := rawMap(t, scenario["phases"])
		rawMap(t, phases["exercise"])["timeout"] = "1.5s"
		prefix := "http://127.0.0.1:8080/"
		readiness["status"] = float64(200)
		steps := rawSlice(t, driver["steps"])
		requestStep := cloneJSONValue(t, steps[0])
		assertionStep := cloneJSONValue(
			t,
			rawHTTPAssertionStepWithOperation(t, driver, "fileExists"),
		)
		bounded := make([]any, 0, domain.AlphaHTTPMaxJourneySteps)
		for index := 0; index < domain.AlphaHTTPMaxRequestSteps; index++ {
			bounded = append(bounded, cloneJSONValue(t, requestStep))
		}
		for len(bounded) < domain.AlphaHTTPMaxJourneySteps {
			bounded = append(bounded, cloneJSONValue(t, assertionStep))
		}
		driver["steps"] = bounded
		firstRequest := rawMap(t, rawMap(t, bounded[0])["request"])
		firstRequest["url"] = prefix + strings.Repeat(
			"a",
			domain.AlphaHTTPMaxURLBytes-len(prefix),
		)
		firstRequest["timeout"] = "1.5s"
		readiness["timeout"] = "2m"
		rawMap(t, rawMap(t, bounded[len(bounded)-1])["assert"])["fileExists"] =
			"/outputs/界.json"
		assertSchemaAccepts(
			t,
			schemas["repo-passport.schema.json"],
			value,
			"repository exact HTTP boundaries",
		)
	})

	t.Run("repository schema accepts explicit null JSON", func(t *testing.T) {
		value := cloneJSONMap(t, manifestRaw)
		_, driver, _ := rawManifestHTTPParts(t, value)
		request := rawMap(
			t,
			rawMap(t, rawSlice(t, driver["steps"])[0])["request"],
		)
		request["json"] = nil
		delete(request, "body")
		assertSchemaAccepts(
			t,
			schemas["repo-passport.schema.json"],
			value,
			"explicit null JSON",
		)
	})

	repositoryRejects := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "request-only journey",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				steps := rawSlice(t, driver["steps"])
				driver["steps"] = []any{steps[0]}
			},
		},
		{
			name: "sub-millisecond exercise fallback",
			mutate: func(value map[string]any) {
				spec := rawMap(t, value["spec"])
				scenarios := rawMap(t, spec["scenarios"])
				scenario := rawMap(t, scenarios["quickstart"])
				phases := rawMap(t, scenario["phases"])
				rawMap(t, phases["exercise"])["timeout"] = "1.5ms"
			},
		},
		{
			name: "leading zero port",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				rawMap(t, rawMap(t, rawSlice(t, driver["steps"])[0])["request"])["url"] =
					"http://127.0.0.1:08080/echo"
			},
		},
		{
			name: "2049 byte URL",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				prefix := "http://127.0.0.1:8080/"
				rawMap(t, rawMap(t, rawSlice(t, driver["steps"])[0])["request"])["url"] =
					prefix + strings.Repeat(
						"a",
						domain.AlphaHTTPMaxURLBytes-len(prefix)+1,
					)
			},
		},
		{
			name: "129 steps",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				steps := rawSlice(t, driver["steps"])
				for len(steps) <= domain.AlphaHTTPMaxJourneySteps {
					steps = append(steps, cloneJSONValue(t, steps[2]))
				}
				driver["steps"] = steps
			},
		},
		{
			name: "33 requests",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				steps := rawSlice(t, driver["steps"])
				for index := 1; index < 33; index++ {
					steps = append(steps, cloneJSONValue(t, steps[0]))
				}
				driver["steps"] = steps
			},
		},
		{
			name: "65 headers",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				request := rawMap(t, rawMap(t, rawSlice(t, driver["steps"])[0])["request"])
				headers := make(map[string]any, 65)
				for index := 0; index < 65; index++ {
					headers[fmt.Sprintf("x-%02d", index)] = "ok"
				}
				request["headers"] = headers
			},
		},
		{
			name: "non ASCII header value",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				request := rawMap(t, rawMap(t, rawSlice(t, driver["steps"])[0])["request"])
				request["headers"] = map[string]any{"x-test": "界"}
			},
		},
		{
			name: "HTTP file outside outputs",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				rawMap(
					t,
					rawHTTPAssertionStepWithOperation(
						t,
						driver,
						"fileExists",
					)["assert"],
				)["fileExists"] =
					"/workspace/result.json"
			},
		},
		{
			name: "HTTP JSON file outside outputs",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				assertion := rawMap(
					t,
					rawHTTPAssertionStepWithOperation(
						t,
						driver,
						"jsonFile",
					)["assert"],
				)
				rawMap(t, assertion["jsonFile"])["path"] =
					"/workspace/result.json"
			},
		},
		{
			name: "oversize JSONPath",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				assertion := rawMap(
					t,
					rawMap(t, rawSlice(t, driver["steps"])[2])["assert"],
				)
				jsonPath := rawMap(
					t,
					rawMap(t, assertion["response"])["jsonPath"],
				)
				jsonPath["path"] = "$." +
					strings.Repeat("a", domain.AlphaJSONPathMaxBytes)
			},
		},
		{
			name: "missing kill grace",
			mutate: func(value map[string]any) {
				_, _, signal := rawManifestHTTPParts(t, value)
				signal["type"] = "kill"
				delete(signal, "gracePeriod")
			},
		},
		{
			name: "1ns timeout",
			mutate: func(value map[string]any) {
				readiness, _, _ := rawManifestHTTPParts(t, value)
				readiness["timeout"] = "1ns"
			},
		},
		{
			name: "status 199",
			mutate: func(value map[string]any) {
				readiness, _, _ := rawManifestHTTPParts(t, value)
				readiness["status"] = float64(199)
			},
		},
		{
			name: "response status 199",
			mutate: func(value map[string]any) {
				_, driver, _ := rawManifestHTTPParts(t, value)
				assertion := rawMap(
					t,
					rawMap(t, rawSlice(t, driver["steps"])[1])["assert"],
				)
				rawMap(t, assertion["response"])["status"] = float64(199)
			},
		},
	}
	for _, test := range repositoryRejects {
		t.Run("repository rejects "+test.name, func(t *testing.T) {
			value := cloneJSONMap(t, manifestRaw)
			test.mutate(value)
			assertSchemaRejects(
				t,
				schemas["repo-passport.schema.json"],
				value,
				test.name,
			)
		})
	}

	t.Run("resolved schema accepts Unicode HTTP output", func(t *testing.T) {
		value := cloneJSONMap(t, planRaw)
		assertions := rawSlice(t, value["journeyAssertions"])
		rawAssertionWithOperation(t, assertions, "fileExists")["fileExists"] =
			"/outputs/界.json"
		for _, commandValue := range rawSlice(t, value["commands"]) {
			command := rawMap(t, commandValue)
			switch command["role"] {
			case "service":
				rawMap(t, command["readiness"])["timeout"] = "2m"
			case "signal":
				rawMap(t, command["signal"])["gracePeriod"] = "1.5s"
			}
		}
		journey := rawMap(t, value["httpJourney"])
		request := rawMap(
			t,
			rawMap(t, rawSlice(t, journey["steps"])[0])["request"],
		)
		request["timeout"] = "1.5s"
		assertSchemaAccepts(
			t,
			schemas["resolved-plan.schema.json"],
			value,
			"resolved Unicode HTTP output",
		)
	})
	resolvedRejects := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "empty HTTP journey assertions",
			mutate: func(value map[string]any) {
				value["journeyAssertions"] = []any{}
			},
		},
		{
			name: "request-only resolved journey",
			mutate: func(value map[string]any) {
				journey := rawMap(t, value["httpJourney"])
				steps := rawSlice(t, journey["steps"])
				journey["steps"] = []any{steps[0]}
			},
		},
		{
			name: "HTTP file outside outputs",
			mutate: func(value map[string]any) {
				rawAssertionWithOperation(
					t,
					rawSlice(t, value["journeyAssertions"]),
					"fileExists",
				)["fileExists"] =
					"/workspace/result.json"
			},
		},
		{
			name: "HTTP JSON file outside outputs",
			mutate: func(value map[string]any) {
				assertion := rawAssertionWithOperation(
					t,
					rawSlice(t, value["journeyAssertions"]),
					"jsonFile",
				)
				rawMap(t, assertion["jsonFile"])["path"] =
					"/workspace/result.json"
			},
		},
		{
			name: "JSON Schema validator drift",
			mutate: func(value map[string]any) {
				assertion := rawMap(
					t,
					rawSlice(t, value["journeyAssertions"])[2],
				)
				schema := rawMap(
					t,
					rawMap(t, assertion["response"])["jsonSchema"],
				)
				schema["validatorVersion"] = "different-validator@v1"
			},
		},
		{
			name: "status 199",
			mutate: func(value map[string]any) {
				assertions := rawSlice(t, value["journeyAssertions"])
				rawMap(t, rawMap(t, assertions[0])["response"])["status"] =
					float64(199)
			},
		},
		{
			name: "readiness status 199",
			mutate: func(value map[string]any) {
				for _, commandValue := range rawSlice(t, value["commands"]) {
					command := rawMap(t, commandValue)
					if command["role"] == "service" {
						rawMap(t, command["readiness"])["status"] = float64(199)
						return
					}
				}
				t.Fatal("resolved plan has no service command")
			},
		},
		{
			name: "signal missing grace",
			mutate: func(value map[string]any) {
				for _, commandValue := range rawSlice(t, value["commands"]) {
					command := rawMap(t, commandValue)
					if command["role"] == "signal" {
						delete(rawMap(t, command["signal"]), "gracePeriod")
						return
					}
				}
				t.Fatal("resolved plan has no signal command")
			},
		},
		{
			name: "129 steps",
			mutate: func(value map[string]any) {
				journey := rawMap(t, value["httpJourney"])
				steps := rawSlice(t, journey["steps"])
				for len(steps) <= domain.AlphaHTTPMaxJourneySteps {
					steps = append(steps, cloneJSONValue(t, steps[1]))
				}
				journey["steps"] = steps
			},
		},
		{
			name: "33 requests",
			mutate: func(value map[string]any) {
				journey := rawMap(t, value["httpJourney"])
				steps := rawSlice(t, journey["steps"])
				for index := 1; index < 33; index++ {
					steps = append(steps, cloneJSONValue(t, steps[0]))
				}
				journey["steps"] = steps
			},
		},
	}
	for _, test := range resolvedRejects {
		t.Run("resolved rejects "+test.name, func(t *testing.T) {
			value := cloneJSONMap(t, planRaw)
			test.mutate(value)
			assertSchemaRejects(
				t,
				schemas["resolved-plan.schema.json"],
				value,
				test.name,
			)
		})
	}
}

func TestHTTPDurationSchemaDefinitionsMatchWholeMilliseconds(t *testing.T) {
	tests := []struct {
		file       string
		definition string
		accept     []string
		reject     []string
	}{
		{
			file:       "repo-passport.schema.json",
			definition: "positiveMillisecondDuration",
			accept:     []string{"1ms", "1.5s", "2m", "1h"},
			reject:     []string{"1ns", "1.5ms", "0ms", "0.000s"},
		},
		{
			file:       "repo-passport.schema.json",
			definition: "httpReadinessDuration",
			accept:     []string{"1ms", "1.5s", "2m"},
			reject:     []string{"1ns", "1.5ms", "0ms", "2m1ms"},
		},
		{
			file:       "resolved-plan.schema.json",
			definition: "wholeMillisecondDuration",
			accept: []string{
				"1ms",
				"1.5s",
				"2m",
				"2m0s",
				"1h",
				"1h0m0s",
			},
			reject: []string{"1ns", "1.5ms", "0ms", "0.000s"},
		},
	}
	for _, test := range tests {
		t.Run(test.file+" "+test.definition, func(t *testing.T) {
			schema := compileSchemaDefinition(
				t,
				test.file,
				test.definition,
			)
			for _, value := range test.accept {
				assertSchemaAccepts(t, schema, value, value)
			}
			for _, value := range test.reject {
				assertSchemaRejects(t, schema, value, value)
			}
		})
	}
}

func TestVerificationResourceSummarySchemaIsBackwardCompatibleAndBounded(
	t *testing.T,
) {
	schema := compileSchemaDefinition(
		t,
		"verification.schema.json",
		"resources",
	)
	assertSchemaAccepts(
		t,
		schema,
		map[string]any{"durationMillis": 0},
		"legacy duration-only resource summary",
	)
	full := domain.ResourceSummary{
		SandboxPeakMemoryBytes: 4096,
		SandboxCPUTimeMillis:   17,
		DurationMillis:         23,
		MaxTasks:               3,
		LogBytes:               512,
		WritableBytes:          2048,
		OutputBytes:            1024,
		ObservedFields: []domain.ResourceObservedField{
			domain.ResourceObservedMaxTasks,
			domain.ResourceObservedOutputBytes,
			domain.ResourceObservedSandboxCPUTimeMillis,
			domain.ResourceObservedSandboxPeakMemoryBytes,
			domain.ResourceObservedWritableBytes,
		},
	}
	assertSchemaAccepts(t, schema, full, "complete bounded resource summary")
	wire := marshalJSONMap(t, full)
	if wire["writableBytes"] != float64(2048) ||
		wire["outputBytes"] != float64(1024) {
		t.Fatalf("new resource evidence fields were not emitted: %#v", wire)
	}
	for _, field := range []string{
		"peakMemoryBytes",
		"cpuTimeMillis",
		"durationMillis",
		"maxProcesses",
		"logBytes",
		"sandboxPeakMemoryBytes",
		"sandboxCPUTimeMillis",
		"maxTasks",
		"writableBytes",
		"outputBytes",
	} {
		assertSchemaRejects(
			t,
			schema,
			map[string]any{
				"durationMillis": 0,
				field:            -1,
			},
			"negative "+field,
		)
	}
	assertSchemaRejects(
		t,
		schema,
		map[string]any{
			"durationMillis": 0,
			"peakDiskBytes":  1,
		},
		"unknown resource metric",
	)
	assertSchemaRejects(
		t,
		schema,
		map[string]any{
			"durationMillis": 0,
			"writableBytes":  1,
		},
		"new metric without observedFields",
	)
	assertSchemaAccepts(
		t,
		schema,
		map[string]any{
			"durationMillis": 0,
			"observedFields": []string{"writableBytes"},
		},
		"observed zero metric",
	)
}

func TestVerificationRunnerSeparatesEnforcementFromObservationCoverage(
	t *testing.T,
) {
	schema := compileSchemaDefinition(
		t,
		"verification.schema.json",
		"runner",
	)
	runner := marshalJSONMap(t, fullyObservedRunner())
	assertSchemaAccepts(t, schema, runner, "fully observed enforced runner")

	resourceEnforcement := cloneJSONMap(t, runner)
	resourceEnforcement["resourceUsage"] = "enforcement-only"
	assertSchemaRejects(
		t,
		schema,
		resourceEnforcement,
		"resource enforcement presented as observation",
	)

	processEnforcement := cloneJSONMap(t, runner)
	processEnforcement["processExecObservation"] = "enforcement-only"
	assertSchemaRejects(
		t,
		schema,
		processEnforcement,
		"process enforcement presented as observation",
	)

	networkEnforcement := cloneJSONMap(t, runner)
	networkEnforcement["networkAttemptObservation"] = "enforcement-only"
	assertSchemaAccepts(
		t,
		schema,
		networkEnforcement,
		"network enforcement coverage",
	)
}

func TestAttestationPublicSchemasCompileAndRejectExtensions(t *testing.T) {
	schemas := compilePublicSchemas(t)
	digest := "sha256:" + strings.Repeat("a", 64)

	manifest := map[string]any{
		"schemaVersion":  "1",
		"bundleFormat":   "repopass.attestation.bundle.v1",
		"privacyProfile": "minimal-public",
		"files": []any{
			map[string]any{
				"path":   "payload/verification.json",
				"sha256": digest,
				"size":   float64(1024),
			},
			map[string]any{
				"path":   "signer-public-key.pem",
				"sha256": digest,
				"size":   float64(113),
			},
		},
	}
	assertSchemaAccepts(
		t,
		schemas["bundle-manifest.schema.json"],
		manifest,
		"minimal-public bundle manifest",
	)

	runner := map[string]any{
		"backend":                    "docker",
		"available":                  true,
		"controllerOS":               "windows",
		"workloadOS":                 "linux",
		"rootless":                   "unknown",
		"networkDeny":                true,
		"networkAttemptObservation":  "unavailable",
		"processExecObservation":     "unavailable",
		"filesystemWriteObservation": "unavailable",
		"filesystemReadObservation":  "unavailable",
		"portObservation":            "unavailable",
		"resourceUsage":              "unavailable",
	}
	results := map[string]any{
		"functional":      "pass",
		"capability":      "incomplete",
		"reproducibility": "not-tested",
		"cleanup":         "clean",
		"evidence":        "unsigned",
		"freshness":       "current",
		"overall":         "inconclusive",
	}
	statement := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name": "bundle-manifest.json",
			"digest": map[string]any{
				"sha256": strings.Repeat("b", 64),
			},
		}},
		"predicateType": "https://repopass.dev/attestation/verification/v0.1",
		"predicate": map[string]any{
			"schemaVersion":              "1",
			"runId":                      "run_abcdef0123456789",
			"verificationId":             "vrf_abcdef0123456789",
			"verificationArtifactDigest": digest,
			"verificationDigest":         digest,
			"source": map[string]any{
				"identity":   digest,
				"treeDigest": digest,
			},
			"plan": map[string]any{
				"scenario":                  "quickstart",
				"environment":               "linux-node",
				"planDigest":                digest,
				"policyBundleDigest":        digest,
				"resolvedPlanSchemaVersion": "4",
				"evidence": map[string]any{
					"profile": "minimal-public",
					"include": []any{"normalized-observations", "verification-summary"},
					"exclude": []any{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
				},
			},
			"runner":          runner,
			"originalResults": results,
		},
	}
	assertSchemaAccepts(
		t,
		schemas["attestation.schema.json"],
		statement,
		"RepoPassport in-toto statement",
	)

	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     "e30=",
		"signatures": []any{map[string]any{
			"keyid": digest,
			"sig":   strings.Repeat("A", 86) + "==",
		}},
	}
	assertSchemaAccepts(
		t,
		schemas["dsse-envelope.schema.json"],
		envelope,
		"single-signature Ed25519 DSSE envelope",
	)

	for name, value := range map[string]map[string]any{
		"bundle-manifest.schema.json": manifest,
		"attestation.schema.json":     statement,
		"dsse-envelope.schema.json":   envelope,
	} {
		withExtension := cloneJSONMap(t, value)
		withExtension["x-unbound"] = true
		assertSchemaRejects(
			t,
			schemas[name],
			withExtension,
			name+" with an unbound extension",
		)
	}
}

func TestOfflineTrustPolicySchemaContract(t *testing.T) {
	schemas := compilePublicSchemas(t)
	schema := schemas["offline-trust-policy-v1.schema.json"]
	keyID := "sha256:" + strings.Repeat("a", 64)
	policy := map[string]any{
		"schemaVersion":  "1",
		"keyAlgorithm":   "ed25519",
		"keyIdAlgorithm": "spki-sha256",
		"keys":           []any{map[string]any{"keyId": keyID, "status": "trusted"}},
	}
	assertSchemaAccepts(t, schema, policy, "offline trust policy")
	for name, mutate := range map[string]func(map[string]any){
		"unknown field":   func(value map[string]any) { value["unknown"] = true },
		"wrong algorithm": func(value map[string]any) { value["keyAlgorithm"] = "rsa" },
		"empty keys":      func(value map[string]any) { value["keys"] = []any{} },
		"duplicate key entry": func(value map[string]any) {
			entry := map[string]any{"keyId": keyID, "status": "trusted"}
			value["keys"] = []any{entry, entry}
		},
		"uppercase key ID": func(value map[string]any) {
			value["keys"] = []any{map[string]any{"keyId": "sha256:" + strings.Repeat("A", 64), "status": "trusted"}}
		},
		"unknown status": func(value map[string]any) {
			value["keys"] = []any{map[string]any{"keyId": keyID, "status": "disabled"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneJSONMap(t, policy)
			mutate(candidate)
			assertSchemaRejects(t, schema, candidate, name)
		})
	}
}

func TestOfflineTrustPolicyV2SchemasContract(t *testing.T) {
	schemas := compilePublicSchemas(t)
	keyID := "sha256:" + strings.Repeat("a", 64)
	payload := map[string]any{
		"schemaVersion": "2", "generation": uint64(1), "keyAlgorithm": "ed25519", "keyIdAlgorithm": "spki-sha256",
		"keys": []any{map[string]any{"keyId": keyID, "status": "trusted"}},
	}
	assertSchemaAccepts(t, schemas["offline-trust-policy-v2.schema.json"], payload, "v2 offline trust policy")
	for name, mutate := range map[string]func(map[string]any){
		"zero generation":   func(value map[string]any) { value["generation"] = 0 },
		"unsafe generation": func(value map[string]any) { value["generation"] = uint64(9007199254740992) },
		"v1 downgrade":      func(value map[string]any) { value["schemaVersion"] = "1" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneJSONMap(t, payload)
			mutate(candidate)
			assertSchemaRejects(t, schemas["offline-trust-policy-v2.schema.json"], candidate, name)
		})
	}
	envelope := map[string]any{
		"payloadType": "application/vnd.repopass.offline-trust-policy.v2+json", "payload": "e30=",
		"signatures": []any{map[string]any{"keyid": keyID, "sig": strings.Repeat("A", 86) + "=="}},
	}
	assertSchemaAccepts(t, schemas["offline-trust-policy-v2-envelope.schema.json"], envelope, "v2 policy envelope")
	envelope["payloadType"] = "application/vnd.in-toto+json"
	assertSchemaRejects(t, schemas["offline-trust-policy-v2-envelope.schema.json"], envelope, "wrong payload type")
}

func TestReleaseIndexAndKeyPolicySchemasContract(t *testing.T) {
	schemas := compilePublicSchemas(t)
	keyID := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	index := map[string]any{
		"artifactType": "repopass.external-release-index",
		"channel":      "alpha",
		"files": []any{map[string]any{
			"path": "SHA256SUMS", "sha256": digest, "size": uint64(1),
		}},
		"product":           "repopass",
		"productVersion":    "0.1.0-alpha.33",
		"releaseGeneration": uint64(1),
		"schemaVersion":     "1",
		"trustBoundary": map[string]any{
			"capability": "incomplete", "formalClaim": false,
			"identityAttestation": "none", "overall": "inconclusive",
			"timeAttestation": "none",
		},
	}
	assertSchemaAccepts(t, schemas["release-index-v1.schema.json"], index, "release index")
	for name, mutate := range map[string]func(map[string]any){
		"extension":     func(value map[string]any) { value["unknown"] = true },
		"wrong version": func(value map[string]any) { value["productVersion"] = "0.1.0-alpha.27" },
		"unsafe path": func(value map[string]any) {
			value["files"] = []any{map[string]any{"path": "nested/file", "sha256": digest, "size": uint64(1)}}
		},
		"oversized artifact": func(value map[string]any) {
			value["files"] = []any{map[string]any{"path": "artifact.bin", "sha256": digest, "size": uint64(134217729)}}
		},
		"oversized SHA256SUMS": func(value map[string]any) {
			value["files"] = []any{map[string]any{"path": "SHA256SUMS", "sha256": digest, "size": uint64(65537)}}
		},
		"trust-boundary upgrade": func(value map[string]any) {
			rawMap(t, value["trustBoundary"])["formalClaim"] = true
		},
	} {
		t.Run("index "+name, func(t *testing.T) {
			candidate := cloneJSONMap(t, index)
			mutate(candidate)
			assertSchemaRejects(t, schemas["release-index-v1.schema.json"], candidate, name)
		})
	}

	policy := map[string]any{
		"schemaVersion": "1", "product": "repopass", "channel": "alpha",
		"purpose": "release-index-signing", "generation": uint64(1),
		"keyAlgorithm": "ed25519", "keyIdAlgorithm": "spki-sha256",
		"keys": []any{map[string]any{"keyId": keyID, "status": "trusted"}},
	}
	assertSchemaAccepts(t, schemas["release-key-policy-v1.schema.json"], policy, "release key policy")
	policy["purpose"] = "evidence-signing"
	assertSchemaRejects(t, schemas["release-key-policy-v1.schema.json"], policy, "wrong policy purpose")

	for _, test := range []struct {
		name, schema, payloadType string
	}{
		{"release index envelope", "release-index-envelope-v1.schema.json", "application/vnd.repopass.release-index.v1+json"},
		{"release key policy envelope", "release-key-policy-envelope-v1.schema.json", "application/vnd.repopass.release-key-policy.v1+json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope := map[string]any{
				"payloadType": test.payloadType, "payload": "e30=",
				"signatures": []any{map[string]any{"keyid": keyID, "sig": strings.Repeat("A", 86) + "=="}},
			}
			assertSchemaAccepts(t, schemas[test.schema], envelope, test.name)
			envelope["payloadType"] = "application/vnd.in-toto+json"
			assertSchemaRejects(t, schemas[test.schema], envelope, "wrong payload type")
		})
	}
}

func compilePublicSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	names := []string{
		"repo-passport.schema.json",
		"resolved-plan.schema.json",
		"observation.schema.json",
		"assertion.schema.json",
		"verification.schema.json",
		"error.schema.json",
		"bundle-manifest.schema.json",
		"attestation.schema.json",
		"dsse-envelope.schema.json",
		"offline-trust-policy-v1.schema.json",
		"offline-trust-policy-v2.schema.json",
		"offline-trust-policy-v2-envelope.schema.json",
		"offline-trust-policy-authority-transition-v1.schema.json",
		"offline-trust-policy-authority-transition-envelope-v1.schema.json",
		"offline-trust-policy-authority-transition-chain-v1.schema.json",
		"release-index-v1.schema.json",
		"release-index-envelope-v1.schema.json",
		"release-key-policy-v1.schema.json",
		"release-key-policy-envelope-v1.schema.json",
		"release-authority-transition-v1.schema.json",
		"release-authority-transition-envelope-v1.schema.json",
		"release-authority-transition-chain-v1.schema.json",
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode schema %s: %v", name, err)
		}
		if err := compiler.AddResource(schemaBaseURL+name, document); err != nil {
			t.Fatalf("register schema %s: %v", name, err)
		}
	}
	compiled := make(map[string]*jsonschema.Schema, len(names))
	for _, name := range names {
		schema, err := compiler.Compile(schemaBaseURL + name)
		if err != nil {
			t.Fatalf("compile schema %s: %v", name, err)
		}
		compiled[name] = schema
	}
	return compiled
}

func compileSchemaDefinition(
	t *testing.T,
	file string,
	definition string,
) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read schema %s: %v", file, err)
	}
	var document struct {
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode schema %s: %v", file, err)
	}
	raw, ok := document.Definitions[definition]
	if !ok {
		t.Fatalf("schema %s has no definition %s", file, definition)
	}
	var wrapped map[string]any
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		t.Fatalf("decode definition %s: %v", definition, err)
	}
	wrapped["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	wrapped["$id"] = "https://schemas.repopass.dev/tests/" +
		file + "/" + definition
	wrapped["$defs"] = document.Definitions
	wrappedData, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("marshal definition %s: %v", definition, err)
	}
	resource, err := jsonschema.UnmarshalJSON(bytes.NewReader(wrappedData))
	if err != nil {
		t.Fatalf("decode definition resource %s: %v", definition, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(
		wrapped["$id"].(string),
		resource,
	); err != nil {
		t.Fatalf("register definition %s: %v", definition, err)
	}
	compiled, err := compiler.Compile(wrapped["$id"].(string))
	if err != nil {
		t.Fatalf("compile definition %s: %v", definition, err)
	}
	return compiled
}

func assertSchemaRejects(
	t *testing.T,
	schema *jsonschema.Schema,
	value any,
	description string,
) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", description, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode %s: %v", description, err)
	}
	if err := schema.Validate(instance); err == nil {
		t.Fatalf("schema unexpectedly accepted %s:\n%s", description, data)
	}
}

func assertSchemaAccepts(
	t *testing.T,
	schema *jsonschema.Schema,
	value any,
	description string,
) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", description, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode %s: %v", description, err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema rejected %s: %v\n%s", description, err, data)
	}
}

func marshalJSONMap(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON object: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode JSON object: %v", err)
	}
	return result
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	return rawMap(t, cloneJSONValue(t, value))
}

func cloneJSONValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("clone JSON value: %v", err)
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode cloned JSON value: %v", err)
	}
	return result
}

func rawMap(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("JSON value is %T, want object", value)
	}
	return result
}

func rawSlice(t *testing.T, value any) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("JSON value is %T, want array", value)
	}
	return result
}

func rawHTTPAssertionStepWithOperation(
	t *testing.T,
	driver map[string]any,
	operation string,
) map[string]any {
	t.Helper()
	for _, rawStep := range rawSlice(t, driver["steps"]) {
		step := rawMap(t, rawStep)
		rawAssertion, exists := step["assert"]
		if !exists {
			continue
		}
		assertion := rawMap(t, rawAssertion)
		if _, exists := assertion[operation]; exists {
			return step
		}
	}
	t.Fatalf("HTTP driver has no %q assertion step", operation)
	return nil
}

func rawAssertionWithOperation(
	t *testing.T,
	assertions []any,
	operation string,
) map[string]any {
	t.Helper()
	for _, rawAssertion := range assertions {
		assertion := rawMap(t, rawAssertion)
		if _, exists := assertion[operation]; exists {
			return assertion
		}
	}
	t.Fatalf("resolved plan has no %q assertion", operation)
	return nil
}

func rawManifestHTTPParts(
	t *testing.T,
	value map[string]any,
) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	spec := rawMap(t, value["spec"])
	scenarios := rawMap(t, spec["scenarios"])
	scenario := rawMap(t, scenarios["quickstart"])
	phases := rawMap(t, scenario["phases"])
	run := rawMap(t, phases["run"])
	service := rawMap(t, run["service"])
	readiness := rawMap(t, rawMap(t, service["readiness"])["http"])
	exercise := rawMap(t, phases["exercise"])
	driver := rawMap(t, exercise["driver"])
	cleanup := rawMap(t, phases["cleanup"])
	cleanupSteps := rawSlice(t, cleanup["steps"])
	signal := rawMap(t, rawMap(t, cleanupSteps[0])["signal"])
	return readiness, driver, signal
}

func runCLI(t *testing.T, dependencies cli.Dependencies, args ...string) emittedEnvelope {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := cli.App{
		Deps:   dependencies,
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if exitCode := app.Run(context.Background(), args); exitCode != 0 {
		t.Fatalf("CLI exit code = %d; stderr: %s; stdout: %s", exitCode, stderr.String(), stdout.String())
	}
	var envelope emittedEnvelope
	decodeJSON(t, stdout.Bytes(), &envelope)
	if envelope.Status != "ok" || envelope.Error != nil {
		t.Fatalf("CLI emitted status %q and error %#v", envelope.Status, envelope.Error)
	}
	return envelope
}

func verificationFromEnvelope(t *testing.T, envelope emittedEnvelope) json.RawMessage {
	t.Helper()
	var data emittedVerification
	decodeJSON(t, envelope.Data, &data)
	if len(data.Verification) == 0 {
		t.Fatal("verify envelope did not include verification")
	}
	return data.Verification
}

func validateJSON(t *testing.T, schema *jsonschema.Schema, raw json.RawMessage) {
	t.Helper()
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode emitted JSON: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("emitted JSON does not validate against %s: %v\n%s", schema.Location, err, raw)
	}
}

func decodeJSON(t *testing.T, data []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(data, destination); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, data)
	}
}

func healthyManifest(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(
		"..", "testdata", "fixtures", "healthy", "healthy-node-cli", "repo-passport.yml",
	))
	if err != nil {
		t.Fatalf("resolve healthy manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("healthy manifest: %v", err)
	}
	return path
}

func healthyHTTPManifest(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(
		"..",
		"testdata",
		"fixtures",
		"healthy",
		"healthy-python-http",
		"repo-passport.yml",
	))
	if err != nil {
		t.Fatalf("resolve healthy HTTP manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("healthy HTTP manifest: %v", err)
	}
	return path
}

func fullyObservedRunner() domain.RunnerFeatures {
	return domain.RunnerFeatures{
		Backend:                    "schema-test",
		Available:                  true,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 "linux",
		Rootless:                   "yes",
		NetworkDeny:                true,
		NetworkAttemptObservation:  "full",
		ProcessExecObservation:     "full",
		FilesystemWriteObservation: "full",
		FilesystemReadObservation:  "full",
		PortObservation:            "full",
		ResourceUsage:              "full",
		ResourceLimitEnforcement:   true,
		EngineVersion:              "0.1.0",
	}
}

func unavailableRunner() domain.RunnerFeatures {
	return domain.RunnerFeatures{
		Backend:                    "schema-test",
		Available:                  false,
		ControllerOS:               runtime.GOOS,
		WorkloadOS:                 "linux",
		Rootless:                   "unknown",
		NetworkDeny:                false,
		NetworkAttemptObservation:  "unavailable",
		ProcessExecObservation:     "unavailable",
		FilesystemWriteObservation: "unavailable",
		FilesystemReadObservation:  "unavailable",
		PortObservation:            "unavailable",
		ResourceUsage:              "unavailable",
		Reason:                     "schema-contract-test runner is unavailable",
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
