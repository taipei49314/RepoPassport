package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

func TestCompileOperationNotificationRulesLocksPhaseAndPatternSemantics(
	t *testing.T,
) {
	plan := domain.ResolvedPlan{Capabilities: map[domain.Phase]domain.CapabilitySet{
		domain.PhaseRun: {
			Filesystem: domain.FilesystemCapability{Write: []string{
				"/outputs/z/**",
				"/outputs/a/*",
				"/outputs/literal[1]*",
				"/outputs/a/*",
			}},
		},
		domain.PhaseBuild: {
			Filesystem: domain.FilesystemCapability{Write: []string{
				"/outputs/build-only",
			}},
		},
	}}
	rules, err := compileOperationNotificationRules(plan, domain.PhaseRun)
	if err != nil {
		t.Fatal(err)
	}
	want := []operationNotificationRule{
		{Kind: "child", Base: "/outputs/a"},
		{Kind: "exact", Base: "/outputs/literal[1]*"},
		{Kind: "tree", Base: "/outputs/z"},
	}
	if len(rules) != len(want) {
		t.Fatalf("rules = %#v, want %#v", rules, want)
	}
	for index := range want {
		if rules[index] != want[index] {
			t.Fatalf("rules = %#v, want %#v", rules, want)
		}
	}
	for _, rule := range rules {
		if strings.Contains(rule.Base, "build-only") {
			t.Fatalf("another phase leaked into controls: %#v", rules)
		}
	}

	tooMany := make([]string, activityTraceOperationRuleLimit+1)
	for index := range tooMany {
		tooMany[index] = "/outputs/" + strings.Repeat("x", index%8+1)
	}
	plan.Capabilities[domain.PhaseRun] = domain.CapabilitySet{
		Filesystem: domain.FilesystemCapability{Write: tooMany},
	}
	if _, err := compileOperationNotificationRules(
		plan,
		domain.PhaseRun,
	); err == nil {
		t.Fatal("phase rule count above 256 was accepted")
	}

	plan.Capabilities[domain.PhaseRun] = domain.CapabilitySet{
		Filesystem: domain.FilesystemCapability{Write: []string{"/tmp/**"}},
	}
	if _, err := compileOperationNotificationRules(
		plan,
		domain.PhaseRun,
	); err == nil {
		t.Fatal("out-of-root rule was accepted")
	}
}

func TestOperationNotificationEligibilityIsPythonCLIForegroundOnly(t *testing.T) {
	base := PreparedRun{
		Backend: "docker",
		Runner: domain.RunnerFeatures{
			Available:  true,
			WorkloadOS: "linux",
		},
		Plan: domain.ResolvedPlan{
			RuntimeAdapter: "python",
			JourneyDriver:  "cli",
			Commands: []domain.PlanCommand{{
				Role: "foreground",
			}},
			Capabilities: map[domain.Phase]domain.CapabilitySet{},
		},
	}
	if eligible, failure := operationNotificationEligible(&base); !eligible || failure != "" {
		t.Fatalf("eligible tuple rejected: eligible=%v failure=%q", eligible, failure)
	}
	journeyOnly := base
	journeyOnly.Plan.Commands = []domain.PlanCommand{{Role: "journey"}}
	if eligible, failure := operationNotificationEligible(&journeyOnly); !eligible || failure != "" {
		t.Fatalf("CLI journey dispatch rejected: eligible=%v failure=%q", eligible, failure)
	}

	tests := map[string]func(*PreparedRun){
		"node": func(value *PreparedRun) {
			value.Plan.RuntimeAdapter = "node"
		},
		"http": func(value *PreparedRun) {
			value.Plan.JourneyDriver = "http"
		},
		"service": func(value *PreparedRun) {
			value.Plan.Commands[0].Role = "service"
		},
		"background": func(value *PreparedRun) {
			value.Plan.Capabilities[domain.PhaseRun] = domain.CapabilitySet{
				Process: domain.ProcessCapability{Background: true},
			}
		},
		"podman": func(value *PreparedRun) {
			value.Backend = "podman"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copied := base
			copied.Plan.Commands = append(
				[]domain.PlanCommand(nil),
				base.Plan.Commands...,
			)
			copied.Plan.Capabilities = map[domain.Phase]domain.CapabilitySet{}
			mutate(&copied)
			if eligible, _ := operationNotificationEligible(&copied); eligible {
				t.Fatal("unsupported tuple was accepted")
			}
		})
	}
}

func TestOperationNotificationPhaseControlRequiresExactAck(t *testing.T) {
	token := strings.Repeat("a", 64)
	digest := activityTraceSessionDigest(token)
	stream := newOperationNotificationFrameStream()
	ack := map[string]any{
		"type":            "phase-ack",
		"schemaVersion":   "1",
		"sessionDigest":   digest,
		"observerAdapter": "python-inotify-linux",
		"phase":           "run",
		"ruleCount":       1,
		"windowSequence":  1,
	}
	rawAck, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(append(rawAck, '\n')); err != nil {
		t.Fatal(err)
	}
	writer := &operationNotificationTestWriter{}
	session := &activityTraceSession{
		token:           token,
		sessionDigest:   digest,
		expectedAdapter: "python-inotify-linux",
		stdin:           writer,
		stream:          stream,
	}
	if err := session.setOperationNotificationPhase(
		context.Background(),
		domain.PhaseRun,
		[]operationNotificationRule{{Kind: "tree", Base: "/outputs/cache"}},
	); err != nil {
		t.Fatal(err)
	}
	if session.operationWindowSequence != 1 {
		t.Fatalf("window sequence = %d", session.operationWindowSequence)
	}
	var control map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(writer.Bytes()), &control); err != nil {
		t.Fatal(err)
	}
	if control["phase"] != "run" || control["token"] != token {
		t.Fatalf("control = %#v", control)
	}

	ack["rawPath"] = "/outputs/private"
	rawAck, _ = json.Marshal(ack)
	if _, err := decodeOperationNotificationPhaseAck(
		rawAck,
		digest,
		"run",
		1,
		1,
	); err == nil {
		t.Fatal("phase acknowledgement with an extra field was accepted")
	}
}

func TestPythonOperationNotificationHelperFailsClosedBeforePhaseAck(t *testing.T) {
	script := pythonActivityTraceScript
	pending := strings.Index(
		script,
		`if not failure and pending_notifications():latch("notification-gap")`,
	)
	activate := strings.Index(script, `phase=value["phase"]`)
	ack := strings.Index(script, `emit({"type":"phase-ack"`)
	if pending < 0 || activate <= pending || ack <= activate {
		t.Fatalf(
			"phase ACK is not ordered after pending-notification guard: pending=%d activate=%d ack=%d",
			pending,
			activate,
			ack,
		)
	}
	newDirectory := strings.Index(
		script,
		`if mask&IN_ISDIR and mask&(IN_CREATE|IN_MOVED_TO):latch("new-directory-watch-gap");return`,
	)
	count := strings.Index(script, "count+=1;counts[phase]+=1")
	if newDirectory < 0 || count <= newDirectory {
		t.Fatalf(
			"new-directory watch race is not rejected before aggregates: gap=%d count=%d",
			newDirectory,
			count,
		)
	}
	for _, marker := range []string{
		`if mask&IN_Q_OVERFLOW:latch("notification-overflow");return`,
		`if count>MAX_EVENTS:latch("notification-overflow");return`,
		`if not failure and pending_notifications():latch("notification-gap")`,
		`emit({"type":"phase-ack"`,
		`emit({"type":"failed"`,
		`if failure:failed()`,
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("latched fail-closed lifecycle marker %q is absent", marker)
		}
	}
}

func TestPythonOperationNotificationTypedFailurePublishesNoAggregates(
	t *testing.T,
) {
	digest := activityTraceSessionDigest(strings.Repeat("b", 64))
	for _, failure := range []string{
		activityTraceFailureOverflow,
		activityTraceFailureNewDirectoryGap,
		activityTraceFailureGap,
	} {
		t.Run(failure, func(t *testing.T) {
			result, err := decodeActivityTraceFinalFrame(
				validActivityTraceFailedJSON(digest, failure),
				digest,
				"python-inotify-linux",
			)
			if err != nil || result.Failure != failure ||
				result.OperationNotification != nil ||
				result.NotificationCount != 0 ||
				result.CanonicalTranscriptDigest != "" {
				t.Fatalf("typed failed result=%#v err=%v", result, err)
			}
			activity := activityTraceObservationState{
				required:                   true,
				backendEligible:            true,
				startIdentityVerified:      true,
				readyIdentityVerified:      true,
				stopIdentityVerified:       true,
				finalIdentityVerified:      true,
				workloadQuiescenceVerified: true,
				ready:                      true,
				finalReady:                 true,
				phaseSignalsComplete:       true,
				result:                     result,
			}
			comparison := operationNotificationObservationState{
				required:                       true,
				eligible:                       true,
				phaseAcknowledgementsComplete:  true,
				preDispatchQuiescenceVerified:  true,
				postDispatchQuiescenceVerified: true,
				preDispatchQuiescenceChecks:    1,
				postDispatchQuiescenceChecks:   1,
				confirmedDispatches:            1,
			}
			event, finding := summarizeOperationNotifications(
				activity,
				comparison,
				time.Unix(1, 0),
			)
			if event.Result != "unavailable" ||
				event.Coverage != coverageUnavailable || finding != nil ||
				event.Details["comparisonResult"] !=
					operationNotificationResultUntested ||
				event.Details["failure"] != failure {
				t.Fatalf("typed failure summary=%#v finding=%#v", event, finding)
			}
			for _, key := range []string{
				"windowCount", "declaredPatternCount",
				"comparedNotificationCount", "allowedNotificationCount",
				"undeclaredNotificationCount", "mutationCounts",
			} {
				if _, present := event.Details[key]; present {
					t.Fatalf("typed failure exposed %s: %#v", key, event.Details)
				}
			}
		})
	}
}

func TestPythonOperationNotificationFinalIsBoundedAndAlgebraic(t *testing.T) {
	digest := activityTraceSessionDigest(strings.Repeat("b", 64))
	valid := validPythonOperationNotificationFinal(t, digest)
	result, err := decodeActivityTraceFinalFrame(
		valid,
		digest,
		"python-inotify-linux",
	)
	if err != nil || result.OperationNotification == nil ||
		result.OperationNotification.ComparisonResult !=
			operationNotificationResultPositive {
		t.Fatalf("valid Python final rejected: result=%#v err=%v", result, err)
	}

	var base map[string]any
	if err := json.Unmarshal(valid, &base); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"partial-counts": func(value map[string]any) {
			delete(value, "metadataNotificationCount")
		},
		"allowed-algebra": func(value map[string]any) {
			value["allowedNotificationCount"] = 1
		},
		"category-algebra": func(value map[string]any) {
			value["createNotificationCount"] = 0
		},
		"false-clear": func(value map[string]any) {
			value["comparisonResult"] = operationNotificationResultClear
		},
		"too-many-rules": func(value map[string]any) {
			value["declaredPatternCount"] =
				activityTraceOperationRuleLimit + 1
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copied := make(map[string]any, len(base))
			for key, value := range base {
				copied[key] = value
			}
			mutate(copied)
			raw, _ := json.Marshal(copied)
			if _, err := decodeActivityTraceFinalFrame(
				raw,
				digest,
				"python-inotify-linux",
			); err == nil {
				t.Fatal("invalid Python final was accepted")
			}
		})
	}

	if _, err := decodeActivityTraceFinalFrame(
		validActivityTraceFinalJSON(digest, "node-fs-watch-linux"),
		digest,
		"node-fs-watch-linux",
	); err != nil {
		t.Fatalf("Node final compatibility changed: %v", err)
	}
}

func TestOperationNotificationSummaryPublishesAggregatesOnly(t *testing.T) {
	aggregate := &operationNotificationResult{
		WindowCount:                 1,
		DeclaredPatternCount:        1,
		ComparedNotificationCount:   1,
		UndeclaredNotificationCount: 1,
		CreateNotificationCount:     1,
		ComparisonResult:            operationNotificationResultPositive,
	}
	activity := activityTraceObservationState{
		required:                   true,
		backendEligible:            true,
		startIdentityVerified:      true,
		readyIdentityVerified:      true,
		stopIdentityVerified:       true,
		finalIdentityVerified:      true,
		workloadQuiescenceVerified: true,
		ready:                      true,
		finalReady:                 true,
		phaseSignalsComplete:       true,
		result: activityTraceResult{
			ObserverAdapter:       "python-inotify-linux",
			OperationNotification: aggregate,
		},
	}
	comparison := operationNotificationObservationState{
		required:                       true,
		eligible:                       true,
		phaseAcknowledgementsComplete:  true,
		preDispatchQuiescenceVerified:  true,
		postDispatchQuiescenceVerified: true,
		preDispatchQuiescenceChecks:    1,
		postDispatchQuiescenceChecks:   1,
		confirmedDispatches:            1,
	}
	event, finding := summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	if event.Result != "observed" ||
		event.Details["comparisonResult"] != operationNotificationResultPositive ||
		event.Coverage != coverageBestEffort || finding == nil ||
		finding.Code != domain.CodeUndeclaredFilesystemWrite ||
		finding.Phase != "" {
		t.Fatalf("summary=%#v finding=%#v", event, finding)
	}
	raw, err := json.Marshal(struct {
		Event   domain.ObservationEvent `json:"event"`
		Finding *domain.Error           `json:"finding"`
	}{event, finding})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"/outputs/private", "write-rule-marker", strings.Repeat("a", 64),
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("private marker leaked: %q in %s", forbidden, raw)
		}
	}

	comparison.postDispatchQuiescenceVerified = false
	event, finding = summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	if event.Result != "unavailable" ||
		event.Details["comparisonResult"] != operationNotificationResultUntested ||
		finding != nil {
		t.Fatalf("incomplete comparison published positive evidence: %#v %#v", event, finding)
	}
	if _, present := event.Details["undeclaredNotificationCount"]; present {
		t.Fatalf("partial positive count published: %#v", event.Details)
	}
}

func validPythonOperationNotificationFinal(
	t *testing.T,
	digest string,
) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(
		validActivityTraceFinalJSON(digest, "python-inotify-linux"),
		&value,
	); err != nil {
		t.Fatal(err)
	}
	value["windowCount"] = 1
	value["declaredPatternCount"] = 1
	value["comparedNotificationCount"] = 1
	value["allowedNotificationCount"] = 0
	value["undeclaredNotificationCount"] = 1
	value["createNotificationCount"] = 1
	value["deleteNotificationCount"] = 0
	value["writeNotificationCount"] = 0
	value["renameNotificationCount"] = 0
	value["metadataNotificationCount"] = 0
	value["comparisonResult"] = operationNotificationResultPositive
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type operationNotificationTestWriter struct {
	bytes.Buffer
}

func (*operationNotificationTestWriter) Close() error { return nil }
