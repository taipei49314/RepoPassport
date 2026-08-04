package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

func TestOperationNotificationRunnerEligibilityDispatchMatrix(t *testing.T) {
	prepared := operationNotificationRunnerPrepared("python", "cli", "foreground")
	if eligible, failure := operationNotificationEligible(prepared); !eligible || failure != "" {
		t.Fatalf("Python CLI foreground rejected: eligible=%v failure=%q", eligible, failure)
	}
	prepared = operationNotificationRunnerPrepared("python", "cli", "journey")
	if eligible, failure := operationNotificationEligible(prepared); !eligible || failure != "" {
		t.Fatalf("Python CLI journey rejected: eligible=%v failure=%q", eligible, failure)
	}

	tests := []struct {
		name    string
		adapter string
		driver  string
		role    string
	}{
		{name: "node", adapter: "node", driver: "cli", role: "journey"},
		{name: "http", adapter: "python", driver: "http", role: "service"},
		{name: "service", adapter: "python", driver: "cli", role: "service"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared := operationNotificationRunnerPrepared(
				test.adapter,
				test.driver,
				test.role,
			)
			if eligible, _ := operationNotificationEligible(prepared); eligible {
				t.Fatal("unsupported comparison tuple was accepted")
			}
		})
	}
}

func TestOperationNotificationRunnerCountsOnlyVerifiedDispatchBoundaries(
	t *testing.T,
) {
	containerID := strings.Repeat("c", 64)
	prepared := operationNotificationRunnerPrepared(
		"python",
		"cli",
		"journey",
	)
	prepared.RunID = "test1234"
	executor := &fakeExecutor{handler: func(
		_ context.Context,
		_ string,
		args []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		switch {
		case len(args) > 0 && args[0] == "inspect":
			_, _ = io.WriteString(
				stdout,
				`{"id":"`+containerID+`","runLabel":"test1234"}`+"\n",
			)
			return 0, nil
		case containsArgument(args, pythonWorkloadQuiescenceCheckScript):
			return 0, nil
		default:
			return -1, io.ErrUnexpectedEOF
		}
	}}
	comparison := newOperationNotificationObservationState(prepared, true)
	activity := activityTraceObservationState{containerID: containerID}
	runner := testRunner(executor)
	runner.verifyOperationNotificationQuiescenceBoundary(
		prepared,
		&activity,
		&comparison,
		true,
	)
	runner.verifyOperationNotificationQuiescenceBoundary(
		prepared,
		&activity,
		&comparison,
		false,
	)
	if comparison.failure != "" ||
		comparison.preDispatchQuiescenceChecks != 1 ||
		comparison.postDispatchQuiescenceChecks != 1 {
		t.Fatalf("verified boundary state = %#v", comparison)
	}

	failed := newOperationNotificationObservationState(prepared, true)
	activity.containerID = "mutable-name"
	runner.verifyOperationNotificationQuiescenceBoundary(
		prepared,
		&activity,
		&failed,
		true,
	)
	if failed.preDispatchQuiescenceVerified ||
		failed.preDispatchQuiescenceChecks != 0 ||
		failed.failure != "pre-dispatch-quiescence-failed" {
		t.Fatalf("failed boundary counted as verified: %#v", failed)
	}
}

func TestOperationNotificationQuiescenceChurnFailsClosed(t *testing.T) {
	containerID := strings.Repeat("d", 64)
	prepared := operationNotificationRunnerPrepared(
		"python",
		"cli",
		"foreground",
	)
	prepared.RunID = "test1234"
	executor := &fakeExecutor{handler: func(
		_ context.Context,
		_ string,
		args []string,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if len(args) > 0 && args[0] == "inspect" {
			_, _ = io.WriteString(
				stdout,
				`{"id":"`+containerID+`","runLabel":"test1234"}`+"\n",
			)
			return 0, nil
		}
		if containsArgument(args, pythonWorkloadQuiescenceCheckScript) {
			return 1, io.ErrUnexpectedEOF
		}
		return -1, io.ErrUnexpectedEOF
	}}
	comparison := newOperationNotificationObservationState(prepared, true)
	activity := activityTraceObservationState{containerID: containerID}
	testRunner(executor).verifyOperationNotificationQuiescenceBoundary(
		prepared,
		&activity,
		&comparison,
		true,
	)
	if comparison.failure != "pre-dispatch-quiescence-failed" ||
		comparison.preDispatchQuiescenceVerified ||
		comparison.preDispatchQuiescenceChecks != 0 {
		t.Fatalf("quiescence churn was accepted: %#v", comparison)
	}
}

func TestOperationNotificationRunStepAccountsOnlyConfirmedDispatch(
	t *testing.T,
) {
	prepared := operationNotificationRunnerPrepared(
		"python",
		"cli",
		"foreground",
	)
	step := preparedStep{
		command: domain.PlanCommand{
			ID:    "dispatch",
			Phase: domain.PhaseRun,
			Role:  "foreground",
			Argv:  []string{"python", "-c", "pass"},
		},
		timeout: time.Second,
	}
	for _, test := range []struct {
		name      string
		exitCode  int
		err       error
		confirmed bool
	}{
		{name: "successful dispatch", exitCode: 0, confirmed: true},
		{name: "exec setup failure", exitCode: -1, err: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{handler: func(
				_ context.Context,
				_ string,
				_ []string,
				_ io.Writer,
				_ io.Writer,
			) (int, error) {
				return test.exitCode, test.err
			}}
			execution := testRunner(executor).runStep(
				context.Background(),
				prepared,
				step,
				"repopass-test1234",
			)
			if execution.dispatchConfirmed != test.confirmed {
				t.Fatalf(
					"dispatchConfirmed = %v, want %v: %#v",
					execution.dispatchConfirmed,
					test.confirmed,
					execution,
				)
			}
		})
	}
}

func TestOperationNotificationSummaryRequiresOnePreAndPostCheckPerWindow(
	t *testing.T,
) {
	activity := completeOperationNotificationRunnerActivity(2)
	comparison := operationNotificationObservationState{
		required:                       true,
		eligible:                       true,
		phaseAcknowledgementsComplete:  true,
		preDispatchQuiescenceVerified:  true,
		postDispatchQuiescenceVerified: true,
		preDispatchQuiescenceChecks:    2,
		postDispatchQuiescenceChecks:   1,
		confirmedDispatches:            2,
	}
	event, finding := summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	if event.Result != "unavailable" ||
		event.Details["comparisonResult"] != operationNotificationResultUntested ||
		finding != nil {
		t.Fatalf("mismatched window gates published evidence: %#v %#v", event, finding)
	}
	if _, present := event.Details["windowCount"]; present {
		t.Fatalf("mismatched window gates published partial counts: %#v", event.Details)
	}

	comparison.postDispatchQuiescenceChecks = 2
	event, finding = summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	if event.Result != "observed" ||
		event.Details["comparisonResult"] != operationNotificationResultPositive ||
		event.Details["quiescenceWindowCount"] != 2 || finding == nil {
		t.Fatalf("matched window gates rejected: %#v %#v", event, finding)
	}
}

func TestOperationNotificationUnconfirmedDispatchFailsClosed(t *testing.T) {
	activity := completeOperationNotificationRunnerActivity(1)
	comparison := operationNotificationObservationState{
		required:                       true,
		eligible:                       true,
		phaseAcknowledgementsComplete:  true,
		preDispatchQuiescenceVerified:  true,
		postDispatchQuiescenceVerified: true,
		preDispatchQuiescenceChecks:    1,
		postDispatchQuiescenceChecks:   1,
	}
	recordOperationNotificationDispatch(&comparison, false)
	event, finding := summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	if comparison.failure != "workload-dispatch-unconfirmed" ||
		event.Result != "unavailable" ||
		event.Details["comparisonResult"] != operationNotificationResultUntested ||
		finding != nil {
		t.Fatalf("unconfirmed dispatch published comparison: %#v %#v", event, finding)
	}
	for _, key := range []string{
		"windowCount", "quiescenceWindowCount", "comparedNotificationCount",
		"undeclaredNotificationCount", "mutationCounts",
	} {
		if _, present := event.Details[key]; present {
			t.Fatalf("unconfirmed dispatch exposed partial %q: %#v", key, event.Details)
		}
	}

	comparison.failure = ""
	recordOperationNotificationDispatch(&comparison, true)
	event, finding = summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	if event.Result != "observed" || finding == nil {
		t.Fatalf("confirmed dispatch rejected: %#v %#v", event, finding)
	}
}

func TestOperationNotificationEligibleCleanupDoesNotCreateDispatchWindow(
	t *testing.T,
) {
	writer := &operationNotificationRunnerWriter{}
	activity := activityTraceObservationState{
		ready:                 true,
		readyIdentityVerified: true,
		session: &activityTraceSession{
			token:           strings.Repeat("a", 64),
			expectedAdapter: "python-inotify-linux",
			stdin:           writer,
			stream:          newOperationNotificationFrameStream(),
		},
	}
	comparison := operationNotificationObservationState{
		required: true,
		eligible: true,
	}
	markOutputsActivityPhase(
		&activity,
		&comparison,
		domain.ResolvedPlan{},
		domain.PhaseCleanup,
		false,
	)
	if writer.Len() != 0 || activity.session.operationWindowSequence != 0 {
		t.Fatalf(
			"non-dispatch cleanup created a window: bytes=%q sequence=%d",
			writer.String(),
			activity.session.operationWindowSequence,
		)
	}
}

func TestUnsupportedPythonActivityUsesAckCompatibleEmptyRules(t *testing.T) {
	token := strings.Repeat("b", 64)
	digest := activityTraceSessionDigest(token)
	stream := newOperationNotificationFrameStream()
	ack, err := json.Marshal(map[string]any{
		"type":            "phase-ack",
		"schemaVersion":   "1",
		"sessionDigest":   digest,
		"observerAdapter": "python-inotify-linux",
		"phase":           "exercise",
		"ruleCount":       0,
		"windowSequence":  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = stream.Write(append(ack, '\n'))
	writer := &operationNotificationRunnerWriter{}
	activity := activityTraceObservationState{
		ready:                 true,
		readyIdentityVerified: true,
		phaseSignalsComplete:  true,
		session: &activityTraceSession{
			token:           token,
			sessionDigest:   digest,
			expectedAdapter: "python-inotify-linux",
			stdin:           writer,
			stream:          stream,
		},
	}
	comparison := operationNotificationObservationState{
		required: true,
		eligible: false,
	}
	markOutputsActivityPhase(
		&activity,
		&comparison,
		domain.ResolvedPlan{},
		domain.PhaseExercise,
		true,
	)
	if activity.session == nil || !activity.phaseSignalsComplete {
		t.Fatalf("ACK-compatible unsupported activity failed: %#v", activity)
	}
	var control struct {
		Command string                      `json:"command"`
		Token   string                      `json:"token"`
		Phase   string                      `json:"phase"`
		Rules   []operationNotificationRule `json:"rules"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(writer.Bytes()), &control); err != nil {
		t.Fatal(err)
	}
	if control.Command != "phase" || control.Phase != "exercise" ||
		control.Token != token || control.Rules == nil || len(control.Rules) != 0 {
		t.Fatalf("unsupported Python control is not empty-rule ACK protocol: %#v", control)
	}
}

func TestOperationNotificationPositiveFindingPrecedesRetainedFindingContract(
	t *testing.T,
) {
	activity := completeOperationNotificationRunnerActivity(1)
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
	_, notificationFinding := summarizeOperationNotifications(
		activity,
		comparison,
		time.Unix(1, 0),
	)
	retainedFinding := filesystemDeclarationFinding(
		filesystemDeclarationComparison{
			Result:                "nonconforming-retained-state",
			UndeclaredChangeCount: 1,
		},
	)
	if notificationFinding == nil || retainedFinding == nil {
		t.Fatalf(
			"positive comparison prerequisites missing: notification=%#v retained=%#v",
			notificationFinding,
			retainedFinding,
		)
	}
	selected := selectFilesystemDeclarationFinding(
		notificationFinding,
		retainedFinding,
	)
	if selected != notificationFinding ||
		selected.Code != domain.CodeUndeclaredFilesystemWrite {
		t.Fatalf("finding precedence = %#v", selected)
	}
	if fallback := selectFilesystemDeclarationFinding(nil, retainedFinding); fallback != retainedFinding {
		t.Fatalf("retained fallback = %#v", fallback)
	}
}

func operationNotificationRunnerPrepared(
	adapter string,
	driver string,
	role string,
) *PreparedRun {
	plan := domain.ResolvedPlan{
		RuntimeAdapter: adapter,
		JourneyDriver:  driver,
		Commands: []domain.PlanCommand{{
			Phase: domain.PhaseExercise,
			Role:  role,
		}},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {
				Filesystem: domain.FilesystemCapability{
					Write: []string{"/outputs/**"},
				},
			},
		},
	}
	if driver == "http" {
		plan.HTTPJourney = &domain.PlanHTTPJourney{}
	}
	return sealPreparedRunForTest(&PreparedRun{
		Backend: "docker",
		Runner: domain.RunnerFeatures{
			Available:  true,
			WorkloadOS: "linux",
		},
		Plan: plan,
	})
}

func completeOperationNotificationRunnerActivity(
	windows int,
) activityTraceObservationState {
	return activityTraceObservationState{
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
			ObserverAdapter: "python-inotify-linux",
			OperationNotification: &operationNotificationResult{
				WindowCount:                 windows,
				ComparedNotificationCount:   1,
				UndeclaredNotificationCount: 1,
				CreateNotificationCount:     1,
				ComparisonResult:            operationNotificationResultPositive,
			},
		},
	}
}

type operationNotificationRunnerWriter struct {
	bytes.Buffer
}

func (*operationNotificationRunnerWriter) Close() error { return nil }
