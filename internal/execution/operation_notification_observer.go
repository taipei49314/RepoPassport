package execution

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const (
	operationNotificationResultPositive = "nonconforming-notifications"
	operationNotificationResultClear    = "no-undeclared-observed"
	operationNotificationResultUntested = "not-tested"
	operationNotificationObserver       = "docker-python-outputs-inotify-comparison"
)

type operationNotificationRule struct {
	Kind string `json:"kind"`
	Base string `json:"base"`
}

type operationNotificationResult struct {
	WindowCount                 int
	DeclaredPatternCount        int
	ComparedNotificationCount   int
	AllowedNotificationCount    int
	UndeclaredNotificationCount int
	CreateNotificationCount     int
	DeleteNotificationCount     int
	WriteNotificationCount      int
	RenameNotificationCount     int
	MetadataNotificationCount   int
	ComparisonResult            string
}

type operationNotificationPhaseAck struct {
	Type            string
	SchemaVersion   string
	SessionDigest   string
	ObserverAdapter string
	Phase           string
	RuleCount       int
	WindowSequence  int
}

// operationNotificationObservationState contains only controller-side gates.
// Notification aggregates remain in activityTraceResult and are publishable
// only when every gate below and every activity-trace integrity gate succeeds.
type operationNotificationObservationState struct {
	required                       bool
	eligible                       bool
	eligibilityFailure             string
	phaseAcknowledgementsComplete  bool
	preDispatchQuiescenceVerified  bool
	postDispatchQuiescenceVerified bool
	preDispatchQuiescenceChecks    int
	postDispatchQuiescenceChecks   int
	confirmedDispatches            int
	failure                        string
}

func newOperationNotificationObservationState(
	prepared *PreparedRun,
	required bool,
) operationNotificationObservationState {
	eligible, failure := operationNotificationEligible(prepared)
	return operationNotificationObservationState{
		required:                       required,
		eligible:                       eligible,
		eligibilityFailure:             failure,
		phaseAcknowledgementsComplete:  true,
		preDispatchQuiescenceVerified:  true,
		postDispatchQuiescenceVerified: true,
	}
}

func operationNotificationEligible(
	prepared *PreparedRun,
) (bool, string) {
	if prepared == nil || prepared.Backend != "docker" {
		return false, "unsupported-backend"
	}
	if !prepared.Runner.Available || prepared.Runner.WorkloadOS != "linux" {
		return false, "unsupported-workload-os"
	}
	plan := prepared.executionPlan
	if !prepared.executionPlanSealed {
		plan = prepared.Plan
	}
	if plan.RuntimeAdapter != "python" {
		return false, "unsupported-runtime-adapter"
	}
	if plan.JourneyDriver != "cli" || plan.HTTPJourney != nil {
		return false, "unsupported-journey-driver"
	}
	hasSynchronousDispatch := false
	for _, command := range plan.Commands {
		switch command.Role {
		case "foreground":
			hasSynchronousDispatch = true
		case "journey":
			hasSynchronousDispatch = true
		default:
			return false, "asynchronous-workload-present"
		}
		if command.Signal != nil || command.Readiness != nil {
			return false, "asynchronous-workload-present"
		}
	}
	if !hasSynchronousDispatch {
		return false, "no-synchronous-dispatch"
	}
	for _, capability := range plan.Capabilities {
		if capability.Process.Background ||
			(capability.Process.BackgroundProcesses != nil &&
				*capability.Process.BackgroundProcesses) {
			return false, "background-process-capability"
		}
	}
	return true, ""
}

func compileOperationNotificationRules(
	plan domain.ResolvedPlan,
	phase domain.Phase,
) ([]operationNotificationRule, error) {
	capability, present := plan.Capabilities[phase]
	if !present {
		return []operationNotificationRule{}, nil
	}
	if len(capability.Filesystem.Write) > activityTraceOperationRuleLimit {
		return nil, errors.New("operation notification rule limit exceeded")
	}
	unique := make(map[operationNotificationRule]struct{})
	for _, pattern := range capability.Filesystem.Write {
		if !validFilesystemDeclarationPattern(pattern) {
			return nil, errors.New("operation notification rule is invalid")
		}
		rule := operationNotificationRule{Kind: "exact", Base: pattern}
		if strings.HasSuffix(pattern, "/**") {
			rule.Kind = "tree"
			rule.Base = strings.TrimSuffix(pattern, "/**")
		} else if strings.HasSuffix(pattern, "/*") {
			rule.Kind = "child"
			rule.Base = strings.TrimSuffix(pattern, "/*")
		}
		unique[rule] = struct{}{}
	}
	rules := make([]operationNotificationRule, 0, len(unique))
	for rule := range unique {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(left, right int) bool {
		if rules[left].Base != rules[right].Base {
			return rules[left].Base < rules[right].Base
		}
		return rules[left].Kind < rules[right].Kind
	})
	return rules, nil
}

func (s *activityTraceSession) setOperationNotificationPhase(
	ctx context.Context,
	phase domain.Phase,
	rules []operationNotificationRule,
) error {
	if s == nil || s.expectedAdapter != "python-inotify-linux" {
		return errors.New("operation notification comparison is unavailable")
	}
	if len(rules) > activityTraceOperationRuleLimit ||
		s.operationWindowSequence >= activityTraceOperationWindowLimit {
		return errors.New("operation notification control bound exceeded")
	}
	switch phase {
	case domain.PhaseSetup, domain.PhaseBuild, domain.PhaseRun,
		domain.PhaseExercise, domain.PhaseCleanup:
	default:
		return errors.New("operation notification phase is invalid")
	}
	for _, rule := range rules {
		validBase := rule.Base == containerOutputs ||
			validObservedFilesystemPath(rule.Base)
		if (rule.Kind != "exact" && rule.Kind != "child" &&
			rule.Kind != "tree") || !validBase {
			return errors.New("operation notification rule is invalid")
		}
	}
	control := struct {
		Command string                      `json:"command"`
		Token   string                      `json:"token"`
		Phase   string                      `json:"phase"`
		Rules   []operationNotificationRule `json:"rules"`
	}{
		Command: "phase",
		Token:   s.token,
		Phase:   string(phase),
		Rules:   rules,
	}
	if err := s.writeBoundedControl(
		ctx,
		control,
		activityTraceOperationControlLimit,
	); err != nil {
		return err
	}
	frame, err := s.stream.next(ctx)
	if err != nil {
		return errors.New("operation notification phase acknowledgement is unavailable")
	}
	expectedSequence := s.operationWindowSequence + 1
	ack, err := decodeOperationNotificationPhaseAck(
		frame,
		s.sessionDigest,
		string(phase),
		len(rules),
		expectedSequence,
	)
	if err != nil || ack.ObserverAdapter != s.expectedAdapter {
		return errors.New("operation notification phase acknowledgement is invalid")
	}
	s.operationWindowSequence = expectedSequence
	return nil
}

func markOperationNotificationPhase(
	activity *activityTraceObservationState,
	comparison *operationNotificationObservationState,
	plan domain.ResolvedPlan,
	phase domain.Phase,
) {
	if comparison == nil || !comparison.required || !comparison.eligible {
		return
	}
	if activity == nil || activity.session == nil || !activity.ready ||
		!activity.readyIdentityVerified {
		comparison.phaseAcknowledgementsComplete = false
		comparison.failure = "observer-not-ready"
		return
	}
	rules, err := compileOperationNotificationRules(plan, phase)
	if err == nil {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			activityTraceControlTimeout,
		)
		err = activity.session.setOperationNotificationPhase(ctx, phase, rules)
		cancel()
	}
	if err != nil {
		comparison.phaseAcknowledgementsComplete = false
		comparison.failure = "phase-control-failed"
		activity.phaseSignalsComplete = false
		activity.session.abort()
		activity.session = nil
	}
}

// markOutputsActivityPhase keeps the historical activity trace protocol
// working for every adapter while enabling rule acknowledgements only for the
// bounded Alpha.24 tuple. A non-dispatch phase hint is deliberately ignored by
// the eligible comparison so trusted-runner cleanup cannot manufacture an
// extra declaration window.
func markOutputsActivityPhase(
	activity *activityTraceObservationState,
	comparison *operationNotificationObservationState,
	plan domain.ResolvedPlan,
	phase domain.Phase,
	dispatch bool,
) {
	if comparison != nil && comparison.required && comparison.eligible {
		if dispatch {
			markOperationNotificationPhase(
				activity,
				comparison,
				plan,
				phase,
			)
		}
		return
	}
	if activity != nil && activity.session != nil &&
		activity.session.expectedAdapter == "python-inotify-linux" {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			activityTraceControlTimeout,
		)
		err := activity.session.setOperationNotificationPhase(
			ctx,
			phase,
			[]operationNotificationRule{},
		)
		cancel()
		if err != nil {
			activity.phaseSignalsComplete = false
			if activity.failure == "" {
				activity.failure = "phase-control-failed"
			}
			activity.session.abort()
			activity.session = nil
		}
		return
	}
	markActivityTracePhase(activity, phase)
}

func (r *Runner) verifyOperationNotificationQuiescenceBoundary(
	prepared *PreparedRun,
	activity *activityTraceObservationState,
	comparison *operationNotificationObservationState,
	preDispatch bool,
) {
	if comparison == nil || !comparison.required || !comparison.eligible {
		return
	}
	failure := "post-dispatch-quiescence-failed"
	if preDispatch {
		failure = "pre-dispatch-quiescence-failed"
	}
	if activity == nil ||
		!fullContainerIDPattern.MatchString(activity.containerID) {
		markOperationNotificationQuiescenceFailure(
			comparison,
			preDispatch,
			failure,
		)
		return
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		r.config.CreateTimeout,
	)
	err := r.inspectResourceContainerIdentity(
		ctx,
		prepared,
		activity.containerID,
	)
	if err == nil {
		err = r.verifyWorkloadProcessesQuiescent(
			ctx,
			prepared,
			activity.containerID,
		)
	}
	cancel()
	if err != nil {
		markOperationNotificationQuiescenceFailure(
			comparison,
			preDispatch,
			failure,
		)
		return
	}
	if preDispatch {
		comparison.preDispatchQuiescenceChecks++
	} else {
		comparison.postDispatchQuiescenceChecks++
	}
}

func markOperationNotificationQuiescenceFailure(
	comparison *operationNotificationObservationState,
	preDispatch bool,
	failure string,
) {
	if comparison == nil {
		return
	}
	if preDispatch {
		comparison.preDispatchQuiescenceVerified = false
	} else {
		comparison.postDispatchQuiescenceVerified = false
	}
	if comparison.failure == "" {
		comparison.failure = failure
	}
}

func recordOperationNotificationDispatch(
	comparison *operationNotificationObservationState,
	confirmed bool,
) {
	if comparison == nil || !comparison.required || !comparison.eligible {
		return
	}
	if !confirmed {
		if comparison.failure == "" {
			comparison.failure = "workload-dispatch-unconfirmed"
		}
		return
	}
	comparison.confirmedDispatches++
}

func decodeOperationNotificationPhaseAck(
	raw []byte,
	expectedSessionDigest string,
	expectedPhase string,
	expectedRuleCount int,
	expectedSequence int,
) (operationNotificationPhaseAck, error) {
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"type", "schemaVersion", "sessionDigest", "observerAdapter",
		"phase", "ruleCount", "windowSequence",
	}) {
		return operationNotificationPhaseAck{}, errors.New(
			"operation notification phase acknowledgement is invalid",
		)
	}
	ack := operationNotificationPhaseAck{}
	values := []struct {
		key    string
		target any
	}{
		{"type", &ack.Type},
		{"schemaVersion", &ack.SchemaVersion},
		{"sessionDigest", &ack.SessionDigest},
		{"observerAdapter", &ack.ObserverAdapter},
		{"phase", &ack.Phase},
		{"ruleCount", &ack.RuleCount},
		{"windowSequence", &ack.WindowSequence},
	}
	for _, value := range values {
		if decodeActivityTraceValue(fields[value.key], value.target) != nil {
			return operationNotificationPhaseAck{}, errors.New(
				"operation notification phase acknowledgement is invalid",
			)
		}
	}
	if ack.Type != "phase-ack" || ack.SchemaVersion != "1" ||
		ack.SessionDigest != expectedSessionDigest ||
		ack.ObserverAdapter != "python-inotify-linux" ||
		ack.Phase != expectedPhase || ack.RuleCount != expectedRuleCount ||
		ack.RuleCount < 0 || ack.RuleCount > activityTraceOperationRuleLimit ||
		ack.WindowSequence != expectedSequence || ack.WindowSequence < 1 ||
		ack.WindowSequence > activityTraceOperationWindowLimit {
		return operationNotificationPhaseAck{}, errors.New(
			"operation notification phase acknowledgement is invalid",
		)
	}
	return ack, nil
}

func validOperationNotificationResult(
	result operationNotificationResult,
	notificationCount int,
	renameHintCount int,
	changeHintCount int,
) bool {
	counts := []int{
		result.WindowCount,
		result.DeclaredPatternCount,
		result.ComparedNotificationCount,
		result.AllowedNotificationCount,
		result.UndeclaredNotificationCount,
		result.CreateNotificationCount,
		result.DeleteNotificationCount,
		result.WriteNotificationCount,
		result.RenameNotificationCount,
		result.MetadataNotificationCount,
	}
	for _, count := range counts {
		if count < 0 || count > activityTraceNotificationLimit {
			return false
		}
	}
	if result.WindowCount > activityTraceOperationWindowLimit ||
		result.DeclaredPatternCount >
			result.WindowCount*activityTraceOperationRuleLimit ||
		result.ComparedNotificationCount != notificationCount ||
		result.AllowedNotificationCount+
			result.UndeclaredNotificationCount != notificationCount ||
		result.CreateNotificationCount+result.DeleteNotificationCount+
			result.WriteNotificationCount+result.RenameNotificationCount+
			result.MetadataNotificationCount != notificationCount ||
		result.CreateNotificationCount+result.DeleteNotificationCount+
			result.RenameNotificationCount != renameHintCount ||
		result.WriteNotificationCount+
			result.MetadataNotificationCount != changeHintCount {
		return false
	}
	switch result.ComparisonResult {
	case operationNotificationResultPositive:
		return result.UndeclaredNotificationCount > 0
	case operationNotificationResultClear:
		return result.UndeclaredNotificationCount == 0
	default:
		return false
	}
}

func summarizeOperationNotifications(
	activity activityTraceObservationState,
	comparison operationNotificationObservationState,
	completedAt time.Time,
) (domain.ObservationEvent, *domain.Error) {
	comparisonResult := operationNotificationResultUntested
	publicResult := "unavailable"
	coverage := coverageUnavailable
	confidence := "unknown"
	complete := comparison.required && comparison.eligible &&
		comparison.failure == "" && activity.failure == "" &&
		comparison.phaseAcknowledgementsComplete &&
		comparison.preDispatchQuiescenceVerified &&
		comparison.postDispatchQuiescenceVerified &&
		activity.startIdentityVerified && activity.readyIdentityVerified &&
		activity.stopIdentityVerified && activity.finalIdentityVerified &&
		activity.workloadQuiescenceVerified && activity.ready &&
		activity.finalReady && activity.phaseSignalsComplete &&
		activity.result.ObserverAdapter == "python-inotify-linux" &&
		activity.result.OperationNotification != nil &&
		comparison.preDispatchQuiescenceChecks > 0 &&
		comparison.preDispatchQuiescenceChecks ==
			activity.result.OperationNotification.WindowCount &&
		comparison.postDispatchQuiescenceChecks ==
			activity.result.OperationNotification.WindowCount &&
		comparison.confirmedDispatches ==
			activity.result.OperationNotification.WindowCount &&
		!activity.result.OverflowDetected && !activity.result.GapDetected
	if complete {
		comparisonResult = activity.result.OperationNotification.ComparisonResult
		publicResult = "observed"
		coverage = coverageBestEffort
		confidence = "high"
	}
	details := map[string]any{
		"scope":                          "outputs-operation-notification-comparison",
		"publicEvidence":                 "aggregate-only",
		"rawPathIncluded":                false,
		"ruleTextIncluded":               false,
		"contentIncluded":                false,
		"actorAttribution":               coverageUnavailable,
		"renamePairing":                  coverageUnavailable,
		"preDispatchQuiescenceVerified":  comparison.preDispatchQuiescenceVerified,
		"postDispatchQuiescenceVerified": comparison.postDispatchQuiescenceVerified,
		"phaseAcknowledgementsComplete":  comparison.phaseAcknowledgementsComplete,
		"notificationLimit":              activityTraceNotificationLimit,
		"ruleLimitPerWindow":             activityTraceOperationRuleLimit,
		"windowLimit":                    activityTraceOperationWindowLimit,
		"evidenceBasis":                  "aggregate-only",
		"comparisonResult":               comparisonResult,
		"blindSpots": []string{
			"outside-outputs", "read-and-syscall-history",
			"actor-and-process-attribution", "rename-pairing",
			"inotify-coalescing", "new-directory-watch-race",
		},
	}
	if complete {
		aggregate := activity.result.OperationNotification
		details["windowCount"] = aggregate.WindowCount
		details["quiescenceWindowCount"] =
			comparison.preDispatchQuiescenceChecks
		details["declaredPatternCount"] = aggregate.DeclaredPatternCount
		details["comparedNotificationCount"] = aggregate.ComparedNotificationCount
		details["allowedNotificationCount"] = aggregate.AllowedNotificationCount
		details["undeclaredNotificationCount"] = aggregate.UndeclaredNotificationCount
		details["mutationCounts"] = []string{
			fmt.Sprintf("create=%d", aggregate.CreateNotificationCount),
			fmt.Sprintf("delete=%d", aggregate.DeleteNotificationCount),
			fmt.Sprintf("write=%d", aggregate.WriteNotificationCount),
			fmt.Sprintf("rename=%d", aggregate.RenameNotificationCount),
			fmt.Sprintf("metadata=%d", aggregate.MetadataNotificationCount),
		}
	}
	failure := comparison.failure
	if failure == "" {
		failure = comparison.eligibilityFailure
	}
	if failure == "" && comparisonResult == operationNotificationResultUntested {
		failure = activity.failure
		if failure == "" {
			failure = activity.result.Failure
		}
	}
	if failure != "" {
		details["failure"] = failure
	}
	timestamp := activity.observedAt
	if timestamp.IsZero() {
		timestamp = completedAt
	}
	event := domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "filesystem.operation-notification.summary",
		Resource:      containerOutputs,
		Result:        publicResult,
		Observer:      operationNotificationObserver,
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       details,
	}
	if complete && comparisonResult == operationNotificationResultPositive {
		return event, &domain.Error{
			SchemaVersion: "1",
			Code:          domain.CodeUndeclaredFilesystemWrite,
			Severity:      domain.SeverityHigh,
			Message:       "Filesystem mutation notifications exceeded the active phase's declared write scope.",
			Details: map[string]any{
				"observer":                    operationNotificationObserver,
				"evidenceBasis":               "aggregate-only",
				"undeclaredNotificationCount": activity.result.OperationNotification.UndeclaredNotificationCount,
			},
			EvidenceRefs: []string{},
			Retryable:    false,
		}
	}
	return event, nil
}

func selectFilesystemDeclarationFinding(
	operationNotification *domain.Error,
	retainedState *domain.Error,
) *domain.Error {
	if operationNotification != nil {
		return operationNotification
	}
	return retainedState
}
