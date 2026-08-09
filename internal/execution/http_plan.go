package execution

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/structuredjson"
)

const (
	serviceSignalHelperSlack = 750 * time.Millisecond
)

func (r *Runner) validateHTTPPlan(plan domain.ResolvedPlan) error {
	if plan.HTTPJourney == nil {
		if plan.JourneyDriver == "http" {
			return planError(
				"journeyDriver=http requires a resolved HTTP journey.",
			)
		}
		for _, command := range plan.Commands {
			if command.Role == "service" ||
				command.Role == "signal" ||
				command.Readiness != nil {
				return planError(
					"Service lifecycle commands require a resolved HTTP journey.",
				)
			}
		}
		for _, assertion := range plan.JourneyAssertions {
			if assertion.Response != nil || assertion.JSONFile != nil {
				return planError(
					"HTTP response and JSON file assertions require a resolved HTTP journey.",
				)
			}
		}
		return nil
	}
	if plan.JourneyDriver != "http" {
		return planError(
			"Resolved HTTP journey requires journeyDriver=http.",
		)
	}
	for _, required := range []string{
		"background-service",
		"service-signal",
		"loopback-http-driver",
	} {
		if !containsExact(plan.RequiredRunnerFeatures, required) {
			return planError(
				fmt.Sprintf(
					"Resolved HTTP journey omitted required feature %q.",
					required,
				),
			)
		}
	}

	var service *domain.PlanCommand
	var signal *domain.PlanCommand
	signalIndex := -1
	for index := range plan.Commands {
		command := &plan.Commands[index]
		switch command.Role {
		case "service":
			if service != nil {
				return planError(
					"Resolved HTTP journey contains more than one service.",
				)
			}
			service = command
		case "signal":
			if signal != nil {
				return planError(
					"Resolved HTTP journey contains more than one service signal.",
				)
			}
			signal = command
			signalIndex = index
		case "journey":
			return planError(
				"Resolved HTTP journey must not contain a CLI journey command.",
			)
		}
	}
	if service == nil ||
		service.ID != plan.HTTPJourney.ServiceID ||
		service.Readiness == nil {
		return planError(
			"Resolved HTTP journey is not bound to exactly one ready service.",
		)
	}
	if signal == nil ||
		signal.Signal == nil ||
		signal.Signal.Target != service.ID {
		return planError(
			"Resolved HTTP service requires one matching cleanup signal.",
		)
	}
	if signalIndex != len(plan.Commands)-1 {
		return planError(
			"Resolved HTTP service signal must be the final command.",
		)
	}
	signalCommandTimeout, err := time.ParseDuration(signal.Timeout)
	if err != nil ||
		signalCommandTimeout <= serviceSignalHelperSlack ||
		signalCommandTimeout > r.config.MaxStepTimeout {
		return planError(
			"Resolved HTTP service signal timeout is invalid.",
		)
	}
	if r.config.CleanupTimeout <= serviceSignalHelperSlack {
		return planError(
			"Runner cleanup timeout leaves no bounded service signal window.",
		)
	}
	maximumSignalGrace :=
		r.config.CleanupTimeout - serviceSignalHelperSlack
	if maximumSignalGrace > domain.AlphaHTTPMaxSignalGrace {
		maximumSignalGrace = domain.AlphaHTTPMaxSignalGrace
	}
	signalGraceWindow :=
		signalCommandTimeout - serviceSignalHelperSlack
	if maximumSignalGrace > signalGraceWindow {
		maximumSignalGrace = signalGraceWindow
	}
	if err := validateSignal(
		*signal.Signal,
		maximumSignalGrace,
	); err != nil {
		return planError(err.Error())
	}

	readiness := service.Readiness
	if readiness.Status < domain.AlphaHTTPMinimumStatus ||
		readiness.Status > domain.AlphaHTTPMaximumStatus {
		return planError("Resolved HTTP readiness status is invalid.")
	}
	if err := validateLoopbackHTTPURL(readiness.URL); err != nil {
		return planError("Resolved HTTP readiness URL is unsafe.")
	}
	maximumReadiness := r.config.MaxStepTimeout
	if maximumReadiness > domain.AlphaHTTPMaxReadinessTime {
		maximumReadiness = domain.AlphaHTTPMaxReadinessTime
	}
	_, err = domain.ParseAlphaHTTPDuration(
		readiness.Timeout,
		maximumReadiness,
	)
	if err != nil {
		return planError("Resolved HTTP readiness timeout is invalid.")
	}
	if err := validateDeclaredServicePort(plan, readiness.URL); err != nil {
		return planError(err.Error())
	}
	for _, phase := range []domain.Phase{
		domain.PhaseRun,
		domain.PhaseExercise,
	} {
		capability, ok := plan.Capabilities[phase]
		if !ok || !capability.Network.Deny ||
			len(capability.Network.Allow) != 0 {
			return planError(
				"HTTP run and exercise phases require enforced network deny.",
			)
		}
	}

	if len(plan.JourneyAssertions) == 0 {
		return planError(
			"Resolved HTTP journey requires at least one assertion.",
		)
	}
	if len(plan.HTTPJourney.Steps) < 2 ||
		len(plan.HTTPJourney.Steps) >
			domain.AlphaHTTPMaxJourneySteps {
		return planError(
			"Resolved HTTP journey step count is outside the runner limit.",
		)
	}
	assertions := make(
		map[string]domain.PlanAssertion,
		len(plan.JourneyAssertions),
	)
	for _, assertion := range plan.JourneyAssertions {
		assertions[assertion.ID] = assertion
		switch {
		case assertion.Response != nil:
			response := assertion.Response
			if response.RequestID == "" ||
				response.Status == nil &&
					response.Header == nil &&
					response.BodyContains == nil &&
					response.JSONPath == nil &&
					response.JSONSchema == nil {
				return planError(
					"Resolved HTTP response assertion has no predicate.",
				)
			}
			if response.Status != nil &&
				(*response.Status < domain.AlphaHTTPMinimumStatus ||
					*response.Status >
						domain.AlphaHTTPMaximumStatus) {
				return planError(
					"Resolved HTTP response assertion status is invalid.",
				)
			}
			if response.BodyContains != nil &&
				*response.BodyContains == "" {
				return planError(
					"Resolved HTTP response body assertion is empty.",
				)
			}
			if response.BodyContains != nil &&
				len([]byte(*response.BodyContains)) >
					domain.AlphaHTTPMaxResponseMatchBytes {
				return planError(
					"Resolved HTTP response body assertion exceeds the alpha profile limit.",
				)
			}
			if response.BodyContains != nil &&
				int64(len([]byte(*response.BodyContains))) >
					r.config.MaxHTTPResponseBytes {
				return planError(
					"Resolved HTTP response body assertion exceeds the runner limit.",
				)
			}
			if response.Header != nil &&
				(!validHTTPHeaderName(strings.ToLower(response.Header.Name)) ||
					strings.ContainsAny(response.Header.Contains, "\r\n\x00") ||
					len([]byte(response.Header.Contains)) >
						domain.AlphaHTTPMaxHeaderValueBytes) {
				return planError(
					"Resolved HTTP header assertion is invalid.",
				)
			}
			if response.JSONPath != nil {
				if _, err := structuredjson.CompilePath(
					response.JSONPath.Path,
				); err != nil {
					return planError(
						"Resolved HTTP JSONPath assertion is outside the bounded singular profile.",
					)
				}
				if len(response.JSONPath.Equals) == 0 {
					return planError(
						"Resolved HTTP JSONPath assertion has no expected JSON value.",
					)
				}
				if _, err := structuredjson.Decode(
					response.JSONPath.Equals,
					structuredjson.DefaultInstanceDecodeLimits(),
				); err != nil {
					return planError(
						"Resolved HTTP JSONPath expected value is not bounded strict JSON.",
					)
				}
			}
			if response.JSONSchema != nil {
				if err := validateStructuredJSONSchemaRef(
					*response.JSONSchema,
				); err != nil {
					return err
				}
			}
		case assertion.JSONFile != nil:
			if err := validateHTTPOutputAssertionPath(
				assertion.JSONFile.Path,
			); err != nil {
				return planError(err.Error())
			}
			if assertion.JSONFile.Path == "/outputs" {
				return planError(
					"Resolved HTTP JSON file assertion must target a file below /outputs.",
				)
			}
			if err := validateStructuredJSONSchemaRef(
				assertion.JSONFile.Schema,
			); err != nil {
				return err
			}
		case assertion.FileExists != "":
			if err := validateHTTPOutputAssertionPath(
				assertion.FileExists,
			); err != nil {
				return planError(err.Error())
			}
		default:
			return planError(
				"HTTP journey contains a non-HTTP assertion operation.",
			)
		}
	}

	requests := make(map[string]struct{})
	referencedAssertions := make(map[string]struct{})
	requestCount := 0
	assertionStepCount := 0
	for _, step := range plan.HTTPJourney.Steps {
		if (step.Request == nil) == (step.AssertionID == "") {
			return planError(
				"Resolved HTTP step must contain exactly one operation.",
			)
		}
		if step.Request != nil {
			request := *step.Request
			if !assertionIDPattern.MatchString(request.ID) {
				return planError(
					"Resolved HTTP request ID is not schema-compatible.",
				)
			}
			if _, exists := requests[request.ID]; exists {
				return planError(
					"Resolved HTTP request IDs must be unique.",
				)
			}
			if _, exists := assertions[request.ID]; exists {
				return planError(
					"Resolved HTTP request and assertion IDs must be distinct.",
				)
			}
			requests[request.ID] = struct{}{}
			requestCount++
			if requestCount > domain.AlphaHTTPMaxRequestSteps {
				return planError(
					"Resolved HTTP request count exceeds the runner limit.",
				)
			}
			if !sameHTTPOrigin(readiness.URL, request.URL) {
				return planError(
					"Resolved HTTP request crosses the declared service origin.",
				)
			}
			if request.Method !=
				strings.ToLower(strings.TrimSpace(request.Method)) {
				return planError(
					"Resolved HTTP request method is not canonical.",
				)
			}
			for name := range request.Headers {
				if name != strings.ToLower(strings.TrimSpace(name)) {
					return planError(
						"Resolved HTTP request header name is not canonical.",
					)
				}
			}
			maximumRequest := r.config.MaxStepTimeout
			if maximumRequest > domain.AlphaHTTPMaxRequestTime {
				maximumRequest = domain.AlphaHTTPMaxRequestTime
			}
			parsedTimeout, parseErr :=
				domain.ParseAlphaHTTPDuration(
					request.Timeout,
					maximumRequest,
				)
			if parseErr != nil {
				return planError(
					"Resolved HTTP request timeout is invalid.",
				)
			}
			if _, err := trustedHTTPRequestFromPlan(
				request,
				parsedTimeout,
				r.config.MaxHTTPRequestBytes,
				r.config.MaxHTTPHeaderBytes,
			); err != nil {
				return planError(
					"Resolved HTTP request is unsafe: " + err.Error(),
				)
			}
			continue
		}

		assertion, exists := assertions[step.AssertionID]
		if !exists {
			return planError(
				"Resolved HTTP step references an unknown assertion.",
			)
		}
		if _, exists := referencedAssertions[step.AssertionID]; exists {
			return planError(
				"Resolved HTTP assertion is referenced more than once.",
			)
		}
		referencedAssertions[step.AssertionID] = struct{}{}
		assertionStepCount++
		if assertion.Response != nil {
			if _, exists := requests[assertion.Response.RequestID]; !exists {
				return planError(
					"Resolved HTTP assertion must reference an earlier request.",
				)
			}
		}
	}
	if requestCount == 0 {
		return planError("Resolved HTTP journey contains no request.")
	}
	if assertionStepCount == 0 {
		return planError(
			"Resolved HTTP journey contains no assertion step.",
		)
	}
	if len(referencedAssertions) != len(assertions) {
		return planError(
			"Every resolved HTTP assertion must appear exactly once in journey order.",
		)
	}
	return nil
}

func validateDeclaredServicePort(
	plan domain.ResolvedPlan,
	readinessURL string,
) error {
	_, port, err := domain.ParseAlphaHTTPURL(readinessURL)
	if err != nil {
		return errors.New("resolved readiness URL is invalid")
	}
	capability, ok := plan.Capabilities[domain.PhaseRun]
	if !ok {
		return errors.New("resolved HTTP service has no run capability")
	}
	if len(capability.Ports.Listen) != 1 {
		return errors.New(
			"resolved HTTP service must declare exactly one run TCP listener",
		)
	}
	matches := 0
	for _, binding := range capability.Ports.Listen {
		if binding.Host == "127.0.0.1" &&
			binding.Port == port &&
			(binding.Protocol == "" || binding.Protocol == "tcp") {
			matches++
		}
	}
	if matches != 1 {
		return errors.New(
			"resolved HTTP service origin is not bound to one declared TCP listener",
		)
	}
	return nil
}

func validateSignal(signal domain.PlanSignal, maximum time.Duration) error {
	switch signal.Type {
	case "term", "kill", "int", "hup":
	default:
		return errors.New("resolved service signal type is invalid")
	}
	if signal.GracePeriod == "" {
		return errors.New("resolved service signal has no grace period")
	}
	grace, err := domain.ParseAlphaHTTPDuration(
		signal.GracePeriod,
		domain.AlphaHTTPMaxSignalGrace,
	)
	if err != nil || grace > maximum {
		return errors.New("resolved service signal grace period is invalid")
	}
	return nil
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func planError(message string) error {
	return domain.NewError(
		domain.CodePlanUnresolved,
		domain.SeverityHigh,
		message,
	)
}
