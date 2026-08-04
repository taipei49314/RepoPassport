package execution

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

type inputFakeExecutor struct {
	*fakeExecutor
	inputHandler func(
		context.Context,
		string,
		[]string,
		[]byte,
		io.Writer,
		io.Writer,
	) (int, error)
}

func (f *inputFakeExecutor) RunInput(
	ctx context.Context,
	name string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	input, err := io.ReadAll(stdin)
	if err != nil {
		return -1, err
	}
	f.mu.Lock()
	f.calls = append(
		f.calls,
		commandCall{name: name, args: cloneStrings(args)},
	)
	f.mu.Unlock()
	if f.inputHandler == nil {
		return 0, nil
	}
	return f.inputHandler(
		ctx,
		name,
		args,
		input,
		stdout,
		stderr,
	)
}

func TestExecuteHTTPServiceJourneyUsesIsolatedDriverAndResolvedSignal(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	runRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "server.js"),
		[]byte("server fixture\n"),
	)
	plan := testHTTPPlan(t, sourceRoot)
	plan.Commands[len(plan.Commands)-1].Timeout = "850ms"
	plan.HTTPJourney.Steps[0].Request.Headers =
		map[string]string{"x-test": "original"}

	serviceStopped := make(chan struct{})
	var stopOnce sync.Once
	base := successfulNodeSandbox(func(
		ctx context.Context,
		_ string,
		args []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		if !containsArgument(args, "/workspace/server.js") {
			return 0, nil
		}
		select {
		case <-serviceStopped:
			return 143, errors.New("service terminated by signal")
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	})
	fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if containsArgument(args, nodeServiceSignalScript) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("signal helper has no resolved deadline")
			}
			if remaining := time.Until(deadline); remaining <= 0 ||
				remaining > 900*time.Millisecond {
				t.Fatalf(
					"signal helper deadline ignored resolved step timeout: %s",
					remaining,
				)
			}
			if len(args) == 0 ||
				args[len(args)-1] != "true" {
				t.Fatalf(
					"Runner-owned finalization omitted private no-op authorization: %v",
					args,
				)
			}
			stopOnce.Do(func() { close(serviceStopped) })
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"escalated":false,"remaining":0,`+
					`"initialTargets":1,"sent":1}`+"\n",
			)
			return 0, nil
		}
		return base(ctx, name, args, stdout, stderr)
	}
	fake.inputHandler = func(
		_ context.Context,
		_ string,
		args []string,
		input []byte,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if !containsAdjacent(args, "--user", containerDriverUser) ||
			!containsArgument(args, nodeHTTPHelperScript) {
			t.Fatalf("unsafe trusted HTTP helper invocation: %v", args)
		}
		var spec httpHelperRequest
		if err := json.Unmarshal(input, &spec); err != nil {
			t.Fatalf("decode helper request: %v", err)
		}
		body := ""
		if strings.Contains(spec.URL, "/echo") {
			body = "hello from service"
		}
		encoded := `{"ok":true,"status":200,` +
			`"headers":[{"name":"content-type","value":"text/plain"}],` +
			`"bodyBase64":"` +
			base64.StdEncoding.EncodeToString([]byte(body)) +
			`","bodyBytes":` +
			strconv.Itoa(len(body)) +
			`,"bodyTruncated":false,"durationMillis":1}` + "\n"
		_, _ = io.WriteString(stdout, encoded)
		return 0, nil
	}

	runner := testRunner(fake)
	prepared, err := runner.Prepare(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if err != nil {
		t.Fatalf("Prepare returned error: %v", err)
	}
	privatePlanBefore, err := json.Marshal(prepared.executionPlan)
	if err != nil {
		t.Fatalf("Marshal private execution plan: %v", err)
	}

	plan.RuntimeAdapter = "python"
	plan.Resources.DiskBytes = 1
	plan.Commands[0].Argv[0] = "python"
	plan.HTTPJourney.Steps[0].Request.URL =
		"http://127.0.0.1:8080/mutated"
	plan.HTTPJourney.Steps[0].Request.Headers["x-test"] = "mutated"
	originalMutatedStatus := 598
	plan.JourneyAssertions[0].Response.Status = &originalMutatedStatus
	plan.HTTPJourney.Steps = nil
	plan.JourneyAssertions = nil

	prepared.Plan.RuntimeAdapter = "python"
	prepared.Plan.RuntimeVersion = "0.0.0"
	prepared.Plan.BaseImageReference = "mutated.invalid/image:latest"
	prepared.Plan.Resources.DiskBytes = 1
	prepared.Plan.Commands[0].Argv[0] = "python"
	prepared.Plan.HTTPJourney.Steps[0].Request.Headers["x-test"] =
		"public-mutated"
	prepared.Plan.RequiredRunnerFeatures[0] = "mutated-feature"
	runCapability := prepared.Plan.Capabilities[domain.PhaseRun]
	runCapability.Ports.Listen[0].Port = 9090
	prepared.Plan.Capabilities[domain.PhaseRun] = runCapability
	prepared.Plan.HTTPJourney.Steps = nil
	mutatedStatus := 599
	prepared.Plan.JourneyAssertions[0].Response.Status = &mutatedStatus
	privatePlanAfter, err := json.Marshal(prepared.executionPlan)
	if err != nil {
		t.Fatalf("Marshal private execution plan after mutation: %v", err)
	}
	if !bytes.Equal(privatePlanBefore, privatePlanAfter) {
		t.Fatal("public or original plan mutation changed sealed execution plan")
	}

	outcome, err := runner.Run(context.Background(), prepared)
	if err != nil {
		t.Fatalf(
			"Run after public plan mutation returned error: %v\noutcome=%#v",
			err,
			outcome,
		)
	}
	if len(outcome.Assertions) != 1 ||
		outcome.Assertions[0].Status != "passed" {
		t.Fatalf("HTTP assertion result = %#v", outcome.Assertions)
	}
	expected := outcome.Assertions[0].Expected.(map[string]any)
	substringCheck, ok := expected["substringCheck"].(map[string]any)
	if !ok || len(substringCheck) != 2 ||
		substringCheck["configured"] != true ||
		substringCheck["valuePublished"] != false {
		t.Fatalf("public substring metadata = %#v", expected)
	}
	assertionJSON, err := json.Marshal(outcome.Assertions[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(assertionJSON, []byte("hello")) {
		t.Fatalf("repository-controlled substring entered public assertion: %s", assertionJSON)
	}
	serviceResult := findStepByRole(t, outcome.Steps, "service")
	if serviceResult.ExitCode != 143 || serviceResult.TimedOut {
		t.Fatalf("service result = %#v, want signaled exit 143", serviceResult)
	}
	signalResult := findStepByRole(t, outcome.Steps, "signal")
	if signalResult.ExitCode != 0 {
		t.Fatalf("signal result = %#v, want exit 0", signalResult)
	}
	for _, observation := range outcome.Observations {
		wire, marshalErr := json.Marshal(observation)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if strings.Contains(string(wire), "secret-query-value") {
			t.Fatalf(
				"HTTP query leaked into observation: %s",
				string(wire),
			)
		}
	}
	dispatchIndex := -1
	readinessIndex := -1
	startIndex := -1
	for index, observation := range outcome.Observations {
		switch observation.Operation {
		case "service.dispatch":
			dispatchIndex = index
			if observation.Result != "observed" ||
				observation.Details["state"] != "attempted" {
				t.Fatalf(
					"service dispatch evidence = %#v",
					observation,
				)
			}
		case "service.readiness":
			if observation.Result == "succeeded" {
				readinessIndex = index
			}
		case "service.start":
			if observation.Result == "succeeded" {
				startIndex = index
			}
		}
	}
	if dispatchIndex < 0 ||
		readinessIndex <= dispatchIndex ||
		startIndex <= readinessIndex {
		t.Fatalf(
			"service lifecycle order dispatch=%d readiness=%d start=%d",
			dispatchIndex,
			readinessIndex,
			startIndex,
		)
	}
}

func TestClonePlanDeepCopiesHTTPExecutionContract(t *testing.T) {
	status := 200
	bodyContains := "ready"
	body := "request"
	plan := domain.ResolvedPlan{
		Commands: []domain.PlanCommand{{
			ID:   "service",
			Argv: []string{"node", "server.js"},
			Readiness: &domain.PlanHTTPReadiness{
				URL: "http://127.0.0.1:8080/ready",
			},
		}},
		HTTPJourney: &domain.PlanHTTPJourney{
			ServiceID: "service",
			Steps: []domain.PlanHTTPDriverStep{{
				Request: &domain.PlanHTTPRequest{
					ID:      "request",
					Headers: map[string]string{"x-test": "original"},
					Body:    &body,
					JSON:    json.RawMessage(`{"value":"original"}`),
				},
			}},
		},
		JourneyAssertions: []domain.PlanAssertion{{
			ID: "assertion",
			Response: &domain.PlanHTTPResponseAssertion{
				RequestID: "request",
				Status:    &status,
				Header: &domain.PlanHTTPHeaderAssertion{
					Name: "content-type", Contains: "json",
				},
				BodyContains: &bodyContains,
			},
		}},
	}
	cloned := clonePlan(plan)

	plan.Commands[0].Readiness.URL = "mutated"
	plan.HTTPJourney.Steps[0].Request.Headers["x-test"] = "mutated"
	*plan.HTTPJourney.Steps[0].Request.Body = "mutated"
	plan.HTTPJourney.Steps[0].Request.JSON[0] = '['
	*plan.JourneyAssertions[0].Response.Status = 500
	plan.JourneyAssertions[0].Response.Header.Contains = "mutated"
	*plan.JourneyAssertions[0].Response.BodyContains = "mutated"

	if cloned.Commands[0].Readiness.URL !=
		"http://127.0.0.1:8080/ready" {
		t.Fatal("readiness pointer was not deep-cloned")
	}
	request := cloned.HTTPJourney.Steps[0].Request
	if request.Headers["x-test"] != "original" ||
		*request.Body != "request" ||
		string(request.JSON) != `{"value":"original"}` {
		t.Fatalf("HTTP request was not deep-cloned: %#v", request)
	}
	response := cloned.JourneyAssertions[0].Response
	if *response.Status != 200 ||
		response.Header.Contains != "json" ||
		*response.BodyContains != "ready" {
		t.Fatalf("HTTP assertion was not deep-cloned: %#v", response)
	}
}

func TestClonePlanDeepCopiesEveryCapabilityReference(t *testing.T) {
	childProcesses := true
	shell := true
	backgroundProcesses := true
	logBytes := int64(4096)
	devices := true
	hostIntegration := true
	plan := domain.ResolvedPlan{
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {
				Network: domain.NetworkCapability{
					Allow: []domain.NetworkDestination{{
						Host: "example.invalid",
						Port: 443,
					}},
				},
				Filesystem: domain.FilesystemCapability{
					Read:    []string{"/workspace/**"},
					Write:   []string{"/outputs/**"},
					Create:  []string{"/outputs/**"},
					Delete:  []string{"/outputs/**"},
					Rename:  []string{"/outputs/**"},
					Chmod:   []string{"/outputs/**"},
					Symlink: []string{"/outputs/**"},
				},
				Ports: domain.PortCapability{
					Listen: []domain.PortBinding{{
						Host: "127.0.0.1",
						Port: 8080,
					}},
				},
				Process: domain.ProcessCapability{
					Exec:                []string{"node"},
					ChildProcesses:      &childProcesses,
					Shell:               &shell,
					BackgroundProcesses: &backgroundProcesses,
				},
				Environment: &domain.EnvironmentCapability{
					Read:   []string{"PATH"},
					Write:  []string{"RESULT"},
					Locale: "C",
				},
				Secrets: []string{"TOKEN"},
				Resources: &domain.DeclaredResourceLimits{
					CPU: map[string]any{
						"weights": []any{1, "two"},
					},
					Memory:   "256MiB",
					LogBytes: &logBytes,
				},
				Devices:         &devices,
				HostIntegration: &hostIntegration,
			},
		},
	}
	cloned := clonePlan(plan)
	before, err := json.Marshal(cloned)
	if err != nil {
		t.Fatalf("Marshal capability clone: %v", err)
	}

	capability := plan.Capabilities[domain.PhaseExercise]
	capability.Network.Allow[0].Host = "mutated.invalid"
	capability.Filesystem.Read[0] = "/mutated/read"
	capability.Filesystem.Write[0] = "/mutated/write"
	capability.Filesystem.Create[0] = "/mutated/create"
	capability.Filesystem.Delete[0] = "/mutated/delete"
	capability.Filesystem.Rename[0] = "/mutated/rename"
	capability.Filesystem.Chmod[0] = "/mutated/chmod"
	capability.Filesystem.Symlink[0] = "/mutated/symlink"
	capability.Ports.Listen[0].Port = 9090
	capability.Process.Exec[0] = "python"
	*capability.Process.ChildProcesses = false
	*capability.Process.Shell = false
	*capability.Process.BackgroundProcesses = false
	capability.Environment.Read[0] = "MUTATED"
	capability.Environment.Write[0] = "MUTATED"
	capability.Environment.Locale = "mutated"
	capability.Secrets[0] = "MUTATED"
	capability.Resources.Memory = "1B"
	capability.Resources.CPU.(map[string]any)["weights"].([]any)[0] = 99
	*capability.Resources.LogBytes = 1
	*capability.Devices = false
	*capability.HostIntegration = false
	plan.Capabilities[domain.PhaseExercise] = capability

	after, err := json.Marshal(cloned)
	if err != nil {
		t.Fatalf("Marshal capability clone after mutation: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("capability mutation changed cloned execution plan")
	}
}

func TestSanitizedHTTPResourceDropsQuery(t *testing.T) {
	resource, queryPresent := sanitizedHTTPResource(
		"http://127.0.0.1:8080/a%2Fb?token=secret#ignored",
	)
	if resource != "http://127.0.0.1:8080/a%2Fb" ||
		!queryPresent ||
		strings.Contains(resource, "secret") {
		t.Fatalf(
			"sanitized resource = %q, queryPresent=%v",
			resource,
			queryPresent,
		)
	}
}

func TestHTTPBodyAssertionIsInconclusiveWhenBoundedBodyWasTruncated(
	t *testing.T,
) {
	contains := "needle"
	result := evaluateHTTPResponseAssertion(
		&PreparedRun{},
		domain.PlanAssertion{
			ID: "body",
			Response: &domain.PlanHTTPResponseAssertion{
				RequestID: "request", BodyContains: &contains,
			},
		},
		map[string]httpExchange{
			"request": {
				Response: trustedHTTPResponse{
					Status: 200, Body: []byte("bounded prefix"),
					BodyBytes: 1025, BodyTruncated: true,
				},
			},
		},
	)
	if result.Status != "inconclusive" {
		t.Fatalf("truncated assertion = %#v, want inconclusive", result)
	}
	expected := result.Expected.(map[string]any)
	check, ok := expected["substringCheck"].(map[string]any)
	if !ok || check["configured"] != true || check["valuePublished"] != false {
		t.Fatalf("truncated public substring metadata = %#v", expected)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(contains)) {
		t.Fatalf("truncated assertion exposed repository substring: %s", encoded)
	}
}

func TestWaitForReadinessMapsEarlyExitAndDeadline(t *testing.T) {
	command := domain.PlanCommand{
		Phase: domain.PhaseRun,
		ID:    "app",
		Role:  "service",
		Readiness: &domain.PlanHTTPReadiness{
			URL:    "http://127.0.0.1:8080/ready",
			Status: 200, Timeout: "25ms",
		},
	}
	prepared := sealPreparedRunForTest(&PreparedRun{
		Backend: "docker",
		Plan: domain.ResolvedPlan{
			RuntimeAdapter: "node",
		},
	})

	t.Run("early exit", func(t *testing.T) {
		exited := stepExecution{
			result:     StepResult{ExitCode: 1},
			exportSafe: true,
		}
		service := &runningService{
			command: command,
			done:    make(chan stepExecution, 1),
			result:  &exited,
		}
		_, err := testRunner(&inputFakeExecutor{
			fakeExecutor: &fakeExecutor{},
		}).waitForReadiness(
			context.Background(),
			prepared,
			"container",
			service,
		)
		if got := domain.ErrorCodeOf(err); got !=
			domain.CodeServiceStartFailed {
			t.Fatalf(
				"early exit code = %q, want %q: %v",
				got,
				domain.CodeServiceStartFailed,
				err,
			)
		}
	})

	t.Run("transport until deadline", func(t *testing.T) {
		fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
		fake.handler = func(
			_ context.Context,
			_ string,
			args []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			if !containsArgument(args, nodeHTTPDriverQuiesceScript) {
				t.Fatalf("unexpected cleanup helper: %v", args)
			}
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"remaining":0,"killed":0}`+"\n",
			)
			return 0, nil
		}
		fake.inputHandler = func(
			_ context.Context,
			_ string,
			_ []string,
			_ []byte,
			_ io.Writer,
			_ io.Writer,
		) (int, error) {
			return -1, errors.New("transport unavailable")
		}
		service := &runningService{
			command: command,
			cancel:  func() {},
			done:    make(chan stepExecution, 1),
		}
		_, err := testRunner(fake).waitForReadiness(
			context.Background(),
			prepared,
			"container",
			service,
		)
		if got := domain.ErrorCodeOf(err); got !=
			domain.CodeReadinessFailed {
			t.Fatalf(
				"readiness deadline code = %q, want %q: %v",
				got,
				domain.CodeReadinessFailed,
				err,
			)
		}
	})
}

func TestTrustedHTTPHelperResponseFailsClosed(t *testing.T) {
	validEmpty := `{"ok":true,"status":200,"headers":[],"bodyBase64":"",` +
		`"bodyBytes":0,"bodyTruncated":false,"durationMillis":1}`
	successWithoutOK := `{"status":200,"headers":[],"bodyBase64":"",` +
		`"bodyBytes":0,"bodyTruncated":false,"durationMillis":1}`
	tooManyHeaders := `{"ok":true,"status":200,"headers":[` +
		strings.TrimSuffix(
			strings.Repeat(`{"name":"x","value":""},`,
				domain.AlphaHTTPMaxHeaders+1),
			",",
		) +
		`],"bodyBase64":"","bodyBytes":0,` +
		`"bodyTruncated":false,"durationMillis":1}`
	tests := []struct {
		name      string
		output    string
		forbidden string
	}{
		{name: "malformed", output: `{`},
		{name: "top level array", output: `[]`},
		{name: "trailing document", output: validEmpty + "\n{}"},
		{
			name:   "status-only false pass",
			output: `{"ok":true,"status":200}`,
		},
		{
			name: "duplicate status",
			output: `{"ok":true,"status":200,"status":201,` +
				`"headers":[],"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{
			name: "duplicate ok",
			output: `{"ok":true,"ok":true,"status":200,` +
				`"headers":[],"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{
			name: "conflicting duplicate ok",
			output: `{"ok":false,"ok":true,"status":200,` +
				`"headers":[],"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{name: "success missing ok", output: successWithoutOK},
		{
			name: "success missing status",
			output: `{"ok":true,"headers":[],"bodyBase64":"",` +
				`"bodyBytes":0,"bodyTruncated":false,` +
				`"durationMillis":1}`,
		},
		{
			name: "success missing headers",
			output: `{"ok":true,"status":200,"bodyBase64":"",` +
				`"bodyBytes":0,"bodyTruncated":false,` +
				`"durationMillis":1}`,
		},
		{
			name: "success missing body",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBytes":0,"bodyTruncated":false,` +
				`"durationMillis":1}`,
		},
		{
			name: "success missing body size",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"","bodyTruncated":false,` +
				`"durationMillis":1}`,
		},
		{
			name: "success missing truncation",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"","bodyBytes":0,` +
				`"durationMillis":1}`,
		},
		{
			name: "success missing duration",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false}`,
		},
		{
			name:   "success unknown field",
			output: validEmpty[:len(validEmpty)-1] + `,"extra":true}`,
		},
		{
			name: "success failure-union field",
			output: validEmpty[:len(validEmpty)-1] +
				`,"error":"timeout"}`,
		},
		{
			name:   "failure missing error",
			output: `{"ok":false}`,
		},
		{
			name:   "failure success-union status",
			output: `{"ok":false,"error":"timeout","status":200}`,
		},
		{
			name: "failure success-union fields",
			output: `{"ok":false,"error":"timeout","headers":[],` +
				`"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false,"durationMillis":0}`,
		},
		{
			name:   "failure unknown field",
			output: `{"ok":false,"error":"timeout","extra":true}`,
		},
		{
			name:   "failure duplicate error",
			output: `{"ok":false,"error":"timeout","error":"transport"}`,
		},
		{
			name:   "failure null error",
			output: `{"ok":false,"error":null}`,
		},
		{
			name:   "failure unknown error",
			output: `{"ok":false,"error":"not-a-helper-error"}`,
		},
		{
			name: "ok wrong type",
			output: strings.Replace(validEmpty, `"ok":true`,
				`"ok":"true"`, 1),
		},
		{
			name: "status wrong type",
			output: strings.Replace(validEmpty, `"status":200`,
				`"status":"200"`, 1),
		},
		{
			name: "headers null",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":null`, 1),
		},
		{
			name: "body null",
			output: strings.Replace(validEmpty, `"bodyBase64":""`,
				`"bodyBase64":null`, 1),
		},
		{
			name: "body size wrong type",
			output: strings.Replace(validEmpty, `"bodyBytes":0`,
				`"bodyBytes":"0"`, 1),
		},
		{
			name: "truncation wrong type",
			output: strings.Replace(validEmpty, `"bodyTruncated":false`,
				`"bodyTruncated":0`, 1),
		},
		{
			name: "duration wrong type",
			output: strings.Replace(validEmpty, `"durationMillis":1`,
				`"durationMillis":"1"`, 1),
		},
		{
			name: "header missing name",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":[{"value":""}]`, 1),
		},
		{
			name: "header missing value",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":[{"name":"x"}]`, 1),
		},
		{
			name: "header duplicate name",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":[{"name":"x","name":"y","value":""}]`, 1),
		},
		{
			name: "header unknown field",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":[{"name":"x","value":"","extra":true}]`, 1),
		},
		{
			name: "header null value",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":[{"name":"x","value":null}]`, 1),
		},
		{
			name:   "too many headers",
			output: tooManyHeaders,
		},
		{
			name: "noncanonical header name",
			output: strings.Replace(validEmpty, `"headers":[]`,
				`"headers":[{"name":"X-Test","value":""}]`, 1),
		},
		{
			name: "informational status",
			output: strings.Replace(
				validEmpty,
				`"status":200`,
				`"status":199`,
				1,
			),
		},
		{
			name: "status too high",
			output: strings.Replace(
				validEmpty,
				`"status":200`,
				`"status":600`,
				1,
			),
		},
		{
			name: "negative body size",
			output: strings.Replace(validEmpty, `"bodyBytes":0`,
				`"bodyBytes":-1`, 1),
		},
		{
			name: "negative duration",
			output: strings.Replace(validEmpty, `"durationMillis":1`,
				`"durationMillis":-1`, 1),
		},
		{
			name: "duration exceeds request deadline",
			output: strings.Replace(validEmpty, `"durationMillis":1`,
				`"durationMillis":1251`, 1),
		},
		{
			name: "invalid untruncated size",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"","bodyBytes":1,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{
			name: "noncanonical body base64",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"YQ==\n","bodyBytes":1,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{
			name: "invalid truncated size",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"YQ==","bodyBytes":1,` +
				`"bodyTruncated":true,"durationMillis":1}`,
		},
		{
			name: "oversized body",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"YWJjZGU=","bodyBytes":5,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{
			name: "oversized header",
			output: `{"ok":true,"status":200,` +
				`"headers":[{"name":"x","value":"12345678"}],` +
				`"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false,"durationMillis":1}`,
		},
		{
			name: "raw body redacted",
			output: `{"ok":true,"status":200,"headers":[],` +
				`"bodyBase64":"RAW_BODY_SECRET","bodyBytes":1,` +
				`"bodyTruncated":false,"durationMillis":1}`,
			forbidden: "RAW_BODY_SECRET",
		},
		{
			name: "raw header redacted",
			output: `{"ok":true,"status":200,` +
				`"headers":[{"name":"x","value":"RAW_HEADER_SECRET\r"}],` +
				`"bodyBase64":"","bodyBytes":0,` +
				`"bodyTruncated":false,"durationMillis":1}`,
			forbidden: "RAW_HEADER_SECRET",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fake := &inputFakeExecutor{
				fakeExecutor: &fakeExecutor{},
			}
			fake.inputHandler = func(
				_ context.Context,
				_ string,
				_ []string,
				_ []byte,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				_, _ = io.WriteString(stdout, test.output)
				return 0, nil
			}
			config := DefaultConfig()
			config.MaxHTTPControlBytes = 1024
			config.MaxHTTPResponseBytes = 4
			config.MaxHTTPHeaderBytes = 8
			runner := NewRunner(fake, config)
			_, err := runner.runTrustedHTTPRequest(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan: domain.ResolvedPlan{
						RuntimeAdapter: "node",
					},
				}),
				"container",
				trustedHTTPRequest{
					ID: "request", Method: "GET",
					URL:     "http://127.0.0.1:8080/",
					Timeout: time.Second,
				},
			)
			if err == nil {
				t.Fatal("unsafe helper response was accepted")
			}
			if test.forbidden != "" &&
				strings.Contains(err.Error(), test.forbidden) {
				t.Fatalf("helper error leaked raw control data: %v", err)
			}
		})
	}
}

func TestDecodeHTTPHelperResponseAcceptsOnlyExactUnionMembers(
	t *testing.T,
) {
	success, err := decodeHTTPHelperResponse([]byte(
		`{"ok":true,"status":599,` +
			`"headers":[{"name":"x-test","value":"value"}],` +
			`"bodyBase64":"YQ==","bodyBytes":2,` +
			`"bodyTruncated":true,"durationMillis":0}`,
	))
	if err != nil {
		t.Fatalf("exact success envelope was rejected: %v", err)
	}
	if !success.OK ||
		success.Status != domain.AlphaHTTPMaximumStatus ||
		len(success.Headers) != 1 ||
		success.Headers[0].Name != "x-test" ||
		success.Headers[0].Value != "value" ||
		success.BodyBase64 != "YQ==" ||
		success.BodyBytes != 2 ||
		!success.BodyTruncated ||
		success.DurationMillis != 0 {
		t.Fatalf("decoded success envelope = %#v", success)
	}

	failure, err := decodeHTTPHelperResponse(
		[]byte(`{"ok":false,"error":"timeout"}`),
	)
	if err != nil {
		t.Fatalf("exact failure envelope was rejected: %v", err)
	}
	if failure.OK || failure.Error != "timeout" {
		t.Fatalf("decoded failure envelope = %#v", failure)
	}
}

func TestSignalServiceAcceptsCompletedEscalation(t *testing.T) {
	fake := &fakeExecutor{
		handler: func(
			_ context.Context,
			_ string,
			args []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			if !containsArgument(args, nodeServiceSignalScript) {
				t.Fatalf("unexpected signal command: %v", args)
			}
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"escalated":true,"remaining":0,`+
					`"initialTargets":1,"sent":1}`+"\n",
			)
			return 0, nil
		},
	}
	helper, result, err := testRunner(fake).signalService(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan: domain.ResolvedPlan{
				RuntimeAdapter: "node",
			},
		}),
		"container",
		domain.PlanCommand{
			Phase: domain.PhaseCleanup,
			ID:    "stop-app",
			Role:  "signal",
			Signal: &domain.PlanSignal{
				Target: "app", Type: "term", GracePeriod: "1ms",
			},
		},
		false,
	)
	if err != nil || !helper.Escalated || helper.Remaining != 0 ||
		result.ExitCode != 0 {
		t.Fatalf(
			"completed escalation = %#v, result=%#v, err=%v",
			helper,
			result,
			err,
		)
	}
}

func TestAttachedServiceCancellationReturnsWithinBound(t *testing.T) {
	returned := make(chan struct{})
	fake := &fakeExecutor{
		handler: func(
			ctx context.Context,
			_ string,
			_ []string,
			_ io.Writer,
			_ io.Writer,
		) (int, error) {
			<-ctx.Done()
			close(returned)
			return -1, ctx.Err()
		},
	}
	runner := testRunner(fake)
	parent, cancel := context.WithCancel(context.Background())
	service := runner.startService(
		parent,
		&PreparedRun{Backend: "docker"},
		preparedStep{
			command: domain.PlanCommand{
				Phase: domain.PhaseRun,
				ID:    "app",
				Argv:  []string{"node", "/workspace/server.js"},
				Role:  "service",
			},
			timeout: time.Second,
		},
		"container",
	)
	cancel()
	waitCtx, cancelWait := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancelWait()
	execution, err := waitServiceResult(waitCtx, service)
	if err != nil {
		t.Fatalf("waitServiceResult: %v", err)
	}
	if got := domain.ErrorCodeOf(execution.primaryError); got !=
		domain.CodeCancelled {
		t.Fatalf(
			"cancelled service code = %q, want %q",
			got,
			domain.CodeCancelled,
		)
	}
	select {
	case <-returned:
	default:
		t.Fatal("attached service executor did not return after cancellation")
	}
}

func TestValidateHTTPPlanRejectsEmptyBodyMatch(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "server.js"),
		[]byte("server fixture\n"),
	)
	plan := testHTTPPlan(t, sourceRoot)
	empty := ""
	plan.JourneyAssertions[0].Response.BodyContains = &empty
	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanUnresolved {
		t.Fatalf(
			"empty body match code = %q, want %q: %v",
			got,
			domain.CodePlanUnresolved,
			err,
		)
	}
}

func TestValidateHTTPPlanRejectsHTTPDriverWithoutHTTPJourney(t *testing.T) {
	plan := testPlan(t, t.TempDir())
	plan.JourneyDriver = "http"
	plan.JourneyDriverVersion = "0.1.0"

	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanUnresolved {
		t.Fatalf(
			"HTTP driver without HTTP journey code = %q, want %q: %v",
			got,
			domain.CodePlanUnresolved,
			err,
		)
	}
}

func TestValidateHTTPPlanRejectsStdoutSchemaWithoutHTTPJourney(
	t *testing.T,
) {
	reference := validCLIStdoutSchemaReference()
	plan := testPlan(t, t.TempDir())
	plan.JourneyDriver = "http"
	plan.JourneyDriverVersion = "0.1.0"
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID:               "stdout-schema",
		StdoutJSONSchema: &reference,
	}}

	_, _, err := testRunner(&fakeExecutor{}).validatePlan(plan)
	if got := domain.ErrorCodeOf(err); got != domain.CodePlanUnresolved {
		t.Fatalf(
			"HTTP stdout schema without HTTP journey code = %q, want %q: %v",
			got,
			domain.CodePlanUnresolved,
			err,
		)
	}
}

func testHTTPPlan(
	t *testing.T,
	sourceRoot string,
) domain.ResolvedPlan {
	t.Helper()
	plan := testPlan(t, sourceRoot)
	status := 200
	bodyContains := "hello"
	plan.JourneyDriver = "http"
	plan.JourneyDriverVersion = "0.1.0"
	plan.Commands = []domain.PlanCommand{
		{
			Phase: domain.PhaseRun,
			ID:    "app",
			Argv:  []string{"node", "/workspace/server.js"},
			Readiness: &domain.PlanHTTPReadiness{
				URL: "http://127.0.0.1:8080/ready" +
					"?token=secret-query-value",
				Status: 200, Timeout: "2s",
			},
			Timeout: "10s",
			Role:    "service",
		},
		{
			Phase:   domain.PhaseCleanup,
			ID:      "stop-app",
			Timeout: "2s",
			Role:    "signal",
			Signal: &domain.PlanSignal{
				Target: "app", Type: "term", GracePeriod: "100ms",
			},
		},
	}
	plan.JourneyAssertions = []domain.PlanAssertion{{
		ID: "echo-ok",
		Response: &domain.PlanHTTPResponseAssertion{
			RequestID: "echo",
			Status:    &status,
			Header: &domain.PlanHTTPHeaderAssertion{
				Name: "content-type", Contains: "text/plain",
			},
			BodyContains: &bodyContains,
		},
	}}
	plan.HTTPJourney = &domain.PlanHTTPJourney{
		ServiceID: "app",
		Steps: []domain.PlanHTTPDriverStep{
			{Request: &domain.PlanHTTPRequest{
				ID: "echo", Method: "get",
				URL: "http://127.0.0.1:8080/echo" +
					"?token=secret-query-value",
				Timeout: "2s",
			}},
			{AssertionID: "echo-ok"},
		},
	}
	plan.Capabilities = map[domain.Phase]domain.CapabilitySet{
		domain.PhaseRun: {
			Network: domain.NetworkCapability{Deny: true},
			Ports: domain.PortCapability{Listen: []domain.PortBinding{{
				Host: "127.0.0.1", Port: 8080, Protocol: "tcp",
			}}},
		},
		domain.PhaseExercise: {
			Network: domain.NetworkCapability{Deny: true},
		},
	}
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"background-service",
		"service-signal",
		"loopback-http-driver",
	)
	return plan
}

func findStepByRole(
	t *testing.T,
	steps []StepResult,
	role string,
) StepResult {
	t.Helper()
	for _, step := range steps {
		if step.Role == role {
			return step
		}
	}
	t.Fatalf("step with role %q not found in %#v", role, steps)
	return StepResult{}
}
