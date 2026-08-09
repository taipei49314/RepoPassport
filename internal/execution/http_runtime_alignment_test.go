package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestHTTPRuntimeMirrorsFrozenContract(t *testing.T) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "server.js"),
		[]byte("server fixture\n"),
	)
	base := testHTTPPlan(t, sourceRoot)
	runner := testRunner(&fakeExecutor{})

	assertRejected := func(
		t *testing.T,
		mutate func(*domain.ResolvedPlan),
	) {
		t.Helper()
		plan := clonePlan(base)
		mutate(&plan)
		if err := runner.validateHTTPPlan(plan); err == nil {
			t.Fatal("contract-invalid HTTP plan was accepted")
		}
	}

	t.Run("readiness status lower bound", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.Commands[0].Readiness.Status = 199
		})
	})
	t.Run("response status lower bound", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			status := 199
			plan.JourneyAssertions[0].Response.Status = &status
		})
	})
	t.Run("readiness whole milliseconds", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.Commands[0].Readiness.Timeout = "1500us"
		})
	})
	t.Run("readiness two minute ceiling", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.Commands[0].Readiness.Timeout = "120001ms"
		})
	})
	t.Run("request whole milliseconds", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.HTTPJourney.Steps[0].Request.Timeout = "1500us"
		})
	})
	t.Run("all signals require grace", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			signal := plan.Commands[len(plan.Commands)-1].Signal
			signal.Type = "kill"
			signal.GracePeriod = ""
		})
	})
	t.Run("signal grace uses whole milliseconds", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.Commands[len(plan.Commands)-1].
				Signal.GracePeriod = "1500us"
		})
	})
	t.Run("signal timeout includes helper slack", func(t *testing.T) {
		plan := clonePlan(base)
		plan.Commands[len(plan.Commands)-1].Timeout =
			(100*time.Millisecond +
				serviceSignalHelperSlack).String()
		if err := runner.validateHTTPPlan(plan); err != nil {
			t.Fatalf("exact signal timeout budget: %v", err)
		}

		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.Commands[len(plan.Commands)-1].Timeout =
				(100*time.Millisecond +
					serviceSignalHelperSlack -
					time.Millisecond).String()
		})
	})
	t.Run("journey step ceiling", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			for len(plan.HTTPJourney.Steps) <=
				domain.AlphaHTTPMaxJourneySteps {
				plan.HTTPJourney.Steps = append(
					plan.HTTPJourney.Steps,
					domain.PlanHTTPDriverStep{
						AssertionID: "echo-ok",
					},
				)
			}
		})
	})
	t.Run("request step ceiling", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			steps := make(
				[]domain.PlanHTTPDriverStep,
				0,
				domain.AlphaHTTPMaxRequestSteps+1,
			)
			for index := 0; index <=
				domain.AlphaHTTPMaxRequestSteps; index++ {
				steps = append(steps, domain.PlanHTTPDriverStep{
					Request: &domain.PlanHTTPRequest{
						ID:      fmt.Sprintf("request-%02d", index),
						Method:  "get",
						URL:     "http://127.0.0.1:8080/request",
						Timeout: "1ms",
					},
				})
			}
			plan.HTTPJourney.Steps = append(
				steps,
				domain.PlanHTTPDriverStep{
					AssertionID: "echo-ok",
				},
			)
			plan.JourneyAssertions[0].Response.RequestID =
				"request-00"
		})
	})
	t.Run("request-only journey", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.HTTPJourney.Steps =
				plan.HTTPJourney.Steps[:1]
			plan.JourneyAssertions = nil
		})
	})
	t.Run("assertion without operation", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.JourneyAssertions[0] =
				domain.PlanAssertion{ID: "echo-ok"}
		})
	})
	t.Run("JSON automatic header counts", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			request := plan.HTTPJourney.Steps[0].Request
			request.Headers = runtimeHeaders(
				domain.AlphaHTTPMaxHeaders,
				"x",
			)
			request.JSON = json.RawMessage(`{"ok":true}`)
		})
	})
	t.Run("effective header aggregate", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			request := plan.HTTPJourney.Steps[0].Request
			request.Headers = runtimeHeaders(
				8,
				strings.Repeat(
					"x",
					domain.AlphaHTTPMaxHeaderValueBytes,
				),
			)
		})
	})
	t.Run("header values are printable ASCII", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.HTTPJourney.Steps[0].Request.Headers =
				map[string]string{"x-test": "snowman-\u2603"}
		})
	})
	t.Run("output path is valid UTF-8", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.JourneyAssertions[0].Response = nil
			plan.JourneyAssertions[0].FileExists =
				"/outputs/" + string([]byte{0xff})
		})
	})
	t.Run("effective header boundary accepted", func(t *testing.T) {
		plan := clonePlan(base)
		request := plan.HTTPJourney.Steps[0].Request
		request.Headers = runtimeHeaders(
			domain.AlphaHTTPMaxHeaders-1,
			"x",
		)
		request.JSON = json.RawMessage(`{"ok":true}`)
		if err := runner.validateHTTPPlan(plan); err != nil {
			t.Fatalf("63 headers plus automatic JSON header: %v", err)
		}
	})
	t.Run("ten second signal grace accepted", func(t *testing.T) {
		plan := clonePlan(base)
		plan.Commands[len(plan.Commands)-1].
			Signal.GracePeriod = "10s"
		plan.Commands[len(plan.Commands)-1].Timeout = "11s"
		defaultRunner := NewRunner(
			&fakeExecutor{},
			DefaultConfig(),
		)
		if err := defaultRunner.validateHTTPPlan(plan); err != nil {
			t.Fatalf("10s signal grace: %v", err)
		}
	})
	t.Run("response match fixed bounds", func(t *testing.T) {
		config := DefaultConfig()
		config.MaxHTTPResponseBytes =
			2 * domain.AlphaHTTPMaxResponseMatchBytes
		boundaryRunner := NewRunner(&fakeExecutor{}, config)

		atBodyBoundary := clonePlan(base)
		bodyBoundary := strings.Repeat(
			"x",
			domain.AlphaHTTPMaxResponseMatchBytes,
		)
		atBodyBoundary.JourneyAssertions[0].
			Response.BodyContains = &bodyBoundary
		if err := boundaryRunner.validateHTTPPlan(
			atBodyBoundary,
		); err != nil {
			t.Fatalf("bodyContains at boundary: %v", err)
		}

		overBodyBoundary := clonePlan(base)
		bodyOver := bodyBoundary + "x"
		overBodyBoundary.JourneyAssertions[0].
			Response.BodyContains = &bodyOver
		if err := boundaryRunner.validateHTTPPlan(
			overBodyBoundary,
		); err == nil {
			t.Fatal("oversized bodyContains was accepted")
		}

		atHeaderBoundary := clonePlan(base)
		atHeaderBoundary.JourneyAssertions[0].
			Response.Header.Contains = strings.Repeat(
			"x",
			domain.AlphaHTTPMaxHeaderValueBytes,
		)
		if err := boundaryRunner.validateHTTPPlan(
			atHeaderBoundary,
		); err != nil {
			t.Fatalf("header contains at boundary: %v", err)
		}

		overHeaderBoundary := clonePlan(base)
		overHeaderBoundary.JourneyAssertions[0].
			Response.Header.Contains = strings.Repeat(
			"x",
			domain.AlphaHTTPMaxHeaderValueBytes+1,
		)
		if err := boundaryRunner.validateHTTPPlan(
			overHeaderBoundary,
		); err == nil {
			t.Fatal("oversized header contains was accepted")
		}
	})
	t.Run("JSONPath expected exponent limit", func(t *testing.T) {
		assertRejected(t, func(plan *domain.ResolvedPlan) {
			plan.JourneyAssertions[0].Response.JSONPath =
				&domain.PlanJSONPathAssertion{
					Path:   "$.value",
					Equals: json.RawMessage(`1e1000001`),
				}
		})
	})
}

func TestBoundedSignalFinalizationTimeoutUsesResolvedStepBudget(
	t *testing.T,
) {
	for name, test := range map[string]struct {
		resolved time.Duration
		cleanup  time.Duration
		wanted   time.Duration
	}{
		"resolved is smaller": {
			resolved: 850 * time.Millisecond,
			cleanup:  15 * time.Second,
			wanted:   850 * time.Millisecond,
		},
		"cleanup is smaller": {
			resolved: 20 * time.Second,
			cleanup:  15 * time.Second,
			wanted:   15 * time.Second,
		},
	} {
		if got := boundedSignalFinalizationTimeout(
			test.resolved,
			test.cleanup,
		); got != test.wanted {
			t.Fatalf(
				"%s timeout = %s, want %s",
				name,
				got,
				test.wanted,
			)
		}
	}
}

func TestTrustedHTTPRequestContractAndPort80(t *testing.T) {
	t.Run("canonical URL and duration", func(t *testing.T) {
		for name, request := range map[string]domain.PlanHTTPRequest{
			"leading zero port": {
				ID: "request", Method: "get",
				URL: "http://127.0.0.1:080/path", Timeout: "1ms",
			},
			"dot segment": {
				ID: "request", Method: "get",
				URL: "http://127.0.0.1:80/a/../b", Timeout: "1ms",
			},
			"encoded unreserved": {
				ID: "request", Method: "get",
				URL: "http://127.0.0.1:80/%61", Timeout: "1ms",
			},
			"empty query": {
				ID: "request", Method: "get",
				URL: "http://127.0.0.1:80/path?", Timeout: "1ms",
			},
			"fractional millisecond": {
				ID: "request", Method: "get",
				URL: "http://127.0.0.1:80/path", Timeout: "1500us",
			},
			"noncanonical method": {
				ID: "request", Method: "GET",
				URL: "http://127.0.0.1:80/path", Timeout: "1ms",
			},
		} {
			request := request
			t.Run(name, func(t *testing.T) {
				if _, err := trustedHTTPRequestFromPlan(
					request,
					time.Second,
					1<<20,
					64<<10,
				); err == nil {
					t.Fatal("unsafe request was accepted")
				}
			})
		}
	})

	t.Run("request body byte boundaries", func(t *testing.T) {
		for name, request := range map[string]domain.PlanHTTPRequest{
			"text exact": {
				ID: "request", Method: "post",
				URL: "http://127.0.0.1:80/path", Timeout: "1ms",
				Body: stringPointer(strings.Repeat(
					"x",
					domain.AlphaHTTPMaxRequestBodyBytes,
				)),
			},
			"text over": {
				ID: "request", Method: "post",
				URL: "http://127.0.0.1:80/path", Timeout: "1ms",
				Body: stringPointer(strings.Repeat(
					"x",
					domain.AlphaHTTPMaxRequestBodyBytes+1,
				)),
			},
			"JSON exact": {
				ID: "request", Method: "post",
				URL: "http://127.0.0.1:80/path", Timeout: "1ms",
				JSON: json.RawMessage(
					`"` +
						strings.Repeat(
							"x",
							domain.AlphaHTTPMaxRequestBodyBytes-2,
						) +
						`"`,
				),
			},
			"JSON over": {
				ID: "request", Method: "post",
				URL: "http://127.0.0.1:80/path", Timeout: "1ms",
				JSON: json.RawMessage(
					`"` +
						strings.Repeat(
							"x",
							domain.AlphaHTTPMaxRequestBodyBytes-1,
						) +
						`"`,
				),
			},
		} {
			request := request
			t.Run(name, func(t *testing.T) {
				_, err := trustedHTTPRequestFromPlan(
					request,
					time.Second,
					2*domain.AlphaHTTPMaxRequestBodyBytes,
					domain.AlphaHTTPMaxHeaderAggregateBytes,
				)
				over := strings.Contains(name, "over")
				if over && err == nil {
					t.Fatal("oversized request body was accepted")
				}
				if !over && err != nil {
					t.Fatalf("boundary request body: %v", err)
				}
			})
		}
	})

	t.Run("explicit port 80 reaches both adapters", func(t *testing.T) {
		for _, adapter := range []string{"node", "python"} {
			adapter := adapter
			t.Run(adapter, func(t *testing.T) {
				fake := &inputFakeExecutor{
					fakeExecutor: &fakeExecutor{},
				}
				fake.inputHandler = func(
					_ context.Context,
					_ string,
					args []string,
					input []byte,
					stdout io.Writer,
					_ io.Writer,
				) (int, error) {
					var spec httpHelperRequest
					if err := json.Unmarshal(input, &spec); err != nil {
						t.Fatal(err)
					}
					if spec.Port != 80 {
						t.Fatalf("helper port = %d, want 80", spec.Port)
					}
					if adapter == "node" &&
						!strings.Contains(
							nodeHTTPHelperScript,
							"Object.create(null)",
						) {
						t.Fatal("Node helper header map has a prototype")
					}
					_, _ = io.WriteString(
						stdout,
						`{"ok":true,"status":200,"headers":[],`+
							`"bodyBase64":"","bodyBytes":0,`+
							`"bodyTruncated":false,`+
							`"durationMillis":1}`+"\n",
					)
					if !containsArgument(
						args,
						map[string]string{
							"node":   nodeHTTPHelperScript,
							"python": pythonHTTPHelperScript,
						}[adapter],
					) {
						t.Fatalf("wrong adapter helper: %v", args)
					}
					return 0, nil
				}
				_, err := testRunner(fake).runTrustedHTTPRequest(
					context.Background(),
					sealPreparedRunForTest(&PreparedRun{
						Backend: "docker",
						Plan: domain.ResolvedPlan{
							RuntimeAdapter: adapter,
						},
					}),
					"container",
					trustedHTTPRequest{
						ID: "port-80", Method: "GET",
						URL: "http://127.0.0.1:80/",
						Headers: []httpHeader{{
							Name: "__proto__", Value: "safe",
						}},
						Timeout: time.Second,
					},
				)
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}

func TestHTTPJourneyContextMappingAndOrderedCancellation(t *testing.T) {
	responseStatus := 200
	plan := domain.ResolvedPlan{
		RuntimeAdapter: "node",
		HTTPJourney: &domain.PlanHTTPJourney{
			ServiceID: "app",
			Steps: []domain.PlanHTTPDriverStep{
				{Request: &domain.PlanHTTPRequest{
					ID: "request", Method: "get",
					URL:     "http://127.0.0.1:8080/",
					Timeout: "1s",
				}},
				{AssertionID: "response-ok"},
			},
		},
		JourneyAssertions: []domain.PlanAssertion{{
			ID: "response-ok",
			Response: &domain.PlanHTTPResponseAssertion{
				RequestID: "request",
				Status:    &responseStatus,
			},
		}},
	}
	service := func() *runningService {
		return &runningService{
			command: domain.PlanCommand{ID: "app"},
			cancel:  func() {},
			done:    make(chan stepExecution, 1),
		}
	}

	t.Run("parent cancellation at ordered boundary", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
		fake.inputHandler = func(
			_ context.Context,
			_ string,
			_ []string,
			_ []byte,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"status":200,"headers":[],`+
					`"bodyBase64":"","bodyBytes":0,`+
					`"bodyTruncated":false,`+
					`"durationMillis":1}`+"\n",
			)
			cancel()
			return 0, nil
		}
		prepared := sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan:    clonePlan(plan),
		})
		_, snapshots, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				ctx,
				prepared,
				"container",
				service(),
			)
		if !driverStarted {
			t.Fatal("completed trusted HTTP helper was not reported as started")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodeCancelled {
			t.Fatalf("cancel code = %q: %v", got, journeyErr)
		}
		results := evaluateHTTPJourneyAssertions(
			prepared,
			snapshots,
		)
		if len(results) != 1 || results[0].Status != "blocked" {
			t.Fatalf("cancelled assertion = %#v", results)
		}
	})

	t.Run("parent deadline before step", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(
			context.Background(),
			time.Now().Add(-time.Second),
		)
		defer cancel()
		fake := &inputFakeExecutor{
			fakeExecutor: &fakeExecutor{},
		}
		fake.inputHandler = func(
			context.Context,
			string,
			[]string,
			[]byte,
			io.Writer,
			io.Writer,
		) (int, error) {
			t.Fatal("expired journey invoked an HTTP helper")
			return -1, nil
		}
		_, _, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				ctx,
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan:    clonePlan(plan),
				}),
				"container",
				service(),
			)
		if driverStarted {
			t.Fatal("pre-step deadline reported an HTTP driver start")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodeTimeout {
			t.Fatalf("deadline code = %q: %v", got, journeyErr)
		}
	})

	t.Run("request revalidation before driver", func(t *testing.T) {
		invalidPlan := clonePlan(plan)
		invalidPlan.HTTPJourney.Steps[0].Request.Method = "GET"
		fake := &inputFakeExecutor{
			fakeExecutor: &fakeExecutor{},
		}
		fake.inputHandler = func(
			context.Context,
			string,
			[]string,
			[]byte,
			io.Writer,
			io.Writer,
		) (int, error) {
			t.Fatal("rejected request invoked an HTTP helper")
			return -1, nil
		}
		_, _, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan:    invalidPlan,
				}),
				"container",
				service(),
			)
		if driverStarted {
			t.Fatal("request revalidation failure reported a driver start")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodePlanUnresolved {
			t.Fatalf("revalidation code = %q: %v", got, journeyErr)
		}
	})

	t.Run("service exit before driver", func(t *testing.T) {
		fake := &inputFakeExecutor{
			fakeExecutor: &fakeExecutor{},
		}
		fake.inputHandler = func(
			context.Context,
			string,
			[]string,
			[]byte,
			io.Writer,
			io.Writer,
		) (int, error) {
			t.Fatal("exited service invoked an HTTP helper")
			return -1, nil
		}
		exited := stepExecution{
			result: StepResult{ExitCode: 1},
		}
		exitedService := service()
		exitedService.result = &exited
		_, _, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan:    clonePlan(plan),
				}),
				"container",
				exitedService,
			)
		if driverStarted {
			t.Fatal("service exit before the first step reported a driver start")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodeServiceStartFailed {
			t.Fatalf("early service exit code = %q: %v", got, journeyErr)
		}
	})

	t.Run("file assertion prevalidation before driver", func(t *testing.T) {
		filePlan := domain.ResolvedPlan{
			RuntimeAdapter: "node",
			HTTPJourney: &domain.PlanHTTPJourney{
				ServiceID: "app",
				Steps: []domain.PlanHTTPDriverStep{{
					AssertionID: "unsafe-file",
				}},
			},
			JourneyAssertions: []domain.PlanAssertion{{
				ID:         "unsafe-file",
				FileExists: "/workspace/result.json",
			}},
		}
		fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
		fake.handler = func(
			context.Context,
			string,
			[]string,
			io.Writer,
			io.Writer,
		) (int, error) {
			t.Fatal("rejected file assertion invoked a helper")
			return -1, nil
		}
		_, _, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan:    filePlan,
				}),
				"container",
				service(),
			)
		if driverStarted {
			t.Fatal("file assertion prevalidation reported a driver start")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodeObserverIncomplete {
			t.Fatalf("file prevalidation code = %q: %v", got, journeyErr)
		}
	})

	t.Run("file assertion helper attempt", func(t *testing.T) {
		filePlan := domain.ResolvedPlan{
			RuntimeAdapter: "node",
			HTTPJourney: &domain.PlanHTTPJourney{
				ServiceID: "app",
				Steps: []domain.PlanHTTPDriverStep{{
					AssertionID: "missing-file",
				}},
			},
			JourneyAssertions: []domain.PlanAssertion{{
				ID:         "missing-file",
				FileExists: "/outputs/result.json",
			}},
		}
		fake := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
		fake.handler = func(
			_ context.Context,
			_ string,
			_ []string,
			stdout io.Writer,
			_ io.Writer,
		) (int, error) {
			_, _ = io.WriteString(stdout, `{"status":"missing"}`)
			return 0, nil
		}
		_, _, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan:    filePlan,
				}),
				"container",
				service(),
			)
		if !driverStarted {
			t.Fatal("file helper attempt was not reported as started")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodeJourneyAssertionFailed {
			t.Fatalf("file helper code = %q: %v", got, journeyErr)
		}
	})

	t.Run("helper watchdog", func(t *testing.T) {
		watchdogPlan := clonePlan(plan)
		watchdogPlan.HTTPJourney.Steps =
			watchdogPlan.HTTPJourney.Steps[:1]
		watchdogPlan.JourneyAssertions = nil
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
			_, _ = io.WriteString(
				stdout,
				`{"ok":false,"error":"timeout"}`+"\n",
			)
			return 0, nil
		}
		fake.handler = func(
			context.Context,
			string,
			[]string,
			io.Writer,
			io.Writer,
		) (int, error) {
			t.Fatal("completed helper failure triggered root quiescence")
			return -1, nil
		}
		_, _, _, driverStarted, journeyErr :=
			testRunner(fake).executeHTTPJourney(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan:    watchdogPlan,
				}),
				"container",
				service(),
			)
		if !driverStarted {
			t.Fatal("invoked watchdog helper was not reported as started")
		}
		if got := domain.ErrorCodeOf(journeyErr); got !=
			domain.CodeTimeout {
			t.Fatalf("watchdog code = %q: %v", got, journeyErr)
		}
	})

	for name, expected := range map[string]domain.ErrorCode{
		"host cancellation": domain.CodeCancelled,
		"host deadline":     domain.CodeTimeout,
	} {
		name := name
		expected := expected
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			uncertainPlan := clonePlan(plan)
			uncertainPlan.HTTPJourney.Steps =
				uncertainPlan.HTTPJourney.Steps[:1]
			uncertainPlan.JourneyAssertions = nil
			fake := &inputFakeExecutor{
				fakeExecutor: &fakeExecutor{},
			}
			fake.inputHandler = func(
				context.Context,
				string,
				[]string,
				[]byte,
				io.Writer,
				io.Writer,
			) (int, error) {
				if name == "host cancellation" {
					cancel()
					return -1, context.Canceled
				}
				return -1, context.DeadlineExceeded
			}
			fake.handler = func(
				_ context.Context,
				_ string,
				args []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				if !containsArgument(
					args,
					nodeHTTPDriverQuiesceScript,
				) {
					t.Fatalf(
						"unexpected cleanup helper: %v",
						args,
					)
				}
				_, _ = io.WriteString(
					stdout,
					`{"ok":true,"remaining":0,"killed":0}`+
						"\n",
				)
				return 0, nil
			}
			_, _, _, driverStarted, journeyErr :=
				testRunner(fake).executeHTTPJourney(
					ctx,
					sealPreparedRunForTest(&PreparedRun{
						Backend: "docker",
						Plan:    uncertainPlan,
					}),
					"container",
					service(),
				)
			if !driverStarted {
				t.Fatal("invoked failing HTTP helper was not reported as started")
			}
			if got := domain.ErrorCodeOf(journeyErr); got !=
				expected {
				t.Fatalf(
					"%s code = %q: %v",
					name,
					got,
					journeyErr,
				)
			}
		})
	}
}

func TestReadinessBackoffAttemptBoundAndResidue(t *testing.T) {
	for attempts, wanted := range map[int]time.Duration{
		1: 100 * time.Millisecond,
		2: 200 * time.Millisecond,
		3: 400 * time.Millisecond,
		4: 800 * time.Millisecond,
		5: time.Second,
		6: time.Second,
	} {
		if got := readinessRetryBackoff(attempts); got != wanted {
			t.Fatalf(
				"backoff(%d) = %s, want %s",
				attempts,
				got,
				wanted,
			)
		}
	}
	if maxHTTPReadinessAttempts != 128 {
		t.Fatalf(
			"readiness attempt cap = %d",
			maxHTTPReadinessAttempts,
		)
	}

	for name, expected := range map[string]domain.ErrorCode{
		"parent cancellation": domain.CodeCancelled,
		"parent deadline":     domain.CodeTimeout,
	} {
		name := name
		expected := expected
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if name == "parent cancellation" {
				ctx, cancel = context.WithCancel(
					context.Background(),
				)
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(
					context.Background(),
					time.Now().Add(-time.Second),
				)
			}
			defer cancel()
			fake := &inputFakeExecutor{
				fakeExecutor: &fakeExecutor{},
			}
			fake.inputHandler = func(
				context.Context,
				string,
				[]string,
				[]byte,
				io.Writer,
				io.Writer,
			) (int, error) {
				t.Fatal("expired readiness invoked a helper")
				return -1, nil
			}
			service := &runningService{
				command: domain.PlanCommand{
					ID: "app",
					Readiness: &domain.PlanHTTPReadiness{
						URL:    "http://127.0.0.1:8080/ready",
						Status: 200, Timeout: "2m",
					},
				},
				cancel: func() {},
				done:   make(chan stepExecution, 1),
			}
			_, readinessErr := testRunner(fake).
				waitForReadiness(
					ctx,
					sealPreparedRunForTest(&PreparedRun{
						Backend: "docker",
						Plan: domain.ResolvedPlan{
							RuntimeAdapter: "node",
						},
					}),
					"container",
					service,
				)
			if got := domain.ErrorCodeOf(readinessErr); got !=
				expected {
				t.Fatalf(
					"%s code = %q: %v",
					name,
					got,
					readinessErr,
				)
			}
		})
	}

	var attempts atomic.Int32
	fake := &inputFakeExecutor{
		fakeExecutor: &fakeExecutor{},
	}
	fake.inputHandler = func(
		context.Context,
		string,
		[]string,
		[]byte,
		io.Writer,
		io.Writer,
	) (int, error) {
		attempts.Add(1)
		return -1, errors.New("uncertain host exec")
	}
	fake.handler = func(
		context.Context,
		string,
		[]string,
		io.Writer,
		io.Writer,
	) (int, error) {
		return -1, errors.New("cannot exclude UID 65533 residue")
	}
	service := &runningService{
		command: domain.PlanCommand{
			ID: "app",
			Readiness: &domain.PlanHTTPReadiness{
				URL:    "http://127.0.0.1:8080/ready",
				Status: 200, Timeout: "2m",
			},
		},
		cancel: func() {},
		done:   make(chan stepExecution, 1),
	}
	_, readinessErr := testRunner(fake).waitForReadiness(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan: domain.ResolvedPlan{
				RuntimeAdapter: "node",
			},
		}),
		"container",
		service,
	)
	if got := domain.ErrorCodeOf(readinessErr); got !=
		domain.CodeProcessLeak {
		t.Fatalf("residue code = %q: %v", got, readinessErr)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("readiness retried uncertain residue %d times", got)
	}
}

func TestReadinessCompletedTransportFailureDoesNotRootQuiesce(
	t *testing.T,
) {
	var attempts atomic.Int32
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
		attempts.Add(1)
		_, _ = io.WriteString(
			stdout,
			`{"ok":false,"error":"transport"}`+"\n",
		)
		return 0, nil
	}
	fake.handler = func(
		_ context.Context,
		_ string,
		_ []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		t.Fatal("completed readiness helper triggered root quiescence")
		return -1, nil
	}
	service := &runningService{
		command: domain.PlanCommand{
			ID: "app",
			Readiness: &domain.PlanHTTPReadiness{
				URL:    "http://127.0.0.1:8080/ready",
				Status: 200, Timeout: "50ms",
			},
		},
		cancel: func() {},
		done:   make(chan stepExecution, 1),
	}
	_, readinessErr := testRunner(fake).waitForReadiness(
		context.Background(),
		sealPreparedRunForTest(&PreparedRun{
			Backend: "docker",
			Plan: domain.ResolvedPlan{
				RuntimeAdapter: "node",
			},
		}),
		"container",
		service,
	)
	if got := domain.ErrorCodeOf(readinessErr); got !=
		domain.CodeReadinessFailed {
		t.Fatalf("readiness code = %q: %v", got, readinessErr)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("50ms readiness attempts = %d, want 1", got)
	}
}

func TestSignalEnvelopeAllowsObservedTargetRaceOnly(t *testing.T) {
	for name, envelope := range map[string]string{
		"partial send accepted": `{"ok":true,"escalated":false,` +
			`"remaining":0,"initialTargets":2,"sent":1}`,
		"sent exceeds observed rejected": `{"ok":true,"escalated":false,` +
			`"remaining":0,"initialTargets":2,"sent":3}`,
	} {
		envelope := envelope
		t.Run(name, func(t *testing.T) {
			fake := &fakeExecutor{
				handler: func(
					context.Context,
					string,
					[]string,
					io.Writer,
					io.Writer,
				) (int, error) {
					return 0, nil
				},
			}
			fake.handler = func(
				_ context.Context,
				_ string,
				_ []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				_, _ = io.WriteString(stdout, envelope+"\n")
				return 0, nil
			}
			_, _, err := testRunner(fake).signalService(
				context.Background(),
				sealPreparedRunForTest(&PreparedRun{
					Backend: "docker",
					Plan: domain.ResolvedPlan{
						RuntimeAdapter: "node",
					},
				}),
				"container",
				domain.PlanCommand{
					ID: "stop", Role: "signal",
					Signal: &domain.PlanSignal{
						Target:      "app",
						Type:        "term",
						GracePeriod: "1ms",
					},
				},
				false,
			)
			if name == "partial send accepted" && err != nil {
				t.Fatalf("partial send rejected: %v", err)
			}
			if name != "partial send accepted" && err == nil {
				t.Fatal("impossible signal envelope was accepted")
			}
		})
	}

	t.Run("confirmed already exited no-op", func(t *testing.T) {
		fake := &fakeExecutor{
			handler: func(
				_ context.Context,
				_ string,
				args []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				if len(args) == 0 ||
					args[len(args)-1] != "true" {
					t.Fatalf(
						"already-exited authorization missing: %v",
						args,
					)
				}
				_, _ = io.WriteString(
					stdout,
					`{"ok":true,"escalated":false,`+
						`"remaining":0,"initialTargets":0,`+
						`"sent":0}`+"\n",
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
				ID: "stop", Role: "signal",
				Signal: &domain.PlanSignal{
					Target:      "app",
					Type:        "term",
					GracePeriod: "1ms",
				},
			},
			true,
		)
		if err != nil ||
			!helper.AlreadyExited ||
			helper.InitialTargets != 0 ||
			helper.Sent != 0 ||
			result.ExitCode != 0 {
			t.Fatalf(
				"already-exited helper=%#v result=%#v err=%v",
				helper,
				result,
				err,
			)
		}
	})
}

func TestSignalHelperPredicatesMatchControllerContract(t *testing.T) {
	for _, helper := range []struct {
		name   string
		script string
		parts  []string
	}{
		{
			name:   "node",
			script: nodeServiceSignalScript,
			parts: []string{
				`delivered=initial.length>0&&sent>0&&sent<=initial.length&&remaining===0`,
				`quiescentNoop=allowQuiescentNoop&&initial.length>=0&&sent===0&&remaining===0&&!escalated`,
				`ok=delivered||quiescentNoop`,
			},
		},
		{
			name:   "python",
			script: pythonServiceSignalScript,
			parts: []string{
				`delivered=len(initial)>0 and sent>0 and sent<=len(initial) and remaining==0`,
				`quiescent_noop=allow_quiescent_noop and len(initial)>=0 and sent==0 and remaining==0 and not escalated`,
				`ok=delivered or quiescent_noop`,
			},
		},
	} {
		t.Run(helper.name+" source", func(t *testing.T) {
			for _, part := range helper.parts {
				if !strings.Contains(helper.script, part) {
					t.Fatalf("%s helper predicate drift: %q", helper.name, part)
				}
			}
		})
	}

	tests := []struct {
		name              string
		response          signalHelperResult
		authorized        bool
		wantDelivered     bool
		wantQuiescentNoop bool
	}{
		{
			name: "delivered",
			response: signalHelperResult{
				OK: true, InitialTargets: 2, Sent: 1,
			},
			wantDelivered: true,
		},
		{
			name: "delivered escalation",
			response: signalHelperResult{
				OK: true, Escalated: true, InitialTargets: 1, Sent: 1,
			},
			wantDelivered: true,
		},
		{
			name:       "authorized zero target no-op",
			response:   signalHelperResult{OK: true},
			authorized: true, wantQuiescentNoop: true,
		},
		{
			name:       "authorized observed target no-op",
			response:   signalHelperResult{OK: true, InitialTargets: 2},
			authorized: true, wantQuiescentNoop: true,
		},
		{
			name:     "unauthorized zero target no-op",
			response: signalHelperResult{OK: true},
		},
		{
			name:     "unauthorized observed target no-op",
			response: signalHelperResult{OK: true, InitialTargets: 2},
		},
		{
			name:       "negative initial",
			response:   signalHelperResult{OK: true, InitialTargets: -1},
			authorized: true,
		},
		{
			name: "negative sent",
			response: signalHelperResult{
				OK: true, InitialTargets: 1, Sent: -1,
			},
			authorized: true,
		},
		{
			name: "sent exceeds initial",
			response: signalHelperResult{
				OK: true, InitialTargets: 1, Sent: 2,
			},
			authorized: true,
		},
		{
			name: "remaining target",
			response: signalHelperResult{
				OK: true, Remaining: 1, InitialTargets: 1,
			},
			authorized: true,
		},
		{
			name: "escalated no-op",
			response: signalHelperResult{
				OK: true, Escalated: true, InitialTargets: 1,
			},
			authorized: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivered, quiescentNoop := classifySignalHelperResult(
				test.response,
				test.authorized,
			)
			if delivered != test.wantDelivered ||
				quiescentNoop != test.wantQuiescentNoop {
				t.Fatalf(
					"classification delivered=%v no-op=%v",
					delivered,
					quiescentNoop,
				)
			}
		})
	}
}

func TestRunnerAuthorizedQuiescentNoOpStillWaitsForAttachedService(
	t *testing.T,
) {
	for _, test := range []struct {
		name    string
		initial int
	}{
		{name: "initial zero", initial: 0},
		{name: "observed target vanished", initial: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			mustWriteFile(
				t,
				filepath.Join(sourceRoot, "server.js"),
				[]byte("server fixture\n"),
			)
			plan := testHTTPPlan(t, sourceRoot)
			plan.Commands[len(plan.Commands)-1].Signal.GracePeriod = "1ms"

			releaseService := make(chan struct{})
			serviceReturned := make(chan struct{})
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
				case <-releaseService:
					close(serviceReturned)
					return 0, nil
				case <-ctx.Done():
					close(serviceReturned)
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
					if len(args) == 0 || args[len(args)-1] != "true" {
						t.Fatalf(
							"Runner finalization authorization missing: %v",
							args,
						)
					}
					_, _ = io.WriteString(
						stdout,
						fmt.Sprintf(
							`{"ok":true,"escalated":false,"remaining":0,`+
								`"initialTargets":%d,"sent":0}`+"\n",
							test.initial,
						),
					)
					close(releaseService)
					return 0, nil
				}
				return base(ctx, name, args, stdout, stderr)
			}
			fake.inputHandler = successfulHTTPJourneyInputHandler(t)

			outcome, err := testRunner(fake).Execute(
				context.Background(),
				plan,
				sourceRoot,
				t.TempDir(),
				"docker",
			)
			if err != nil {
				t.Fatalf("authorized no-op run failed: %v", err)
			}
			select {
			case <-serviceReturned:
			default:
				t.Fatal("Runner returned before attached service execution")
			}
			serviceResult := findStepByRole(t, outcome.Steps, "service")
			if serviceResult.ExitCode != 0 || serviceResult.ErrorCode != "" {
				t.Fatalf("attached service result = %#v", serviceResult)
			}
			signalResult := findStepByRole(t, outcome.Steps, "signal")
			if signalResult.ExitCode != 0 || signalResult.ErrorCode != "" {
				t.Fatalf("authorized no-op signal result = %#v", signalResult)
			}

			signalObserved := false
			exitObserved := false
			for _, observation := range outcome.Observations {
				switch observation.Operation {
				case "service.signal":
					if observation.Result == "succeeded" &&
						observation.Details["alreadyExited"] == true &&
						observation.Details["initialTargets"] == test.initial &&
						observation.Details["sent"] == 0 {
						signalObserved = true
					}
					if _, claimsDelivery := observation.Details["delivered"]; claimsDelivery {
						t.Fatalf("no-op observation implied signal delivery: %#v", observation)
					}
				case "service.exit":
					if observation.Result == "failed" &&
						observation.Details["exitedBeforeSignal"] == true {
						exitObserved = true
					}
				}
			}
			if !signalObserved || !exitObserved ||
				outcome.Cleanup != domain.CleanupClean {
				t.Fatalf(
					"no-op observations signal=%v exit=%v cleanup=%q: %#v",
					signalObserved,
					exitObserved,
					outcome.Cleanup,
					outcome.Observations,
				)
			}
		})
	}
}

func TestRunnerAuthorizedQuiescentNoOpWaitTimeoutFailsCleanup(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		filepath.Join(sourceRoot, "server.js"),
		[]byte("server fixture\n"),
	)
	plan := testHTTPPlan(t, sourceRoot)
	plan.Commands[len(plan.Commands)-1].Signal.GracePeriod = "1ms"

	serviceCancelled := make(chan struct{})
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
		<-ctx.Done()
		close(serviceCancelled)
		return -1, ctx.Err()
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
			if len(args) == 0 || args[len(args)-1] != "true" {
				t.Fatalf("Runner finalization authorization missing: %v", args)
			}
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"escalated":false,"remaining":0,`+
					`"initialTargets":0,"sent":0}`+"\n",
			)
			return 0, nil
		}
		return base(ctx, name, args, stdout, stderr)
	}
	fake.inputHandler = successfulHTTPJourneyInputHandler(t)
	runner := testRunner(fake)
	runner.config.CleanupTimeout = serviceSignalHelperSlack + time.Millisecond

	started := time.Now()
	outcome, err := runner.Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got != domain.CodeCleanupFailed {
		t.Fatalf("wait timeout code = %q, want %q: %v", got, domain.CodeCleanupFailed, err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("attached-service wait exceeded deterministic bound: %s", time.Since(started))
	}
	select {
	case <-serviceCancelled:
	case <-time.After(time.Second):
		t.Fatal("timed-out attached service was not cancelled")
	}
	if outcome.Cleanup != domain.CleanupInconclusive {
		t.Fatalf("wait timeout cleanup = %q", outcome.Cleanup)
	}
	signalObserved := false
	for _, observation := range outcome.Observations {
		if observation.Operation == "service.signal" &&
			observation.Result == "succeeded" &&
			observation.Details["alreadyExited"] == true &&
			observation.Details["sent"] == 0 {
			signalObserved = true
		}
	}
	if !signalObserved {
		t.Fatalf("authorized no-op signal observation missing: %#v", outcome.Observations)
	}
}

func TestEarlyServiceExecFailureNeverEmitsSuccessfulStart(
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
	base := successfulNodeSandbox(func(
		_ context.Context,
		_ string,
		args []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		if containsArgument(args, "/workspace/server.js") {
			return 125, errors.New("synthetic exec dispatch failure")
		}
		return 0, nil
	})
	fake := &inputFakeExecutor{
		fakeExecutor: &fakeExecutor{},
	}
	fake.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		if containsArgument(args, nodeServiceSignalScript) {
			if len(args) == 0 ||
				args[len(args)-1] != "true" {
				t.Fatalf(
					"known service exit was not authorized: %v",
					args,
				)
			}
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"escalated":false,"remaining":0,`+
					`"initialTargets":0,"sent":0}`+"\n",
			)
			return 0, nil
		}
		return base(ctx, name, args, stdout, stderr)
	}
	fake.inputHandler = func(
		context.Context,
		string,
		[]string,
		[]byte,
		io.Writer,
		io.Writer,
	) (int, error) {
		return 0, nil
	}
	outcome, err := testRunner(fake).Execute(
		context.Background(),
		plan,
		sourceRoot,
		runRoot,
		"docker",
	)
	if got := domain.ErrorCodeOf(err); got !=
		domain.CodeServiceStartFailed {
		t.Fatalf("service exec failure code = %q: %v", got, err)
	}
	dispatchObserved := false
	alreadyExitedObserved := false
	unexpectedExitObserved := false
	quiesceObserved := false
	for _, observation := range outcome.Observations {
		if observation.Operation == "service.dispatch" &&
			observation.Result == "observed" &&
			observation.Details["state"] == "attempted" {
			dispatchObserved = true
		}
		if observation.Operation == "service.start" &&
			observation.Result == "succeeded" {
			t.Fatalf(
				"early exec failure forged start success: %#v",
				observation,
			)
		}
		if observation.Operation == "service.signal" &&
			observation.Result == "succeeded" &&
			observation.Details["alreadyExited"] == true &&
			observation.Details["initialTargets"] == 0 &&
			observation.Details["sent"] == 0 {
			alreadyExitedObserved = true
		}
		if observation.Operation == "service.exit" &&
			observation.Result == "failed" &&
			observation.Details["exitedBeforeSignal"] == true {
			unexpectedExitObserved = true
		}
		if observation.Operation == "sandbox.processes.quiesce" &&
			observation.Result == "succeeded" {
			quiesceObserved = true
		}
	}
	if !dispatchObserved {
		t.Fatal("service dispatch attempt was not recorded")
	}
	if !alreadyExitedObserved ||
		!unexpectedExitObserved ||
		!quiesceObserved {
		t.Fatalf(
			"already-exited evidence signal=%v exit=%v quiesce=%v observations=%#v",
			alreadyExitedObserved,
			unexpectedExitObserved,
			quiesceObserved,
			outcome.Observations,
		)
	}
	signalResult := findStepByRole(t, outcome.Steps, "signal")
	if signalResult.ExitCode != 0 ||
		signalResult.ErrorCode != "" {
		t.Fatalf("already-exited signal result = %#v", signalResult)
	}
	if outcome.Cleanup != domain.CleanupClean {
		t.Fatalf("already-exited cleanup = %q", outcome.Cleanup)
	}
}

func successfulHTTPJourneyInputHandler(t *testing.T) func(
	context.Context,
	string,
	[]string,
	[]byte,
	io.Writer,
	io.Writer,
) (int, error) {
	t.Helper()
	return func(
		_ context.Context,
		_ string,
		args []string,
		_ []byte,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if !containsArgument(args, nodeHTTPHelperScript) {
			t.Fatalf("unexpected input helper command: %v", args)
		}
		_, _ = io.WriteString(
			stdout,
			`{"ok":true,"status":200,`+
				`"headers":[{"name":"content-type","value":"text/plain"}],`+
				`"bodyBase64":"aGVsbG8=","bodyBytes":5,`+
				`"bodyTruncated":false,"durationMillis":1}`+"\n",
		)
		return 0, nil
	}
}

func runtimeHeaders(count int, value string) map[string]string {
	headers := make(map[string]string, count)
	for index := 0; index < count; index++ {
		headers[fmt.Sprintf("x-%02d", index)] = value
	}
	return headers
}

func stringPointer(value string) *string {
	return &value
}
