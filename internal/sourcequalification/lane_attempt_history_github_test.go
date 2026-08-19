package sourcequalification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type historyTestRun struct {
	ID         int64  `json:"id"`
	HeadSHA    string `json:"head_sha"`
	RunAttempt int64  `json:"run_attempt"`
	Path       string `json:"path"`
}

func historyTestScope() laneAttemptHistoryScope {
	return laneAttemptHistoryScope{
		WorkflowRepository:     canonicalWorkflowRepository,
		WorkflowPath:           canonicalWorkflowPath,
		TestedRevision:         "5311458d349ba4d5f5bbbdda70f24e1b3fddf318",
		Lane:                   LaneLinuxAMD64,
		CurrentWorkflowRunID:   "31958060805",
		CurrentWorkflowAttempt: 1,
	}
}

func startLoopbackTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listen is unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	return server
}

func historyTestServer(t *testing.T, pages map[int][]historyTestRun) *httptest.Server {
	t.Helper()
	return startLoopbackTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		page := 1
		if value := request.URL.Query().Get("page"); value != "" {
			fmt.Sscanf(value, "%d", &page)
		}
		runs := pages[page]
		if runs == nil {
			runs = []historyTestRun{}
		}
		total := 0
		for _, pageRuns := range pages {
			total += len(pageRuns)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"total_count":   total,
			"workflow_runs": runs,
		})
	}))
}

func historyTestProvider(server *httptest.Server) laneAttemptHistoryProvider {
	return &gitHubLaneAttemptHistoryProvider{
		apiBaseURL: server.URL,
		token:      "test-token",
		client:     server.Client(),
	}
}

func currentHistoryTestRun() historyTestRun {
	scope := historyTestScope()
	return historyTestRun{
		ID:         31958060805,
		HeadSHA:    scope.TestedRevision,
		RunAttempt: 1,
		Path:       scope.WorkflowPath,
	}
}

func TestGitHubAttemptHistoryReportsNoPriorExecution(t *testing.T) {
	server := historyTestServer(t, map[int][]historyTestRun{
		1: {
			currentHistoryTestRun(),
			{ID: 900, HeadSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RunAttempt: 1, Path: canonicalWorkflowPath},
		},
	})
	defer server.Close()
	prior, err := historyTestProvider(server).HasPriorExecution(context.Background(), historyTestScope())
	if err != nil || prior {
		t.Fatalf("expected no prior execution, got prior=%v err=%v", prior, err)
	}
}

func TestGitHubAttemptHistoryDetectsPriorRunForRevision(t *testing.T) {
	scope := historyTestScope()
	server := historyTestServer(t, map[int][]historyTestRun{
		1: {
			currentHistoryTestRun(),
			{ID: 901, HeadSHA: scope.TestedRevision, RunAttempt: 1, Path: canonicalWorkflowPath},
		},
	})
	defer server.Close()
	prior, err := historyTestProvider(server).HasPriorExecution(context.Background(), scope)
	if err != nil || !prior {
		t.Fatalf("expected prior execution, got prior=%v err=%v", prior, err)
	}
}

func TestGitHubAttemptHistoryDetectsPriorRunAcrossPages(t *testing.T) {
	scope := historyTestScope()
	firstPage := make([]historyTestRun, 0, 100)
	firstPage = append(firstPage, currentHistoryTestRun())
	for index := 0; index < 99; index++ {
		firstPage = append(firstPage, historyTestRun{
			ID:         int64(1000 + index),
			HeadSHA:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			RunAttempt: 1,
			Path:       canonicalWorkflowPath,
		})
	}
	server := historyTestServer(t, map[int][]historyTestRun{
		1: firstPage,
		2: {{ID: 902, HeadSHA: scope.TestedRevision, RunAttempt: 1, Path: canonicalWorkflowPath}},
	})
	defer server.Close()
	prior, err := historyTestProvider(server).HasPriorExecution(context.Background(), scope)
	if err != nil || !prior {
		t.Fatalf("expected prior execution across pages, got prior=%v err=%v", prior, err)
	}
}

func TestGitHubAttemptHistoryRequiresCurrentRunInView(t *testing.T) {
	server := historyTestServer(t, map[int][]historyTestRun{
		1: {{ID: 903, HeadSHA: "cccccccccccccccccccccccccccccccccccccccc", RunAttempt: 1, Path: canonicalWorkflowPath}},
	})
	defer server.Close()
	_, err := historyTestProvider(server).HasPriorExecution(context.Background(), historyTestScope())
	if !errors.Is(err, errAuthenticatedLaneAttemptHistoryUnavailable) {
		t.Fatalf("expected unavailable error when the current run is missing, got %v", err)
	}
}

func TestGitHubAttemptHistoryTreatsRerunAttemptAsPrior(t *testing.T) {
	scope := historyTestScope()
	scope.CurrentWorkflowAttempt = 2
	current := currentHistoryTestRun()
	current.RunAttempt = 2
	server := historyTestServer(t, map[int][]historyTestRun{1: {current}})
	defer server.Close()
	prior, err := historyTestProvider(server).HasPriorExecution(context.Background(), scope)
	if err != nil || !prior {
		t.Fatalf("expected rerun attempt to count as prior execution, got prior=%v err=%v", prior, err)
	}
}

func TestGitHubAttemptHistoryRejectsInconsistentCurrentRun(t *testing.T) {
	current := currentHistoryTestRun()
	current.HeadSHA = "dddddddddddddddddddddddddddddddddddddddd"
	server := historyTestServer(t, map[int][]historyTestRun{1: {current}})
	defer server.Close()
	_, err := historyTestProvider(server).HasPriorExecution(context.Background(), historyTestScope())
	if !errors.Is(err, errAuthenticatedLaneAttemptHistoryUnavailable) {
		t.Fatalf("expected unavailable error for inconsistent current run, got %v", err)
	}
}

func TestGitHubAttemptHistoryFailsClosedOnServerError(t *testing.T) {
	server := startLoopbackTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	_, err := historyTestProvider(server).HasPriorExecution(context.Background(), historyTestScope())
	if !errors.Is(err, errAuthenticatedLaneAttemptHistoryUnavailable) {
		t.Fatalf("expected unavailable error on server failure, got %v", err)
	}
}

func TestGitHubAttemptHistoryRejectsIncompleteScope(t *testing.T) {
	server := historyTestServer(t, map[int][]historyTestRun{1: {currentHistoryTestRun()}})
	defer server.Close()
	scope := historyTestScope()
	scope.TestedRevision = ""
	if _, err := historyTestProvider(server).HasPriorExecution(context.Background(), scope); !errors.Is(err, errAuthenticatedLaneAttemptHistoryUnavailable) {
		t.Fatalf("expected unavailable error for incomplete scope, got %v", err)
	}
	wrongRepository := historyTestScope()
	wrongRepository.WorkflowRepository = "someone/else"
	if _, err := historyTestProvider(server).HasPriorExecution(context.Background(), wrongRepository); !errors.Is(err, errAuthenticatedLaneAttemptHistoryUnavailable) {
		t.Fatalf("expected unavailable error for foreign repository scope, got %v", err)
	}
}

func TestEnvironmentAttemptHistoryProviderSelection(t *testing.T) {
	t.Setenv("SQ_GITHUB_TOKEN", "")
	t.Setenv("SQ_GITHUB_API_URL", "")
	if _, ok := newEnvironmentLaneAttemptHistoryProvider().(unavailableLaneAttemptHistoryProvider); !ok {
		t.Fatal("expected unavailable provider without environment configuration")
	}
	t.Setenv("SQ_GITHUB_TOKEN", "test-token")
	t.Setenv("SQ_GITHUB_API_URL", "https://api.github.example")
	if _, ok := newEnvironmentLaneAttemptHistoryProvider().(*gitHubLaneAttemptHistoryProvider); !ok {
		t.Fatal("expected GitHub provider with environment configuration")
	}
}
