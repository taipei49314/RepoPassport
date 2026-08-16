package sourcequalification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"
)

const (
	attemptHistoryTokenEnvironment  = "SQ_GITHUB_TOKEN"
	attemptHistoryAPIURLEnvironment = "SQ_GITHUB_API_URL"
	attemptHistoryPageSize          = 100
	attemptHistoryMaximumPages      = 32
	attemptHistoryMaximumBodyBytes  = 4 << 20
	attemptHistoryRequestTimeout    = 30 * time.Second
)

// gitHubLaneAttemptHistoryProvider answers the prior-execution question from
// the authenticated GitHub workflow-run history of the canonical qualification
// workflow. Runs — not artifacts or receipt claims — are the history source.
// Any incomplete, inconsistent, or unauthenticated view is an error, never an
// answer: the caller converts that error to BLOCKED.
//
// The workflow executes both lanes on every run, so a prior run of the
// canonical workflow for the same tested revision is a prior execution for
// every lane scope; the lane field narrows nothing but stays in the scope the
// provider validates.
type gitHubLaneAttemptHistoryProvider struct {
	apiBaseURL string
	token      string
	client     *http.Client
}

// newEnvironmentLaneAttemptHistoryProvider selects the authenticated GitHub
// provider when the workflow supplied credentials, and otherwise keeps the
// fail-closed unavailable provider so non-CI invocations remain BLOCKED.
func newEnvironmentLaneAttemptHistoryProvider() laneAttemptHistoryProvider {
	token := os.Getenv(attemptHistoryTokenEnvironment)
	apiBaseURL := os.Getenv(attemptHistoryAPIURLEnvironment)
	if token == "" || apiBaseURL == "" {
		return unavailableLaneAttemptHistoryProvider{}
	}
	return &gitHubLaneAttemptHistoryProvider{
		apiBaseURL: apiBaseURL,
		token:      token,
		client:     &http.Client{Timeout: attemptHistoryRequestTimeout},
	}
}

type gitHubWorkflowRunPage struct {
	TotalCount   int64               `json:"total_count"`
	WorkflowRuns []gitHubWorkflowRun `json:"workflow_runs"`
}

type gitHubWorkflowRun struct {
	ID         int64  `json:"id"`
	HeadSHA    string `json:"head_sha"`
	RunAttempt int64  `json:"run_attempt"`
	Path       string `json:"path"`
}

func (provider *gitHubLaneAttemptHistoryProvider) HasPriorExecution(
	ctx context.Context,
	scope laneAttemptHistoryScope,
) (bool, error) {
	if ctx == nil || ctx.Err() != nil || provider == nil || provider.client == nil ||
		provider.token == "" || provider.apiBaseURL == "" || !validAttemptHistoryScope(scope) {
		return false, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	if scope.CurrentWorkflowAttempt > 1 {
		// A rerun means an earlier attempt already executed; RFC-0002 rejects
		// rerun laundering, so the answer is a definite prior execution.
		return true, nil
	}

	currentSeen := false
	prior := false
	for page := 1; page <= attemptHistoryMaximumPages; page++ {
		runs, err := provider.fetchWorkflowRunPage(ctx, scope, page)
		if err != nil {
			return false, err
		}
		for _, run := range runs {
			if run.Path != scope.WorkflowPath {
				return false, errAuthenticatedLaneAttemptHistoryUnavailable
			}
			runID := strconv.FormatInt(run.ID, 10)
			if runID == scope.CurrentWorkflowRunID {
				if run.HeadSHA != scope.TestedRevision ||
					run.RunAttempt != scope.CurrentWorkflowAttempt {
					return false, errAuthenticatedLaneAttemptHistoryUnavailable
				}
				currentSeen = true
				continue
			}
			if run.HeadSHA == scope.TestedRevision {
				prior = true
			}
		}
		if len(runs) < attemptHistoryPageSize {
			if !currentSeen {
				return false, errAuthenticatedLaneAttemptHistoryUnavailable
			}
			return prior, nil
		}
	}
	// More history than the bounded page budget: the view is incomplete.
	return false, errAuthenticatedLaneAttemptHistoryUnavailable
}

func (provider *gitHubLaneAttemptHistoryProvider) fetchWorkflowRunPage(
	ctx context.Context,
	scope laneAttemptHistoryScope,
	page int,
) ([]gitHubWorkflowRun, error) {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/actions/workflows/%s/runs?per_page=%d&page=%d",
		provider.apiBaseURL,
		scope.WorkflowRepository,
		url.PathEscape(path.Base(scope.WorkflowPath)),
		attemptHistoryPageSize,
		page,
	)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+provider.token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := provider.client.Do(request)
	if err != nil {
		return nil, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, attemptHistoryMaximumBodyBytes+1))
	if err != nil || int64(len(body)) > attemptHistoryMaximumBodyBytes {
		return nil, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	var decoded gitHubWorkflowRunPage
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.WorkflowRuns == nil {
		return nil, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	if len(decoded.WorkflowRuns) > attemptHistoryPageSize {
		return nil, errAuthenticatedLaneAttemptHistoryUnavailable
	}
	return decoded.WorkflowRuns, nil
}

func validAttemptHistoryScope(scope laneAttemptHistoryScope) bool {
	return scope.WorkflowRepository == canonicalWorkflowRepository &&
		scope.WorkflowPath == canonicalWorkflowPath &&
		validRepositoryOID(scope.TestedRevision) &&
		scope.CurrentWorkflowRunID != "" &&
		scope.CurrentWorkflowAttempt >= 1 &&
		(scope.Lane == LaneLinuxAMD64 || scope.Lane == LaneWindowsAMD64)
}
