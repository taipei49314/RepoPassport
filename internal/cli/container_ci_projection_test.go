//go:build integration

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestHealthyJourneyCIResultForLogRedactsSensitiveFields(t *testing.T) {
	const privateMarker = "private-marker-should-never-reach-ci"
	result := domain.VerificationResult{
		Errors: []*domain.Error{{
			Code:         domain.CodeReadinessFailed,
			Phase:        domain.PhaseRun,
			Message:      privateMarker,
			Details:      map[string]any{"raw": privateMarker},
			EvidenceRefs: []string{privateMarker},
			Suggestion:   privateMarker,
		}},
		Repeats: domain.RepeatSummary{Requested: 3, Completed: 2, Matching: 1},
		Runner: domain.RunnerFeatures{
			Backend:                    "podman",
			Available:                  true,
			NetworkDeny:                true,
			NetworkAttemptObservation:  "unavailable",
			ProcessExecObservation:     "best-effort",
			FilesystemWriteObservation: "unavailable",
			FilesystemReadObservation:  "full",
			PortObservation:            "unavailable",
			ResourceUsage:              "full",
			ResourceLimitEnforcement:   true,
			Reason:                     privateMarker,
		},
	}

	raw, err := json.Marshal(healthyJourneyCIResultForLog(result))
	if err != nil {
		t.Fatalf("marshal CI projection: %v", err)
	}
	text := string(raw)
	for _, required := range []string{
		`"code":"READINESS_FAILED"`,
		`"phase":"run"`,
		`"requested":3`,
		`"completed":2`,
		`"matching":1`,
		`"backend":"podman"`,
		`"resourceLimitEnforcement":true`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("CI projection omitted %q: %s", required, text)
		}
	}
	for _, forbidden := range []string{
		privateMarker,
		`"message"`,
		`"details"`,
		`"evidenceRefs"`,
		`"suggestion"`,
		`"reason"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("CI projection disclosed %q: %s", forbidden, text)
		}
	}
}
