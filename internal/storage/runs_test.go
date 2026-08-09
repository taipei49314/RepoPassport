package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/verification"
)

func TestRunStoreRoundTripUsesAuthoritativeRoot(t *testing.T) {
	base := t.TempDir()
	trustedRoot := filepath.Join(base, "trusted-runs")
	workloadOutput := filepath.Join(base, "workload", "outputs")
	if err := os.MkdirAll(workloadOutput, 0o700); err != nil {
		t.Fatalf("create workload output: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(workloadOutput, "verification.json"),
		[]byte(`{"verificationId":"workload-forged","results":{"overall":"verified"}}`),
		0o600,
	); err != nil {
		t.Fatalf("write forged workload verification: %v", err)
	}

	result := authoritativeResult(t)
	store := RunStore{Root: trustedRoot}
	directory, err := store.Write(result)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if filepath.Clean(directory) == filepath.Clean(workloadOutput) {
		t.Fatal("trusted run store resolved to the workload output directory")
	}

	got, err := store.Read(result.RunID)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.VerificationID != result.VerificationID || got.Results.Overall != result.Results.Overall {
		t.Fatalf("Read returned non-authoritative result: %#v", got)
	}
	for _, name := range []string{
		"verification.json",
		"report.html",
		"observations.ndjson",
		"assertions.json",
		"policy-decisions.json",
	} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("authoritative artifact %s is missing: %v", name, err)
		}
	}
}

func TestRunStoreRejectsTraversalRunID(t *testing.T) {
	store := RunStore{Root: t.TempDir()}
	for _, id := range []string{"../vrf_escape", `vrf_..\escape`, "workload-controlled"} {
		if _, err := store.Directory(id); err == nil {
			t.Fatalf("Directory(%q) unexpectedly succeeded", id)
		} else if got := domain.ErrorCodeOf(err); got != domain.CodeSourcePathTraversal {
			t.Fatalf("Directory(%q) code = %q, want %q: %v", id, got, domain.CodeSourcePathTraversal, err)
		}
	}
}

func TestRunStoreRejectsTamperedVerification(t *testing.T) {
	store := RunStore{Root: t.TempDir()}
	result := authoritativeResult(t)
	directory, err := store.Write(result)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := filepath.Join(directory, "verification.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read verification artifact: %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"functional": "pass"`), []byte(`"functional": "fail"`), 1)
	if bytes.Equal(data, tampered) {
		t.Fatal("test did not locate the functional verdict to tamper")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered verification artifact: %v", err)
	}

	_, err = store.Read(result.RunID)
	if err == nil {
		t.Fatal("Read accepted a verification artifact whose protected contents were modified")
	}
	if got := domain.ErrorCodeOf(err); got != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("Read tamper code = %q, want %q: %v", got, domain.CodeEvidenceDigestMismatch, err)
	}
}

func TestRunStoreRejectsSymlinkedAuthoritativeRoot(t *testing.T) {
	base := t.TempDir()
	realRoot := filepath.Join(base, "real-runs")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatalf("create real root: %v", err)
	}
	linkedRoot := filepath.Join(base, "linked-runs")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	store := RunStore{Root: linkedRoot}
	if _, err := store.Write(authoritativeResult(t)); err == nil {
		t.Fatal("Write accepted a symlinked authoritative root")
	} else if got := domain.ErrorCodeOf(err); got != domain.CodeEvidenceDigestMismatch {
		t.Fatalf("symlinked root code = %q, want %q: %v", got, domain.CodeEvidenceDigestMismatch, err)
	}
}

func authoritativeResult(t *testing.T) domain.VerificationResult {
	t.Helper()
	started := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	result, err := verification.Build(verification.Input{
		RunID:          "run_authoritative",
		VerificationID: "vrf_authoritative",
		Plan: domain.ResolvedPlan{
			SchemaVersion: "4",
			Evidence: domain.PlanEvidence{
				Profile: "minimal-public",
				Include: []string{"normalized-observations", "verification-summary"},
				Exclude: []string{"raw-stderr", "raw-stdout", "raw-syscall-trace"},
			},
			Source: domain.PlanSource{
				Identity:   "sha256:source",
				TreeDigest: "sha256:tree",
			},
			Scenario:           "quickstart",
			Environment:        "linux-node",
			PlanDigest:         "sha256:plan",
			PolicyBundleDigest: "sha256:policy",
			ObserverSet:        []string{"network-enforcement"},
		},
		Runner:      domain.RunnerFeatures{Backend: "test", NetworkDeny: true},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Observations: []domain.ObservationEvent{{
			SchemaVersion: "1",
			Timestamp:     started,
			Phase:         domain.PhaseCleanup,
			Actor:         "trusted-runner",
			Operation:     "cleanup.residue.summary",
			Resource:      "/outputs",
			Result:        "succeeded",
			Observer:      "controller-cleanup-residue-classifier",
			Coverage:      "enforcement-only",
			Confidence:    "high",
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
				"opaqueInventoryToken":      "hmac-sha256:abababababababababababababababababababababababababababababababab",
				"quiescenceConfirmed":       true,
				"regularFileCount":          0,
				"scope":                     "/outputs",
				"specialCount":              0,
				"symlinkCount":              0,
				"tokenScheme":               "ephemeral-keyed-hmac-sha256",
				"unmatchedCount":            0,
				"verdict":                   "clean",
			},
		}},
		Assertions: []domain.AssertionResult{{ID: "journey", Type: "exit-code", Status: "pass"}},
		Requested:  1,
		Completed:  1,
		Matching:   1,
		Cleanup:    domain.CleanupClean,
	})
	if err != nil {
		t.Fatalf("verification.Build: %v", err)
	}
	return result
}
