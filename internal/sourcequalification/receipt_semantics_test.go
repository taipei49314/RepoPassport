package sourcequalification

import (
	"strings"
	"testing"
)

func TestParseCanonicalReceiptRejectsAdditionalPrivacyCandidatesWithoutEcho(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	tests := []struct {
		name              string
		candidate         string
		sensitiveFragment string
	}{
		{
			name:              "POSIX path",
			candidate:         "/home/private-user/repopass/runner-image",
			sensitiveFragment: "private-user",
		},
		{
			name:              "URL query",
			candidate:         "https://ci.example.invalid/job?token=TEST_QUERY_SECRET",
			sensitiveFragment: "TEST_QUERY_SECRET",
		},
		{
			name:              "email",
			candidate:         "private.builder@example.invalid",
			sensitiveFragment: "private.builder@example.invalid",
		},
		{
			name:              "authorization header",
			candidate:         "Authorization: Bearer TEST_AUTH_SECRET_0123456789",
			sensitiveFragment: "TEST_AUTH_SECRET",
		},
		{
			name:              "PEM private key header",
			candidate:         "-----BEGIN PRIVATE KEY-----",
			sensitiveFragment: "PRIVATE KEY",
		},
		{
			name:              "unrecognized high entropy",
			candidate:         "f9Q2vL7mK4pR8xT1wY6cN3bH0sJ5dG9uI2oE7aZ4nM8rP6kV1qC5",
			sensitiveFragment: "f9Q2vL7mK4pR8xT1wY6c",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
				receiptParserObject(document, "platform")["runnerImage"] = test.candidate
			})
			_, err := parseCanonicalReceipt(raw, LaneLinuxAMD64)
			if err == nil {
				t.Fatal("parseCanonicalReceipt accepted a forbidden privacy candidate")
			}
			message := strings.ToLower(err.Error())
			for _, forbidden := range []string{test.candidate, test.sensitiveFragment} {
				if strings.Contains(message, strings.ToLower(forbidden)) {
					t.Fatal("parseCanonicalReceipt error echoed rejected private content")
				}
			}
		})
	}
}

func TestParseCanonicalReceiptRejectsFieldAwarePrivacyCandidatesWithoutEcho(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	tests := []struct {
		name              string
		candidate         string
		sensitiveFragment string
		mutate            func(map[string]any, string)
	}{
		{
			name:              "kernel version endpoint",
			candidate:         "6.11.0 runner.internal:443",
			sensitiveFragment: "runner.internal",
			mutate: func(document map[string]any, candidate string) {
				receiptParserObject(document, "platform")["kernelVersion"] = candidate
			},
		},
		{
			name:              "temporary POSIX path",
			candidate:         "/tmp/repopass-private/runner-image",
			sensitiveFragment: "repopass-private",
			mutate: func(document map[string]any, candidate string) {
				receiptParserObject(document, "platform")["runnerImage"] = candidate
			},
		},
		{
			name:              "manual ref email",
			candidate:         "refs/heads/private.builder@example.invalid",
			sensitiveFragment: "private.builder@example.invalid",
			mutate: func(document map[string]any, candidate string) {
				receiptPrivacySetManualRef(document, LaneLinuxAMD64, candidate)
			},
		},
		{
			name:              "manual ref high entropy",
			candidate:         "refs/heads/f9Q2vL7mK4pR8xT1wY6cN3bH0sJ5dG9uI2oE7aZ4nM8rP6kV1qC5",
			sensitiveFragment: "f9Q2vL7mK4pR8xT1wY6c",
			mutate: func(document map[string]any, candidate string) {
				receiptPrivacySetManualRef(document, LaneLinuxAMD64, candidate)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
				test.mutate(document, test.candidate)
			})
			_, err := parseCanonicalReceipt(raw, LaneLinuxAMD64)
			if err == nil {
				t.Fatal("parseCanonicalReceipt accepted a forbidden field-aware privacy candidate")
			}
			message := strings.ToLower(err.Error())
			for _, forbidden := range []string{test.candidate, test.sensitiveFragment} {
				if strings.Contains(message, strings.ToLower(forbidden)) {
					t.Fatal("parseCanonicalReceipt error echoed rejected private content")
				}
			}
		})
	}
}

func receiptPrivacySetManualRef(document map[string]any, lane Lane, ref string) {
	run := receiptParserObject(document, "run")
	run["event"] = "workflow_dispatch"
	run["ref"] = ref
	identity := RunIdentity{
		WorkflowRepository: run["workflowRepository"].(string),
		WorkflowPath:       run["workflowPath"].(string),
		Event:              run["event"].(string),
		Ref:                ref,
		WorkflowRunID:      run["workflowRunId"].(string),
		WorkflowRunAttempt: run["workflowRunAttempt"].(int),
		TestedRevision:     run["headSHA"].(string),
	}
	qualificationRunID := QualificationRunID(identity)
	run["qualificationRunId"] = qualificationRunID
	receiptParserObject(document, "attempt")["attemptId"] = AttemptID(qualificationRunID, lane, 1)
}

func TestParseCanonicalReceiptFieldAwarePrivacyKeepsStrictValuesExempt(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
		receiptPrivacySetManualRef(document, LaneLinuxAMD64, "refs/heads/release/v0.1.0-alpha.33")
	})
	if _, err := parseCanonicalReceipt(raw, LaneLinuxAMD64); err != nil {
		t.Fatalf("parseCanonicalReceipt rejected strict digests, IDs, timestamps, or safe manual ref: %v", err)
	}
}

func TestParseCanonicalReceiptAcceptsRFCFailExitVariants(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	tests := []struct {
		name     string
		exitCode any
	}{
		{name: "semantic mismatch exit zero", exitCode: int64(0)},
		{name: "timeout null exit", exitCode: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
				gates := receiptParserArray(document, "gates")
				failed := gates[0].(map[string]any)
				failed["exitCode"] = test.exitCode
				failed["status"] = "FAIL"
				for _, value := range gates[1:] {
					gate := value.(map[string]any)
					gate["exitCode"] = nil
					gate["finishedAt"] = nil
					gate["startedAt"] = nil
					gate["status"] = "NOT_RUN"
				}
				document["qualificationStatus"] = "FAIL"
				receiptParserObject(document, "execution")["skippedGateCount"] = int64(len(gates) - 1)
			})
			if _, err := parseCanonicalReceipt(raw, LaneLinuxAMD64); err != nil {
				t.Fatalf("parseCanonicalReceipt rejected RFC FAIL outcome: %v", err)
			}
		})
	}
}

func TestParseCanonicalReceiptAcceptsOrdinalTwoHistoryButClosureRejectsIt(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
		receiptSemanticsSetOrdinalTwo(document, LaneLinuxAMD64)
	})
	receipt, err := parseCanonicalReceipt(raw, LaneLinuxAMD64)
	if err != nil {
		t.Fatalf("parseCanonicalReceipt rejected valid ordinal-two history: %v", err)
	}
	if receipt.Attempt.Ordinal != 2 || len(receipt.Attempt.PriorAttempts) != 1 ||
		receipt.Attempt.RetryOf == nil ||
		*receipt.Attempt.RetryOf != receipt.Attempt.PriorAttempts[0].AttemptID {
		t.Fatal("parseCanonicalReceipt did not preserve the ordinal-two retry chain")
	}
	run := RunIdentity{
		WorkflowRepository: receipt.Run.WorkflowRepository,
		WorkflowPath:       receipt.Run.WorkflowPath,
		Event:              receipt.Run.Event,
		Ref:                receipt.Run.Ref,
		WorkflowRunID:      receipt.Run.WorkflowRunID,
		WorkflowRunAttempt: int(receipt.Run.WorkflowRunAttempt),
		TestedRevision:     receipt.Subject.TestedRevision,
	}
	if !ClosingAttemptEligible(run, 1) {
		t.Fatal("canonical main-push fixture is not otherwise closure-eligible")
	}
	if ClosingAttemptEligible(run, int(receipt.Attempt.Ordinal)) {
		t.Fatal("historical ordinal-two receipt crossed the closure boundary")
	}
}

func TestParseCanonicalReceiptRejectsOrdinalTwoHistoryTampering(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "retry does not bind immediate predecessor",
			mutate: func(document map[string]any) {
				receiptParserObject(document, "attempt")["retryOf"] = "sha256:" + strings.Repeat("2", 64) + ":linux-amd64:1"
			},
		},
		{
			name: "prior attempt claims pass",
			mutate: func(document map[string]any) {
				attempt := receiptParserObject(document, "attempt")
				prior := attempt["priorAttempts"].([]any)[0].(map[string]any)
				prior["qualificationStatus"] = "PASS"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, func(document map[string]any) {
				receiptSemanticsSetOrdinalTwo(document, LaneLinuxAMD64)
				test.mutate(document)
			})
			if _, err := parseCanonicalReceipt(raw, LaneLinuxAMD64); err == nil {
				t.Fatal("parseCanonicalReceipt accepted tampered ordinal-two history")
			}
		})
	}
}

func receiptSemanticsSetOrdinalTwo(document map[string]any, lane Lane) {
	run := receiptParserObject(document, "run")
	qualificationRunID := run["qualificationRunId"].(string)
	priorAttemptID := "sha256:" + strings.Repeat("1", 64) + ":" + string(lane) + ":1"
	attempt := receiptParserObject(document, "attempt")
	attempt["attemptId"] = AttemptID(qualificationRunID, lane, 2)
	attempt["ordinal"] = 2
	attempt["priorAttempts"] = []any{
		map[string]any{
			"attemptId":           priorAttemptID,
			"qualificationStatus": "FAIL",
			"receiptSHA256":       receiptParserSHA256([]byte("prior canonical receipt")),
		},
	}
	attempt["retryOf"] = priorAttemptID
}
