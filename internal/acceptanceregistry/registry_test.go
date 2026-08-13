package acceptanceregistry

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func TestPublishedRegistryMatchesExactContract(t *testing.T) {
	raw := readPublishedRegistry(t)
	registry, err := ParseRegistry(raw)
	if err != nil {
		t.Fatalf("ParseRegistry rejected the published contract: %v", err)
	}
	if registry.ArtifactType != "repopass-acceptance-registry" ||
		registry.Product != "repopass" || registry.SchemaVersion != "1" {
		t.Fatalf("registry identity = %#v", registry)
	}
	want := exactRegistryRows()
	if !rowsEqual(registry.Rows, want) {
		t.Fatalf("published registry rows differ from the exact 37-row contract\n got: %#v\nwant: %#v", registry.Rows, want)
	}
	digest, err := RegistryDigest(raw)
	if err != nil || !validSHA256Digest(digest) {
		t.Fatalf("RegistryDigest = %q, %v", digest, err)
	}
}

func TestParseRegistryRejectsScopeAndCanonicalTampering(t *testing.T) {
	raw := readPublishedRegistry(t)
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(map[string]any){
		"unknown top-level": func(value map[string]any) { value["extra"] = true },
		"wrong product":     func(value map[string]any) { value["product"] = "other" },
		"missing row": func(value map[string]any) {
			rows := value["rows"].([]any)
			value["rows"] = rows[:len(rows)-1]
		},
		"extra row": func(value map[string]any) {
			rows := value["rows"].([]any)
			value["rows"] = append(rows, cloneJSON(rows[len(rows)-1]))
		},
		"reordered rows": func(value map[string]any) {
			rows := value["rows"].([]any)
			rows[0], rows[1] = rows[1], rows[0]
		},
		"duplicate id": func(value map[string]any) {
			rows := value["rows"].([]any)
			rows[1].(map[string]any)["id"] = rows[0].(map[string]any)["id"]
		},
		"required false": func(value map[string]any) {
			value["rows"].([]any)[0].(map[string]any)["required"] = false
		},
		"criterion drift": func(value map[string]any) {
			value["rows"].([]any)[0].(map[string]any)["criterion"] = "weaker"
		},
		"platform drift": func(value map[string]any) {
			value["rows"].([]any)[0].(map[string]any)["appliesTo"] = []any{"repository"}
		},
		"policy drift": func(value map[string]any) {
			value["rows"].([]any)[0].(map[string]any)["evaluation"] = map[string]any{
				"kind":       "not-run",
				"reasonCode": "ROADMAP_WORK_NOT_SCHEDULED",
			}
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneJSON(document).(map[string]any)
			mutate(candidate)
			encoded, err := canonicaljson.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRegistry(encoded); err == nil {
				t.Fatal("ParseRegistry accepted scope tampering")
			}
		})
	}

	noncanonical := map[string][]byte{
		"trailing newline":         append(bytes.Clone(raw), '\n'),
		"leading BOM":              append([]byte{0xef, 0xbb, 0xbf}, raw...),
		"alternate whitespace":     append([]byte("{ "), raw[1:]...),
		"invalid UTF-8":            append([]byte{0xff}, raw...),
		"duplicate top-level name": append([]byte(`{"artifactType":"repopass-acceptance-registry",`), raw[1:]...),
		"oversized":                append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxRegistryBytes-len(raw)+1)...),
	}
	for name, candidate := range noncanonical {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRegistry(candidate); err == nil {
				t.Fatal("ParseRegistry accepted noncanonical or out-of-bounds bytes")
			}
		})
	}
}

func TestEvaluateDerivesInitialHonestState(t *testing.T) {
	registryRaw := readPublishedRegistry(t)
	request := validEvaluationRequest()
	raw, err := Evaluate(registryRaw, request)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	evaluation, err := ParseEvaluation(registryRaw, raw)
	if err != nil {
		t.Fatalf("ParseEvaluation: %v", err)
	}
	if evaluation.OverallStatus != OverallIncomplete || evaluation.FormalClaim || evaluation.StableEligible {
		t.Fatalf("evaluation overstates incomplete roadmap: %#v", evaluation)
	}
	if evaluation.Subject != request.Subject || evaluation.Run != request.Run {
		t.Fatal("evaluation subject or run drifted")
	}
	if len(evaluation.Rows) != 37 {
		t.Fatalf("evaluation rows = %d, want 37", len(evaluation.Rows))
	}
	want := map[string]RowStatus{
		"RP-B00":        StatusPass,
		"RP-B04":        StatusPass,
		"RP-M0-MODULE":  StatusPass,
		"RP-M0-QUAL":    StatusBlocked,
		"RP-M1-JOURNEY": StatusPass,
	}
	for _, row := range evaluation.Rows {
		expected, ok := want[row.ID]
		if !ok {
			expected = StatusNotRun
		}
		if row.Status != expected {
			t.Errorf("%s status = %s, want %s", row.ID, row.Status, expected)
		}
	}
	if !validSHA256Digest(evaluation.RegistryDigest) || !validSHA256Digest(evaluation.EvaluationDigest) {
		t.Fatal("evaluation digests are not canonical SHA-256 values")
	}
	if !bytes.Equal(raw, mustCanonical(t, evaluation)) {
		t.Fatal("Evaluate did not return canonical bytes")
	}
}

func TestEvaluateFailsClosedForRequiredCheckAndSubjectStates(t *testing.T) {
	registryRaw := readPublishedRegistry(t)
	tests := []struct {
		name      string
		mutate    func(*EvaluationRequest)
		overall   OverallStatus
		rowStatus map[string]RowStatus
		rowReason map[string]string
	}{
		{
			name: "pull request cannot close baseline",
			mutate: func(request *EvaluationRequest) {
				request.Run.Event = "pull_request"
				request.Run.Ref = "refs/pull/16/merge"
			},
			overall:   OverallIncomplete,
			rowStatus: map[string]RowStatus{"RP-B00": StatusNotRun},
			rowReason: map[string]string{"RP-B00": "NOT_DEFAULT_BRANCH"},
		},
		{
			name: "go failure",
			mutate: func(request *EvaluationRequest) {
				request.Checks.Go = "failure"
			},
			overall: OverallFail,
			rowStatus: map[string]RowStatus{
				"RP-B00":       StatusFail,
				"RP-M0-MODULE": StatusFail,
			},
		},
		{
			name: "container skipped",
			mutate: func(request *EvaluationRequest) {
				request.Checks.Container = "skipped"
			},
			overall: OverallIncomplete,
			rowStatus: map[string]RowStatus{
				"RP-B00":        StatusNotRun,
				"RP-B04":        StatusNotRun,
				"RP-M1-JOURNEY": StatusNotRun,
			},
		},
		{
			name: "windows cancelled",
			mutate: func(request *EvaluationRequest) {
				request.Checks.WindowsGo = "cancelled"
			},
			overall: OverallFail,
			rowStatus: map[string]RowStatus{
				"RP-B00":       StatusFail,
				"RP-M0-MODULE": StatusFail,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validEvaluationRequest()
			test.mutate(&request)
			raw, err := Evaluate(registryRaw, request)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			evaluation, err := ParseEvaluation(registryRaw, raw)
			if err != nil {
				t.Fatalf("ParseEvaluation: %v", err)
			}
			if evaluation.OverallStatus != test.overall || evaluation.StableEligible {
				t.Fatalf("roll-up = %s/%v, want %s/false", evaluation.OverallStatus, evaluation.StableEligible, test.overall)
			}
			for id, status := range test.rowStatus {
				row := evaluationRow(t, evaluation, id)
				if row.Status != status {
					t.Errorf("%s status = %s, want %s", id, row.Status, status)
				}
			}
			for id, reason := range test.rowReason {
				if got := evaluationRow(t, evaluation, id).ReasonCode; got != reason {
					t.Errorf("%s reason = %s, want %s", id, got, reason)
				}
			}
		})
	}
}

func TestParseEvaluationRejectsTamperingAndCompletionLaundering(t *testing.T) {
	registryRaw := readPublishedRegistry(t)
	raw, err := Evaluate(registryRaw, validEvaluationRequest())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"formal claim":          func(value map[string]any) { value["formalClaim"] = true },
		"stable eligible":       func(value map[string]any) { value["stableEligible"] = true },
		"overall pass":          func(value map[string]any) { value["overallStatus"] = "PASS" },
		"registry substitution": func(value map[string]any) { value["registryDigest"] = "sha256:" + strings.Repeat("f", 64) },
		"subject substitution":  func(value map[string]any) { value["subject"].(map[string]any)["treeSHA"] = strings.Repeat("f", 40) },
		"row pass laundering": func(value map[string]any) {
			rows := value["rows"].([]any)
			rows[1].(map[string]any)["status"] = "PASS"
			rows[1].(map[string]any)["reasonCode"] = "CURRENT_REQUIRED_CHECKS_PASSED"
		},
		"row reorder": func(value map[string]any) {
			rows := value["rows"].([]any)
			rows[0], rows[1] = rows[1], rows[0]
		},
		"evidence reorder": func(value map[string]any) {
			rows := value["rows"].([]any)
			evidence := rows[0].(map[string]any)["evidence"].([]any)
			evidence[0], evidence[1] = evidence[1], evidence[0]
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneJSON(document).(map[string]any)
			mutate(candidate)
			delete(candidate, "evaluationDigest")
			candidate["evaluationDigest"] = strings.Repeat("x", 71)
			encoded, marshalErr := canonicaljson.Marshal(candidate)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, err := ParseEvaluation(registryRaw, encoded); err == nil {
				t.Fatal("ParseEvaluation accepted tampering")
			}
		})
	}
	if err := RequireComplete(registryRaw, raw); err == nil {
		t.Fatal("RequireComplete accepted the intentionally incomplete v1 evaluation")
	}
}

func TestAggregateRowsPrecedenceAndCompletion(t *testing.T) {
	allPass := make([]RowEvaluation, 37)
	for index := range allPass {
		allPass[index] = RowEvaluation{ID: exactRegistryRows()[index].ID, Status: StatusPass}
	}
	if overall, stable := aggregateRows(allPass); overall != OverallPass || !stable {
		t.Fatalf("all-pass aggregate = %s/%v", overall, stable)
	}
	allPass[0].Status = StatusNotRun
	if overall, stable := aggregateRows(allPass); overall != OverallIncomplete || stable {
		t.Fatalf("not-run aggregate = %s/%v", overall, stable)
	}
	allPass[1].Status = StatusBlocked
	if overall, stable := aggregateRows(allPass); overall != OverallIncomplete || stable {
		t.Fatalf("blocked aggregate = %s/%v", overall, stable)
	}
	allPass[2].Status = StatusFail
	if overall, stable := aggregateRows(allPass); overall != OverallFail || stable {
		t.Fatalf("fail aggregate = %s/%v", overall, stable)
	}
}

func exactRegistryRows() []RegistryRow {
	rows := []RegistryRow{
		row("RP-B00", "BASELINE", []string{"github", "repository"}, "The baseline revision equals the live default branch, or default-branch drift is recorded and the baseline is recomputed."),
		row("RP-B01", "BASELINE", []string{"linux-amd64", "repository", "windows-amd64"}, "Source gates pass on their first attempt; public output and receipts remain outside the repository and contain no secret."),
		row("RP-B02", "BASELINE", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Current-source container evidence and historical Alpha evidence are classified without presenting historical evidence as current."),
		row("RP-B03", "BASELINE", []string{"docker-linux-amd64", "podman-linux-amd64", "repository"}, "The source worktree is clean before and after the baseline, with no process, container, network, or volume residue."),
		row("RP-B04", "BASELINE", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Healthy results remain capability INCOMPLETE and overall INCONCLUSIVE until the required observations exist."),
		row("RP-M0-CORPUS", "M0", []string{"linux-amd64", "repository", "windows-amd64"}, "The complete fixture matrix and frozen fuzz or property seeds pass on Linux and Windows build paths, and malicious fixtures fail closed."),
		row("RP-M0-MODULE", "M0", []string{"linux-amd64", "release", "repository", "windows-amd64"}, "Clone, build, import, module metadata, and release assets use one exact canonical repository namespace."),
		row("RP-M0-QUAL", "M0", []string{"linux-amd64", "repository", "windows-amd64"}, "The current source archive, required tests, and receipts bind one exact source revision and tree without repackaging historical Alpha evidence."),
		row("RP-M0-SPEC", "M0", []string{"linux-amd64", "repository", "windows-amd64"}, "Every public schema, specification, and reference behavior has machine-readable conformance coverage and unknown semantics fail closed."),
		row("RP-M1-JOURNEY", "M1", []string{"docker-linux-amd64", "podman-linux-amd64"}, "CLI and HTTP healthy journeys pass functionally, remain reproducibly stable, and clean up on every supported Docker and Podman tuple."),
		row("RP-M2-COVERAGE", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Every required observer category reaches its normative high or complete coverage and gap or overflow fixtures remain incomplete."),
		row("RP-M2-MATRIX", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Docker and Podman each have current exact-source clean-VM evidence with no required skip or retry laundering."),
		row("RP-M2-RESIDUE", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Success, timeout, cancellation, crash, termination-resistant, and early-exit paths restore the after-inventory to the baseline."),
		row("RP-M2-VERDICT", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "At least one healthy Node and Python profile honestly reaches capability CONFORMING and overall VERIFIED while adversarial gaps do not."),
		row("RP-M3-IDENTITY", "M3", []string{"external-review", "release"}, "Accepted evidence is authorized by external identity and policy; self-signed, unknown, revoked, or stale signers are not accepted."),
		row("RP-M3-INTEGRITY", "M3", []string{"external-review", "release"}, "Removal, rename, remint, signature, key, policy, source, and SBOM substitution all fail closed."),
		row("RP-M3-PORTABLE", "M3", []string{"linux-amd64", "release", "windows-amd64"}, "The release verifier kit validates the exact bundle on two clean operating systems without the producer worktree."),
		row("RP-M3-PRIVACY", "M3", []string{"release", "repository"}, "Every public file is typed and privacy-checked, and raw data renamed into an allowlisted slot is still rejected."),
		row("RP-M4-CHECK", "M4", []string{"github"}, "A real pull-request check binds the exact pull-request revision and maps healthy, failed, and inconclusive results according to the specification."),
		row("RP-M4-FORK", "M4", []string{"github"}, "A fork pull request receives no secret or write authority and artifact substitution cannot deceive the privileged publisher."),
		row("RP-M4-REPRO", "M4", []string{"github", "release"}, "A downloaded check artifact is independently verifiable and binds its workflow run and source revision."),
		row("RP-M5-JOURNEY", "M5", []string{"ui"}, "A new user can follow the README on a clean machine, complete the local trial, and verify the evidence."),
		row("RP-M5-SECURITY", "M5", []string{"ui"}, "Untrusted repository text or reports cannot execute script, inject HTML, open arbitrary network access, or disclose raw evidence."),
		row("RP-M5-TRUTH", "M5", []string{"ui"}, "Every UI status traces to the canonical model and visibly preserves INCOMPLETE or INCONCLUSIVE rather than presenting success."),
		row("RP-M6-AUTHORITY", "M6", []string{"hosted-runner"}, "A compromised worker or forged result cannot produce accepted evidence or a passing GitHub Check."),
		row("RP-M6-CLEANUP", "M6", []string{"hosted-runner"}, "Every termination path destroys the VM and credential, seals its store prefix, and restores the after-inventory to baseline."),
		row("RP-M6-ISOLATION", "M6", []string{"hosted-runner"}, "Two concurrent tenants have no filesystem, process, network, or artifact cross-contamination."),
		row("RP-M6-LIVE", "M6", []string{"hosted-runner"}, "An owner-controlled hosted environment has current-source evidence; without real infrastructure this row remains blocked."),
		row("RP-M7-CAPABILITY", "M7", []string{"plugin"}, "Unauthorized I/O is blocked before it occurs and a plugin cannot change policy, coverage, or the overall verdict."),
		row("RP-M7-CONFORMANCE", "M7", []string{"plugin"}, "Two reference plugins pass the same conformance kit and unsupported protocol versions return a stable error."),
		row("RP-M7-SUPPLYCHAIN", "M7", []string{"plugin", "release"}, "Plugin signature, trust, SBOM, and currentness are verifiable and an unknown signer remains unknown or blocked."),
		row("RP-Q-PROTOCOL", "QUALIFICATION", []string{"external-review", "release"}, "An independent reviewer approves and hash-freezes the acceptance policy before observing results."),
		row("RP-Q-REPLAY", "QUALIFICATION", []string{"external-review", "release"}, "The reviewer reruns the required matrix in a clean room with no unexplained required skip, blocked result, or internal error."),
		row("RP-Q-SUBJECT", "QUALIFICATION", []string{"external-review", "release"}, "The audited subject is the merged default-branch commit and tree plus final candidate artifact digests, and any later byte change invalidates the pass."),
		row("RP-Q-VERDICT", "QUALIFICATION", []string{"external-review", "release"}, "The reviewer returns PASS for the exact candidate with no open P0 or P1, and implementer or self-CI evidence cannot substitute for that verdict."),
		row("RP-REGISTRY", "M0", []string{"repository"}, "The complete M0--M7 registry and public specification or RFC exact set are closed and every required row has current evidence."),
		row("RP-R-STABLE-SCHEMA", "RELEASE", []string{"linux-amd64", "release", "windows-amd64"}, "Historical v1 verification, v2 round-trip and negative tests, and builder, CLI, and kit version agreement all pass."),
	}
	for index := range rows {
		switch rows[index].ID {
		case "RP-B00":
			rows[index].Evaluation = EvaluationPolicy{Kind: "required-checks", RequiredChecks: []string{"ci/container-matrix", "ci/go", "ci/schema-json", "ci/windows-go"}}
		case "RP-B04", "RP-M1-JOURNEY":
			rows[index].Evaluation = EvaluationPolicy{Kind: "required-checks", RequiredChecks: []string{"ci/container-matrix"}}
		case "RP-M0-MODULE":
			rows[index].Evaluation = EvaluationPolicy{Kind: "required-checks", RequiredChecks: []string{"ci/go", "ci/windows-go"}}
		case "RP-M0-QUAL":
			rows[index].Evaluation = EvaluationPolicy{Kind: "blocked", ReasonCode: "SOURCE_QUALIFICATION_PREREQUISITES_UNAVAILABLE"}
		default:
			rows[index].Evaluation = EvaluationPolicy{Kind: "not-run", ReasonCode: "ROADMAP_WORK_NOT_SCHEDULED"}
		}
	}
	return rows
}

func row(id, milestone string, appliesTo []string, criterion string) RegistryRow {
	return RegistryRow{AppliesTo: appliesTo, Criterion: criterion, ID: id, Milestone: milestone, Required: true}
}

func validEvaluationRequest() EvaluationRequest {
	return EvaluationRequest{
		Subject: Subject{
			Repository: "github.com/taipei49314/RepoPassport",
			Revision:   strings.Repeat("a", 40),
			TreeSHA:    strings.Repeat("b", 40),
		},
		Run: Run{
			Attempt:      1,
			Event:        "push",
			ID:           31673266929,
			Ref:          "refs/heads/main",
			WorkflowPath: ".github/workflows/ci.yml",
		},
		Checks: CheckResults{Container: "success", Go: "success", SchemaJSON: "success", WindowsGo: "success"},
	}
}

func readPublishedRegistry(t *testing.T) []byte {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(current), "..", "..", "acceptance-registry.json"))
	if err != nil {
		t.Fatalf("read acceptance-registry.json: %v", err)
	}
	return raw
}

func rowsEqual(left, right []RegistryRow) bool {
	leftRaw, leftErr := canonicaljson.Marshal(left)
	rightRaw, rightErr := canonicaljson.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func evaluationRow(t *testing.T, evaluation Evaluation, id string) RowEvaluation {
	t.Helper()
	for _, row := range evaluation.Rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("missing evaluation row %s", id)
	return RowEvaluation{}
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func cloneJSON(value any) any {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result any
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return result
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || (character > '9' && character < 'a') || character > 'f' {
			return false
		}
	}
	return true
}
