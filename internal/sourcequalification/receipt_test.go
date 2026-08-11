// Package sourcequalification is expected to expose the following minimal
// RFC-0002 contract API:
//
//	type QualificationStatus string
//	const (
//		StatusPass QualificationStatus = "PASS"
//		StatusFail QualificationStatus = "FAIL"
//		StatusBlocked QualificationStatus = "BLOCKED"
//		StatusNotRun QualificationStatus = "NOT_RUN"
//	)
//	type Lane string
//	const (
//		LaneLinuxAMD64 Lane = "linux-amd64"
//		LaneWindowsAMD64 Lane = "windows-amd64"
//	)
//	type RunIdentity struct {
//		WorkflowRepository string
//		WorkflowPath string
//		Event string
//		Ref string
//		WorkflowRunID string
//		WorkflowRunAttempt int
//		TestedRevision string
//	}
//	func ReceiptTopLevelKeys() []string
//	func FixedLimitations() []string
//	func AggregateQualificationStatus([]QualificationStatus) QualificationStatus
//	func QualificationRunID(RunIdentity) string
//	func AttemptID(string, Lane, int) string
//	func ClosingAttemptEligible(RunIdentity, int) bool
package sourcequalification

import (
	"reflect"
	"testing"
)

func TestReceiptTopLevelKeysAndLimitationsAreFrozen(t *testing.T) {
	wantKeys := []string{
		"artifactType", "attempt", "controller", "execution", "gates",
		"limitations", "notApplicable", "platform", "predicateType",
		"productDimensions", "qualificationStatus", "run", "schemaVersion",
		"source", "subject",
	}
	if got := ReceiptTopLevelKeys(); !reflect.DeepEqual(got, wantKeys) {
		t.Fatalf("receipt top-level keys = %#v, want %#v", got, wantKeys)
	}

	wantLimitations := []string{
		"currentness-requires-live-caller-input",
		"gate-execution-is-self-ci",
		"github-artifact-is-untrusted-transport",
		"lfs-pointers-not-resolved",
		"network-service-state-is-not-bound",
		"no-external-review",
		"no-publisher-or-workflow-identity",
		"no-signature-transparency-trusted-time-or-revocation",
		"product-verdicts-not-evaluated",
		"rp-m0-qual-only",
		"stable-release-not-authorized",
	}
	if got := FixedLimitations(); !reflect.DeepEqual(got, wantLimitations) {
		t.Fatalf("limitations = %#v, want %#v", got, wantLimitations)
	}

	keys := ReceiptTopLevelKeys()
	keys[0] = "mutated"
	limitations := FixedLimitations()
	limitations[0] = "mutated"
	if ReceiptTopLevelKeys()[0] != wantKeys[0] || FixedLimitations()[0] != wantLimitations[0] {
		t.Fatal("frozen receipt slices expose mutable process state")
	}
}

func TestQualificationStatusAggregationPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		statuses []QualificationStatus
		want     QualificationStatus
	}{
		{"all pass", []QualificationStatus{StatusPass, StatusPass}, StatusPass},
		{"not run over pass", []QualificationStatus{StatusPass, StatusNotRun}, StatusNotRun},
		{"blocked over not run", []QualificationStatus{StatusNotRun, StatusBlocked, StatusPass}, StatusBlocked},
		{"fail over all", []QualificationStatus{StatusBlocked, StatusFail, StatusNotRun, StatusPass}, StatusFail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := AggregateQualificationStatus(test.statuses); got != test.want {
				t.Fatalf("aggregate = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunAndAttemptBinding(t *testing.T) {
	run := RunIdentity{
		WorkflowRepository: "taipei49314/RepoPassport",
		WorkflowPath:       ".github/workflows/source-qualification.yml",
		Event:              "push",
		Ref:                "refs/heads/main",
		WorkflowRunID:      "123456789",
		WorkflowRunAttempt: 1,
		TestedRevision:     "89abcdef0123456789abcdef0123456789abcdef",
	}
	const wantRunID = "sha256:b6ed912dadba5a87ce596820cc5b33e1882cc5b6ad1f6f8dc7b30d30e6537e68"
	if got := QualificationRunID(run); got != wantRunID {
		t.Fatalf("qualification run ID = %q, want %q", got, wantRunID)
	}
	if got, want := AttemptID(wantRunID, LaneLinuxAMD64, 2), wantRunID+":linux-amd64:2"; got != want {
		t.Fatalf("attempt ID = %q, want %q", got, want)
	}
	if !ClosingAttemptEligible(run, 1) {
		t.Fatal("first canonical main push attempt is not closure-eligible")
	}
	for _, mutate := range []func(*RunIdentity){
		func(value *RunIdentity) { value.Event = "workflow_dispatch" },
		func(value *RunIdentity) { value.Ref = "refs/heads/topic" },
		func(value *RunIdentity) { value.WorkflowRunAttempt = 2 },
	} {
		changed := run
		mutate(&changed)
		if ClosingAttemptEligible(changed, 1) {
			t.Fatalf("non-closing run accepted: %#v", changed)
		}
		if QualificationRunID(changed) == wantRunID {
			t.Fatalf("changed run retained qualification run ID: %#v", changed)
		}
	}
	if ClosingAttemptEligible(run, 2) {
		t.Fatal("receipt ordinal 2 is closure-eligible")
	}
}
