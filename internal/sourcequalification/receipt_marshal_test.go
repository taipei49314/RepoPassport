package sourcequalification

// Production contract under test:
//
//	func marshalCanonicalReceipt(qualificationReceipt, Lane) ([]byte, error)
//
// The producer must emit the byte-identical canonical document accepted by
// the independent strict parser; it may not repair an invalid receipt.

import (
	"bytes"
	"testing"
)

func TestMarshalCanonicalReceiptReproducesStrictLaneReceipt(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	for _, lane := range []Lane{LaneLinuxAMD64, LaneWindowsAMD64} {
		want := receiptParserCanonical(t, lane, archive, manifest, nil)
		document, err := parseCanonicalReceipt(want, lane)
		if err != nil {
			t.Fatalf("parse fixture %s: %v", lane, err)
		}
		got, err := marshalCanonicalReceipt(document, lane)
		if err != nil {
			t.Fatalf("marshalCanonicalReceipt(%s): %v", lane, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("canonical receipt bytes changed for %s", lane)
		}
		if len(got) == 0 || got[len(got)-1] == '\n' {
			t.Fatalf("canonical receipt for %s is empty or newline terminated", lane)
		}
	}
}

func TestMarshalCanonicalReceiptRejectsInsteadOfRepairingInvalidFacts(t *testing.T) {
	archive := []byte("canonical archive bytes")
	manifest := []byte(`{"artifactType":"repopass-source-archive-manifest"}`)
	raw := receiptParserCanonical(t, LaneLinuxAMD64, archive, manifest, nil)
	document, err := parseCanonicalReceipt(raw, LaneLinuxAMD64)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*qualificationReceipt)
	}{
		{"wrong lane", func(value *qualificationReceipt) { value.Run.Lane = LaneWindowsAMD64 }},
		{"wrong status", func(value *qualificationReceipt) { value.QualificationStatus = StatusBlocked }},
		{"raw logs", func(value *qualificationReceipt) { value.Execution.RawLogsPublished = true }},
		{"missing gate", func(value *qualificationReceipt) { value.Gates = value.Gates[:len(value.Gates)-1] }},
		{"private platform value", func(value *qualificationReceipt) { value.Platform.RunnerImage = `C:\Users\private\runner` }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := document
			candidate.Gates = append([]receiptGate(nil), document.Gates...)
			test.mutate(&candidate)
			if raw, err := marshalCanonicalReceipt(candidate, LaneLinuxAMD64); err == nil || raw != nil {
				t.Fatalf("invalid receipt was emitted: bytes=%d err=%v", len(raw), err)
			}
		})
	}
}
