package canonicaljson

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalIsStableAcrossMapOrder(t *testing.T) {
	first := map[string]any{
		"z": map[string]any{"two": 2, "one": 1},
		"a": []any{"x", json.Number("3")},
	}
	second := map[string]any{
		"a": []any{"x", json.Number("3")},
		"z": map[string]any{"one": 1, "two": 2},
	}

	firstJSON, err := Marshal(first)
	if err != nil {
		t.Fatalf("Marshal(first): %v", err)
	}
	secondJSON, err := Marshal(second)
	if err != nil {
		t.Fatalf("Marshal(second): %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("map insertion order changed canonical JSON:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}

	firstDigest, err := Digest(first)
	if err != nil {
		t.Fatalf("Digest(first): %v", err)
	}
	secondDigest, err := Digest(second)
	if err != nil {
		t.Fatalf("Digest(second): %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("map insertion order changed digest: %q != %q", firstDigest, secondDigest)
	}
}

func TestMarshalIsIdempotent(t *testing.T) {
	input := map[string]any{
		"nested": map[string]any{"b": true, "a": nil},
		"number": json.Number("1000000000000000001"),
		"text":   "<untrusted>",
	}

	first, err := Marshal(input)
	if err != nil {
		t.Fatalf("Marshal(input): %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(first))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode canonical JSON: %v", err)
	}
	second, err := Marshal(decoded)
	if err != nil {
		t.Fatalf("Marshal(decoded): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonicalization was not idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestMarshalRejectsNonASCIIObjectKeys(t *testing.T) {
	if _, err := Marshal(map[string]any{"鍵": "value"}); err == nil {
		t.Fatal("Marshal unexpectedly accepted a non-ASCII object key")
	}
}
