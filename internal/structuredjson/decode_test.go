package structuredjson

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestDecodePreservesNumbersAndJSONShape(t *testing.T) {
	value, err := Decode(
		[]byte(`{"integer":9007199254740993,"decimal":1.50,"items":[true,null,"ok"]}`),
		DefaultInstanceDecodeLimits(),
	)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("Decode type = %T", value)
	}
	if got, ok := object["integer"].(json.Number); !ok ||
		got.String() != "9007199254740993" {
		t.Fatalf("integer = %#v (%T)", object["integer"], object["integer"])
	}
	if got, ok := object["decimal"].(json.Number); !ok ||
		got.String() != "1.50" {
		t.Fatalf("decimal = %#v (%T)", object["decimal"], object["decimal"])
	}
	items, ok := object["items"].([]any)
	if !ok || len(items) != 3 || items[0] != true ||
		items[1] != nil || items[2] != "ok" {
		t.Fatalf("items = %#v", object["items"])
	}
}

func TestDecodeRejectsAmbiguousOrMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		kind ErrorKind
	}{
		{
			name: "duplicate",
			raw:  []byte(`{"sensitive-value-name":1,"sensitive-value-name":2}`),
			kind: ErrorDuplicateKey,
		},
		{
			name: "escaped duplicate",
			raw:  []byte(`{"sensitive-value-name":1,"sensitive-value-\u006eame":2}`),
			kind: ErrorDuplicateKey,
		},
		{
			name: "nested duplicate",
			raw:  []byte(`{"outer":{"sensitive-value-name":1,"sensitive-value-name":2}}`),
			kind: ErrorDuplicateKey,
		},
		{
			name: "second value",
			raw:  []byte(`true false`),
			kind: ErrorInvalidJSON,
		},
		{
			name: "trailing token",
			raw:  []byte(`{}x`),
			kind: ErrorInvalidJSON,
		},
		{
			name: "empty",
			raw:  []byte(``),
			kind: ErrorInvalidJSON,
		},
		{
			name: "malformed",
			raw:  []byte(`{"key":`),
			kind: ErrorInvalidJSON,
		},
		{
			name: "invalid UTF-8",
			raw:  []byte{'"', 0xff, '"'},
			kind: ErrorInvalidUTF8,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(test.raw, DefaultInstanceDecodeLimits())
			if KindOf(err) != test.kind {
				t.Fatalf("Decode error = %v (%q), want %q", err, KindOf(err), test.kind)
			}
			if err != nil && strings.Contains(err.Error(), "sensitive-value-name") {
				t.Fatalf("error leaked attacker-controlled key: %v", err)
			}
		})
	}
}

func TestDecodeEnforcesEveryLimit(t *testing.T) {
	if _, err := Decode(
		[]byte(`null`),
		DecodeLimits{MaxBytes: 4, MaxDepth: 1, MaxNodes: 1},
	); err != nil {
		t.Fatalf("exact limits should pass: %v", err)
	}
	if _, err := Decode(
		[]byte(`null`),
		DecodeLimits{MaxBytes: 3, MaxDepth: 1, MaxNodes: 1},
	); KindOf(err) != ErrorTooLarge {
		t.Fatalf("byte-limit error = %v (%q)", err, KindOf(err))
	}

	if _, err := Decode(
		[]byte(`[[0]]`),
		DecodeLimits{MaxBytes: 32, MaxDepth: 2, MaxNodes: 3},
	); err != nil {
		t.Fatalf("exact depth/node limits should pass: %v", err)
	}
	if _, err := Decode(
		[]byte(`[[[0]]]`),
		DecodeLimits{MaxBytes: 32, MaxDepth: 2, MaxNodes: 4},
	); KindOf(err) != ErrorDepthLimit {
		t.Fatalf("depth-limit error = %v (%q)", err, KindOf(err))
	}
	if _, err := Decode(
		[]byte(`[0,1]`),
		DecodeLimits{MaxBytes: 32, MaxDepth: 2, MaxNodes: 2},
	); KindOf(err) != ErrorNodeLimit {
		t.Fatalf("node-limit error = %v (%q)", err, KindOf(err))
	}

	invalidLimits := []DecodeLimits{
		{},
		{MaxBytes: 0, MaxDepth: 1, MaxNodes: 1},
		{MaxBytes: 1, MaxDepth: 0, MaxNodes: 1},
		{MaxBytes: 1, MaxDepth: 1, MaxNodes: 0},
	}
	for _, limits := range invalidLimits {
		if _, err := Decode([]byte(`0`), limits); KindOf(err) != ErrorInvalidLimits {
			t.Fatalf("limits %#v error = %v (%q)", limits, err, KindOf(err))
		}
	}
}

func TestDefaultInstanceDecodeLimitsCannotBeMutatedGlobally(t *testing.T) {
	mutated := DefaultInstanceDecodeLimits()
	mutated.MaxBytes = 1
	mutated.MaxDepth = 1
	mutated.MaxNodes = 1

	got := DefaultInstanceDecodeLimits()
	if got.MaxBytes != 1<<20 ||
		got.MaxDepth != 128 ||
		got.MaxNodes != 100_000 {
		t.Fatalf("default instance policy was mutated: %#v", got)
	}
}

func TestDecodeEnforcesJSONNumberExponentProfile(t *testing.T) {
	limit := strconv.Itoa(MaxJSONNumberExponent)
	for _, raw := range []string{
		`1e` + limit,
		`1e-` + limit,
		`-1E+` + limit,
		`1.0e999`,
		`0.` + strings.Repeat("0", MaxJSONNumberExponent-1) + `1`,
	} {
		if _, err := Decode(
			[]byte(raw),
			DefaultInstanceDecodeLimits(),
		); err != nil {
			t.Errorf("Decode boundary %q: %v", raw, err)
		}
	}

	overLimit := strconv.Itoa(MaxJSONNumberExponent + 1)
	for _, raw := range []string{
		`1e` + overLimit,
		`1e-` + overLimit,
		`1.0e-1000`,
		`0.` + strings.Repeat("0", MaxJSONNumberExponent) + `1`,
		`{"expected":1e1000001}`,
	} {
		_, err := Decode([]byte(raw), DefaultInstanceDecodeLimits())
		if KindOf(err) != ErrorNumberExponentLimit {
			t.Errorf(
				"Decode over-limit %q error = %v (%q), want %q",
				raw,
				err,
				KindOf(err),
				ErrorNumberExponentLimit,
			)
		}
		if err != nil && strings.Contains(err.Error(), "1000001") {
			t.Errorf("number-limit error leaked raw exponent: %v", err)
		}
	}
}
