package structuredjson

import (
	"encoding/json"
	"math"
	"testing"
)

func TestSemanticEqualUsesExactDecimalNumbers(t *testing.T) {
	equal := [][2]any{
		{json.Number("1"), json.Number("1.0")},
		{json.Number("10"), json.Number("1e1")},
		{json.Number("-0"), json.Number("0.000e999999999")},
		{json.Number("9007199254740993"), uint64(9007199254740993)},
		{json.Number("1e999999999"), json.Number("10e999999998")},
		{json.Number("0.1250"), 0.125},
		{int64(-42), json.Number("-42.000")},
	}
	for _, pair := range equal {
		if !SemanticEqual(pair[0], pair[1]) {
			t.Errorf("SemanticEqual(%v, %v) = false", pair[0], pair[1])
		}
	}

	notEqual := [][2]any{
		{json.Number("9007199254740993"), json.Number("9007199254740992")},
		{json.Number("1e999999999"), json.Number("1e999999998")},
		{json.Number("0.1"), json.Number("0.10000000000000001")},
		{json.Number("1"), "1"},
		{json.Number("invalid"), json.Number("invalid")},
		{math.NaN(), math.NaN()},
		{math.Inf(1), math.Inf(1)},
	}
	for _, pair := range notEqual {
		if SemanticEqual(pair[0], pair[1]) {
			t.Errorf("SemanticEqual(%v, %v) = true", pair[0], pair[1])
		}
	}
}

func TestSemanticEqualKeepsHugeExponentComparisonExact(t *testing.T) {
	if !SemanticEqual(
		json.Number("1e1000001"),
		json.Number("10e1000000"),
	) {
		t.Fatal("equivalent huge exponents did not compare equal")
	}
	if SemanticEqual(
		json.Number("1e1000001"),
		json.Number("1e1000000"),
	) {
		t.Fatal("distinct huge exponents compared equal")
	}
}

func TestSemanticEqualComparesCompleteJSONValues(t *testing.T) {
	left := mustDecode(t, `{
		"name":"example",
		"numbers":[1,2.0,3e0],
		"nested":{"enabled":true,"value":null}
	}`)
	right := mustDecode(t, `{
		"nested":{"value":null,"enabled":true},
		"numbers":[1.0,2,3],
		"name":"example"
	}`)
	if !SemanticEqual(left, right) {
		t.Fatal("equivalent objects did not compare equal")
	}
	if SemanticEqual(left, mustDecode(t, `{"name":"example"}`)) {
		t.Fatal("different object sizes compared equal")
	}
	if SemanticEqual(
		mustDecode(t, `[1,2,3]`),
		mustDecode(t, `[3,2,1]`),
	) {
		t.Fatal("array order was ignored")
	}
	if !SemanticEqual(nil, nil) || SemanticEqual(nil, false) {
		t.Fatal("null comparison is incorrect")
	}
}

func TestSemanticEqualFailsClosedOnUnsupportedOrExcessiveValues(t *testing.T) {
	if SemanticEqual(struct{}{}, struct{}{}) {
		t.Fatal("unsupported structs compared equal")
	}
	left := any("leaf")
	right := any("leaf")
	for range maxEqualityDepth + 1 {
		left = []any{left}
		right = []any{right}
	}
	if SemanticEqual(left, right) {
		t.Fatal("values beyond equality depth compared equal")
	}
}

func mustDecode(t *testing.T, raw string) any {
	t.Helper()
	value, err := Decode([]byte(raw), DefaultInstanceDecodeLimits())
	if err != nil {
		t.Fatalf("Decode(%q): %v", raw, err)
	}
	return value
}
