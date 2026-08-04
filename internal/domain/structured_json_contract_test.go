package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlanJSONPathAssertionPreservesRawJSONValues(t *testing.T) {
	tests := []struct {
		name  string
		value json.RawMessage
		want  string
	}{
		{
			name:  "large integer",
			value: json.RawMessage("9007199254740993"),
			want:  `"equals":9007199254740993`,
		},
		{
			name:  "null",
			value: json.RawMessage("null"),
			want:  `"equals":null`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(PlanJSONPathAssertion{
				Path:   "$.value",
				Equals: test.value,
			})
			if err != nil {
				t.Fatalf("Marshal PlanJSONPathAssertion: %v", err)
			}
			if !strings.Contains(string(raw), test.want) {
				t.Fatalf("Marshal output = %s, want %s", raw, test.want)
			}
		})
	}
}
