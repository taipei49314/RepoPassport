package structuredjson

import (
	"strings"
	"testing"
)

func TestPathLookupSupportsSingularSelectors(t *testing.T) {
	root := mustDecode(t, `{
		"user": {
			"items": [{"id": 7}, null],
			"presentNull": null
		},
		"a'b": "single",
		"a\"b": "double",
		"slash\\key": "slash",
		"line\nkey": "line",
		"雪": "unicode",
		"": "empty"
	}`)
	tests := []struct {
		expression string
		expected   any
	}{
		{"$", root},
		{"$.user.items[0].id", mustDecode(t, `7`)},
		{`$['user']["items"][1]`, nil},
		{`$['a\'b']`, "single"},
		{`$["a\"b"]`, "double"},
		{`$['a\"b']`, "double"},
		{`$['slash\\key']`, "slash"},
		{`$['line\nkey']`, "line"},
		{`$['\u96ea']`, "unicode"},
		{`$['']`, "empty"},
	}
	for _, test := range tests {
		t.Run(test.expression, func(t *testing.T) {
			path, err := CompilePath(test.expression)
			if err != nil {
				t.Fatalf("CompilePath: %v", err)
			}
			actual, found := path.Lookup(root)
			if !found {
				t.Fatal("Lookup reported missing")
			}
			if !SemanticEqual(actual, test.expected) {
				t.Fatalf("Lookup = %#v, want %#v", actual, test.expected)
			}
			if path.String() != test.expression {
				t.Fatalf("String = %q", path.String())
			}
		})
	}
}

func TestPathLookupDistinguishesMissingAndNull(t *testing.T) {
	root := mustDecode(t, `{"present":null,"array":[null]}`)
	for _, expression := range []string{"$.present", "$.array[0]"} {
		path, err := ParsePath(expression)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", expression, err)
		}
		value, found := path.Lookup(root)
		if !found || value != nil {
			t.Fatalf("Lookup(%q) = (%#v, %v), want (nil, true)", expression, value, found)
		}
	}
	for _, expression := range []string{
		"$.missing",
		"$.array[1]",
		"$.present.value",
		"$.array.name",
	} {
		path, err := ParsePath(expression)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", expression, err)
		}
		if value, found := path.Lookup(root); found {
			t.Fatalf("Lookup(%q) = (%#v, true), want missing", expression, value)
		}
	}
	if value, found := (Path{}).Lookup(root); found || value != nil {
		t.Fatalf("zero Path Lookup = (%#v, %v)", value, found)
	}
}

func TestCompilePathRejectsNonSingularOrAmbiguousSyntax(t *testing.T) {
	invalid := []string{
		"",
		"not-rooted",
		"$.",
		"$..name",
		"$.*",
		"$[*]",
		"$[?(@.ok)]",
		"$[0:2]",
		"$[-1]",
		"$[01]",
		"$[1,2]",
		"$[ 0]",
		"$[0 ]",
		"$()",
		"$.é",
		"$['unterminated]",
		`$['bad\q']`,
		`$["bad\q"]`,
		"$['name']trailing",
		"$[9223372036854775808]",
	}
	for _, expression := range invalid {
		t.Run(expression, func(t *testing.T) {
			if _, err := CompilePath(expression); KindOf(err) != ErrorInvalidPath {
				t.Fatalf("CompilePath error = %v (%q)", err, KindOf(err))
			}
		})
	}
	if _, err := CompilePath(string([]byte{'$', '.', 0xff})); KindOf(err) != ErrorInvalidPath {
		t.Fatalf("invalid UTF-8 error = %v (%q)", err, KindOf(err))
	}
}

func TestCompilePathEnforcesByteAndSelectorLimits(t *testing.T) {
	tooLong := "$." + strings.Repeat("a", MaxPathBytes)
	if _, err := CompilePath(tooLong); KindOf(err) != ErrorPathLimit {
		t.Fatalf("path byte-limit error = %v (%q)", err, KindOf(err))
	}

	maximum := "$" + strings.Repeat(".a", MaxSelectors)
	path, err := CompilePath(maximum)
	if err != nil {
		t.Fatalf("CompilePath maximum selectors: %v", err)
	}
	if path.SelectorCount() != MaxSelectors {
		t.Fatalf("SelectorCount = %d, want %d", path.SelectorCount(), MaxSelectors)
	}
	if _, err := CompilePath(maximum + ".a"); KindOf(err) != ErrorPathLimit {
		t.Fatalf("selector-limit error = %v (%q)", err, KindOf(err))
	}
}
