package structuredjson

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxPathBytes = 1024
	MaxSelectors = 64
)

type selectorKind uint8

const (
	selectName selectorKind = iota + 1
	selectIndex
)

type selector struct {
	kind  selectorKind
	name  string
	index int
}

// Path is an immutable, compiled singular JSONPath. The accepted grammar is:
//
//	$ ( .identifier | ['name'] | ["name"] | [non-negative-index] )*
//
// Wildcards, slices, filters, recursive descent, functions, and unions are not
// part of this bounded profile.
type Path struct {
	expression string
	selectors  []selector
	valid      bool
}

// CompilePath validates and compiles the bounded singular JSONPath subset.
func CompilePath(expression string) (Path, error) {
	if len(expression) == 0 || !utf8.ValidString(expression) {
		return Path{}, &Error{Kind: ErrorInvalidPath}
	}
	if len([]byte(expression)) > MaxPathBytes {
		return Path{}, &Error{Kind: ErrorPathLimit}
	}
	if expression[0] != '$' {
		return Path{}, &Error{Kind: ErrorInvalidPath}
	}

	compiled := Path{
		expression: expression,
		selectors:  make([]selector, 0, 8),
		valid:      true,
	}
	for offset := 1; offset < len(expression); {
		if len(compiled.selectors) >= MaxSelectors {
			return Path{}, &Error{Kind: ErrorPathLimit}
		}
		var (
			item selector
			next int
			err  error
		)
		switch expression[offset] {
		case '.':
			item, next, err = parseDotSelector(expression, offset)
		case '[':
			item, next, err = parseBracketSelector(expression, offset)
		default:
			err = &Error{Kind: ErrorInvalidPath}
		}
		if err != nil {
			return Path{}, err
		}
		compiled.selectors = append(compiled.selectors, item)
		offset = next
	}
	return compiled, nil
}

// ParsePath is an alias for CompilePath. Both names return the same immutable
// representation; ParsePath is convenient for manifest and planner validation.
func ParsePath(expression string) (Path, error) {
	return CompilePath(expression)
}

// String returns the original validated path expression.
func (p Path) String() string {
	return p.expression
}

// SelectorCount returns the number of singular selection operations.
func (p Path) SelectorCount() int {
	return len(p.selectors)
}

// Lookup returns (nil, true) for a present JSON null and (_, false) for a
// missing member, an out-of-range index, or a type mismatch.
func (p Path) Lookup(root any) (any, bool) {
	if !p.valid {
		return nil, false
	}
	current := root
	for _, item := range p.selectors {
		switch item.kind {
		case selectName:
			object, ok := current.(map[string]any)
			if !ok {
				return nil, false
			}
			current, ok = object[item.name]
			if !ok {
				return nil, false
			}
		case selectIndex:
			array, ok := current.([]any)
			if !ok || item.index < 0 || item.index >= len(array) {
				return nil, false
			}
			current = array[item.index]
		default:
			return nil, false
		}
	}
	return current, true
}

func parseDotSelector(expression string, offset int) (selector, int, error) {
	start := offset + 1
	if start >= len(expression) || !isIdentifierStart(expression[start]) {
		return selector{}, 0, &Error{Kind: ErrorInvalidPath}
	}
	end := start + 1
	for end < len(expression) && isIdentifierContinue(expression[end]) {
		end++
	}
	return selector{kind: selectName, name: expression[start:end]}, end, nil
}

func parseBracketSelector(expression string, offset int) (selector, int, error) {
	start := offset + 1
	if start >= len(expression) {
		return selector{}, 0, &Error{Kind: ErrorInvalidPath}
	}
	if expression[start] == '\'' || expression[start] == '"' {
		name, next, err := parseQuotedName(expression, start)
		if err != nil || next >= len(expression) || expression[next] != ']' {
			return selector{}, 0, &Error{Kind: ErrorInvalidPath}
		}
		return selector{kind: selectName, name: name}, next + 1, nil
	}

	end := start
	for end < len(expression) && expression[end] >= '0' && expression[end] <= '9' {
		end++
	}
	if end == start || end >= len(expression) || expression[end] != ']' {
		return selector{}, 0, &Error{Kind: ErrorInvalidPath}
	}
	if end-start > 1 && expression[start] == '0' {
		return selector{}, 0, &Error{Kind: ErrorInvalidPath}
	}
	index64, err := strconv.ParseUint(expression[start:end], 10, 63)
	if err != nil || index64 > uint64(maxInt()) {
		return selector{}, 0, &Error{Kind: ErrorInvalidPath}
	}
	return selector{kind: selectIndex, index: int(index64)}, end + 1, nil
}

func parseQuotedName(expression string, start int) (string, int, error) {
	quote := expression[start]
	escaped := false
	end := start + 1
	for ; end < len(expression); end++ {
		switch {
		case escaped:
			escaped = false
		case expression[end] == '\\':
			escaped = true
		case expression[end] == quote:
			literal := expression[start : end+1]
			name, err := decodePathString(literal, quote)
			if err != nil {
				return "", 0, &Error{Kind: ErrorInvalidPath}
			}
			return name, end + 1, nil
		}
	}
	return "", 0, &Error{Kind: ErrorInvalidPath}
}

func decodePathString(literal string, quote byte) (string, error) {
	if quote == '"' {
		var value string
		if err := json.Unmarshal([]byte(literal), &value); err != nil {
			return "", err
		}
		if !utf8.ValidString(value) {
			return "", &Error{Kind: ErrorInvalidPath}
		}
		return value, nil
	}

	content := literal[1 : len(literal)-1]
	var converted strings.Builder
	converted.Grow(len(content) + 2)
	converted.WriteByte('"')
	for index := 0; index < len(content); index++ {
		character := content[index]
		if character == '"' {
			converted.WriteString(`\"`)
			continue
		}
		if character != '\\' {
			converted.WriteByte(character)
			continue
		}
		if index+1 >= len(content) {
			return "", &Error{Kind: ErrorInvalidPath}
		}
		index++
		switch content[index] {
		case '\'':
			converted.WriteByte('\'')
		case '"':
			converted.WriteString(`\"`)
		case '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
			converted.WriteByte('\\')
			converted.WriteByte(content[index])
		default:
			return "", &Error{Kind: ErrorInvalidPath}
		}
		if content[index] == 'u' {
			// The four hexadecimal digits remain in content and are copied by
			// subsequent iterations; json.Unmarshal validates the sequence.
			continue
		}
	}
	converted.WriteByte('"')
	var value string
	if err := json.Unmarshal([]byte(converted.String()), &value); err != nil {
		return "", err
	}
	if !utf8.ValidString(value) {
		return "", &Error{Kind: ErrorInvalidPath}
	}
	return value, nil
}

func isIdentifierStart(value byte) bool {
	return value == '_' ||
		value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z'
}

func isIdentifierContinue(value byte) bool {
	return isIdentifierStart(value) || value >= '0' && value <= '9'
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
