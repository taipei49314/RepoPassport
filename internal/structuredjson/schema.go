package structuredjson

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	MaxSchemaBytes        = 256 << 10
	MaxSchemaDepth        = 64
	MaxSchemaNodes        = 16_384
	MaxSchemaBranches     = 128
	MaxSchemaPatterns     = 128
	MaxSchemaPatternBytes = 4096
	MaxSchemaReferences   = 256

	schemaResourceURL = "https://schemas.repopass.dev/internal/structured-json/root"
	draft2020URL      = "https://json-schema.org/draft/2020-12/schema"
)

var schemaDecodeLimits = DecodeLimits{
	MaxBytes: MaxSchemaBytes,
	MaxDepth: MaxSchemaDepth,
	MaxNodes: MaxSchemaNodes,
}

// Schema is a compiled Draft 2020-12 schema in the bounded, offline profile.
// It is immutable after construction and can be reused for validation.
type Schema struct {
	compiled *jsonschema.Schema
}

// CompileSchema parses and compiles one Draft 2020-12 schema. Schema documents
// are capped at 256 KiB. References must be same-document fragments, dynamic
// and recursive references are rejected, and the compiler has no external
// resource loader.
func CompileSchema(raw []byte) (*Schema, error) {
	document, err := Decode(raw, schemaDecodeLimits)
	if err != nil {
		return nil, err
	}
	switch document.(type) {
	case bool, map[string]any:
	default:
		return nil, &Error{Kind: ErrorSchemaCompile}
	}
	if err := inspectSchemaPolicy(document); err != nil {
		return nil, err
	}

	compiled, err := compileSchemaDocument(document)
	if err != nil {
		return nil, err
	}
	return &Schema{compiled: compiled}, nil
}

func compileSchemaDocument(
	document any,
) (compiled *jsonschema.Schema, resultErr error) {
	defer func() {
		if recover() != nil {
			compiled = nil
			resultErr = &Error{Kind: ErrorSchemaCompile}
		}
	}()

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(denySchemaLoader{})
	if err := compiler.AddResource(schemaResourceURL, document); err != nil {
		return nil, &Error{Kind: ErrorSchemaCompile}
	}
	compiled, err := compiler.Compile(schemaResourceURL)
	if err != nil {
		return nil, &Error{Kind: ErrorSchemaCompile}
	}
	return compiled, nil
}

// Validate checks a JSON-compatible value. Values returned by Decode are the
// preferred input because duplicate object keys and byte limits can only be
// enforced while parsing raw JSON.
func (s *Schema) Validate(instance any) error {
	if s == nil || s.compiled == nil {
		return &Error{Kind: ErrorSchemaCompile}
	}
	limits := DefaultInstanceDecodeLimits()
	if err := validateValueShape(
		instance,
		limits.MaxDepth,
		limits.MaxNodes,
	); err != nil {
		return err
	}
	return validateCompiledSchema(s.compiled, instance)
}

func validateCompiledSchema(
	compiled *jsonschema.Schema,
	instance any,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = &Error{Kind: ErrorSchemaEvaluation}
		}
	}()
	if err := compiled.Validate(instance); err != nil {
		return summarizeValidationError(err)
	}
	return nil
}

// ValidateJSON strictly decodes and validates one raw JSON instance.
func (s *Schema) ValidateJSON(raw []byte, limits DecodeLimits) error {
	instance, err := Decode(raw, limits)
	if err != nil {
		return err
	}
	return s.Validate(instance)
}

type schemaPolicyState struct {
	scanned    map[schemaScanKey]struct{}
	branches   int
	patterns   int
	references int
}

type schemaScanKey struct {
	location         string
	resourceLocation string
}

func inspectSchemaPolicy(document any) error {
	state := schemaPolicyState{
		scanned: make(map[schemaScanKey]struct{}),
	}
	return state.scanSchema(document, "#", document, "#")
}

// scanSchema follows Draft 2020-12 subschema-bearing keywords and local JSON
// Pointer references. It deliberately does not recursively inspect instance
// data held by keywords such as const, enum, default, and examples. A pointer
// reference can still promote a value at any document location to a schema, in
// which case that target is scanned before compilation.
func (s *schemaPolicyState) scanSchema(
	value any,
	location string,
	resource any,
	resourceLocation string,
) error {
	if object, isObject := value.(map[string]any); isObject {
		if identifier, exists := object["$id"]; exists {
			if _, ok := identifier.(string); !ok {
				return &Error{Kind: ErrorSchemaCompile}
			}
			resource = value
			resourceLocation = location
		}
	}

	scanKey := schemaScanKey{
		location:         location,
		resourceLocation: resourceLocation,
	}
	if _, exists := s.scanned[scanKey]; exists {
		return nil
	}
	s.scanned[scanKey] = struct{}{}

	switch typed := value.(type) {
	case bool:
		return nil
	case map[string]any:
		if dialect, exists := typed["$schema"]; exists {
			value, ok := dialect.(string)
			if !ok ||
				strings.TrimSuffix(value, "#") != draft2020URL {
				return &Error{Kind: ErrorSchemaPolicy}
			}
		}
		if _, exists := typed["$vocabulary"]; exists {
			return &Error{Kind: ErrorSchemaPolicy}
		}
		for _, keyword := range []string{
			"$dynamicRef",
			"$recursiveRef",
		} {
			if _, exists := typed[keyword]; exists {
				return &Error{Kind: ErrorSchemaPolicy}
			}
		}
		if reference, exists := typed["$ref"]; exists {
			value, ok := reference.(string)
			if !ok || !strings.HasPrefix(value, "#") {
				return &Error{Kind: ErrorSchemaPolicy}
			}
			s.references++
			if s.references > MaxSchemaReferences {
				return &Error{Kind: ErrorSchemaPolicy}
			}
			target, targetLocation, isPointer, ok := resolveLocalSchemaReference(
				resource,
				resourceLocation,
				value,
			)
			if !ok {
				return &Error{Kind: ErrorSchemaCompile}
			}
			if isPointer {
				if err := s.scanSchema(
					target,
					targetLocation,
					resource,
					resourceLocation,
				); err != nil {
					return err
				}
			}
		}
		if pattern, exists := typed["pattern"]; exists {
			value, ok := pattern.(string)
			if !ok {
				return &Error{Kind: ErrorSchemaCompile}
			}
			if err := s.addPattern(value); err != nil {
				return err
			}
		}
		if patterns, exists := typed["patternProperties"]; exists {
			values, ok := patterns.(map[string]any)
			if !ok {
				return &Error{Kind: ErrorSchemaCompile}
			}
			for pattern := range values {
				if err := s.addPattern(pattern); err != nil {
					return err
				}
			}
		}

		for _, keyword := range schemaArrayKeywords {
			raw, exists := typed[keyword]
			if !exists {
				continue
			}
			branches, ok := raw.([]any)
			if !ok {
				return &Error{Kind: ErrorSchemaCompile}
			}
			if isBranchKeyword(keyword) {
				s.branches += len(branches)
				if s.branches > MaxSchemaBranches {
					return &Error{Kind: ErrorSchemaPolicy}
				}
			}
			for index, branch := range branches {
				if err := s.scanSchema(
					branch,
					appendSchemaLocation(location, keyword, strconv.Itoa(index)),
					resource,
					resourceLocation,
				); err != nil {
					return err
				}
			}
		}

		for _, keyword := range schemaMapKeywords {
			raw, exists := typed[keyword]
			if !exists {
				continue
			}
			children, ok := raw.(map[string]any)
			if !ok {
				return &Error{Kind: ErrorSchemaCompile}
			}
			for name, child := range children {
				if keyword == "dependencies" {
					if _, isPropertyDependency := child.([]any); isPropertyDependency {
						continue
					}
				}
				if err := s.scanSchema(
					child,
					appendSchemaLocation(location, keyword, name),
					resource,
					resourceLocation,
				); err != nil {
					return err
				}
			}
		}

		for _, keyword := range schemaSingleKeywords {
			child, exists := typed[keyword]
			if !exists {
				continue
			}
			if err := s.scanSchema(
				child,
				appendSchemaLocation(location, keyword),
				resource,
				resourceLocation,
			); err != nil {
				return err
			}
		}
		return nil
	default:
		return &Error{Kind: ErrorSchemaCompile}
	}
}

var schemaArrayKeywords = [...]string{
	"allOf",
	"anyOf",
	"oneOf",
	"prefixItems",
}

var schemaMapKeywords = [...]string{
	"$defs",
	"definitions",
	"properties",
	"patternProperties",
	"dependentSchemas",
	"dependencies",
}

var schemaSingleKeywords = [...]string{
	"not",
	"additionalProperties",
	"items",
	"additionalItems",
	"contains",
	"propertyNames",
	"if",
	"then",
	"else",
	"unevaluatedProperties",
	"unevaluatedItems",
	"contentSchema",
}

func isBranchKeyword(keyword string) bool {
	return keyword == "allOf" ||
		keyword == "anyOf" ||
		keyword == "oneOf"
}

func resolveLocalSchemaReference(
	resource any,
	resourceLocation string,
	reference string,
) (target any, location string, isPointer, ok bool) {
	fragment, err := url.PathUnescape(strings.TrimPrefix(reference, "#"))
	if err != nil {
		return nil, "", false, false
	}
	if fragment == "" {
		return resource, resourceLocation, true, true
	}
	if !strings.HasPrefix(fragment, "/") {
		// A plain-name fragment is an anchor. All standard subschema locations
		// are scanned independently, and the compiler resolves the anchor.
		return nil, "", false, true
	}

	current := resource
	canonical := resourceLocation
	for _, encodedToken := range strings.Split(fragment[1:], "/") {
		token, ok := decodeJSONPointerToken(encodedToken)
		if !ok {
			return nil, "", false, false
		}
		canonical = appendSchemaLocation(canonical, token)
		switch typed := current.(type) {
		case map[string]any:
			current, ok = typed[token]
			if !ok {
				return nil, "", false, false
			}
		case []any:
			index, err := parseJSONPointerIndex(token)
			if err != nil || index >= len(typed) {
				return nil, "", false, false
			}
			current = typed[index]
		default:
			return nil, "", false, false
		}
	}
	return current, canonical, true, true
}

func decodeJSONPointerToken(encoded string) (string, bool) {
	var decoded strings.Builder
	for index := 0; index < len(encoded); index++ {
		if encoded[index] != '~' {
			decoded.WriteByte(encoded[index])
			continue
		}
		if index+1 >= len(encoded) {
			return "", false
		}
		index++
		switch encoded[index] {
		case '0':
			decoded.WriteByte('~')
		case '1':
			decoded.WriteByte('/')
		default:
			return "", false
		}
	}
	return decoded.String(), true
}

func parseJSONPointerIndex(token string) (int, error) {
	if token == "" ||
		(len(token) > 1 && token[0] == '0') ||
		token == "-" {
		return 0, errors.New("invalid JSON Pointer array index")
	}
	for _, digit := range token {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid JSON Pointer array index")
		}
	}
	return strconv.Atoi(token)
}

func appendSchemaLocation(location string, tokens ...string) string {
	var result strings.Builder
	result.WriteString(location)
	for _, token := range tokens {
		result.WriteByte('/')
		result.WriteString(
			strings.ReplaceAll(
				strings.ReplaceAll(token, "~", "~0"),
				"/",
				"~1",
			),
		)
	}
	return result.String()
}

func (s *schemaPolicyState) addPattern(pattern string) error {
	s.patterns++
	if s.patterns > MaxSchemaPatterns ||
		len([]byte(pattern)) > MaxSchemaPatternBytes {
		return &Error{Kind: ErrorSchemaPolicy}
	}
	return nil
}

func validateValueShape(value any, maximumDepth, maximumNodes int) error {
	nodes := 0
	var visit func(any, int) error
	visit = func(current any, depth int) error {
		nodes++
		if nodes > maximumNodes {
			return &Error{Kind: ErrorNodeLimit}
		}
		switch typed := current.(type) {
		case nil, bool:
			return nil
		case string:
			if !utf8.ValidString(typed) {
				return &Error{Kind: ErrorUnsupportedValue}
			}
			return nil
		case json.Number:
			withinLimit, valid := jsonNumberWithinExponentLimit(typed.String())
			if !valid {
				return &Error{Kind: ErrorUnsupportedValue}
			}
			if !withinLimit {
				return &Error{Kind: ErrorNumberExponentLimit}
			}
			return nil
		case []any:
			if depth+1 > maximumDepth {
				return &Error{Kind: ErrorDepthLimit}
			}
			for _, item := range typed {
				if err := visit(item, depth+1); err != nil {
					return err
				}
			}
			return nil
		case map[string]any:
			if depth+1 > maximumDepth {
				return &Error{Kind: ErrorDepthLimit}
			}
			for key, item := range typed {
				if !utf8.ValidString(key) {
					return &Error{Kind: ErrorUnsupportedValue}
				}
				if err := visit(item, depth+1); err != nil {
					return err
				}
			}
			return nil
		default:
			if number, ok := supportedNumberLexeme(typed); ok {
				withinLimit, valid := jsonNumberWithinExponentLimit(number)
				if !valid {
					return &Error{Kind: ErrorUnsupportedValue}
				}
				if !withinLimit {
					return &Error{Kind: ErrorNumberExponentLimit}
				}
				return nil
			}
			return &Error{Kind: ErrorUnsupportedValue}
		}
	}
	return visit(value, 0)
}

type denySchemaLoader struct{}

func (denySchemaLoader) Load(string) (any, error) {
	return nil, errors.New("external JSON Schema loading is disabled")
}

func summarizeValidationError(err error) error {
	var validationError *jsonschema.ValidationError
	if !errors.As(err, &validationError) {
		return &Error{Kind: ErrorSchemaNotSatisfied}
	}
	leaf := validationError
	for len(leaf.Causes) > 0 {
		leaf = leaf.Causes[0]
	}
	return &Error{
		Kind:           ErrorSchemaNotSatisfied,
		SchemaLocation: jsonPointer(leaf.ErrorKind.KeywordPath()),
	}
}

func jsonPointer(parts []string) string {
	var result strings.Builder
	for _, part := range parts {
		result.WriteByte('/')
		result.WriteString(
			strings.ReplaceAll(
				strings.ReplaceAll(part, "~", "~0"),
				"/",
				"~1",
			),
		)
	}
	return result.String()
}
