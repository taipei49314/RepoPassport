package structuredjson

import "errors"

// ErrorKind is a stable, non-sensitive classification for structured JSON
// failures. Error strings deliberately contain no attacker-controlled JSON
// values.
type ErrorKind string

const (
	ErrorInvalidLimits       ErrorKind = "invalid-limits"
	ErrorTooLarge            ErrorKind = "too-large"
	ErrorInvalidUTF8         ErrorKind = "invalid-utf8"
	ErrorInvalidJSON         ErrorKind = "invalid-json"
	ErrorDuplicateKey        ErrorKind = "duplicate-key"
	ErrorDepthLimit          ErrorKind = "depth-limit"
	ErrorNodeLimit           ErrorKind = "node-limit"
	ErrorNumberExponentLimit ErrorKind = "number-exponent-limit"
	ErrorInvalidPath         ErrorKind = "invalid-path"
	ErrorPathLimit           ErrorKind = "path-limit"
	ErrorUnsupportedValue    ErrorKind = "unsupported-value"
	ErrorSchemaPolicy        ErrorKind = "schema-policy"
	ErrorSchemaCompile       ErrorKind = "schema-compile"
	ErrorSchemaEvaluation    ErrorKind = "schema-evaluation"
	ErrorSchemaNotSatisfied  ErrorKind = "schema-not-satisfied"
)

// Error is returned for every expected validation failure in this package.
// SchemaLocation can identify a schema keyword. InstanceLocation is reserved
// for compatibility and is intentionally left empty so attacker-controlled
// object member names are not retained in returned errors.
type Error struct {
	Kind             ErrorKind
	InstanceLocation string
	SchemaLocation   string
}

func (e *Error) Error() string {
	switch e.Kind {
	case ErrorInvalidLimits:
		return "structured JSON limits are invalid"
	case ErrorTooLarge:
		return "structured JSON exceeds the byte limit"
	case ErrorInvalidUTF8:
		return "structured JSON is not valid UTF-8"
	case ErrorInvalidJSON:
		return "structured JSON syntax is invalid"
	case ErrorDuplicateKey:
		return "structured JSON contains a duplicate object key"
	case ErrorDepthLimit:
		return "structured JSON exceeds the nesting-depth limit"
	case ErrorNodeLimit:
		return "structured JSON exceeds the node limit"
	case ErrorNumberExponentLimit:
		return "structured JSON number exceeds the exponent limit"
	case ErrorInvalidPath:
		return "structured JSON path syntax is invalid"
	case ErrorPathLimit:
		return "structured JSON path exceeds a safety limit"
	case ErrorUnsupportedValue:
		return "value is not in the supported JSON data model"
	case ErrorSchemaPolicy:
		return "JSON Schema uses a feature outside the bounded profile"
	case ErrorSchemaCompile:
		return "JSON Schema could not be compiled"
	case ErrorSchemaEvaluation:
		return "JSON Schema evaluation could not be completed"
	case ErrorSchemaNotSatisfied:
		return "JSON instance does not satisfy the schema"
	default:
		return "structured JSON operation failed"
	}
}

// KindOf returns a stable classification without requiring callers to expose
// an underlying parser or validator error.
func KindOf(err error) ErrorKind {
	var structuredError *Error
	if errors.As(err, &structuredError) {
		return structuredError.Kind
	}
	return ""
}
