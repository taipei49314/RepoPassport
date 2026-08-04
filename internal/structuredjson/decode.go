package structuredjson

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// DecodeLimits bounds all memory-bearing dimensions that are independent of
// the caller's transport limits. Every field must be positive.
type DecodeLimits struct {
	MaxBytes int
	MaxDepth int
	MaxNodes int
}

const (
	defaultInstanceMaxBytes = 1 << 20
	defaultInstanceMaxDepth = 128
	defaultInstanceMaxNodes = 100_000
)

// DefaultInstanceDecodeLimits returns the bounded profile used for HTTP
// responses and ordered JSON output assertions. A fresh value is returned so
// callers cannot mutate process-wide validation policy.
func DefaultInstanceDecodeLimits() DecodeLimits {
	return DecodeLimits{
		MaxBytes: defaultInstanceMaxBytes,
		MaxDepth: defaultInstanceMaxDepth,
		MaxNodes: defaultInstanceMaxNodes,
	}
}

// Decode parses exactly one UTF-8 JSON value. It preserves numbers as
// json.Number, rejects duplicate object keys and trailing values, and enforces
// the supplied byte, depth, node, and MaxJSONNumberExponent limits.
func Decode(raw []byte, limits DecodeLimits) (any, error) {
	if limits.MaxBytes <= 0 || limits.MaxDepth <= 0 || limits.MaxNodes <= 0 {
		return nil, &Error{Kind: ErrorInvalidLimits}
	}
	if len(raw) > limits.MaxBytes {
		return nil, &Error{Kind: ErrorTooLarge}
	}
	if !utf8.Valid(raw) {
		return nil, &Error{Kind: ErrorInvalidUTF8}
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	state := decodeState{decoder: decoder, limits: limits}
	token, err := decoder.Token()
	if err != nil {
		return nil, &Error{Kind: ErrorInvalidJSON}
	}
	value, err := state.decodeToken(token, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, &Error{Kind: ErrorInvalidJSON}
	}
	return value, nil
}

type decodeState struct {
	decoder *json.Decoder
	limits  DecodeLimits
	nodes   int
}

func (s *decodeState) decodeToken(token json.Token, depth int) (any, error) {
	s.nodes++
	if s.nodes > s.limits.MaxNodes {
		return nil, &Error{Kind: ErrorNodeLimit}
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		switch typed := token.(type) {
		case nil, bool, string:
			return token, nil
		case json.Number:
			withinLimit, valid := jsonNumberWithinExponentLimit(typed.String())
			if !valid {
				return nil, &Error{Kind: ErrorInvalidJSON}
			}
			if !withinLimit {
				return nil, &Error{Kind: ErrorNumberExponentLimit}
			}
			return token, nil
		default:
			return nil, &Error{Kind: ErrorInvalidJSON}
		}
	}

	if depth+1 > s.limits.MaxDepth {
		return nil, &Error{Kind: ErrorDepthLimit}
	}
	switch delimiter {
	case '{':
		return s.decodeObject(depth + 1)
	case '[':
		return s.decodeArray(depth + 1)
	default:
		return nil, &Error{Kind: ErrorInvalidJSON}
	}
}

func (s *decodeState) decodeObject(depth int) (map[string]any, error) {
	value := make(map[string]any)
	for s.decoder.More() {
		keyToken, err := s.decoder.Token()
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidJSON}
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, &Error{Kind: ErrorInvalidJSON}
		}
		if _, duplicate := value[key]; duplicate {
			return nil, &Error{Kind: ErrorDuplicateKey}
		}
		itemToken, err := s.decoder.Token()
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidJSON}
		}
		item, err := s.decodeToken(itemToken, depth)
		if err != nil {
			return nil, err
		}
		value[key] = item
	}
	closing, err := s.decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, &Error{Kind: ErrorInvalidJSON}
	}
	return value, nil
}

func (s *decodeState) decodeArray(depth int) ([]any, error) {
	value := make([]any, 0)
	for s.decoder.More() {
		itemToken, err := s.decoder.Token()
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidJSON}
		}
		item, err := s.decodeToken(itemToken, depth)
		if err != nil {
			return nil, err
		}
		value = append(value, item)
	}
	closing, err := s.decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return nil, &Error{Kind: ErrorInvalidJSON}
	}
	return value, nil
}
