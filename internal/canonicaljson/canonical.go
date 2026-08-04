package canonicaljson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Marshal returns deterministic UTF-8 JSON. Go's encoding/json sorts map keys,
// escapes strings deterministically, and preserves struct field order. Inputs
// must not contain NaN or Infinity. The normative subset is documented in
// spec/canonicalization.md.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode canonical JSON: %w", err)
	}
	if err := validateASCIIObjectKeys(normalized); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func validateASCIIObjectKeys(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			for _, character := range key {
				if character > 0x7f {
					return fmt.Errorf("canonical JSON object key %q is not ASCII", key)
				}
			}
			if err := validateASCIIObjectKeys(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := validateASCIIObjectKeys(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func Digest(v any) (string, error) {
	data, err := Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func Indent(v any) ([]byte, error) {
	data, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
