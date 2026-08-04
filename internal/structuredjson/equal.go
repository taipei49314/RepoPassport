package structuredjson

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"
)

const (
	maxEqualityDepth = 256
	maxEqualityNodes = 200_000
)

// SemanticEqual compares values in the JSON data model. Object order is
// ignored and numbers are compared as exact decimal values without converting
// json.Number through float64.
func SemanticEqual(left, right any) bool {
	budget := maxEqualityNodes
	return semanticEqual(left, right, 0, &budget)
}

func semanticEqual(left, right any, depth int, budget *int) bool {
	(*budget)--
	if *budget < 0 || depth > maxEqualityDepth {
		return false
	}

	leftNumber, leftIsNumber := canonicalNumber(left)
	rightNumber, rightIsNumber := canonicalNumber(right)
	if leftIsNumber || rightIsNumber {
		return leftIsNumber && rightIsNumber &&
			leftNumber.equal(rightNumber)
	}

	switch leftValue := left.(type) {
	case nil:
		return right == nil
	case bool:
		rightValue, ok := right.(bool)
		return ok && leftValue == rightValue
	case string:
		rightValue, ok := right.(string)
		return ok && leftValue == rightValue
	case []any:
		rightValue, ok := right.([]any)
		if !ok || len(leftValue) != len(rightValue) {
			return false
		}
		for index := range leftValue {
			if !semanticEqual(
				leftValue[index],
				rightValue[index],
				depth+1,
				budget,
			) {
				return false
			}
		}
		return true
	case map[string]any:
		rightValue, ok := right.(map[string]any)
		if !ok || len(leftValue) != len(rightValue) {
			return false
		}
		for key, item := range leftValue {
			other, exists := rightValue[key]
			if !exists ||
				!semanticEqual(item, other, depth+1, budget) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

type decimalNumber struct {
	negative bool
	digits   string
	exponent *big.Int
}

func (n decimalNumber) equal(other decimalNumber) bool {
	return n.negative == other.negative &&
		n.digits == other.digits &&
		n.exponent.Cmp(other.exponent) == 0
}

func canonicalNumber(value any) (decimalNumber, bool) {
	raw, ok := supportedNumberLexeme(value)
	if !ok {
		return decimalNumber{}, false
	}
	return parseDecimal(raw)
}

func supportedNumberLexeme(value any) (string, bool) {
	switch typed := value.(type) {
	case json.Number:
		return typed.String(), true
	case int:
		return strconv.FormatInt(int64(typed), 10), true
	case int8:
		return strconv.FormatInt(int64(typed), 10), true
	case int16:
		return strconv.FormatInt(int64(typed), 10), true
	case int32:
		return strconv.FormatInt(int64(typed), 10), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case uint:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint8:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint16:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint32:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint64:
		return strconv.FormatUint(typed, 10), true
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return "", false
		}
		return strconv.FormatFloat(float64(typed), 'g', -1, 32), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return "", false
		}
		return strconv.FormatFloat(typed, 'g', -1, 64), true
	default:
		return "", false
	}
}

func parseDecimal(raw string) (decimalNumber, bool) {
	if raw == "" {
		return decimalNumber{}, false
	}
	negative := false
	if raw[0] == '-' {
		negative = true
		raw = raw[1:]
		if raw == "" {
			return decimalNumber{}, false
		}
	}

	mantissa := raw
	exponentText := ""
	if index := strings.IndexAny(raw, "eE"); index >= 0 {
		mantissa = raw[:index]
		exponentText = raw[index+1:]
		if exponentText == "" ||
			strings.IndexAny(exponentText, "eE") >= 0 {
			return decimalNumber{}, false
		}
	}
	explicitExponent := new(big.Int)
	if exponentText != "" {
		if _, ok := explicitExponent.SetString(exponentText, 10); !ok {
			return decimalNumber{}, false
		}
	}

	integerPart := mantissa
	fractionPart := ""
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		if strings.IndexByte(mantissa[index+1:], '.') >= 0 {
			return decimalNumber{}, false
		}
		integerPart = mantissa[:index]
		fractionPart = mantissa[index+1:]
	}
	if integerPart == "" || !allDigits(integerPart) ||
		fractionPart != "" && !allDigits(fractionPart) {
		return decimalNumber{}, false
	}
	if len(integerPart) > 1 && integerPart[0] == '0' {
		return decimalNumber{}, false
	}
	if strings.Contains(mantissa, ".") && fractionPart == "" {
		return decimalNumber{}, false
	}

	digits := strings.TrimLeft(integerPart+fractionPart, "0")
	if digits == "" {
		return decimalNumber{
			digits:   "0",
			exponent: new(big.Int),
		}, true
	}
	trailingZeros := len(digits) - len(strings.TrimRight(digits, "0"))
	if trailingZeros > 0 {
		digits = digits[:len(digits)-trailingZeros]
	}
	exponent := new(big.Int).Set(explicitExponent)
	exponent.Sub(exponent, big.NewInt(int64(len(fractionPart))))
	exponent.Add(exponent, big.NewInt(int64(trailingZeros)))
	return decimalNumber{
		negative: negative,
		digits:   digits,
		exponent: exponent,
	}, true
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
