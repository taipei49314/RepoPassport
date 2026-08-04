package structuredjson

// MaxJSONNumberExponent is the largest absolute explicit or effective
// base-10 exponent accepted by Decode and JSON Schema validation. The
// effective exponent is the explicit exponent minus the number of fractional
// digits, matching the power materialized by math/big.Rat-based validators.
//
// A limit of 1000 keeps each exponent-derived power near 3322 bits while
// remaining well beyond the exponent range of ordinary binary64 JSON values.
const MaxJSONNumberExponent = 1000

// jsonNumberWithinExponentLimit validates the JSON number grammar and bounds
// both exponent forms before a third-party validator can materialize powers of
// ten. It returns (false, false) for an invalid number lexeme.
func jsonNumberWithinExponentLimit(raw string) (withinLimit, valid bool) {
	if raw == "" {
		return false, false
	}

	index := 0
	if raw[index] == '-' {
		index++
		if index == len(raw) {
			return false, false
		}
	}

	switch {
	case raw[index] == '0':
		index++
		if index < len(raw) && isDecimalDigit(raw[index]) {
			return false, false
		}
	case raw[index] >= '1' && raw[index] <= '9':
		for index < len(raw) && isDecimalDigit(raw[index]) {
			index++
		}
	default:
		return false, false
	}

	fractionDigits := 0
	if index < len(raw) && raw[index] == '.' {
		index++
		fractionStart := index
		for index < len(raw) && isDecimalDigit(raw[index]) {
			index++
		}
		fractionDigits = index - fractionStart
		if fractionDigits == 0 {
			return false, false
		}
	}

	explicitExponent := 0
	if index < len(raw) && (raw[index] == 'e' || raw[index] == 'E') {
		index++
		if index == len(raw) {
			return false, false
		}
		exponentSign := 1
		if raw[index] == '+' || raw[index] == '-' {
			if raw[index] == '-' {
				exponentSign = -1
			}
			index++
			if index == len(raw) {
				return false, false
			}
		}
		exponentDigits := 0
		exponentMagnitude := 0
		exceedsLimit := false
		for index < len(raw) && isDecimalDigit(raw[index]) {
			exponentDigits++
			digit := int(raw[index] - '0')
			if exponentMagnitude >
				(MaxJSONNumberExponent-digit)/10 {
				exceedsLimit = true
			} else if !exceedsLimit {
				exponentMagnitude = exponentMagnitude*10 + digit
			}
			index++
		}
		if exponentDigits == 0 {
			return false, false
		}
		if exceedsLimit {
			if index != len(raw) {
				return false, false
			}
			return false, true
		}
		explicitExponent = exponentSign * exponentMagnitude
	}

	if index != len(raw) {
		return false, false
	}
	effectiveExponent := explicitExponent - fractionDigits
	return effectiveExponent >= -MaxJSONNumberExponent &&
		effectiveExponent <= MaxJSONNumberExponent, true
}

func isDecimalDigit(value byte) bool {
	return value >= '0' && value <= '9'
}
