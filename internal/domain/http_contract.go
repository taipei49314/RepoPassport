package domain

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	AlphaHTTPMaxURLBytes             = 2048
	AlphaHTTPMaxJourneySteps         = 128
	AlphaHTTPMaxRequestSteps         = 32
	AlphaHTTPMaxHeaders              = 64
	AlphaHTTPMaxHeaderValueBytes     = 8 << 10
	AlphaHTTPMaxHeaderAggregateBytes = 64 << 10
	AlphaHTTPMaxRequestBodyBytes     = 1 << 20
	AlphaHTTPMaxResponseMatchBytes   = 1 << 20
	AlphaHTTPMaxOutputPathBytes      = 4096

	AlphaHTTPContentTypeName  = "content-type"
	AlphaHTTPJSONContentType  = "application/json"
	AlphaHTTPMinimumStatus    = 200
	AlphaHTTPMaximumStatus    = 599
	AlphaHTTPMinimumDuration  = time.Millisecond
	AlphaHTTPMaxRequestTime   = 30 * time.Minute
	AlphaHTTPMaxReadinessTime = 2 * time.Minute
	AlphaHTTPMaxSignalGrace   = 10 * time.Second
)

// ParseAlphaHTTPURL validates the cross-adapter URL subset used by the alpha
// HTTP journey. It returns the canonical decimal port on success.
func ParseAlphaHTTPURL(value string) (*url.URL, int, error) {
	if len(value) == 0 || len(value) > AlphaHTTPMaxURLBytes {
		return nil, 0, fmt.Errorf("HTTP URL must contain 1 to %d bytes", AlphaHTTPMaxURLBytes)
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return nil, 0, fmt.Errorf("HTTP URL must use visible ASCII with non-ASCII data percent-encoded")
		}
	}
	if strings.ContainsRune(value, '\\') {
		return nil, 0, fmt.Errorf("HTTP URL must not contain a backslash")
	}

	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Scheme != "http" ||
		parsed.Hostname() != "127.0.0.1" ||
		parsed.User != nil ||
		parsed.Fragment != "" ||
		parsed.RawFragment != "" ||
		parsed.Opaque != "" ||
		parsed.Port() == "" ||
		(parsed.ForceQuery && parsed.RawQuery == "") {
		return nil, 0, fmt.Errorf("invalid canonical loopback HTTP URL")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid HTTP URL port")
	}
	if parsed.Host != "127.0.0.1:"+strconv.Itoa(port) {
		return nil, 0, fmt.Errorf("HTTP URL authority is not canonical")
	}
	if parsed.String() != value {
		return nil, 0, fmt.Errorf("HTTP URL is not canonically encoded")
	}
	if !validAlphaHTTPRawQuery(parsed.RawQuery) {
		return nil, 0, fmt.Errorf("HTTP URL query is not RFC 3986 encoded")
	}

	canonicalPath := (&url.URL{Path: parsed.Path}).EscapedPath()
	if parsed.EscapedPath() != canonicalPath {
		return nil, 0, fmt.Errorf("HTTP URL path is not canonically encoded")
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, 0, fmt.Errorf("HTTP URL path must not contain dot segments")
		}
	}
	return parsed, port, nil
}

// ParseAlphaHTTPDuration accepts only positive, whole-millisecond durations.
// A zero maximum disables the upper bound.
func ParseAlphaHTTPDuration(value string, maximum time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil ||
		duration < AlphaHTTPMinimumDuration ||
		duration%time.Millisecond != 0 ||
		(maximum > 0 && duration > maximum) {
		return 0, fmt.Errorf("HTTP duration is outside the whole-millisecond alpha bounds")
	}
	return duration, nil
}

// ValidateAlphaHTTPHeaders validates limits that apply to the effective header
// set. The trusted driver's automatic JSON Content-Type is included.
func ValidateAlphaHTTPHeaders(headers map[string]string, hasJSON bool) error {
	effectiveCount := len(headers)
	aggregateBytes := 0
	hasContentType := false
	for name, value := range headers {
		if len(value) > AlphaHTTPMaxHeaderValueBytes {
			return fmt.Errorf("HTTP header value exceeds %d bytes", AlphaHTTPMaxHeaderValueBytes)
		}
		if !isPrintableASCII(value) {
			return fmt.Errorf("HTTP header value must contain only printable ASCII")
		}
		aggregateBytes += len(name) + len(value) + 4
		if strings.EqualFold(name, AlphaHTTPContentTypeName) {
			hasContentType = true
		}
	}
	if hasJSON && !hasContentType {
		effectiveCount++
		aggregateBytes += len(AlphaHTTPContentTypeName) + len(AlphaHTTPJSONContentType) + 4
	}
	if effectiveCount > AlphaHTTPMaxHeaders {
		return fmt.Errorf("effective HTTP header count exceeds %d", AlphaHTTPMaxHeaders)
	}
	if aggregateBytes > AlphaHTTPMaxHeaderAggregateBytes {
		return fmt.Errorf("effective HTTP headers exceed %d aggregate bytes", AlphaHTTPMaxHeaderAggregateBytes)
	}
	return nil
}

// ValidateAlphaHTTPOutputPath validates the UTF-8 /outputs path subset used by
// point-in-time HTTP file assertions.
func ValidateAlphaHTTPOutputPath(value string) error {
	if !utf8.ValidString(value) ||
		len(value) == 0 ||
		len(value) > AlphaHTTPMaxOutputPathBytes ||
		!strings.HasPrefix(value, "/") ||
		strings.ContainsRune(value, '\\') ||
		path.Clean(value) != value ||
		(value != "/outputs" && !strings.HasPrefix(value, "/outputs/")) {
		return fmt.Errorf("HTTP output path is not a normalized /outputs path")
	}
	for _, valueRune := range value {
		if unicode.IsControl(valueRune) {
			return fmt.Errorf("HTTP output path contains control data")
		}
	}
	return nil
}

func isPrintableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validAlphaHTTPRawQuery(value string) bool {
	for index := 0; index < len(value); index++ {
		current := value[index]
		switch {
		case current >= 'a' && current <= 'z',
			current >= 'A' && current <= 'Z',
			current >= '0' && current <= '9',
			strings.ContainsRune("-._~!$&'()*+,;=:@/?", rune(current)):
			continue
		case current == '%':
			if index+2 >= len(value) ||
				!isHexDigit(value[index+1]) ||
				!isHexDigit(value[index+2]) {
				return false
			}
			index += 2
		default:
			return false
		}
	}
	return true
}

func isHexDigit(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}
