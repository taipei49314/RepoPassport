// Package privacy implements the frozen, local minimal-public publication gate.
// It deliberately reports only fixed policy metadata; matched content and paths
// never cross the error boundary.
package privacy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/structuredjson"
)

const (
	Profile            = "minimal-public"
	Policy             = "minimal-public-v1alpha2"
	EvaluationPassed   = "passed"
	RulesetDigest      = "sha256:b77ef257f122a975bb033637dfcc1aab3872ab894cd73066565141e7de773db4"
	maxDepth           = 64
	maxNodes           = 65_536
	maxStringBytes     = 65_536
	maxFindings        = 100
	maxVerificationRaw = 16 << 20
)

const policyDescriptor = `{"candidatePolicy":{"base64MinDistinct":8,"base64MinEntropyBitsPerByte":4,"base64MinLength":24,"hexMinEntropyBitsPerByte":3,"hexMinLength":32,"maxSeparatorsBeforeSplit":2,"windowLength":64,"windowStride":16},"limits":{"maxDepth":64,"maxFindings":100,"maxNodes":65536,"maxStringBytes":65536},"patternSetVersion":"minimal-public-patterns-2026-08-01.11","policy":"minimal-public-v1alpha2","profile":"minimal-public","rules":["PRIVATE_KEY_PEM","AUTHORIZATION_CREDENTIAL","CREDENTIAL_ASSIGNMENT","KNOWN_PROVIDER_CREDENTIAL","JWT_COMPACT","URL_CREDENTIAL_OR_QUERY","EMAIL_ADDRESS","HOST_PRIVATE_PATH","SENSITIVE_DYNAMIC_FIELD","HIGH_ENTROPY_CANDIDATE","PUBLIC_RESOURCE_CONTRACT","PRIVACY_SCAN_LIMIT"]}`

var orderedRuleIDs = []string{
	"PRIVATE_KEY_PEM",
	"AUTHORIZATION_CREDENTIAL",
	"CREDENTIAL_ASSIGNMENT",
	"KNOWN_PROVIDER_CREDENTIAL",
	"JWT_COMPACT",
	"URL_CREDENTIAL_OR_QUERY",
	"EMAIL_ADDRESS",
	"HOST_PRIVATE_PATH",
	"SENSITIVE_DYNAMIC_FIELD",
	"HIGH_ENTROPY_CANDIDATE",
	"PUBLIC_RESOURCE_CONTRACT",
	"PRIVACY_SCAN_LIMIT",
}

var (
	privateKeyPattern            = regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)
	explicitAuthorizationPattern = regexp.MustCompile(`(?i)(?:proxy-)?authorization\s*[:=]\s*(?:basic|bearer)\s+\S+|(?:set-)?cookie\s*[:=]\s*\S+|session(?:id|_id)?\s*[:=]\s*\S+`)
	bareAuthorizationPattern     = regexp.MustCompile(`(?i)(?:^|[^0-9a-z_-])(basic|bearer)\s+([0-9a-z+/=._~-]{4,1000})(?:$|[^0-9a-z+/=._~-])`)
	credentialAssignmentPattern  = regexp.MustCompile(`(?i)(?:^|[^0-9a-z_])["']?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization|cookie)["']?\s*[:=]\s*["']?[^\s"'}]+`)
	knownProviderPatterns        = []*regexp.Regexp{
		regexp.MustCompile(`(?:^|[^0-9A-Z])(?:AKIA|ASIA)[0-9A-Z]{16}(?:$|[^0-9A-Z])`),
		regexp.MustCompile(`(?i)(?:^|[^0-9a-z_])(?:github_pat_[0-9a-z_]{20,}|gh[pousr]_[0-9a-z]{20,})(?:$|[^0-9a-z_])`),
		regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])glpat-[0-9A-Za-z_-]{20,}(?:$|[^0-9A-Za-z_-])`),
		regexp.MustCompile(`(?:^|[^0-9A-Za-z-])xox[baprs]-[0-9A-Za-z-]{10,}(?:$|[^0-9A-Za-z-])`),
		regexp.MustCompile(`(?:^|[^0-9A-Za-z_])sk_live_[0-9A-Za-z]{16,}(?:$|[^0-9A-Za-z])`),
		regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?:$|[^0-9A-Za-z_-])`),
		regexp.MustCompile(`(?:^|[^0-9A-Za-z_])npm_[0-9A-Za-z]{20,}(?:$|[^0-9A-Za-z])`),
	}
	jwtPattern             = regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])([0-9A-Za-z_-]{2,1000}\.[0-9A-Za-z_-]{2,1000}\.[0-9A-Za-z_-]{2,1000})(?:$|[^0-9A-Za-z_-])`)
	emailPattern           = regexp.MustCompile(`(?i)(?:^|[^0-9a-z.!#$%&'*+/=?^_` + "`" + `{|}~-])[0-9a-z.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[0-9a-z](?:[0-9a-z-]{0,61}[0-9a-z])?(?:\.[0-9a-z](?:[0-9a-z-]{0,61}[0-9a-z])?)*\.[a-z](?:[a-z-]{0,61}[a-z])?(?:$|[^0-9a-z-])`)
	windowsPathPattern     = regexp.MustCompile(`(?i)(?:^|[^0-9a-z])(?:[a-z]:[\\/]|\\\\|\\\?\\|\\\.\\)[^\s"']+`)
	posixHomePattern       = regexp.MustCompile(`(?i)(?:^|[^0-9a-z])/(?:home|users|root)/[^\s"']+`)
	absoluteURLPattern     = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]{0,31}://[^\s"'<>]+`)
	fileURIPattern         = regexp.MustCompile(`(?i)(?:^|[^a-z])file:(?:/{1,3}|\\)[^\s"']+`)
	sensitiveKeyPattern    = regexp.MustCompile(`(?i)(?:^|[_-])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization|cookie|session|environment|env|stdout|stderr|raw|body|content|data[_-]?root|source[_-]?root|repository[_-]?root|workspace[_-]?dir|outputs[_-]?dir|host[_-]?(?:root|path)|local[_-]?path|run[_-]?dir)(?:$|[_-])`)
	hexCandidatePattern    = regexp.MustCompile(`^[0-9A-Fa-f]{32,}$`)
	base64CandidatePattern = regexp.MustCompile(`^[0-9A-Za-z+/=_-]{24,}$`)
)

// Evaluation is fixed public metadata emitted only after a complete pass.
type Evaluation struct {
	PrivacyProfile       string `json:"privacyProfile"`
	PrivacyPolicy        string `json:"privacyPolicy"`
	PrivacyRulesetDigest string `json:"privacyRulesetDigest"`
	PrivacyEvaluation    string `json:"privacyEvaluation"`
}

func Passed() Evaluation {
	return Evaluation{Profile, Policy, RulesetDigest, EvaluationPassed}
}

func Descriptor() string { return policyDescriptor }

func RuleIDs() []string { return append([]string(nil), orderedRuleIDs...) }

// Evaluate verifies the bounded public representation. The caller is
// responsible for canonical/schema/integrity validation before invoking it.
func Evaluate(raw []byte) (Evaluation, error) {
	if len(raw) == 0 || len(raw) > maxVerificationRaw || !utf8.Valid(raw) {
		return Evaluation{}, blocked([]finding{{"PRIVACY_SCAN_LIMIT", "document"}}, false)
	}
	root, err := structuredjson.Decode(raw, structuredjson.DecodeLimits{
		MaxBytes: maxVerificationRaw, MaxDepth: maxDepth, MaxNodes: maxNodes,
	})
	if err != nil {
		return Evaluation{}, blocked([]finding{{"PRIVACY_SCAN_LIMIT", "document"}}, false)
	}
	state := scanState{}
	state.walk(root, nil, false)
	if len(state.findings) != 0 {
		return Evaluation{}, blocked(state.findings, state.truncated)
	}
	return Passed(), nil
}

type finding struct{ rule, surface string }

type scanState struct {
	findings  []finding
	truncated bool
}

func (s *scanState) add(rule, surface string) {
	if len(s.findings) >= maxFindings {
		s.truncated = true
		return
	}
	s.findings = append(s.findings, finding{rule, surface})
}

func (s *scanState) walk(value any, path []string, dynamic bool) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			s.scanString(key, append(path, key), "dynamic-key", false)
			childDynamic := dynamic || isDynamicRoot(key)
			if childDynamic && sensitiveDynamicKey(key) && nonEmpty(child) &&
				!dynamicFieldExemption(append(path, key), child) {
				s.add("SENSITIVE_DYNAMIC_FIELD", "dynamic-field")
			}
			if key == "resource" && stringAt(typed, "operation") == "sandbox.outputs.export" && stringValue(child) != "/outputs" {
				s.add("PUBLIC_RESOURCE_CONTRACT", "observation-resource")
			}
			s.walk(child, append(path, key), childDynamic)
		}
	case []any:
		for _, child := range typed {
			s.walk(child, path, dynamic)
		}
	case string:
		s.scanString(typed, path, "string-value", true)
	}
}

func isDynamicRoot(key string) bool {
	switch key {
	case "details", "expected", "actual":
		return true
	}
	return false
}

func sensitiveDynamicKey(key string) bool {
	if sensitiveKeyPattern.MatchString(key) {
		return true
	}
	tokens := keyTokens(key)
	compact := strings.Join(tokens, "")
	switch compact {
	case "password", "passwd", "pwd", "secret", "token", "apikey", "accesskey",
		"clientsecret", "authorization", "cookie", "session", "environment", "env",
		"stdout", "stderr", "raw", "body", "content", "dataroot", "sourceroot",
		"repositoryroot", "workspacedir", "outputsdir", "hostroot", "hostpath",
		"localpath", "rundir", "contentincluded", "rawpathincluded", "stdoutcomplete":
		return true
	}
	for index, token := range tokens {
		switch token {
		case "password", "passwd", "pwd", "credential", "credentials", "authorization", "auth",
			"secret", "token", "cookie", "session", "environment", "stdout", "stderr", "raw", "stream", "body":
			return true
		case "content":
			if index+1 >= len(tokens) || (tokens[index+1] != "type" && tokens[index+1] != "included") {
				return true
			}
		}
	}
	for _, sequence := range [][]string{
		{"private", "key"}, {"api", "key"}, {"access", "key"}, {"client", "secret"},
		{"host", "root"}, {"host", "path"}, {"local", "path"}, {"run", "dir"},
		{"data", "root"}, {"source", "root"}, {"repository", "root"},
		{"workspace", "dir"}, {"outputs", "dir"},
	} {
		if containsTokenSequence(tokens, sequence) {
			return true
		}
	}
	return false
}

func keyTokens(key string) []string {
	var tokens []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			tokens = append(tokens, strings.ToLower(key[start:end]))
		}
		start = -1
	}
	for index := 0; index < len(key); index++ {
		character := key[index]
		if !asciiLetter(character) && !asciiDigit(character) {
			flush(index)
			continue
		}
		if start < 0 {
			start = index
			continue
		}
		previous := key[index-1]
		nextLower := index+1 < len(key) && asciiLower(key[index+1])
		boundary := asciiDigit(character) != asciiDigit(previous) ||
			asciiUpper(character) && (asciiLower(previous) || asciiUpper(previous) && nextLower)
		if boundary {
			flush(index)
			start = index
		}
	}
	flush(len(key))
	return tokens
}

func containsTokenSequence(tokens, sequence []string) bool {
	if len(sequence) == 0 || len(tokens) < len(sequence) {
		return false
	}
	for start := 0; start+len(sequence) <= len(tokens); start++ {
		matched := true
		for index := range sequence {
			if tokens[start+index] != sequence[index] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func asciiLower(value byte) bool  { return value >= 'a' && value <= 'z' }
func asciiUpper(value byte) bool  { return value >= 'A' && value <= 'Z' }
func asciiLetter(value byte) bool { return asciiLower(value) || asciiUpper(value) }
func asciiDigit(value byte) bool  { return value >= '0' && value <= '9' }

func nonEmpty(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) != 0
	case map[string]any:
		return len(typed) != 0
	default:
		return true
	}
}

func stringAt(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}
func stringValue(value any) string { result, _ := value.(string); return result }

func (s *scanState) scanString(value string, path []string, surface string, allowExemption bool) {
	if len(value) > maxStringBytes {
		s.add("PRIVACY_SCAN_LIMIT", surface)
		return
	}
	checks := []struct {
		id    string
		match bool
	}{
		{"PRIVATE_KEY_PEM", privateKeyPattern.MatchString(value)},
		{"AUTHORIZATION_CREDENTIAL", authorizationCredential(value)},
		{"CREDENTIAL_ASSIGNMENT", credentialAssignmentPattern.MatchString(value)},
		{"JWT_COMPACT", jwtCompact(value)},
		{"URL_CREDENTIAL_OR_QUERY", unsafeURL(value)},
		{"EMAIL_ADDRESS", emailPattern.MatchString(value)},
		{"HOST_PRIVATE_PATH", windowsPathPattern.MatchString(value) || posixHomePattern.MatchString(value) || fileURIPattern.MatchString(value)},
	}
	for _, provider := range knownProviderPatterns {
		if provider.MatchString(value) {
			checks = append(checks, struct {
				id    string
				match bool
			}{"KNOWN_PROVIDER_CREDENTIAL", true})
			break
		}
	}
	candidate := value
	for _, prefix := range []string{"sha256:", "hmac-sha256:"} {
		if strings.HasPrefix(candidate, prefix) {
			candidate = candidate[len(prefix):]
			break
		}
	}
	digestShaped := len(candidate) == 64 && (lowerHex(candidate, 64) || upperOrLowerHex(candidate, 64))
	if (highEntropyCandidate(candidate) || digestShaped) && !(allowExemption && exactExemption(path, value)) {
		checks = append(checks, struct {
			id    string
			match bool
		}{"HIGH_ENTROPY_CANDIDATE", true})
	}
	for _, check := range checks {
		if check.match {
			s.add(check.id, surface)
		}
	}
}

func jwtCompact(value string) bool {
	for _, match := range jwtPattern.FindAllStringSubmatch(value, -1) {
		if len(match) != 2 {
			continue
		}
		segments := strings.Split(match[1], ".")
		if len(segments) != 3 {
			continue
		}
		header, headerErr := base64.RawURLEncoding.Strict().DecodeString(segments[0])
		payload, payloadErr := base64.RawURLEncoding.Strict().DecodeString(segments[1])
		if headerErr == nil && payloadErr == nil && len(header) <= 3072 && len(payload) <= 3072 && jsonObject(header) && jsonObject(payload) {
			return true
		}
	}
	return false
}

func authorizationCredential(value string) bool {
	if explicitAuthorizationPattern.MatchString(value) {
		return true
	}
	for _, match := range bareAuthorizationPattern.FindAllStringSubmatch(value, -1) {
		if len(match) != 3 {
			continue
		}
		switch strings.ToLower(match[1]) {
		case "basic":
			decoded, err := base64.StdEncoding.Strict().DecodeString(match[2])
			parts := bytesSplitOnce(decoded, ':')
			if err == nil && len(decoded) <= 3072 && len(parts) == 2 && len(parts[0]) != 0 && len(parts[1]) != 0 {
				return true
			}
		case "bearer":
			if len(match[2]) >= 20 && containsASCIIClass(match[2], "0123456789") && containsASCIIClass(match[2], "abcdefghijklmnopqrstuvwxyz") {
				return true
			}
		}
	}
	return false
}

func bytesSplitOnce(value []byte, separator byte) [][]byte {
	for index, character := range value {
		if character == separator {
			return [][]byte{value[:index], value[index+1:]}
		}
	}
	return nil
}

func containsASCIIClass(value, class string) bool {
	for _, character := range value {
		if strings.ContainsRune(class, character) || strings.ContainsRune(strings.ToUpper(class), character) {
			return true
		}
	}
	return false
}

func jsonObject(raw []byte) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && object != nil
}

func unsafeURL(value string) bool {
	for _, field := range absoluteURLPattern.FindAllString(value, -1) {
		trimmed := strings.TrimRight(field, `.,);`)
		parsed, err := url.Parse(trimmed)
		if err == nil && parsed.IsAbs() && parsed.Host != "" && (parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "") {
			return true
		}
	}
	return false
}

func highEntropyCandidate(value string) bool {
	for _, candidate := range candidateSegments(value) {
		if candidateScore(candidate) {
			return true
		}
	}
	return false
}

func candidateSegments(value string) []string {
	segments := make([]string, 0, 4)
	start := -1
	flush := func(end int) {
		if start < 0 || end-start < 24 {
			start = -1
			return
		}
		candidate := value[start:end]
		if strings.Count(candidate, "-")+strings.Count(candidate, "_") > 2 {
			for _, part := range strings.FieldsFunc(candidate, func(r rune) bool { return r == '-' || r == '_' }) {
				if len(part) >= 24 {
					segments = append(segments, part)
				}
			}
		} else {
			segments = append(segments, candidate)
		}
		if len(candidate) > 64 && strings.Count(candidate, "-")+strings.Count(candidate, "_") <= 2 {
			for offset := 0; offset+64 <= len(candidate); offset += 16 {
				segments = append(segments, candidate[offset:offset+64])
			}
		}
		start = -1
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		allowed := character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			strings.ContainsRune("+/=_-", rune(character))
		if allowed {
			if start < 0 {
				start = index
			}
			continue
		}
		flush(index)
	}
	flush(len(value))
	return segments
}

func candidateScore(value string) bool {
	if !hexCandidatePattern.MatchString(value) && !base64CandidatePattern.MatchString(value) {
		return false
	}
	var counts [256]int
	distinct := 0
	for index := 0; index < len(value); index++ {
		character := value[index]
		if counts[character] == 0 {
			distinct++
		}
		counts[character]++
	}
	entropy := 0.0
	length := float64(len(value))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	if hexCandidatePattern.MatchString(value) {
		return len(value)%2 == 0 && entropy >= 3.0
	}
	return distinct >= 8 && entropy >= 4.0
}

func exactExemption(path []string, value string) bool {
	joined := strings.Join(path, ".")
	if joined == "assertions.expected.validatorVersion" {
		return value == domain.AlphaJSONValidatorVersion
	}
	if joined == "observations.details.tokenScheme" {
		return value == "ephemeral-keyed-hmac-sha256"
	}
	if joined == "observations.resource" || joined == "errors.details.containerName" {
		return generatedContainerName(value)
	}
	if joined == "assertions.evidenceRefs" || joined == "errors.evidenceRefs" {
		return exactEvidenceRef(value)
	}
	if joined == "observations.details.opaqueInventoryToken" {
		return strings.HasPrefix(value, "hmac-sha256:") && lowerHex(value[len("hmac-sha256:"):], 64)
	}
	if joined == "subject.commit" {
		return lowerHex(value, 40)
	}
	if joined == "runId" || joined == "verificationId" {
		return opaqueID(value)
	}
	if joined == "startedAt" || joined == "completedAt" || joined == "observations.timestamp" {
		return canonicalUTCTimestamp(value)
	}
	if joined == "subject.identity" {
		return canonicalIdentity(value)
	}
	digestPaths := map[string]struct{}{
		"subject.treeDigest": {}, "plan.planDigest": {}, "plan.policyBundleDigest": {},
		"digests.observations": {}, "digests.assertions": {},
		"digests.policyDecisions": {}, "digests.verification": {},
		"policyDecisions.policyBundleDigest": {},
		"assertions.expected.digest":         {}, "assertions.expected.schema.digest": {},
		"assertions.expected.jsonSchema.digest": {},
		"assertions.actual.sha256":              {},
		"observations.details.baselineDigest":   {}, "observations.details.finalDigest": {},
		"observations.details.canonicalTranscriptDigest": {},
		"observations.details.canonicalSampleDigest":     {},
	}
	if _, ok := digestPaths[joined]; ok {
		return strings.HasPrefix(value, "sha256:") && lowerHex(value[len("sha256:"):], 64)
	}
	return false
}

func dynamicFieldExemption(path []string, value any) bool {
	if stringValue(value) != "" && exactExemption(path, stringValue(value)) {
		return true
	}
	joined := strings.Join(path, ".")
	boolean, ok := value.(bool)
	if !ok {
		return false
	}
	switch joined {
	case "observations.details.contentIncluded", "observations.details.rawPathIncluded":
		return !boolean
	case "assertions.actual.stdoutComplete":
		return boolean
	case "assertions.actual.bodyContainsMatched",
		"assertions.actual.bodyTruncated",
		"assertions.actual.structuredJSONBodyTruncated",
		"observations.details.bodyTruncated":
		return true
	}
	return false
}

func generatedContainerName(value string) bool {
	const prefix = "repopass-"
	return strings.HasPrefix(value, prefix) && lowerHex(value[len(prefix):], 32)
}

func exactEvidenceRef(value string) bool {
	const runPrefix, runSuffix = "run:", ":filesystem"
	if strings.HasPrefix(value, runPrefix) && strings.HasSuffix(value, runSuffix) {
		middle := value[len(runPrefix) : len(value)-len(runSuffix)]
		return lowerHex(middle, 32)
	}
	const schemaPrefix = "json-schema:sha256:"
	return strings.HasPrefix(value, schemaPrefix) && lowerHex(value[len(schemaPrefix):], 64)
}

func canonicalUTCTimestamp(value string) bool {
	if !strings.HasSuffix(value, "Z") {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func upperOrLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func opaqueID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c == '_' || c == '-' || c == '.' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

func canonicalIdentity(value string) bool {
	return strings.HasPrefix(value, "sha256:") && lowerHex(value[len("sha256:"):], 64)
}

func blocked(findings []finding, truncated bool) error {
	rules := map[string]struct{}{}
	surfaces := map[string]struct{}{}
	for _, item := range findings {
		rules[item.rule] = struct{}{}
		surfaces[item.surface] = struct{}{}
	}
	ruleList := orderedPresent(rules, orderedRuleIDs)
	surfaceList := make([]string, 0, len(surfaces))
	for item := range surfaces {
		surfaceList = append(surfaceList, item)
	}
	sort.Strings(surfaceList)
	err := domain.NewError(domain.CodeEvidencePrivacyBlocked, domain.SeverityHigh, "The authoritative verification artifact is blocked by the minimal-public privacy policy.")
	err.Details = map[string]any{
		"privacyProfile": Profile, "privacyPolicy": Policy,
		"privacyRulesetDigest": RulesetDigest, "ruleIds": strings.Join(ruleList, ","),
		"surfaces": strings.Join(surfaceList, ","), "findingCount": len(findings), "truncated": truncated,
	}
	return err
}

func orderedPresent(set map[string]struct{}, order []string) []string {
	result := make([]string, 0, len(set))
	for _, item := range order {
		if _, ok := set[item]; ok {
			result = append(result, item)
		}
	}
	return result
}

func init() {
	sum := sha256.Sum256([]byte(policyDescriptor))
	if "sha256:"+hex.EncodeToString(sum[:]) != RulesetDigest {
		panic("minimal-public policy descriptor digest mismatch")
	}
	if encoded, err := json.Marshal(json.RawMessage(policyDescriptor)); err != nil || len(encoded) == 0 {
		panic("minimal-public policy descriptor invalid")
	}
}
