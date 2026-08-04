package privacy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func TestFrozenPolicyDescriptorAndOrderedRules(t *testing.T) {
	const expectedDescriptor = `{"candidatePolicy":{"base64MinDistinct":8,"base64MinEntropyBitsPerByte":4,"base64MinLength":24,"hexMinEntropyBitsPerByte":3,"hexMinLength":32,"maxSeparatorsBeforeSplit":2,"windowLength":64,"windowStride":16},"limits":{"maxDepth":64,"maxFindings":100,"maxNodes":65536,"maxStringBytes":65536},"patternSetVersion":"minimal-public-patterns-2026-08-04.12","policy":"minimal-public-v1alpha3","profile":"minimal-public","rules":["PRIVATE_KEY_PEM","AUTHORIZATION_CREDENTIAL","CREDENTIAL_ASSIGNMENT","KNOWN_PROVIDER_CREDENTIAL","JWT_COMPACT","URL_CREDENTIAL_OR_QUERY","EMAIL_ADDRESS","HOST_PRIVATE_PATH","SENSITIVE_DYNAMIC_FIELD","HIGH_ENTROPY_CANDIDATE","PUBLIC_RESOURCE_CONTRACT","PRIVACY_SCAN_LIMIT"]}`
	const expectedDigest = "sha256:b837a6758185671c7eff7463ac1cc72b6e29cdf44324fe0d84ec29158c4c88a9"
	if Descriptor() != expectedDescriptor || RulesetDigest != expectedDigest {
		t.Fatalf("frozen descriptor drift: descriptorEqual=%v digest=%q", Descriptor() == expectedDescriptor, RulesetDigest)
	}
	sum := sha256.Sum256([]byte(Descriptor()))
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != RulesetDigest {
		t.Fatalf("ruleset digest = %q, want %q", got, RulesetDigest)
	}
	want := []string{"PRIVATE_KEY_PEM", "AUTHORIZATION_CREDENTIAL", "CREDENTIAL_ASSIGNMENT", "KNOWN_PROVIDER_CREDENTIAL", "JWT_COMPACT", "URL_CREDENTIAL_OR_QUERY", "EMAIL_ADDRESS", "HOST_PRIVATE_PATH", "SENSITIVE_DYNAMIC_FIELD", "HIGH_ENTROPY_CANDIDATE", "PUBLIC_RESOURCE_CONTRACT", "PRIVACY_SCAN_LIMIT"}
	if got := RuleIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered rules = %#v", got)
	}
	got := RuleIDs()
	got[0] = "mutated"
	if RuleIDs()[0] != want[0] {
		t.Fatal("RuleIDs returned mutable process state")
	}
}

func TestEveryFrozenRuleAndBoundaryNearMiss(t *testing.T) {
	tests := []struct{ rule, value, near string }{
		{"PRIVATE_KEY_PEM", "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----"},
		{"PRIVATE_KEY_PEM", "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----", "encrypted public metadata"},
		{"AUTHORIZATION_CREDENTIAL", "Authorization: Bearer synthetic-value", "authorization pending"},
		{"AUTHORIZATION_CREDENTIAL", "Bearer c3ludGhldGljLXZhbHVl", "bearer documentationpending"},
		{"AUTHORIZATION_CREDENTIAL", "Basic dXNlcjpwYXNz", "basic test"},
		{"CREDENTIAL_ASSIGNMENT", "client_secret=synthetic-value", "client secret is absent"},
		{"CREDENTIAL_ASSIGNMENT", `{"password":"synthetic"}`, `{"password":""}`},
		{"CREDENTIAL_ASSIGNMENT", `'api_key': 'synthetic'`, `'api_key': ''`},
		{"CREDENTIAL_ASSIGNMENT", `password="synthetic"`, `compassword="synthetic"`},
		{"KNOWN_PROVIDER_CREDENTIAL", "AKIA" + "ABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNO"},
		{"KNOWN_PROVIDER_CREDENTIAL", "ASIA" + "ABCDEFGHIJKLMNOP", "XASIAABCDEFGHIJKLMNOPY"},
		{"KNOWN_PROVIDER_CREDENTIAL", "github_" + "pat_synthetic_012345678901234567890", "github workflow"},
		{"KNOWN_PROVIDER_CREDENTIAL", "glpat-" + "01234567890123456789", "gitlab project"},
		{"KNOWN_PROVIDER_CREDENTIAL", "xoxb-" + "0123456789-synthetic", "slack token absent"},
		{"KNOWN_PROVIDER_CREDENTIAL", "sk_" + "live_0123456789abcdef", "stripe test credential absent"},
		{"KNOWN_PROVIDER_CREDENTIAL", "AIza" + "01234567890123456789012345678901234", "google api"},
		{"KNOWN_PROVIDER_CREDENTIAL", "npm_" + "01234567890123456789", "npm package"},
		{"JWT_COMPACT", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeW50aGV0aWMifQ.c2ln", "one.two"},
		{"JWT_COMPACT", "e30.e30.c2ln", "abc.def.ghi"},
		{"JWT_COMPACT", "e30.e30.c2ln", "MQ.MQ.c2ln"},
		{"URL_CREDENTIAL_OR_QUERY", "https://example.invalid/path?synthetic=value", "https://example.invalid/path"},
		{"URL_CREDENTIAL_OR_QUERY", "https://user@example.invalid/path", "https://example.invalid/path"},
		{"URL_CREDENTIAL_OR_QUERY", "url=https://example.invalid/path?synthetic=value", "url=https://example.invalid/path"},
		{"URL_CREDENTIAL_OR_QUERY", "ssh://user@example.invalid/path", "ssh://example.invalid/path"},
		{"URL_CREDENTIAL_OR_QUERY", "custom+scheme://example.invalid/path?q=1", "custom+scheme://example.invalid/path"},
		{"EMAIL_ADDRESS", "synthetic.user@example.invalid", "example.invalid"},
		{"EMAIL_ADDRESS", "synthetic.user@example.invalid", "package@v6.0.2"},
		{"HOST_PRIVATE_PATH", `C:` + `\Users\synthetic\artifact`, `/workspace/artifact`},
		{"HOST_PRIVATE_PATH", `/home/` + `synthetic/artifact`, `/outputs/artifact`},
		{"HOST_PRIVATE_PATH", `/Users/` + `synthetic/artifact`, `/outputs/artifact`},
		{"HOST_PRIVATE_PATH", `path=C:` + `\Users\synthetic\artifact`, `/outputs/artifact`},
		{"HOST_PRIVATE_PATH", `root=/home/` + `synthetic/artifact`, `/outputs/artifact`},
		{"HOST_PRIVATE_PATH", `file:/home/` + `synthetic/artifact`, `profile: public`},
		{"HIGH_ENTROPY_CANDIDATE", "0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for index, test := range tests {
		t.Run(fmt.Sprintf("%02d-%s", index, test.rule), func(t *testing.T) {
			assertBlockedRule(t, objectWithValue(test.value), test.rule)
			if _, err := Evaluate(objectWithValue(test.near)); err != nil {
				t.Fatalf("near miss blocked: %v", err)
			}
		})
	}
	assertBlockedRule(t, []byte(`{"observations":[{"operation":"sandbox.outputs.export","resource":"/controller/private"}]}`), "PUBLIC_RESOURCE_CONTRACT")
	if _, err := Evaluate([]byte(`{"observations":[{"operation":"sandbox.outputs.export","resource":"/outputs"}]}`)); err != nil {
		t.Fatalf("public resource contract blocked: %v", err)
	}
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"client_secret":"synthetic"}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	for _, key := range []string{"dataRoot", "sourceRoot", "repositoryRoot", "workspaceDir", "outputsDir", "hostPath", "credentials", "authContext", "accessToken", "privateKey", "environmentVariables", "rawResponseBody", "stdoutContent", "responseContent", "privateKeyMaterial", "apiKeyValue", "accessKeyId", "hostPathHint", "localPathValue", "rawResponseBodyText", "oauth2Token", "raw2Body"} {
		assertBlockedRule(t, []byte(fmt.Sprintf(`{"observations":[{"details":{"%s":"synthetic"}}]}`, key)), "SENSITIVE_DYNAMIC_FIELD")
	}
	for _, key := range []string{"authorName", "drawCount", "upstreamStatus", "contentType"} {
		if _, err := Evaluate([]byte(fmt.Sprintf(`{"observations":[{"details":{"%s":"synthetic"}}]}`, key))); err != nil {
			t.Fatalf("benign dynamic key %q blocked: %v", key, err)
		}
	}
	if _, err := Evaluate([]byte(`{"observations":[{"details":{"client_secret":""}}]}`)); err != nil {
		t.Fatalf("empty dynamic field blocked: %v", err)
	}
}

func TestVariableSurfacesAndTypedExemptions(t *testing.T) {
	marker := "synthetic.user@example.invalid"
	for _, raw := range []string{
		`{"runner":{"reason":%q}}`,
		`{"observations":[{"actor":%q}]}`,
		`{"observations":[{"resource":%q}]}`,
		`{"observations":[{"details":{"note":%q}}]}`,
		`{"assertions":[{"expected":%q}]}`,
		`{"assertions":[{"actual":%q}]}`,
		`{"assertions":[{"message":%q}]}`,
		`{"assertions":[{"evidenceRefs":[%q]}]}`,
		`{"policyDecisions":[{"message":%q,"evidenceRefs":[]}]}`,
		`{"policyDecisions":[{"message":"safe","evidenceRefs":[%q]}]}`,
		`{"errors":[{"message":%q,"details":{},"suggestion":"","evidenceRefs":[]}]}`,
		`{"errors":[{"message":"safe","details":{},"suggestion":%q,"evidenceRefs":[]}]}`,
		`{"errors":[{"message":"safe","details":{},"suggestion":"","evidenceRefs":[%q]}]}`,
	} {
		assertBlockedRule(t, []byte(fmt.Sprintf(raw, marker)), "EMAIL_ADDRESS")
	}
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"synthetic.user@example.invalid":"ok"}}]}`), "EMAIL_ADDRESS")

	allowed := []string{
		`{"subject":{"treeDigest":"sha256:` + strings.Repeat("a", 64) + `","commit":"` + strings.Repeat("b", 40) + `","identity":"sha256:` + strings.Repeat("c", 64) + `"}}`,
		`{"subject":{"treeDigest":"sha256:` + strings.Repeat("a", 64) + `","commit":"0123456789abcdef0123456789abcdef01234567","identity":"git:0123456789abcdef0123456789abcdef01234567"}}`,
		`{"runId":"run_opaque_0123456789","verificationId":"vrf_opaque_0123456789"}`,
		`{"startedAt":"2026-08-01T00:00:00Z","completedAt":"2026-08-01T00:00:01Z"}`,
		`{"observations":[{"timestamp":"2026-08-01T00:00:00Z","details":{"opaqueInventoryToken":"hmac-sha256:` + strings.Repeat("d", 64) + `"}}]}`,
	}
	for _, raw := range allowed {
		if _, err := Evaluate([]byte(raw)); err != nil {
			t.Fatalf("typed exemption blocked: %v", err)
		}
	}
	for _, raw := range []string{
		`{"observations":[{"resource":"repopass-0123456789abcdef0123456789abcdef"}]}`,
		`{"errors":[{"details":{"containerName":"repopass-0123456789abcdef0123456789abcdef"}}]}`,
		`{"assertions":[{"evidenceRefs":["run:0123456789abcdef0123456789abcdef:filesystem"]}]}`,
		`{"errors":[{"evidenceRefs":["json-schema:sha256:` + strings.Repeat("a", 64) + `"]}]}`,
		`{"observations":[{"details":{"canonicalSampleDigest":"sha256:` + strings.Repeat("a", 64) + `"}}]}`,
		`{"observations":[{"details":{"tokenScheme":"ephemeral-keyed-hmac-sha256"}}]}`,
		`{"assertions":[{"expected":{"validatorVersion":"` + domain.AlphaJSONValidatorVersion + `"}}]}`,
		`{"observations":[{"details":{"contentIncluded":false,"rawPathIncluded":false}}],"assertions":[{"actual":{"stdoutComplete":true}}]}`,
		`{"observations":[{"details":{"bodyTruncated":false}}],"assertions":[{"expected":{"substringCheck":{"configured":true,"valuePublished":false},"jsonSchema":{"digest":"sha256:` + strings.Repeat("a", 64) + `"}},"actual":{"bodyContainsMatched":true,"bodyTruncated":false,"structuredJSONBodyTruncated":true}}]}`,
	} {
		if _, err := Evaluate([]byte(raw)); err != nil {
			t.Fatalf("typed producer exemption blocked: %v", err)
		}
	}
	assertBlockedRule(t, []byte(`{"message":"`+domain.AlphaJSONValidatorVersion+`"}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"assertions":[{"expected":{"validatorVersion":"github.com/santhosh-tekuri/jsonschema/v6@v6.0.3"}}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"contentIncluded":true}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"errors":[{"details":{"contentIncluded":false}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"rawPathIncluded":"false"}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"assertions":[{"actual":{"stdoutComplete":false}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"assertions":[{"expected":{"bodyContains":"safe-looking repository value"}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"assertions":[{"actual":{"bodyContainsMatched":"true"}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"assertions":[{"actual":{"bodyTruncated":0}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"assertions":[{"actual":{"structuredJSONBodyTruncated":0}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"bodyTruncated":"false"}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"errors":[{"details":{"bodyTruncated":false}}]}`), "SENSITIVE_DYNAMIC_FIELD")
	assertBlockedRule(t, []byte(`{"assertions":[{"expected":{"jsonSchema":{"digest":"sha256:`+strings.Repeat("A", 64)+`"}}}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"assertions":[{"expected":{"otherSchema":{"digest":"sha256:`+strings.Repeat("a", 64)+`"}}}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"message":"run:0123456789abcdef0123456789abcdef:filesystem"}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"observations":[{"resource":"repopass-0123456789abcdef0123456789abcdeg"}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, objectWithValue("0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_"), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, objectWithValue("prefix!0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_!suffix"), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, objectWithValue(strings.Repeat("a", 80)+"0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_"+strings.Repeat("b", 80)), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"opaqueInventoryToken":"hmac-sha256:`+strings.Repeat("A", 64)+`"}}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"policyDecisions":[{"message":"sha256:`+strings.Repeat("a", 64)+`"}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"observations":[{"details":{"digest":"sha256:`+strings.Repeat("a", 64)+`"}}]}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"subject":{"commit":"`+strings.Repeat("a", 64)+`"}}`), "HIGH_ENTROPY_CANDIDATE")
	assertBlockedRule(t, []byte(`{"observations":[{"timestamp":"`+"0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_"+`"}]}`), "HIGH_ENTROPY_CANDIDATE")
}

func TestRepresentativeCleanPublicVerificationSurfacePasses(t *testing.T) {
	raw := []byte(`{
		"runId":"run_opaque_0123456789",
		"verificationId":"vrf_opaque_0123456789",
		"startedAt":"2026-08-01T00:00:00Z",
		"completedAt":"2026-08-01T00:00:01Z",
		"subject":{"treeDigest":"sha256:` + strings.Repeat("a", 64) + `","commit":"` + strings.Repeat("b", 40) + `","identity":"sha256:` + strings.Repeat("c", 64) + `"},
		"observations":[
			{"operation":"sandbox.outputs.export","resource":"/outputs","timestamp":"2026-08-01T00:00:00Z","details":{"contentIncluded":false,"rawPathIncluded":false,"tokenScheme":"ephemeral-keyed-hmac-sha256","opaqueInventoryToken":"hmac-sha256:` + strings.Repeat("d", 64) + `"}},
			{"operation":"sandbox.cleanup","resource":"repopass-0123456789abcdef0123456789abcdef","details":{"canonicalSampleDigest":"sha256:` + strings.Repeat("e", 64) + `"}}
		],
		"assertions":[{"expected":{"validatorVersion":"` + domain.AlphaJSONValidatorVersion + `","digest":"sha256:` + strings.Repeat("f", 64) + `"},"actual":{"stdoutComplete":true},"evidenceRefs":["run:0123456789abcdef0123456789abcdef:filesystem"]}],
		"errors":[]
	}`)
	if _, err := Evaluate(raw); err != nil {
		t.Fatalf("representative clean public verification surface blocked: %v", err)
	}
}

func TestErrorIsFixedSafeNonEchoAndDeterministic(t *testing.T) {
	markers := []string{
		"unique.synthetic@example.invalid", "synthetic_password=unique-value",
		`C:` + `\Users\unique\private`, "https://example.invalid/?unique=value",
		"0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_unique",
	}
	secretKey := "0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_dynamic_key"
	secretValue := "0123456789abcdefABCDEFghijklMNOPQRSTUVWXYZ_dynamic_value"
	dynamicRaw, _ := json.Marshal(map[string]any{"observations": []any{map[string]any{"details": map[string]any{secretKey: secretValue}}}})
	_, dynamicErr := Evaluate(dynamicRaw)
	dynamicEncoded, _ := json.Marshal(dynamicErr)
	if strings.Contains(string(dynamicEncoded), secretKey) || strings.Contains(string(dynamicEncoded), secretValue) {
		t.Fatalf("dynamic key/value echoed in error: %s", dynamicEncoded)
	}
	orderedA := []byte(`{"z":"synthetic.user@example.invalid","a":"https://example.invalid/?synthetic=value"}`)
	orderedB := []byte(`{"a":"https://example.invalid/?synthetic=value","z":"synthetic.user@example.invalid"}`)
	if first, second := errorJSON(t, orderedA), errorJSON(t, orderedB); first != second {
		t.Fatalf("JSON member order changed fixed error: %s != %s", first, second)
	}
	var first string
	for iteration := 0; iteration < 20; iteration++ {
		object := map[string]any{}
		for index := len(markers) - 1; index >= 0; index-- {
			object[fmt.Sprintf("field-%d", index)] = markers[index]
		}
		raw, _ := json.Marshal(object)
		_, err := Evaluate(raw)
		if err == nil {
			t.Fatal("unsafe object passed")
		}
		encoded, _ := json.Marshal(err)
		for _, marker := range markers {
			if strings.Contains(string(encoded), marker) {
				t.Fatalf("error echoed marker in %s", encoded)
			}
		}
		if iteration == 0 {
			first = string(encoded)
		} else if string(encoded) != first {
			t.Fatalf("nondeterministic error: %s != %s", encoded, first)
		}
	}
	var typed *domain.Error
	_, err := Evaluate(objectWithValue(markers[0]))
	if !errors.As(err, &typed) || typed.Code != domain.CodeEvidencePrivacyBlocked || typed.Severity != domain.SeverityHigh {
		t.Fatalf("typed error = %#v", err)
	}
}

func TestConcurrentEvaluationAndLimitsFailClosed(t *testing.T) {
	raw := objectWithValue("synthetic.user@example.invalid")
	original := append([]byte(nil), raw...)
	want := errorJSON(t, raw)
	var wait sync.WaitGroup
	for i := 0; i < 50; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if got := errorJSON(t, raw); got != want {
				t.Errorf("concurrent result drift")
			}
		}()
	}
	wait.Wait()
	threshold := objectWithValue("abcdefghijklmnopabcdefghijklmnop")
	thresholdWant := errorJSON(t, threshold)
	for iteration := 0; iteration < 1000; iteration++ {
		if got := errorJSON(t, threshold); got != thresholdWant {
			t.Fatal("threshold classification drift")
		}
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("Evaluate mutated caller input")
	}

	deep := strings.Repeat(`{"x":`, 65) + `null` + strings.Repeat(`}`, 65)
	assertBlockedRule(t, []byte(deep), "PRIVACY_SCAN_LIMIT")
	largeString, _ := json.Marshal(map[string]any{"value": strings.Repeat("x", maxStringBytes+1)})
	assertBlockedRule(t, largeString, "PRIVACY_SCAN_LIMIT")
	values := make([]any, maxNodes+1)
	nodes, _ := json.Marshal(values)
	assertBlockedRule(t, nodes, "PRIVACY_SCAN_LIMIT")
	assertBlockedRule(t, []byte{0xff}, "PRIVACY_SCAN_LIMIT")
	tooLarge := make([]byte, maxVerificationRaw+1)
	assertBlockedRule(t, tooLarge, "PRIVACY_SCAN_LIMIT")

	many := map[string]any{}
	for index := 0; index < 150; index++ {
		many[fmt.Sprintf("field-%03d", index)] = "synthetic.user@example.invalid"
	}
	manyRaw, _ := json.Marshal(many)
	_, manyErr := Evaluate(manyRaw)
	var typed *domain.Error
	if !errors.As(manyErr, &typed) || typed.Details["findingCount"] != maxFindings || typed.Details["truncated"] != true {
		t.Fatalf("finding cap details = %#v", typed)
	}
}

func FuzzEvaluateNeverPanicsOrEchoes(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`{}`), objectWithValue("safe"), objectWithValue("synthetic.user@example.invalid"), objectWithValue("e30.e30.c2ln"), objectWithValue("url=custom+scheme://host.invalid?q=1"), []byte{0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := Evaluate(raw)
		if err == nil {
			return
		}
		encoded, marshalErr := json.Marshal(err)
		if marshalErr != nil {
			t.Fatalf("marshal error: %v", marshalErr)
		}
		if len(raw) >= 8 && strings.Contains(string(encoded), string(raw)) {
			t.Fatal("error echoed complete input")
		}
	})
}

func objectWithValue(value string) []byte {
	raw, _ := json.Marshal(map[string]any{"value": value})
	return raw
}

func assertBlockedRule(t *testing.T, raw []byte, rule string) {
	t.Helper()
	_, err := Evaluate(raw)
	var typed *domain.Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected blocked %s, got %v", rule, err)
	}
	rules, ok := typed.Details["ruleIds"].(string)
	if !ok || !contains(strings.Split(rules, ","), rule) {
		t.Fatalf("rules = %#v, want %s", typed.Details["ruleIds"], rule)
	}
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func errorJSON(t *testing.T, raw []byte) string {
	t.Helper()
	_, err := Evaluate(raw)
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	return string(encoded)
}
