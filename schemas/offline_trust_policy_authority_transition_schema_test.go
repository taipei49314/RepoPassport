package schemas_test

import (
	"strings"
	"testing"
)

func TestOfflineTrustPolicyAuthorityTransitionSchemasContract(t *testing.T) {
	schemas := compilePublicSchemas(t)
	previousID := "sha256:" + strings.Repeat("a", 64)
	nextID := "sha256:" + strings.Repeat("b", 64)
	payload := map[string]any{
		"schemaVersion": "1", "purpose": "offline-trust-policy-authority-rotation",
		"policyPayloadType": "application/vnd.repopass.offline-trust-policy.v2+json",
		"generation":        uint64(1), "keyAlgorithm": "ed25519", "keyIdAlgorithm": "spki-sha256",
		"previousAuthorityKeyId": previousID, "nextAuthorityKeyId": nextID,
	}
	assertSchemaAccepts(t, schemas["offline-trust-policy-authority-transition-v1.schema.json"], payload, "offline trust-policy authority transition")
	for name, mutate := range map[string]func(map[string]any){
		"extension":         func(value map[string]any) { value["unknown"] = true },
		"zero generation":   func(value map[string]any) { value["generation"] = 0 },
		"unsafe generation": func(value map[string]any) { value["generation"] = uint64(9007199254740992) },
		"wrong purpose":     func(value map[string]any) { value["purpose"] = "release-policy-authority-rotation" },
		"wrong policy type": func(value map[string]any) {
			value["policyPayloadType"] = "application/vnd.repopass.release-key-policy.v1+json"
		},
		"wrong algorithm":  func(value map[string]any) { value["keyAlgorithm"] = "rsa" },
		"uppercase key ID": func(value map[string]any) { value["nextAuthorityKeyId"] = "sha256:" + strings.Repeat("B", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneJSONMap(t, payload)
			mutate(candidate)
			assertSchemaRejects(t, schemas["offline-trust-policy-authority-transition-v1.schema.json"], candidate, name)
		})
	}

	envelope := map[string]any{
		"payloadType": "application/vnd.repopass.offline-trust-policy-authority-transition.v1+json",
		"payload":     "e30=",
		"signatures": []any{map[string]any{
			"keyid": previousID, "sig": strings.Repeat("A", 86) + "==",
		}},
	}
	assertSchemaAccepts(t, schemas["offline-trust-policy-authority-transition-envelope-v1.schema.json"], envelope, "offline trust-policy authority transition envelope")
	for name, mutate := range map[string]func(map[string]any){
		"release type": func(value map[string]any) {
			value["payloadType"] = "application/vnd.repopass.release-authority-transition.v1+json"
		},
		"no signatures": func(value map[string]any) { value["signatures"] = []any{} },
		"two signatures": func(value map[string]any) {
			signature := map[string]any{"keyid": previousID, "sig": strings.Repeat("A", 86) + "=="}
			value["signatures"] = []any{signature, signature}
		},
		"extension": func(value map[string]any) { value["unknown"] = true },
	} {
		t.Run("envelope "+name, func(t *testing.T) {
			candidate := cloneJSONMap(t, envelope)
			mutate(candidate)
			assertSchemaRejects(t, schemas["offline-trust-policy-authority-transition-envelope-v1.schema.json"], candidate, name)
		})
	}
}
