package schemas_test

import "testing"

func TestReleaseAuthorityTransitionChainSchemaContract(t *testing.T) {
	schemas := compilePublicSchemas(t)
	hop := map[string]any{
		"transitionEnvelope":   "e30=",
		"nextAuthoritySpkiPem": "e30=",
	}
	chain := map[string]any{
		"schemaVersion": "1",
		"product":       "repopass",
		"channel":       "alpha",
		"purpose":       "release-policy-authority-rotation-chain",
		"hops":          []any{hop, hop},
	}
	schema := schemas["release-authority-transition-chain-v1.schema.json"]
	assertSchemaAccepts(t, schema, chain, "release authority transition chain")
	for name, mutate := range map[string]func(map[string]any){
		"unknown chain field": func(value map[string]any) { value["unknown"] = true },
		"wrong version":       func(value map[string]any) { value["schemaVersion"] = "2" },
		"wrong product":       func(value map[string]any) { value["product"] = "other" },
		"wrong channel":       func(value map[string]any) { value["channel"] = "stable" },
		"wrong purpose":       func(value map[string]any) { value["purpose"] = "release-policy-authority-rotation" },
		"zero hops":           func(value map[string]any) { value["hops"] = []any{} },
		"one hop":             func(value map[string]any) { value["hops"] = []any{hop} },
		"nine hops": func(value map[string]any) {
			value["hops"] = []any{hop, hop, hop, hop, hop, hop, hop, hop, hop}
		},
		"unknown hop field": func(value map[string]any) {
			value["hops"] = []any{map[string]any{
				"transitionEnvelope": "e30=", "nextAuthoritySpkiPem": "e30=", "unknown": true,
			}, hop}
		},
		"invalid envelope base64": func(value map[string]any) {
			value["hops"] = []any{map[string]any{
				"transitionEnvelope": "***=", "nextAuthoritySpkiPem": "e30=",
			}, hop}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneJSONMap(t, chain)
			mutate(candidate)
			assertSchemaRejects(t, schema, candidate, name)
		})
	}
}
