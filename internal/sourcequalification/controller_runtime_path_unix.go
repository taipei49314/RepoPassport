//go:build !windows

package sourcequalification

func canonicalTrustedRuntimePathPlatform(string) (string, error) {
	return "", errGateInvalidInput
}
