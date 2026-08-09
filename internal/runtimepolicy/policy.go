package runtimepolicy

import (
	"strings"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

const (
	PolicyVersion = "baseline-v1-runtime-images-1"

	NodeReference = "docker.io/library/node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3"
	NodeDigest    = "sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3"
	NodeVersion   = "22.23.1"

	PythonReference = "docker.io/library/python:3.12.13-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
	PythonDigest    = "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
	PythonVersion   = "3.12.13"

	approvedPlatform = "linux/amd64"
)

type BindingEntry struct {
	Adapter   string `json:"adapter"`
	Version   string `json:"version"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	Platform  string `json:"platform"`
}

type approvedRuntime struct {
	adapter   string
	version   string
	reference string
	digest    string
	platform  string
}

var approvedRuntimes = [...]approvedRuntime{
	{
		adapter:   "node",
		version:   NodeVersion,
		reference: NodeReference,
		digest:    NodeDigest,
		platform:  approvedPlatform,
	},
	{
		adapter:   "python",
		version:   PythonVersion,
		reference: PythonReference,
		digest:    PythonDigest,
		platform:  approvedPlatform,
	},
}

func Binding() map[string]any {
	entries := make([]BindingEntry, 0, len(approvedRuntimes))
	for _, approved := range approvedRuntimes {
		entries = append(entries, BindingEntry{
			Adapter:   approved.adapter,
			Version:   approved.version,
			Reference: approved.reference,
			Digest:    approved.digest,
			Platform:  approved.platform,
		})
	}
	return map[string]any{
		"version": PolicyVersion,
		"images":  entries,
	}
}

// Validate enforces the built-in baseline-v1 runtime TCB. Digest pinning alone
// does not make image-provided controller helpers trustworthy, so alpha accepts
// only exact operator-approved tuples.
func Validate(
	adapter string,
	version string,
	reference string,
	digest string,
	platform string,
) *domain.Error {
	normalizedAdapter := strings.ToLower(strings.TrimSpace(adapter))
	for _, approved := range approvedRuntimes {
		if normalizedAdapter == approved.adapter &&
			version == approved.version &&
			reference == approved.reference &&
			digest == approved.digest &&
			platform == approved.platform {
			return nil
		}
	}

	err := domain.NewError(
		domain.CodeRunnerFeatureUnavailable,
		domain.SeverityCritical,
		"Runtime image tuple is not approved by the built-in baseline-v1 execution policy.",
	)
	err.Details = map[string]any{
		"feature":          "operator-approved-runtime-image",
		"runtimeAdapter":   normalizedAdapter,
		"runtimeVersion":   version,
		"imageReference":   reference,
		"imageDigest":      digest,
		"platform":         platform,
		"approvedPlatform": approvedPlatform,
	}
	return err
}
