package execution

import (
	"fmt"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

// FeatureNegotiation separates hard execution requirements from observer
// coverage. Incomplete observer coverage is explicit and must be consumed by
// the verifier; it is never silently represented as full support.
type FeatureNegotiation struct {
	Incomplete []string `json:"incomplete,omitempty"`
}

func NegotiateFeatures(
	required []string,
	features domain.RunnerFeatures,
) (FeatureNegotiation, error) {
	result := FeatureNegotiation{}
	for _, raw := range required {
		feature := strings.ToLower(strings.TrimSpace(raw))
		if feature == "" {
			continue
		}
		switch feature {
		case "linux-container":
			if !features.Available || features.WorkloadOS != "linux" {
				return result, unavailableFeature(feature)
			}
		case "platform:linux/amd64", "platform:linux/arm64":
			if !features.Available || features.WorkloadOS != "linux" {
				return result, unavailableFeature(feature)
			}
		case "read-only-source",
			"isolated-workspace",
			"bounded-logs",
			"process-cleanup",
			"process-tree-cleanup",
			"cleanup-residue-classification",
			"read-only-root",
			"non-root",
			"background-service",
			"service-signal",
			"loopback-http-driver":
			if !features.Available {
				return result, unavailableFeature(feature)
			}
		case "network-deny", "network-enforcement":
			if !features.NetworkDeny {
				return result, unavailableFeature(feature)
			}
		case "setup-egress-allowlist":
			return result, unavailableFeature(feature)
		case "process-exec-observation":
			if !coverageIsFull(features.ProcessExecObservation) {
				result.Incomplete = appendUnique(result.Incomplete, feature)
			}
		case "filesystem-write-observation":
			if !filesystemCoverageIsAdequate(
				features.FilesystemWriteObservation,
			) {
				result.Incomplete = appendUnique(result.Incomplete, feature)
			}
		case "port-listen-observation":
			if !coverageIsFull(features.PortObservation) {
				result.Incomplete = appendUnique(result.Incomplete, feature)
			}
		case "resource-usage-observation":
			if !resourceCoverageIsAdequate(features.ResourceUsage) {
				result.Incomplete = appendUnique(result.Incomplete, feature)
			}
		default:
			switch {
			case strings.HasPrefix(feature, "network-allowlist:"):
				return result, unavailableFeature(feature)
			case strings.HasPrefix(feature, "observer:"):
				observer := strings.TrimPrefix(feature, "observer:")
				if observerIncomplete(observer, features) {
					result.Incomplete = appendUnique(result.Incomplete, feature)
					continue
				}
				if observer == "network-enforcement" && features.NetworkDeny {
					continue
				}
				if observer == "filesystem-write" &&
					filesystemCoverageIsAdequate(
						features.FilesystemWriteObservation,
					) {
					continue
				}
				if observer == "resource-usage" &&
					resourceCoverageIsAdequate(features.ResourceUsage) {
					continue
				}
				return result, unavailableFeature(feature)
			default:
				return result, unavailableFeature(feature)
			}
		}
	}
	return result, nil
}

func observerIncomplete(observer string, features domain.RunnerFeatures) bool {
	switch observer {
	case "process-exec":
		return !coverageIsFull(features.ProcessExecObservation)
	case "filesystem-write":
		return !filesystemCoverageIsAdequate(
			features.FilesystemWriteObservation,
		)
	case "port-listen":
		return !coverageIsFull(features.PortObservation)
	case "resource-usage":
		return !resourceCoverageIsAdequate(features.ResourceUsage)
	default:
		return false
	}
}

func coverageIsFull(value string) bool {
	return strings.EqualFold(value, coverageFull)
}

func resourceCoverageIsAdequate(value string) bool {
	return coverageIsFull(value) ||
		strings.EqualFold(value, "high")
}

func filesystemCoverageIsAdequate(value string) bool {
	return coverageIsFull(value) ||
		strings.EqualFold(value, "high")
}

func unavailableFeature(feature string) error {
	err := domain.NewError(
		domain.CodeRunnerFeatureUnavailable,
		domain.SeverityHigh,
		fmt.Sprintf("Runner feature %q is unavailable.", feature),
	)
	err.Details = map[string]any{"feature": feature}
	return err
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
