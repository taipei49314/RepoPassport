package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/atomicfile"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"gopkg.in/yaml.v3"
)

type ProvenanceRecord struct {
	Field      string                 `json:"field"`
	Value      any                    `json:"value"`
	Source     string                 `json:"source"`
	Method     string                 `json:"method"`
	Confidence float64                `json:"confidence"`
	Status     domain.DetectionStatus `json:"status"`
}

func Candidate(project domain.ProjectDescriptor, projectName string) (Manifest, []ProvenanceRecord) {
	projectName = normalizeName(projectName)
	adapter := "node"
	runtimeVersion := "22.0.0"
	image := "docker.io/library/node:22-bookworm-slim"
	environmentName := "linux-node"
	command := []string{"node", "index.js"}
	for _, language := range project.Languages {
		if language == "python" {
			adapter = "python"
			runtimeVersion = "3.12.0"
			image = "docker.io/library/python:3.12-slim"
			environmentName = "linux-python"
			command = []string{"python", "app.py"}
			break
		}
	}
	var commandSource string
	var commandConfidence float64 = 0.35
	for _, signal := range project.Signals {
		if signal.Field == "entrypoint" {
			if argv, ok := stringSlice(signal.Value); ok && len(argv) > 0 {
				command = argv
				commandSource = signal.Source
				commandConfidence = signal.Confidence
				break
			}
		}
	}
	if commandSource == "" {
		commandSource = "static adapter fallback; maintainer confirmation required"
	}

	scenario := ScenarioSpec{
		Title:       "Quickstart candidate",
		Description: "Inferred verification candidate. Review every command and pin the base image before planning.",
		Environment: environmentName,
		Phases: PhaseSet{
			Exercise: &ExercisePhase{
				Timeout: "1m",
				Driver: DriverSpec{
					Type:    "cli",
					Command: command,
					Assertions: []DriverAssertion{
						{ExitCode: intPointer(0)},
					},
				},
			},
		},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseExercise: {
				Network: domain.NetworkCapability{Deny: true},
				Filesystem: domain.FilesystemCapability{
					Read:  []string{"/workspace/**", "/inputs/**"},
					Write: []string{"/outputs/**"},
				},
			},
		},
		Verification: VerificationSpec{
			Repeats:          1,
			SuccessThreshold: 1,
			RequiredObservers: []string{
				"network-enforcement",
				"filesystem-write",
				"resource-usage",
			},
			Cleanup: CleanupSpec{AllowedResidue: []string{"/outputs/**"}},
		},
	}
	manifest := Manifest{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata: Metadata{
			Name:        projectName,
			DisplayName: displayName(projectName),
			Description: "RepoPassport candidate generated from static repository signals.",
		},
		Spec: Spec{
			Project: ProjectSpec{
				Kind:        project.ProjectKind,
				Audiences:   []string{"developer"},
				Entrypoints: []string{"quickstart"},
			},
			Environments: map[string]EnvironmentSpec{
				environmentName: {
					Platform:  PlatformSpec{OS: "linux", Architecture: "amd64"},
					Runtime:   RuntimeSpec{Adapter: adapter, Version: runtimeVersion},
					BaseImage: BaseImageSpec{Reference: image},
					Resources: ResourceSpec{CPU: 1, Memory: "512MiB", Disk: "1GiB", PIDs: 128},
				},
			},
			Scenarios: map[string]ScenarioSpec{"quickstart": scenario},
			Policies:  PolicySpec{Profile: "baseline-v1"},
			Evidence: EvidenceSpec{
				Profile: "minimal-public",
				Include: []string{"verification-summary", "normalized-observations"},
				Exclude: []string{"raw-stdout", "raw-stderr", "raw-syscall-trace"},
			},
		},
	}
	provenance := []ProvenanceRecord{
		{
			Field: "spec.environments." + environmentName + ".runtime.adapter", Value: adapter,
			Source: "static language detection", Method: adapter + "-static-adapter",
			Confidence: 0.98, Status: domain.StatusInferred,
		},
		{
			Field: "spec.scenarios.quickstart.phases.exercise.driver.command", Value: command,
			Source: commandSource, Method: adapter + "-static-adapter",
			Confidence: commandConfidence, Status: domain.StatusInferred,
		},
		{
			Field: "spec.environments." + environmentName + ".baseImage.reference", Value: image,
			Source: "authoring default; mutable and not verification-ready", Method: "repopass-init",
			Confidence: 0.2, Status: domain.StatusInferred,
		},
	}
	return manifest, provenance
}

func WriteCandidate(root string, candidate Manifest, provenance []ProvenanceRecord, overwrite bool) (string, string, error) {
	secureRoot, err := secureInitDirectory(root, false)
	if err != nil {
		return "", "", err
	}
	manifestPath := filepath.Join(secureRoot, "repo-passport.yml")
	provenanceDir := filepath.Join(secureRoot, ".repopass")
	provenancePath := filepath.Join(provenanceDir, "init-provenance.json")
	if !overwrite {
		if _, err := os.Lstat(manifestPath); err == nil {
			return "", "", domain.NewError(domain.CodeManifestInvalid, domain.SeverityHigh, "repo-passport.yml already exists.")
		} else if !os.IsNotExist(err) {
			return "", "", domain.WrapError(domain.CodeInternal, domain.SeverityHigh, "Candidate destination could not be inspected.", err)
		}
	}
	data, err := yaml.Marshal(candidate)
	if err != nil {
		return "", "", domain.WrapError(domain.CodeInternal, domain.SeverityHigh, "Candidate manifest could not be encoded.", err)
	}
	provenanceData, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return "", "", domain.WrapError(domain.CodeInternal, domain.SeverityHigh, "Provenance could not be encoded.", err)
	}
	provenanceData = append(provenanceData, '\n')
	if _, err := secureInitDirectory(provenanceDir, true); err != nil {
		return "", "", err
	}
	if err := atomicfile.Write(provenancePath, provenanceData, 0o600); err != nil {
		return "", "", domain.WrapError(domain.CodeInternal, domain.SeverityHigh, "Provenance could not be written.", err)
	}
	if err := atomicfile.Write(manifestPath, data, 0o644); err != nil {
		return "", "", domain.WrapError(domain.CodeInternal, domain.SeverityHigh, "Candidate manifest could not be written.", err)
	}
	return manifestPath, provenancePath, nil
}

func secureInitDirectory(value string, create bool) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	if create {
		if err := os.Mkdir(absolute, 0o700); err != nil && !os.IsExist(err) {
			return "", domain.WrapError(domain.CodeInternal, domain.SeverityHigh, "Provenance directory could not be created.", err)
		}
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", domain.WrapError(domain.CodeSourceNotFound, domain.SeverityHigh, "Initialization directory could not be opened.", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", domain.NewError(domain.CodeSourceSymlinkEscape, domain.SeverityCritical, "Initialization directory may not be a symlink or reparse point.")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameInitPath(absolute, resolved) {
		return "", domain.WrapError(domain.CodeSourceSymlinkEscape, domain.SeverityCritical, "Initialization directory resolved through a symlink or reparse point.", err)
	}
	return resolved, nil
}

func sameInitPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func normalizeName(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	lastDash := false
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if valid {
			builder.WriteRune(character)
			lastDash = false
		} else if !lastDash && builder.Len() > 0 {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "repository"
	}
	if len(result) > 63 {
		result = strings.TrimRight(result[:63], "-")
	}
	return result
}

func displayName(value string) string {
	parts := strings.Split(value, "-")
	for index, part := range parts {
		if part == "" {
			continue
		}
		parts[index] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func stringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...), true
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}

func intPointer(value int) *int { return &value }

func CandidateWarning() string {
	return fmt.Sprintf("Generated fields are %s only; pin the base image digest and review commands before planning.", domain.StatusInferred)
}
