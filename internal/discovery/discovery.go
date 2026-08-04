package discovery

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/repopass/repopass/internal/domain"
)

type packageJSON struct {
	Name         string            `json:"name"`
	Main         string            `json:"main"`
	Bin          any               `json:"bin"`
	Scripts      map[string]string `json:"scripts"`
	Dependencies map[string]string `json:"dependencies"`
	DevDeps      map[string]string `json:"devDependencies"`
	Engines      map[string]string `json:"engines"`
}

func Inspect(ctx context.Context, snapshot domain.SourceSnapshot) (domain.ProjectDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return domain.ProjectDescriptor{}, domain.WrapError(domain.CodeCancelled, domain.SeverityWarning, "Inspection was cancelled.", err)
	}
	files := make(map[string]struct{}, len(snapshot.Inventory))
	for _, entry := range snapshot.Inventory {
		files[entry.Path] = struct{}{}
	}
	result := domain.ProjectDescriptor{
		ProjectKind:  "unknown",
		Languages:    []string{},
		RuntimeHints: []string{},
		Entrypoints:  []string{},
		Signals:      []domain.DetectionSignal{},
	}

	if _, ok := files["package.json"]; ok {
		detectNode(snapshot.Root, files, &result)
	}
	if _, pyproject := files["pyproject.toml"]; pyproject {
		detectPython(snapshot.Root, files, &result)
	} else if _, requirements := files["requirements.txt"]; requirements {
		detectPython(snapshot.Root, files, &result)
	} else if _, app := files["app.py"]; app {
		detectPython(snapshot.Root, files, &result)
	}

	if len(result.Languages) == 0 {
		result.Warnings = append(result.Warnings, "No supported Node.js or Python runtime was inferred.")
	}
	result.Languages = sortedUnique(result.Languages)
	result.RuntimeHints = sortedUnique(result.RuntimeHints)
	result.Entrypoints = sortedUnique(result.Entrypoints)
	sort.Slice(result.Signals, func(i, j int) bool { return result.Signals[i].Field < result.Signals[j].Field })
	return result, nil
}

func detectNode(root string, files map[string]struct{}, result *domain.ProjectDescriptor) {
	data, err := readBounded(filepath.Join(root, "package.json"), 1<<20)
	if err != nil {
		result.Warnings = append(result.Warnings, "package.json could not be read safely: "+err.Error())
		return
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		result.Warnings = append(result.Warnings, "package.json is invalid JSON and was not interpreted.")
		return
	}
	result.Languages = append(result.Languages, "javascript")
	result.RuntimeHints = append(result.RuntimeHints, "node")
	addSignal(result, "languages", "javascript", "package.json", "node-package-adapter", 1)
	addSignal(result, "runtime", "node", "package.json", "node-package-adapter", 1)
	if version := pkg.Engines["node"]; version != "" {
		addSignal(result, "runtimeVersion", version, "package.json#/engines/node", "node-package-adapter", 0.98)
		result.RuntimeHints = append(result.RuntimeHints, "node "+version)
	}
	switch {
	case hasFile(files, "pnpm-lock.yaml"):
		result.PackageManager = "pnpm"
	case hasFile(files, "yarn.lock"):
		result.PackageManager = "yarn"
	case hasFile(files, "package-lock.json"):
		result.PackageManager = "npm"
	default:
		result.PackageManager = "npm"
	}
	addSignal(result, "packageManager", result.PackageManager, "lockfile/package.json", "node-package-adapter", 0.95)

	if main := cleanRelativeCandidate(pkg.Main); main != "" && hasFile(files, main) {
		result.Entrypoints = append(result.Entrypoints, "node "+main)
		addSignal(result, "entrypoint", []string{"node", main}, "package.json#/main", "node-package-adapter", 0.9)
	}
	switch bin := pkg.Bin.(type) {
	case string:
		if candidate := cleanRelativeCandidate(bin); candidate != "" {
			result.Entrypoints = append(result.Entrypoints, "node "+candidate)
			addSignal(result, "entrypoint", []string{"node", candidate}, "package.json#/bin", "node-package-adapter", 0.99)
			result.ProjectKind = "cli"
		}
	case map[string]any:
		for name, raw := range bin {
			if candidate, ok := raw.(string); ok {
				candidate = cleanRelativeCandidate(candidate)
				if candidate != "" {
					result.Entrypoints = append(result.Entrypoints, "node "+candidate)
					addSignal(result, "entrypoint."+name, []string{"node", candidate}, "package.json#/bin/"+name, "node-package-adapter", 0.99)
					result.ProjectKind = "cli"
				}
			}
		}
	}
	if _, ok := pkg.Scripts["start"]; ok {
		addSignal(result, "script.start", pkg.Scripts["start"], "package.json#/scripts/start", "node-package-adapter", 0.8)
		result.Warnings = append(result.Warnings, "The start script is a shell string and was not converted into a verification command.")
		if result.ProjectKind == "unknown" {
			result.ProjectKind = "web-app"
		}
	}
	if hasAnyDependency(pkg, "express", "fastify", "koa", "hono", "next") && result.ProjectKind == "unknown" {
		result.ProjectKind = "web-app"
	}
	if hasFile(files, "tsconfig.json") {
		result.Languages = append(result.Languages, "typescript")
		addSignal(result, "languages", "typescript", "tsconfig.json", "node-package-adapter", 0.99)
	}
}

func detectPython(root string, files map[string]struct{}, result *domain.ProjectDescriptor) {
	result.Languages = append(result.Languages, "python")
	result.RuntimeHints = append(result.RuntimeHints, "python")
	addSignal(result, "languages", "python", "pyproject.toml/requirements.txt", "python-static-adapter", 0.98)
	addSignal(result, "runtime", "python", "pyproject.toml/requirements.txt", "python-static-adapter", 0.98)
	result.PackageManager = "pip"
	if hasFile(files, "poetry.lock") {
		result.PackageManager = "poetry"
	} else if hasFile(files, "uv.lock") {
		result.PackageManager = "uv"
	}
	if hasFile(files, "app.py") {
		result.Entrypoints = append(result.Entrypoints, "python app.py")
		addSignal(result, "entrypoint", []string{"python", "app.py"}, "app.py", "python-static-adapter", 0.75)
	}
	if hasFile(files, "__main__.py") {
		result.Entrypoints = append(result.Entrypoints, "python .")
		addSignal(result, "entrypoint", []string{"python", "."}, "__main__.py", "python-static-adapter", 0.9)
		result.ProjectKind = "cli"
	}
	if hasFile(files, "pyproject.toml") {
		data, err := readBounded(filepath.Join(root, "pyproject.toml"), 1<<20)
		if err == nil {
			text := string(data)
			if regexp.MustCompile(`(?m)^\[project\.scripts\]\s*$`).MatchString(text) {
				result.ProjectKind = "cli"
				addSignal(result, "projectKind", "cli", "pyproject.toml#[project.scripts]", "python-static-adapter", 0.9)
			}
			if strings.Contains(text, "fastapi") || strings.Contains(text, "flask") || strings.Contains(text, "django") {
				if result.ProjectKind == "unknown" {
					result.ProjectKind = "web-app"
				}
			}
			if match := regexp.MustCompile(`(?m)^requires-python\s*=\s*"([^"]+)"`).FindStringSubmatch(text); len(match) == 2 {
				addSignal(result, "runtimeVersion", match[1], "pyproject.toml#/project/requires-python", "python-static-adapter", 0.95)
			}
		}
	}
	if result.ProjectKind == "unknown" {
		result.ProjectKind = "cli"
	}
}

func addSignal(result *domain.ProjectDescriptor, field string, value any, source, method string, confidence float64) {
	result.Signals = append(result.Signals, domain.DetectionSignal{
		Field: field, Value: value, Source: source, Method: method,
		Confidence: confidence, Status: domain.StatusInferred,
	})
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, domain.NewError(domain.CodeSourceTooLarge, domain.SeverityHigh, "Metadata file exceeds the inspection limit.")
	}
	data := make([]byte, info.Size())
	_, err = io.ReadFull(file, data)
	return data, err
}

func cleanRelativeCandidate(value string) string {
	value = filepath.ToSlash(filepath.Clean(value))
	value = strings.TrimPrefix(value, "./")
	if value == "." || value == "" || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return ""
	}
	return value
}

func hasFile(files map[string]struct{}, name string) bool {
	_, ok := files[name]
	return ok
}

func hasAnyDependency(pkg packageJSON, names ...string) bool {
	for _, name := range names {
		if _, ok := pkg.Dependencies[name]; ok {
			return true
		}
		if _, ok := pkg.DevDeps[name]; ok {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
