package sourcequalification

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestSourceQualificationWorkflowContract(t *testing.T) {
	root := workflowRepositoryRoot(t)
	path := filepath.Join(root, ".github", "workflows", "source-qualification.yml")
	raw := readWorkflowContractFile(t, path)
	source := strings.ReplaceAll(string(raw), "\r\n", "\n")

	wantJobs := []string{
		"accept",
		"aggregate",
		"context",
		"linux",
		"replay-linux",
		"replay-windows",
		"windows",
	}
	if got := workflowTopLevelMappingKeys(t, source, "jobs"); !reflect.DeepEqual(got, wantJobs) {
		t.Fatalf("workflow jobs = %q, want exact source-qualification jobs %q", got, wantJobs)
	}

	wantPermissions := map[string]string{"actions": "read", "contents": "read"}
	if got := workflowTopLevelScalarMap(t, source, "permissions"); !reflect.DeepEqual(got, wantPermissions) {
		t.Fatalf("workflow permissions = %#v, want exact read-only permissions %#v", got, wantPermissions)
	}

	requireWorkflowFragments(t, source, []string{
		"fetch-depth: 0",
		"persist-credentials: false",
		"source-qualification-linux-amd64-",
		"source-qualification-windows-amd64-",
		"source-qualification-controller-linux-amd64-",
		"source-qualification-controller-windows-amd64-",
		"source-qualification-aggregate-",
		"source-qualification-tools-",
		"source-qualification-attempt-",
		"if-no-files-found: error",
		"overwrite: false",
		"compression-level: 0",
		"retention-days: 90",
		"artifact-ids:",
		"verify-subject",
		"--workflow-run-attempt",
		"--expected-package-digest",
		"--expected-tool-manifest-digest",
		"--expected-executable-digest",
		"github.run_attempt",
	})

	alwaysPattern := regexp.MustCompile(`(?m)^\s*if:\s*(?:\$\{\{\s*)?always\(\)(?:\s*\}\})?\s*$`)
	if count := len(alwaysPattern.FindAllString(source, -1)); count < 4 {
		t.Fatalf("workflow has %d if: always() guards, want at least both lane publications, aggregate, and accept", count)
	}

	requirePinnedWorkflowActions(t, source, []string{
		"actions/checkout",
		"actions/download-artifact",
		"actions/setup-go",
		"actions/upload-artifact",
	})
}

func TestPrivateSourceQualificationCLIContract(t *testing.T) {
	root := workflowRepositoryRoot(t)
	directory := filepath.Join(root, "internal", "sourcequalification", "cmd", "repopass-source-qualify")
	mainPath := filepath.Join(directory, "main.go")
	mainSource := readWorkflowContractFile(t, mainPath)
	if !regexp.MustCompile(`(?m)^package main\s*$`).Match(mainSource) {
		t.Fatalf("%s must remain a private package main", filepath.ToSlash(mainPath))
	}

	literals := workflowGoStringLiterals(t, directory)
	for _, value := range []string{
		"produce-lane",
		"assemble",
		"assemble-tools",
		"verify-integrity",
		"verify-subject",
		"validate-schema-json",
		"version",
		"--repo-root",
		"--lane",
		"--event",
		"--expected-ref",
		"--expected-base-revision",
		"--expected-tested-revision",
		"--expected-tree",
		"--expected-qualification-run-id",
		"--workflow-run-id",
		"--workflow-run-attempt",
		"--private-log-root",
		"--out-dir",
		"--linux-dir",
		"--windows-dir",
		"--package-dir",
		"--linux-controller",
		"--windows-controller",
		"--expected-repository",
		"--expected-package-digest",
		"--tool-manifest",
		"--expected-tool-manifest-digest",
		"--expected-executable-digest",
		"--root",
	} {
		if !literals[value] {
			t.Errorf("private source-qualification CLI is missing exact command/flag literal %q", value)
		}
	}

	for _, forbidden := range []string{
		"--command",
		"--registry",
		"--receipt",
		"--status",
		"--platform",
		"--archive-inventory",
	} {
		if literals[forbidden] {
			t.Errorf("private source-qualification CLI exposes forbidden caller-selected input %q", forbidden)
		}
	}
}

func workflowRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(directory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve repository root from %s: %v", directory, err)
	}
	return root
}

func readWorkflowContractFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("required source contract %s: %v", filepath.ToSlash(path), err)
	}
	return raw
}

func workflowTopLevelMappingKeys(t *testing.T, source, section string) []string {
	t.Helper()
	values := workflowTopLevelScalarMap(t, source, section)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func workflowTopLevelScalarMap(t *testing.T, source, section string) map[string]string {
	t.Helper()
	lines := strings.Split(source, "\n")
	start := -1
	for index, line := range lines {
		if line == section+":" {
			start = index + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("workflow is missing top-level %s mapping", section)
	}
	result := map[string]string{}
	entryPattern := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):(?:\s*(.*))$`)
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' {
			break
		}
		match := entryPattern.FindStringSubmatch(line)
		if match != nil {
			result[match[1]] = strings.TrimSpace(strings.SplitN(match[2], "#", 2)[0])
		}
	}
	return result
}

func requireWorkflowFragments(t *testing.T, source string, fragments []string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(source, fragment) {
			t.Errorf("source-qualification workflow is missing contract fragment %q", fragment)
		}
	}
}

func requirePinnedWorkflowActions(t *testing.T, source string, required []string) {
	t.Helper()
	usesPattern := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*([^\s#]+)`)
	pinPattern := regexp.MustCompile(`^([^@]+)@([0-9a-f]{40})$`)
	found := map[string]bool{}
	for _, match := range usesPattern.FindAllStringSubmatch(source, -1) {
		pinned := pinPattern.FindStringSubmatch(match[1])
		if pinned == nil {
			t.Errorf("workflow action is not pinned to one lowercase 40-hex commit: %q", match[1])
			continue
		}
		found[pinned[1]] = true
	}
	for _, action := range required {
		if !found[action] {
			t.Errorf("workflow does not use required pinned action %s", action)
		}
	}
}

func workflowGoStringLiterals(t *testing.T, directory string) map[string]bool {
	t.Helper()
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, directory, func(info os.FileInfo) bool {
		return strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse private source-qualification CLI: %v", err)
	}
	values := map[string]bool{}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err == nil {
					values[value] = true
				}
				return true
			})
		}
	}
	return values
}
