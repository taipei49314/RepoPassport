package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestInspectNodeDoesNotExecuteScriptsOrEntrypoints(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "package.json", `{
  "name": "no-execution",
  "main": "should-not-run.mjs",
  "scripts": {
    "start": "node should-not-run.mjs"
  },
  "engines": {
    "node": ">=22 <23"
  }
}`)
	writeDiscoveryFile(
		t,
		root,
		"should-not-run.mjs",
		`import { writeFileSync } from "node:fs"; writeFileSync("sentinel", "executed");`,
	)

	snapshot := domain.SourceSnapshot{
		Root: root,
		Inventory: []domain.FileEntry{
			{Path: "package.json"},
			{Path: "should-not-run.mjs"},
		},
	}
	descriptor, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sentinel")); !os.IsNotExist(err) {
		t.Fatalf("inspection executed repository code; sentinel stat error = %v", err)
	}
	if !containsString(descriptor.Languages, "javascript") || !containsString(descriptor.RuntimeHints, "node") {
		t.Fatalf("unexpected Node descriptor: %#v", descriptor)
	}
	if !warningsContain(descriptor.Warnings, "was not converted into a verification command") {
		t.Fatalf("start-script warning missing: %#v", descriptor.Warnings)
	}
}

func TestInspectPythonDoesNotImportModulesOrRunSetup(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "pyproject.toml", `[project]
name = "no-execution"
version = "1.0.0"
requires-python = ">=3.12,<3.13"
dependencies = []
`)
	writeDiscoveryFile(t, root, "app.py", `open("sentinel-app", "w").write("executed")`)
	writeDiscoveryFile(t, root, "setup.py", `open("sentinel-setup", "w").write("executed")`)

	snapshot := domain.SourceSnapshot{
		Root: root,
		Inventory: []domain.FileEntry{
			{Path: "app.py"},
			{Path: "pyproject.toml"},
			{Path: "setup.py"},
		},
	}
	descriptor, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	for _, name := range []string{"sentinel-app", "sentinel-setup"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("inspection executed Python repository code %q; stat error = %v", name, err)
		}
	}
	if !containsString(descriptor.Languages, "python") || !containsString(descriptor.RuntimeHints, "python") {
		t.Fatalf("unexpected Python descriptor: %#v", descriptor)
	}
}

func TestInspectNodeBinIdentifiesCLIEntrypoint(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "package.json", `{
  "name": "static-cli",
  "bin": {
    "static-cli": "cli.mjs"
  }
}`)
	writeDiscoveryFile(t, root, "cli.mjs", `process.stdout.write("ok\n");`)

	snapshot := domain.SourceSnapshot{
		Root: root,
		Inventory: []domain.FileEntry{
			{Path: "cli.mjs"},
			{Path: "package.json"},
		},
	}
	descriptor, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if descriptor.ProjectKind != "cli" {
		t.Fatalf("project kind = %q, want cli", descriptor.ProjectKind)
	}
	if !containsString(descriptor.Entrypoints, "node cli.mjs") {
		t.Fatalf("CLI entrypoint missing: %#v", descriptor.Entrypoints)
	}
}

func writeDiscoveryFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create parent for %s: %v", relative, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func warningsContain(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}
