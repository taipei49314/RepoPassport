// The private controller CLI is expected to expose:
//
//	func run(args []string, stdout, stderr io.Writer) int
//
// All public output is one bounded canonical JSONL record. Flag parser text,
// filesystem paths, and underlying errors are never public diagnostics.
package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

const (
	cliNotApplicable = "NOT_APPLICABLE"
	cliControllerID  = "repopass-source-qualify"
	cliSchemaGateID  = "RP-M0-QUAL-SCHEMA-JSON"
)

func TestRunRejectsInvalidCommandsAndFlagsWithOneFixedPrivateRecord(t *testing.T) {
	private := filepath.Join(t.TempDir(), "private-user", "secret-token-value")
	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown command", []string{"unknown-command-" + private}},
		{"version unknown flag", []string{"version", "--private-path", private}},
		{"version help flag", []string{"version", "--help"}},
		{"version positional input", []string{"version", private}},
		{"schema missing root", []string{"validate-schema-json"}},
		{"schema unknown flag", []string{"validate-schema-json", "--unknown", private}},
		{"schema positional input", []string{"validate-schema-json", private}},
		{"produce lane forbidden command flag", []string{"produce-lane", "--command", private}},
		{"assemble forbidden registry flag", []string{"assemble", "--registry", private}},
		{"assemble tools forbidden receipt flag", []string{"assemble-tools", "--receipt", private}},
		{"verify integrity forbidden status flag", []string{"verify-integrity", "--status", private}},
		{"verify subject forbidden platform flag", []string{"verify-subject", "--platform", private}},
	}
	want := cliExpectedRecord(
		"SOURCE_QUAL_INVALID_INPUT",
		cliControllerID,
		"FAIL",
	)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := cliRun(test.args)
			if exitCode == 0 {
				t.Fatal("run accepted invalid controller input")
			}
			cliAssertRecord(t, stdout, stderr, want)
			cliAssertPrivate(t, stdout, private, "unknown-command", "private-path", "flag provided", "Usage of", "secret-token-value")
		})
	}
}

func TestRunVersionPositiveAndNegative(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		exitCode, stdout, stderr := cliRun([]string{"version"})
		if exitCode != 0 {
			t.Fatalf("version exit code = %d, want 0", exitCode)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
			"SOURCE_QUAL_OK",
			cliControllerID,
			"PASS",
		))
	})

	t.Run("negative", func(t *testing.T) {
		private := filepath.Join(t.TempDir(), "version-private-value")
		exitCode, stdout, stderr := cliRun([]string{"version", "--unknown=" + private})
		if exitCode == 0 {
			t.Fatal("version accepted an unknown flag")
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
			"SOURCE_QUAL_INVALID_INPUT",
			cliControllerID,
			"FAIL",
		))
		cliAssertPrivate(t, stdout, private, "unknown", "flag provided")
	})
}

func TestRunValidateSchemaJSONPositiveAndNegative(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		root := t.TempDir()
		cliWriteJSON(t, root, "schemas/example.schema.json", []byte(`{"type":"object"}`))
		cliWriteJSON(t, root, "testdata/fixtures/example.json", []byte(`{"status":"healthy"}`))

		exitCode, stdout, stderr := cliRun([]string{"validate-schema-json", "--root", root})
		if exitCode != 0 {
			t.Fatalf("validate-schema-json exit code = %d, want 0", exitCode)
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
			"SOURCE_QUAL_OK",
			cliSchemaGateID,
			"PASS",
		))
		cliAssertPrivate(t, stdout, root)
	})

	t.Run("invalid document", func(t *testing.T) {
		root := t.TempDir()
		cliWriteJSON(t, root, "schemas/private.schema.json", []byte(`{"type":"object","type":"array"}`))

		exitCode, stdout, stderr := cliRun([]string{"validate-schema-json", "--root", root})
		if exitCode == 0 {
			t.Fatal("validate-schema-json accepted duplicate JSON keys")
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
			"SOURCE_QUAL_MANIFEST_INVALID",
			cliSchemaGateID,
			"FAIL",
		))
		cliAssertPrivate(t, stdout, root, "private.schema.json", "duplicate")
	})

	t.Run("invalid root", func(t *testing.T) {
		private := filepath.Join(t.TempDir(), "missing-private-root")
		exitCode, stdout, stderr := cliRun([]string{"validate-schema-json", "--root", private})
		if exitCode == 0 {
			t.Fatal("validate-schema-json accepted an unavailable root")
		}
		cliAssertRecord(t, stdout, stderr, cliExpectedRecord(
			"SOURCE_QUAL_MANIFEST_INVALID",
			cliSchemaGateID,
			"FAIL",
		))
		cliAssertPrivate(t, stdout, private, "missing-private-root", "unavailable")
	})
}

func TestRunReturnsNonzeroWhenCanonicalOutputFails(t *testing.T) {
	var stderr bytes.Buffer
	if exitCode := run([]string{"version"}, cliFailWriter{}, &stderr); exitCode == 0 {
		t.Fatal("run returned success after its public output failed")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must remain empty after output failure, got %q", stderr.Bytes())
	}
}

func cliRun(args []string) (int, []byte, []byte) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(args, &stdout, &stderr)
	return exitCode, bytes.Clone(stdout.Bytes()), bytes.Clone(stderr.Bytes())
}

func cliExpectedRecord(code, id, status string) map[string]any {
	return map[string]any{
		"code":                code,
		"id":                  id,
		"qualificationStatus": status,
		"sha256":              cliNotApplicable,
		"testedRevision":      cliNotApplicable,
		"treeSHA":             cliNotApplicable,
	}
}

func cliAssertRecord(t *testing.T, stdout, stderr []byte, expected map[string]any) {
	t.Helper()
	if len(stderr) != 0 {
		t.Fatalf("stderr must be empty, got %q", stderr)
	}
	if len(stdout) == 0 || len(stdout) > 4096 {
		t.Fatalf("stdout JSONL length = %d, want 1..4096", len(stdout))
	}
	if stdout[len(stdout)-1] != '\n' || bytes.Count(stdout, []byte{'\n'}) != 1 || bytes.Contains(stdout, []byte{'\r'}) {
		t.Fatalf("stdout is not exactly one LF-terminated JSONL record: %q", stdout)
	}
	canonical, err := canonicaljson.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	want := append(canonical, '\n')
	if !bytes.Equal(stdout, want) {
		t.Fatalf("stdout record mismatch\n got: %s want: %s", stdout, want)
	}
}

func cliAssertPrivate(t *testing.T, stdout []byte, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && strings.Contains(string(stdout), value) {
			t.Fatalf("stdout disclosed forbidden input or raw diagnostic %q", value)
		}
	}
}

func cliWriteJSON(t *testing.T, root, relative string, raw []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

type cliFailWriter struct{}

func (cliFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("private output failure")
}

var _ io.Writer = cliFailWriter{}
