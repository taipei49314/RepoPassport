package execution

import (
	"strings"
	"testing"
)

func TestOutputPermissionRepairUsesBoundedDirectoryFDTraversal(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		required   []string
		prohibited []string
	}{
		{
			name:   "node",
			script: nodeOutputRepairScript,
			required: []string{
				"MAX_ENTRIES=2048",
				"MAX_DEPTH=64",
				"fchmodSync(fd,0o777)",
				"opendirSync",
				"directory.readSync()",
				"C.O_DIRECTORY",
				"C.O_NOFOLLOW",
				"ctimeNs",
				"mtimeNs",
			},
			prohibited: []string{
				"chmodSync(current",
				"readdirSync",
				"readFileSync",
				`require("node:path")`,
			},
		},
		{
			name:   "python",
			script: pythonOutputRepairScript,
			required: []string{
				"MAX_ENTRIES=2048",
				"MAX_DEPTH=64",
				"os.fchmod(fd,0o777)",
				"os.scandir(fd)",
				"os.O_DIRECTORY",
				"os.O_NOFOLLOW",
				"st_ctime_ns",
				"st_mtime_ns",
			},
			prohibited: []string{
				"os.chmod(",
				"os.listdir(",
				"entry.path",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, required := range test.required {
				if !strings.Contains(test.script, required) {
					t.Errorf("repair helper is missing %q", required)
				}
			}
			for _, prohibited := range test.prohibited {
				if strings.Contains(test.script, prohibited) {
					t.Errorf("repair helper contains prohibited %q", prohibited)
				}
			}
		})
	}
}

func TestOutputPermissionRepairRejectsUnsupportedRuntime(t *testing.T) {
	if args := outputRepairRuntimeArgs("ruby"); args != nil {
		t.Fatalf("unsupported runtime repair args = %#v, want nil", args)
	}
}
