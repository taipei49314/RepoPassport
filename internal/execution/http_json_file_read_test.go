package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

func TestReadHTTPOutputJSONFileAcceptsVerifiedBoundedPayload(t *testing.T) {
	content := []byte(`{"answer":42}`)
	control := validHTTPJSONFileReadControl(content)

	for _, adapter := range []string{"node", "python"} {
		t.Run(adapter, func(t *testing.T) {
			fake := &fakeExecutor{}
			fake.handler = func(
				_ context.Context,
				backend string,
				args []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				if backend != "docker" {
					t.Fatalf("backend = %q, want docker", backend)
				}
				if !containsAdjacent(args, "--user", "0:0") {
					t.Fatalf("trusted helper does not run as root: %v", args)
				}
				if !containsAdjacent(args, "--workdir", trustedHelperWorkdir) {
					t.Fatalf("trusted helper workdir = %v", args)
				}
				if args[0] != "exec" ||
					args[len(args)-1] != "/outputs/result.json" {
					t.Fatalf("unexpected helper lifecycle: %v", args)
				}
				if adapter == "node" {
					if !containsArgument(args, nodeHTTPJSONFileReadScript) {
						t.Fatalf("fixed Node helper was not used: %v", args)
					}
				} else {
					if !containsArgument(args, pythonHTTPJSONFileReadScript) {
						t.Fatalf("fixed Python helper was not used: %v", args)
					}
					assertIsolatedPythonHelper(t, args)
				}
				_, _ = io.WriteString(stdout, control)
				return 0, nil
			}
			runner := testRunner(fake)
			prepared := sealPreparedRunForTest(&PreparedRun{
				Plan: domain.ResolvedPlan{
					RuntimeAdapter: adapter,
				},
				Backend: "docker",
			})

			snapshot, err := runner.readHTTPOutputJSONFile(
				context.Background(),
				prepared,
				"repopass-container",
				"/outputs/result.json",
			)
			if err != nil {
				t.Fatalf("readHTTPOutputJSONFile: %v", err)
			}
			if !bytes.Equal(snapshot.content, content) {
				t.Fatalf("content = %q, want %q", snapshot.content, content)
			}
			if snapshot.size != int64(len(content)) {
				t.Fatalf("size = %d, want %d", snapshot.size, len(content))
			}
			sum := sha256.Sum256(content)
			wantDigest := fmt.Sprintf("sha256:%x", sum[:])
			if snapshot.sha256 != wantDigest {
				t.Fatalf("digest = %q, want %q", snapshot.sha256, wantDigest)
			}
			encoded, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatalf("marshal snapshot: %v", err)
			}
			if string(encoded) != "{}" {
				t.Fatalf("snapshot leaked into evidence JSON: %s", encoded)
			}
		})
	}
}

func TestDecodeHTTPJSONFileReadResponseEnforcesExactOneMiBBoundary(
	t *testing.T,
) {
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{name: "empty", content: []byte{}},
		{
			name: "exact maximum",
			content: bytes.Repeat(
				[]byte("x"),
				int(httpJSONFileMaxBytes),
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := decodeHTTPJSONFileReadResponse(
				[]byte(validHTTPJSONFileReadControl(test.content)),
			)
			if err != nil {
				t.Fatalf("boundary payload was rejected: %v", err)
			}
			if snapshot.size != int64(len(test.content)) ||
				len(snapshot.content) != len(test.content) {
				t.Fatalf(
					"snapshot size = %d/%d, want %d",
					snapshot.size,
					len(snapshot.content),
					len(test.content),
				)
			}
		})
	}

	_, err := decodeHTTPJSONFileReadResponse(
		[]byte(`{"status":"too-large"}`),
	)
	assertHTTPJSONFileReadFailure(t, err, httpJSONFileTooLarge)
}

func TestDecodeHTTPJSONFileReadResponseRejectsUntrustedControl(t *testing.T) {
	content := []byte(`{"secret":"must-not-leak"}`)
	valid := strings.TrimSpace(validHTTPJSONFileReadControl(content))
	sum := sha256.Sum256(content)
	digest := fmt.Sprintf("sha256:%x", sum[:])
	encoded := base64.StdEncoding.EncodeToString(content)

	tests := []struct {
		name    string
		control string
		failure httpJSONFileReadFailure
	}{
		{
			name:    "unknown field",
			control: `{"status":"missing","extra":true}`,
			failure: httpJSONFileInvalidControl,
		},
		{
			name:    "second document",
			control: valid + "\n{}",
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "duplicate field",
			control: `{"status":"missing",` +
				`"status":"too-large"}`,
			failure: httpJSONFileInvalidControl,
		},
		{
			name:    "top level array",
			control: `[]`,
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "missing payload field",
			control: fmt.Sprintf(
				`{"status":"ok","size":%d,"sha256":%q}`,
				len(content),
				digest,
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "null payload",
			control: fmt.Sprintf(
				`{"status":"ok","size":%d,"contentBase64":null,"sha256":%q}`,
				len(content),
				digest,
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "negative size",
			control: fmt.Sprintf(
				`{"status":"ok","size":-1,"contentBase64":"","sha256":%q}`,
				digest,
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "declared size over limit",
			control: fmt.Sprintf(
				`{"status":"ok","size":%d,"contentBase64":"","sha256":%q}`,
				httpJSONFileMaxBytes+1,
				digest,
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "base64 length mismatch",
			control: fmt.Sprintf(
				`{"status":"ok","size":%d,"contentBase64":"","sha256":%q}`,
				len(content),
				digest,
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "invalid base64",
			control: fmt.Sprintf(
				`{"status":"ok","size":3,"contentBase64":"!!!!","sha256":%q}`,
				digest,
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name: "digest mismatch",
			control: fmt.Sprintf(
				`{"status":"ok","size":%d,"contentBase64":%q,"sha256":%q}`,
				len(content),
				encoded,
				"sha256:"+strings.Repeat("0", 64),
			),
			failure: httpJSONFileIntegrity,
		},
		{
			name: "failure carries payload",
			control: fmt.Sprintf(
				`{"status":"missing","size":%d}`,
				len(content),
			),
			failure: httpJSONFileInvalidControl,
		},
		{
			name:    "unknown status",
			control: `{"status":"surprise"}`,
			failure: httpJSONFileInvalidControl,
		},
		{
			name:    "empty control",
			control: "",
			failure: httpJSONFileInvalidControl,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeHTTPJSONFileReadResponse(
				[]byte(test.control),
			)
			assertHTTPJSONFileReadFailure(t, err, test.failure)
			if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatalf("error leaked repository content: %v", err)
			}
		})
	}

	_, err := decodeHTTPJSONFileReadResponse(
		bytes.Repeat(
			[]byte("x"),
			int(httpJSONFileMaxControlBytes)+1,
		),
	)
	assertHTTPJSONFileReadFailure(t, err, httpJSONFileControlLimit)
}

func TestDecodeHTTPJSONFileReadResponseClassifiesHelperStatuses(
	t *testing.T,
) {
	tests := []struct {
		status  string
		failure httpJSONFileReadFailure
	}{
		{status: "missing", failure: httpJSONFileMissing},
		{status: "symlink", failure: httpJSONFileSymlink},
		{status: "directory", failure: httpJSONFileDirectory},
		{status: "special", failure: httpJSONFileSpecial},
		{status: "too-large", failure: httpJSONFileTooLarge},
		{status: "changed", failure: httpJSONFileChanged},
		{status: "error", failure: httpJSONFileHelperExecution},
	}

	for _, test := range tests {
		t.Run(test.status, func(t *testing.T) {
			_, err := decodeHTTPJSONFileReadResponse(
				[]byte(fmt.Sprintf(`{"status":%q}`, test.status)),
			)
			assertHTTPJSONFileReadFailure(t, err, test.failure)
		})
	}
}

func TestReadHTTPOutputJSONFileFailsClosedBeforeOrDuringHelper(
	t *testing.T,
) {
	t.Run("nil prepared run", func(t *testing.T) {
		fake := &fakeExecutor{}
		runner := testRunner(fake)
		_, err := runner.readHTTPOutputJSONFile(
			context.Background(),
			nil,
			"container",
			"/outputs/result.json",
		)
		assertHTTPJSONFileReadFailure(
			t,
			err,
			httpJSONFileHelperExecution,
		)
		if len(fake.snapshotCalls()) != 0 {
			t.Fatal("nil prepared run reached the executor")
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		fake := &fakeExecutor{}
		runner := testRunner(fake)
		_, err := runner.readHTTPOutputJSONFile(
			context.Background(),
			sealPreparedRunForTest(&PreparedRun{
				Plan: domain.ResolvedPlan{RuntimeAdapter: "node"},
			}),
			"container",
			"/outputs/../secret.json",
		)
		assertHTTPJSONFileReadFailure(t, err, httpJSONFileInvalidPath)
		if len(fake.snapshotCalls()) != 0 {
			t.Fatal("unsafe path reached the executor")
		}
	})

	t.Run("unsupported runtime", func(t *testing.T) {
		fake := &fakeExecutor{}
		runner := testRunner(fake)
		_, err := runner.readHTTPOutputJSONFile(
			context.Background(),
			sealPreparedRunForTest(&PreparedRun{
				Plan: domain.ResolvedPlan{RuntimeAdapter: "ruby"},
			}),
			"container",
			"/outputs/result.json",
		)
		assertHTTPJSONFileReadFailure(
			t,
			err,
			httpJSONFileUnsupportedRuntime,
		)
		if len(fake.snapshotCalls()) != 0 {
			t.Fatal("unsupported runtime reached the executor")
		}
	})

	t.Run("nonzero exit", func(t *testing.T) {
		fake := &fakeExecutor{
			handler: func(
				context.Context,
				string,
				[]string,
				io.Writer,
				io.Writer,
			) (int, error) {
				return 9, nil
			},
		}
		_, err := testRunner(fake).readHTTPOutputJSONFile(
			context.Background(),
			nodePreparedRun(),
			"container",
			"/outputs/result.json",
		)
		assertHTTPJSONFileReadFailure(
			t,
			err,
			httpJSONFileHelperExecution,
		)
	})

	t.Run("stderr", func(t *testing.T) {
		fake := &fakeExecutor{
			handler: func(
				_ context.Context,
				_ string,
				_ []string,
				_ io.Writer,
				stderr io.Writer,
			) (int, error) {
				_, _ = io.WriteString(stderr, "untrusted diagnostic")
				return 0, nil
			},
		}
		_, err := testRunner(fake).readHTTPOutputJSONFile(
			context.Background(),
			nodePreparedRun(),
			"container",
			"/outputs/result.json",
		)
		assertHTTPJSONFileReadFailure(
			t,
			err,
			httpJSONFileHelperExecution,
		)
		if strings.Contains(err.Error(), "untrusted diagnostic") {
			t.Fatalf("stderr leaked through trusted error: %v", err)
		}
	})

	t.Run("control truncation", func(t *testing.T) {
		fake := &fakeExecutor{
			handler: func(
				_ context.Context,
				_ string,
				_ []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				_, _ = io.CopyN(
					stdout,
					strings.NewReader(
						strings.Repeat(
							"x",
							int(httpJSONFileMaxControlBytes)+1,
						),
					),
					httpJSONFileMaxControlBytes+1,
				)
				return 0, nil
			},
		}
		_, err := testRunner(fake).readHTTPOutputJSONFile(
			context.Background(),
			nodePreparedRun(),
			"container",
			"/outputs/result.json",
		)
		assertHTTPJSONFileReadFailure(t, err, httpJSONFileControlLimit)
	})

	t.Run("deadline", func(t *testing.T) {
		fake := &fakeExecutor{
			handler: func(
				ctx context.Context,
				_ string,
				_ []string,
				_ io.Writer,
				_ io.Writer,
			) (int, error) {
				return -1, ctx.Err()
			},
		}
		expired, cancel := context.WithDeadline(
			context.Background(),
			time.Now().Add(-time.Second),
		)
		defer cancel()
		_, err := testRunner(fake).readHTTPOutputJSONFile(
			expired,
			nodePreparedRun(),
			"container",
			"/outputs/result.json",
		)
		assertHTTPJSONFileReadFailure(t, err, httpJSONFileHelperTimeout)
	})
}

func TestHTTPJSONFileReadScriptsApplySecureBoundedWalk(t *testing.T) {
	nodeRequirements := []string{
		`require("node:fs")`,
		`require("node:path")`,
		`require("node:crypto")`,
		"O_NOFOLLOW",
		"O_DIRECTORY",
		"O_NONBLOCK",
		"/proc/self/fd/",
		"lstatSync",
		"fstatSync",
		"limit+1",
		`toString("base64")`,
	}
	for _, required := range nodeRequirements {
		if !strings.Contains(nodeHTTPJSONFileReadScript, required) {
			t.Fatalf("Node helper lacks %q", required)
		}
	}

	pythonRequirements := []string{
		"import base64",
		"hashlib",
		"O_NOFOLLOW",
		"O_DIRECTORY",
		"O_NONBLOCK",
		"dir_fd=parent",
		"follow_symlinks=False",
		"os.fstat",
		"LIMIT+1",
		"base64.b64encode",
	}
	for _, required := range pythonRequirements {
		if !strings.Contains(pythonHTTPJSONFileReadScript, required) {
			t.Fatalf("Python helper lacks %q", required)
		}
	}
}

func TestHTTPJSONFileReadFailureWrapping(t *testing.T) {
	cause := errors.New("repository-controlled detail")
	err := newHTTPJSONFileReadError(httpJSONFileIntegrity, cause)
	if !errors.Is(err, cause) {
		t.Fatal("trusted error did not retain its internal cause")
	}
	if strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("trusted error exposed its internal cause: %v", err)
	}
	assertHTTPJSONFileReadFailure(t, err, httpJSONFileIntegrity)
}

func validHTTPJSONFileReadControl(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf(
		`{"status":"ok","size":%d,"contentBase64":%q,"sha256":"sha256:%x"}`+"\n",
		len(content),
		base64.StdEncoding.EncodeToString(content),
		sum[:],
	)
}

func nodePreparedRun() *PreparedRun {
	return sealPreparedRunForTest(&PreparedRun{
		Plan:    domain.ResolvedPlan{RuntimeAdapter: "node"},
		Backend: "docker",
	})
}

func assertHTTPJSONFileReadFailure(
	t *testing.T,
	err error,
	want httpJSONFileReadFailure,
) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	if got := httpJSONFileReadFailureOf(err); got != want {
		t.Fatalf("failure = %q, want %q (error: %v)", got, want, err)
	}
}
