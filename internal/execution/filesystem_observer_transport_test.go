package execution

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/repopass/repopass/internal/domain"
)

func TestCollectFilesystemSnapshotUsesExactTrustedArgv(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	tests := []struct {
		adapter string
		tail    []string
	}{
		{
			adapter: "node",
			tail:    []string{"node", "-e", nodeFilesystemSnapshotScript},
		},
		{
			adapter: "python",
			tail: []string{
				"python",
				"-I",
				"-S",
				"-c",
				pythonFilesystemSnapshotScript,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.adapter, func(t *testing.T) {
			fake := &fakeExecutor{}
			fake.handler = func(
				_ context.Context,
				name string,
				args []string,
				stdout io.Writer,
				_ io.Writer,
			) (int, error) {
				if name != "docker" {
					t.Fatalf("backend executable = %q, want docker", name)
				}
				prefix := []string{
					"exec",
					"--user",
					"0:0",
					"--workdir",
					trustedHelperWorkdir,
					containerID,
				}
				if len(args) != len(prefix)+len(test.tail) ||
					!slices.Equal(args[:len(prefix)], prefix) ||
					!slices.Equal(args[len(prefix):], test.tail) {
					t.Fatalf("filesystem helper argv = %#v", args)
				}
				_, _ = io.WriteString(
					stdout,
					`{"ok":true,"entries":[]}`+"\n",
				)
				return 0, nil
			}
			prepared := &PreparedRun{
				Backend: "docker",
				executionPlan: domain.ResolvedPlan{
					RuntimeAdapter: test.adapter,
				},
			}
			snapshot, err := testRunner(fake).collectFilesystemSnapshot(
				context.Background(),
				prepared,
				containerID,
			)
			if err != nil {
				t.Fatalf("collectFilesystemSnapshot: %v", err)
			}
			if len(snapshot.Entries) != 0 ||
				!filesystemDigestPattern.MatchString(snapshot.Digest) {
				t.Fatalf("filesystem snapshot = %#v", snapshot)
			}
			if calls := fake.snapshotCalls(); len(calls) != 1 {
				t.Fatalf("filesystem helper calls = %#v", calls)
			}
		})
	}
}

func TestCollectFilesystemSnapshotRejectsDirtyTransport(t *testing.T) {
	containerID := strings.Repeat("b", 64)
	fake := &fakeExecutor{}
	fake.handler = func(
		_ context.Context,
		_ string,
		_ []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		_, _ = io.WriteString(stdout, `{"ok":true,"entries":[]}`+"\n")
		_, _ = io.WriteString(stderr, "unexpected helper stderr")
		return 0, nil
	}
	prepared := &PreparedRun{
		Backend: "docker",
		executionPlan: domain.ResolvedPlan{
			RuntimeAdapter: "node",
		},
	}
	if _, err := testRunner(fake).collectFilesystemSnapshot(
		context.Background(),
		prepared,
		containerID,
	); err == nil {
		t.Fatal("filesystem helper transport with stderr was accepted")
	}
}

func TestCollectFilesystemSnapshotRejectsUntrustedIdentityAndAdapter(
	t *testing.T,
) {
	fake := &fakeExecutor{}
	runner := testRunner(fake)
	for _, test := range []struct {
		name      string
		adapter   string
		container string
	}{
		{
			name:      "short container id",
			adapter:   "node",
			container: "container-name",
		},
		{
			name:      "unsupported adapter",
			adapter:   "ruby",
			container: strings.Repeat("c", 64),
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			prepared := &PreparedRun{
				Backend: "docker",
				executionPlan: domain.ResolvedPlan{
					RuntimeAdapter: test.adapter,
				},
			}
			if _, err := runner.collectFilesystemSnapshot(
				context.Background(),
				prepared,
				test.container,
			); err == nil {
				t.Fatal("untrusted filesystem helper binding was accepted")
			}
		})
	}
	if calls := fake.snapshotCalls(); len(calls) != 0 {
		t.Fatalf("invalid helper binding reached executor: %#v", calls)
	}
}
