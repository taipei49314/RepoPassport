package sourcequalification

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const (
	gateExecutorNetworkHelperEnvironment = "REPOPASS_GATE_EXECUTOR_NETWORK_HELPER"
	gateExecutorNetworkTargetEnvironment = "REPOPASS_GATE_EXECUTOR_NETWORK_TARGET"
)

func skipIfHostLoopbackUnavailable(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("host loopback listen is unavailable: %v", err)
	}
	_ = listener.Close()
}

func TestOSGateExecutorEnforcesNetworkNoneOrBlocksBeforeInvocation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("host loopback listen is unavailable: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()

	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	environment := []string{
		gateExecutorNetworkHelperEnvironment + "=1",
		gateExecutorNetworkTargetEnvironment + "=" + listener.Addr().String(),
	}
	if runtime.GOOS == "windows" {
		environment = append(environment,
			"SYSTEMROOT="+os.Getenv("SYSTEMROOT"),
			"WINDIR="+os.Getenv("WINDIR"),
		)
	}
	result, executeErr := newOSGateExecutor().Execute(context.Background(), gateProcessRequest{
		Application: executable,
		Args:        []string{"-test.run=^TestOSGateExecutorNetworkHelperProcess$"},
		Dir:         t.TempDir(),
		Env:         environment,
		Network:     NetworkNone,
		Timeout:     5 * time.Second,
		StdoutLimit: 1024,
		StderrLimit: 1024,
	})

	if result.Blocked {
		if executeErr == nil || result.ExitCode != nil {
			t.Fatalf("blocked network isolation result = %#v, err=%v", result, executeErr)
		}
	} else {
		if executeErr != nil || result.ExitCode == nil || *result.ExitCode != 0 ||
			result.TimedOut || result.Cancelled || result.CleanupFailed {
			t.Fatalf("network-isolated result = %#v, err=%v", result, executeErr)
		}
	}

	select {
	case <-accepted:
		t.Fatal("NetworkNone gate reached a host listener")
	case <-time.After(250 * time.Millisecond):
	}
}

func TestOSGateExecutorNetworkHelperProcess(t *testing.T) {
	if os.Getenv(gateExecutorNetworkHelperEnvironment) == "" {
		return
	}
	connection, err := net.DialTimeout("tcp", os.Getenv(gateExecutorNetworkTargetEnvironment), 500*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		os.Exit(51)
	}
	os.Exit(0)
}
