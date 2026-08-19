//go:build linux

package sourcequalification

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxPid1IsHostInitMatchesProcComm(t *testing.T) {
	t.Parallel()
	comm, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(comm)) == "init" || strings.TrimSpace(string(comm)) == "systemd"
	if got := linuxPid1IsHostInit(); got != want {
		t.Fatalf("linuxPid1IsHostInit() = %v, /proc/1/comm = %q", got, comm)
	}
}

func TestLinuxPrivilegedKillProcessGroupCommand(t *testing.T) {
	t.Parallel()
	if _, _, ok := linuxPrivilegedKillProcessGroupCommand(1); ok {
		t.Fatal("pid 1 process group was accepted")
	}
	if _, _, ok := linuxPrivilegedKillProcessGroupCommand(0); ok {
		t.Fatal("process group 0 was accepted")
	}
	if _, _, ok := linuxPrivilegedKillProcessGroupCommand(-9); ok {
		t.Fatal("negative process group was accepted")
	}
	sudo, args, ok := linuxPrivilegedKillProcessGroupCommand(9562)
	if !ok {
		t.Skip("privileged kill helpers were not trusted")
	}
	if sudo != "/usr/bin/sudo" {
		t.Fatalf("privileged kill launcher = %q, want /usr/bin/sudo", sudo)
	}
	for _, want := range []string{"-n", "--", "-s", "KILL", "--", "-9562"} {
		if !containsExactArg(args, want) {
			t.Fatalf("privileged kill arguments %q missing %q", args, want)
		}
	}
	if !containsExactArg(args, "/usr/bin/kill") && !containsExactArg(args, "/bin/kill") {
		t.Fatalf("privileged kill arguments %q omitted kill", args)
	}
	killIndex := -1
	pgidIndex := -1
	for index, argument := range args {
		if argument == "/usr/bin/kill" || argument == "/bin/kill" {
			killIndex = index
		}
		if argument == "-9562" {
			pgidIndex = index
		}
	}
	if killIndex < 0 || pgidIndex < 2 || args[pgidIndex-1] != "--" {
		t.Fatalf("process group %q was not after kill --: %q", "-9562", args)
	}
}

func TestUnixKillProcessGroupReapsMembers(t *testing.T) {
	command := exec.Command("sleep", "30")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	processGroup := command.Process.Pid
	if err := unixKillProcessGroup(processGroup); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("unixKillProcessGroup: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("sleep did not exit after SIGKILL")
	}
	if !waitUnixGateProcessGroup(processGroup, time.Now().Add(time.Second)) {
		t.Fatal("process group survived SIGKILL")
	}
}

func TestLinuxSelectGateIsolationRefusesInheritedPidNamespaceMarker(t *testing.T) {
	t.Setenv(linuxPidNamespaceEnvironmentName, linuxPidNamespaceEnvironmentValue)
	_, _, _, ok := linuxSelectGateIsolation(
		context.Background(),
		NetworkNone,
		linuxRootlessProbeEnvironment(),
		"/usr/bin/true",
		nil,
	)
	if ok {
		t.Fatal("isolation was selected after inheriting the pid-namespace marker")
	}
}

func TestLinuxOSGateExecutorBlocksWhenPidNamespaceMarkerIsSet(t *testing.T) {
	t.Setenv(linuxPidNamespaceEnvironmentName, linuxPidNamespaceEnvironmentValue)
	request := gateExecutorRequest(t, "streams", time.Second, 1024, 1024)
	result, err := newOSGateExecutor().Execute(context.Background(), request)
	if !result.Blocked || result.CleanupFailed || !errors.Is(err, errGateIsolationUnavailable) {
		t.Fatalf("marked nested isolation result = %#v, err=%v", result, err)
	}
}

func TestLinuxSelectGateIsolationRefusesNonHostPidNamespace(t *testing.T) {
	t.Parallel()
	if !linuxInNonHostPidNamespace() {
		t.Skip("host pid namespace")
	}
	_, _, _, ok := linuxSelectGateIsolation(
		context.Background(),
		NetworkNone,
		linuxRootlessProbeEnvironment(),
		"/usr/bin/true",
		nil,
	)
	if ok {
		t.Fatal("nested unshare --pid was selected from inside a pid namespace")
	}
}

func TestLinuxOSGateExecutorBlocksWithoutCleanupFailedInNonHostPidNamespace(t *testing.T) {
	if !linuxInNonHostPidNamespace() {
		t.Skip("host pid namespace")
	}
	request := gateExecutorRequest(t, "streams", time.Second, 1024, 1024)
	result, err := newOSGateExecutor().Execute(context.Background(), request)
	if !result.Blocked || result.CleanupFailed || !errors.Is(err, errGateIsolationUnavailable) {
		t.Fatalf("nested isolation result = %#v, err=%v", result, err)
	}
}

func TestLinuxRootlessGateIsolationArgumentsKeepMappedRoot(t *testing.T) {
	t.Parallel()
	args, ok := linuxRootlessGateIsolationArguments(NetworkNone, "/usr/bin/true", []string{"--version"})
	if !ok {
		t.Fatal("rootless NetworkNone isolation helpers were not trusted")
	}
	for _, want := range []string{"--user", "--map-root-user", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--net", "--", "/usr/bin/true", "--version"} {
		if !containsExactArg(args, want) {
			t.Fatalf("rootless NetworkNone arguments %q missing %q", args, want)
		}
	}
	requireLoopbackBringUpBefore(t, args, "/usr/bin/true")
	modules, ok := linuxRootlessGateIsolationArguments(NetworkGoModules, "/usr/bin/true", nil)
	if !ok {
		t.Fatal("rootless Go-modules isolation helpers were not trusted")
	}
	if containsExactArg(modules, "--net") {
		t.Fatalf("rootless Go-modules arguments isolated the host network: %q", modules)
	}
	requireNoLoopbackBringUp(t, modules)
}

func TestLinuxPrivilegedGateIsolationArgumentsUseReplayShapedNetns(t *testing.T) {
	t.Parallel()
	environment := []string{"HOME=/", "PATH=/usr/bin:/bin"}
	none, ok := privilegedIsolationArgs(t, NetworkNone, environment, "/opt/hostedtoolcache/go/bin/go", []string{"version"})
	if !ok {
		t.Fatal("privileged NetworkNone isolation helpers were not trusted")
	}
	modules, ok := privilegedIsolationArgs(t, NetworkGoModules, environment, "/opt/hostedtoolcache/go/bin/go", []string{"version"})
	if !ok {
		t.Fatal("privileged Go-modules isolation helpers were not trusted")
	}

	for _, args := range [][]string{none, modules} {
		for _, want := range []string{
			"-n", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
			"--reuid=1001", "--regid=1001", "--clear-groups",
			"--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
			"-i", "HOME=/", linuxPidNamespaceEnvironment, "/opt/hostedtoolcache/go/bin/go", "version",
		} {
			if !containsExactArg(args, want) {
				t.Fatalf("privileged arguments %q missing %q", args, want)
			}
		}
		for _, forbidden := range []string{"--user", "--map-root-user"} {
			if containsExactArg(args, forbidden) {
				t.Fatalf("privileged arguments reused the AppArmor-blocked rootless uid_map path: %q", args)
			}
		}
	}
	if !containsExactArg(none, "--net") {
		t.Fatalf("privileged NetworkNone arguments omitted --net: %q", none)
	}
	requireLoopbackBringUpBefore(t, none, "--reuid=1001")
	if containsExactArg(modules, "--net") {
		t.Fatalf("privileged Go-modules arguments isolated the host network: %q", modules)
	}
	requireNoLoopbackBringUp(t, modules)
}

func privilegedIsolationArgs(
	t *testing.T,
	network NetworkMode,
	environment []string,
	application string,
	arguments []string,
) ([]string, bool) {
	t.Helper()
	_, args, ok := linuxPrivilegedGateIsolationCommand(network, 1001, 1001, environment, application, arguments)
	return args, ok
}

func requireLoopbackBringUpBefore(t *testing.T, arguments []string, later string) {
	t.Helper()
	scriptIndex := -1
	laterIndex := -1
	for index, argument := range arguments {
		if strings.Contains(argument, `link set lo up && exec "$@"`) {
			scriptIndex = index
		}
		if later != "" && argument == later && laterIndex < 0 {
			laterIndex = index
		}
	}
	if scriptIndex < 0 {
		t.Fatalf("NetworkNone isolation omitted loopback bring-up: %q", arguments)
	}
	if later != "" && (laterIndex < 0 || scriptIndex >= laterIndex) {
		t.Fatalf("loopback bring-up was not before %q: %q", later, arguments)
	}
}

func requireNoLoopbackBringUp(t *testing.T, arguments []string) {
	t.Helper()
	for _, argument := range arguments {
		if strings.Contains(argument, "link set lo up") {
			t.Fatalf("non-NetworkNone isolation brought up loopback: %q", arguments)
		}
	}
}

func containsExactArg(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}

func TestLinuxPrivilegedGateIsolationCommandRefusesInvalidIdentities(t *testing.T) {
	t.Parallel()
	if _, _, ok := linuxPrivilegedGateIsolationCommand(NetworkNone, -1, 1001, []string{"HOME=/"}, "/usr/bin/true", nil); ok {
		t.Fatal("negative uid was accepted")
	}
	if _, _, ok := linuxPrivilegedGateIsolationCommand(NetworkNone, 1001, -1, []string{"HOME=/"}, "/usr/bin/true", nil); ok {
		t.Fatal("negative gid was accepted")
	}
	if _, _, ok := linuxPrivilegedGateIsolationCommand(NetworkNone, 1001, 1001, []string{"HOME=/"}, "", nil); ok {
		t.Fatal("empty application was accepted")
	}
}

func TestLinuxRootlessAndPrivilegedIsolationAreDistinctVectors(t *testing.T) {
	t.Parallel()
	rootlessArgs, ok := linuxRootlessGateIsolationArguments(NetworkNone, "/usr/bin/true", nil)
	if !ok {
		t.Fatal("rootless NetworkNone isolation helpers were not trusted")
	}
	rootless := strings.Join(rootlessArgs, "\x00")
	_, privileged, ok := linuxPrivilegedGateIsolationCommand(NetworkNone, 1001, 1001, []string{"HOME=/"}, "/usr/bin/true", nil)
	if !ok {
		t.Fatal("privileged helpers were not trusted")
	}
	if strings.Contains(rootless, "sudo") {
		t.Fatal("rootless vector unexpectedly invoked sudo")
	}
	if !containsExactArg(privileged, "-n") {
		t.Fatalf("privileged vector omitted sudo -n: %q", privileged)
	}
}
