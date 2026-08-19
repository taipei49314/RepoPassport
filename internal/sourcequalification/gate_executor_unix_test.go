//go:build linux

package sourcequalification

import (
	"strings"
	"testing"
)

func TestLinuxRootlessGateIsolationArgumentsKeepMappedRoot(t *testing.T) {
	t.Parallel()
	args := linuxRootlessGateIsolationArguments(NetworkNone, "/usr/bin/true", []string{"--version"})
	for _, want := range []string{"--user", "--map-root-user", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--net", "--", "/usr/bin/true", "--version"} {
		if !containsExactArg(args, want) {
			t.Fatalf("rootless NetworkNone arguments %q missing %q", args, want)
		}
	}
	modules := linuxRootlessGateIsolationArguments(NetworkGoModules, "/usr/bin/true", nil)
	if containsExactArg(modules, "--net") {
		t.Fatalf("rootless Go-modules arguments isolated the host network: %q", modules)
	}
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
			"-i", "HOME=/", "/opt/hostedtoolcache/go/bin/go", "version",
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
	if containsExactArg(modules, "--net") {
		t.Fatalf("privileged Go-modules arguments isolated the host network: %q", modules)
	}
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
	rootless := strings.Join(linuxRootlessGateIsolationArguments(NetworkNone, "/usr/bin/true", nil), "\x00")
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
