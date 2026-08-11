// The production registry is expected to expose:
//
//	type NetworkMode string
//	type GateSpec struct {
//		ID string
//		Argv []string
//		TimeoutSeconds int
//		Network NetworkMode
//	}
//	func RequiredGates(Lane) []GateSpec
package sourcequalification

import (
	"reflect"
	"testing"
)

func TestRequiredGateRegistryIsFrozenByPlatform(t *testing.T) {
	common := []GateSpec{
		gate("RP-M0-QUAL-GO-VERSION", 30, "none", "go", "version"),
		gate("RP-M0-QUAL-SCHEMA-JSON", 120, "none", "repopass-source-qualify", "validate-schema-json", "--root", "."),
		gate("RP-M0-QUAL-MODULE-DOWNLOAD", 600, "go-modules", "go", "mod", "download", "-modcacherw", "all"),
		gate("RP-M0-QUAL-MODULE-VERIFY", 120, "none", "go", "mod", "verify"),
		gate("RP-M0-QUAL-TIDY-DIFF", 300, "none", "go", "mod", "tidy", "-diff"),
		gate("RP-M0-QUAL-FORMAT", 120, "none", "gofmt", "-l", "."),
		gate("RP-M0-QUAL-VET", 600, "none", "go", "vet", "./..."),
		gate("RP-M0-QUAL-TEST", 2100, "none", "go", "test", "-count=1", "-timeout=30m", "./..."),
		gate("RP-M0-QUAL-INTEGRATION-COMPILE", 600, "none", "go", "test", "-count=1", "-tags=integration", "./internal/cli", "-run", "^$"),
	}
	releaseBuild := gate("RP-M0-QUAL-RELEASE-BUILD", 1500, "go-modules", "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", "scripts/build-release.ps1", "-Version", "0.1.0-alpha.33", "-TestedRevision", "{testedRevision}")

	wantLinux := append(append([]GateSpec(nil), common...),
		gate("RP-M0-QUAL-VULN-MODULE", 900, "go-modules-and-vulnerability-database", "go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "-C", "cmd/repopass", "-scan", "module"),
		gate("RP-M0-QUAL-VULN-TEST", 1200, "go-modules-and-vulnerability-database", "go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "-test", "./..."),
		releaseBuild,
	)
	wantWindows := append(append([]GateSpec(nil), common...),
		releaseBuild,
		gate("RP-M0-QUAL-WINDOWS-LOCK-STRESS", 720, "none", "go", "test", "-count=20", "-timeout=10m", "./internal/releasestate", "./internal/trustchainstate", "./internal/trustrotationstate", "./internal/truststate", "-run", "^(TestObserveContextAndTimeoutBoundLockContention|TestObserveChainStateConcurrencyCancellationAndProcessContention|TestObserveContentionAndCancellationLeaveStateUnchanged|TestObserveCrossProcessLockTimeoutAndExitRelease)$"),
	)

	for _, test := range []struct {
		name string
		lane Lane
		want []GateSpec
	}{
		{"linux", LaneLinuxAMD64, wantLinux},
		{"windows", LaneWindowsAMD64, wantWindows},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := RequiredGates(test.lane); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("required gates = %#v, want %#v", got, test.want)
			}
		})
	}

	got := RequiredGates(LaneLinuxAMD64)
	got[0].ID = "mutated"
	got[0].Argv[0] = "mutated"
	if RequiredGates(LaneLinuxAMD64)[0].ID != wantLinux[0].ID || RequiredGates(LaneLinuxAMD64)[0].Argv[0] != "go" {
		t.Fatal("required gate registry exposes mutable process state")
	}
	if got := RequiredGates(Lane("darwin-amd64")); got != nil {
		t.Fatalf("unsupported lane registry = %#v, want nil", got)
	}
}

func gate(id string, timeoutSeconds int, network NetworkMode, argv ...string) GateSpec {
	return GateSpec{ID: id, Argv: argv, TimeoutSeconds: timeoutSeconds, Network: network}
}
