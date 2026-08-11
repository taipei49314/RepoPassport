package sourcequalification

const (
	NetworkNone                              NetworkMode = "none"
	NetworkGoModules                         NetworkMode = "go-modules"
	NetworkVulnerabilityDatabase             NetworkMode = "vulnerability-database"
	NetworkGoModulesAndVulnerabilityDatabase NetworkMode = "go-modules-and-vulnerability-database"
)

type NetworkMode string

type GateSpec struct {
	ID             string
	Argv           []string
	TimeoutSeconds int
	Network        NetworkMode
}

var commonGateRegistry = []GateSpec{
	newGateSpec("RP-M0-QUAL-GO-VERSION", 30, NetworkNone, "go", "version"),
	newGateSpec("RP-M0-QUAL-SCHEMA-JSON", 120, NetworkNone, "repopass-source-qualify", "validate-schema-json", "--root", "."),
	newGateSpec("RP-M0-QUAL-MODULE-DOWNLOAD", 600, NetworkGoModules, "go", "mod", "download", "-modcacherw", "all"),
	newGateSpec("RP-M0-QUAL-MODULE-VERIFY", 120, NetworkNone, "go", "mod", "verify"),
	newGateSpec("RP-M0-QUAL-TIDY-DIFF", 300, NetworkNone, "go", "mod", "tidy", "-diff"),
	newGateSpec("RP-M0-QUAL-FORMAT", 120, NetworkNone, "gofmt", "-l", "."),
	newGateSpec("RP-M0-QUAL-VET", 600, NetworkNone, "go", "vet", "./..."),
	newGateSpec("RP-M0-QUAL-TEST", 2100, NetworkNone, "go", "test", "-count=1", "-timeout=30m", "./..."),
	newGateSpec("RP-M0-QUAL-INTEGRATION-COMPILE", 600, NetworkNone, "go", "test", "-count=1", "-tags=integration", "./internal/cli", "-run", "^$"),
}

var releaseBuildGate = newGateSpec(
	"RP-M0-QUAL-RELEASE-BUILD",
	1500,
	NetworkGoModules,
	"pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
	"scripts/build-release.ps1", "-Version", "0.1.0-alpha.33",
	"-TestedRevision", "{testedRevision}",
)

var linuxGateRegistry = appendGateSpecs(
	commonGateRegistry,
	newGateSpec(
		"RP-M0-QUAL-VULN-MODULE",
		900,
		NetworkGoModulesAndVulnerabilityDatabase,
		"go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0",
		"-C", "cmd/repopass", "-scan", "module",
	),
	newGateSpec(
		"RP-M0-QUAL-VULN-TEST",
		1200,
		NetworkGoModulesAndVulnerabilityDatabase,
		"go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0",
		"-test", "./...",
	),
	releaseBuildGate,
)

var windowsGateRegistry = appendGateSpecs(
	commonGateRegistry,
	releaseBuildGate,
	newGateSpec(
		"RP-M0-QUAL-WINDOWS-LOCK-STRESS",
		720,
		NetworkNone,
		"go", "test", "-count=20", "-timeout=10m",
		"./internal/releasestate", "./internal/trustchainstate",
		"./internal/trustrotationstate", "./internal/truststate", "-run",
		"^(TestObserveContextAndTimeoutBoundLockContention|TestObserveChainStateConcurrencyCancellationAndProcessContention|TestObserveContentionAndCancellationLeaveStateUnchanged|TestObserveCrossProcessLockTimeoutAndExitRelease)$",
	),
)

func RequiredGates(lane Lane) []GateSpec {
	switch lane {
	case LaneLinuxAMD64:
		return cloneGateSpecs(linuxGateRegistry)
	case LaneWindowsAMD64:
		return cloneGateSpecs(windowsGateRegistry)
	default:
		return nil
	}
}

func newGateSpec(id string, timeoutSeconds int, network NetworkMode, argv ...string) GateSpec {
	return GateSpec{
		ID:             id,
		Argv:           append([]string(nil), argv...),
		TimeoutSeconds: timeoutSeconds,
		Network:        network,
	}
}

func appendGateSpecs(prefix []GateSpec, suffix ...GateSpec) []GateSpec {
	result := cloneGateSpecs(prefix)
	for _, gate := range suffix {
		gate.Argv = append([]string(nil), gate.Argv...)
		result = append(result, gate)
	}
	return result
}

func cloneGateSpecs(registry []GateSpec) []GateSpec {
	result := make([]GateSpec, len(registry))
	for index, gate := range registry {
		result[index] = gate
		result[index].Argv = append([]string(nil), gate.Argv...)
	}
	return result
}
