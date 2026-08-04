package execution

import (
	"strings"
	"testing"
)

func TestWorkloadProcessStateIsQuiescent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state string
		want  bool
	}{
		{state: "Z", want: true},
		{state: "X", want: true},
		{state: "S", want: false},
		{state: "R", want: false},
		{state: "D", want: false},
		{state: "T", want: false},
		{state: "", want: false},
		{state: "ZX", want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.state, func(t *testing.T) {
			t.Parallel()
			if got := workloadProcessStateIsQuiescent(test.state); got != test.want {
				t.Fatalf(
					"workloadProcessStateIsQuiescent(%q) = %v, want %v",
					test.state,
					got,
					test.want,
				)
			}
		})
	}
}

func TestWorkloadQuiesceScriptsUseFailClosedProcessStates(t *testing.T) {
	t.Parallel()

	for name, script := range map[string]string{
		"node":   nodeWorkloadQuiesceScript,
		"python": pythonWorkloadQuiesceScript,
	} {
		script := script
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(script, "State:") {
				t.Fatal("quiesce script does not inspect process State")
			}
			if !strings.Contains(script, quiescentWorkloadProcessStates) {
				t.Fatalf(
					"quiesce script does not share the %q quiescent-state policy",
					quiescentWorkloadProcessStates,
				)
			}
			if !strings.Contains(script, "65532") ||
				!strings.Contains(script, "65533") {
				t.Fatal(
					"final quiescence does not cover workload and trusted driver UIDs",
				)
			}
		})
	}
}

func TestPythonWorkloadQuiescenceCheckIsObserveOnlyAndFailClosed(t *testing.T) {
	t.Parallel()

	script := pythonWorkloadQuiescenceCheckScript
	for _, required := range []string{
		"/proc", "State:", quiescentWorkloadProcessStates, "65532", "65533",
		"PASSES=2", "SEPARATION_SECONDS=0.02", "time.sleep",
		"current!=previous", "process snapshot changed while reading",
		"process identity is malformed",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("quiescence check is missing %q", required)
		}
	}
	for _, forbidden := range []string{"os.kill", "process.kill", "SIGKILL"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("observe-only quiescence check contains %q", forbidden)
		}
	}
	if args := workloadQuiescenceCheckRuntimeArgs("node"); args != nil {
		t.Fatalf("node must remain unsupported, got %#v", args)
	}
	args := workloadQuiescenceCheckRuntimeArgs("python")
	if len(args) != 4 || args[0] != "-I" || args[1] != "-S" ||
		args[2] != "-c" || args[3] != script {
		t.Fatalf("unexpected Python quiescence command: %#v", args)
	}
}

func TestPythonWorkloadQuiescenceCheckOrdersSeparatedStableSnapshots(
	t *testing.T,
) {
	t.Parallel()

	script := pythonWorkloadQuiescenceCheckScript
	first := strings.Index(script, "previous=snapshot()")
	delay := strings.Index(script, "time.sleep(SEPARATION_SECONDS)")
	second := strings.Index(script, "current=snapshot()")
	comparison := strings.Index(script, "if current!=previous")
	if first < 0 || delay <= first || second <= delay || comparison <= second {
		t.Fatalf(
			"quiescence snapshots are not separated and compared: first=%d delay=%d second=%d comparison=%d",
			first,
			delay,
			second,
			comparison,
		)
	}
	if strings.Contains(script, "except FileNotFoundError:\n        continue") {
		t.Fatal("PID churn is still silently accepted")
	}
}
