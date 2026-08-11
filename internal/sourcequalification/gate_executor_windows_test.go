//go:build windows

package sourcequalification

import (
	"errors"
	"testing"
	"time"
)

func TestWaitWindowsGateProcessesAllowsRootAccountingToSettle(t *testing.T) {
	observations := []uint32{1, 1, 0}
	calls := 0
	ok := waitWindowsGateProcesses(time.Now().Add(time.Second), func() (uint32, error) {
		if calls >= len(observations) {
			t.Fatal("active-process query exceeded the fixed observation sequence")
		}
		value := observations[calls]
		calls++
		return value, nil
	})
	if !ok {
		t.Fatal("transient root-process accounting lag was treated as cleanup residue")
	}
	if calls != len(observations) {
		t.Fatalf("active-process query calls = %d, want %d", calls, len(observations))
	}
}

func TestWaitWindowsGateProcessesFailsClosedOnQueryError(t *testing.T) {
	want := errors.New("private query failure")
	if waitWindowsGateProcesses(time.Now().Add(time.Second), func() (uint32, error) {
		return 0, want
	}) {
		t.Fatal("job accounting query failure was accepted as quiescent")
	}
}

func TestClassifyWindowsGateAccountingDistinguishesRootLagFromResidue(t *testing.T) {
	for _, test := range []struct {
		name   string
		total  uint32
		active uint32
		want   windowsGateAccountingDisposition
	}{
		{name: "quiescent root", total: 1, active: 0, want: windowsGateAccountingQuiescent},
		{name: "signaled root still active", total: 1, active: 1, want: windowsGateAccountingRootPending},
		{name: "terminated descendant", total: 2, active: 0, want: windowsGateAccountingResidue},
		{name: "active descendant", total: 2, active: 1, want: windowsGateAccountingResidue},
		{name: "missing root", total: 0, active: 0, want: windowsGateAccountingInvalid},
		{name: "active exceeds total", total: 1, active: 2, want: windowsGateAccountingInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyWindowsGateAccountingSnapshot(test.total, test.active); got != test.want {
				t.Fatalf("disposition = %v, want %v", got, test.want)
			}
		})
	}
}

func TestWaitWindowsGateRootAccountingRejectsDescendantsWithoutGrace(t *testing.T) {
	calls := 0
	ok := waitWindowsGateRootAccounting(time.Now().Add(time.Second), func() (uint32, uint32, error) {
		calls++
		return 2, 0, nil
	})
	if ok {
		t.Fatal("a descendant was accepted as transient root accounting lag")
	}
	if calls != 1 {
		t.Fatalf("snapshot calls = %d, want immediate fail-closed decision", calls)
	}
}

func TestWaitWindowsGateRootAccountingAllowsOnlyRootToSettle(t *testing.T) {
	snapshots := []struct {
		total  uint32
		active uint32
	}{
		{total: 1, active: 1},
		{total: 1, active: 1},
		{total: 1, active: 0},
	}
	calls := 0
	ok := waitWindowsGateRootAccounting(time.Now().Add(time.Second), func() (uint32, uint32, error) {
		if calls >= len(snapshots) {
			t.Fatal("snapshot query exceeded the fixed observation sequence")
		}
		value := snapshots[calls]
		calls++
		return value.total, value.active, nil
	})
	if !ok {
		t.Fatal("signaled root accounting did not settle")
	}
	if calls != len(snapshots) {
		t.Fatalf("snapshot calls = %d, want %d", calls, len(snapshots))
	}
}

func TestWaitWindowsGateRootAccountingFailsClosedWhenRootNeverSettles(t *testing.T) {
	calls := 0
	ok := waitWindowsGateRootAccounting(time.Now().Add(25*time.Millisecond), func() (uint32, uint32, error) {
		calls++
		return 1, 1, nil
	})
	if ok {
		t.Fatal("root accounting that exceeded its deadline was accepted")
	}
	if calls == 0 {
		t.Fatal("root accounting was not queried")
	}
}
