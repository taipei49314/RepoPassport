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

func TestClassifyWindowsGateProcessSnapshotDistinguishesRootLagFromResidue(t *testing.T) {
	const rootProcessID = uint32(41)
	for _, test := range []struct {
		name     string
		assigned uint32
		listed   []uintptr
		want     windowsGateProcessDisposition
	}{
		{name: "quiescent", assigned: 0, want: windowsGateProcessesQuiescent},
		{name: "signaled root still listed", assigned: 1, listed: []uintptr{uintptr(rootProcessID)}, want: windowsGateProcessesRootAccounting},
		{name: "descendant only", assigned: 1, listed: []uintptr{99}, want: windowsGateProcessesResidue},
		{name: "root and descendant", assigned: 2, listed: []uintptr{uintptr(rootProcessID), 99}, want: windowsGateProcessesResidue},
		{name: "truncated list", assigned: 2, listed: []uintptr{uintptr(rootProcessID)}, want: windowsGateProcessesInvalid},
		{name: "impossible extra id", assigned: 1, listed: []uintptr{uintptr(rootProcessID), 99}, want: windowsGateProcessesInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyWindowsGateProcessSnapshot(rootProcessID, test.assigned, test.listed); got != test.want {
				t.Fatalf("disposition = %v, want %v", got, test.want)
			}
		})
	}
}

func TestWaitWindowsGateRootAccountingRejectsDescendantsWithoutGrace(t *testing.T) {
	calls := 0
	ok := waitWindowsGateRootAccounting(time.Now().Add(time.Second), 41, func() (uint32, []uintptr, error) {
		calls++
		return 2, []uintptr{41, 99}, nil
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
		assigned uint32
		listed   []uintptr
	}{
		{assigned: 1, listed: []uintptr{41}},
		{assigned: 1, listed: []uintptr{41}},
		{assigned: 0},
	}
	calls := 0
	ok := waitWindowsGateRootAccounting(time.Now().Add(time.Second), 41, func() (uint32, []uintptr, error) {
		if calls >= len(snapshots) {
			t.Fatal("snapshot query exceeded the fixed observation sequence")
		}
		value := snapshots[calls]
		calls++
		return value.assigned, value.listed, nil
	})
	if !ok {
		t.Fatal("signaled root accounting did not settle")
	}
	if calls != len(snapshots) {
		t.Fatalf("snapshot calls = %d, want %d", calls, len(snapshots))
	}
}
