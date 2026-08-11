//go:build windows

package sourcequalification

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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

func TestReleaseWindowsGateHandleClearsOnlyAfterSuccessfulClose(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handle := windows.Handle(41)
		calls := 0
		if !releaseWindowsGateHandle(&handle, func(got windows.Handle) error {
			calls++
			if got != 41 {
				t.Fatalf("closed handle = %d, want 41", got)
			}
			return nil
		}) {
			t.Fatal("successful handle release was rejected")
		}
		if handle != 0 || calls != 1 {
			t.Fatalf("release result handle=%d calls=%d, want 0/1", handle, calls)
		}
	})

	t.Run("failure retains handle for cleanup retry", func(t *testing.T) {
		handle := windows.Handle(42)
		if releaseWindowsGateHandle(&handle, func(windows.Handle) error {
			return errors.New("private close failure")
		}) {
			t.Fatal("failed handle release was accepted")
		}
		if handle != 42 {
			t.Fatalf("failed release changed handle to %d, want 42", handle)
		}
	})

	t.Run("already released", func(t *testing.T) {
		var handle windows.Handle
		if !releaseWindowsGateHandle(&handle, func(windows.Handle) error {
			t.Fatal("close callback invoked for a zero handle")
			return nil
		}) {
			t.Fatal("zero handle was not treated as released")
		}
	})
}

func TestClassifyWindowsGateProcessSnapshotDistinguishesRootFromResidue(t *testing.T) {
	const rootProcessID = uint32(41)
	for _, test := range []struct {
		name     string
		assigned uint32
		listed   []uintptr
		want     windowsGateProcessDisposition
	}{
		{name: "quiescent", assigned: 0, want: windowsGateProcessesQuiescent},
		{name: "signaled root still listed", assigned: 1, listed: []uintptr{uintptr(rootProcessID)}, want: windowsGateProcessesRootOnly},
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
