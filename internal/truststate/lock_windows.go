//go:build windows

package truststate

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func acquireLock(ctx context.Context, file *os.File, timeout time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrUnavailable
	}
	deadline := time.Now().Add(timeout)
	for {
		overlapped := windows.Overlapped{}
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped) }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrUnavailable
		}
		if err := waitForLock(ctx, deadline); err != nil {
			return nil, err
		}
	}
}
