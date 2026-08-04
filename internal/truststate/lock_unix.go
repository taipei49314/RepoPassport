//go:build unix

package truststate

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func acquireLock(ctx context.Context, file *os.File, timeout time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrUnavailable
	}
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, ErrUnavailable
		}
		if err := waitForLock(ctx, deadline); err != nil {
			return nil, err
		}
	}
}
