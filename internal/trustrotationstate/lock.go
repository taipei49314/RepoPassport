package trustrotationstate

import (
	"context"
	"time"
)

func waitForLock(ctx context.Context, deadline time.Time) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return ErrUnavailable
	}
	delay := 20 * time.Millisecond
	if remaining < delay {
		delay = remaining
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ErrUnavailable
	case <-timer.C:
		return nil
	}
}
