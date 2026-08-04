//go:build !unix && !windows

package truststate

import (
	"context"
	"os"
	"time"
)

func acquireLock(context.Context, *os.File, time.Duration) (func(), error) {
	return nil, ErrUnavailable
}
