//go:build !unix && !windows

package trustchainstate

import (
	"context"
	"os"
	"time"
)

func acquireLock(context.Context, *os.File, time.Duration) (func(), error) {
	return nil, ErrUnavailable
}
