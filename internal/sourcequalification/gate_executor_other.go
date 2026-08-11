//go:build !windows && !linux

package sourcequalification

import "context"

func executeOSGateProcess(context.Context, gateProcessRequest) (gateProcessResult, error) {
	return gateProcessResult{Blocked: true}, errGateProcessBlocked
}
