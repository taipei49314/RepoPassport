//go:build linux

package sourcequalification

import (
	"context"
	"testing"
	"time"
)

func gateExecutorIsolationUnavailableForTest(network NetworkMode) bool {
	isolationApplication, ok := trustedLinuxSystemApplication("/usr/bin/unshare")
	return !ok || !linuxGateIsolationAvailable(context.Background(), isolationApplication, network)
}

func TestGateExecutorBlockedClassificationRequiresObservedUnavailableIsolation(t *testing.T) {
	request := gateExecutorRequest(t, "streams", time.Second, 1024, 1024)
	result := gateProcessResult{Blocked: true}
	if gateExecutorBlockedByUnavailableIsolation(t, request, result, errGateProcessBlocked, false) {
		t.Fatal("generic BLOCKED result was accepted without an unavailable-isolation probe")
	}
	if !gateExecutorBlockedByUnavailableIsolation(t, request, result, errGateProcessBlocked, true) {
		t.Fatal("exact BLOCKED result was rejected after an unavailable-isolation probe")
	}
}
