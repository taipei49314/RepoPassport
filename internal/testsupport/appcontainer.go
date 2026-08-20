package testsupport

import (
	"runtime"
	"testing"
)

type appContainerDisposition uint8

const (
	appContainerRun appContainerDisposition = iota
	appContainerSkip
	appContainerFail
)

func classifyAppContainerTest(goos string, appContainer bool, detectionErr error) appContainerDisposition {
	if detectionErr != nil {
		return appContainerFail
	}
	if goos == "windows" && appContainer {
		return appContainerSkip
	}
	return appContainerRun
}

// IsAppContainer reports whether the test runs in a Windows AppContainer.
// Detection failures are fatal so an unknown isolation state never weakens a
// test into a skip.
func IsAppContainer(t testing.TB) bool {
	t.Helper()
	appContainer, err := currentProcessIsAppContainer()
	switch classifyAppContainerTest(runtime.GOOS, appContainer, err) {
	case appContainerFail:
		t.Fatalf("detect Windows AppContainer token: %v", err)
	case appContainerSkip:
		return true
	}
	return false
}

// RequireHostFilesystem skips tests whose intended host filesystem security
// contract cannot be exercised by a Windows AppContainer restricted token.
func RequireHostFilesystem(t testing.TB) {
	t.Helper()
	if IsAppContainer(t) {
		t.Skip("host filesystem security semantics are unavailable inside a Windows AppContainer")
	}
}
