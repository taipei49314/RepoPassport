package testsupport

import (
	"errors"
	"testing"
)

func TestClassifyAppContainerTestFailsClosed(t *testing.T) {
	detectionErr := errors.New("token query failed")
	tests := []struct {
		name         string
		goos         string
		appContainer bool
		err          error
		want         appContainerDisposition
	}{
		{name: "ordinary Windows", goos: "windows", want: appContainerRun},
		{name: "Windows AppContainer", goos: "windows", appContainer: true, want: appContainerSkip},
		{name: "non-Windows ignores impossible marker", goos: "linux", appContainer: true, want: appContainerRun},
		{name: "Windows detection failure", goos: "windows", err: detectionErr, want: appContainerFail},
		{name: "non-Windows detection failure", goos: "linux", err: detectionErr, want: appContainerFail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyAppContainerTest(test.goos, test.appContainer, test.err); got != test.want {
				t.Fatalf("classifyAppContainerTest(%q, %v, %v) = %d, want %d", test.goos, test.appContainer, test.err, got, test.want)
			}
		})
	}
}

func TestCurrentProcessAppContainerDetection(t *testing.T) {
	if _, err := currentProcessIsAppContainer(); err != nil {
		t.Fatal(err)
	}
}
