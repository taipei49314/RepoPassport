package sourcequalification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeBindingTestApplication(t *testing.T, directory, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write test application: %v", err)
	}
	return path
}

func bindTestApplications(t *testing.T, applications map[string]string) gateApplicationBinding {
	t.Helper()
	binding, err := newOSGateExecutor().BindApplications(context.Background(), applications)
	if err != nil {
		t.Fatalf("BindApplications: %v", err)
	}
	if binding == nil || nilGateDependency(binding) {
		t.Fatal("BindApplications returned no binding")
	}
	return binding
}

func TestBindApplicationsHoldsResolvedApplications(t *testing.T) {
	directory := t.TempDir()
	applications := map[string]string{
		"alpha": writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes")),
		"beta":  writeBindingTestApplication(t, directory, "beta.exe", []byte("beta-bytes")),
	}
	binding := bindTestApplications(t, applications)
	for index := 0; index < 3; index++ {
		if err := binding.Verify(context.Background()); err != nil {
			t.Fatalf("Verify %d: %v", index, err)
		}
	}
	if err := binding.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestBindApplicationsRefusesMissingApplication(t *testing.T) {
	directory := t.TempDir()
	applications := map[string]string{
		"alpha": writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes")),
		"beta":  filepath.Join(directory, "missing.exe"),
	}
	binding, err := newOSGateExecutor().BindApplications(context.Background(), applications)
	if !errors.Is(err, errGateApplicationBindingUnavailable) {
		t.Fatalf("expected binding refusal, got binding=%v err=%v", binding, err)
	}
	if binding != nil && !nilGateDependency(binding) {
		t.Fatal("refusal must not return a live binding")
	}
}

func TestBindApplicationsRefusesRelativeApplicationPath(t *testing.T) {
	directory := t.TempDir()
	writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes"))
	binding, err := newOSGateExecutor().BindApplications(
		context.Background(),
		map[string]string{"alpha": filepath.Join("relative", "alpha.exe")},
	)
	if !errors.Is(err, errGateApplicationBindingUnavailable) {
		t.Fatalf("expected binding refusal, got binding=%v err=%v", binding, err)
	}
}

func TestBindApplicationsRefusesEmptyApplications(t *testing.T) {
	binding, err := newOSGateExecutor().BindApplications(context.Background(), nil)
	if !errors.Is(err, errGateApplicationBindingUnavailable) {
		t.Fatalf("expected binding refusal, got binding=%v err=%v", binding, err)
	}
}

func TestBindApplicationsRefusesNilOrCancelledContext(t *testing.T) {
	directory := t.TempDir()
	applications := map[string]string{
		"alpha": writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes")),
	}
	//nolint:staticcheck // deliberately probing the nil-context refusal path.
	if _, err := newOSGateExecutor().BindApplications(nil, applications); !errors.Is(err, errGateApplicationBindingUnavailable) {
		t.Fatalf("nil context: expected refusal, got %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newOSGateExecutor().BindApplications(cancelled, applications); !errors.Is(err, errGateApplicationBindingUnavailable) {
		t.Fatalf("cancelled context: expected refusal, got %v", err)
	}
}

func TestBindingVerifyRefusesNilContext(t *testing.T) {
	directory := t.TempDir()
	binding := bindTestApplications(t, map[string]string{
		"alpha": writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes")),
	})
	defer func() {
		if err := binding.Release(); err != nil {
			t.Fatalf("Release: %v", err)
		}
	}()
	//nolint:staticcheck // deliberately probing the nil-context refusal path.
	if err := binding.Verify(nil); !errors.Is(err, errGateApplicationBindingViolated) {
		t.Fatalf("nil context: expected violation, got %v", err)
	}
}

func TestBindingVerifyAfterReleaseFails(t *testing.T) {
	directory := t.TempDir()
	binding := bindTestApplications(t, map[string]string{
		"alpha": writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes")),
	})
	if err := binding.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := binding.Verify(context.Background()); !errors.Is(err, errGateApplicationBindingViolated) {
		t.Fatalf("expected violation after release, got %v", err)
	}
}

func TestBindingReleaseTwiceFails(t *testing.T) {
	directory := t.TempDir()
	binding := bindTestApplications(t, map[string]string{
		"alpha": writeBindingTestApplication(t, directory, "alpha.exe", []byte("alpha-bytes")),
	})
	if err := binding.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := binding.Release(); !errors.Is(err, errGateApplicationBindingViolated) {
		t.Fatalf("expected second release to fail, got %v", err)
	}
}
