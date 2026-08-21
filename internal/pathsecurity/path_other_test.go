//go:build !windows

package pathsecurity

import "testing"

func TestQualificationTestDescriptorIsWindowsOnly(t *testing.T) {
	if descriptor, available := QualificationTestDescriptor(); available || descriptor != "" {
		t.Fatalf("non-Windows qualification descriptor = %q, %v", descriptor, available)
	}
}
