package sourcequalification

import "testing"

func TestValidReceiptRunnerImageAcceptsHostedRunnerImageOS(t *testing.T) {
	tests := []struct {
		name  string
		lane  Lane
		value string
		ok    bool
	}{
		{name: "linux ImageOS", lane: LaneLinuxAMD64, value: "ubuntu24", ok: true},
		{name: "linux runner label", lane: LaneLinuxAMD64, value: "ubuntu-24.04", ok: true},
		{name: "windows ImageOS numeric", lane: LaneWindowsAMD64, value: "win25", ok: true},
		{name: "windows runner label", lane: LaneWindowsAMD64, value: "windows-2025", ok: true},
		{name: "windows ImageOS with VS qualifier", lane: LaneWindowsAMD64, value: "win25-vs2026", ok: true},
		{name: "linux image rejected on windows", lane: LaneWindowsAMD64, value: "ubuntu24", ok: false},
		{name: "windows image rejected on linux", lane: LaneLinuxAMD64, value: "win25-vs2026", ok: false},
		{name: "trailing hyphen", lane: LaneWindowsAMD64, value: "win25-", ok: false},
		{name: "missing numeric image id", lane: LaneWindowsAMD64, value: "win-vs2026", ok: false},
		{name: "path qualifier", lane: LaneWindowsAMD64, value: `win25-C:\Windows`, ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validReceiptRunnerImage(test.value, test.lane); got != test.ok {
				t.Fatalf("validReceiptRunnerImage(%q, %s) = %v, want %v",
					test.value, test.lane, got, test.ok)
			}
		})
	}
}

func TestValidateReceiptPlatformAcceptsCurrentHostedWindowsImageOS(t *testing.T) {
	platform := receiptPlatform{
		GitVersion:         "git version 2.54.0.windows.1",
		GoVersion:          receiptGoVersion,
		GOARCH:             "amd64",
		GOOS:               "windows",
		KernelVersion:      "10.0.26100.0",
		PowerShellVersion:  "7.6.4",
		RunnerArch:         "X64",
		RunnerImage:        "win25-vs2026",
		RunnerImageVersion: "20260810.198.2",
		RunnerOS:           "Windows",
	}
	if err := validateReceiptPlatform(platform, LaneWindowsAMD64); err != nil {
		t.Fatalf("validateReceiptPlatform: %v", err)
	}
	if err := validateReceiptPrivacy(platform); err != nil {
		t.Fatalf("validateReceiptPrivacy: %v", err)
	}
}
