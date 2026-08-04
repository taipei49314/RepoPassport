//go:build windows

package attestation

import "testing"

func TestWindowsNativePathRejectsDevicesExtendedNamespaceAndADS(t *testing.T) {
	for _, value := range []string{
		`C:\safe\file.pem:secret`,
		`\\?\C:\safe\file.pem`,
		`\\.\C:\safe\file.pem`,
		`//?/C:/safe/file.pem`,
		`//./C:/safe/file.pem`,
		`\\server\share\safe\file.pem`,
		`C:\safe\trailing.`,
		`C:\safe\trailing `,
		`C:\safe\CON`,
		`C:\safe\con.txt`,
		`C:\safe\COM1.pem`,
		`C:\safe\LPT¹`,
	} {
		if safeNativePath(value) {
			t.Fatalf("safeNativePath(%q) = true, want false", value)
		}
	}
	for _, value := range []string{`C:\safe\file.pem`} {
		if !safeNativePath(value) {
			t.Fatalf("safeNativePath(%q) = false, want true", value)
		}
	}
}
