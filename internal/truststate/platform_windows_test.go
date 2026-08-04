//go:build windows

package truststate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsAtomicPrivateCreateBarrierAllowsPausedPeer(t *testing.T) {
	for _, stage := range []string{"data-root", "state-parent", "state-root", "lock"} {
		t.Run(stage, func(t *testing.T) {
			dataRoot := filepath.Join(t.TempDir(), "controller-data")
			stateParent := filepath.Join(dataRoot, "trust-policy-state")
			stateDirectory := filepath.Join(stateParent, "v1")
			target := dataRoot
			switch stage {
			case "state-parent":
				createPrivateDirectoryForTest(t, dataRoot)
				target = stateParent
			case "state-root":
				createPrivateDirectoryForTest(t, dataRoot)
				createPrivateDirectoryForTest(t, stateParent)
				target = stateDirectory
			case "lock":
				createPrivateDirectoryForTest(t, dataRoot)
				createPrivateDirectoryForTest(t, stateParent)
				createPrivateDirectoryForTest(t, stateDirectory)
				target = filepath.Join(stateDirectory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lock")
			}

			created := make(chan struct{})
			resume := make(chan struct{})
			var once sync.Once
			previousHook := afterPrivateCreate
			afterPrivateCreate = func(path string) {
				if samePath(path, target) {
					once.Do(func() { close(created) })
					<-resume
				}
			}
			defer func() { afterPrivateCreate = previousHook }()

			creator := make(chan struct {
				result Result
				err    error
			}, 1)
			go func() {
				result, err := Observe(context.Background(), dataRoot, testAuthority, 1, testDigestA)
				creator <- struct {
					result Result
					err    error
				}{result, err}
			}()
			select {
			case <-created:
			case <-time.After(5 * time.Second):
				t.Fatal("creator did not pause after atomic create")
			}

			peerResult, peerErr := Observe(context.Background(), dataRoot, testAuthority, 1, testDigestA)
			if peerErr != nil || (peerResult.Evaluation != EvaluationInitialized && peerResult.Evaluation != EvaluationMatched) {
				close(resume)
				t.Fatalf("peer while creator paused = %#v, %v", peerResult, peerErr)
			}
			close(resume)
			creatorResult := <-creator
			if creatorResult.err != nil || (creatorResult.result.Evaluation != EvaluationInitialized && creatorResult.result.Evaluation != EvaluationMatched) {
				t.Fatalf("creator after peer = %#v, %v", creatorResult.result, creatorResult.err)
			}
		})
	}
}

func TestWindowsAtomicCreateSecurityDescriptorIndependentInspection(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-directory")
	created, err := createPrivateDirectory(directory)
	if err != nil || !created {
		t.Fatalf("atomic directory create = created:%v err:%v", created, err)
	}
	assertWindowsAtomicSecurityDescriptor(t, directory)

	lockPath := filepath.Join(directory, "private.lock")
	lock, created, err := createPrivateLock(lockPath)
	if err != nil || !created {
		t.Fatalf("atomic lock create = created:%v err:%v", created, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	assertWindowsAtomicSecurityDescriptor(t, lockPath)
}

func TestUnsafeExistingWindowsObjectsRemainUnchanged(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dataRoot := filepath.Join(t.TempDir(), "controller-data")
		if err := os.Mkdir(dataRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		before := makeWindowsDACLUnsafeForTest(t, dataRoot)
		result, err := Observe(context.Background(), dataRoot, testAuthority, 1, testDigestA)
		if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
			t.Fatalf("unsafe directory = %#v, %v", result, err)
		}
		if after := securityDescriptorForTest(t, dataRoot); after != before {
			t.Fatalf("unsafe directory security descriptor changed:\n before=%q\n after=%q", before, after)
		}
	})

	t.Run("lock", func(t *testing.T) {
		dataRoot := filepath.Join(t.TempDir(), "controller-data")
		stateParent := filepath.Join(dataRoot, "trust-policy-state")
		stateDirectory := filepath.Join(stateParent, "v1")
		createPrivateDirectoryForTest(t, dataRoot)
		createPrivateDirectoryForTest(t, stateParent)
		createPrivateDirectoryForTest(t, stateDirectory)
		lockPath := filepath.Join(stateDirectory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lock")
		sentinel := []byte("repopass-unsafe-lock-sentinel\x00\xff")
		file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(sentinel); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		beforeBytes, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		before := makeWindowsDACLUnsafeForTest(t, lockPath)
		result, err := Observe(context.Background(), dataRoot, testAuthority, 1, testDigestA)
		if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
			t.Fatalf("unsafe lock = %#v, %v", result, err)
		}
		if after := securityDescriptorForTest(t, lockPath); after != before {
			t.Fatalf("unsafe lock security descriptor changed:\n before=%q\n after=%q", before, after)
		}
		afterBytes, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterBytes, beforeBytes) || !bytes.Equal(afterBytes, sentinel) {
			t.Fatalf("unsafe lock bytes changed: before=%q after=%q", beforeBytes, afterBytes)
		}
	})

	t.Run("unprotected-directory", func(t *testing.T) {
		dataRoot := filepath.Join(t.TempDir(), "controller-data")
		createPrivateDirectoryForTest(t, dataRoot)
		setWindowsUnprotectedDACLForTest(t, dataRoot)
		result, err := Observe(context.Background(), dataRoot, testAuthority, 1, testDigestA)
		if !errors.Is(err, ErrUnavailable) || result != (Result{Evaluation: EvaluationUnavailable}) {
			t.Fatalf("unprotected directory = %#v, %v", result, err)
		}
	})
}

func assertWindowsAtomicSecurityDescriptor(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("GetNamedSecurityInfo(%q) = %#v, %v", path, descriptor, err)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		t.Fatalf("security descriptor control for %q = %#x, %v", path, control, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		t.Fatalf("security descriptor owner for %q = %#v, %v", path, owner, err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil || !owner.Equals(currentUser.User.Sid) {
		t.Fatalf("security descriptor owner for %q is not the current user: %v", path, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("security descriptor DACL for %q = %#v, %v", path, dacl, err)
	}
	expected := map[string]struct{}{
		owner.String(): {},
		"S-1-5-18":     {},
		"S-1-5-32-544": {},
	}
	if int(dacl.AceCount) != len(expected) {
		t.Fatalf("security descriptor ACE count for %q = %d, want %d", path, dacl.AceCount, len(expected))
	}
	actual := make(map[string]struct{}, dacl.AceCount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) {
			t.Fatalf("security descriptor ACE %d for %q is invalid: %#v, %v", index, path, ace, err)
		}
		if ace.Mask != 0x1f01ff {
			t.Fatalf("security descriptor ACE %d mask for %q = %#x, want FILE_ALL_ACCESS", index, path, ace.Mask)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			t.Fatalf("security descriptor ACE %d SID for %q is invalid", index, path)
		}
		principal := sid.String()
		if _, permitted := expected[principal]; !permitted {
			t.Fatalf("security descriptor ACE %d principal for %q = %q", index, path, principal)
		}
		if _, duplicate := actual[principal]; duplicate {
			t.Fatalf("security descriptor ACE %d principal for %q is duplicated: %q", index, path, principal)
		}
		actual[principal] = struct{}{}
	}
	for principal := range expected {
		if _, present := actual[principal]; !present {
			t.Fatalf("security descriptor for %q is missing principal %q", path, principal)
		}
	}
}

func TestWindowsLegacyProtectedOwnerRightsDACLCompatible(t *testing.T) {
	dataRoot := filepath.Join(t.TempDir(), "controller-data")
	stateParent := filepath.Join(dataRoot, "trust-policy-state")
	stateDirectory := filepath.Join(stateParent, "v1")
	for _, path := range []string{dataRoot, stateParent, stateDirectory} {
		createPrivateDirectoryForTest(t, path)
		setWindowsDACLForTest(t, path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
		if err := validatePrivateStateDirectory(path); err != nil {
			t.Fatalf("legacy private directory %q: %v", path, err)
		}
	}
	lockPath := filepath.Join(stateDirectory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lock")
	lock, created, err := createPrivateLock(lockPath)
	if err != nil || !created {
		t.Fatalf("create legacy lock = created:%v err:%v", created, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	setWindowsDACLForTest(t, lockPath, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
	legacyLock, err := openExistingPrivateLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOpenedRegularFile(legacyLock, lockPath, true); err != nil {
		legacyLock.Close()
		t.Fatalf("legacy private lock: %v", err)
	}
	if err := legacyLock.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Observe(context.Background(), dataRoot, testAuthority, 1, testDigestA)
	if err != nil || result != (Result{Evaluation: EvaluationInitialized, Generation: 1}) {
		t.Fatalf("legacy protected owner-rights DACL = %#v, %v", result, err)
	}
}

func TestWindowsPrivateDACLSDDLUsesUniquePrincipals(t *testing.T) {
	cases := map[string]string{
		"ordinary-owner":       `O:S-1-5-21-1-2-3-4D:P(A;;FA;;;S-1-5-21-1-2-3-4)(A;;FA;;;SY)(A;;FA;;;BA)`,
		"local-system-owner":   `O:S-1-5-18D:P(A;;FA;;;S-1-5-18)(A;;FA;;;BA)`,
		"administrators-owner": `O:S-1-5-32-544D:P(A;;FA;;;S-1-5-32-544)(A;;FA;;;SY)`,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			owner := "S-1-5-21-1-2-3-4"
			switch name {
			case "local-system-owner":
				owner = "S-1-5-18"
			case "administrators-owner":
				owner = "S-1-5-32-544"
			}
			if got := privateDACLSDDL(owner); got != want {
				t.Fatalf("privateDACLSDDL(%q) = %q, want %q", owner, got, want)
			}
		})
	}
}

func TestWindowsPrivateDACLPrincipalProfilesAllowOverlappingOwners(t *testing.T) {
	cases := []struct {
		name       string
		owner      string
		principals []string
	}{
		{"explicit-system-owner", "S-1-5-18", []string{"S-1-5-18", "S-1-5-32-544"}},
		{"explicit-administrators-owner", "S-1-5-32-544", []string{"S-1-5-32-544", "S-1-5-18"}},
		{"legacy-system-owner", "S-1-5-18", []string{"S-1-3-4", "S-1-5-18", "S-1-5-32-544"}},
		{"legacy-administrators-owner", "S-1-5-32-544", []string{"S-1-3-4", "S-1-5-18", "S-1-5-32-544"}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if !validPrivateDACLPrincipals(item.owner, item.principals) {
				t.Fatalf("validPrivateDACLPrincipals(%q, %#v) = false", item.owner, item.principals)
			}
		})
	}
}

func createPrivateDirectoryForTest(t *testing.T, path string) {
	t.Helper()
	created, err := createPrivateDirectory(path)
	if err != nil || !created {
		t.Fatalf("create private directory %q = created:%v err:%v", path, created, err)
	}
	if err := validatePrivateStateDirectory(path); err != nil {
		t.Fatalf("validate private directory %q: %v", path, err)
	}
}

func makeWindowsDACLUnsafeForTest(t *testing.T, path string) string {
	t.Helper()
	setWindowsDACLForTest(t, path, "D:P(A;;FA;;;WD)")
	return securityDescriptorForTest(t, path)
}

func setWindowsDACLForTest(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("unsafe DACL = %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func setWindowsUnprotectedDACLForTest(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("unprotected DACL = %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func securityDescriptorForTest(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		t.Fatalf("get security descriptor %q: %v", path, err)
	}
	return descriptor.String()
}
