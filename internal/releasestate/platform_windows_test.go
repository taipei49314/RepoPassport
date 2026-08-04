//go:build windows

package releasestate

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

func TestWindowsPrivateObjectsAreCreatedAtomically(t *testing.T) {
	for _, stage := range []string{"data-root", "state-parent", "version", "kind", "lock"} {
		t.Run(stage, func(t *testing.T) {
			dataRoot := filepath.Join(t.TempDir(), "controller-data")
			stateParent := filepath.Join(dataRoot, "release-state")
			versionRoot := filepath.Join(stateParent, "v1")
			kindRoot := filepath.Join(versionRoot, "policy")
			target := dataRoot
			switch stage {
			case "state-parent":
				createPrivateDirectoryForTest(t, dataRoot)
				target = stateParent
			case "version":
				createPrivateDirectoryForTest(t, dataRoot)
				createPrivateDirectoryForTest(t, stateParent)
				target = versionRoot
			case "kind":
				createPrivateDirectoryForTest(t, dataRoot)
				createPrivateDirectoryForTest(t, stateParent)
				createPrivateDirectoryForTest(t, versionRoot)
				target = kindRoot
			case "lock":
				createPrivateDirectoryForTest(t, dataRoot)
				createPrivateDirectoryForTest(t, stateParent)
				createPrivateDirectoryForTest(t, versionRoot)
				createPrivateDirectoryForTest(t, kindRoot)
				target = filepath.Join(kindRoot, stateKey(testAuthorityA, "repopass", "alpha")+".lock")
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

			creator := make(chan observedOutcome, 1)
			go func() {
				creator <- capture(ObservePolicy(context.Background(), dataRoot, testAuthorityA, "repopass", "alpha", 1, testDigestA))
			}()
			select {
			case <-created:
			case <-time.After(5 * time.Second):
				t.Fatal("creator did not pause after private object creation")
			}
			peer := capture(ObservePolicy(context.Background(), dataRoot, testAuthorityA, "repopass", "alpha", 1, testDigestA))
			if peer.err != nil || (peer.result.Evaluation != EvaluationInitialized && peer.result.Evaluation != EvaluationMatched) {
				close(resume)
				t.Fatalf("paused-create peer = %#v, %v", peer.result, peer.err)
			}
			close(resume)
			createdOutcome := <-creator
			if createdOutcome.err != nil || (createdOutcome.result.Evaluation != EvaluationInitialized && createdOutcome.result.Evaluation != EvaluationMatched) {
				t.Fatalf("creator = %#v, %v", createdOutcome.result, createdOutcome.err)
			}
		})
	}
}

func TestWindowsRejectsUnsafeExistingObjectsWithoutMutation(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-data")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		before := makeWindowsDACLUnsafeForTest(t, root)
		assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 1, testDigestA)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
		if after := securityDescriptorForTest(t, root); after != before {
			t.Fatalf("unsafe directory descriptor changed: before=%q after=%q", before, after)
		}
	})

	t.Run("lock", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "controller-data")
		if _, err := ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 1, testDigestA); err != nil {
			t.Fatal(err)
		}
		stateDirectory, err := stateRoot(context.Background(), root, policyState)
		if err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(stateDirectory, stateKey(testAuthorityA, "repopass", "alpha")+".lock")
		sentinel := []byte("unsafe-lock-sentinel\x00\xff")
		if err := os.WriteFile(lockPath, sentinel, 0o600); err != nil {
			t.Fatal(err)
		}
		before := makeWindowsDACLUnsafeForTest(t, lockPath)
		assertOutcome(t, capture(ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)), Result{EvaluationUnavailable, 0}, ErrUnavailable)
		afterBytes, err := os.ReadFile(lockPath)
		if err != nil || !bytes.Equal(afterBytes, sentinel) || securityDescriptorForTest(t, lockPath) != before {
			t.Fatalf("unsafe lock changed: bytes=%q err=%v", afterBytes, err)
		}
	})
}

func TestWindowsAtomicCreateSecurityDescriptors(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-directory")
	created, err := createPrivateDirectory(directory)
	if err != nil || !created {
		t.Fatalf("create directory = %v, %v", created, err)
	}
	assertWindowsPrivateDescriptor(t, directory)
	lockPath := filepath.Join(directory, "private.lock")
	lock, created, err := createPrivateLock(lockPath)
	if err != nil || !created {
		t.Fatalf("create lock = %v, %v", created, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	assertWindowsPrivateDescriptor(t, lockPath)
}

func createPrivateDirectoryForTest(t *testing.T, path string) {
	t.Helper()
	created, err := createPrivateDirectory(path)
	if err != nil || !created {
		t.Fatalf("create private directory %q = %v, %v", path, created, err)
	}
}

func makeWindowsDACLUnsafeForTest(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	return securityDescriptorForTest(t, path)
}

func securityDescriptorForTest(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		t.Fatalf("security descriptor %q: %v", path, err)
	}
	return descriptor.String()
}

func assertWindowsPrivateDescriptor(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		t.Fatalf("descriptor %q = %#v, %v", path, descriptor, err)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		t.Fatalf("descriptor control %q = %#x, %v", path, control, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		t.Fatalf("descriptor owner %q = %#v, %v", path, owner, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !owner.Equals(user.User.Sid) {
		t.Fatalf("descriptor owner is not current user: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		t.Fatalf("descriptor DACL %q = %#v, %v", path, dacl, err)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+unsafe.Sizeof(ace.SidStart)) || ace.Mask != 0x1f01ff {
			t.Fatalf("descriptor ACE %d for %q invalid: %#v, %v", index, path, ace, err)
		}
	}
}

func TestWindowsUnsafeDACLReturnsTypedUnavailable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller-data")
	if _, err := ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 1, testDigestA); err != nil {
		t.Fatal(err)
	}
	path := stateFileForTest(t, root, indexState, testAuthorityA, "repopass", "alpha")
	makeWindowsDACLUnsafeForTest(t, path)
	result, err := ObserveIndex(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)
	if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
		t.Fatalf("unsafe state DACL = %#v, %v", result, err)
	}
}
