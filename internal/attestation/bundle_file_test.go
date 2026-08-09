package attestation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/domain"
)

type failingTemporaryFile struct {
	*os.File
	shortWrite bool
	syncError  error
}

func (f *failingTemporaryFile) Write(value []byte) (int, error) {
	if !f.shortWrite {
		return f.File.Write(value)
	}
	maximum := len(value) / 2
	if maximum == 0 {
		return 0, nil
	}
	return f.File.Write(value[:maximum])
}

func (f *failingTemporaryFile) Sync() error {
	if f.syncError != nil {
		return f.syncError
	}
	return f.File.Sync()
}

func TestWriteNewBundleFailuresNeverExposePartialFinal(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*bundleFileOperations)
	}{
		{
			name: "short write",
			configure: func(operations *bundleFileOperations) {
				operations.createTemp = func(directory, pattern string) (temporaryBundleFile, error) {
					file, err := os.CreateTemp(directory, pattern)
					if err != nil {
						return nil, err
					}
					return &failingTemporaryFile{File: file, shortWrite: true}, nil
				}
			},
		},
		{
			name: "sync failure",
			configure: func(operations *bundleFileOperations) {
				operations.createTemp = func(directory, pattern string) (temporaryBundleFile, error) {
					file, err := os.CreateTemp(directory, pattern)
					if err != nil {
						return nil, err
					}
					return &failingTemporaryFile{File: file, syncError: errors.New("injected sync failure")}, nil
				}
			},
		},
		{
			name: "publication failure",
			configure: func(operations *bundleFileOperations) {
				operations.publish = func(string, string) (bool, error) {
					return false, errors.New("injected publication failure")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			output := filepath.Join(parent, "bundle.tar")
			operations := defaultBundleFileOperations()
			test.configure(&operations)
			err := writeNewBundle(output, []byte("complete-bundle"), operations)
			if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
				t.Fatalf("error code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
			}
			if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
				t.Fatalf("failure exposed a final output: %v", statErr)
			}
			temporaryMatches, globErr := filepath.Glob(filepath.Join(parent, ".repopass-attestation-*"))
			if globErr != nil {
				t.Fatalf("inspect temporary files: %v", globErr)
			}
			if len(temporaryMatches) != 0 {
				t.Fatalf("temporary files remain after failure: %v", temporaryMatches)
			}
		})
	}
}

func TestWriteNewBundlePostPublishFailuresReportRecoveryState(t *testing.T) {
	bundle := []byte("complete-bundle")
	for _, test := range []struct {
		name               string
		configure          func(*bundleFileOperations, string)
		wantDurability     string
		wantTemporaryCount int
	}{
		{
			name: "publish reports error after creating destination",
			configure: func(operations *bundleFileOperations, _ string) {
				operations.publish = func(source, destination string) (bool, error) {
					if err := os.Link(source, destination); err != nil {
						return false, err
					}
					return true, errors.New("injected post-publication error")
				}
			},
			wantDurability: "confirmed",
		},
		{
			name: "temporary cleanup fails after publication",
			configure: func(operations *bundleFileOperations, _ string) {
				operations.publish = func(source, destination string) (bool, error) {
					if err := os.Link(source, destination); err != nil {
						return false, err
					}
					return true, errors.New("injected post-publication error")
				}
				operations.remove = func(string) error {
					return errors.New("injected cleanup failure")
				}
			},
			wantDurability:     "confirmed",
			wantTemporaryCount: 1,
		},
		{
			name: "final lstat fails",
			configure: func(operations *bundleFileOperations, output string) {
				outputChecks := 0
				operations.lstat = func(path string) (os.FileInfo, error) {
					if sameFilesystemPath(path, output) {
						outputChecks++
						if outputChecks == 2 {
							return nil, errors.New("injected final lstat failure")
						}
					}
					return os.Lstat(path)
				}
			},
			wantDurability: "unknown",
		},
		{
			name: "final identity mismatches",
			configure: func(operations *bundleFileOperations, output string) {
				mismatch := filepath.Join(filepath.Dir(output), "different-file")
				if err := os.WriteFile(mismatch, bundle, 0o600); err != nil {
					t.Fatalf("write mismatch fixture: %v", err)
				}
				mismatchInfo, err := os.Lstat(mismatch)
				if err != nil {
					t.Fatalf("stat mismatch fixture: %v", err)
				}
				outputChecks := 0
				operations.lstat = func(path string) (os.FileInfo, error) {
					if sameFilesystemPath(path, output) {
						outputChecks++
						if outputChecks == 2 {
							return mismatchInfo, nil
						}
					}
					return os.Lstat(path)
				}
			},
			wantDurability: "unknown",
		},
		{
			name: "directory sync fails",
			configure: func(operations *bundleFileOperations, _ string) {
				operations.syncDirectory = func(string) error {
					return errors.New("injected directory sync failure")
				}
			},
			wantDurability: "unknown",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			output := filepath.Join(parent, "bundle.tar")
			operations := defaultBundleFileOperations()
			test.configure(&operations, output)
			err := writeNewBundle(output, bundle, operations)
			assertPublishedBuildFailure(t, err, test.wantDurability)
			if got, readErr := os.ReadFile(output); readErr != nil || string(got) != string(bundle) {
				t.Fatalf("published final is not complete: got=%q err=%v", got, readErr)
			}
			temporaryMatches, globErr := filepath.Glob(filepath.Join(parent, ".repopass-attestation-*"))
			if globErr != nil {
				t.Fatalf("inspect temporary files: %v", globErr)
			}
			if len(temporaryMatches) != test.wantTemporaryCount {
				t.Fatalf("temporary count = %d, want %d: %v", len(temporaryMatches), test.wantTemporaryCount, temporaryMatches)
			}
			for _, temporaryPath := range temporaryMatches {
				if got, readErr := os.ReadFile(temporaryPath); readErr != nil || string(got) != string(bundle) {
					t.Fatalf("remaining temporary is partial: got=%q err=%v", got, readErr)
				}
			}
		})
	}
}

func TestWriteNewBundleCleanupDoesNotDeleteReusedTemporaryName(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "bundle.tar")
	replacement := []byte("replacement-owned-by-someone-else")
	var reusedPath string
	var originalPath string
	operations := defaultBundleFileOperations()
	operations.publish = func(source, _ string) (bool, error) {
		reusedPath = source
		originalPath = source + ".original"
		if err := os.Rename(source, originalPath); err != nil {
			return false, err
		}
		if err := os.WriteFile(source, replacement, 0o600); err != nil {
			return false, err
		}
		return false, errors.New("injected pre-publication failure after name reuse")
	}
	err := writeNewBundle(output, []byte("complete-bundle"), operations)
	if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("error code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
	}
	if got, readErr := os.ReadFile(reusedPath); readErr != nil || string(got) != string(replacement) {
		t.Fatalf("reused temporary name was removed or changed: got=%q err=%v", got, readErr)
	}
	if _, statErr := os.Lstat(originalPath); statErr != nil {
		t.Fatalf("original temporary fixture unexpectedly missing: %v", statErr)
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		t.Fatalf("failed publication exposed final output: %v", statErr)
	}
}

func TestWriteNewBundleDoesNotClobberExistingOrNonregularDestination(t *testing.T) {
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing.tar")
	want := []byte("existing-content")
	if err := os.WriteFile(existing, want, 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	if err := WriteNewBundle(existing, []byte("replacement")); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("existing output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if got, err := os.ReadFile(existing); err != nil || string(got) != string(want) {
		t.Fatalf("existing output changed: got=%q err=%v", got, err)
	}

	nonregular := filepath.Join(parent, "directory.tar")
	if err := os.Mkdir(nonregular, 0o700); err != nil {
		t.Fatalf("create nonregular output: %v", err)
	}
	if err := WriteNewBundle(nonregular, []byte("replacement")); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("nonregular output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if info, err := os.Lstat(nonregular); err != nil || !info.IsDir() {
		t.Fatalf("nonregular output changed: info=%v err=%v", info, err)
	}
}

func TestWriteNewBundleDoesNotClobberSymlinkDestinationWhenAvailable(t *testing.T) {
	parent := t.TempDir()
	want := []byte("existing-content")
	victim := filepath.Join(parent, "victim.txt")
	if err := os.WriteFile(victim, want, 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	linkedOutput := filepath.Join(parent, "linked.tar")
	if err := os.Symlink(victim, linkedOutput); err != nil {
		return
	}
	if err := WriteNewBundle(linkedOutput, []byte("replacement")); domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("linked output code = %q: %v", domain.ErrorCodeOf(err), err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != string(want) {
		t.Fatalf("symlink victim changed: got=%q err=%v", got, err)
	}
}

func TestWriteNewPublicKeyFailuresNeverExposePartialFinal(t *testing.T) {
	_, privateKey := generateKey(t)
	publicKeyPEM := publicKeyPEMForTest(t, privateKey)
	for _, test := range []struct {
		name      string
		configure func(*bundleFileOperations)
	}{
		{
			name: "short write",
			configure: func(operations *bundleFileOperations) {
				operations.createTemp = func(directory, pattern string) (temporaryBundleFile, error) {
					file, err := os.CreateTemp(directory, pattern)
					if err != nil {
						return nil, err
					}
					return &failingTemporaryFile{File: file, shortWrite: true}, nil
				}
			},
		},
		{
			name: "sync failure",
			configure: func(operations *bundleFileOperations) {
				operations.createTemp = func(directory, pattern string) (temporaryBundleFile, error) {
					file, err := os.CreateTemp(directory, pattern)
					if err != nil {
						return nil, err
					}
					return &failingTemporaryFile{File: file, syncError: errors.New("injected sync failure")}, nil
				}
			},
		},
		{
			name: "publication failure",
			configure: func(operations *bundleFileOperations) {
				operations.publish = func(string, string) (bool, error) {
					return false, errors.New("injected publication failure")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			output := filepath.Join(parent, "signer-public.pem")
			operations := defaultBundleFileOperations()
			test.configure(&operations)
			err := writeNewPublicKey(output, publicKeyPEM, operations)
			if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
				t.Fatalf("error code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
			}
			if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
				t.Fatalf("failure exposed a final public key: %v", statErr)
			}
			temporaryMatches, globErr := filepath.Glob(filepath.Join(parent, ".repopass-public-key-*"))
			if globErr != nil || len(temporaryMatches) != 0 {
				t.Fatalf("public-key temporary files remain: matches=%v err=%v", temporaryMatches, globErr)
			}
		})
	}
}

func TestWriteSigningArtifactsBundleFailureRetainsOnlyCompletePublicKey(t *testing.T) {
	_, privateKey := generateKey(t)
	publicKeyPEM := publicKeyPEMForTest(t, privateKey)
	parent := t.TempDir()
	bundlePath := filepath.Join(parent, "bundle.tar")
	publicPath := filepath.Join(parent, "signer-public.pem")
	publicOperations := defaultBundleFileOperations()
	bundleOperations := defaultBundleFileOperations()
	bundleOperations.publish = func(string, string) (bool, error) {
		return false, errors.New("injected bundle publication failure")
	}
	err := writeSigningArtifacts(
		bundlePath,
		[]byte("complete-bundle"),
		publicPath,
		publicKeyPEM,
		publicOperations,
		bundleOperations,
	)
	if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("error code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
	}
	typed, ok := err.(*domain.Error)
	if !ok || typed.Details["publicKeyPublished"] != true ||
		typed.Details["publicKeyDurability"] != "confirmed" {
		t.Fatalf("retained companion details = %#v", err)
	}
	if got, readErr := os.ReadFile(publicPath); readErr != nil || string(got) != string(publicKeyPEM) {
		t.Fatalf("retained public companion is incomplete: got=%q err=%v", got, readErr)
	}
	if _, statErr := os.Lstat(bundlePath); !os.IsNotExist(statErr) {
		t.Fatalf("failed bundle publication exposed a bundle: %v", statErr)
	}
}

func TestWriteSigningArtifactsPreflightRejectsCollisionAndUnsafeDestinations(t *testing.T) {
	_, privateKey := generateKey(t)
	publicKeyPEM := publicKeyPEMForTest(t, privateKey)
	for _, test := range []struct {
		name    string
		prepare func(string) (string, string)
	}{
		{
			name: "bundle public collision",
			prepare: func(parent string) (string, string) {
				shared := filepath.Join(parent, "shared-output")
				return shared, shared
			},
		},
		{
			name: "existing public output",
			prepare: func(parent string) (string, string) {
				publicPath := filepath.Join(parent, "existing-public.pem")
				if err := os.WriteFile(publicPath, []byte("preserve"), 0o600); err != nil {
					t.Fatalf("write existing public output: %v", err)
				}
				return filepath.Join(parent, "bundle.tar"), publicPath
			},
		},
		{
			name: "nonregular public output",
			prepare: func(parent string) (string, string) {
				publicPath := filepath.Join(parent, "public-directory")
				if err := os.Mkdir(publicPath, 0o700); err != nil {
					t.Fatalf("create public output directory: %v", err)
				}
				return filepath.Join(parent, "bundle.tar"), publicPath
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			bundlePath, publicPath := test.prepare(parent)
			err := WriteSigningArtifacts(bundlePath, []byte("complete-bundle"), publicPath, publicKeyPEM)
			if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
				t.Fatalf("code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
			}
			if _, statErr := os.Lstat(bundlePath); !os.IsNotExist(statErr) {
				t.Fatalf("preflight failure created bundle: %v", statErr)
			}
		})
	}

	t.Run("symlink public output", func(t *testing.T) {
		parent := t.TempDir()
		victim := filepath.Join(parent, "victim")
		want := []byte("preserve")
		if err := os.WriteFile(victim, want, 0o600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		publicPath := filepath.Join(parent, "linked-public.pem")
		if err := os.Symlink(victim, publicPath); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		bundlePath := filepath.Join(parent, "bundle.tar")
		err := WriteSigningArtifacts(bundlePath, []byte("complete-bundle"), publicPath, publicKeyPEM)
		if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
			t.Fatalf("code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
		}
		if got, readErr := os.ReadFile(victim); readErr != nil || string(got) != string(want) {
			t.Fatalf("symlink victim changed: got=%q err=%v", got, readErr)
		}
		if _, statErr := os.Lstat(bundlePath); !os.IsNotExist(statErr) {
			t.Fatalf("symlink preflight failure created bundle: %v", statErr)
		}
	})

	t.Run("malformed public content", func(t *testing.T) {
		parent := t.TempDir()
		bundlePath := filepath.Join(parent, "bundle.tar")
		publicPath := filepath.Join(parent, "public.pem")
		err := WriteSigningArtifacts(bundlePath, []byte("complete-bundle"), publicPath, []byte("not a public key\n"))
		if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
			t.Fatalf("code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
		}
		for _, path := range []string{bundlePath, publicPath} {
			if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
				t.Fatalf("malformed content created %s: %v", filepath.Base(path), statErr)
			}
		}
	})
}

func assertPublishedBuildFailure(t *testing.T, err error, durability string) {
	t.Helper()
	if domain.ErrorCodeOf(err) != domain.CodeEvidenceBuildFailed {
		t.Fatalf("error code = %q, want %q: %v", domain.ErrorCodeOf(err), domain.CodeEvidenceBuildFailed, err)
	}
	typed, ok := err.(*domain.Error)
	if !ok || typed.Details["published"] != true || typed.Details["durability"] != durability {
		t.Fatalf("published failure details = %#v, want published=true durability=%q", typed, durability)
	}
}
