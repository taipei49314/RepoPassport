//go:build unix

package releasestate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixRejectsUnsafePermissions(t *testing.T) {
	for _, target := range []string{"data-root", "state-root", "state-file", "lock-file"} {
		t.Run(target, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "controller-data")
			if _, err := ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 1, testDigestA); err != nil {
				t.Fatal(err)
			}
			stateDirectory, err := stateRoot(context.Background(), root, policyState)
			if err != nil {
				t.Fatal(err)
			}
			path := root
			switch target {
			case "state-root":
				path = stateDirectory
			case "state-file":
				path = filepath.Join(stateDirectory, stateKey(testAuthorityA, "repopass", "alpha")+".json")
			case "lock-file":
				path = filepath.Join(stateDirectory, stateKey(testAuthorityA, "repopass", "alpha")+".lock")
			}
			if err := os.Chmod(path, 0o777); err != nil {
				t.Skipf("cannot change permissions: %v", err)
			}
			result, err := ObservePolicy(context.Background(), root, testAuthorityA, "repopass", "alpha", 2, testDigestB)
			if !errors.Is(err, ErrUnavailable) || result.Evaluation != EvaluationUnavailable {
				t.Fatalf("unsafe %s = %#v, %v", target, result, err)
			}
		})
	}
}
