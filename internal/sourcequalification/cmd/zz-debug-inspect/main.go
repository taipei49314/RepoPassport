package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/sourcequalification"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: zz-debug-inspect ROOT BASE TESTED")
		os.Exit(2)
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		fmt.Printf("INSPECT_ERR=abs: %v\n", err)
		os.Exit(1)
	}
	snapshot, err := sourcequalification.InspectRepository(sourcequalification.RepositoryRequest{
		Root:                   root,
		ExpectedBaseRevision:   os.Args[2],
		ExpectedTestedRevision: os.Args[3],
	})
	if err != nil {
		fmt.Printf("INSPECT_ERR=%v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"INSPECT_OK files=%d tree=%s head=%s dirty=%t\n",
		len(snapshot.Files),
		snapshot.Subject.TreeSHA,
		snapshot.Subject.TestedRevision,
		snapshot.Subject.Dirty,
	)
}
