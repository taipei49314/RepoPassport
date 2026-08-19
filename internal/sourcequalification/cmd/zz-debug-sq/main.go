package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/taipei49314/RepoPassport/internal/sourcequalification"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: zz-debug-sq gotest ROOT [go-test-args...] | zz-debug-sq download ROOT BASE TESTED | zz-debug-sq remaining ROOT BASE TESTED")
		os.Exit(2)
	}
	root, err := filepath.Abs(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs: %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "gotest":
		args := []string{"test", "-count=1", "-timeout=8m", "-failfast", "./..."}
		if len(os.Args) > 3 {
			args = os.Args[3:]
		}
		report, err := sourcequalification.DebugNetworkNoneGoTest(ctx, root, args, 10*time.Minute)
		fmt.Print(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gotest: %v\n", err)
			os.Exit(1)
		}
	case "download":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: zz-debug-sq download ROOT BASE TESTED")
			os.Exit(2)
		}
		report, err := sourcequalification.DebugIsolatedModuleDownload(ctx, root, os.Args[3], os.Args[4])
		fmt.Print(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "download: %v\n", err)
			os.Exit(1)
		}
	case "remaining":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: zz-debug-sq remaining ROOT BASE TESTED")
			os.Exit(2)
		}
		report, err := sourcequalification.DebugIsolatedRemainingGates(ctx, root, os.Args[3], os.Args[4])
		fmt.Print(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "remaining: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
