package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/taipei49314/RepoPassport/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	app := cli.App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(app.RunVerifier(ctx, os.Args[1:]))
}
