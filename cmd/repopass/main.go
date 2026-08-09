package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/taipei49314/RepoPassport/internal/cli"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/execution"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	app := cli.App{
		Deps: cli.Dependencies{
			ProbeAll: func(ctx context.Context) ([]domain.RunnerFeatures, error) {
				return execution.DetectBackends(ctx), nil
			},
			ProbeBackend: func(ctx context.Context, backend string) ([]domain.RunnerFeatures, error) {
				features, err := execution.Doctor(ctx, backend)
				if err != nil {
					return nil, err
				}
				return []domain.RunnerFeatures{features}, nil
			},
			Execute: execute,
		},
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	}
	os.Exit(app.Run(ctx, os.Args[1:]))
}

func execute(
	ctx context.Context,
	plan domain.ResolvedPlan,
	sourceRoot string,
	runRoot string,
	backend string,
) (cli.RunnerOutcome, error) {
	outcome, err := execution.Execute(ctx, plan, sourceRoot, runRoot, backend)
	return cli.RunnerOutcome{
		Runner:       outcome.Runner,
		Observations: outcome.Observations,
		Assertions:   outcome.Assertions,
		Errors:       outcome.Errors,
		Resources:    outcome.Resources,
		Completed:    !outcome.CompletedAt.IsZero(),
		Cleanup:      outcome.Cleanup,
	}, err
}
