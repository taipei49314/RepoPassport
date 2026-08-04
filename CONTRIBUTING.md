# Contributing to RepoPassport

Thank you for helping build a repository contract and verification layer that
is useful without overstating what it knows.

## Before you start

Read:

- [README.md](README.md);
- [docs/architecture.md](docs/architecture.md);
- [docs/security-model.md](docs/security-model.md);
- the normative documents under `spec/`.

Open an issue before a large change. Use a short-lived branch and keep each pull
request focused.

An RFC is required for:

- manifest schema semantics;
- verdict aggregation or precedence;
- evidence predicates or digest layout;
- core policy and trust-boundary changes;
- runner conformance requirements;
- plugin protocol changes;
- breaking CLI or HTTP API changes.

Implementation code cannot silently redefine a normative document. If behavior
and spec differ, update the spec through the appropriate review first.

## Development checks

Use the Go version declared in `go.mod`.

```bash
gofmt -w .
go vet ./...
go test ./...
```

Container integration tests are opt-in because they execute fixture workloads:

```bash
go test -tags=integration ./...
```

Run them only on an isolated Linux development environment with the container
backend configured by the test harness. Do not run malicious fixture programs
directly on the host.

## Change guidelines

- Keep domain packages free of Docker, Podman, HTTP framework, and persistence
  implementation types.
- Put interfaces near the core code that consumes them.
- Pass `context.Context` through I/O and execution boundaries.
- Use typed, stable public error codes; messages may improve, codes do not.
- Keep functional, capability, reproducibility, cleanup, evidence, and freshness
  results in separate fields.
- Never infer a pass from absent observations.
- Never execute README code blocks or import repository modules during static
  discovery.
- Prefer argv arrays. Shell execution is outside the initial supported slice.
- Keep structured output versioned and deterministic.
- Treat repository strings as hostile when rendering logs, terminal output, or
  HTML.

## Adding fixtures

Fixtures live under:

```text
testdata/fixtures/
  healthy/
  invalid/
  nonconforming/
  blocked/
  flaky/
  malicious/
```

A fixture should include:

- a minimal repository workload;
- `repo-passport.yml`;
- `fixture.json` with the expected classification and public error code;
- deterministic, synthetic input;
- no external package installation unless the fixture specifically tests setup
  network policy;
- an explanation of the trust property it exercises.

Use full 64-hex `sha256:` image references in manifests. Keep fixtures small and
dependency-free. A malicious fixture must be harmless outside the intended
sandbox and must never need real credentials, public network access, elevated
privileges, or destructive host actions.

For invalid manifests, change one rule at a time. This makes the expected error
unambiguous.

Golden output must normalize timestamps, IDs, temporary paths, and platform
noise. Regenerating golden output without explaining a semantic change is not
acceptable.

## Tests expected with changes

- Unit tests for success and failure paths.
- Contract tests for changed ports or adapters.
- Schema examples for manifest changes.
- Golden fixture updates for observable output changes.
- A malicious or adversarial regression fixture for security fixes.
- Property or fuzz tests for parsers, canonicalization, paths, archives, globs,
  URLs, event input, and evidence input where applicable.

## Pull request checklist

- [ ] Code is formatted and `go vet ./...` passes.
- [ ] Unit and relevant integration tests pass.
- [ ] Structured schemas and generated files do not drift.
- [ ] New public errors are documented with remediation.
- [ ] Security and known-limitations docs reflect changed guarantees.
- [ ] Repository-controlled text remains escaped and redacted.
- [ ] No unpinned GitHub Action, unnecessary workflow permission, secret, or
      writable cross-trust cache was introduced.
- [ ] Normative changes include an accepted RFC when required.

## Security reports

Do not use a public pull request to disclose an unpatched vulnerability. Follow
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the Apache
License 2.0.
