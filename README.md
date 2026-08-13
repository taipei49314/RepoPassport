# RepoPassport

Local-first tooling to **describe, plan, run, and independently verify** a repository
scenario — with evidence that a workload cannot forge from inside the sandbox.

> **Canonical source and Go module:**
> `github.com/taipei49314/RepoPassport`. Repository-owned imports, release
> build information, and the public `schemas` package use this exact,
> case-sensitive namespace.

[![CI](https://github.com/taipei49314/RepoPassport/actions/workflows/ci.yml/badge.svg)](https://github.com/taipei49314/RepoPassport/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/status-v1alpha1-orange.svg)](docs/release.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Six questions (kept separate)

- Did the declared journey **work**?
- Did the workload stay within its declared **capabilities**?
- Was the result **reproducible**?
- Was **cleanup** complete?
- What **evidence** exists, and who signed it?
- Is that evidence still **current**?

Functional success never overrides a capability violation. Missing observation
coverage never becomes a pass.

The complete roadmap scope is frozen in the canonical
[`acceptance-registry.json`](acceptance-registry.json) as exactly 37 required
rows. CI emits a current-source, producer-owned evaluation of that registry;
an honest `INCOMPLETE` evaluation is expected while later milestones and
external qualification remain unfinished. It is not a release approval or a
substitute for the independent `RP-Q-*` gates.

> **Status:** working `v1alpha1` vertical slice (`v0.1.0-alpha`).  
> Supported path is intentionally narrow: local source snapshots, static
> Node/Python discovery, deterministic plans, dependency-free CLI journeys, and
> one attached HTTP service on exact built-in Linux `amd64` runtime tuples.  
> Built-in observer coverage remains incomplete — a functional pass is capability
> `incomplete` and overall `inconclusive`, not "overall verified."  
> Alpha history: [CHANGELOG.md](CHANGELOG.md).

## Quick start

Prerequisites:

- the Go version declared by `go.mod`
- Docker or Podman with a Linux engine **only** for live verification

```bash
git clone https://github.com/taipei49314/RepoPassport.git
cd RepoPassport

gofmt -w .
go vet ./...
go test ./...

# Inspect / validate a healthy fixture
go run ./cmd/repopass inspect ./testdata/fixtures/healthy/healthy-node-cli --output json
go run ./cmd/repopass validate ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml
```

Go consumers of the public strict validators use the canonical package:

```go
import "github.com/taipei49314/RepoPassport/schemas"
```

Target verification flow:

```bash
go run ./cmd/repopass plan \
  --manifest ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml \
  --scenario quickstart \
  --write-lock

# The alpha runner never pulls during execution. Pre-pull the exact
# Node/Python linux/amd64 tuples listed in docs/release.md first.

go run ./cmd/repopass verify \
  --manifest ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml \
  --scenario quickstart \
  --output json
```

Without `--fail-on`, a completed verification exits zero and callers must read
the structured verdict. CI should normally add
`--fail-on functional-fail,blocked,nonconforming,inconclusive`.

Five-minute walkthrough: [docs/quickstart.md](docs/quickstart.md).  
Release / runtime tuples: [docs/release.md](docs/release.md).

### Attestation (optional, after a run)

```bash
go run ./cmd/repopass --data-dir <authoritative-data-dir> attest \
  --run <run-id> \
  --key <private-pkcs8.pem> \
  --out <new-bundle.tar> \
  --public-key-out <new-public-spki.pem>

go run ./cmd/repopass verify-attestation <new-bundle.tar> \
  --expect-bundle-digest sha256:<64-lowercase-hex> \
  --trust-key <new-public-spki.pem>
```

Trust is never inferred from "signature looks valid alone." Without an explicit
trust key / signed policy path, a cryptographically valid bundle still fails
verification with trust `unknown`.

## Trust model

Repository files, manifests, logs, filenames, URLs, and generated artifacts are
untrusted input. RepoPassport's resolver, policy evaluator, verifier, and
evidence builder run outside the workload. A workload cannot award itself a
`PASS` by writing a result file.

The initial implementation aims to preserve these invariants:

- source snapshots are immutable during a run;
- repository commands are never executed by `inspect`;
- commands are represented as argument arrays, not inferred shell snippets;
- host credentials, home directories, engine sockets, and devices are not
  mounted into workloads;
- the exact selected runtime image, its language runtime, and fixed `/bin/tar`
  export helper are explicitly allowlisted parts of the local trusted computing
  base; a digest alone is not a trust decision;
- required runner features are checked before execution and observer gaps remain
  explicit in verification;

<details>
<summary>Additional trust-boundary and observer limits</summary>

- resource-limit enforcement and resource-usage observation are independent:
  enforcement alone never supplies `ResourceUsage` coverage, and an incomplete
  resource sample never becomes a zero-valued observation;
- retained-state observation and filesystem-write observation are independent:
  a complete bounded `/outputs` snapshot pair gives the retained-state summary
  event coverage `high` but only composite filesystem-write `best-effort`; it cannot establish
  operation history or undeclared-write conformance;
- Docker `/outputs` activity tracing is a bounded trusted-helper observation:
  strict `READY`/`FINAL` JSONL, identity and quiescence checks, and fail-closed
  overflow/gap handling can provide only aggregate `best-effort` notification
  hints, never filesystem operation or syscall history;
- Docker TCP listener tracing for the supported single-service HTTP profile is
  a bounded controller-owned peer observation: the peer shares only the
  target network namespace, strict `READY`/`FINAL` and identity/isolation/
  quiescence/cleanup gates apply to the whole result, and the aggregate
  evidence can provide only `best-effort` port observation, never complete
  socket history, UDP coverage, or process attribution;
- Docker engine-diff observation is independently bounded and opaque: only the
  exact `docker container diff <immutable-64hex-id>` control call is allowed,
  raw output and paths are never public evidence, and only an identity-bound
  post-quiescence/pre-repair final transcript may contribute `best-effort`;
- the `alpha.10` profile retains one attached repository service as UID/GID
  `65532` and a bounded controller-supplied HTTP helper as UID/GID `65533`
  inside the same network-disabled sandbox;
- controller-supplied Python helpers use isolated mode (`python -I -S`) with
  working directory `/`, so repository modules in `/workspace` cannot hijack
  their imports;
- each readiness/request timeout is an absolute wall-clock deadline, not a
  socket-inactivity timer. Runner-owned helper slack is reserved only to stop
  and account for the helper after that functional deadline. HTTP timeouts
  must resolve to whole milliseconds of at least 1 ms: `1.5s` is valid because
  it is 1,500 ms, while `1.5ms` is invalid. Readiness is capped at 2 minutes,
  retries use bounded exponential backoff, and no more than 128 attempts are
  made. Each explicit per-request timeout and the resolved exercise fallback
  used when it is omitted are capped at 30 minutes; that fallback is
  `phases.exercise.timeout`, or 1 minute when the phase timeout is absent;
- an HTTP journey contains at most 128 ordered steps and 32 requests. Expected
  readiness/response status values are 200–599. Effective headers must
  simultaneously satisfy count ≤ 64 and aggregate bytes ≤ 65,536, with each
  value capped at 8,192 bytes. The aggregate is the sum of
  `len(name bytes) + len(value bytes) + 4` for every effective header; accepted
  names and values are ASCII, so these are also their UTF-8 byte lengths. The
  driver's automatic JSON `content-type` is included in both the count and
  aggregate. A text request body and the actual serialized bytes of a JSON
  request are each capped at 1 MiB. Response header `contains` values are
  capped at 8,192 bytes, and non-empty `bodyContains` values at 1 MiB;
- before a readiness retry or cleanup begins, the UID/GID `65533` driver must
  have exited synchronously or be quiesced by a trusted root helper; inability
  to confirm either outcome fails closed;
- an HTTP `fileExists` assertion is evaluated at its ordered journey step by a
  trusted `lstat` walk confined to `/outputs`. Its normalized UTF-8 path is at
  most 4,096 bytes, and a symlink in any path component cannot satisfy it;
- structured response assertions support a singular JSONPath subset
  (`$`, dot/bracket members, and non-negative array indexes) and offline
  Draft 2020-12 JSON Schema. JSON is decoded strictly with exact numbers;
  duplicate keys, trailing data, excessive depth/nodes, decimal exponents
  outside `-1000..1000`, unsupported JSONPath operators, external/dynamic
  schema references, and schemas over 256 KiB fail closed. The resolved plan
  binds schema path, digest, dialect, and validator version;
- CLI `stdoutJsonSchema` uses the same offline Draft 2020-12 validator and
  strict JSON limits against the complete captured stdout. Shared log
  truncation is inconclusive, while a complete malformed or mismatching
  document fails. Evidence records only the sealed schema binding and safe
  booleans/failure kind, never stdout content, parsed values, property names,
  a stdout hash, or a stdout byte count;
- ordered `jsonFile` reads one regular file below `/outputs` through a bounded
  dirfd/`O_NOFOLLOW` helper, verifies its size and SHA-256 in the controller,
  and validates the point-in-time snapshot against the plan-bound schema.
  File JSON is capped at 1 MiB. Raw response/file JSON and extracted values
  are not copied into assertion evidence;
- HTTP cleanup applies the declared service signal and grace period, escalates
  surviving UID/GID `65532` processes to `SIGKILL`, and performs final
  workload quiescence. Delivered success requires `initialTargets >= 1` and
  `1 <= sent <= initialTargets`; a target/disappearance race fails closed for
  direct helper calls. Runner-owned attached-service finalization may privately
  authorize the exact quiescent no-op described above, but still waits for the
  attached execution. Every signal type, including `kill`, requires a
  whole-millisecond grace period from 1 ms through 10 seconds. The service
  signal is the final resolved command, and the runner retains separate helper
  slack;
- `service.start` is recorded as succeeded only after the declared readiness
  status has been observed; merely launching the attached process is not
  service-start success;
- verdict dimensions and observation coverage remain visible in structured
  output;
- a local Alpha.15 attestation is a deterministic offline wrapper around one
  authoritative historical verification. Its Ed25519 signature and explicit
  SPKI trust decision do not establish freshness, re-run the scenario, recover
  the source's former local path, or upgrade any original verdict. A sealed
  `sbom` selection may bind one strict caller-supplied SPDX 2.3 derivative;
- JSON, text, and static HTML reports derive from the same verification model.

</details>

Read the full [security model](docs/security-model.md) and
[security policy](SECURITY.md).

## Repository map

```text
cmd/              CLI entry points
internal/         reference implementation and application ports
schemas/          machine-readable contracts
spec/             normative behavior
testdata/         healthy, invalid, nonconforming, and malicious fixtures
docs/             user, maintainer, architecture, and security guidance
.codex/skills/    repo-local agent workflow
```

Normative behavior belongs in `spec/`; machine validation belongs in
`schemas/`. Implementation behavior must not silently redefine either.

## Fixture highlights

- `healthy-node-cli`: dependency-free Node CLI that writes a declared output
  and exercises a plan-bound stdout JSON Schema assertion.
- `healthy-python-cli`: dependency-free Python CLI that persists setup state
  into the exercise phase and writes a declared output.
- `healthy-node-http` / `healthy-python-http`: single-service HTTP journeys with
  trusted assertions (`status`, headers, `bodyContains`, `fileExists`, JSONPath,
  schemas, ordered `jsonFile` as applicable).
- `invalid/*`: must fail closed (unknown fields, literal secrets, ...).
- `malicious/*`: forged verification JSON, undeclared residue, undeclared retained
  writes — workload self-judgment must not produce a trusted pass.

Fixtures are documentation as well as tests. Each fixture includes its expected
classification and is designed to run without package installation.

## Project principles

- Declarations are not evidence.
- The workload does not judge itself.
- Models and adapters may propose; only the verifier decides.
- `UNKNOWN` or `INCOMPLETE` is better than a false pass.
- Verification and interactive trial are different products.
- Evidence should be portable and independently checkable.
- RepoPassport does not publish a single "security score."

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Schema semantics, verdict
aggregation, evidence predicates, core policy, trust boundaries, plugin
protocol, runner conformance, and breaking CLI/API changes require an RFC.

## License

Licensed under the [Apache License 2.0](LICENSE).
