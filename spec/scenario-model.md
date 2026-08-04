# Scenario and Command Model

A scenario is a deterministic journey declaration. It does not contain a script template and it cannot supply its own verdict.

## Phase order

The canonical phase order is:

```text
prepare -> setup -> build -> run -> exercise -> cleanup -> finalize
```

`finalize` is controller-owned and never appears in a manifest. The public
schema recognizes `prepare`, `setup`, `build`, `run`, `exercise`, and
`cleanup`.

The `v0.1.0-alpha.3` reference executable profile runs foreground argv commands
in declared phase order, a CLI exercise command, or one constrained attached
HTTP service and HTTP exercise journey. Only the matching HTTP cleanup signal
is executable. Explicit shells, stdin fixtures, synthetic-secret injection,
multiple services, and the richer assertion surface remain contract shape for
later profiles. They must fail closed with a stable unsafe or unavailable
error; they must never be silently omitted from a verification.

If any functional phase fails:

1. The orchestrator stops later functional work.
2. It still runs safety cleanup.
3. It preserves completed observations.
4. The verifier selects `fail`, `blocked`, or `inconclusive` from the failure semantics; it does not infer success from an exit code alone.

## Phase forms

`prepare`, `setup`, `build`, and `cleanup` are step phases:

```yaml
setup:
  timeout: 5m
  steps:
    - id: install
      run:
        command: [pnpm, install, --frozen-lockfile]
```

`run` may contain ordered `steps`, one long-running `service`, or both:

```yaml
run:
  timeout: 2m
  service:
    id: app
    command: [pnpm, start]
    readiness:
      http:
        url: http://127.0.0.1:3000/health
        status: 200
        timeout: 30s
```

`exercise` contains exactly one CLI or HTTP driver. `cleanup` may signal a service:

```yaml
cleanup:
  timeout: 30s
  steps:
    - id: stop-app
      signal:
        target: app
        type: term
        gracePeriod: 5s
```

Signal enum values are lowercase: `term`, `kill`, `int`, and `hup`. In the
`alpha.3` executable subset, exactly one cleanup signal must target the
scenario's one HTTP service. Signal steps in other phases or without that
service lifecycle fail closed. Every signal type, including `kill`, requires a
`gracePeriod` that resolves to a whole number of milliseconds from 1 ms through
10 seconds.

Each phase may additionally declare:

- `timeout`;
- `observerRequirements[]`, each with an observer and minimum coverage;
- `outputs[]`, the declared sandbox output paths.

## Command form

The default and currently executable form is an argv array:

```yaml
steps:
  - id: launch
    run:
      command: [python, -m, app]
```

There is no string splitting, interpolation, glob expansion, variable expansion, command substitution, or implicit shell.

The public contract reserves an explicit shell alternative:

```yaml
steps:
  - id: launch-through-shell
    run:
      shell:
        executable: /bin/sh
        command: "python -m app"
```

`command` and `shell` are mutually exclusive. A profile that implements shell
execution must lock an absolute shell executable and produce a risk warning.
The current reference profile rejects it with `MANIFEST_UNSAFE_SHELL`. A runner
MUST NOT convert an argv command to shell text.

Environment members are references, not values:

```yaml
environment:
  INPUT_PATH:
    source: input
    name: source-file
  API_KEY:
    source: secret
    name: api-key
```

The allowed sources in the full contract are `input` and `secret`. A profile
that implements them retains only reference metadata in the plan and injects
values ephemerally. The current reference profile rejects command environment
references and synthetic-secret injection as unavailable.

The complete v1alpha1 target materializes these omitted execution defaults into
the lockfile:

| Field | Default |
|---|---|
| `workingDirectory` | `/workspace` |
| `timeout` | Versioned policy default for the phase |
| `allowedExitCodes` | `[0]` |
| `outputMode` | `text` |

The current reference plan records phase, step ID, argv, phase timeout, and
foreground/journey role. The richer command fields above remain outside its
executable profile.

## CLI driver

A CLI driver declares an argv command and at least one assertion:

```yaml
exercise:
  driver:
    type: cli
    command: [python, -m, app, convert, /inputs/a.json]
    assertions:
      - id: exited-cleanly
        exitCode: 0
      - id: announced-completion
        stdoutContains: completed
      - id: result-created
        fileExists: /outputs/result.json
```

The current executable CLI assertions are:

- exit code;
- stdout contains or regex;
- stderr contains;
- output file existence;

The public schema also reserves stdout JSON Schema, stderr regex, and JSON-file
assertions. Those operations are unavailable in the current runner. An
assertion object has one assertion operation plus `id`; current executable
assertions are required. Explicit optional assertions are rejected until their
aggregation semantics are implemented. Regexes use Go's RE2 engine and invalid
patterns fail before execution.

The current Docker/Podman backend always treats exit statuses 125, 126, and 127
as reserved operational failures. A journey assertion cannot convert one into a
trusted workload exit. A future backend may support that range only with a
runner-owned mechanism that distinguishes engine/exec setup failure from the
workload's status.

`stdinFixture` is a reserved declaration for bounded input from the immutable
source snapshot. The current executable profile rejects it as unavailable.

## HTTP driver

The `alpha.3` executable HTTP profile is limited to one attached service under
an exact approved Node or Python Linux `amd64` runtime/image tuple. Repository
service code runs as non-root UID/GID `65532`. The bounded, controller-supplied
readiness/request helper is trusted driver code; it runs synchronously as the
separate non-root UID/GID `65533` and exits after each operation.
On the Python tuple, every controller-supplied helper MUST use isolated mode
and skip automatic `site` initialization (`python -I -S`) with working
directory `/`; it MUST NOT resolve imports through `/workspace`.

Each readiness/request timeout is an absolute wall-clock deadline for the
operation. It MUST NOT be implemented as a socket-inactivity timer that resets
when traffic progresses. Runner-owned helper slack MAY follow the functional
deadline only to cancel, quiesce, and confirm helper exit. Before another
readiness attempt or cleanup, UID/GID `65533` MUST have exited synchronously or
been quiesced by a trusted root helper; inability to prove either state MUST
fail closed. Every HTTP timeout MUST resolve to a whole number of milliseconds
and MUST be at least 1 ms. A fractional-second value such as `1.5s` is valid
because it resolves to 1,500 ms; a fractional-millisecond value such as
`1.5ms` is invalid. Readiness timeout MUST NOT exceed 2 minutes. Each explicit
request timeout MUST NOT exceed 30 minutes. If a request omits `timeout`, its
resolved fallback MUST be `phases.exercise.timeout`, or 1 minute when that
field is absent, and that fallback MUST also be no greater than 30 minutes.

HTTP requests and assertions are separate ordered steps:

```yaml
exercise:
  driver:
    type: http
    steps:
      - request:
          id: import-sample
          method: post
          url: http://127.0.0.1:3000/import
          json:
            folder: /inputs/images
      - assert:
          id: import-status
          response:
            requestId: import-sample
            status: 200
      - assert:
          id: result-created
          fileExists: /outputs/result.json
```

HTTP method enums are lowercase. The schema accepts only loopback HTTP URLs in
v1alpha1. The executable profile further requires literal
`http://127.0.0.1:<explicit-port>` URLs, one declared `127.0.0.1` TCP listener,
matching ports, and one origin for readiness and all requests. Each URL MUST be
canonical and no longer than 2,048 UTF-8 bytes. The service and trusted helper
run in the same container with `--network none`; the runner MUST NOT publish
the service to a host interface merely to exercise it.

An HTTP journey MUST contain no more than 128 ordered steps and no more than 32
request steps. A request's effective header set MUST simultaneously satisfy
count ≤ 64 and aggregate bytes ≤ 65,536; each header value MUST be no longer
than 8,192 bytes. The aggregate MUST equal
`sum(len(name bytes) + len(value bytes) + 4)` over every effective header.
Accepted names and values are ASCII, so those lengths are also their UTF-8 byte
lengths. The trusted driver's automatic JSON `content-type` MUST participate
in both the count and aggregate. Readiness and response status expectations
MUST be in the range 200–599. A text request body MUST be no larger than 1 MiB
in UTF-8. For a `json` request, the actual serialized JSON byte sequence MUST
be no larger than 1 MiB; the limit is applied after serialization, not
estimated from the source shape.

The executable response assertions are status, one header substring,
`bodyContains`, singular `jsonPath.equals`, and offline Draft 2020-12
`jsonSchema`. `fileExists` and `jsonFile` may follow HTTP requests, and each
MUST be evaluated when its ordered step is reached. A response header
`contains` value MUST be no
longer than 8,192 UTF-8 bytes. `bodyContains` MUST be non-empty and no larger
than 1 MiB in UTF-8. The trusted file check MUST accept only a normalized UTF-8
`/outputs` path no longer than 4,096 bytes, use `lstat` without following each
path component, and reject any symlink.

`jsonPath` MUST be a singular expression no longer than 1,024 UTF-8 bytes and
64 selectors: `$`, dot/quoted-bracket members, and non-negative array indexes.
Wildcard, slice, union, filter, recursive-descent, and function syntax MUST
fail closed. Strict JSON input MUST be at most 1 MiB, preserve exact JSON
numbers, distinguish missing from `null`, and reject duplicate keys, trailing
values, invalid UTF-8, structures beyond the declared depth/node limits, and
explicit or effective decimal exponents outside `-1000..1000`. Planning MUST
apply the same strict profile to canonicalized `jsonPath.equals` values that
execution revalidates.

Schema files MUST be regular portable source files no larger than 256 KiB.
The resolved plan MUST bind path, SHA-256, Draft 2020-12 dialect, and validator
version, and execution MUST revalidate the copied immutable snapshot before a
workload container starts. Only same-document fragment `$ref` is supported;
remote, cross-file, dynamic, recursive, and custom-vocabulary resolution MUST
fail closed. `jsonFile` MUST target a regular file below `/outputs`, use a
bounded dirfd/`O_NOFOLLOW` read, and be evaluated from that point-in-time
snapshot. Raw JSON and extracted values MUST NOT enter assertion evidence.
Redirect following, TLS, request authentication, arbitrary sandbox file reads,
multiple services, full RFC 9535 JSONPath, and CLI JSON Schema assertions are
outside this profile and MUST NOT be silently emulated.

Request and response bodies, headers, and logs are untrusted and bounded.
The trusted helper control channel MUST accept exactly one complete success or
failure object and MUST reject missing, duplicate, unknown, wrong-union, or
trailing fields before an assertion consumes the response. Renderers escape
untrusted fields. Authentication-bearing headers are rejected. A future
secret-bearing request implementation must use runner injection rather than
literal credentials in the manifest.

## Readiness

The HTTP readiness probe is independent of the functional journey. It uses the
same bounded trusted helper and literal loopback origin. A successful readiness
status means only that the service is ready for exercise. It is not a
functional PASS. Retries MUST use exponential backoff bounded by the remaining
absolute readiness deadline and MUST stop after at most 128 attempts. A
`service.start` lifecycle observation MUST NOT be marked `succeeded` when the
process is merely launched; it becomes `succeeded` only after readiness
succeeds.

A service that exits before readiness produces `SERVICE_START_FAILED`. A
service that remains alive but does not return the declared readiness status
before its bounded deadline produces `READINESS_FAILED`.

## HTTP cleanup

The profile requires exactly one cleanup signal targeting the declared
service. The trusted helper sends the declared signal, waits the declared grace
period, and escalates remaining UID/GID `65532` workload processes to
`SIGKILL`. It MUST identify at least one workload target and successfully
deliver at least one signal. If targets disappear between enumeration and
delivery so no send can be confirmed, that enumeration/delivery race MUST make
cleanup fail closed. The UID/GID `65533` HTTP helper is synchronous and must
already have exited.
Signal success requires `initialTargets >= 1` and `sent >= 1`; it MUST NOT
require a successful send to every initially enumerated target.
Controller-owned finalization then quiesces remaining UID/GID `65532` workload
processes before output export and forced container removal. Cleanup still runs
after readiness or functional failure.

The service signal MUST be the final cleanup step and final resolved command.
Every signal type, including `kill`, MUST declare a grace period that resolves
to a whole number of milliseconds from 1 ms through 10 seconds. The runner
MUST reserve a separate bounded interval for signal-helper completion; grace
MUST NOT consume the entire cleanup deadline.

This lifecycle is enforcement and functional evidence, not complete process
observation. The built-in filesystem-write and port-listen observers remain
unavailable, foreground process coverage remains best effort, and resource
usage remains enforcement-only. Therefore an HTTP functional pass is
capability `incomplete` and overall `inconclusive`.

## Repetition

Each repeat uses:

- the same source, plan, policy, runner profile, and observer set;
- a fresh workspace and sandbox;
- deterministic fixtures;
- independent observations and assertion results.

The verifier MUST NOT select the best run. Repetition compares semantic
assertion outcomes, excluding per-run duration, message text, and evidence
references. `flaky` is a reproducibility verdict, never a functional verdict.
An inconsistent functional result is `inconclusive` with reproducibility
`flaky`.
