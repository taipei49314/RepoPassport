# Manifest reference

The manifest filename is `repo-passport.yml`. It is a human-readable
declaration, not evidence that the repository behaves as declared.

The current executable profile is `v0.1.0-alpha.26`. It includes CLI journeys
and the single-service HTTP subset documented below; broader public-schema
shapes remain fail-closed.

## Root

The following is a shape fragment, not a standalone valid manifest. The empty
objects must be replaced by the required fields shown in later sections.

```yaml
apiVersion: repopass.dev/v1alpha1
kind: RepositoryPassport
metadata: {}
spec:
  project: {}
  environments: {}
  scenarios: {}
  policies: {}
  evidence: {}
```

Unknown fields are rejected unless their name begins with `x-`. Extensions must
not override core security or verdict semantics.

## Metadata

```yaml
metadata:
  name: local-image-organizer
  displayName: Local Image Organizer
  description: Organizes local images without cloud upload.
  labels:
    category: media
```

Maintainer metadata is declarative and does not establish a verified identity.

## Project

```yaml
spec:
  project:
    kind: web-app
    audiences:
      - end-user
      - developer
    entrypoints:
      - quickstart
```

Initial project kinds include `cli`, `web-app`, `api`, `library`, `notebook`,
`model`, `dataset`, `documentation`, `desktop-app`, `mobile-app`, and
`unknown`. Every `entrypoints` value must name a key under `spec.scenarios`.

## Environment

```yaml
spec:
  environments:
    linux-node:
      platform:
        os: linux
        architecture: amd64
      runtime:
        adapter: node
        version: "22.23.1"
      baseImage:
        reference: docker.io/library/node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3
      resources:
        cpu: 1
        memory: 256MiB
        disk: 1GiB
        pids: 64
```

A verified plan requires a full 64-hex image digest and an exact runtime
version. Mutable tags and runtime ranges may be authoring hints, but the planner
must not produce a formal plan until both are resolved. The executable
`baseline-v1` profile is narrower still: it accepts only the exact Node
22.23.1 and Python 3.12.13 Linux `amd64` tuples listed in
[the release guide](release.md). The allowlist is included in the policy bundle
digest; other pinned images and `arm64` currently fail closed.

Before workload commands run, the local backend probes the selected image and
fails closed if its runtime version differs from the plan. That probe is the
selected image's bounded self-report; it does not establish publisher trust.
An operator must separately trust and pre-pull the exact allowed image. Its
language runtime supplies fixed root helpers and `/bin/tar`, so both are
explicit parts of the local runner trusted computing base.

The public environment schema also recognizes `resources.time`,
`resources.logBytes`, `requiredServices`, and `requiredRunnerFeatures`. They are
not part of the current executable profile and fail closed during planning.
CPU, memory, and PID values become engine create flags. The disk value is bound
into an aggregate engine tmpfs cap shared by `/outputs`, workload home, and
temporary storage. Source, workspace, and input mounts remain read-only. The
current local runner rejects a disk value above 2 GiB. Accepted outputs are
quiesced and streamed as USTAR into a bounded Go safe extractor; engine `cp` is
not used.

## Scenario

This is also a shape fragment. Empty `inputs`, `phases`, `capabilities`, and
`verification` objects are not a complete executable scenario.

```yaml
spec:
  scenarios:
    quickstart:
      title: Process a synthetic message
      description: Writes a deterministic JSON result.
      environment: linux-node
      inputs: {}
      phases: {}
      capabilities: {}
      verification: {}
```

Scenarios are the unit of verification. Results bind a source, scenario,
environment, plan, policy, runner profile, and observer set.

## Inputs

```yaml
inputs:
  message:
    type: file
    required: true
    fixture: fixtures/message.txt
    mount:
      path: /inputs/message.txt
      readOnly: true
```

Input types include `string`, `integer`, `boolean`, `file`, `directory`, `json`,
`secret-reference`, and `choice`. The current executable profile resolves only
read-only file and directory fixtures; other recognized types fail closed as
unavailable. Public verification should use deterministic synthetic fixtures by
default.

The `required` field is required by the public schema. `required: false` is
schema-valid but unavailable in the executable alpha. A `choice` input requires
`choices`; all choice semantics, including a `choices` field attached to a file
or directory input, fail closed rather than being discarded.

## Commands

Use argument arrays:

```yaml
steps:
  - id: run-tool
    run:
      command:
        - node
        - /workspace/cli.mjs
        - /inputs/message.txt
        - /outputs/result.json
```

Static discovery may propose commands but cannot execute them. README shell
blocks are low-trust hints only. Shell execution is an explicit alternate
object, outside the initial supported slice, and must never be inferred. The
current safety policy rejects it during semantic validation with
`MANIFEST_UNSAFE_SHELL`.

The public command object also recognizes `workingDirectory`, input/secret
`environment` references, per-action `timeout`, `allowedExitCodes`, and
`outputMode`. Those fields are schema-valid but planner-gated until they are
bound into the resolved command and enforced by the runner. Foreground argument
arrays and the enclosing phase timeout are the supported command subset.
CLI journey exit-code assertions may declare implemented non-zero exits, but
125–127 remain reserved Docker/Podman operational statuses and always fail
closed in this backend.

The executable HTTP subset requires exactly one cleanup signal targeting its
one declared service. The trusted signal helper applies the declared signal
and grace period, escalates remaining UID/GID `65532` workload processes to
`SIGKILL`, and final safety cleanup quiesces UID/GID `65532` before export.
Signal success requires at least one enumerated workload target and at least
one successful delivery. If targets disappear between enumeration and send so
that delivery cannot be confirmed, cleanup fails closed.
The service signal must be the final cleanup step and final resolved command.
Every signal type, including `kill`, requires a whole-millisecond grace period
from 1 ms through 10 seconds, and the cleanup deadline must retain separate
runner-owned slack for signal-helper completion.
Signal steps outside that HTTP cleanup shape remain planner-gated. Phase-level
`observerRequirements` and `outputs` are also planner-gated.

## CLI exercise

```yaml
phases:
  exercise:
    timeout: 30s
    driver:
      type: cli
      command:
        - node
        - /workspace/cli.mjs
        - /inputs/message.txt
        - /outputs/result.json
      assertions:
        - id: process-exited
          exitCode: 0
        - id: process-reported
          stdoutContains: '"message":"hello repopass"'
        - id: stdout-shape
          stdoutJsonSchema: .repopass/schemas/cli-stdout.schema.json
        - id: result-created
          fileExists: /outputs/result.json
```

Assertions are evaluated by the trusted driver, not by a result file produced
inside the workload.

`stdoutJsonSchema` is a controller-evaluated CLI assertion. Its value is one
portable normalized path to a regular file in the immutable source snapshot;
each path segment is at most 255 bytes and the schema file is at most 256 KiB.
The schema is resolved offline. `$schema` may be omitted; when present, it must
name Draft 2020-12, with an optional trailing `#`. Remote, dynamic, and
cross-file references are rejected.

The controller validates the complete captured stdout as exactly one strict
JSON document. Instance limits are 1 MiB, depth 128, 100,000 nodes, and
explicit/effective decimal exponent `-1000..1000`. Invalid UTF-8, duplicate
keys, trailing content, empty output, and bound violations cannot pass.
Complete malformed JSON and schema mismatch are `failed`. Because stdout and
stderr share one bounded log-capture status, any truncation makes completeness
unknowable and is `inconclusive`, never validation of a prefix.

The resolved plan binds schema path, SHA-256 digest, dialect, and validator
version. Public assertion evidence includes that expected binding and only
safe completeness/match booleans plus a failure kind. It does not include raw
stdout, parsed values, property names, a stdout digest, or byte count. The
verifier integrity-binds the controller result but does not independently
recapture stdout.

Alpha.15 resolved plans use schema version `"4"` and bind the exact evidence
profile/include/exclude selection. Version-1, version-2, and version-3 locks are
historical and fail current checking/execution. Historical Alpha.10 resolved
plans use schema version `"3"` because cleanup classification
is now required plan material. The CLI
journey driver is `0.2.0`; the HTTP journey driver remains `0.1.0`, and the
manifest API remains `repopass.dev/v1alpha1`. Version-1 and version-2 plan
locks produce `PLAN_DRIFT` and must be regenerated; old evidence remains a
historical, read-only integrity record.

## HTTP service and exercise

`v0.1.0-alpha.19` retains exactly one attached HTTP service for the approved
Node or Python Linux `amd64` runtime/image tuple. The service runs as non-root
UID/GID `65532`. A controller-supplied, bounded HTTP helper runs as non-root
UID/GID `65533`; it is trusted driver code, not repository code.
For the Python tuple, controller-supplied helpers use `python -I -S` and
working directory `/`. The repository workspace is therefore not their import
root and cannot replace helper imports with repository modules.

The timeout attached to readiness or an HTTP request is an absolute wall-clock
deadline for that operation, not a socket-inactivity timeout that resets when
bytes move. Runner-owned helper slack exists only to cancel, quiesce, and
confirm process exit after the functional deadline. Before readiness retries
or service cleanup proceed, UID/GID `65533` must have exited synchronously or
been quiesced by a trusted root helper; failure to confirm that state fails
closed.

HTTP timeout and signal `gracePeriod` values must parse to an integer number of
milliseconds and be at least 1 ms. Fractional seconds are accepted when the
result is a whole millisecond: `1.5s` is 1,500 ms and valid, while `1.5ms` is
not. Readiness may be at most 2 minutes. It uses bounded exponential backoff
and stops after no more than 128 attempts, even if time remains. A
service-start lifecycle observation is `succeeded` only after readiness returns
its declared status; attached-process launch alone is not a successful service
start. Each explicit request timeout is at most 30 minutes. If a request omits
`timeout`, the resolved fallback is `phases.exercise.timeout`, or 1 minute when
that phase timeout is absent; the fallback is also capped at 30 minutes.

```yaml
phases:
  run:
    timeout: 1m
    service:
      id: app
      command:
        - python
        - /workspace/server.py
        - --output
        - /outputs/request.json
      readiness:
        http:
          url: http://127.0.0.1:8080/health
          status: 200
          timeout: 15s
  exercise:
    timeout: 30s
    driver:
      type: http
      steps:
        - request:
            id: echo
            method: post
            url: http://127.0.0.1:8080/echo
            json:
              message: hello
        - assert:
            id: echo-status
            response:
              requestId: echo
              status: 200
        - assert:
            id: echo-message
            response:
              requestId: echo
              jsonPath:
                path: $.received.message
                equals: hello
        - assert:
            id: echo-schema
            response:
              requestId: echo
              jsonSchema: .repopass/schemas/echo.schema.json
        - assert:
            id: request-created
            fileExists: /outputs/request.json
        - assert:
            id: request-schema
            jsonFile:
              path: /outputs/request.json
              schema: .repopass/schemas/echo.schema.json
  cleanup:
    timeout: 15s
    steps:
      - id: stop-service
        signal:
          target: app
          type: term
          gracePeriod: 5s
```

The executable HTTP contract is deliberately narrower than the public shape:

- `phases.run.service` is the scenario's only service and has HTTP readiness;
- run capabilities declare exactly one TCP listener with host
  `127.0.0.1` and an explicit port;
- readiness and request URLs are canonical, are no longer than 2,048 UTF-8
  bytes, and use literal
  `http://127.0.0.1:<explicit-port>`, match that declared port, and share one
  origin;
- the service is attached to the controller rather than detached inside the
  sandbox;
- readiness checks an expected status in the range 200–599 before exercise;
- the journey has at most 128 ordered request/assertion steps and at most 32
  requests;
- effective request headers must simultaneously satisfy count ≤ 64 and
  aggregate bytes ≤ 65,536, and each header value is no longer than 8,192
  bytes. Aggregate bytes are
  `sum(len(name bytes) + len(value bytes) + 4)` over every effective header;
  accepted names and values are ASCII, so these are also their UTF-8 byte
  lengths. The trusted driver's automatic JSON `content-type` counts in both
  the effective count and aggregate;
- a text request body and the actual bytes produced by serializing a `json`
  request are each no larger than 1 MiB;
- response assertions support status 200–599, one header substring whose
  `contains` value is no longer than 8,192 bytes, and a non-empty
  `bodyContains` value no larger than 1 MiB;
- `jsonPath.equals` accepts only a singular path: `$`, `.ASCII_identifier`,
  quoted bracket members, and non-negative `[index]`. Paths are limited to
  1,024 UTF-8 bytes and 64 selectors. Missing and JSON `null` are distinct;
  numbers retain exact JSON precision. The canonical expected value and
  response both use the same 1 MiB, depth, node, and decimal-exponent
  (`-1000..1000`) limits;
- response `jsonSchema` uses Draft 2020-12 and a regular portable repository
  file no larger than 256 KiB. Planning and execution bind and revalidate its
  path, SHA-256, dialect, and validator version. Only same-document fragment
  references are accepted; remote, cross-file, dynamic, recursive, and custom
  vocabulary resolution is rejected;
- `fileExists` is evaluated when its ordered step is reached, not deferred
  until finalization. A trusted in-container `lstat` walk accepts only a
  normalized UTF-8 `/outputs` path no longer than 4,096 bytes and rejects a
  symlink in any component;
- `jsonFile` is evaluated at its ordered step and must name a regular file
  below `/outputs`. A fixed helper uses dirfd/`O_NOFOLLOW`, reads at most
  1 MiB, and returns bounded base64/size/SHA-256. The controller recomputes
  integrity, applies strict JSON parsing, and validates the snapshot against
  the plan-bound schema. Raw JSON and extracted values are not evidence;
- cleanup contains exactly one signal targeting the service. After its grace
  period, the helper escalates remaining workload processes to `SIGKILL`;
  it must report `initialTargets >= 1` and `sent >= 1`, so an
  enumeration/send race fails closed without requiring a send to every
  initially enumerated target. Every signal type, including `kill`, requires
  a whole-millisecond grace period from 1 ms through 10 seconds. The signal is
  the final cleanup step and final resolved command and leaves runner-owned
  helper slack. Finalization quiesces UID/GID `65532` before output export,
  after UID/GID `65533` exit or trusted root quiescence has been confirmed.

The service and HTTP helper run in the same container and therefore share its
loopback interface. That container is created with `--network none`, and the
runner supplies no host-publish option. Loopback traffic is not external egress
and never requires a host port.

Redirect following, TLS URLs, authentication-bearing headers, multiple
services, full RFC 9535 JSONPath, remote/cross-file schemas, arbitrary sandbox
file reads are outside this profile.
Unsupported shapes are never weakened to a nearby supported behavior.

## Phase-scoped capabilities

```yaml
capabilities:
  exercise:
    network:
      deny: true
    filesystem:
      read:
        - /workspace/**
        - /inputs/**
      write:
        - /outputs/**
```

The executable subset accepts deny-all runtime/exercise networking and
declarative filesystem read paths plus writes confined to `/outputs`.
Declarative process `exec` and port `listen` shapes can be bound to a plan;
the HTTP slice additionally accepts its one `tcp` loopback listener. The
built-in backend does not fully observe those behaviors. Setup allowlists are
recognized but planner-gated until a controlled proxy or firewall can enforce
them. Advanced filesystem operations, other protocol-qualified network/listen
declarations, per-phase resources, environment and secret capabilities,
devices, and host integration are also gated.

Declarations and observations remain separate. Denying network does not prove
that no connection was attempted; attempted-destination observation is a
distinct feature. Filesystem and port declarations may therefore produce a
functional pass while required observation coverage remains incomplete.
Likewise, resource-limit enforcement cannot satisfy a `ResourceUsage`
observer.

Alpha.8 adds a Docker-only `port.listener-trace.summary` event, not a manifest
setting or a new runner wire field. It is eligible only for the exact approved
Node or Python Linux `amd64` image/runtime tuple and the sealed HTTP profile:
one service, one signal lifecycle, and one declared canonical
`127.0.0.1:<port>/tcp` run listener matching the readiness origin. Podman and
all other shapes report the observer unavailable.

Immediately before service dispatch, the controller creates a peer container
from the exact same pinned image and joins only the target container's network
namespace. The controller verifies that PID, mount, IPC, and cgroup namespaces
remain separate. The peer runs as UID/GID `65534`, with a read-only root,
all capabilities dropped, `no-new-privileges`, no mounts, published ports,
devices, privilege, or added capabilities, and fixed 64 MiB memory/swap,
16-PID, and 0.25-CPU limits.

The peer accepts a cryptographically random token only through bounded stdin
JSONL. It must return one strict `READY` after its initial sample and before
service dispatch, and one strict `FINAL` after service termination and
quiescence. The declared endpoint must be absent initially, observed during
the sample window, and absent again at `FINAL`; the peer is removed and its
removal confirmed before target-container removal. Each frame is capped at
8 KiB, total stdout at 16 KiB, stderr at 8 KiB, endpoints at 16, samples at
1,200, transitions at 4,096, polling at 100 ms with a maximum accepted 1-second
gap, and the canonical sample stream at 1 MiB. Identity, namespace, protocol,
stderr, exit, timeout, overflow, gap, boundary, or removal failure makes the
event `unavailable`.

The helper reads only Linux `/proc/net/tcp` and `/proc/net/tcp6` listener
tables. Public evidence is declared-endpoint aggregate data plus a keyed
canonical helper commitment; it excludes the session token, raw `/proc`
content, socket inodes, undeclared endpoint identities, and process
attribution. The controller does not independently recompute that commitment.
Polling has a sample-window blind spot for short-lived listeners and supplies
neither kernel-event, process-attribution, nor UDP coverage. A clean event
therefore sets `PortObservation` to only `best-effort`; required `port-listen`
remains incomplete and the overall verdict remains `inconclusive`.

Historical Alpha.7 added a Docker-only `filesystem.activity-trace.summary` event, not a
manifest setting or new runner wire field. Before the workload, the controller
starts a trusted root helper through the exact shell-free
`docker exec --interactive --user 0:0 ...` transport. After quiescence it sends `STOP`.
The bounded stdin/stdout JSONL stream must contain exactly one `READY` and one
`FINAL`; the random session token is stdin-only and cannot appear in argv,
environment variables, logs, or public evidence.

Each JSONL frame is capped at 8 KiB, total stdout at 16 KiB, stderr at 8 KiB,
notifications at 4,096, and the canonical transcript at 1 MiB. No
workload-writable control file is created.

The event is aggregate-only: bounded notification counts,
controller-window phase hints, and a keyed canonical transcript digest. It is
not operation or syscall history and exposes no raw path, content, token, or
actor. Node manually installs non-recursive per-directory `fs.watch` watchers
with a 2,048-watch cap and reports kernel queue-overflow detection
`unavailable`. Python uses inotify with the same cap and fails closed on queue
overflow. Protocol contamination, dirty stderr, nonzero exit, timeout,
identity mismatch, overflow, a detected gap, or any bound failure makes the
whole event `unavailable`.

Dynamic watch races, coalescing, reads, rename pairing, directory replacement,
exact operation/phase semantics, and actor attribution remain blind spots.
The helper reports `observerPlacement=in-sandbox-trusted-helper` and
`sharesSandboxResourceBudget=true`, so it may perturb resource measurements.
Podman activity tracing is unavailable. A
clean event contributes only `best-effort` notification hints and cannot
complete required filesystem-write observation.

Alpha.24 does not add manifest fields or widen the resolved-plan schema.
For the exact Docker/Linux/pinned-Python/CLI synchronous foreground tuple, it
uses the existing phase-scoped `filesystem.write` patterns as the complete
mutation-notification declaration vocabulary. The controller sends only the
active phase's validated exact, `/*`, and `/**` rules to a trusted helper and
requires a phase acknowledgement plus workload-UID quiescence before and after
the dispatch. A complete unmatched notification may produce one aggregate
`UNDECLARED_FILESYSTEM_WRITE` per repeat. The public operation is
`filesystem.operation-notification.summary`, with observer
`docker-python-outputs-inotify-comparison`, resource `/outputs`, and coverage
no higher than `best-effort`.

This is a positive detector, not proof of conformance or complete operation
history. Healthy runs remain capability `incomplete`, overall `inconclusive`,
and `formalClaim=false`. Node, Podman, non-Linux/non-Python runtimes,
HTTP/services, signal workflows, and background execution are unavailable.
Queue overflow, unknown events, watch errors/races, unsafe paths, identity or
transport failure, malformed/out-of-order frames, phase/quiescence failure, or
any bound failure is `not-tested`, with no partial aggregate or finding. Paths,
rules, contents, tokens, inotify cookies, and raw transcripts are never public;
rename pairing, reads, syscalls, actor/process attribution, xattrs, ACLs,
ownership, and paths outside `/outputs` remain out of scope.

After readiness, a runtime Python overflow/gap is carried only as an exact
minimal `failed` union with the bound session digest, Python adapter,
`ok=false`, and one of `notification-overflow`,
`new-directory-watch-gap`, or `notification-gap`. The controller requires
clean transport and exact exit `1`; the union contains no aggregate counts,
commitment, path, rule, or raw event.

Historical Alpha.6 adds a Docker-only `filesystem.engine-diff.summary` event, not a
manifest setting or new runner wire field. The controller uses the exact
shell-free argument vector `docker container diff <immutable-64hex-id>`.
Stdout and stderr are each capped at 4 MiB; only exit `0`, no truncation, and
empty stderr are accepted. Because filenames may contain newlines, stdout is
opaque. Public evidence exposes only its SHA-256, byte count, and nonempty
flag—never raw bytes, paths, or parsed `A`/`C`/`D` records.

The pre-workload baseline is diagnostic only and does not affect coverage.
Only an identity-reverified final collection after workload quiescence and
before repair may contribute `best-effort`. Docker's output is cumulative from
container creation and may include trusted and pre-workload activity; it
provides no actor, operation-time, or phase attribution. It excludes the
separate `/outputs` tmpfs and bind or other mounted source/workspace/input
filesystems.

Alpha.5 adds a separate `filesystem.retained-state.summary` observation event,
not a new runner wire field. The schema-version-1 runner contract is unchanged:
required/composite filesystem-write coverage is read only from the existing
`FilesystemWriteObservation` field. A complete strict, controller-owned,
bounded snapshot pair below `/outputs` can give that event coverage `high`:
the baseline is post-initialization/pre-workload, the final snapshot is
post-quiescence/pre-repair, and both verify the same immutable container
identity and run label. The bounds are 2,048 entries, 1,024 UTF-8 bytes per
normalized path, 256 retained changes, and a 4 MiB control envelope. Snapshot
commitments include path, type, mode, size, regular-file content SHA-256, and
raw symlink-target SHA-256. Public evidence is only an aggregate
`filesystem.retained-state.summary` containing snapshot digests, entry counts,
and a change count.

Retained state is not filesystem operation history. The observer includes
trusted helpers and runner-managed, workload-writable disposable
`/outputs/.home` and `/outputs/.tmp`, which are excluded from export,
but excludes state outside `/outputs`, transient create/delete,
write-then-restore, operation time, process/phase attribution, rename identity,
ownership, timestamps, xattrs, ACLs, inode identity, and device identity.
Failure is nonfatal and reports retained-state `unavailable`. Composite
`FilesystemWriteObservation` remains `best-effort`, so required
filesystem-write remains incomplete; no undeclared-write result is derived.

The retained-state and engine-diff path commitments use unsalted raw SHA-256.
Not publishing the raw path does not provide dictionary-resistant path
secrecy: low-entropy path guesses can be tested. The Alpha.7 activity trace's
keyed digest does not alter that historical property.

Alpha.8 live record `20260731T085836Z` passed all 19 ordered guest gates and all
12 required cases on the exact Docker 29.1.3 / Ubuntu 24.04.4 / kernel
6.8.0-134-generic / Linux `amd64` / cgroup-v2 / QEMU / approved-image tuple.
The record includes Node and Python peer-listener lifecycle evidence, the Linux
race gate, unchanged residue inventories, and clean teardown. Peak memory is
cgroup-wide, not RSS; PID peak counts tasks, not processes; writable allocation
is a final snapshot, not a peak. Other tuples remain unavailable or unclaimed.
With the built-in observer set, a functional CLI or HTTP pass still remains
capability `incomplete` and overall `inconclusive`; neither M1 nor M2 is
complete. The record is unsigned and is not a Podman, rootless, other-version,
other-kernel, other-image, or `arm64` claim.

### Alpha.25 peer listener observation

`port.listener-trace.summary` remains a runner observation, not a manifest
field. For its exact Docker/Linux/amd64 approved Node-or-Python single-service
HTTP profile, Alpha.25 compares sampled TCP listeners with the canonical
declared listener. Public detail is aggregate-only: fixed non-sensitive
observer metadata, `comparisonResult`, and `evidenceBasis` always; exactly four
endpoint-related counts only if complete; and no comparison counts when
`not-tested`. It does not expose raw endpoint data or prove listener
absence, UDP behavior, or process attribution. `PortObserverVersion=0.3.0` is
part of the resolved-plan digest.

## Secrets

Literal secrets are forbidden. A scenario can request a synthetic value without
placing secret material in the manifest:

```yaml
secrets:
  api-key:
    source: synthetic
    scope:
      phases:
        - exercise
    exposeAs:
      env: API_KEY
```

The invalid fixture intentionally demonstrates a forbidden literal value.
Synthetic-secret declarations are schema-valid, but the current local planner
rejects them as unavailable before execution.

## Verification

```yaml
verification:
  repeats: 3
  successThreshold: 3
  requiredObservers:
    - process-exec
    - filesystem-write
    - port-listen
    - network-enforcement
    - resource-usage
  cleanup:
    allowedResidue:
      - /outputs/**
```

The executable alpha accepts only an all-matching repeat contract:
`successThreshold == repeats`. Custom stability rules, resource variance, and
custom cleanup residue sets fail closed. `allowedResidue` is currently limited
to an empty list or `/outputs/**`. Classifier `0.1.0` inventories the final
bounded `/outputs` tmpfs without publishing individual paths: zero descendants
is `clean`, covered regular files/plain directories are `allowed-residue`, and
an empty profile with any descendant or any symlink/special entry is
`undeclared-residue`. Incomplete evidence is `not-tested`.
Missing required observers prevent a complete verdict. Summary
event coverage `high` does not satisfy the required
`filesystem-write` observer because its composite coverage remains
`best-effort`. The optional Docker engine-diff event also contributes at most
`best-effort` and does not change that requirement. Likewise, the Alpha.8
peer listener event contributes at most `best-effort`; it cannot satisfy a
required `port-listen` observer.
Repetition uses a fresh sandbox for each run.

## Policy and evidence

```yaml
spec:
  policies:
    profile: baseline-v1
  evidence:
    profile: minimal-public
    include:
      - verification-summary
      - normalized-observations
    exclude:
      - raw-stdout
      - raw-stderr
      - raw-syscall-trace
```

The executable alpha accepts exactly `baseline-v1` and two fixed
`minimal-public` selections: the two listed `include` values above, or those
same values plus `sbom`. All three listed `exclude` values are mandatory. The
resolved plan sorts and binds this exact object. An SBOM-selected run requires
one caller-supplied strict SPDX 2.3 JSON attachment at `attest` time;
`local-full`, other attachment types, and custom include/exclude sets fail
closed.

The `sbom` token means only that the later offline bundle must contain a
validated canonical derivative. That derivative is either caller-supplied
`attest --spdx FILE` or the Alpha.18 narrow static path
`attest --derive-spdx --current-manifest FILE`; the latter is mutually
exclusive, accepts only root `package.json` with lockfile-version-3
`package-lock.json`, and executes no npm, Node, Git, network, or repository
command. It requires two stable snapshots before derivation and a third before
signing. Lockfile integrity is checksum-shape-only, not registry verification.
Neither path requests general npm compatibility, package discovery, SBOM truth
or completeness, license/vulnerability evaluation, or a capability/overall
upgrade. Sealed Alpha.18 evidence is historical and does not qualify Alpha.19.

Independent policy and evidence versioning is the architecture target. The
current implementation uses the fixed built-in selections above. Private or raw
trace data is not included in public evidence.

Alpha.22 retains Alpha.21's local-state option for Alpha.20's
`offline-trust-policy-v2` replay authorization input to
`verify-attestation`. Its signed envelope, caller
authority SPKI, and caller minimum generation are not `spec.policies`, evidence
selection, resolved-plan material, bundle members, or signed predicate fields,
and do not change this manifest schema. With only the complete signed triple,
the exact valueless `--persist-trust-policy-state` adds controller-local state
below global `--data-dir`, not manifest data: one canonical authority record
and lock detect rollback and same-generation different-payload equivocation
relative to surviving local state. It precedes signer authorization and does
not add policy authoring, private-key management, authority lifecycle,
tamper-resistant/distributed state, trusted time, or historical revocation.
On Windows, Alpha.22 creates new state-directory components and lock files with
their protected private DACL in the create operation; this does not change the
manifest schema.

Alpha.31's bounded `sign-offline-trust-policy` producer also remains entirely
outside the manifest contract. Its generation, signer SPKI files, decisions,
authority private key, output envelope, and authority companion are not
`spec.policies`, plan inputs, evidence, or bundle members. Producing those
sidecars changes no manifest schema and supplies no automatic trust bootstrap.

Alpha.32's one-hop offline trust-policy authority transition also remains
outside the manifest. Its root/terminal key files, transition envelope,
authority floor, combined controller-local state, and producer output are
replay inputs only; they do not alter `spec.policies`, a resolved plan, bundle
membership, evidence, or manifest schema. The companions do not bootstrap
trust and multi-hop policy-authority chains remain unsupported.

Alpha.33's explicit 2..8-hop offline trust-policy authority chain also remains
outside the manifest. Its hop envelopes and keys, root/terminal companions,
authority floor, chain-policy state, and assembler output are replay inputs
only; they do not alter `spec.policies`, resolved plans, bundle membership,
evidence, or the manifest schema. Embedded and companion keys do not bootstrap
trust.

Alpha.19 `offline-trust-policy-v1` is a separate replay authorization input to
`verify-attestation`. It is not `spec.policies`, evidence selection, resolved
plan material, a bundle member, or a signed predicate field, and it does not
change this manifest schema.

See the complete fixture manifests under `testdata/fixtures/healthy/`.
