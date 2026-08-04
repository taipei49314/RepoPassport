# Architecture

RepoPassport targets a modular Go architecture with hexagonal boundaries. The
current `v1alpha1` reference slice implements those responsibilities in a
smaller package set; this document therefore distinguishes target boundaries
from packages that exist today. Domain models remain independent of Docker,
Podman, a database driver, a web framework, or a signing service.

## Target dependency direction

```text
cmd
  |
  v
application ----> domain
  |                 ^
  v                 |
core ports <---- adapters
```

The diagram is the intended dependency direction, not a claim that every named
box is already a Go package. Today, CLI use-case orchestration lives primarily
in `internal/cli`; manifest resolution is split across `internal/manifest` and
`internal/planner`; baseline policy and evidence assembly are implemented
inside the verification and storage path. Dedicated application, resolver,
policy, and general evidence packages remain architectural seams. The narrow
Alpha.15 local signer, deterministic bundle/companion publisher, strict bundle
parser, digest pins, offline policy evaluator, and verifier live in
`internal/attestation`; the
bounded fail-closed publication policy lives in `internal/privacy`; the pure
bounded SPDX profile and no-link reader live in `internal/spdx`.
Alpha.27's canonical verifier-kit builder and parser live in
`internal/releasekit`; the reduced `cmd/repopass-verify` entry point shares the
full CLI's attestation verifier while exposing no repository execution command.

`pkg/` is reserved for deliberately public, versioned packages. Moving a type
there is an API commitment, not a convenience.

## Conceptual modules

| Module | Responsibility |
|---|---|
| `domain` | Source, plan, run, observation, assertion, verdict, and public error models |
| `application` | Inspect, validate, plan, verify, report, attest, verify-attestation, and doctor use cases |
| `acquisition` | Resolve an input reference, create an immutable snapshot, and inventory files |
| `discovery` | Produce static detection signals with provenance and confidence |
| `resolver` | Validate and merge manifest declarations, defaults, and inferred proposals |
| `planner` | Produce a fully resolved plan, canonical form, digest, and lockfile |
| `execution` | Negotiate runner features and manage phase, timeout, cancel, and cleanup lifecycle |
| `verification` | Evaluate assertions, capability mismatches, cleanup, repeats, and aggregate status |
| `policy` | Apply non-bypassable core policy and a versioned policy bundle |
| `evidence` | Bind source, plan, policy, runner, observations, assertions, and verification |
| `attestation` | Wrap one authoritative historical verification in deterministic v1 five/six-member or derived-v2 seven-member in-toto/DSSE bundles and apply explicit SPKI-key or digest-pinned offline-policy trust |
| `releasekit` | Build and validate exact canonical Linux/Windows portable offline-verifier archives without carrying evidence or trust roots |
| `spdx` | Strictly validate caller-supplied SPDX, or statically derive the frozen package-lock-v3 profile without commands; neither path interprets SBOM truth or completeness |
| `rendering` | Produce text, versioned JSON, and offline static HTML from one model |

Names in this table describe responsibilities. Only names represented under
`internal/` are current package boundaries.

## Trusted pipeline

```text
untrusted source
  -> immutable snapshot and inventory
  -> static discovery
  -> strict manifest validation
  -> resolved plan and digest
  -> runner feature negotiation
  -> isolated execution plus available controller-side observation
  -> external assertions and policy evaluation
  -> multidimensional verification
  -> report and authoritative evidence
  -> optional local attestation, optional plan-selected SPDX derivative, digest-pinned replay, and offline explicit-key/policy verification
```

The current backend supplies runner-owned lifecycle and enforcement
observations, with best-effort or unavailable coverage for several behavior
categories. Alpha.10 retains Alpha.8's narrow `/outputs` retained-state
observer, Docker engine-diff commitment, Docker-only bounded activity trace,
and Docker-only peer-container TCP listener observer for the supported
single-service Node/Python HTTP profile. None provides a general external
syscall, filesystem operation-history, or network-attempt observer.

Alpha.24 adds a bounded positive notification comparison beside, not in place
of, the retained-state observer. Its exact support tuple is Docker, Linux, the
pinned Python adapter, and synchronous CLI foreground commands without a
service, HTTP journey, signal workflow, or background work. For each supported
controller dispatch, a root trusted helper receives only that phase's bounded
existing `filesystem.write` rules, acknowledges the phase before command
execution, and reports only aggregate mutation-match status. The controller
checks immutable container identity and workload UID quiescence before and
after the window. This permits positive detection of transient create/delete,
write-then-restore, and rules borrowed from another phase without publishing
paths, rule text, contents, tokens, inotify cookies, or raw transcripts.

It is intentionally not a complete operation-history or syscall observer.
Node `fs.watch`, Podman, non-Linux/non-Python runtimes, HTTP/services, signal
workflows, and background execution are unavailable for this comparison. Queue
overflow, watch races, transport or identity errors, unsafe paths, phase or
quiescence failure, and every bound failure fail closed to `not-tested` with no
partial public aggregate or positive finding. Inotify coalescing, rename
pairing, reads, actor/process attribution, xattrs, ACLs, ownership, and paths
outside `/outputs` remain outside the detector. Coverage is no higher than
`best-effort`; healthy runs remain capability `incomplete`, overall
`inconclusive`, and `formalClaim=false`. Alpha.24 does not complete M1, M2, or
rootless qualification.

For a runtime Python overflow or gap after readiness, the helper latches one of
three bounded causes, closes its watches, and stays alive only to acknowledge
exact controller phases and receive `stop`. It then emits a minimal exact
`failed` union bound to the session and Python adapter and exits `1`. Success
aggregate fields are forbidden in that union; malformed unions or any other
exit fail closed as transport failure.

Alpha.9 added one controller-owned assertion path, not a new observer. A
CLI `stdoutJsonSchema` assertion takes the complete bounded stdout captured by
the journey runner, strict-decodes exactly one JSON document, and evaluates an
already prepared offline Draft 2020-12 schema. Planning and preparation bind
the local schema path, digest, dialect, and validator version. The verifier
integrity-binds the resulting assertion event; it does not independently
recapture or re-evaluate workload stdout.

Strict instance limits are 1 MiB, depth 128, 100,000 nodes, and exponent
`-1000..1000`. Shared stdout/stderr log truncation prevents a completeness
claim and is `inconclusive`; a complete malformed or schema-mismatching
document is `failed`. Public evidence retains only safe status booleans and a
failure kind with the sealed schema binding. It excludes stdout content,
parsed values, property names, stdout hashes, and byte counts.

Alpha.10 adds a separate controller-owned final cleanup inventory. It runs
after immutable-ID workload quiescence and existing final observers, removes
runner-managed disposable `.home`/`.tmp`, rechecks the immutable identity and
run label, and then performs a bounded no-follow inventory of `/outputs`.
Classification is limited to `clean`, `allowed-residue`,
`undeclared-residue`, or `not-tested`. Its fixed boundary is before any
conditional permission repair, output export, peer/target removal, and
controller work-root deletion. It is retained-state classification, not
filesystem operation history and not an attestation.

Alpha.11 adds a post-verification path, not a new execution observer. `attest`
loads the authoritative verification through the external run store and
recomputes its integrity before constructing canonical JSON, an in-toto
Statement v1, one Ed25519 DSSE signature, and an exact five-entry uncompressed
USTAR. `verify-attestation` reparses and byte-reconstructs that complete bundle,
checks all content and signature bindings offline, then compares the embedded
SPKI key with an independently supplied explicit trust key. The embedded key
and key ID do not confer trust.

Alpha.13 adds a bounded replay layer around that unchanged five-entry bundle:
an optional separately published canonical SPKI PEM companion, complete raw-
bundle and PEM digests in reports, and an expected-bundle digest checked before
optional trust-key I/O. These additions do not alter the signed statement,
original verdicts, or explicit trust semantics.

Alpha.15 makes the evidence selection explicit schema-4 plan material. The raw
tar member-name set selects either the exact five-member model or an exact
six-member model containing `payload/sbom.spdx.json`. The latter is accepted
only when the authoritative plan selected `sbom`; the caller input is read
twice through one identity-bound regular-file handle, strictly validated,
canonicalized, privacy-checked, and bound through manifest, statement, DSSE,
and public digest metadata. This is attachment integrity, not SBOM generation,
dependency discovery, semantic normalization, license/vulnerability analysis,
or a completeness/currentness claim.

Alpha.18 adds a separate version-2 derived-SBOM model. Only
`attest --derive-spdx --current-manifest FILE` may select it; it reads the root
`package.json` and lockfile-version-3 `package-lock.json` through stable local
snapshots without npm, Node, Git, network, or repository-command execution.
Two snapshots bind derivation and a third binds signing. The v2 bundle carries
canonical SPDX plus provenance. Replay touches current source only after
explicit trust and a raw-bundle digest pin, then reports `fresh`, `stale`, or
`unknown` separately. Lockfile integrity is shape-checked only, not registry
verified. The profile is not general npm support, discovery/completeness,
license/vulnerability analysis, a capability pass, or an overall verification.

Alpha.22 retains Alpha.21's opt-in local state gate for the then verifier-only signed
authorization input after cryptographic and privacy verification. A
caller supplies a canonical Ed25519 authority SPKI, canonical DSSE envelope,
and minimum policy generation; the exact valueless
`--persist-trust-policy-state` then uses global `--data-dir` (or its default).
The verifier authenticates the canonical `offline-trust-policy-v2` payload
relative to that authority, applies the caller floor, serializes one canonical
authority-scoped generation/payload record and lock, then evaluates the
embedded evidence signer. The state detects lower-generation rollback and
same-generation different-payload equivocation only relative to the surviving
local record; qualified policies advance it even if the signer is rejected.
State failure releases no claims or freshness work. It does not manage
authority private keys/lifecycle, make state tamper-resistant or distributed,
provide trusted time/historical revocation, or change the signed bundle graph.
On Windows, newly created state directories and lock files receive their
protected private DACL in the kernel create call and are then validated;
existing objects are validation-only. No signed graph, CLI, schema, or report
shape changes in Alpha.22.

Alpha.31 adds a separate full-CLI producer for that unchanged authorization
graph. It derives sorted unique signer identities from canonical Ed25519 SPKIs,
builds the strict v2 payload, signs with a distinct caller-managed authority
key, self-verifies, rechecks signer snapshots, and atomically publishes the
envelope plus authority companion. These producer inputs and outputs remain
outside the manifest, plan, attestation bundle, and portable-verifier kit. The
companion is never an implicit trust root, and no new runtime capability or
overall-verification claim follows from producing a policy.

Alpha.32 adds a separate one-hop transition primitive inside
`internal/attestation` and a root-scoped combined local-state adapter in
`internal/trustrotationstate`. The CLI remains the orchestration boundary:
intrinsic bundle verification precedes explicit root/terminal/transition I/O;
the terminal policy and role/floor bindings precede the single combined state
commit; signer claims and optional freshness are released last. Direct
per-authority policy state remains in `internal/truststate` and is not silently
migrated. The exact-three producer reuses the fail-closed local publication
transaction, while portable packaging contains no transition sidecar.

Alpha.33 composes 2..8 of those exact transition envelopes in a canonical
unsigned transport inside `internal/attestation`. The explicit root is the
only initial trust anchor; every embedded next key is admitted only after its
preceding hop authenticates the exact SPKI identity. `internal/trustchainstate`
owns a separate root-scoped atomic chain+policy record, intentionally without
direct/one-hop migration or comparison. CLI orchestration preserves intrinsic
bundle-first I/O, completes chain and terminal-policy role/floor validation,
then performs at most one state transaction before signer/freshness release.
The portable package carries no chain sidecar and exposes no assembler.

Alpha.19 separately adds an unsigned authorization input after cryptographic and
privacy verification. A canonical, raw-digest-pinned policy maps only the
verifier-computed Ed25519 SPKI key ID to `trusted` or `revoked`; absence is
`not-listed`. It does not change the signed graph or exact bundle member set.
The policy delivery and digest-selection process remains operator trust, not a
new service or signer port.

This layer preserves the historical result. It neither re-runs the scenario
nor changes original verdicts. Without an opt-in current manifest, its separate
`freshnessEvaluation: "not-evaluated"` is intentional; the embedded
`originalResults.freshness` is not a new currentness observation. Alpha.16 may
instead compare a caller-supplied current local root only after explicit trust
and a raw-bundle pin. Two pre-plan and one post-plan source snapshots bound the
source/policy/plan comparison; only the exact signed backend supplies the
finite runner-stable-v1 projection. This unsigned report never re-aggregates
the historical result. The stored verification still does not carry its former
local source path, so the caller-supplied root is not inferred provenance.

The executable `baseline-v1` policy also binds the exact Node/Python runtime
image tuples that may supply the sandbox supervisor and fixed helpers. That
allowlist participates in the policy bundle digest. It narrows the local trusted
computing base; it is not image provenance or signature verification.
The `core.resource-limit-enforcement` rule is also bound into
`policyBundleDigest`, so changing that enforcement decision changes the plan
identity rather than only the later verification output.

The workload never writes into the verifier's artifact directory. Workload
files named `verification.json`, `observations.json`, or `evidence.json` remain
ordinary untrusted outputs.

## Run lifecycle

The target lifecycle is separate from verdicts:

```text
CREATED
-> RESOLVING
-> PREFLIGHT
-> READY
-> PREPARING_SANDBOX
-> EXECUTING
-> OBSERVING
-> EVALUATING
-> FINALIZING
-> COMPLETED
```

These named states are a normative state-machine design; the current local
slice does not persist each state as a lifecycle record. Cancellation and
expiration are lifecycle outcomes and must not be stored as functional or
capability verdict values.

Phases use this order:

```text
PREPARE -> SETUP -> BUILD -> RUN -> EXERCISE -> CLEANUP -> FINALIZE
```

After a phase failure, normal functional work stops, but bounded safety cleanup
still runs and already collected observations remain available.

## Alpha.25 peer TCP-listener comparison boundary

For the already sealed Docker/Linux/amd64 approved Node-or-Python one-service
HTTP profile, Alpha.25 treats peer TCP observation as a declared-versus-sampled
aggregate comparison. The public summary has fixed non-sensitive observer
metadata plus `comparisonResult` and `evidenceBasis=aggregate-only`, and adds
exactly four endpoint-related counts—baseline, declared, sampled, and
undeclared—when complete. The `not-tested` shape has no comparison counts.
Raw endpoints, addresses, ports, URLs, `/proc` rows, socket/PID/namespace
identifiers, tokens, frames, and stderr never leave the trusted observer path.
The plan binds `PortObserverVersion=0.3.0`; earlier locks drift.

This remains 100 ms Linux TCP polling. It is no proof of listener absence and
does not cover short-lived listeners, UDP/Unix sockets, outbound/NAT activity,
or process attribution. It cannot turn capability `incomplete`, overall
`inconclusive`, or `formalClaim=false` into a stronger claim.

## Source and workspace layout

The abstract Linux workload layout is:

```text
/source           immutable, read-only source snapshot
/workspace        fresh read-only physical copy of the source snapshot
/inputs           required read-only file or directory fixtures
/outputs          engine-managed writable tmpfs with the plan's aggregate disk cap
/outputs/.home    runner-managed, workload-writable disposable home; excluded from export
/outputs/.tmp     runner-managed, workload-writable disposable temp; excluded from export
```

The executable alpha bind mounts controller-owned source, workspace, and input
copies read-only. Writable state exists only in the engine-managed `/outputs`
tmpfs, currently capped at no more than 2 GiB. After controller output
initialization and before workload execution, the runner verifies the immutable
container identity and captures a bounded retained-state baseline. On Docker,
it also invokes the shell-free fixed argument vector
`docker container diff <immutable-64hex-id>` and records an opaque diagnostic
baseline commitment. Before workload execution on Docker, it starts the
activity helper with `docker exec --interactive --user 0:0 ...` and waits for
strict `READY`. For a supported single-service HTTP plan that requires
`port-listen`, the controller creates a separate peer observer immediately
before service dispatch, starts its attached transport asynchronously, and
waits for its strict `READY`; setup and build are outside that listener sample
window. After execution, the controller:

1. quiesces every process belonging to the fixed workload UID;
2. re-verifies the target and peer identities and namespaces, sends `STOP` to
   the peer listener observer, and accepts only a strict `FINAL` frame;
3. re-verifies the same immutable container identity, sends `STOP`, accepts
   only a strict `FINAL`, and closes the activity session;
4. before changing the
   tree, captures the bounded final retained-state snapshot plus the Docker-only
   opaque engine-diff commitment;
5. deletes disposable `.home`/`.tmp` state and validates/repairs the remaining
   ordinary output tree with a fixed image-runtime helper;
6. streams that quiescent tree through the allowlisted image's fixed
   `/bin/tar --format=ustar --blocking-factor=1 --exclude=./.home
   --exclude=./.tmp -C /outputs -cf - .` command;
7. extracts into a private controller staging directory with Go code that
   rejects links, special files, extended metadata, non-portable paths,
   collisions, and count/byte overflow;
8. inventories the staged tree again, atomically commits it, forcibly removes
   any peer observer, then forcibly removes the target sandbox.

This path does not use engine `cp`: live testing showed that stopped or paused
engine tmpfs content is not portable through that operation. Host paths are not
a domain concept; another backend may use named volumes, snapshots, or a
different isolated storage primitive.

## Runner and observer negotiation

Every backend publishes a feature set. A plan lists required runner and observer
features. The contract requires missing hard enforcement to fail closed with
`RUNNER_FEATURE_UNAVAILABLE`; current backend gaps and release restrictions are
listed in `known-limitations.md`. A portable runner-profile digest is deferred.

Observation coverage is recorded per category:

- `FULL`
- `HIGH`
- `BEST_EFFORT`
- `ENFORCEMENT_ONLY`
- `UNAVAILABLE`

A rendered report uses the uppercase labels above. Versioned JSON uses the
lowercase wire values `full`, `high`, `best-effort`, `enforcement-only`, and
`unavailable`.

A feature such as network deny may be enforced while attempted destinations are
unobservable. Reports must display both facts.

Filesystem retained state and filesystem-write history are also separate
facts. A complete alpha.5 baseline/final pair gives the
`filesystem.retained-state.summary` observation event coverage `high`, while composite
`FilesystemWriteObservation` remains `best-effort`; the required
`filesystem-write` observer therefore remains incomplete. Observer failure is
nonfatal and gives the summary event coverage `unavailable`.

The Docker-only `filesystem.engine-diff.summary` is another independent
component, not operation history. The controller uses exactly
`docker container diff <immutable-64hex-id>`; stdout and stderr are each capped
at 4 MiB, and only exit `0` with no truncation and empty stderr is accepted.
Because filenames can contain newlines, stdout is opaque: no `A`/`C`/`D`
records or paths are parsed or published. Evidence contains only a SHA-256
commitment, byte count, and nonempty flag.

The pre-workload engine-diff baseline is diagnostic only and does not grant or
downgrade coverage. Only an identity-bound final collection after workload
quiescence and before repair may make the engine-diff component
`best-effort`. Docker defines that transcript cumulatively from container
creation, so it includes trusted and pre-workload activity and cannot provide
actor, time, or phase attribution. It excludes the separate `/outputs` tmpfs
and bind or other mounts such as source, workspace, and inputs.

The Docker-only `filesystem.activity-trace.summary` is a third independent
component. The controller owns a shell-free asynchronous
`docker exec --interactive --user 0:0 ...` session whose trusted root helper starts before
the workload and survives quiescence of workload UID/GID `65532` and driver
UID/GID `65533`. Its stdin/stdout protocol is bounded JSONL with exactly one
`READY` and one `FINAL`; the cryptographically random session token crosses
only stdin and never appears in argv, environment variables, logs, or public
evidence. No workload-writable control file is created. Dirty
stderr, nonzero exit, timeout, malformed, extra, trailing, or
oversize frames, identity mismatch, overflow, gap, or count/bound mismatch
fails the whole component closed to `unavailable`.

Raw paths exist only in bounded helper memory. The public event contains
aggregate notification and controller-window phase-hint counts plus a keyed
canonical transcript digest; it is not operation or syscall history. Node
uses manually installed non-recursive per-directory `fs.watch` watchers,
capped at 2,048, and reports kernel queue-overflow detection `unavailable`.
Python uses inotify with the same cap and fails closed on queue overflow.
Dynamic watch races, coalescing, reads, rename pairing, directory replacement,
exact operation semantics, exact phase attribution, and actor attribution
remain blind spots. The helper reports
`observerPlacement=in-sandbox-trusted-helper` and
`sharesSandboxResourceBudget=true`, so it can perturb resource measurements.
Podman activity coverage is unavailable until separately live-qualified.

Alpha.8's Docker-only `port.listener-trace.summary` is a separate component
that runs alongside the HTTP journey driver and is eligible only for the
supported single-service HTTP profile. The controller creates a second
container from the target's exact pinned image/runtime, starts it with the fixed asynchronous
`docker start --attach --interactive <immutable-64hex-peer-id>` transport, and
uses `--network container:<immutable-64hex-target-id>`. Only the network
namespace is shared. Strict identity and namespace checks require different
PID, mount, IPC, and cgroup namespaces, exact target/peer run and observer
labels, the exact image, expected running state, and immutable 64-hex IDs.

The peer runs as UID/GID `65534` with a read-only root, all capabilities
dropped, `no-new-privileges`, 64 MiB memory and swap, 16 PIDs, and 0.25 CPU. It
has no mounts, devices, published ports, privilege, or added capabilities. The
Node or Python helper reads only `/proc/net/tcp` and `/proc/net/tcp6`, recognizes
kernel state `0A` as TCP `LISTEN`, and samples every 100 ms for at most 1,200
samples. The declared endpoint is exactly
`127.0.0.1:<declared-port>/tcp`. A complete session requires the endpoint to be
absent in the initial barrier, observed listening within the sample window, and
absent again in the final barrier after workload quiescence.

The peer protocol uses a cryptographically random 256-bit token delivered only
through bounded stdin JSONL, with exactly one `READY` and one `FINAL`. Frames,
streams, endpoints, samples, transitions, sample gaps, and canonical bytes are
strictly bounded. Dirty stderr, malformed or extra data, timeout, overflow,
identity or namespace mismatch, an excessive sample gap, incomplete
quiescence, or failed peer removal fails closed. Observer failure is
supplemental to the functional journey; peer-removal failure is also an
independent cleanup error, and the peer is removed before the target.

The public summary is aggregate-only. It exposes neither the token, raw
`/proc` rows, inode data, nor undeclared endpoint details. Its canonical digest
is a helper commitment, not a controller-recomputed attestation. Even a
complete session gives `PortObservation=best-effort`: polling can miss short
listener intervals, and the observer supplies neither UDP, connection,
network-attempt, process-owner, nor complete port-history coverage. Podman
port observation remains `unavailable`.

## Specification boundaries

```text
spec/          normative prose and decision tables
schemas/       machine-readable wire contracts
internal/      reference implementation
testdata/       fixture-based behavioral inputs
```

Schema semantics, status aggregation, evidence predicates, core policy, trust
model, plugin protocol, runner conformance, and breaking CLI/API changes require
an RFC.

## Deferred architecture

Hosted control planes, microVM workers, GitHub applications, interactive trial,
public registries, and external JSON-RPC plugins are not required by the first
local vertical slice. Static Node and Python discovery plus Docker/Podman and
CLI execution are compiled into the binary. `v0.1.0-alpha.19` retains one
constrained attached Node or Python HTTP service, same-container loopback
readiness and request driving, ordered bounded assertions, singular JSONPath,
offline Draft 2020-12 response/file schema validation, point-in-time
`/outputs` `jsonFile`, and a final service signal. It adds offline Draft
2020-12 validation of complete CLI stdout. Multiple services, redirects, TLS,
authenticated requests, full RFC 9535 JSONPath, and remote/cross-file schemas
remain deferred.

The resolved-plan wire and digest contract is now schema version `"4"`. It
retains cleanup classifier `0.1.0`, CLI driver `0.2.0`, and HTTP driver `0.1.0`,
and adds the exact plan-bound `minimal-public` evidence selection. The manifest
API remains `repopass.dev/v1alpha1`. Version-1, version-2, and version-3 locks
are treated as `PLAN_DRIFT` and must be regenerated, never silently upgraded.
Historical evidence may still be checked under its original integrity
contract, but it is not current execution authority.

The M3 package remains intentionally local and file based. It can
bind one plan-selected, caller-supplied strict SPDX derivative, but it does not
generate an SBOM or establish completeness, correctness, currentness, license
or vulnerability status, or producer identity. Sigstore, OIDC, transparency
logs, KMS, TPM/HSM, trusted timestamping, historical/effective-time revocation,
managed key lifecycle, authenticated hosted policy, and remote publication remain deferred;
this architecture does not represent complete M3.

Within that compiled subset, readiness is capped at 2 minutes. Each explicit
request timeout and the resolved exercise fallback used when omitted are capped
at 30 minutes; the fallback is `phases.exercise.timeout`, or 1 minute when
absent. Effective headers must simultaneously satisfy count ≤ 64 and aggregate
bytes ≤ 65,536. The aggregate is
`sum(len(name bytes) + len(value bytes) + 4)` over every effective header;
accepted names and values are ASCII, so these are also their UTF-8 byte
lengths, and an automatic JSON `content-type` participates in both limits.

This executable lifecycle is not complete behavior observation. The alpha.5
retained-state collector uses strict bounds of 2,048 entries, 1,024 UTF-8 bytes
per normalized path, 256 retained changes, and a 4 MiB control envelope. Its
post-initialization/pre-workload and post-quiescence/pre-repair snapshots bind
the same immutable container identity. Snapshot commitments include SHA-256 of
regular-file contents and raw symlink targets, but the public event is an
aggregate-only `filesystem.retained-state.summary`.

Retained-state summary event coverage may be `high`; composite filesystem-write
and foreground-process coverage remain `best-effort`. Alpha.8 can give
port-listen coverage only `best-effort` for a complete Docker peer-observer
session in the supported HTTP profile; otherwise it is `unavailable`. The
snapshots include trusted helpers and runner-managed, workload-writable
disposable `.home`/`.tmp` directories, which are excluded from export. They
cannot see outside
`/outputs`, transient create/delete or write-restore behavior, operation time,
process/phase attribution, rename identity, ownership, timestamps, xattrs,
ACLs, inode identity, or device identity. They do not support undeclared-write
detection. Failure is a nonfatal `unavailable` retained-state observation.

Historical Alpha.6 additionally emits a Docker-only
`filesystem.engine-diff.summary`. It commits to the final opaque Docker CLI
stdout without publishing raw output, paths, or parsed change classes. A clean,
bounded, identity-checked, post-quiescence/pre-repair final transcript can give
that component only `best-effort`; baseline failure does not alter coverage.
The transcript describes engine-visible changes since container creation, may
include trusted and pre-workload activity, and omits `/outputs` tmpfs and
mounted filesystems. Dirty stderr, a nonzero exit, truncation, identity failure,
or quiescence failure makes it `unavailable`.

Alpha.7 additionally emits the Docker-only activity summary described above.
A complete, clean, identity-bound `READY`/`FINAL` session can contribute only
`best-effort` notification hints. The required filesystem observer remains
incomplete and no undeclared-write conclusion is derived.

Alpha.8 additionally emits the Docker-only peer listener summary described
above for the supported single-service HTTP profile. A clean, bounded,
identity- and namespace-bound session that sees the declared TCP listener open
and then closed can contribute only `best-effort` port-listen coverage. Because
required observer coverage below `high` is incomplete, this does not make the
capability conforming.

The historical retained-state and engine-diff path commitments use unsalted
raw SHA-256. Withholding raw paths is therefore not dictionary-resistant path
secrecy: low-entropy candidate paths can be guessed and tested. The Alpha.7
activity trace's per-session keyed canonical digest does not strengthen those
older commitments.

Alpha.8 live record `20260731T085836Z` passed all 19 ordered guest gates and all
12 required cases on Docker client/server 29.1.3 in an isolated Ubuntu 24.04.4
LTS, kernel 6.8.0-134-generic, Linux `amd64`, cgroup-v2 QEMU VM. It includes
sequential Node/Python peer-listener evidence, Linux race testing, unchanged
before/after container, network, volume, source, and host-listener records, and
clean guest/QEMU/seed teardown. Local/repro record `20260731T085753Z` also
passed and reproduced the release files. The record is unsigned and applies
only to that exact Docker/VM/kernel/image tuple—not Podman, rootless operation,
other versions, kernels, images, or architectures. Consequently, a successful
HTTP journey still remains capability `incomplete` and overall `inconclusive`;
neither M1 nor M2 is complete.
