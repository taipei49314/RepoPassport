# Security model

RepoPassport answers whether a specific repository scenario worked under a
specific declared capability contract and observation boundary. It is not a
malware scanner, vulnerability scanner, or proof that all repository code is
safe. The HTTP statements below describe only the constrained
single-service profile retained by `v0.1.0-alpha.33`.

## Alpha.33 offline policy-authority chain boundary

Chain mode verifies 2..8 ordered existing Alpha.32 transition envelopes from
one explicit caller root. Embedded keys become usable only after exact
previous-hop authentication; authorities are globally unique and cycle-free,
generations strictly increase, and the final key must equal the explicit
terminal policy authority and meet its floor. The authenticated terminal
policy must keep every root, intermediate, and terminal authority out of both
trusted and revoked evidence-signer roles.

The intrinsic bundle is verified before trust inputs, and the complete chain
and policy pass before a separate root-scoped chain+policy state transaction.
That local namespace is neither migrated from nor compared with direct or
one-hop state. The producer's root and terminal SPKIs are transport companions,
not trust bootstrap; portable kits carry neither and expose no producer. A
compromised accepted root can authorize a malicious chain. This is bounded
continuity, not compromise recovery, identity, trusted time, transparency, or
historical revocation. Claims remain none/none/false/incomplete/inconclusive.

## Alpha.32 offline policy-authority transition boundary

Rotation mode extends the signed-policy verifier with one purpose-separated
old-root-signed transition, one explicit previous root, one explicit terminal
authority, and an authority generation floor. The intrinsic bundle is verified
before trust inputs; the terminal policy is authenticated and role-separated
before a root-scoped combined state tuple can commit. The tuple owns both
transition and policy generations under one lock and atomic file replacement,
so partial advancement is impossible.

The previous and terminal SPKIs emitted by the full-CLI producer are companion
transport only. The portable kit carries neither and exposes no producer. A
compromised accepted previous root can still authorize a malicious terminal;
this is one-hop continuity, not compromise recovery, multi-hop lifecycle,
identity, trusted time, transparency, or historical revocation. Local state
can be reset/forked with its data directory. Claims remain
none/none/false/incomplete/inconclusive.

## Alpha.31 offline trust-policy issuer boundary

The full CLI can produce the existing `offline-trust-policy-v2` authorization
input from 1..32 caller-supplied canonical Ed25519 signer SPKIs, explicit
trusted/revoked decisions, and one safe-integer generation. A separate
canonical PKCS#8 Ed25519 authority key supplies the purpose-separated DSSE
signature. Key IDs come only from canonical SPKI DER; the set is globally
sorted and unique, and the authority cannot also be a policy signer. The
producer parses and authenticates its exact result before an exact-two,
no-replace directory publication.

The published authority SPKI remains companion transport, not trust bootstrap.
Verification continues to require an independently trusted authority input and
an explicit caller floor. The command does not generate, retain, rotate, or
remotely publish keys and does not add KMS/HSM, transparency, identity, trusted
time, expiry, historical revocation, or tamper-resistant state. The portable
verifier remains read-only and rejects this producer before command-specific
I/O. Capability and overall semantics remain `incomplete` and `inconclusive`.

## Alpha.29 external release-index authority-transition trust boundary

The release index is a signed, external inventory for exactly one artifact
root. Its signature proves cryptographic binding only after the verifier uses a
caller-supplied canonical Ed25519 authority SPKI to authenticate the dedicated
purpose-separated release-key policy. No index-adjacent key, bundled key,
policy, evidence record, or automatic discovery path is a trust anchor. The
release signer and authority must be different keys; revoked or unlisted
release signers fail closed. Opt-in rotation authenticates a canonical
`release-authority-transition-v1` only under an explicit previous-root SPKI and
binds it to one distinct explicit next policy authority. A companion or bundled
previous root never implicitly becomes a trust anchor.

Acceptance is therefore relative to the explicit root and policy supplied for
that invocation. It makes no publisher legal-identity or trusted-time claim:
`identityAttestation=none`, `timeAttestation=none`, `formalClaim=false`,
capability `incomplete`, and overall `inconclusive`. This does not supply root
discovery, publisher identity, trusted time, remote publication, transparency,
or tamper-resistant/distributed state; wider root lifecycle, historical
revocation, and key custody are deferred.

Verification authenticates the index signature and its exact scope/floor
before transition, policy, state, artifact, or runner access. In rotation mode
it authenticates the explicit old root, next authority, and transition before
policy I/O, and observes transition state before policy state when persisted.
It then authenticates the floor-qualified policy, authorizes the already-
authenticated signer, verifies the artifact set, and only then observes release state. Files are
bounded to 128 MiB each and 512 MiB per set; `SHA256SUMS` is capped at 64 KiB.

Artifact verification performs two complete stable scans and rejects observed
identity, size, digest, or inventory drift. This requires a quiescent,
operator-controlled root; it is not an atomic filesystem snapshot and does not
claim immunity to a hostile concurrent namespace or content writer.

Authority-transition, policy, and release generation records are local rollback/equivocation guards,
not trusted clocks or tamper-resistant storage. Their protection is relative
only to the surviving selected data root: deletion, restore, copy, rename, or
fork can reset or fork history. Exact-digest mode instead relies on the caller
to supply the intended immutable digest.

## Alpha.26 typed public qualification evidence

The Alpha.26 qualification boundary keeps raw Docker/OS/runtime/image/test/race/
listener artifacts private and exposes only canonical typed fixed-VM receipts
plus strict source, harness, matrix, verdict, and identity records. Fixed-VM
public inclusion is determined by an exact inventory and an explicit parser or
record grammar for every path; marker scanning and filenames alone are not
trusted. Renaming raw content into a fixed-VM allowed slot or recomputing the
full unsigned digest chain does not make that content valid. Local qualification
Go logs remain bounded transcripts with gate-specific checks and confidentiality
scanning rather than universally typed receipts.

This is a public-data minimization control, not a guarantee that all secrets can
be recognized. That historical Alpha.26 external index has no signature,
identity attestation, or trusted-time attestation and detects mutation only;
Alpha.29 does not retroactively upgrade it. Runtime capability coverage
does not change: healthy results remain `incomplete`/`inconclusive`, positive
undeclared-listener fixtures remain `nonconforming`, and
`formalClaim=false`.

## Alpha.22 local authenticated offline policy state

The verifier-only signed-policy triple authenticates a canonical
`offline-trust-policy-v2` payload only against a separately supplied canonical
Ed25519 authority SPKI, through one DSSE envelope of the dedicated policy
payload type. It first enforces the signed generation against the caller's
minimum for that invocation. The exact valueless
`--persist-trust-policy-state` may then use global `--data-dir` (or its
controller default) for one canonical authority-scoped generation/payload
record and lock. This local guard rejects lower generations and different
payloads at an established generation before signer authorization, accepted
claims, or freshness. It intentionally records a floor-qualified authenticated
policy even when the evidence signer is `revoked` or `not-listed`.

On Windows, newly created state directories and per-authority lock files are
born with a protected private DACL supplied to the kernel create operation and
are validated before use. Existing objects are validated without ACL repair.
This narrows creation-time exposure only and is not a native sandbox or an
administrator-resistant security boundary.

The guard is not durable against deletion, replacement, snapshot restore, or
forking of the selected data directory; it is neither tamper-resistant nor
distributed state and supplies no trusted time, expiry, historical revocation,
authority lifecycle, key custody, hosted trust, or complete verification.
Alpha.22 itself supplied no policy-signing or private-key-management
capability; Alpha.31 adds only the bounded caller-key producer above, not key
management or authority lifecycle.

## Alpha.19 offline trust-policy boundary

The offline policy is an independently supplied, unsigned authorization input.
It is read only after any supplied raw-bundle pin and complete canonical
bundle, signature, SPDX, and privacy verification. Its required digest pins
the exact bytes before parsing, and policy lookup uses only the signer key ID
recomputed from canonical SPKI DER. Envelope self-reporting cannot select a
different entry.

`trusted` authorizes, while `revoked` and `not-listed` reject. Here `revoked`
means only that the key is rejected by the currently supplied policy; it says
nothing about signing time or historical status. The digest does not
authenticate who authored or selected the policy, prevent rollback, establish
trusted time, or provide transparency. The operator and delivery mechanism
remain in the trust boundary. No external signer/KMS/HSM/Sigstore/OIDC or
hosted policy service is added.

## Alpha.18 derived SPDX boundary

The repository-derived path is exactly
`attest --derive-spdx --current-manifest FILE`, mutually exclusive with a
caller-supplied SPDX file. Its command-free static reader accepts only root
`package.json` and lockfile-version-3 `package-lock.json`; it never runs npm,
Node, Git, network access, or repository commands. Two matching snapshots must
precede derivation and a third must precede signing. Canonical SPDX and
provenance bind the version-2 bundle model.

The accepted lockfile integrity is only a checksum-shape constraint, not a
registry authenticity or download check. This does not provide general npm
compatibility, dependency discovery/completeness, SBOM truth, license or
vulnerability analysis, supplier identity, capability conformance, overall
verification, or M3 completion. Re-observation requires explicit SPKI trust
and a raw-bundle digest pin before current source access; it reports `fresh`,
`stale`, or `unknown` independently. Sealed Alpha.18 qualification evidence
applies only to its exact historical source and does not qualify Alpha.19.

## Alpha.17 dependency security boundary

The selected application module graph replaces the required indirect
`golang.org/x/text@v0.14.0` module with the minimum reviewed fixed release
`v0.39.0` for `GO-2026-5970` / `CVE-2026-56852`. Module authenticity remains
enabled. CI downloads and verifies the public modules and rejects any
`go mod tidy -diff` output before running pinned `govulncheck v1.6.0` gates
over both the `cmd/repopass` module graph and reachable source/test symbols.
Alpha.16 had no reachable or imported-package finding for this advisory; the
affected version was nevertheless selected as a required module.

The exact upstream graph-only effects are `x/mod` `v0.8.0 -> v0.37.0`,
`x/tools` `v0.6.0 -> v0.47.0`, and added `x/sync@v0.21.0`. Other
repository-declared requirements remain at their Alpha.16 versions, and formal
qualification must prove that the three tool modules are absent from both
product binaries.

This is a point-in-time dependency gate, not SBOM generation, dependency
completeness, exploitability analysis, all-build-tag coverage, license safety,
or a guarantee of future vulnerability absence. It changes no runtime trust
boundary or original verdict. Capability remains `incomplete` and overall
remains `inconclusive`.

## Assets

Assets to protect include:

- the controller host, container engine, and engine virtual machine;
- host credentials, agents, tokens, configuration, and personal files;
- source identity and immutable snapshots;
- inputs and workload outputs;
- runner policy and feature declarations;
- observations, assertions, policy decisions, verification, and evidence;
- signing identities and private keys;
- reports consumed by terminals, browsers, CI, and APIs.

## Trust levels

| Component or data | Trust |
|---|---|
| Repository source, manifest, README, archive, filenames | Untrusted |
| Workload process and every file it writes | Untrusted |
| Exact `baseline-v1` base image, its runtime binary, and `/bin/tar` | Built-in allowlisted and operator-approved part of the local runner TCB; a digest proves immutability, not trust |
| Runtime adapter proposals | Constrained; validated before use |
| Source acquisition and planner | Trusted computing base |
| Sandbox backend and external observers | Trusted computing base, with declared limitations |
| Bounded HTTP helper, journey driver, verifier, policy evaluator | Trusted computing base |
| Evidence builder and configured signer | Trusted computing base |
| Maintainer declarations | Authorship claim, not automatically verified identity |

## Hard invariants

The manifest cannot disable these rules:

1. Inspection and static discovery do not execute repository code.
2. The workload cannot write trusted observation, assertion, policy,
   verification, or evidence storage.
3. No host root, home directory, credential directory, SSH agent, cloud
   credential, engine socket, arbitrary device, host PID namespace, host
   network, or privileged container is exposed. HTTP verification does not
   publish a host port.
4. Workload commands run as non-root with unnecessary capabilities dropped and
   bounded CPU, memory, PIDs, wall time, logs, and writable storage. Source,
   workspace, and input mounts are read-only. `/outputs`, workload home, and
   temporary storage share one engine tmpfs capped by the declared disk limit.
   The local ceiling is 2 GiB. The runner actively verifies UID/GID `65532`,
   zero inheritable/permitted/effective/ambient capabilities, and
   `no-new-privileges` before repository code runs. An attached HTTP service
   uses that identity; the bounded controller-supplied HTTP helper uses the
   separate fixed non-root UID/GID `65533`.
5. The runner supplies the idle supervisor and fixed helper arguments, using
   the runtime binary and `/bin/tar` from an exact built-in-allowlisted,
   pre-pulled image. The supervisor/finalization helpers run as root with only
   `DAC_OVERRIDE`, `FOWNER`, and `KILL` added; repository commands never supply
   their arguments. Controller-supplied Python helpers use `python -I -S` with
   working directory `/`, outside the repository import root.
6. Source identity is resolved before execution and the snapshot is immutable
   during the run.
7. A formal plan pins source, image, commands, capability, policy, adapters,
   and required observer features. Runner identity is recorded at execution.
8. Missing enforcement or required observation cannot produce a pass. A
   retained-state summary event may claim coverage `high` only after the observer verifies the same
   immutable container identity at both snapshot boundaries and confirms
   workload quiescence before the final snapshot. On Docker, the activity
   trace also requires a strict identity-bound `READY`/`FINAL` session,
   confirmed quiescence, clean bounded transport, and no overflow or detected
   gap; even then it supplies only `best-effort` notification hints. The engine-diff
    component may claim only `best-effort`, and only after the controller
    re-verifies that identity and uses the fixed shell-free
    `docker container diff <immutable-64hex-id>` call after quiescence and before
    repair. The Docker peer listener component also requires exact target/peer
    identity, only the intended shared network namespace, isolated PID, mount,
    IPC, and cgroup namespaces, a strict bounded `READY`/`FINAL` session,
    workload quiescence, and verified peer removal. Even then it supplies only
    `best-effort` sample-window coverage.
9. Functional, capability, reproducibility, cleanup, evidence, and freshness
   dimensions are stored independently.
10. Cleanup identifies and destroys the entire run sandbox, not just its main
    process. The HTTP slice requires one service signal, applies its declared
    grace period, escalates surviving workload processes to `SIGKILL`, and
    performs final workload quiescence before export. Signal success requires
    at least one workload target and at least one confirmed send, not a send to
    every initial target; a target/send race fails closed. Every signal,
    including `kill`, requires whole-millisecond grace from 1 ms through 10
    seconds. The signal is the final command, and the cleanup deadline
    preserves separate trusted helper slack.
11. Static HTML escapes repository-controlled fields. Text reports emit only
    bounded trusted labels and controller messages; raw workload streams are
    not copied into the report.
12. Attestation signing reads only an authoritative external run whose
    verification integrity recomputes successfully. It never accepts a
    repository-produced verification as authority, never changes the signed
    original verdicts, and never treats an embedded signer key as trusted.

## Key threats and defenses

### Source acquisition

Threats include path traversal, symlink or reparse-point escape, archive bombs,
case and Unicode collisions, special files, mutable source, submodule expansion,
credential-helper use, and private-network fetches.

The initial local source provider enforces root containment, file and byte
limits, rejects unsupported special links, copies into an immutable snapshot,
and computes a content identity. Remote acquisition requires a separate,
hardened design.

### Command and configuration injection

Repository strings do not enter a shell. Commands use argument arrays. Discovery
parses data files without importing modules, installing dependencies, running
package lifecycle scripts, or evaluating README snippets.

Trusted Python helpers are not launched from `/workspace`: isolated mode
(`-I`) ignores environment and user import paths, `-S` skips automatic `site`
initialization, and working directory `/` keeps repository modules off the
helper import path. This protection applies to controller-supplied helpers, not
to the untrusted repository service itself.

### Sandbox escape and host exposure

The first backend runs Linux workloads in a container engine with no privileged
mode, host namespaces, engine socket, device passthrough, or arbitrary writable
host mounts. Controller-owned source, workspace, and fixture copies are mounted
read-only; writable state is confined to an engine tmpfs. After initialization
and before workload execution, fixed controller code verifies the immutable
container identity and captures the retained-state baseline. After execution,
fixed root finalization quiesces all workload-UID processes, re-verifies that
identity, and captures the final snapshot before it removes disposable
home/temp state or repairs the tree. It then rejects non-file/non-directory
output entries. The
allowlisted image's `/bin/tar --format=ustar` streams the quiescent tree to Go
code in the controller. That extractor rejects links, special files, extended
metadata, path escape, non-portable/ambiguous names, and entry or byte overflow;
it reinventories private staging before an atomic commit. Engine `cp` from a
stopped or paused tmpfs is not used. The sandbox is forcibly removed even after
export failure. Containers are a local isolation mechanism, not an absolute
security boundary. Hosted execution requires a stronger per-job VM boundary.

On Docker only, the same boundaries also collect
`docker container diff <immutable-64hex-id>` without a shell. Stdout and stderr
are independently limited to 4 MiB; a nonzero exit, truncation, or any stderr
bytes makes the component `unavailable`. Docker CLI stdout is an opaque byte
transcript because filenames may contain newlines. It is never parsed into
paths or `A`/`C`/`D` records and is not published raw; only a SHA-256
commitment, byte count, and nonempty flag enter public evidence. The baseline
is diagnostic only. Only the post-quiescence, pre-repair final call with a
reverified immutable identity can contribute `best-effort` coverage.

For a supported HTTP plan requiring `port-listen`, the controller
creates a second container from the exact pinned target image and starts its
attached process without a shell. Docker joins it only to the target network
namespace. Strict inspection and in-container namespace checks require
immutable 64-hex target/peer IDs, exact run and observer labels, exact image and
running state, the shared network namespace, and different PID, mount, IPC,
and cgroup namespaces.

The peer has no source, workspace, input, output, host, engine-socket, device,
or published-port mount/exposure. It runs as UID/GID `65534` with a read-only
root filesystem, all capabilities dropped, `no-new-privileges`, 64 MiB memory
and swap, 16 PIDs, and 0.25 CPU; privileged mode and added capabilities are
forbidden. It is removed before the target. A removal failure is an independent
cleanup failure even if the functional HTTP assertions succeeded.

The image digest prevents substitution after planning, but does not establish
publisher identity or prove that the image's `node` or `python` executable is
benign. `baseline-v1` therefore accepts only two exact Linux `amd64` tuples and
includes their binding in the policy bundle digest. The local operator must
still explicitly trust and pre-pull the selected image. Runtime-version and
helper probes are bounded consistency self-reports from that image, not
independent supply-chain attestation.

### CLI stdout schema containment

`stdoutJsonSchema` is evaluated by trusted controller code, never by a
workload-authored verdict. Planning reads one immutable local schema without
executing repository code, rejects remote/dynamic/cross-file references, and
seals its portable path, SHA-256 digest, Draft 2020-12 dialect, and validator
version. Preparation requires that complete binding before execution.

The controller accepts only complete captured stdout containing exactly one
strict JSON document. It enforces 1 MiB, depth 128, 100,000-node, and
`-1000..1000` exponent bounds and rejects invalid UTF-8, duplicate keys,
trailing data, and empty output. Complete malformed JSON or schema mismatch is
`failed`. Because stdout and stderr share one bounded capture indicator,
truncation makes stdout completeness unknowable and is `inconclusive`; a
captured prefix is never treated as the document. Missing sealed bindings
block, while other controller evaluation failures remain `inconclusive`.

Public assertion evidence includes only the sealed expected binding and safe
completeness/match booleans plus a failure kind. Raw stdout, parsed values,
property names, stdout hashes, and byte counts are excluded to limit disclosure
and avoid coupling reproducibility fingerprints to otherwise schema-valid
variable values. The verifier checks artifact integrity but does not
independently recapture stdout.

Current Alpha.15 resolved plans use schema version `"4"` and bind the exact
evidence selection; version-1, version-2, and version-3 locks remain historical.
Historical Alpha.10 resolved plans use schema version `"3"` with a required cleanup
classifier. CLI driver `0.2.0`, HTTP driver `0.1.0`, and manifest
`repopass.dev/v1alpha1` remain unchanged. Version-1 and version-2 locks fail
current-plan checking with `PLAN_DRIFT` instead of being reinterpreted.

### Cleanup-residue boundary

Cleanup classification trusts only a complete post-quiescence inventory of
the `/outputs` tmpfs after disposable `.home`/`.tmp` removal and immutable
container identity/run-label readback. The Node/Python helpers use bounded
streaming no-follow traversal rooted in directory file descriptors. Regular
content and symlink targets are never read. Directory identity/mode changes,
invalid control data, dirty stderr, overflow, timeout, missing randomness, or
any incomplete boundary is `not-tested`, never clean.

Public evidence contains only fixed boundary flags, safe aggregate type
counts, the allowed-profile name, and an opaque one-time token made with a
fresh ephemeral HMAC key. It excludes raw paths, targets, contents, helper
output, and unsalted path hashes. The key and raw inventory are discarded, so
the token cannot be opened or independently recomputed and is neither an
attestation nor proof.

Any symlink or special entry is undeclared and prevents permission repair and
output export of that unsafe tree. The runner records an aggregate export
denial with observation `Result=denied`, continues peer/target/work-root
cleanup, and reports `CLEANUP_RESIDUE` without turning the confirmed
conformance finding into an operational execution failure. A separate later
destroy failure cannot erase the stronger confirmed undeclared verdict.

### HTTP journey containment

`alpha.10` retains one service under an exact approved Node or Python Linux
`amd64` tuple. It is an attached engine exec as UID/GID `65532`, so premature
exit remains visible to the controller. The bounded trusted helper executes as
UID/GID `65533` in the same container and exits synchronously after each
operation. Both use the container's loopback interface while the container
itself remains on `--network none`; the runner does not request host port
publishing.

Readiness and request timeouts are absolute wall-clock deadlines, not
socket-inactivity timers. Network activity does not reset them. Runner-owned
slack after the functional deadline exists only to cancel and account for the
trusted helper. Before a retry or cleanup, UID/GID `65533` exit must be
confirmed; a trusted root helper quiesces a survivor, and inability to confirm
either exit or quiescence fails closed.

HTTP durations must resolve to whole milliseconds and be at least 1 ms.
Fractional seconds are allowed when exact at millisecond precision (`1.5s` is
1,500 ms), but a sub-millisecond value such as `1.5ms` is rejected. Readiness
is capped at 2 minutes and uses exponential retry backoff with a hard
128-attempt ceiling. Readiness and asserted response statuses are limited to
200–599. The controller does not emit a succeeded `service.start` observation
until readiness succeeds. Each explicit request timeout and the resolved
exercise fallback used when omitted are at most 30 minutes; the fallback is
`phases.exercise.timeout`, or 1 minute when that field is absent.

Readiness and journey URLs must be literal
`http://127.0.0.1:<explicit-port>`, be canonical and no longer than 2,048 UTF-8
bytes, match the one declared TCP listener, and remain on one origin. A journey
has at most 128 steps and 32 requests. Effective headers must simultaneously
satisfy count ≤ 64 and aggregate bytes ≤ 65,536, with each value limited to
8,192 bytes. The aggregate is
`sum(len(name bytes) + len(value bytes) + 4)` over every effective header;
accepted names and values are ASCII, so these are also their UTF-8 byte
lengths. The automatic JSON `content-type` is included in both the count and
aggregate. A text request body and the actual serialized bytes of a JSON
request are each limited to 1 MiB. The trusted assertion subset is status, a
header substring, `bodyContains`, `fileExists`, singular `jsonPath.equals`,
offline Draft 2020-12 response `jsonSchema`, and ordered `jsonFile`; the header
`contains` value is limited to 8,192 bytes, and non-empty `bodyContains` is
limited to 1 MiB. The controller uses the resolved `bodyContains` value for
matching but never copies that repository-controlled substring into public
assertion evidence. Public evidence records only fixed configured/value-not-
published metadata and typed match/truncation booleans. Exact typed exemptions
for those booleans and the lower-case response-schema digest belong to frozen
`minimal-public-v1alpha2`; raw or wrong-typed body fields still fail closed.

`fileExists` is an ordered assertion. When that step is reached, a trusted
in-container helper validates a normalized UTF-8 `/outputs` path no longer than
4,096 bytes and uses `lstat` on each component. Missing paths fail the
assertion, helper uncertainty is not a pass, and a symlink in the target or any
parent component is rejected.

Structured JSON is parsed by the controller with byte/depth/node limits,
duplicate-key and trailing-value rejection, exact number handling, and an
explicit/effective decimal exponent range of `-1000..1000`. Planning and
execution apply the same profile to `jsonPath.equals`. JSONPath is restricted
to one singular result. Schema paths and digests are
bound to the immutable source inventory and revalidated after the execution
snapshot is copied. `Prepare` also seals a private deep-cloned execution plan,
and compiled schemas are keyed by the complete path, digest, dialect, and
validator-version binding; later mutation of the exported diagnostic plan
cannot alter runtime decisions. Schema loading is offline and only
same-document fragment references are permitted. `jsonFile` uses a fixed root
helper with
dirfd/`O_NOFOLLOW`, an overflow sentinel, and controller-side digest
recomputation. A changed file or helper uncertainty is inconclusive, not a
pass. Raw structured JSON and extracted values are not persisted in assertion
evidence.

The trusted HTTP helper control channel accepts one exact success or failure
object. Missing, duplicate, unknown, wrong-union, or trailing fields are
rejected before response assertions run.

Redirect following, TLS, request authentication, multiple services, full RFC
9535 JSONPath, remote/cross-file schemas, arbitrary sandbox file reads, and CLI
JSON Schema assertions are not implemented. These surfaces fail closed rather
than delegating security decisions to repository code or silently dropping a
declaration.

The cleanup signal helper similarly fails closed unless it observed at least
one UID/GID `65532` workload target and successfully delivered at least one
signal. A process disappearing between enumeration and delivery cannot be
reported as successful signal cleanup merely because no target remains.
The contract requires `initialTargets >= 1` and `sent >= 1`, not a successful
send to every initially enumerated target. Every signal type, including
`kill`, requires a whole-millisecond grace period from 1 ms through 10 seconds.
The signal must also be the final cleanup step and final resolved command,
leaving a distinct runner-owned window for signal-helper completion rather
than consuming the entire cleanup deadline.

### Network exfiltration

Runtime external egress is denied for the initial executable profile. Setup
allowlists require an actual controlled proxy or firewall; ordinary unrestricted
container networking must not be labeled an allowlist.

The HTTP helper's same-container loopback traffic is not external egress. It
does not require a host listener or weaken the container's `--network none`
setting.

The alpha.8 listener peer shares that same isolated network namespace solely to
sample its kernel TCP tables. It does not publish a host port or add a network
route. Sharing the network namespace is intentional; sharing the PID, mount,
IPC, or cgroup namespace is rejected.

Enforcement and observation are reported separately. A backend may prove that a
network namespace had no external route while being unable to identify attempted
destinations.

### Workload self-attestation

The workload can print `PASS`, create `verification.json`, or imitate an
attestation. Those are untrusted outputs. Trusted results are constructed from
the resolved plan, runner metadata, external journey assertions, external
observations, policy decisions, and run metadata stored outside the workload.

The `fake-verification-json` fixture supplies the adversarial workload input;
storage and CLI regression tests enforce that only the controller-owned run
store is authoritative. The opt-in live-container suite exercises the complete
fixture path.

### Local attestation keys and trust

Alpha.15 retains the local M3-a path and bounded replay inputs. The
signer consumes one canonical
Ed25519 PKCS#8 PEM private key and emits one canonical SPKI PEM public key. The
in-toto Statement v1 is carried in a single-signature DSSE envelope using exact
PAE. The key ID is SHA-256 over SPKI DER. Bundle verification reconstructs the
entire canonical five-entry or plan-selected six-entry USTAR and checks the
authoritative verification, optional strict SPDX derivative, manifest,
statement, payload, key ID, public key, and signature graph before it evaluates
trust.

The embedded public key is attacker-controlled until the signature and bundle
bindings pass, and even then is only signer identification. Trust comes only
from an independently supplied canonical SPKI PEM. No trust key produces
`unknown`; an unavailable, malformed, or different trust key produces
`rejected`; only exact SPKI equality produces `accepted`. A self-signed
substitution, cross-bundle component substitution, or key-ID-only value cannot
establish trust.

The signer may publish the same canonical SPKI PEM as a separate companion and
may require a complete raw-bundle SHA-256 digest before verification. Both are
integrity/identification inputs only. A matching digest or package-local
companion MUST NOT change `unknown` to `accepted`; only explicit
`--trust-key` equality performs the local trust decision.

Private key bytes are not written to bundles, stdout, stderr, or structured
errors. The key file must be bounded, regular, canonical, outside the
authoritative data store and output path and, when the current repository is
detectable from the working directory through `.git` or
`repo-passport.yml`, outside that repository. It must not be reached through a
symlink/reparse point or hard link. Unix group/other permissions are rejected.
On Windows, UNC, device, extended-namespace,
alternate-data-stream, trailing-dot/trailing-space, reserved DOS, reparse, and
hard-linked paths are rejected. Windows signing additionally requires an
explicit current-user owner and a DACL whose only allowed identities are that
owner, SYSTEM, and Builtin Administrators; inability to obtain or prove that
descriptor fails closed.

Output publication uses a same-directory temporary regular file, restricted
permissions, complete write, file flush, close, identity/size recheck, and
atomic no-replace publication. An existing path is never overwritten. This
boundary does not establish resistance to a hostile local actor concurrently
renaming or replacing the output parent with a symlink or junction. Windows
write-through publication is also not a universal power-loss durability
guarantee for every filesystem, network redirector, or storage provider.
The validated key/output guarantees apply only to the observed path and handle
state in the absence of hostile concurrent mutation; this contract does not claim to
defeat a racing local actor changing the key path or parent topology.

When both signing outputs are requested they are prevalidated as new,
distinct, isolated paths. The public companion is published first, so a later
bundle I/O failure may leave only a complete companion; the error reports that
state. No private path or private bytes are included in that report.

Default attestation verification does not establish currentness and reports
`freshnessEvaluation: "not-evaluated"`; the signed
`originalResults.freshness` is historical data. Alpha.16's explicit
`--current-manifest` mode is authorized only by accepted SPKI trust plus a raw
bundle digest pin. It performs bounded stable local snapshots and probes only
the signed backend, producing a separate unsigned `current`, `stale`, or
`unknown` report. This does not rerun the scenario, validate age, or defeat a
hostile concurrent namespace/topology swap. Because the stored verification
does not retain the former local source path, the supplied root is not inferred
historical provenance and cannot create a historical repository path-exclusion
boundary. If neither `.git` nor
`repo-passport.yml` identifies the current repository from the working
directory, that repository boundary is unknown to the signer.

### Resource exhaustion

Runs have wall-time, memory, CPU, PID, log, source file-count, source-size, and
writable-storage limits. The engine enforces one tmpfs size for `/outputs`,
workload home, and temporary storage; the controller separately revalidates the
exported archive bytes, logical file bytes, file count, types, and paths. The
local writable limit cannot exceed 2 GiB. The orchestrator cancels the run and
destroys the sandbox when a supported limit is exceeded.

### Report injection and data leakage

HTML escapes repository-controlled strings, disallows repository scripts and
arbitrary inline HTML/SVG, and uses a restrictive Content Security Policy. Raw
traces and raw stdout/stderr are excluded from the current report. A general
redaction pipeline is deferred, so this slice does not publish raw streams as
public evidence.

CLI stdout-schema assertion evidence also excludes parsed values, property
names, stdout digests, and byte counts. It records only the sealed schema
binding, safe booleans, and a failure kind. A schema-valid value is therefore
not copied into the public reproducibility fingerprint.

### Cache and evidence tampering

Stored verification artifacts are digest-checked before reporting. Evidence
binds source, plan, policy, runner, observations, assertions, and verification.
Content-addressed caches remain a later milestone. Alpha.15 can wrap one
integrity-valid historical result in a deterministic local Ed25519 attestation,
optionally binding one caller-supplied strict SPDX 2.3 derivative when the
schema-4 plan selected `sbom`. That signature establishes only possession of
the corresponding key. The explicit trust-key decision is separate, and
freshness remains not evaluated. The attachment is not generated or proved
complete/correct/current and is not a license or vulnerability evaluation.
Sigstore/OIDC identity, transparency, KMS/TPM/HSM, revocation, timestamping,
SBOM generation/independent validation, and remote publication remain later work.

## Observer coverage

### Alpha.25 peer listener public-data contract

The Docker peer TCP observer is bounded to its exact supported HTTP profile.
Its public summary accepts fixed non-sensitive observer metadata plus
`comparisonResult` and `evidenceBasis=aggregate-only`, with exactly four
endpoint-related aggregate counts only for complete samples. The `not-tested`
terminal has no comparison-count fields. An
unmatched aggregate can yield one `UNDECLARED_PORT_LISTEN` per repeat. Any
unexpected detail key, malformed count, or incomplete boundary is unavailable
for report purposes; raw endpoint/IP/port/URL, process/socket/namespace data,
tokens, frames, and stderr are excluded. This remains sampling, not a proof of
absence, UDP coverage, or attribution; `formalClaim=false` is mandatory.

Silence is meaningful only when the observer documents adequate coverage.

```text
Container lifecycle   FULL for controller-issued create/start/remove operations
Foreground exec       BEST_EFFORT
Child process exec    BEST_EFFORT or UNAVAILABLE
Filesystem retained   HIGH after a complete bounded alpha.5 snapshot pair;
                      otherwise UNAVAILABLE
Docker engine diff    BEST_EFFORT after a clean identity-bound final call;
                      otherwise UNAVAILABLE; Docker only
Outputs activity      BEST_EFFORT notification hints after a strict clean
                      identity-bound READY/FINAL session; otherwise
                      UNAVAILABLE; Docker only
Filesystem writes     BEST_EFFORT composite coverage
Filesystem reads      UNAVAILABLE in the first CLI backend
Network deny          FULL enforcement coverage
Denied destinations   UNAVAILABLE
Port listening        BEST_EFFORT after a complete Docker alpha.8 peer session
                      for the supported HTTP profile; otherwise UNAVAILABLE
Resource enforcement  separate engine-backed feature; not observation
Resource usage        HIGH on the exact alpha.4 Docker/cgroup-v2 tuple;
                      otherwise UNAVAILABLE or unclaimed
```

The report must state these limitations next to the result. In particular,
read-only mounts and a bounded output filesystem are enforcement facts, not
proof of complete filesystem behavior observation. The built-in observer set
therefore remains incomplete even when a functional CLI or HTTP journey
passes. A trusted HTTP response proves only the declared functional assertion;
it does not upgrade process, filesystem, port, network-attempt, or
resource-usage observer coverage. Such a functional pass remains capability
`incomplete` and overall `inconclusive`.

The alpha.8 Docker peer listener observer starts immediately before service
dispatch, so setup and build are outside its sample window. The controller
creates the peer from the target's exact pinned Node/Python Linux `amd64` image,
waits for strict `READY` before starting the service, confirms workload
quiescence before sending `STOP` and accepting strict `FINAL`, and removes the
peer before the target.
The fixed transport is
`docker start --attach --interactive <immutable-64hex-peer-id>` and never
invokes a shell.

The peer's Node or Python helper reads only `/proc/net/tcp` and
`/proc/net/tcp6`, interprets kernel state `0A` as TCP `LISTEN`, and samples at a
fixed 100 ms interval for no more than 1,200 samples. Endpoints are capped at
16, transitions at 4,096, maximum accepted sample gap at 1,000 ms, and
canonical data at 1 MiB. A successful session requires the exact declared
`127.0.0.1:<port>/tcp` endpoint to be absent in the initial barrier, seen
listening during the controller-owned window, and absent in the final barrier.

Control uses a cryptographically random 256-bit token delivered only over
stdin. The strict bounded JSONL protocol accepts exactly one `READY` and one
`FINAL`; each frame is at most 8 KiB, total stdout is at most 16 KiB, and
stderr is at most 8 KiB and must be empty. Invalid UTF-8, dirty stderr,
malformed, unknown, duplicate, missing, trailing, or oversized data, nonzero
exit, timeout, overflow, identity or namespace mismatch, excessive sample gap,
incomplete quiescence, or removal failure fails closed. Observation failure is
supplemental and does not convert a functional success into a functional
failure, while peer-removal failure remains a distinct cleanup error.

Public `port.listener-trace.summary` evidence is aggregate-only and excludes
the session token, raw `/proc` rows, inode data, and undeclared endpoint
details. Its canonical digest is a helper commitment, not a
controller-recomputed attestation. Polling can miss a short listener interval,
and the peer does not observe UDP, connections, network attempts, attempted
destinations, process ownership, or complete port history. Therefore its
maximum coverage is `best-effort`; required `port-listen` remains incomplete,
and overall status remains `inconclusive`. Podman port observation is
`unavailable`.

The alpha.7 Docker activity trace starts before workload execution and stops
after workload quiescence. The controller invokes no shell and owns the
asynchronous `docker exec --interactive --user 0:0 ...` session. The trusted root helper
communicates through strict bounded stdin/stdout JSONL with exactly one
`READY` and one `FINAL`. Its random session token is delivered only through
stdin and never appears in argv, environment variables, logs, or public
evidence. No workload-writable control file is created.

Raw paths remain only in bounded helper memory. Public evidence contains only
aggregate notification and controller-window phase-hint counts plus a
per-session keyed canonical transcript digest. It is not operation or syscall
history. Node manually installs non-recursive per-directory `fs.watch`
watchers capped at 2,048, but kernel queue-overflow detection is unavailable.
Python uses inotify with the same cap and treats queue overflow as total
failure. Dirty stderr, nonzero exit, timeout, protocol contamination, identity
mismatch, overflow, a detected gap, or a bound failure makes the entire trace
`unavailable`; no partial success is published.

Dynamic watch-installation races, notification coalescing, reads, rename
pairing, watched-directory replacement, exact operation and phase semantics,
and actor attribution remain blind spots. The helper's
`observerPlacement=in-sandbox-trusted-helper` and
`sharesSandboxResourceBudget=true` also mean that its CPU, memory, task, and
tmpfs use can perturb sandbox resource measurements. Podman activity tracing
is unavailable until separately live-qualified.

The historical alpha.6 Docker engine-diff component runs the exact fixed argument vector
`docker container diff <immutable-64hex-id>` with independently bounded 4 MiB
stdout and stderr. Only exit `0`, no truncation, and empty stderr are clean.
The stdout transcript is opaque because newline-containing filenames make
line-oriented path parsing ambiguous. Public evidence exposes only its
SHA-256, byte count, and nonempty flag—not raw bytes, paths, or parsed
`A`/`C`/`D` classes.

The pre-workload baseline is diagnostic only and does not grant or downgrade
coverage. A clean final collection after workload quiescence and before repair,
with the immutable container identity reverified, gives only `best-effort`.
Docker's semantics are cumulative from container creation, so the transcript
can include trusted initialization, observer, and other pre-workload activity;
it has no actor, operation-time, or workload-phase attribution. It does not
cover the separate `/outputs` tmpfs or bind and other mounted
source/workspace/input filesystems.

The alpha.5 retained-state observer captures a post-initialization/pre-workload
baseline and a post-quiescence/pre-repair final snapshot below `/outputs`.
Both boundaries verify the same immutable container identity and run label.
The strict bounds are 2,048 entries, 1,024 UTF-8 bytes per normalized path,
256 retained changes, and a 4 MiB helper-control envelope. Snapshot commitments
include entry path, type, mode, and size plus SHA-256 of regular-file contents
and raw symlink targets. Public evidence is aggregate-only: one
`filesystem.retained-state.summary` event contains snapshot digests, entry
counts, and a retained change count, not contents, targets, or per-path change
records.

This scope includes trusted helpers and runner-managed, workload-writable
disposable `/outputs/.home` and `/outputs/.tmp`, which are excluded from
export. It excludes state outside `/outputs`,
transient create/delete, write-then-restore, operation time, process/phase
attribution, rename identity, ownership, timestamps, xattrs, ACLs, inode
identity, and device identity. It cannot support undeclared-write detection.
Snapshot, identity, quiescence, bound, or decode failure is nonfatal and leaves
the summary event coverage `unavailable`; failure is never represented as an
empty successful diff. Composite filesystem-write coverage remains
`best-effort`, the required filesystem-write observer remains incomplete, and
neither M1 nor M2 is complete.

Retained-state and engine-diff path commitments use unsalted raw SHA-256.
Withholding the raw path is not dictionary-resistant path secrecy: an attacker
with a low-entropy candidate set can test guesses. The Alpha.7 activity
trace's keyed canonical digest does not retroactively strengthen those
historical commitments.

For the `alpha.4` collector, `high` is the maximum composite `ResourceUsage`
coverage and requires every sample for every repeat. Live record
`20260730T173121Z` validates it only on the exact Docker 29.1.3 / Ubuntu
24.04.4 / kernel 6.8 / Linux `amd64` / cgroup-v2 / approved-image tuple. The
memory sample is cgroup-wide peak memory, not RSS; `pids.peak` counts
tasks/threads, not processes; writable allocation is a final snapshot, not a
historical peak. Failures remain unavailable/incomplete rather than becoming
zero. This does not repair the remaining observer gaps, complete M1, produce
overall `verified`, or sign the evidence.

Historical Alpha.8 live record `20260731T085836Z` passed the exact-source Docker/Linux
`amd64` VM qualification described below. The record is not a Podman,
rootless, other-version, other-kernel, other-image, or `arm64` claim and does
not change the incomplete/inconclusive observer boundary.

## Non-goals

RepoPassport does not claim:

- all repositories run automatically;
- complete malware or vulnerability detection;
- complete network, process, syscall, filesystem-write history, or
  filesystem-read observation;
- complete TCP/UDP port history from a bounded polling window;
- undeclared-filesystem-write detection from retained-state snapshots, the
  opaque Docker engine-diff commitment, or activity-notification hints;
- that a container is an absolute security boundary;
- image publisher identity, provenance, or signature verification from a digest
  alone;
- that a passing scenario covers unexecuted code paths;
- that unsigned, embedded-key-only, or untrusted self-signed evidence has a
  trusted external identity;
- that the M3-a local signature establishes freshness, provenance services,
  key lifecycle, SBOM completeness, or complete M3;
- that deleting a container proves the controller host has no unrelated
  residue.

## Security testing

Unit and fixture tests cover traversal, link escape, bounded logs, HTML
escaping, controller-owned artifact selection, stored-evidence mutation,
workload-identity invariants, quiesce/export/remove ordering, archive hazards,
portable device-name rejection, reserved engine exit statuses, disk ceilings,
and no-commit failures. Alpha.5 qualification target `20260730T202049Z`
requires its external evidence package to report gate exit `0` and every
required source, schema, unit, integration, retained-state, cleanup, residue,
and reproducible-build result before it qualifies the exact recorded tuple.
A missing package, nonzero exit, skipped required case, or tuple mismatch
qualifies nothing.

This source document does not claim completed Alpha.18 local/repro or fixed-VM
security qualification. Only a final source-bound evidence package containing
all required static, unit, integration, race, live, residue, cleanup, and
reproducibility results may make that claim.

Local/repro record `20260731T085753Z` passed formatting, vet, reachable
vulnerability scanning, complete and shuffled Go tests, integration-tag
compilation, release smoke checks, and byte-identical rebuilds.

Live record `20260731T085836Z` passed all 19 ordered guest gates and all 12
required cases on Docker client/server 29.1.3 in an isolated Ubuntu 24.04.4
LTS, kernel 6.8.0-134-generic, Linux `amd64`, cgroup-v2 QEMU VM. It includes
Linux race testing and sequential Node/Python peer-listener evidence.
Container, network, volume, source, and host-listener inventories matched
before/after; guest cleanup and final QEMU/seed shutdown passed without force.
The evidence is unsigned and exact-tuple only. Capability remains
`incomplete`, overall remains `inconclusive`, and M1/M2 remain incomplete.

Historical live record `20260730T173121Z` passed all 18 gate steps
and all ten required cases on Docker client/server 29.1.3 in an isolated
Ubuntu 24.04.4 kernel 6.8 Linux `amd64` cgroup-v2 QEMU VM. The cases cover
Node/Python CLI,
Node/Python HTTP, forged-workload evidence, TERM-resistant-child escalation,
early service exit, readiness timeout, expected-`ENOSPC` enforcement, and
`TestContainerResourceUsageObservation`.
Source and host-listener manifests were unchanged, before/after all-container
inventories were header-only, and no host-publish residue remained. This is
only a result for that exact Docker/VM/cgroup/image tuple; it is not a Podman,
rootless, other-Docker-version, other-kernel, or `arm64` claim. Local/repro
record `20260730T173051Z` also passed; `govulncheck` found zero reachable and
zero imported-package vulnerabilities, with required-module-only
`GO-2026-5970` not called by the analyzed code. The nine-case
`20260730T150346Z` `alpha.3`, `20260730T102841Z` `alpha.2`, and
`20260730T074535Z` `alpha.1` records remain historical. No functional record
repairs observer gaps: healthy runs remain capability `incomplete` and overall
`inconclusive`, M1 remains incomplete, and evidence remains unsigned.
Additional observer-conformance cases remain required before a stable release.
Malicious fixtures use synthetic data.

Report vulnerabilities through [SECURITY.md](../SECURITY.md).
