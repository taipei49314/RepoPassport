# Known limitations

RepoPassport `v0.1.0-alpha.33` is an early reference implementation with a
deliberately narrow truthful scope. This document is part of the product
contract.

## Alpha.33 offline trust-policy authority-chain boundary

- Only explicit offline chains of 2..8 existing Alpha.32 transitions are
  supported. There is no root discovery, recursive fetch, certificate path,
  expiry, threshold, KMS/HSM, Sigstore/OIDC, transparency, or remote service.
- The caller-supplied root is the only initial trust anchor. Embedded and
  exact-three companion keys do not bootstrap trust.
- Root, intermediate, and terminal authority IDs are globally unique and
  cannot be trusted or revoked evidence signers in the terminal policy.
- Chain state is a separate root-scoped local combined record. It is not
  migrated from or compared with direct or one-hop state; changing modes has
  no claimed rollback guard. Deletion, restore, copy, rename, or fork can also
  reset or fork local history.
- Generations are counters, not trusted time. A compromised accepted root can
  authorize a malicious complete chain; this is continuity, not compromise
  recovery or historical revocation.
- Portable kits contain no chain/policy/root/private-key sidecar and expose no
  chain producer. Identity/time remain `none`, `formalClaim=false`, capability
  `incomplete`, and overall `inconclusive`.

## Alpha.32 offline trust-policy authority-transition boundary

- Only one explicit previous-root-authorized hop is supported. There is no
  policy-authority chain, root discovery, recursive fetch, certificate path,
  expiry, threshold, KMS/HSM, Sigstore/OIDC, transparency, or remote service.
- The exact-three output includes terminal and previous public-key companions;
  neither is a trust anchor. Supplying the producer output as its own trust
  bootstrap defeats the intended external-root assumption.
- Rotation state is one root-scoped local combined record. It is atomic across
  transition and policy dimensions, but deletion, restore, copy, rename, or
  fork can reset/fork history. Direct Alpha.31 per-authority state is not
  silently migrated into this namespace.
- Both generation axes are monotonic counters, not trusted time. A compromised
  accepted previous root can authorize a malicious terminal key; this is
  continuity, not compromise recovery or historical revocation.
- The portable kit contains no transition/policy/root/private-key sidecar and
  exposes no producer. Identity/time remain `none`, `formalClaim=false`,
  capability `incomplete`, and overall `inconclusive`.

## Alpha.31 offline trust-policy issuer boundary

- The full CLI can author and sign only the existing canonical
  `offline-trust-policy-v2` shape. It accepts 1..32 canonical Ed25519 SPKIs,
  trusted/revoked decisions, one safe-integer generation, and one separate
  canonical PKCS#8 Ed25519 authority key. Other algorithms, certificates,
  thresholds, expiry, comments, metadata, and policy extensions are rejected.
- It does not generate, store, back up, rotate, revoke, discover, or distribute
  keys. There is no KMS/HSM/TPM, Sigstore/OIDC, transparency log, hosted policy
  service, remote publication, or secure-erasure guarantee.
- The exact-two output directory contains the signed envelope and authority
  SPKI companion. The companion is not a trust anchor. A verifier must still
  receive the intended authority SPKI through an independent trusted path and
  enforce its own minimum generation.
- Atomic publication protects against partial output and overwrite within the
  supported local parent-directory assumptions. It is not a security boundary
  against an administrator or a hostile writer replacing the trusted parent
  namespace concurrently.
- The portable verifier intentionally has no producer command, private key,
  policy sidecars, or automatic trust bootstrap. Identity/time remain `none`,
  `formalClaim=false`, capability `incomplete`, and overall `inconclusive`.

## Alpha.30 external release-index authority-transition-chain boundary

Alpha.30 accepts an explicit, offline transition chain of 2..8 hops only. It
does not discover roots, recursively fetch authorities, establish historical
revocation, or turn a companion key into a trust anchor. Chain generation is
not trusted time. Persisted chain state is controller-local and can be reset or
forked by deletion, restore, copy, rename, or fork of the selected data root.

- Direct release-index acceptance remains relative to the exact caller-supplied
  authority SPKI and its root-signed, purpose-separated release-key policy.
  Rotation is only one explicit old-root-authorized hop to one distinct next
  policy authority; there is no automatic root discovery or root lifecycle.
- The external index, envelope, signer SPKI, policy, authority root, local
  transition, state, and evidence are outside the indexed artifact root. The
  portable kit contains none of those sidecars, no root/private key, and no
  evidence.
- A valid DSSE signature proves cryptographic authorization and exact inventory
  binding, not legal publisher identity or trusted build/publication time.
  Identity and time attestation are `none`, `formalClaim=false`, capability is
  `incomplete`, and overall is `inconclusive`.
- Publisher identity, trusted time, historical revocation, transparency,
  KMS/HSM, threshold signing, remote publication/fetch,
  tamper-resistant/distributed state, and universal replay prevention remain
  unsupported.
- Artifact processing is deliberately bounded: 128 MiB per file, 512 MiB per
  exact set, and 64 KiB for `SHA256SUMS`; larger releases are unsupported.
- Stateful authority-transition, policy, and release rollback/equivocation
  detection is relative only to each surviving local record. Deleting,
  restoring, copying, renaming, or forking the selected data root can reset or
  fork history. Generation numbers are not trusted time, while exact-digest
  mode is only as authoritative as the caller's pin.
- Artifact verification compares two complete stable scans, but the filesystem
  is not snapshotted atomically. The root must be quiescent and controlled by
  the trusted operator; hostile concurrent namespace/content mutation is not a
  supported security boundary.

## Alpha.27 portable-verifier boundary

- Portable verifier kits target only Linux/amd64 and Windows/amd64. They do not
  establish macOS, arm64, or other-platform compatibility.
- Kit input executables are limited to 32 MiB; validation still materializes
  bounded canonical copies in memory and is a trusted build-time operation.
- A kit contains verification software and its manifest, usage, and trust-
  boundary text. It intentionally contains no evidence bundle, evidence public
  key, private key, trust policy, timestamp, transparency proof, or publisher
  identity.
- Historical offline replay requires no live worktree or network. Explicit
  `--current-manifest` comparison and persisted signed-policy state require the
  caller-selected local source and data directory and are not self-contained
  kit guarantees.
- Signature validity and trust remain separate. An embedded or adjacent public
  key cannot authorize itself; acceptance still depends on independently
  supplied exact trust material under the existing verifier rules.
- Canonical packaging and reproducible bytes do not prove who built or
  distributed a kit. There is no Sigstore/OIDC, transparency, trusted time,
  KMS/HSM, historical revocation, or universal trust bootstrap.
- Portable replay does not rerun a source qualification, VM, container, or
  race test and cannot upgrade capability `incomplete`, overall
  `inconclusive`, or `formalClaim=false` evidence.

## Alpha.26 typed qualification-evidence limits

- Typed receipts reduce the public fixed-VM evidence surface; they do not prove
  that arbitrary future inputs contain no secrets or organization-specific
  metadata.
- Raw runner artifacts still exist transiently in private bounded workspaces so
  deterministic parsers can produce receipts. Cleanup is attempted on all
  exits, but this is not secure erasure or protection from a compromised host.
- An exact parser validates each public slot. It cannot prove the truth of a
  maliciously controlled producer without the independent source, harness,
  environment, and runner bindings retained by qualification.
- The historical Alpha.26 external index remains unsigned and provides no
  author identity, trusted time, transparency, or authority policy. Alpha.29
  does not retroactively sign or reinterpret that historical evidence.
- Runtime observer coverage, Alpha.25 listener sampling blind spots, healthy
  `incomplete`/`inconclusive`, `formalClaim=false`, and incomplete M1/M2/M3 are
  unchanged.

## Alpha.22 local authenticated policy-state boundary

- Alpha.22 introduced a verifier-only mode. Alpha.31 adds the bounded local
  producer described above, but still provides no private-key management,
  authority-key rotation, revocation history, or lifecycle facility.
- It authenticates a canonical `offline-trust-policy-v2` payload only relative
  to the caller-supplied canonical authority SPKI and enforces only that
  invocation's minimum generation. The signed safe integer range is
  `1..9007199254740991`.
- With the complete signed triple, exactly one valueless
  `--persist-trust-policy-state` can retain a per-authority local monotonic
  record under global `--data-dir` (or its default). It detects only rollback
  and same-generation payload equivocation relative to the surviving record.
  On Windows, new state-directory components and lock files receive their
  protected private DACL in the create operation; unsafe existing objects are
  rejected and not repaired. This reduces only a creation-time ACL window.
  It does not protect against deletion, replacement, restore, or fork of that
  directory, and intentionally observes qualified policies before evaluating a
  `revoked` or `not-listed` evidence signer.
- Tamper-resistant/distributed policy state, trusted time, expiry, historical
  revocation, authority lifecycle, KMS/HSM, Sigstore/OIDC, transparency,
  hosted trust, complete M3, capability conformance, and overall verification
  remain unsupported. Capability is `incomplete` and overall is
  `inconclusive`, `formal_claim=false` remains mandatory, and Alpha.21 and
  earlier evidence are historical and bind only their exact source.

## Alpha.19 offline trust-policy boundary

- The policy is a local operator-selected file, not a signed or remotely
  authenticated trust root. Its required digest detects byte changes but does
  not establish authorship, distribution integrity beyond that independent
  pin, authorization provenance, or anti-rollback.
- Only Ed25519 `spki-sha256` identities are supported. The policy does not
  generate, store, rotate, or remotely resolve keys, and does not add
  KMS/HSM/TPM, Sigstore/OIDC, certificate, transparency, or hosted-policy
  integration.
- `revoked` is a present-time decision under the supplied policy. There is no
  trusted signing time, expiry, historical policy state, or proof that a key
  was revoked when the bundle was signed.
- Policy acceptance authorizes only the existing bounded replay claims. It
  does not make an incomplete capability complete, turn an inconclusive
  overall verdict into verified, or complete M3.

## Alpha.18 derived SPDX boundary

- `attest --derive-spdx --current-manifest FILE` is limited to static root
  `package.json` plus lockfile-version-3 `package-lock.json`; it is not general
  npm compatibility and never runs npm, Node, Git, network access, or repository
  commands.
- It requires two matching snapshots before derivation and a third before
  signing. Its checksum validation is shape-only: it does not download from,
  authenticate, or verify against an npm registry.
- The current snapshot must exactly equal the authoritative verification
  subject. This command-free profile has an empty Commit, so it supports only
  the same local/exported non-Git identity; a Git-commit subject fails closed.
- Derived-SBOM replay requires explicit trust and a raw-bundle digest pin before
  source access; `fresh`, `stale`, and `unknown` are separate currentness
  outcomes, not replacements for signed historical verdicts.
- No package-discovery/completeness, SBOM truth, supplier provenance,
  license/vulnerability analysis, complete M3, capability conformance, or
  overall verification is claimed. Sealed Alpha.18 qualification evidence is
  historical, applies only to its exact source, and does not qualify Alpha.19.

## Platform scope

- The initial workload target is Linux.
- A Windows or macOS CLI may act as a controller through Docker Desktop or a
  Podman machine, but that does not mean a Windows or macOS workload was tested.
- Reports distinguish controller OS, workload OS, engine version, runtime, and
  selected backend. Engine VM identity and a portable runner-profile digest are
  not yet recorded.
- The public manifest schema recognizes Linux `amd64` and `arm64`, but the
  executable `baseline-v1` runtime policy currently approves exact Node and
  Python tuples only for Linux `amd64`. An `arm64` manifest therefore fails
  closed before a plan is produced.
- Docker and Podman are separate backends. This snapshot has no general
  engine-version compatibility matrix. The historical Alpha.8 live record
  `20260731T085836Z` binds only Docker client/server 29.1.3, Ubuntu 24.04.4 LTS,
  kernel 6.8.0-134-generic, Linux `amd64`, cgroup v2, QEMU, and the two exact
  approved Node/Python images. It passed all 19 ordered guest gates and all 12
  required cases. Podman, rootless engines, other Docker versions or kernels,
  other images, and `arm64` remain unclaimed. Older records remain historical
  and do not qualify or broaden Alpha.17.

## Minimal-public privacy boundary

- Alpha.14 blocks a frozen bounded set of high-confidence credential, private
  path, URL query/userinfo, email, sensitive dynamic-field, public-resource,
  and entropy-candidate patterns. False positives fail closed.
- This is not universal secret/PII detection, complete redaction, anonymity,
  unlinkability, encoded/encrypted-secret detection, raw-log cleanup, or
  remote-publication safety.
- Exact UTC timestamps and opaque IDs remain linkable/time-revealing public
  metadata. Portable paths, observations, assertions, and policy decisions
  also remain public when they pass the bounded gate.
- `privacyEvaluation: passed` is the decision of the exact current binary, not
  an independently signed privacy proof or evidence about an older verifier.

## Container isolation

- A local container is not an absolute security boundary.
- Hosted execution requires a stronger per-job VM boundary and is not part of
  the first local slice.
- Rootless mode is reported only after an active feature probe. Docker Desktop
  must not be labeled rootless by assumption.
- Repository commands execute as a fixed non-root user. The long-lived
  sandbox's controller-selected idle process runs as root with only
  `DAC_OVERRIDE`, `FOWNER`, and `KILL` added so trusted
  initialization/finalization can quiesce workload processes and repair the
  bounded output tree. Fixed finalization also invokes `/bin/tar` as root.
  Repository command lines do not control those helper arguments, but the
  selected image runtime and tar binary remain part of the local trust boundary.
- In the HTTP slice, the attached repository service runs as UID/GID `65532`.
  The controller-supplied bounded readiness/request helper is a separate
  trusted process running as UID/GID `65533`. Both run in the same container,
  which is created with `--network none`; no host port is published.
- Alpha.8's Docker-only port observer is a separate peer container running as
  UID/GID `65534`. It shares only the target's network namespace through
  `--network container:<immutable-64hex-target-id>`; strict checks require
  different PID, mount, IPC, and cgroup namespaces. It has no host port,
  mounts, devices, privilege, or added capabilities.
- On the Python tuple, controller-supplied trusted helpers run with
  `python -I -S` and working directory `/`. They do not use `/workspace` as an
  import root, which prevents repository modules from shadowing their imports.
- HTTP readiness/request timeouts are absolute wall-clock deadlines; they are
  not socket-inactivity timers. Runner-owned slack is reserved for cancellation
  and helper-exit handling and does not extend the functional deadline.
- The UID/GID `65533` driver must exit synchronously before another readiness
  attempt or cleanup. If it does not, a trusted root helper must quiesce it;
  inability to confirm exit or quiescence fails closed.
- Digest pinning prevents image substitution; it does not establish image
  publisher trust. The local alpha accepts only the exact built-in Node/Python
  tuples in `docs/release.md`; their binding is included in the policy digest.
  A local operator must still trust and pre-pull the selected tuple. Its
  runtime-version probe is a bounded self-report from that image, not independent
  supply-chain attestation.
- CPU, memory, and PID limits are passed to the engine as container-create
  flags. A rejected flag or failed create stops execution, but the first
  backend does not publish a separate per-limit support probe.
- Source, workspace, and fixture mounts are read-only. Writable `/outputs`,
  workload home, and temporary storage share one engine-managed tmpfs whose
  size is the declared disk limit. The cap is aggregate, so temporary data
  reduces the space available for declared outputs. The local runner rejects
  disk limits above 2 GiB.
- After workload processes are quiesced, fixed finalization removes disposable
  home/temp state, rejects special output entries, and streams an uncompressed
  USTAR archive from `/bin/tar`, with fixed one-block framing and explicit
  `.home`/`.tmp` exclusions. Go code extracts into private staging and rejects
  links, special files, extended metadata, path escape, non-portable Windows
  names, case-fold collisions, entry-count overflow, and logical or archive
  bytes beyond their caps. Only a second validated inventory is atomically
  committed. The sandbox is forcibly removed even when export fails.
- Stopped or paused engine tmpfs content was not reliably available through
  engine `cp` in live testing, so that disproved route is not used. The
  quiesce/tar-stream path still requires the live-container gate for every
  claimed engine/version pair.

## Observation

### Alpha.25 peer TCP-listener limits

The peer listener comparison samples only Linux TCP LISTEN tables in its exact
Docker/amd64 approved Node-or-Python single-service HTTP profile. Its public
shape is aggregate-only (fixed non-sensitive observer metadata,
`comparisonResult`, `evidenceBasis`, and, only when complete, exactly four
endpoint-related baseline/declared/sampled/undeclared counts). It must not publish raw
endpoint identity. Sampling may miss a short-lived listener and has no UDP,
Unix socket, outbound/NAT, process attribution, or broader baseline coverage.
`not-tested` has no comparison counts. Therefore required `port-listen` remains
capability-incomplete and no formal claim is made.

- Alpha.8 adds a controller-owned Docker-only TCP listener observer for the
  supported single-service Node/Python HTTP profile. The peer uses the target's
  exact pinned Linux `amd64` image/runtime. Its attached transport is started
  asynchronously with the fixed shell-free
  `docker start --attach --interactive <immutable-64hex-peer-id>` argument
  vector, and strict 64-hex target/peer identities, run/observer labels, image,
  running state, and namespace relationships are rechecked across the session.
- The peer runs as UID/GID `65534` with a read-only root, `cap-drop=ALL`,
  `no-new-privileges`, 64 MiB memory and swap, 16 PIDs, and 0.25 CPU. It has no
  binds, mounts, devices, published ports, privileged mode, or added
  capabilities.
- The Node/Python observer reads only `/proc/net/tcp` and
  `/proc/net/tcp6`, treats state `0A` as TCP `LISTEN`, and samples every 100 ms
  for at most 1,200 samples. It accepts at most 16 endpoints and 4,096
  transitions, a maximum 1,000 ms sample gap, and at most 1 MiB of canonical
  data. The observer window starts immediately before service dispatch, not
  setup or build.
- A complete session requires the exact declared
  `127.0.0.1:<port>/tcp` endpoint to be absent in the initial barrier, observed
  listening during the window, and absent in the final barrier after workload
  quiescence. The peer is forcibly removed before the target container.
- Control uses a cryptographically random 256-bit token delivered only through
  bounded stdin JSONL, with exactly one `READY` and one `FINAL`. Frames are
  capped at 8 KiB, total stdout at 16 KiB, and stderr at 8 KiB. Dirty stderr,
  invalid UTF-8, malformed, unknown, duplicate, missing, trailing, or oversized
  data, timeout, overflow, identity/namespace mismatch, excessive sample gap,
  incomplete quiescence, or failed finalization makes the observation
  `unavailable`. Observer failure is supplemental and does not rewrite the
  functional journey verdict; peer-removal failure is independently a cleanup
  error.
- Public `port.listener-trace.summary` evidence is aggregate-only. It excludes
  the token, raw `/proc` rows, inode data, and undeclared endpoint details. The
  canonical digest is a helper commitment, not a controller-recomputed
  attestation.
- A complete peer session provides only `best-effort` sample-window coverage.
  The 100 ms polling interval can miss short listener intervals, and UDP,
  connections, attempted destinations, process ownership, and general port
  history remain unobserved. Required `port-listen` therefore remains
  capability `INCOMPLETE`, and a healthy journey remains overall
  `INCONCLUSIVE`. Podman port observation is `unavailable`.
- Alpha.7 adds a Docker-only bounded `/outputs` activity trace. The controller
  starts a trusted root helper before workload execution with the exact
  shell-free `docker exec --interactive --user 0:0 ...` transport and stops it after
  workload quiescence.
- The helper requires strict bounded stdin/stdout JSONL with exactly one
  `READY` and one `FINAL`. Its cryptographically random session token crosses
  only stdin and is never present in argv, environment variables, logs, or
  public evidence. Dirty stderr, nonzero exit, timeout, invalid/extra/trailing/
  oversize frames, identity mismatch, overflow, a detected gap, or a bound
  mismatch makes the whole trace `unavailable`.
- Each frame is capped at 8 KiB, total stdout at 16 KiB, stderr at 8 KiB,
  notifications at 4,096, and the canonical transcript at 1 MiB. No
  workload-writable control file is created.
- Raw paths remain only in bounded helper memory. Public evidence is
  aggregate-only: notification and controller-window phase-hint counts plus a
  per-session keyed canonical transcript digest. It contains no paths,
  contents, actors, operations, or syscall history.
- Node manually installs non-recursive per-directory `fs.watch` watchers with
  a 2,048-watch cap. Kernel queue-overflow detection is unavailable for that
  adapter. Python uses inotify with the same watch cap and fails closed on
  inotify queue overflow.
- Dynamic watch-installation races, notification coalescing, reads, rename
  pairing, watched-directory replacement, exact operation semantics, exact
  phase attribution, and actor attribution remain blind spots.
- The helper has `observerPlacement=in-sandbox-trusted-helper` and
  `sharesSandboxResourceBudget=true`; its CPU, memory, tasks, and tmpfs effects
  can perturb sandbox resource measurements. Podman activity tracing is
  unavailable until separately live-qualified. A complete Docker trace still
  provides only `best-effort` notification hints.
- Historical Alpha.6 adds a Docker-only engine writable-layer diff component. The
  controller uses no shell and invokes exactly
  `docker container diff <immutable-64hex-id>` after verifying the full
  immutable container ID.
- Docker CLI stdout and stderr are each limited to 4 MiB. Exit must be `0`,
  neither stream may truncate, and stderr must be empty. A failure or dirty
  transcript gives the component `unavailable` without failing the functional
  journey or stopping later repeats.
- Stdout is an opaque byte transcript because filenames may contain newlines.
  RepoPassport does not parse or publish paths or `A`/`C`/`D` records and does
  not expose the raw transcript. Public evidence contains only a SHA-256
  commitment, byte count, and nonempty flag.
- The pre-workload engine-diff baseline is diagnostic only and does not grant
  or downgrade coverage. Only a final collection after workload quiescence and
  before permission repair, with container identity reverified, can give this
  component `best-effort`.
- Docker reports changes cumulatively since container creation. The final
  transcript may include trusted initialization, observer, and other
  pre-workload activity, and it cannot attribute actor, operation time, or
  workload phase. It is not complete operation history: transient
  create/delete, write-then-restore, and same-classification rewrites can be
  invisible.
- Engine writable-layer scope excludes the separate `/outputs` tmpfs and bind
  or other mounts, including source, workspace, and inputs. The supported
  container root filesystem remains read-only. This component does not
  establish undeclared-write conformance.
- Alpha.24 adds only a bounded positive notification detector for the exact
  Docker/Linux/pinned-Python/CLI synchronous foreground tuple. It can flag
  complete unmatched mutation notifications for transient create/delete,
  write-then-restore, and a path authorized only in another controller phase.
  It is not full filesystem operation history and does not make a healthy run
  conforming or verified: composite filesystem-write coverage stays
  `best-effort`, capability stays `incomplete`, overall stays `inconclusive`,
  and `formalClaim=false`.
- Node, Podman, non-Linux or non-Python runtimes, HTTP/services, signal
  workflows, and background execution are `not-tested`/`unavailable` for the
  Alpha.24 declaration comparison. The helper sees the active phase's existing
  `filesystem.write` rules only and publishes aggregates only; it never
  publishes paths, rule text, content, tokens, inotify cookies, or raw traces.
- Queue overflow, unknown events, a newly created directory/watch race,
  watched-directory replacement, transport or identity failure, malformed or
  out-of-order frames, unsafe path, phase acknowledgement failure, inconsistent
  separated process snapshots, unconfirmed dispatch, or any bound failure makes
  the entire window `not-tested`.
  It publishes neither partial counts nor a positive finding. Inotify
  coalescing, rename pairing, reads, syscalls, actor/process attribution,
  xattrs, ACLs, ownership, and paths outside `/outputs` remain unobserved.
  Runtime overflow/gap after readiness is represented only by a minimal exact
  session-bound typed failure terminal and exit `1`; the three public-safe
  causes are `notification-overflow`, `new-directory-watch-gap`, and
  `notification-gap`. No count, digest, path, rule, or raw event is carried by
  that failure union.
- Alpha.5 can give the `filesystem.retained-state.summary` observation event
  coverage `high` only after a complete strict, controller-owned, bounded
  snapshot pair below `/outputs`.
  The baseline is post-initialization/pre-workload and the final snapshot is
  post-quiescence/pre-repair; both verify the same immutable container identity
  and run label. The limits are 2,048 entries, 1,024 UTF-8 bytes per normalized
  path, 256 retained changes, and a 4 MiB helper-control envelope.
- Snapshot commitments cover path, type, mode, and size; regular-file contents
  and raw symlink targets contribute SHA-256. Public evidence is only an
  aggregate `filesystem.retained-state.summary` with snapshot digests, entry
  counts, and a change count. It does not expose contents, targets, or per-path
  changes.
- The snapshots include trusted helpers and runner-managed,
  workload-writable disposable `/outputs/.home` and `/outputs/.tmp`, which are
  excluded from export. They cannot see outside `/outputs`,
  transient create/delete, write-then-restore, operation time, process/phase
  attribution, rename identity, ownership, timestamps, xattrs, ACLs, inode
  identity, or device identity.
- Consequently, `FilesystemWriteObservation` is only `best-effort`; the
  required filesystem-write observer remains incomplete. Retained-state
  evidence does not implement undeclared-write detection or a full filesystem
  observer. Snapshot, identity, quiescence, bound, or decode failure is
  nonfatal and gives the summary event coverage `unavailable`, never an empty
  successful diff.
- Retained-state and engine-diff path commitments use unsalted raw SHA-256.
  Suppressing raw paths is not dictionary-resistant path secrecy:
  low-entropy candidate paths can be guessed and tested. The Alpha.7 activity
  trace's keyed digest does not strengthen those historical commitments.
- Read-only mounts and writable tmpfs confinement are enforcement facts, not
  filesystem observation.
- Filesystem read observation is generally unavailable in the first backend.
- Main process lifecycle may be known while complete child-process history is
  best effort.
- The `alpha.4` resource observer is not a general host or
  repository-process profiler. It reads sandbox cgroup-v2 CPU time,
  cgroup-wide peak memory, and peak tasks; records final writable allocation,
  verified accepted output, and captured controller logs; and requires every
  field for every repeat. Memory includes cache, tmpfs, kernel memory, and
  trusted helpers and is not RSS. Peak tasks count threads as well as
  processes. Writable allocation is a final snapshot, not a historical peak,
  so transient write/delete growth may be missed.
- Live record `20260730T173121Z` validates `ResourceUsage=high` only on the
  exact Docker 29.1.3 / Ubuntu 24.04.4 / kernel 6.8 / Linux `amd64` / cgroup-v2
  / approved-image tuple. Podman, rootless engines, other versions, kernels,
  architectures, and images have no such claim. Any probe/snapshot failure
  remains unavailable/incomplete and is not converted to a zero value.
- External network deny can be enforced without revealing attempted hostnames or
  IP destinations.
- No observed network event means only that the scenario and available observer
  did not see one. It does not prove all code paths are offline.
- Host-wide residue outside the sandbox is not observable because host mounts
  are prohibited.

Reports show coverage for every observation category. In the current verifier,
coverage below `high` for a required observer produces capability
`INCOMPLETE`, which makes the overall result `INCONCLUSIVE`. Missing hard
execution enforcement may instead block before a workload starts.

The built-in Docker/Podman CLI feature report currently supplies full network
deny enforcement, best-effort foreground process and composite filesystem-write
coverage, and retained-state summary event coverage `high` only after a
complete snapshot pair. Docker additionally offers the bounded opaque
engine-diff component, bounded aggregate activity notification hints, and
`best-effort` port-listen coverage only after a complete alpha.8 peer session
for the supported HTTP profile. Podman offers none of those three Docker-only
observers, and other profiles have `unavailable` port observation.
Because the
resolved plan includes
required observer categories that remain below `high`, this backend cannot
currently produce capability `CONFORMING` or an overall `VERIFIED` result even
when the functional journey passes. Resource-limit enforcement is separate
from observation and cannot satisfy `ResourceUsage`. Executing a trusted
loopback journey helper does not itself upgrade port or child-process
  observation. Neither M1 nor M2 is complete. The original verification result
  remains evidence `unsigned`; an Alpha.11 signature may wrap that immutable
  historical artifact without changing its verdicts.

## Journey support

- Dependency-free CLI journeys remain executable.
- Alpha.9 CLI `stdoutJsonSchema` supports one local, offline Draft 2020-12
  schema. The trusted controller requires complete stdout to be exactly one
  strict JSON document bounded to 1 MiB, depth 128, 100,000 nodes, and exponent
  `-1000..1000`. Shared stdout/stderr log truncation is `inconclusive`;
  complete malformed JSON or schema mismatch is `failed`.
- The schema path, digest, dialect, and validator version are sealed in the
  resolved plan. Assertion evidence omits raw stdout, parsed values, property
  names, stdout hashes, and byte counts. The verifier binds the controller
  result but does not independently recapture stdout.
- Current Alpha.15 resolved plans use schema version `"4"` with CLI driver
  `0.2.0`; Alpha.10 schema version `"3"` is historical;
  the HTTP driver remains `0.1.0` and the manifest API stays
  `repopass.dev/v1alpha1`. Version-1, version-2, and version-3 locks yield `PLAN_DRIFT` and
  require regeneration. Old evidence remains historical and read-only.
- Alpha.10 cleanup inventory observes only retained entry path/type/mode below
  the final `/outputs` tmpfs. It does not observe transient create/delete,
  actor, time, content, access, or state outside `/outputs`, and does not raise
  filesystem-write coverage. Its opaque one-time token uses a fresh HMAC key,
  but the key and raw inventory are discarded; the token cannot be opened or
  independently recomputed and is neither an attestation nor proof.
- `alpha.10` retains exactly one attached HTTP service for the exact approved
  Node or Python Linux `amd64` tuple. The service runs as UID/GID `65532`; the
  bounded trusted helper runs as UID/GID `65533`.
- The HTTP service and helper share one `--network none` container and its
  loopback interface. No host port is published. Every readiness/request URL
  must be canonical, be no longer than 2,048 UTF-8 bytes, use literal
  `http://127.0.0.1:<explicit-port>`, match the scenario's one declared TCP
  listener, and remain on the same origin.
- Readiness and requests are bounded by absolute deadlines expressed as whole
  milliseconds of at least 1 ms. Fractional seconds are valid when they resolve
  exactly to whole milliseconds (`1.5s` becomes 1,500 ms); sub-millisecond
  values such as `1.5ms` are rejected. Readiness is capped at 2 minutes, uses
  exponential retry backoff, and stops after at most 128 attempts. Declared
  readiness and response statuses are 200–599. `service.start` is not recorded
  as succeeded until readiness succeeds. Each explicit request timeout and the
  resolved exercise fallback used when omitted are capped at 30 minutes; that
  fallback is `phases.exercise.timeout`, or 1 minute when absent.
- A journey has at most 128 ordered steps and 32 requests. Effective request
  headers must simultaneously satisfy count ≤ 64 and aggregate bytes ≤ 65,536,
  with no value longer than 8,192 bytes. The aggregate is
  `sum(len(name bytes) + len(value bytes) + 4)` over every effective header;
  accepted names and values are ASCII, so these are also their UTF-8 byte
  lengths. The automatic JSON `content-type` is included in both the count and
  aggregate. Text request bodies and the actual serialized bytes of JSON
  requests are each limited to 1 MiB. The implemented assertion subset is
  response status, header substring, `bodyContains`, `fileExists`, singular
  `jsonPath.equals`, offline Draft 2020-12 response `jsonSchema`, and ordered
  `jsonFile`; header `contains` is capped at 8,192 bytes, while non-empty
  `bodyContains` is capped at 1 MiB.
- HTTP `fileExists` is checked at its ordered journey position by trusted
  in-container `lstat`. It is confined to normalized UTF-8 `/outputs` paths of
  at most 4,096 bytes and rejects a symlink in the target or any parent
  component. It is not merely a post-run exported-file check.
- Structured JSON response/file bodies are capped at 1 MiB and strict-decoded.
  Explicit and effective decimal exponents are limited to `-1000..1000`.
  Schema files are capped at 256 KiB and bound by portable path, SHA-256,
  dialect, and validator version. `jsonFile` is confined to regular files below
  `/outputs` and is a point-in-time assertion. Raw JSON and extracted values
  are not included in assertion evidence.
- The profile requires exactly one cleanup signal targeting the service. The
  trusted helper applies the declared signal and grace period, escalates
  survivors to `SIGKILL`, and finalization quiesces UID/GID `65532` before
  output export and forced container removal. Signal success requires at least
  `initialTargets >= 1` and `sent >= 1`; it does not require every initial
  target to receive the signal. If enumeration races process exit and no send
  succeeds, cleanup fails closed. Every signal type, including `kill`, requires
  a whole-millisecond grace period from 1 ms through 10 seconds. The
  synchronous UID/GID `65533` helper exits after each operation or is
  root-quiesced before cleanup. The service signal is the last cleanup step and
  final resolved command, and the runner keeps separate slack for
  signal-helper completion.
- Full RFC 9535 JSONPath, remote/cross-file schema resolution, redirects, TLS,
  request authentication, arbitrary sandbox file reads, and multiple services
  remain unsupported. These declarations fail closed; they are not silently
  ignored or approximated.
- The runner uses `--pull=never`. An operator must pre-pull the exact
  policy-approved tuple outside verification; mutable tags and unapproved
  digest-pinned images are rejected.
- An exact runtime version is bound into the plan and probed inside the selected
  image before workload commands run. A mismatch fails closed. Live-gate
  coverage is still required for each engine/runtime combination.
- Declared non-zero CLI journey exits outside 125–127 are covered by unit
  tests. Docker/Podman reserve 125–127 for CLI or exec-setup failures, so the
  runner always treats those statuses as operational failures even when a
  journey declares one. Container state is inspected only for bounded
  diagnosis; it does not convert a reserved status into a trusted workload
  exit. Supporting a genuine workload exit in that range requires a later
  runner-owned sentinel protocol.

## Discovery and language support

- The v0.1 portable snapshot and accepted-output profiles allow printable ASCII
  path segments only. Both reject Windows-reserved characters, trailing
  dots/spaces, the device basenames `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  and `LPT1`–`LPT9` (including extension forms), plus the conservative aliases
  `CONIN$`, `CONOUT$`, and `CLOCK$`.
- Initial static discovery focuses on conventional Node and Python projects.
- Discovery does not install dependencies, run lifecycle scripts, execute
  `setup.py`, import a module, or execute README snippets.
- Generated commands remain proposals until the maintainer confirms a manifest.
- Node `dev` scripts are never chosen as a formal verification entry point
  unless explicitly declared.
- Monorepos, unusual build systems, notebooks, models, datasets, desktop apps,
  and mobile apps require later adapters.

## Networked setup

- Dependency-free or prebuilt fixtures are preferred.
- An ordinary container network is not a package-registry allowlist.
- A setup allowlist requires an actual controlled proxy or firewall with
  destination enforcement and evidence.
- Runtime external egress denial is the most reliable initial mode.

## Verification

- One run has reproducibility `NOT_TESTED`, not `STABLE`.
- The alpha executable profile requires an all-matching repeat contract
  (`successThreshold == repeats`). Threshold-tolerant functional aggregation is
  deferred and must fail closed rather than use partial semantics.
- Verification covers only the declared scenario and inputs.
- Functional `PASS` does not override capability `NONCONFORMING`.
- Missing observation never becomes capability `CONFORMING`.
- Overall aggregation remains versioned normative behavior and cannot be
  customized by adapters or workloads.
- Cleanup confirms forced container removal and deletion of the
  controller-owned ephemeral work root. HTTP cleanup additionally confirms its
  signal/escalation/quiescence lifecycle. Alpha.10 also classifies a bounded,
  no-follow `/outputs` inventory against the exact resolved
  `cleanup.allowedResidue` profile; it publishes aggregate counts and an opaque
  one-time token, never raw paths, link targets, or file content. The token has
  no retained key or raw inventory and cannot be opened or independently
  recomputed.
- Workload quiescence, permission repair, tar streaming, safe extraction,
  no-commit failure branches, and forced removal are unit tested with a fake
  command backend. Archive parsing has cross-platform adversarial tests. A real
  Docker/Podman run remains required before claiming the same behavior for an
  engine/version pair.

## Evidence

- The M3 implementation is partial. Alpha.11 implements M3-a local
  attestation, Alpha.13 adds bounded retained replay, Alpha.14 adds the frozen
  privacy gate, Alpha.15/18 add bounded SPDX models, Alpha.16 adds bounded
  freshness, Alpha.19 adds one digest-pinned policy input, Alpha.20 adds a
  verifier-only authenticated policy floor, and Alpha.21 adds opt-in local
  monotonic policy state. They do
  not complete portable evidence, provenance, or M3.
- An authoritative verification may still record evidence `unsigned`.
  Attesting it preserves that exact historical result and does not upgrade any
  functional, capability, reproducibility, cleanup, evidence, freshness, or
  overall verdict.
- Resolved-plan schema version `"4"` binds exactly two supported
  `minimal-public` selections: normalized observations plus verification
  summary, with or without `sbom`; the exact three raw exclusions remain
  required. `local-full`, custom include/exclude sets, and other attachment
  formats remain unavailable.
- `sbom` requires one strict caller-supplied SPDX 2.3 JSON file. The bounded
  derivative is signed and replay-validated, but RepoPassport does not generate
  it, discover dependencies, evaluate licenses/vulnerabilities, establish its
  producer, or guarantee completeness, correctness, or currentness.
- The local signer supports only a canonical Ed25519 PKCS#8 signing key,
  canonical SPKI public key, and one DSSE signature. Trust is either exact
  explicit public-key equality, the bounded canonical Alpha.19 policy, or the
  verifier-only Alpha.20 signed-policy floor, optionally guarded by Alpha.21
  local monotonic state. The
  public key embedded in the bundle and its SHA-256 key ID identify the signer
  but do not create trust. Without either mechanism, a valid signature is
  `unknown`, not accepted; an invalid trust input is rejected.
- Companion equality and expected-bundle digest equality are package-
  local integrity checks, not maintainer identity, CA validation,
  transparency, timestamping, revocation, or external trust.
- Signature validity, signer identity, trust, and freshness are separate
  results. Without `--current-manifest`, `freshnessEvaluation` remains
  `not-evaluated`. Opt-in freshness requires exactly one accepted trust
  mechanism and a raw-bundle digest pin, then compares a caller-identified local source,
  current deterministic policy/plan, and a finite stable profile from only the
  signed backend. The embedded `originalResults.freshness` remains historical
  and is never re-aggregated or upgraded.
- The historical verification stores portable source identity but not the
  former local source path. The caller must supply the current manifest;
  RepoPassport does not infer that it is the historical checkout. The bounded
  triple-snapshot consistency check is not immunity to a hostile concurrent
  namespace swap. It does not rerun the scenario, evaluate elapsed age,
  establish Git/remote/registry provenance, recover complete runner identity,
  re-observe execution coverage, or prove SBOM currentness.
- Sigstore, OIDC identity, transparency logs, KMS, TPM/HSM, hardware-backed
  keys, managed key generation/lifecycle/distribution, trusted timestamping,
  historical/effective-time revocation, authenticated hosted policy, SBOM
  generation/independent validation, and remote publication are unavailable.
- Signing keys must remain outside the authoritative data store and output
  location and, when a current repository is detectable from the working
  directory through `.git` or `repo-passport.yml`, outside that repository.
  Regular-file, canonical-encoding, permission,
  link/reparse, hard-link, and platform path checks fail closed. On Windows,
  the current owner must be explicit and the DACL may grant access only to that
  owner, SYSTEM, and Builtin Administrators. A filesystem/provider on which
  this cannot be proved is unsupported for signing.
- Bundle output uses same-directory staging and no-replace publication. It does
  not claim protection against a hostile concurrent rename, symlink, or
  junction swap of the output parent. It also does not claim universal
  power-loss durability across every Windows filesystem or storage provider.
- Key and output safety claims cover the bounded path/handle state checked when
  a hostile local actor is not concurrently mutating those paths. This contract is
  not a defense against a concurrent key-replacement or parent-topology race.
- Without a `.git` or `repo-passport.yml` marker discoverable from the current
  working directory, the signer does not know the current repository boundary.
  Because the historical run also omits its former local source path, attestation
  cannot exclude keys or output against that unknown former repository
  location.
- An SPDX attachment is not a vulnerability scan or a guarantee of complete
  dependency discovery.

## Trial, hosted service, and integrations

Interactive browser trial, public passport registry, hosted hardened workers,
GitHub Check writeback, release signing, and external plugins are later
milestones. The local CLI should not imply that these services already exist.

## Release validation

- Alpha.20 release qualification requires exact source-bound evidence. Alpha.19
  and sealed Alpha.18 local/repro and fixed-VM evidence are historical and do
  not qualify or broaden Alpha.20.
- Historical Alpha.9 records `20260731T102030Z` and `20260731T102115Z`
  qualify only their exact Alpha.9 source and evidence package, not Alpha.17.
- Source-level unit tests, schema contracts, vet, and cross-compilation do not
  replace the live-container gate.
- Local/repro record `20260731T085753Z` passed formatting, vet, reachable
  vulnerability scanning, full and shuffled tests, integration compilation,
  release smoke checks, and byte-identical rebuilds.
- Alpha.8 live record `20260731T085836Z` passed the Linux race gate and 12/12
  Docker cases, including sequential Node/Python peer-listener evidence.
  Before/after container, network, volume, source, and host-listener records
  matched; guest cleanup and QEMU/seed shutdown passed. This is an exact-tuple,
  unsigned record only. It does not qualify Podman, rootless operation, another
  Docker/kernel/image/architecture tuple, M1, or M2; capability remains
  `INCOMPLETE` and overall remains `INCONCLUSIVE`.
- The historical final `alpha.4` Linux and Windows `amd64` binaries under `dist/` were
  rebuilt from a different source path, reproduced byte-for-byte, and passed
  the checksum/version/header smoke scope in
  `docs/release.md`.
- Live record `20260730T173121Z` passed all 18 gate steps and all ten exact
  required cases, including `TestContainerResourceUsageObservation`, with
  Docker client/server 29.1.3 on isolated Ubuntu 24.04.4 kernel 6.8 Linux
  `amd64`, cgroup v2, under QEMU. Both exact approved image digests matched;
  source and host-listener manifests were unchanged, before/after all-container
  inventories were header-only, and no host-publish residue remained.
- Local/repro record `20260730T173051Z` passed and reproduced the Linux,
  Windows, and `SHA256SUMS` files byte-for-byte. Exact hashes are in
  `docs/release.md`; no packaged evidence bundle is claimed.
- This record claims only that exact Docker/VM/cgroup/image tuple. It does not
  claim Podman, rootless engines, other Docker versions or kernels, or `arm64`.
  Remaining observer gaps still make a healthy functional pass capability
  `INCOMPLETE` and overall `INCONCLUSIVE`; M1 and M2 remain incomplete and
  evidence remains unsigned.
- Historical `alpha.3` record `20260730T150346Z` passed nine required cases,
  `alpha.2` record `20260730T102841Z` passed nine, and `alpha.1` record
  `20260730T074535Z` passed four on the recorded compatibility tuple.

## Security claims

RepoPassport does not claim:

- every repository runs with one command;
- complete safety or malware detection;
- replacement of security review;
- complete telemetry detection;
- guarantees about unexecuted paths;
- that a successful cleanup of an isolated sandbox uninstalls unrelated host
  state.

When a limitation affects a result, structured output and the static report must
present it near the relevant verdict.
