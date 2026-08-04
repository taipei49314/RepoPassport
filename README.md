# RepoPassport

> **Repository location:** this public source mirror is hosted at
> `github.com/taipei49314/RepoPassport`, while the canonical Go module identity
> remains `github.com/repopass/repopass`. Clone-and-build workflows are
> supported; until the repository owner matches the module namespace, do not
> treat the mirror URL as a stable Go import path.

RepoPassport is a local-first reference implementation for describing, planning,
running, and independently verifying a repository scenario.

The project keeps six questions separate:

- Did the declared journey work?
- Did the workload stay within its declared capabilities?
- Was the result reproducible?
- Was cleanup complete?
- What evidence exists, and who signed it?
- Is that evidence still current?

Functional success never overrides a capability violation. Missing observation
coverage never becomes a pass.

> **Project status:** working `v1alpha1` vertical slice, version
> `v0.1.0-alpha.33`. The supported execution path is intentionally narrow:
> local source snapshots, static Node/Python discovery, deterministic plans,
> dependency-free CLI journeys, and one attached HTTP service using the two
> exact built-in Node/Python Linux `amd64` runtime tuples. The HTTP slice
> requires canonical URLs no longer than 2,048 bytes in the exact form
> `http://127.0.0.1:<explicit-port>/...`, with that port uniquely declared.
> Service and trusted driver run in the same `--network none` container; no
> host port is published. Built-in observer coverage remains incomplete, so a
> functional pass is capability `incomplete` and overall `inconclusive`, not
> overall verified.
>
> Alpha.33 adds an opt-in canonical two-through-eight-hop chain for Alpha.32's
> offline trust-policy authority transitions. The caller's explicit root is
> the only initial trust anchor; every hop must be adjacent, uniquely keyed,
> cycle-free, strictly generation-increasing, and bound to the explicit
> terminal policy authority and floor. The terminal policy cannot assign an
> evidence-signer role to any root, intermediate, or terminal authority. The
> full CLI can atomically assemble an exact-three chain sidecar directory; the
> portable verifier verifies chains but rejects that producer. Optional chain
> state is a separate root-scoped atomic chain+policy record and is not a
> cross-mode downgrade guard. Direct and one-hop modes remain supported.
> Companions never bootstrap trust; compromise recovery, root discovery,
> identity, trusted time, transparency, and historical revocation remain
> unsupported. `identityAttestation=none`, `timeAttestation=none`,
> `formalClaim=false`, capability `incomplete`, and overall `inconclusive`
> remain mandatory.
>
> Alpha.32 adds an opt-in one-hop authority transition for Alpha.31's signed
> offline attestation trust policy. Verification requires the complete signed
> policy triple plus an old-root-signed transition, an independently accepted
> explicit old root, an explicit terminal policy-authority SPKI, and separate
> policy/authority generation floors. The same opt-in persistence flag writes
> one root-scoped combined transition+policy record atomically; it never
> advances two independent state files. The full CLI can author an exact-three
> transition sidecar directory, while the portable verifier rejects the
> producer and supports only verification. Direct Alpha.31 verification
> remains supported. Companions never bootstrap trust; multi-hop policy
> authority chains, root discovery, compromise recovery, identity, trusted
> time, transparency, and historical revocation remain unsupported.
> `identityAttestation=none`, `timeAttestation=none`, `formalClaim=false`,
> capability `incomplete`, and overall `inconclusive` remain mandatory.
>
> Alpha.31 adds a bounded full-CLI producer for the existing canonical
> `offline-trust-policy-v2` verification input. The producer accepts a safe
> integer generation plus 1..32 caller-supplied canonical Ed25519 signer SPKIs
> classified as `trusted` or `revoked`, derives and globally sorts their
> `spki-sha256` identities, signs with a separate canonical PKCS#8 Ed25519
> authority key, self-verifies, and atomically publishes exactly the DSSE
> envelope and authority SPKI companion into a new directory. It does not
> generate, retain, rotate, discover, or distribute keys or policies. The
> companion is not a trust anchor; verification still requires an independently
> trusted authority SPKI and caller generation floor. The portable verifier
> rejects this producer command before command-specific I/O. Identity and time
> attestation remain `none`, `formalClaim=false`, capability `incomplete`, and
> overall `inconclusive`.
>
> Alpha.30 adds an opt-in, bounded two-to-eight-hop offline rotation chain for
> the authority that signs `release-key-policy-v1`. Chain verification requires
> an explicit initial trust-root SPKI, authenticated adjacent transition hops,
> and an explicit terminal policy-authority SPKI. Direct Alpha.28 and Alpha.29
> one-hop verification remain supported. Adjacent or bundled keys are never
> trust anchors. The portable verifier exposes `verify-attestation` and
> `verify-release-index`, but its canonical kit contains no root/private key,
> release-index, policy, authority-transition sidecar, or evidence.
> Signature acceptance is not publisher identity or trusted time:
> `identityAttestation=none`, `timeAttestation=none`, `formalClaim=false`,
> capability `incomplete`, and overall `inconclusive`. This is not root
> discovery, publisher identity, trusted time, transparency, remote publication,
> or a tamper-resistant/distributed state service. Artifact processing is capped
> at 128 MiB per file, 512 MiB per exact set, and 64 KiB for `SHA256SUMS`.
> Stateful rollback/equivocation detection is relative only to surviving local
> records; deletion, restore, copy, rename, or fork can reset or fork history.
> Artifact verification uses two complete stable scans of a quiescent,
> operator-controlled root; it is not an atomic snapshot or hostile
> concurrent-writer boundary.
>
> Alpha.26 hardens release qualification and public evidence publication; it
> does not add observer coverage. Fixed-VM Docker/OS/runtime/image/race/test and
> residue transcripts are private bounded inputs. The public qualification
> package keeps only strictly parsed, canonical typed environment, race,
> guest/host residue, verdict, source-binding, and exact receipt records. Raw
> JSONL, Docker inspect/info, runtime logs, listener snapshots, host PIDs, and
> guest console transcripts are not public package inputs. Filename allowlists
> alone are insufficient: every public slot has an explicit parser or record
> grammar, and renamed/rehashed unstructured content must fail closed. This
> reduces the publication surface but is not universal secret detection,
> trusted signer identity/time, M3 completion, or an overall verification
> claim. `formalClaim=false`; healthy capability remains `incomplete` and
> overall remains `inconclusive`.
>
> Alpha.25 binds `PortObserverVersion=0.3.0` into the resolved plan. For the
> already narrow Docker/Linux/amd64 Node-or-Python single-service HTTP profile,
> `port.listener-trace.summary` now has a fixed aggregate comparison shape:
> `comparisonResult` and `evidenceBasis=aggregate-only` always appear alongside
> fixed non-sensitive observer metadata; a complete sample adds exactly four
> endpoint-related counts: baseline, declared, sampled, and undeclared. Raw
> endpoint/IP/port/URL values, `/proc` rows, socket or
> namespace identifiers, PIDs, tokens, frames, and stderr are never public.
> HTTP `bodyContains` predicates also remain private: matching still uses the
> sealed resolved plan, while public assertion evidence reports only fixed
> configured/value-not-published metadata and typed match/truncation booleans.
> `not-tested` contains no comparison counts; an unmatched sample can produce at most one
> aggregate `UNDECLARED_PORT_LISTEN` finding per repeat. This is bounded TCP
> polling, not listener absence proof, UDP coverage, attribution, or baseline
> history. Healthy runs remain capability `incomplete`, overall `inconclusive`,
> and `formalClaim=false`.
>
> Alpha.24 adds a bounded, aggregate-only positive detector for three
> retained-state blind spots: transient create/delete, write-then-restore, and
> a mutation allowed only by another controller-dispatch phase. It is available
> only for Docker/Linux/pinned-Python CLI foreground commands. Before each
> supported command, the trusted helper acknowledges the active phase and its
> bounded existing `filesystem.write` rules. The controller requires separated,
> identical process snapshots at both quiescence boundaries and one confirmed
> successful dispatch for every acknowledged window; the helper emits only
> aggregate results.
> A complete unmatched notification can add one
> `UNDECLARED_FILESYSTEM_WRITE`, without changing functional assertions or
> cleanup. Public evidence never contains paths, rule text, contents, tokens,
> inotify cookies, or raw transcripts.
>
> This is not complete filesystem operation history: Node, Podman, non-Linux
> or non-Python runtimes, HTTP/services, signal workflows, and background work
> remain `not-tested`/`unavailable`. Queue overflow, watch races, identity,
> transport, phase, quiescence, unconfirmed dispatch, or bound failure fail closed without partial
> counts or a finding. Filesystem-write coverage remains at most `best-effort`;
> a healthy functional run remains capability `incomplete`, overall
> `inconclusive`, and `formalClaim=false`. The filesystem observer version is
> `0.6.0`; older locks drift rather than silently inheriting Alpha.24 semantics.
>
> Alpha.22 retains Alpha.21's opt-in controller-local monotonic state guard for
> Alpha.20's verifier-only authenticated offline trust-policy mode.
> `verify-attestation` requires exactly one each of
> `--trust-policy-envelope FILE`, `--trust-policy-authority-key FILE`, and
> `--minimum-trust-policy-generation UINT`; it is mutually exclusive with
> `--trust-key` and Alpha.19's policy/digest pair. The signed canonical
> `offline-trust-policy-v2` payload has a safe-integer generation in
> `1..9007199254740991` and is authenticated only relative to the caller's
> canonical authority SPKI; the caller floor is enforced only for that
> invocation. With the exact valueless `--persist-trust-policy-state`, the
> verifier then uses global `--data-dir` (or its controller default) to retain
> one authority-scoped canonical generation/payload record and lock. It
> rejects rollback and same-generation equivocation relative to that surviving
> record before signer authorization and freshness; `revoked` and `not-listed`
> signers still advance an authenticated floor-qualified policy. The two state
> report fields and their fixed reasons are omitted in stateless and legacy
> modes. On Windows, newly created state directories and lock files receive
> their protected private DACL at creation time through explicit security
> attributes and are then validated before use; existing objects are validated,
> never repaired. This narrows a creation-time ACL window only. This is not
> tamper-resistant or distributed trust, trusted
> time/expiry, authority lifecycle, historical revocation, KMS/HSM,
> Sigstore/OIDC, transparency, hosted trust, or complete M3. Deleting,
> restoring, copying, or forking the data directory can reset/fork local
> history. Capability remains `incomplete` and overall remains `inconclusive`.
>
> Alpha.18 adds an opt-in repository-derived SPDX v2 path:
> `attest --derive-spdx --current-manifest FILE`. It accepts only the frozen
> local `package.json` plus lockfile-version-3 `package-lock.json` profile,
> derives it without npm, Node, Git, network, or repository-command execution,
> requires two matching source snapshots before derivation and a third before
> signing, and binds canonical SPDX plus provenance into the version-2 bundle.
> Re-observation happens only after explicit trust and a complete raw-bundle
> digest pin, and reports SBOM currentness as `fresh`, `stale`, or `unknown`.
> Lockfile checksum validation is shape-only, not registry verification. This
> is neither general npm compatibility nor package discovery/completeness,
> license, vulnerability, or producer-provenance validation. It cannot upgrade
> capability `incomplete` or overall `inconclusive`; Alpha.18 formal race, VM,
> and release-evidence qualification is still pending.
>
> Alpha.17 is a sealed historical dependency-only security remediation. It replaces the required
> indirect `golang.org/x/text@v0.14.0` module with the minimum reviewed fixed
> release `v0.39.0` for `GO-2026-5970` / `CVE-2026-56852`. CI downloads and
> verifies the public modules, rejects any `go mod tidy -diff` output, and uses
> `govulncheck v1.6.0` gates for both the application module graph and
> source/test symbols. No CLI, schema, execution, evidence, freshness, or
> verdict behavior changes in this increment.
>
> The selected graph also advances upstream tool modules `x/mod` from `v0.8.0`
> to `v0.37.0` and `x/tools` from `v0.6.0` to `v0.47.0`, and adds
> `x/sync@v0.21.0`; other repository-declared requirements remain unchanged.
> Release qualification must prove that those three graph-only tool modules are
> not embedded in either final product binary.
>
> These gates describe only the exact selected module graph and vulnerability
> database observed by a qualifying run. They are not an SBOM, a dependency-
> completeness or exploitability proof, or a guarantee against future findings.
> Capability remains `incomplete` and overall remains `inconclusive`.
>
> Alpha.16 adds opt-in `verify-attestation --current-manifest FILE` for a
> trusted, raw-bundle-digest-pinned, bounded local re-observation. It compares
> two stable pre-plan source snapshots, the current policy and deterministic
> plan, a third source snapshot, and the exact signed Docker/Podman backend's
> finite stable profile. The unsigned replay report is `current`, `stale`, or
> `unknown`; it never rewrites or upgrades `originalResults`. Without the
> opt-in flag, replay remains `not-evaluated`.
>
> This check does not rerun the scenario, validate elapsed age, defeat a
> hostile concurrent namespace swap, prove Git/registry provenance, identify
> every runner binary or execution observer, establish revocation/transparency,
> or complete M3.
>
> Alpha.15 adds one bounded M3 portable-evidence increment. Resolved-plan
> schema version `"4"` seals either the existing no-SBOM `minimal-public`
> evidence set or the exact same set plus `sbom`. An SBOM-selected run requires
> exactly one caller-supplied `--spdx FILE`; RepoPassport performs a bounded,
> no-link double read, validates a strict SPDX 2.3 JSON subset, canonicalizes
> it, applies the frozen privacy gate, and binds the derivative into an exact
> six-member offline bundle. The five-member no-SBOM model remains available
> for schema-4 runs.
>
> This is attachment and integrity binding only. RepoPassport does not generate
> the SBOM, discover packages, evaluate licenses or vulnerabilities, or prove
> completeness, correctness, currentness, or producer identity. Attaching it
> never upgrades the authoritative run's verdicts. Plan locks v1, v2, and v3
> remain historical and are rejected by the current schema-4 verifier.
>
> Alpha.14 adds one bounded M3-c publication control. Every current
> `minimal-public` attestation is evaluated by deterministic, fail-closed
> policy `minimal-public-v1alpha2` before signing/publication; replay repeats
> that decision after signature validity but before optional trust-key access.
> Rejection is non-echoing `EVIDENCE_PRIVACY_BLOCKED` (exit 7). Success reports
> the exact profile, policy, ruleset digest, and `passed` decision. This is
> bounded screening, not universal secret/PII detection, redaction, or anonymity.
>
> Alpha.13 adds only a bounded M3-b portable-replay increment. `attest` may
> publish a separate canonical Ed25519 SPKI PEM companion with
> `--public-key-out`; success reports SHA-256 digests over the complete raw
> bundle and canonical companion bytes. `verify-attestation` may pin the raw
> bundle with `--expect-bundle-digest` before any optional trust-key access.
> Matching a bundle digest or a package-local companion never establishes
> signer identity or trust: only `--trust-key` can make the explicit local
> SPKI equality decision.
>
> Both signing outputs must be new, distinct, outside the authoritative run
> store and detected repository, and use bounded same-directory no-replace
> publication. Validation failure publishes neither output. A later bundle
> publication failure may leave only a complete, identity-confirmed public
> companion and reports that state explicitly. Alpha.13 does not add freshness
> re-observation, external identity, transparency, revocation, Sigstore/OIDC,
> KMS/HSM, SBOM, hosted trust, or complete M3.
>
> Alpha.12 fixes one attached-service cleanup time-of-check/time-of-use race.
> Only Runner-owned finalization privately authorizes an exact quiescent no-op:
> the helper must report `ok=true`, `remaining=0`, `sent=0`, no escalation, and
> a nonnegative initial-target count. Direct helper calls remain fail-closed.
> Delivered signals still require `initialTargets >= 1` and
> `1 <= sent <= initialTargets`; only that state may report escalation.
>
> An authorized no-op is public as `service.signal` succeeded with
> `alreadyExited=true` and exact `sent=0`; it does not imply delivery.
> `service.exit` intentionally records `failed` with
> `exitedBeforeSignal=true`. Cleanup is clean only after the Runner's existing
> bounded wait observes the exact attached service finish. A wait timeout or
> cancellation uncertainty remains `CLEANUP_FAILED`; an attached execution
> error remains the primary run error and is never erased. No schema, error code, milestone,
> observer-coverage, or compatibility claim changes in Alpha.12.
>
> Alpha.11 adds only the M3-a local portable-attestation slice. `attest` reads
> an integrity-valid authoritative run from `--data-dir`, accepts one
> canonical Ed25519 PKCS#8 PEM private key, and creates a deterministic,
> uncompressed five-entry USTAR bundle containing the original verification,
> a minimal manifest, an in-toto Statement v1, one DSSE signature, and the
> canonical SPKI PEM public key. `verify-attestation` checks the complete
> canonical bundle and signature offline. Trust remains an explicit operator
> decision: no `--trust-key` is `unknown`, a different key is `rejected`, and
> only the exact canonical Ed25519 SPKI key is `accepted`.
>
> Attestation verification reports artifact integrity, signature validity,
> signer key ID, trust decision, and freshness separately. Without Alpha.16's
> explicit trusted/pinned `--current-manifest` mode, freshness remains
> `not-evaluated`. The embedded historical `results.freshness` is copied as an
> original result, not re-observed currentness; signing never upgrades the
> stored functional, capability, reproducibility, cleanup, evidence,
> freshness, or overall verdict. Sigstore, OIDC, KMS, TPM/HSM, hosted
> identities, and full M3 remain unimplemented.
>
> Signing keys must be bounded regular files outside authoritative run data and
> the output path and, when a current repository is detectable from the working
> directory through `.git` or `repo-passport.yml`, outside that repository.
> Links/reparse points and hard links fail closed. On Windows,
> UNC, device, extended-namespace, alternate-data-stream, trailing-dot/space,
> and reserved DOS paths are rejected; the key owner/DACL must be provable as
> current owner with access limited to that owner, SYSTEM, and Builtin
> Administrators. Output uses same-directory staged no-replace publication,
> but Alpha.13 does not claim resistance to a hostile concurrent parent
> rename/symlink/junction swap or universal power-loss durability across every
> Windows filesystem/provider. Historical verification stores source identity,
> not the former local source path, so attestation cannot recover that path.
> If neither current-repository marker is discoverable, repository exclusion is
> unavailable rather than inferred from the historical run.
>
> Alpha.10 adds a controller-owned cleanup-residue boundary over the final
> `/outputs` tmpfs. After immutable-ID quiescence and existing final observers,
> fixed bounded no-follow helpers remove `.home`/`.tmp`, reverify the container
> identity and run label, and inventory entry path/type/mode without reading
> regular-file content or symlink targets. Public evidence exposes only safe
> counts, boundary-completion flags, and an opaque one-time token made with a
> fresh ephemeral HMAC key: never raw paths, targets, contents, helper output,
> or an unsalted path hash. The key and raw inventory are discarded, so the
> token cannot be opened or independently recomputed and is neither an
> attestation nor proof.
>
> Historical Alpha.10 resolved-plan schema version `"3"` requires classifier `0.1.0` and exactly
> one cleanup profile: `[]` or `["/outputs/**"]`. Zero descendants is `clean`;
> covered regular files/directories are `allowed-residue`; any descendant with
> an empty profile, or any symlink/special/unmatched entry, is
> `undeclared-residue`; an incomplete boundary is `not-tested`. Confirmed
> undeclared residue emits `CLEANUP_RESIDUE` but is not an operational
> execution error, so fresh repeats continue. It remains nonconforming even if
> later forced destruction also fails.
>
> Manifest `v1alpha1`, CLI driver `0.2.0`, and HTTP driver `0.1.0` are unchanged.
> Current resolved plans use schema version `"4"` and bind the exact evidence
> selection. Version-1, version-2, and version-3 plan locks are historical and
> are never reinterpreted as version 4; current checking
> reports `PLAN_DRIFT`. Alpha.9's bounded CLI `stdoutJsonSchema` assertion
> remains available.
>
> This source document does not claim a completed Alpha.24 local/repro or
> fixed-VM qualification. Only a final source-bound evidence package with the
> exact gate results and environment tuple may make that claim.
>
> Earlier qualified source and evidence packages remain historical and do not
> qualify this changed Alpha.24 source. Alpha.23 and earlier evidence remain
> historical. Historical Alpha.9 records
> `20260731T102030Z` (local/repro) and
> `20260731T102115Z` (fixed-VM live) qualify only their exact Alpha.9 source
> and evidence package; they do not broaden Alpha.17.
>
> Historical Alpha.8 added a Docker-only, controller-owned peer-container
> observer for the one declared TCP listener in the supported single-service
> HTTP profile. The
> peer uses the same exact pinned Node/Python Linux `amd64` runtime image as the
> target and joins only the target's network namespace. It does not share the
> target's PID, mount, IPC, or cgroup namespace, publishes no host port, runs as
> UID/GID `65534` with a read-only root filesystem, all capabilities dropped,
> and `no-new-privileges`, and has independent CPU, memory, and PID limits.
>
> The controller starts the peer immediately before service dispatch, requires
> a strict bounded `READY` frame before the service starts, and requests a
> strict bounded `FINAL` frame only after workload quiescence. The helper
> samples only `/proc/net/tcp` and `/proc/net/tcp6` `LISTEN` entries at a
> bounded interval. A complete observation requires the declared
> `127.0.0.1:<port>/tcp` endpoint to be absent at the initial barrier, observed
> during the sample window, and absent again at the final barrier. Public
> `port.listener-trace.summary` evidence is aggregate-only and does not expose
> the session token, raw `/proc` rows, socket inodes, or undeclared endpoints.
>
> This listener trace has coverage `best-effort` only. It is a bounded sample
> window, not complete socket-lifecycle history, and cannot provide process
> attribution or UDP coverage. Dirty stderr, nonzero exit, timeout,
> invalid/missing/extra/trailing/oversize frames, identity or namespace
> mismatch, a sample gap, a bound overflow, failure to observe the declared
> listener close, or peer cleanup failure prevents successful observer
> evidence without rewriting the functional result. A required `port-listen`
> capability therefore remains `incomplete`, overall remains `inconclusive`,
> and Podman port observation is `unavailable`.
>
> Alpha.8 qualification record `20260731T085836Z` passed all 19 ordered guest
> gates and all 12 required live-container cases, including sequential Node and
> Python peer-listener evidence, in an isolated Ubuntu 24.04.4 LTS, kernel
> 6.8.0-134-generic, Linux `amd64`, cgroup-v2 QEMU VM with Docker client/server
> 29.1.3. Linux `go test -race ./internal/execution`, before/after container,
> network, volume, and host-listener comparisons, guest cleanup, and final
> QEMU/seed shutdown also passed. Local/repro record `20260731T085753Z`
> reproduced the release files byte-for-byte. This is only an exact-tuple,
> unsigned Alpha.8 record; it does not qualify Podman, rootless operation,
> another Docker/kernel/image/architecture tuple, M1, or M2, and it does not
> change the honest `incomplete` / `inconclusive` verdict.
>
> Historical Alpha.7 added a Docker-only, bounded, controller-owned activity trace for
> `/outputs`. The controller starts a trusted root helper with the exact
> shell-free `docker exec --interactive --user 0:0 ...` transport before workload
> execution and stops it only after workload quiescence. Control and result
> messages use strict, bounded stdin/stdout JSONL frames: exactly one `READY`
> and one `FINAL`. Frames are capped at 8 KiB, total stdout at 16 KiB, stderr
> at 8 KiB, notifications at 4,096, and the canonical transcript at 1 MiB.
> No workload-writable control file is created. A cryptographically random
> per-session token is sent only
> through stdin; it is never placed in argv, environment variables, logs, or
> public evidence.
>
> The helper retains raw workload paths only in bounded in-memory state.
> Public evidence is aggregate-only: notification counts, controller-window
> phase hints, and a keyed canonical transcript digest. It is not a record of
> filesystem operations or syscalls. Node uses manually installed,
> non-recursive per-directory `fs.watch` watchers capped at 2,048; its kernel
> queue-overflow detection is `unavailable`. Python uses inotify with the same
> 2,048-watch cap and fails the whole observation closed on queue overflow.
> Dynamic watch installation, coalescing, reads, rename pairing, exact
> operation semantics, and actor attribution remain blind spots.
>
> The activity helper has `observerPlacement=in-sandbox-trusted-helper` and
> `sharesSandboxResourceBudget=true`. Its CPU, memory, tasks, and tmpfs effects
> can perturb sandbox resource measurements. Dirty stderr, nonzero exit,
> timeout, extra/trailing/oversize frames, identity mismatch, overflow, or a
> detected gap makes the whole activity trace `unavailable`; functional work
> and cleanup still continue. Podman activity tracing remains `unavailable`
> until separately live-qualified.
>
> Even a complete activity trace provides only `best-effort` notification
> hints. Required filesystem-write observation remains `incomplete`, overall
> verification remains `inconclusive`, and neither M1 nor M2 is complete.
> This source tree does not embed an `alpha.7` live-container qualification
> claim.
>
> Historical Alpha.6 added a Docker-only, bounded, opaque observation of the engine's
> writable-layer diff. The controller uses the fixed, shell-free argument
> vector `docker container diff <immutable-64hex-id>` after checking the full
> immutable container ID. Stdout and stderr are each capped at 4 MiB; exit
> status must be `0`, neither stream may truncate, and stderr must be empty.
> Otherwise this supplemental observation is `unavailable` and the functional
> run continues.
>
> The Docker CLI transcript is not parsed because filenames may contain
> newlines. Public evidence exposes no raw output, paths, or `A`/`C`/`D`
> records, only a SHA-256 commitment, byte count, and nonempty flag. The
> pre-workload baseline is diagnostic only and never controls coverage. Only a
> post-quiescence, pre-repair final transcript with a reverified container
> identity gives the engine-diff component `best-effort` coverage.
>
> Docker's final transcript is cumulative from container creation and may
> include trusted initialization, observer, and other pre-workload work. It
> cannot attribute an actor, operation time, or workload phase and does not
> cover the separate `/outputs` tmpfs or bind and other mounts such as source,
> workspace, and inputs. The source tree did not embed an `alpha.6`
> live-container qualification claim; use only an external package that binds
> the exact source manifest and environment tuple. The historical `alpha.5`
> target does not qualify this version.
>
> Historical Alpha.5 added strict, bounded, controller-owned baseline/final snapshots of
> retained state below `/outputs`. The baseline is post-initialization and
> pre-workload; the final snapshot is post-quiescence and pre-repair. Both bind
> the same immutable container identity. Regular-file contents and raw symlink
> targets contribute SHA-256 commitments, while public evidence exposes only
> aggregate snapshot digests, entry counts, and a change count through
> `filesystem.retained-state.summary`; that event has `high` coverage only
> after the complete snapshot pair succeeds.
> Retained-state and engine-diff commitments use unsalted raw SHA-256. Not
> publishing a raw path is not the same as dictionary-resistant path secrecy:
> an attacker with a small candidate set can test guesses against those
> commitments. The Alpha.7 activity transcript instead uses a per-session
> keyed canonical digest, but that does not retroactively strengthen the
> historical commitments.
>
> A complete snapshot pair gives the `filesystem.retained-state.summary`
> observation event coverage `high`, but composite
> `FilesystemWriteObservation` remains `best-effort`. The required
> filesystem-write observer is still incomplete. The snapshots include trusted
> helpers and runner-managed, workload-writable disposable `.home`/`.tmp`
> state, which is excluded from export, and do not observe state
> outside `/outputs`, transient create/delete or write-restore activity,
> operation time, process/phase attribution, rename identity, ownership,
> timestamps, xattrs, ACLs, inodes, or device identity. Observer failure is
> nonfatal and gives the summary event coverage `unavailable`.
>
> `20260730T202049Z` is the alpha.5 exact-tuple qualification target. Only an
> external evidence package with gate exit `0` and every required gate result
> qualifies it. Otherwise no alpha.5 compatibility result is claimed. A
> qualified result remains limited to its recorded Docker/VM/kernel/Linux
> `amd64`/approved-image tuple and does not claim Podman, rootless operation,
> another version, kernel, image, or `arm64`.
>
> The historical `alpha.4` exact-tuple live gate validates `ResourceUsage` coverage
> `high` on Docker client/server 29.1.3, Ubuntu 24.04.4, kernel 6.8, Linux
> `amd64`, cgroup v2, and the approved pinned images. Its memory value is the
> sandbox cgroup peak, not RSS; PID peak counts tasks/threads, not processes;
> writable bytes are a final allocation snapshot, not a historical peak.
> Resource-limit enforcement is reported separately and cannot satisfy a
> resource-usage observer requirement. Other engines, Docker versions,
> kernels, architectures, or images remain unclaimed.
>
> Live-gate record `20260730T173121Z` passed all 18 gate steps and all ten
> required CLI/HTTP, adversarial, lifecycle, cleanup, and disk-enforcement
> cases plus `TestContainerResourceUsageObservation` on the tuple above.
> Source and host-listener manifests were unchanged, before/after
> all-container inventories were header-only, and no host-publish residue
> remained. The gated source snapshot SHA-256 is
> `4492de55cf8c1c57ccdda8fb0f0be4bd2512a7a2dc393ef0e419e620d2d5b4d6`.
> Local gate `20260730T173051Z` also passed and reproduced the Linux and
> Windows `amd64` release files byte-for-byte. This is a compatibility record
> only for the exact Docker/VM/cgroup/image tuple; it does not claim Podman,
> another Docker version or kernel, or `arm64`. The nine-case
> `20260730T150346Z` `alpha.3`, `20260730T102841Z` `alpha.2`, and
> `20260730T074535Z` `alpha.1` records remain historical. M1 is still
> incomplete, remaining observer gaps make a healthy functional result
> capability `incomplete` and overall `inconclusive`. The original
> verification result's evidence state remains `unsigned`; a local
> attestation signs that historical artifact without rewriting the state.
> See [known limitations](docs/known-limitations.md) before interpreting a
> result.

The exact milestone boundary and deferred work are tracked in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). Release-facing changes
are summarized in [CHANGELOG.md](CHANGELOG.md).

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

Read the full [security model](docs/security-model.md) and
[security policy](SECURITY.md).

## Quick start

Prerequisites:

- the Go version declared by `go.mod`;
- Docker or Podman with a Linux engine only for live verification.

Run the local checks:

```bash
gofmt -w .
go vet ./...
go test ./...
```

Reproducible snapshot build and checksum instructions are in
[docs/release.md](docs/release.md).

Inspect and validate the bundled healthy Node fixture:

```bash
go run ./cmd/repopass inspect ./testdata/fixtures/healthy/healthy-node-cli --output json
go run ./cmd/repopass validate ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml
```

The target verification flow is:

```bash
go run ./cmd/repopass plan \
  --manifest ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml \
  --scenario quickstart \
  --write-lock

# The alpha runner never pulls during execution. baseline-v1 accepts only the
# exact Node/Python linux/amd64 tuples listed in docs/release.md. Approve and
# pre-pull the selected tuple in a trusted preparation step; its digest proves
# immutability, not publisher trust.

go run ./cmd/repopass verify \
  --manifest ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml \
  --scenario quickstart \
  --output json
```

After obtaining the emitted run ID, an operator with a canonical Ed25519
PKCS#8 PEM key stored outside the authoritative data store and output path and,
when detectable, the current repository can create and verify the M3-a bundle
offline:

```bash
go run ./cmd/repopass --data-dir <authoritative-data-dir> attest \
  --run <run-id> \
  --key <private-pkcs8.pem> \
  --out <new-bundle.tar> \
  --public-key-out <new-public-spki.pem>

go run ./cmd/repopass verify-attestation <new-bundle.tar> \
  --expect-bundle-digest sha256:<64-lowercase-hex> \
  --trust-key <new-public-spki.pem>

# Alpha.22 opt-in: persist local monotonic state for a signed policy and floor.
go run ./cmd/repopass --data-dir <controller-data-dir> verify-attestation <new-bundle.tar> \
  --trust-policy-envelope <offline-policy.dsse.json> \
  --trust-policy-authority-key <authority-public-spki.pem> \
  --minimum-trust-policy-generation 1 \
  --persist-trust-policy-state
```

For the repository-owned executable SBOM-selected fixture, use its manifest
for `plan`/`verify`, then pass the fixture attachment while attesting the
resulting run:

```bash
go run ./cmd/repopass verify \
  --manifest ./testdata/fixtures/healthy/minimal-public-spdx/repo-passport.yml \
  --scenario quickstart --output json

go run ./cmd/repopass --data-dir <authoritative-data-dir> attest \
  --run <run-id> \
  --spdx ./testdata/fixtures/healthy/minimal-public-spdx/sbom.spdx.json \
  --key <private-pkcs8.pem> \
  --out <new-six-member-bundle.tar>
```

The bundle and optional public-key companion must be new and distinct, outside
the authoritative data store, and outside the current repository when that
repository is detectable. The expected digest pins transport bytes but does
not confer signer trust. Without either an explicit `--trust-key` or the
complete Alpha.19 digest-pinned policy pair, or the complete Alpha.20 signed
policy triple (optionally Alpha.22 stateful), a cryptographically valid bundle
still exits
with attestation verification failure because trust is `unknown`.

Without `--fail-on`, a completed verification command exits zero and callers
must read the structured verdict. CI should normally add
`--fail-on functional-fail,blocked,nonconforming,inconclusive`.
Authoritative runs default to the controller's user configuration area and are
never trusted from inside the repository.

See the [five-minute quick start](docs/quickstart.md) for fixture expectations
and safe interpretation of output.

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
- `healthy-node-http`: dependency-free single-service HTTP journey with trusted
  status, header, `bodyContains`, `fileExists`, JSONPath, response-schema, and
  ordered `jsonFile` assertions.
- `healthy-python-http`: dependency-free single-service HTTP journey with
  trusted status, `fileExists`, JSONPath, response-schema, and ordered
  `jsonFile` assertions.
- `invalid/unknown-field`: must fail with `MANIFEST_UNKNOWN_FIELD`.
- `invalid/literal-secret`: must fail with `MANIFEST_LITERAL_SECRET`.
- `malicious/fake-verification-json`: writes a forged verification result from
  inside the workload; the trusted verifier must ignore it.
- `malicious/cleanup-undeclared-residue`: keeps functional assertions passing
  while the cleanup classifier reports residue outside its allowlist.
- `malicious/undeclared-retained-write`: writes one declared and one undeclared
  retained output; functional assertions and cleanup remain successful while
  capability and overall become `nonconforming` through one aggregate finding.

Fixtures are documentation as well as tests. Each fixture includes its expected
classification and is designed to run without package installation.

The HTTP profile intentionally excludes redirects, TLS, request
authentication, and multiple services. Full RFC 9535 JSONPath, remote or
cross-file schema references, and arbitrary sandbox file reads remain
unsupported. Those declarations fail closed rather than being ignored.

## Project principles

- Declarations are not evidence.
- The workload does not judge itself.
- Models and adapters may propose; only the verifier decides.
- `UNKNOWN` or `INCOMPLETE` is better than a false pass.
- Verification and interactive trial are different products.
- Evidence should be portable and independently checkable.
- RepoPassport does not publish a single “security score.”

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Schema semantics, verdict
aggregation, evidence predicates, core policy, trust boundaries, plugin
protocol, runner conformance, and breaking CLI/API changes require an RFC.

## License

Licensed under the [Apache License 2.0](LICENSE).
