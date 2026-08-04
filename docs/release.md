# Alpha release build and live gate

`v0.1.0-alpha.33` is the current narrow local vertical slice. This source
document does not claim completed Alpha.33 race, local/repro, or fixed-VM live
qualification. Alpha.32 and earlier evidence remain historical and do not
qualify or repackage this changed source. Historical
Alpha.9 local/repro record `20260731T102030Z` and fixed-VM live record
`20260731T102115Z` bind only their exact Alpha.9 source, release artifacts,
environment tuple, results, and evidence package
`repopass-v0.1.0-alpha.9-evidence-20260731T102115Z`; they do not broaden
Alpha.33. Alpha.8 records remain earlier historical evidence.
A release record must not imply completion of later milestones,
complete capability-conforming observation, full M3, trusted hosted identity,
scenario re-execution, historical-currentness, or SBOM generation/independent validation.

## Alpha.33 offline trust-policy authority-transition-chain release contract

The full CLI adds `assemble-offline-trust-policy-authority-transition-chain`
for 2..8 ordered pairs of existing transition envelopes and their named next
authority SPKIs, plus an explicit root, authority floor, and absent output
directory. It authenticates the complete chain, rejects input drift, and
atomically publishes exactly the terminal SPKI, canonical chain JSON, and root
SPKI companion without overwrite. The portable CLI rejects the producer before
command-specific I/O.

`verify-attestation` chain mode is mutually exclusive with the Alpha.32
one-hop transition flag. It verifies the intrinsic bundle first, then explicit
root/terminal keys, complete chain, terminal policy/floors and every-authority
role separation, followed by at most one opt-in chain-state transaction and
signer/freshness evaluation. The separate root-scoped state binds the chain
digest/hop count/terminal generation and terminal policy generation/digest;
it makes no cross-mode anti-rollback claim.

Qualification must prove two-hop and eight-hop success, bounds/canonical/
ordering/cycle/role/floor failures, exact-three output, direct/one-hop output
compatibility, full/portable parity, rollback/equivocation rejection, Linux
race, fixed WHPX VM, pinned SSH, and a network-none/read-only true-container
replay. Only a fresh exact source-bound Alpha.33 evidence package may carry
those results. This is not root discovery, compromise recovery, trusted
identity/time, transparency, historical revocation, or distributed state; the
honesty boundary remains none/none/false/incomplete/inconclusive.

## Alpha.32 offline trust-policy authority-transition release contract

The full CLI adds `sign-offline-trust-policy-authority-transition` with exact
`--next-authority-key`, `--generation`, `--key`, and new `--out-dir` inputs.
It signs one canonical one-hop transition with the previous authority,
self-verifies it, rejects next-key drift, and atomically publishes exact-three
public companions without overwrite. No private key enters those sidecars or
the seven-file release.

Rotation verification extends, but never replaces, the Alpha.31 signed-policy
triple. It additionally requires the transition envelope, independently
accepted previous root, and authority generation floor. Optional persistence
uses one root-scoped combined state record binding both transition and terminal
policy generations/digests. Qualification must prove direct compatibility,
full/portable parity, exact-three producer output, rollback/equivocation
rejection, independent oracle negatives, Linux race, fixed WHPX VM, and a
network-none/read-only true-container replay. Only exact source-bound evidence
may carry those results.

This one-hop continuity mechanism is not multi-hop lifecycle, root discovery,
compromise recovery, identity, trusted time, transparency, historical
revocation, or tamper-resistant/distributed state. Companions are not trust
anchors. The honesty boundary remains none/none/false/incomplete/inconclusive.

## Alpha.31 offline trust-policy issuer release contract

The full CLI adds `sign-offline-trust-policy` for the unchanged strict
`offline-trust-policy-v2` input. It requires one safe-integer generation,
1..32 repeated trusted/revoked canonical Ed25519 signer-SPKI inputs, one
separate canonical PKCS#8 Ed25519 authority key, and one absent output
directory. Argument shape is rejected before command-specific I/O. Signer IDs
are derived from canonical SPKI DER, globally sorted and unique; authority and
signer roles cannot overlap. The producer signs one dedicated DSSE envelope,
self-verifies it, rechecks signer snapshots, and atomically publishes exactly
the envelope plus authority-SPKI companion without overwrite.

Qualification must bind the exact source and Alpha.31 seven-file release,
exercise producer success and bounded semantic negatives, prove portable
producer rejection before I/O, verify the resulting policy through the full
and portable verifier paths, and retain the existing signed-policy generation
state tests. Linux fixed-VM qualification must additionally run the full test
and race gates and a network-none/read-only true-container replay. Exact
source-bound evidence, not this document, carries those pass/fail results.

The private key and output sidecars stay outside the release artifact root.
The authority companion is not a trust anchor. There is no key generation,
custody, lifecycle, KMS/HSM, remote publication, identity, trusted time, or
capability/overall upgrade. The portable verifier kit remains read-only and
contains no policy sidecars or private keys.

## Alpha.30 external release-index authority-transition-chain contract

Alpha.30 adds an opt-in release-authority-transition-chain-v1 transport. It
contains 2..8 ordered existing transition envelopes and the exact SPKI bytes
they name. The caller supplied root is the sole initial trust anchor. Each hop
is authenticated before policy or state I/O, must be adjacent, unique,
cycle-free, and strictly generation-increasing, and the terminal key must equal
the explicit policy authority. The exact Alpha.30 canonical publication has
seven payload files and seven public sidecars; the chain JSON replaces the
Alpha.29 single-transition sidecar. Direct and one-hop modes remain supported.

The retained external release index is a canonical `release-index-v1` payload
for exactly one release-artifact root. It lists only the root's regular
top-level files, and acceptance rejects missing, extra, unsafe, case-colliding,
linked, nonregular, or mutated members. The index, its DSSE envelope, release
signer SPKI, release-key policy, authority root, evidence, and local state are
not artifact members and are never implicitly discovered.

The index envelope has payload type
`application/vnd.repopass.release-index.v1+json` and exactly one Ed25519
signature. Its signer is authorized only by a separately supplied,
authority-root-signed `release-key-policy-v1` envelope with payload type
`application/vnd.repopass.release-key-policy.v1+json`; direct mode retains its
explicit caller pin and cannot equal the release signer. Legacy one-hop
rotation adds one explicit old trust-root SPKI, one next policy-authority SPKI,
and an old-root-signed `release-authority-transition-v1` DSSE envelope. Chain
mode instead carries 2..8 ordered envelopes and their exact next-key SPKIs
while retaining the same per-hop payload type. Every previous-root companion
remains an explicit caller input, never an implicit trust anchor. Neither mode
provides publisher identity, trusted time, root discovery, transparency, remote
publication, or historical revocation.

`formalClaim=false`, capability is `incomplete`, overall is `inconclusive`, and
both identity and time attestation are `none`.

Index authentication completes before transition, policy, state, artifact, or
runner access. Rotation mode then authenticates the explicit roots and transition
before policy I/O; persisted mode observes that authenticated transition before
policy state. Verification authorizes the release signer, verifies the exact
artifact set, and records the accepted release generation last. Each artifact is capped at 128 MiB, the
artifact set at 512 MiB, and `SHA256SUMS` at 64 KiB.

The artifact root is a quiescent trusted-operator input. Two complete stable
scans reject changes they observe, but do not form an atomic filesystem
snapshot or protect acceptance against a hostile concurrent namespace/content
writer.

The three local monotonic records detect rollback and same-generation
equivocation only relative to surviving state. Deletion, restore, copy, rename,
or fork of the selected data root can reset or fork history. A transition or release
generation is not trusted time, and exact-digest mode is a caller pin rather
than a freshness assertion.

Rotation success retains the release result and adds the old-root key ID, next
policy-authority key ID, transition payload/envelope digests, transition
generation, and caller floor; persisted rotation also reports transition-state
evaluation. Direct-mode results keep the original `release-key-policy-v1` trust
basis and omit all transition-only fields. Neither output form asserts identity
or time, and both remain `formalClaim=false`, capability `incomplete`, and
overall `inconclusive`.

## Alpha.27 portable offline verifier release contract

The release build produces full and verifier-only executables for Linux/amd64
and Windows/amd64 plus one deterministic verifier kit per target. Each kit is
a canonical USTAR archive with exactly the executable,
`PORTABLE_VERIFIER_MANIFEST.json`, `TRUST_BOUNDARY.txt`, and `USAGE.txt`. The
manifest binds the target, product version, executable size and SHA-256,
supported historical replay and trust modes, and the fixed trust boundary.
Kit input executables are capped at 32 MiB to bound the builder's aggregate
in-memory canonical validation.

The reduced executable exposes only help, version, `verify-attestation`, and
`verify-release-index`. Historical replay is offline and does not
need the source worktree. `--current-manifest` and persisted signed-policy state
remain explicit local observation/state paths rather than self-contained kit
claims. The kit provides no trust root: an embedded or adjacent signer key does
not establish publisher identity or acceptance. No macOS/arm64, Sigstore/OIDC,
transparency, trusted time, KMS/HSM, historical revocation, complete M3,
capability conformance, or overall verification is claimed.

## Alpha.26 typed public qualification-evidence release contract

Alpha.26 publishes no raw fixed-VM Docker/OS/runtime/image/race/test/listener
logs or snapshots. The public fixed-VM payload may contain only the exact typed
environment, race, guest/host residue, verdict, summary, source-binding, matrix,
and canonical one-line receipt inventory. Every public fixed-VM path requires
an exact parser or strict record grammar; raw JSONL under its original name or
renamed into a fixed-VM allowed slot must remain invalid even when all package
control digests and the external index are recomputed. Local qualification Go
logs remain bounded transcripts with gate-specific validation and
confidentiality scanning rather than universally typed receipts.

The raw inputs remain bounded private runner artifacts and are cleanup-attempted.
The typed projection reduces public exposure but is not universal secret
detection or proof that future runner output contains no organization-specific
metadata. That historical Alpha.26 external index remains unsigned, with no
identity or trusted-time attestation; Alpha.29 does not retroactively sign it.
Runtime capability semantics, `PortObserverVersion=0.3.0`, healthy
`incomplete`/`inconclusive`, and `formalClaim=false` are unchanged. Source-level
Alpha.26 is not a qualification claim and does not complete M1, M2, or M3.

## Alpha.25 peer TCP-listener comparison release contract

The source-level Alpha.25 contract binds `PortObserverVersion=0.3.0` into the
resolved plan and requires the exact aggregate-only listener-summary shape.
In addition to fixed non-sensitive observer metadata, complete events expose
exactly four endpoint-related counts: baseline, declared, sampled, and
undeclared; `not-tested` exposes no comparison count. At most one aggregate `UNDECLARED_PORT_LISTEN`
may be emitted per repeat. The supported profile is still only Docker/Linux/
amd64 approved Node-or-Python single-service HTTP, and raw endpoint identities
and all helper internals remain non-public. This is a source contract, not a
formal release qualification, absence proof, UDP/attribution claim, or wider
compatibility statement.

## Alpha.22 local signed offline trust-policy-state release contract

Qualification must exercise the exact `--trust-policy-envelope`,
`--trust-policy-authority-key`, and `--minimum-trust-policy-generation` triple
and opt-in valueless `--persist-trust-policy-state`; its duplicate/value/
partial/near-prefix/case-alias pre-I/O failures; both flag forms; and mutual
exclusion with `--trust-key` and the Alpha.19 pair. It must prove bundle pin
plus canonical archive/content, signature, SPDX, and privacy checks occur
before authority-key, envelope, or state access; caller-floor rejection occurs
before state access; and rollback/equivocation/unavailable state occur before
claims, freshness source, or runner probes.

Evidence must bind the canonical `offline-trust-policy-v2` safe-integer
generation range, DSSE payload type and PAE verification, authority-key-ID
binding, signature/payload tamper rejection, floor rejection, trusted/revoked/
not-listed decisions, state bootstrap/match/advance, rollback/equivocation,
unavailable state, and stateless/legacy report-field omission. A qualified
authenticated policy is locally observed before signer evaluation, including
for revoked/not-listed signers. The state record is canonical, authority scoped,
and locked below `--data-dir`. On Windows, new state-directory components and
lock files receive their protected private DACL in the kernel create operation;
existing objects are validation-only and are never repaired. It is not
tamper-resistant/distributed state,
trusted time/expiry, authority lifecycle, historical revocation, KMS/HSM,
Sigstore/OIDC/transparency, hosted trust, complete M3, capability conformance,
or overall verification. This source does not claim Alpha.22 qualification
passed; exact source-bound evidence is required and Alpha.21 evidence is
historical.

## Alpha.19 offline trust-policy release contract

Qualification must exercise the exact paired `--trust-policy` and
`--expect-trust-policy-digest` flags, their mutual exclusion with
`--trust-key`, pre-I/O syntax failures, and required policy digest-before-parse
ordering. It must prove that any supplied bundle pin and complete canonical
bundle/signature/SPDX/privacy checks precede policy access; privacy rejection
must not acquire policy trust metadata. It must cover trusted rotation,
revocation, not-listed attacker re-signing, malformed/noncanonical policy,
bounded path/link/size rejection, accepted freshness with zero pre-acceptance
source/runner probes, and legacy output omission.

The accepted policy is canonical `offline-trust-policy-v1`, at most 64 KiB,
with 1--32 strictly sorted unique Ed25519 `spki-sha256` identities. Its raw
digest pin is integrity only. Release evidence MUST NOT call it policy
authenticity, anti-rollback, historical revocation, trusted time, external
signer identity, KMS/HSM, Sigstore/OIDC, transparency, hosted trust, complete
M3, capability conformance, or overall verification.

## Alpha.18 repository-derived SPDX v2 release contract

The only repository-derived route is exactly
`attest --derive-spdx --current-manifest FILE`, mutually exclusive with
`--spdx FILE`. Qualification must prove its frozen static local profile: root
`package.json`, lockfile-version-3 `package-lock.json`, supported exact
dependency specifications, and no npm, Node, Git, network, or repository
command execution. Two matching snapshots precede derivation and a third
precedes signing; the canonical SPDX and provenance must bind the version-2
bundle model. The current snapshot must exactly equal the authoritative
verification subject. Because this command-free profile has an empty Commit,
it applies only to the same local/exported non-Git identity; an authoritative
Git-commit subject fails closed.

Derived-SBOM currentness may run only after explicit SPKI trust and a complete
raw-bundle digest pin. Its outcome is `fresh`, `stale`, or `unknown`, separate
from the existing signed results. Lockfile integrity is a checksum-shape check,
not registry verification. This is not general npm compatibility, package
discovery/completeness, SBOM truth, license/vulnerability analysis, capability
conformance, overall verification, or complete M3. Alpha.18 formal race,
fixed-VM, and release-evidence gates remain pending.

## Alpha.17 dependency remediation contract

The selected module graph must require indirect
`golang.org/x/text@v0.39.0`, the minimum reviewed fixed release for
`GO-2026-5970` / `CVE-2026-56852`; `v0.14.0` and its sums must be absent. The
module path, `go 1.26` directive, every other application dependency, public
checksum-database defaults, and Alpha.16 product semantics remain unchanged.
The selected graph must contain only three additional upstream consequences:
`x/mod` `v0.8.0 -> v0.37.0`, `x/tools` `v0.6.0 -> v0.47.0`, and added
`x/sync@v0.21.0`. Both final product binaries must prove that they do not embed
those graph-only tool modules.

Qualification must run `go mod verify` and `go mod tidy -diff`, compare the
module graph, and use pinned official `govulncheck v1.6.0` gates in ordinary
exit-status mode. The application gate is exactly
`-C cmd/repopass -scan module` with no package pattern; the independent source
and test gate is exactly `-test ./...`. Both final release executables require
binary scans. Two clean release builds must match byte-for-byte, and the fixed
VM must replay the Alpha.15 six-member SPDX path and Alpha.16 trusted pinned
currentness path before exact-set evidence packaging and tamper verification.

Passing those gates proves only that the exact qualified source and binaries
selected `x/text@v0.39.0`, passed the pinned scanner against the vulnerability
database observed by that run, and retained the explicitly replayed behavior.
It does not prove future vulnerability absence, all-build-tag reachability,
dependency completeness, SBOM truth/currentness, license safety,
exploitability, complete M1/M2/M3, capability conformance, or overall
verification. Capability remains `incomplete` and overall `inconclusive`.

## Alpha.16 bounded local freshness contract

`verify-attestation --current-manifest FILE` is opt-in and requires exactly one
explicit trust key and one canonical complete raw-bundle digest pin. Bundle
shape, integrity, signature, SPDX/privacy profile, safe trust-key read, and
exact SPKI trust acceptance all precede current-source access. A failed trust
decision remains `not-evaluated` and does not probe a runner.
Separated and equals flag forms route identically, including dash-leading path
values; a recognized next freshness flag still means that the preceding value
is missing. Syntax errors remain fixed and occur before I/O.
An unsupported historical Git/non-local identity is classified
`unknown/source-identity-unavailable` before resolving or opening the supplied
current path and before any runner probe.

The current manifest's parent is snapshotted twice before source comparison or
manifest parsing. If source matches, the manifest is strictly loaded and the
signed scenario resolves against that stable snapshot; a third matching
snapshot is required before policy, plan, or runner comparison. Earlier stable
drift stops later access. Only the exact signed Docker/Podman backend is probed,
and `runner-stable-v1` binds backend, controller OS, workload OS, rootless mode,
and engine version.

The unsigned replay report contains four ordered checks and evaluates to
`current`, `stale`, or `unknown`. Stable mismatch is `EVIDENCE_STALE`; source,
plan, or runner uncertainty retains an operational error and is never called
stale. No opt-in retains Alpha.15 `not-evaluated` output. Original signed
results and all bundle/schema bytes remain unchanged.

This is a bounded point-in-time comparison. It is not scenario re-execution,
elapsed-age/expiry validation, hostile namespace-swap immunity, signer
revocation/transparency, Git/registry provenance, complete runner identity,
observer or SBOM re-validation, capability conformance, overall verification,
or complete M3.

## Alpha.15 bounded SPDX attachment contract

Current resolved plans use schema version `"4"` and bind one of two exact
`minimal-public` evidence selections: normalized observations and verification
summary, with or without `sbom`; the fixed raw exclusions are unchanged. Plan
locks v1, v2, and v3 remain historical. The repository-owned
`healthy/minimal-public-spdx` fixture exercises the selected path without
harness-time manifest mutation.

`attest --spdx FILE` is required exactly once only for an SBOM-selected run.
Syntax is occurrence-aware and non-echoing. The file passes a bounded no-link,
same-handle double read, strict SPDX 2.3 JSON validation/canonicalization, and
the frozen privacy policy before key access or publication. The canonical
derivative is stored as `payload/sbom.spdx.json` in the exact six-member model
and bound by manifest order/digest/size, the exact four-field predicate object,
DSSE, and flattened public metadata. A schema-4 no-SBOM run retains the exact
five-member model and reports the flattened metadata as false/empty/empty.

Replay selects the model from raw tar member names and validates all structural,
verification, manifest, statement, DSSE, signature, SPDX-profile, and privacy
bindings before optional trust. Attachment does not generate an SBOM, discover
packages, evaluate licenses or vulnerabilities, prove correctness/completeness/
currentness, establish producer identity, or upgrade any original verdict.

## Alpha.14 M3-c minimal-public gate contract

Release candidates report `minimal-public`, policy
`minimal-public-v1alpha2`, the compiled ruleset digest, and a passed privacy
evaluation for build and replay. Rejection occurs before private-key access on
build and after signature validity but before optional trust-key access on
replay. It publishes no output and echoes no matched content or private path.

This is not universal secret/PII detection or redaction. Exact UTC timestamps
and opaque IDs remain public. Capability remains `incomplete`; overall remains
`inconclusive`. Freshness, external identity, Sigstore, SBOM, and full M3 are
not claimed.

## Alpha.13 M3-b retained portable-replay contract

Alpha.13 may publish a separate canonical Ed25519 SPKI PEM companion with
`attest --public-key-out`. It reports SHA-256 over the complete raw bundle and
over canonical companion PEM bytes while retaining the distinct DER-based
signer key ID. Bundle and companion destinations are new, distinct, isolated,
bounded files using same-directory no-replace publication.

`verify-attestation --expect-bundle-digest` accepts only canonical lowercase
`sha256:<64 hex>`, checks the raw bundle before optional trust-key access, and
reports `EVIDENCE_DIGEST_MISMATCH` on mismatch. Equality does not confer trust
or bypass canonical bundle and signature verification. The companion,
embedded key, digests, and key ID are not maintainer identity, transparency,
revocation, or a CA trust chain. Freshness re-observation, Sigstore/OIDC,
KMS/HSM, SBOM, hosted trust, and full M3 remain deferred.

## Alpha.12 attached-service cleanup lifecycle contract

Alpha.12 fixes one cleanup signal time-of-check/time-of-use race. Only the
Runner-owned attached-service finalization path privately authorizes an exact
quiescent no-op; a direct helper call remains fail-closed.

The Node, Python, and controller predicates accept two disjoint states:

- delivered: `ok=true`, `remaining=0`, `initialTargets>=1`, and
  `1<=sent<=initialTargets`; escalation is allowed only here;
- quiescent no-op: `ok=true`, private authorization present, `remaining=0`,
  `initialTargets>=0`, `sent=0`, and `escalated=false`.

All counts must be nonnegative. Impossible counts, remaining targets,
escalated or unauthorized no-op, false/missing `ok`, malformed, unknown,
duplicate, trailing, or truncated JSON, dirty stderr, and a nonzero helper exit
fail closed. The no-op emits `service.signal` succeeded with
`alreadyExited=true` and exact `sent=0`, without claiming delivery;
`service.exit` records failed with `exitedBeforeSignal=true`.

Helper success does not bypass the existing bounded wait for the exact attached
execution. A wait timeout or cancellation uncertainty remains `CLEANUP_FAILED`;
an attached execution error remains the primary run error, and a primary
readiness or journey failure is never erased.
Immutable-container-ID quiescence, final observers, residue classification,
export safety, forced removal, and residue checks remain mandatory. No schema,
error code, milestone, observer coverage, or compatibility tuple changes.

## Alpha.11 M3-a attestation contract

Alpha.11 adds a local, offline attestation path only. `attest` loads one
authoritative historical verification by run ID, recomputes its integrity, and
accepts one canonical Ed25519 PKCS#8 PEM private key. It emits a deterministic,
uncompressed USTAR with exactly these sorted regular-file entries:

```text
attestation.json
bundle-manifest.json
payload/verification.json
signature.dsse.json
signer-public-key.pem
```

The JSON and USTAR headers are canonical and bounded. The statement uses
in-toto Statement v1 and predicate type
`https://repopass.dev/attestation/verification/v0.1`; its subject binds the
canonical manifest. The predicate binds the run/verification IDs, complete
verification artifact and content digests, source identity, plan/policy
identity, runner, and original verdicts. The DSSE envelope contains exactly
one Ed25519 signature over exact PAE, and the key ID is SHA-256 over SPKI DER.

`verify-attestation` rebuilds the canonical bundle contract, recomputes the
verification's existing integrity, and validates every manifest, statement,
payload, key-ID, public-key, and signature binding before considering trust.
Trust is explicit canonical SPKI equality: absent trust is `unknown`, mismatch
or unreadable trust is `rejected`, and only exact match is `accepted`.

This is not freshness validation. Alpha.11 always reports
`freshnessEvaluation: "not-evaluated"`; the embedded
`originalResults.freshness` is only the historical stored result. The
historical verification has source identity but not its former local source
path, so the attestation cannot recover or re-observe that path. Signing also
does not rewrite any original verdict, including `evidence: unsigned`.

The private key must be a bounded regular file outside the authoritative data
store and output location and, when a current repository is detectable from
the working directory through `.git` or `repo-passport.yml`, outside that
repository. Link/reparse and hard-link states fail closed. Windows also rejects
UNC, device, extended-namespace,
alternate-data-stream, trailing-dot/trailing-space, and reserved DOS paths;
the file must be explicitly owned by the current user with a DACL granting
access only to that owner, SYSTEM, and Builtin Administrators. If ownership or
DACL cannot be proved, signing is unsupported.

Bundle publication requires a new destination and uses a flushed,
same-directory temporary file with identity checks and no-replace publication.
This does not claim protection against a hostile concurrent rename, symlink,
or junction swap of the output parent. It is also not a universal power-loss
durability claim across every Windows filesystem or storage provider.
If no current-repository marker is found, the command cannot infer that
boundary. The historical verification contains no former local source path
from which to reconstruct it.

Sigstore, OIDC, transparency logs, KMS, TPM/HSM, key lifecycle, timestamping,
revocation, hosted trust policy, SBOM generation/completeness validation, and
remote publication remain deferred. M3 is not complete.

## Alpha.15 qualification status

Status: **not claimed by this source document**.

A publishable Alpha.15 result requires a final source-bound evidence package
containing exact local/repro, schema, static-analysis, unit/integration/race,
attestation adversarial, live-VM cleanup stress, release-reproduction, residue,
and environment results. Missing, partial, skipped, failed, or source-mismatched
evidence qualifies nothing.

## Historical qualification status

Earlier qualified source and evidence packages remain historical. Alpha.15
does not reinterpret, repackage, or broaden those results, and they do not
qualify this changed source.

## Exact runtime policy

The built-in `baseline-v1` policy accepts only these tuples. The complete
binding participates in `policyBundleDigest`.
The digest also binds the `core.resource-limit-enforcement` rule that governs
the separate enforcement decision; changing that rule changes the policy-bound
plan identity.

| Adapter | Platform | Runtime | Exact image reference |
| --- | --- | --- | --- |
| Node | `linux/amd64` | `22.23.1` | `docker.io/library/node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| Python | `linux/amd64` | `3.12.13` | `docker.io/library/python:3.12.13-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de` |

The runner uses `--pull=never`. A trusted preparation step must explicitly
approve and pre-pull the selected exact reference. These images provide the
language runtime used by the fixed supervisor/helpers and the `/bin/tar`
export helper, so they are part of the local trusted computing base. Their
digests prevent substitution; they do not prove publisher identity,
provenance, signature validity, or benign behavior.

## Alpha.10 cleanup-residue contract

Resolved-plan schema version `"3"` contains the required classifier version
`"0.1.0"` and one exact cleanup profile: `[]` or `["/outputs/**"]`. Cleanup is
part of canonical plan identity and the semantic repeat fingerprint. The
manifest remains `repopass.dev/v1alpha1`; CLI and HTTP drivers remain `0.2.0`
and `0.1.0`.

The controller's final boundary is:

```text
service finalization
  -> immutable-ID workload/driver quiescence
  -> existing final observers
  -> bounded disposable .home/.tmp removal
  -> immutable identity/run-label readback
  -> strict bounded no-follow /outputs inventory
  -> conditional safe permission repair/export
  -> peer and target forced removal
  -> controller work-root removal
```

The inventory is limited to 2,048 entries, 1,024 UTF-8 path bytes, depth 64,
a 512-KiB control envelope, and 4-KiB stderr. Regular contents and symlink
targets are never read. Public evidence is aggregate-only and uses an opaque
one-time token made with a fresh ephemeral HMAC-SHA-256 key; the key and raw
inventory are not retained. The token cannot be opened or independently
recomputed and is neither an attestation nor proof. Any ambiguity or
incomplete trust boundary is `not-tested`.

Zero entries is `clean`. Covered regular files/plain directories are
`allowed-residue`. Empty-profile descendants and every symlink, special, or
unmatched entry are `undeclared-residue` with `CLEANUP_RESIDUE`. This finding
does not itself stop repeats or make `Execute` return an operational error.
Repair and export of unsafe special/symlink trees are denied with an aggregate
observation `Result=denied`; those trees are still force removed. Later
destruction failure is separate and cannot erase confirmed undeclared residue.

Version-1 and version-2 locks produce `PLAN_DRIFT`; neither is reinterpreted
under version-3 semantics. Capability remains incomplete, healthy overall
remains inconclusive, and unsigned evidence is unchanged.

## Historical Alpha.10 qualification status

Status: **not claimed by this source document**.

A publishable Alpha.10 result requires a final source-bound evidence package
containing exact local/repro, static-analysis, unit/integration/race, live-VM,
cleanup-residue, cleanup, release-reproduction, and environment records. A
missing, partial, failed, or source-mismatched package qualifies nothing.

## Historical Alpha.9 CLI stdout JSON Schema contract

Alpha.9 adds one controller-evaluated `stdoutJsonSchema` assertion to the
dependency-free CLI journey. Planning loads only the declared immutable local
schema, validates the supported offline Draft 2020-12 subset, and seals its
portable path, SHA-256 digest, dialect, and validator version. Schema size is
limited to 256 KiB; remote, dynamic, and cross-file references remain
unsupported.

The controller requires complete captured stdout to be exactly one strict JSON
document. Instance bounds are 1 MiB, depth 128, 100,000 nodes, and decimal
exponent `-1000..1000`. Complete malformed JSON and schema mismatch are
`failed`. Shared stdout/stderr log truncation makes completeness unknowable and
is `inconclusive`; it never validates a captured prefix. A missing sealed
binding is `blocked`, and other controller schema-evaluation failures are
`inconclusive`.

Public assertion evidence includes the sealed binding and only safe booleans
and a failure kind. It excludes raw stdout, parsed values, property names,
stdout hashes, and byte counts. The verifier integrity-binds the controller
assertion; it does not independently recapture stdout.

Only the resolved-plan schema changes to version `"2"`. CLI journey driver
version is `0.2.0`; HTTP remains `0.1.0`. The manifest stays
`repopass.dev/v1alpha1`, and other generated artifacts stay schema version
`"1"`. Version-1 locks produce `PLAN_DRIFT` and must be regenerated. Historical
version-1 evidence remains integrity-readable but is not a current Alpha.9
execution contract.

This increment does not complete capability observation, M1, M2, or overall
verification. Broader Docker/Podman/runtime tuples, remote schemas, signing,
and attestations remain unclaimed.

## Historical Alpha.9 qualification status

Status: **not claimed by this source document**.

Local/repro record `20260731T102030Z` and fixed-VM live record
`20260731T102115Z` qualify only the exact Alpha.9 source and evidence package;
they do not qualify Alpha.10, Alpha.11, or Alpha.12.

## Historical Alpha.8 Docker peer TCP-listener observation contract

Alpha.8 adds a controller-owned peer observer only for the exact Docker,
Linux `amd64`, approved Node/Python, single-service HTTP profile. The resolved
plan must require `port-listen`, contain one canonical
`127.0.0.1:<port>/tcp` run listener matching readiness, and retain the sealed
one-service/one-signal lifecycle. Podman and all other shapes report port
observation unavailable.

Immediately before service dispatch, the controller creates the peer from the
same exact pinned image with `--network container:<target-id>`. It verifies
that only the network namespace is shared: PID, mount, IPC, and cgroup
namespaces must differ. The peer runs as UID/GID `65534`, with read-only root,
all capabilities dropped, `no-new-privileges`, no mounts, published ports,
devices, privilege, or added capabilities, and fixed 64 MiB memory/swap,
16-PID, and 0.25-CPU limits. It is removed, and removal confirmed, before the
target container is removed.

A cryptographically random token crosses only bounded stdin JSONL. One strict
`READY` must follow the initial sample and precede service dispatch. One strict
`FINAL` follows service termination and confirmed workload quiescence. The
declared endpoint must be absent in the initial sample, observed during the
sample window, and absent again at the final sample. Identity, namespace,
security, protocol, boundary, timeout, overflow, gap, dirty stderr, nonzero
exit, or removal failure makes the whole event `unavailable`.

The Node and Python helpers read only Linux `/proc/net/tcp` and
`/proc/net/tcp6` entries in LISTEN state. Bounds are 8 KiB per frame, 16 KiB
total stdout, 8 KiB stderr, 16 endpoints, 1,200 samples, 4,096 transitions,
100 ms sampling, a 1-second maximum accepted gap, and a 1 MiB canonical sample
stream. Public `port.listener-trace.summary` evidence contains fixed
non-sensitive observer metadata, declared-endpoint aggregates, and a keyed
helper commitment. It excludes the
session token, raw `/proc` content, socket inodes, undeclared endpoint
identities, and process attribution; the controller does not independently
recompute the helper commitment.

This is bounded polling, not kernel event history. It can miss short-lived
listeners and provides no UDP or process-attribution coverage. A clean event
therefore sets `PortObservation` to only `best-effort`. A required
`port-listen` observer remains incomplete; capability remains `incomplete`,
overall remains `inconclusive`, M1/M2 remain incomplete, and evidence remains
unsigned.

## Historical Alpha.8 qualification record

Local/repro gate `20260731T085753Z` passed formatting, `go vet ./...`,
reachable vulnerability scanning, `go test ./... -count=1`, a five-repeat
shuffled security-focused suite, integration-tag compilation, release smoke
checks, and an exact byte-for-byte rebuild.

Live gate `20260731T085836Z` passed all 19 ordered guest gates and all 12
required Docker cases, including sequential Node and Python
`TestContainerPeerPortObservation` records and Linux
`go test -race -count=1 -v ./internal/execution`. The exact tuple is Docker
client/server 29.1.3, Ubuntu 24.04.4 LTS, kernel 6.8.0-134-generic, Linux
`amd64`, cgroup v2, QEMU, Go 1.26.5, and the two approved images above.
Container, network, volume, source, and host-listener before/after records
matched; guest cleanup and final QEMU/seed shutdown passed without force.

This is an unsigned, exact-tuple Alpha.8 result only. It does not qualify
Podman, rootless operation, another Docker/kernel/image/architecture tuple,
M1, or M2. A complete listener trace remains `best-effort`, a required
`port-listen` capability remains `incomplete`, and overall remains
`inconclusive`.

## Historical Alpha.7 Docker `/outputs` activity-trace contract

The controller starts a trusted root helper before workload execution with the
exact shell-free `docker exec --interactive --user 0:0 ...` transport and
stops it only after workload quiescence. Control and result messages use bounded
stdin/stdout JSONL. Exactly one `READY` and one `FINAL` frame are required. A
root helper is not targeted by quiescence of workload UID/GID `65532` or
driver UID/GID `65533`. A cryptographically random session token is written
only through stdin and must never appear in argv, environment variables, logs,
or public evidence.
Each frame is capped at 8 KiB, total stdout at 16 KiB, stderr at 8 KiB,
notifications at 4,096, and the canonical transcript at 1 MiB.
No workload-writable control file is created.

Raw workload paths remain only in bounded helper memory. The public
`filesystem.activity-trace.summary` contains aggregate notification counts,
controller-window phase hints, and a per-session keyed canonical transcript
digest. It contains no raw path, content, token, actor attribution, or
operation/syscall record.

The Node adapter manually installs non-recursive per-directory `fs.watch`
watchers capped at 2,048. Its kernel queue-overflow detection is unavailable.
The Python adapter uses inotify with the same cap and fails closed on queue
overflow. Dirty stderr, nonzero exit, timeout, missing/extra/trailing/oversize
frames, identity mismatch, overflow, a detected gap, or any count/bound
mismatch makes the whole trace `unavailable`; no partial success is published.

Dynamic watch installation, coalescing, reads, rename pairing,
watched-directory replacement, exact operation semantics, exact phase
attribution, and actor attribution remain blind spots. The helper has
`observerPlacement=in-sandbox-trusted-helper` and
`sharesSandboxResourceBudget=true`, so its CPU, memory, tasks, and tmpfs use
can perturb resource measurements.

This is Docker-only best-effort notification evidence. Podman activity tracing
is unavailable until separately live-qualified. Required filesystem-write
remains incomplete; capability remains `incomplete`, overall remains
`inconclusive`, M1/M2 remain incomplete, no undeclared-write result is
produced, and evidence remains unsigned.

## Historical Alpha.6 Docker engine filesystem-diff contract

The Docker backend invokes no shell and uses exactly
`docker container diff <immutable-64hex-id>` after verifying the full immutable
container ID. Stdout and stderr are each capped at 4 MiB. Collection is clean
only when the process exits `0`, neither stream is truncated, and stderr is
empty. Any failure or dirty transcript makes this supplemental component
`unavailable` without failing the functional journey or stopping later
repeats.

Docker CLI stdout is an opaque byte transcript because filenames may contain
newlines. RepoPassport does not parse or publish paths or `A`/`C`/`D` records,
and it never exposes the raw transcript. Public evidence contains only a
SHA-256 commitment, byte count, and nonempty flag.

The pre-workload baseline is diagnostic only and neither grants nor downgrades
coverage. Only the final collection after workload quiescence and before
permission repair, with immutable container identity reverified, may give the
engine-diff component `best-effort`. Docker reports changes cumulatively since
container creation, so the transcript can include trusted initialization,
observer, and other pre-workload activity and provides no actor, operation
time, or workload-phase attribution.

The transcript excludes `/outputs`, which is a separate tmpfs, and bind or
other mounts including source, workspace, and inputs. The supported container
root filesystem remains read-only. Retained-state event coverage can still be
`high`, but the combined filesystem-write view remains only `best-effort`.
Required filesystem-write remains incomplete; capability remains `incomplete`,
overall remains `inconclusive`, M1/M2 remain incomplete, no undeclared-write
result is produced, and evidence remains unsigned.

## Historical Alpha.5 retained-state observer contract

The alpha.5 observer takes strict, controller-owned baseline and final
snapshots below `/outputs`. The baseline boundary is after controller output
initialization and before workload execution. The final boundary is after
confirmed workload quiescence and before permission repair,
runner-managed disposable HOME/TMP removal, or output export. The same immutable
container identity and run label must be verified at both boundaries.

Each snapshot accepts at most 2,048 entries and 1,024 UTF-8 bytes per normalized
public path in a 4 MiB helper-control envelope; the retained diff is limited to
256 changes. Entry commitments include path, type, mode, and size. Regular-file
contents and raw symlink targets contribute SHA-256. Public evidence is
aggregate-only: `filesystem.retained-state.summary` contains the two snapshot
digests, entry counts, and retained change count without contents, targets, or
per-path records. Its event coverage is `high` only when the complete pair
succeeds.

Only a complete pair may give the `filesystem.retained-state.summary`
observation event coverage `high`. Composite
`FilesystemWriteObservation` remains `best-effort`, and the required
`filesystem-write` observer remains incomplete. The observed scope includes
trusted helpers and runner-managed, workload-writable disposable
`/outputs/.home` and `/outputs/.tmp`, which are excluded from export.
It cannot see state outside `/outputs`, transient create/delete,
write-then-restore, operation time, process/phase attribution, rename identity,
ownership, timestamps, xattrs, ACLs, inode identity, or device identity.
Snapshot, identity, quiescence, bound, or decode failure is nonfatal and must
produce retained-state `unavailable`, never an empty successful diff.

This observer cannot establish undeclared-write conformance and is not a full
filesystem observer. Capability remains `incomplete`, overall remains
`inconclusive`, M1 and M2 remain incomplete, and evidence remains unsigned.

Retained-state and engine-diff path commitments use unsalted raw SHA-256.
Withholding raw paths is not dictionary-resistant path secrecy: low-entropy
candidate paths can be guessed and tested. Alpha.7's keyed activity digest
does not strengthen those historical commitments.

## Historical Alpha.4 resource-observer contract

The collector may report composite `ResourceUsage` coverage `high` only when
every required sample for every repeat succeeds. Live record
`20260730T173121Z` validates this claim for the exact Docker client/server
29.1.3, Ubuntu 24.04.4, kernel 6.8, Linux `amd64`, cgroup v2, and approved
pinned-image tuple. This is a coverage ceiling, not a claim of `full`
observation or compatibility with another tuple.

The gate must demonstrate sandbox CPU time from `cpu.stat usage_usec`,
cgroup-wide `memory.peak`, `pids.peak`, final writable allocation, verified
accepted output bytes, and captured controller stdout/stderr bytes. The public
CPU millisecond value rounds down while raw microseconds remain observation
detail. Memory is the sandbox cgroup peak—including cache, tmpfs, kernel memory,
and trusted helpers—not RSS or repository-only memory. `pids.peak` counts
tasks/threads, not processes. Writable allocation is a final snapshot, not a
peak; a write/delete spike may be absent.

Structured evidence records these observations as
`sandboxCPUTimeMillis`, `sandboxPeakMemoryBytes`, `maxTasks`, `writableBytes`,
`outputBytes`, and sorted unique `observedFields`. The field list distinguishes
an observed zero from an unavailable measurement. The legacy
`cpuTimeMillis`, `peakMemoryBytes`, and `maxProcesses` keys remain only for
alpha.3 wire compatibility; the new observer does not populate them. OOM and
PID-controller event counters remain observation details rather than resource
summary fields.

Resource-limit enforcement is the separate `resourceLimitEnforcement` runner
feature and cannot satisfy `ResourceUsage`. A missing probe, failed snapshot,
or incomplete repeat must remain unavailable/incomplete and must not be filled
with zero. Podman, rootless engines, other Docker versions, kernels,
architectures, and images remain unclaimed.

Even with this exact-tuple pass, filesystem-write and port-listen observation
remain unavailable and complete child-process observation remains best effort.
Therefore M1 remains incomplete, healthy results remain capability
`incomplete` and overall `inconclusive`, and evidence remains unsigned.

## 1. Source quality gate

Run from the repository root with the Go version declared by `go.mod`:

```powershell
gofmt -l .
go vet ./...
go test -count=1 ./...
go test -count=1 -tags=integration ./internal/cli -run '^$'
```

`gofmt -l .` must print nothing. The last command compiles the integration-tag
suite without selecting a live backend.

## 2. Pre-pull and inspect both approved images

For Docker:

```powershell
$nodeImage = "docker.io/library/node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3"
$pythonImage = "docker.io/library/python:3.12.13-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"

docker pull --platform linux/amd64 $nodeImage
docker pull --platform linux/amd64 $pythonImage
docker image inspect $nodeImage $pythonImage
```

Use the equivalent `podman pull --platform linux/amd64` and
`podman image inspect` commands for a Podman gate. Never replace a failed exact
pull with a mutable tag.

## 3. Live container gate

Record the backend client/server version and feature information, then run the
complete opt-in container test set:

```powershell
docker version
docker info

$env:REPOPASS_INTEGRATION_BACKEND = "docker"
go test -count=1 -tags=integration -v ./internal/cli -run '^TestContainer'
Remove-Item Env:REPOPASS_INTEGRATION_BACKEND
```

Replace `docker` with `podman` only for the generic historical container-suite
record. The retained Alpha.8 peer port observation is unavailable on Podman and its
integration case skips there, so a Podman run cannot qualify that observer. A
publishable Docker gate record contains:

- UTC timestamp and source revision/tree identity;
- controller OS/architecture and backend client/server version;
- workload platform `linux/amd64`;
- both exact image references and inspected digests;
- passing Node CLI, Python CLI, forged-verification, repeated-run, output
  quiescence/permission-repair, tar-stream extraction, expected `ENOSPC` disk
  enforcement, assertion, forced cleanup, and Docker
  `TestContainerOutputsActivityTraceObservation` plus sequential Node/Python
  `TestContainerPeerPortObservation` results;
- a complete healthy CLI case showing the plan-bound stdout JSON Schema
  assertion and its privacy-preserving result shape;
- any skip, retry, or environmental caveat.

Unit tests, integration-suite compilation, image inspection, and a standalone
tar probe do not replace the full fixture run. If either language case is absent
or fails, narrow the release claim instead of recording a pass.

Historical Alpha.9 records `20260731T102030Z` and `20260731T102115Z` apply
only to the exact Alpha.9 source and evidence package. They do not qualify the
Alpha.10 cleanup contract or Alpha.11 attestation implementation. Historical
Alpha.8 record `20260731T085836Z` applies only to Alpha.8.
No Podman, rootless, other-version, other-kernel, other-image, or `arm64`
Alpha.12 live result is claimed.

### Historical Alpha.5 qualification target: `20260730T202049Z`

This identifier defines the intended exact-tuple record; it is not a pass
marker. Alpha.5 is qualified only if the external evidence package for
`20260730T202049Z` reports gate exit `0`, binds the final source and release
artifact identities, and contains every required source-quality, schema,
unit, integration, retained-state, live-container, cleanup, residue, and
reproducible-build result. A missing evidence package, nonzero gate exit,
skipped required case, source/artifact mismatch, or tuple mismatch qualifies
nothing.

The qualification target is the exact Docker client/server 29.1.3, isolated
Ubuntu 24.04.4, kernel 6.8, Linux `amd64`, cgroup-v2, approved Node/Python
image tuple. Even if qualified, the result establishes only
`filesystem.retained-state.summary` observation event coverage `high` for
complete snapshot pairs and composite
`FilesystemWriteObservation=best-effort`. Required
filesystem-write remains incomplete; capability remains `incomplete`, overall
remains `inconclusive`, M1 and M2 remain incomplete, and evidence remains
unsigned. It does not establish undeclared-write detection, full filesystem
observation, Podman, rootless operation, another Docker version or kernel,
another image, or `arm64`.

### Recorded alpha.4 result: `20260730T173121Z`

The exact-tuple live gate exited `0`; all 18 ordered gate steps and all ten
required cases passed. The gated source snapshot SHA-256 is
`4492de55cf8c1c57ccdda8fb0f0be4bd2512a7a2dc393ef0e419e620d2d5b4d6`.

| Field | Recorded value |
| --- | --- |
| Guest VM | Isolated Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic`, Linux `amd64` under QEMU; cgroup v2 with the `systemd` driver |
| Controller/workload toolchain | Linux `amd64`; Go 1.26.5 |
| Docker client/server | 29.1.3, API 1.52; Engine minimum API 1.44; commit `29.1.3-0ubuntu3~24.04.2` |
| Node image inspect | Exact repository digest match for `sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`; `linux/amd64` |
| Python image inspect | Exact repository digest match for `sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de`; `linux/amd64` |
| Source gates | Validator self-test, `go vet ./...`, and `go test -count=1 ./...` exited `0` |
| Container cases | The historical nine alpha.3 cases plus `TestContainerResourceUsageObservation`: `10/10 PASS` |
| Resource proof | Complete cgroup-v2/final-snapshot fields produced `ResourceUsage=high`; resource-limit enforcement remained a separate runner feature |
| Source integrity | Before/after source manifests were identical |
| Listener and container residue | Before/after host-listener manifests were identical; before/after all-container inventories were header-only; no host-publish residue remained |
| Source-manifest file SHA-256 | `0f1593e634a3295ed329dafc977ff1b84e0c1eb226b8e89b073e7fe2a74ead78` |
| Evidence-inventory file SHA-256 | `ffd724e50414c841ebe6e7a7bdd39d8c40102522130039c9e62cf95c83e601c7` |

The ten required cases were `healthy_node_cli`,
`healthy_python_cli_with_persisted_setup_output`, `healthy_python_http`,
`healthy_node_http`, `workload_forged_verification_is_ignored`,
`term_resistant_http_child_is_removed`, `service_exits_before_readiness`,
`service_never_becomes_ready`, `TestContainerDiskQuotaExpectedDenial`, and
`TestContainerResourceUsageObservation`.

Local gate `20260730T173051Z` passed formatting, vet, all non-container tests,
security-sensitive shuffled repetitions, integration-tag compilation, release
build, version/checksum smoke, and an independent byte-for-byte rebuild.
`govulncheck` found zero reachable and zero imported-package vulnerabilities.
It reported one required-module-only issue, `GO-2026-5970`; the analyzed code
does not call the vulnerable symbols.

This pass is scoped only to the exact Docker
29.1.3/Ubuntu 24.04.4/kernel 6.8/Linux `amd64`/cgroup-v2/approved-image tuple.
It is not a Podman, rootless, other-Docker-version, other-kernel, or `arm64`
result. Filesystem-write and port-listen observation remain unavailable and
complete child-process observation remains best effort, so healthy runs remain
capability `incomplete` and overall `inconclusive`; M1 is incomplete and
evidence is unsigned. The source-manifest and evidence-inventory hashes identify
individual metadata files; no packaged evidence bundle is claimed.

The nine release-facing Markdown files were updated after the immutable gate to
record this result. The gated code, schemas, fixtures, tests, scripts, and
`dist/` artifacts remain byte-identical; the source snapshot hash above does
not claim that these post-gate wording changes were inside the archive.

### Recorded alpha.3 result: `20260730T150346Z`

The final immutable gate exited `0` for source archive SHA-256
`f5073b9378dbaa792938267ac10a24c4c3a26585402ad61993168003ace3731e`.
Its source manifest contains 154 entries, and all 18 recorded gate steps
exited `0`.

| Field | Recorded value |
| --- | --- |
| Guest VM | Isolated Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic`, Linux `amd64` under QEMU |
| Controller/workload toolchain | Linux `amd64`; Go 1.26.5 |
| Docker client | 29.1.3, API 1.52, commit `29.1.3-0ubuntu3~24.04.2` |
| Docker Engine server | 29.1.3, API 1.52 (minimum 1.44), commit `29.1.3-0ubuntu3~24.04.2` |
| Node image inspect | Exact repository digest match for `sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`; `linux/amd64` |
| Python image inspect | Exact repository digest match for `sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de`; `linux/amd64` |
| Source gates | Validator self-test, `go vet ./...`, and `go test -count=1 ./...` exited `0` |
| Container cases | `healthy_node_cli`; `healthy_python_cli_with_persisted_setup_output`; `healthy_python_http`; `healthy_node_http`; `workload_forged_verification_is_ignored`; `term_resistant_http_child_is_removed`; `service_exits_before_readiness`; `service_never_becomes_ready`; `TestContainerDiskQuotaExpectedDenial`: `9/9 PASS` |
| Structured HTTP proof | The repeated healthy Python and Node HTTP fixtures require every declared assertion to pass: 15 and 21 assertion results respectively, including JSONPath, response schema, and ordered `jsonFile` |
| Source integrity | Before/after source manifests were identical |
| Listener and container residue | Before/after host-listener manifests were identical; before/after all-container inventories were header-only; no host-publish residue remained |
| Artifact smoke in gate | Both `SHA256SUMS` entries verified; Linux text and JSON version reported `0.1.0-alpha.3` |

The final Linux and Windows `amd64` binaries were rebuilt from a different
source path and matched byte-for-byte. The final local gate also ran five
shuffled repetitions of the acquisition, execution, manifest, planner,
structured-JSON, and schema packages. `govulncheck v1.6.0` reported zero
reachable vulnerabilities; it separately reported one vulnerability in a
required module that the analyzed code does not call.

This pass is scoped only to the exact Docker
29.1.3/Ubuntu 24.04.4 LTS QEMU/Linux `amd64`/approved-image tuple above. It is
not a Podman, other-Docker-version, or `arm64` compatibility result. Built-in
observation remains incomplete, so a healthy functional pass is capability
`incomplete` and overall `inconclusive`. M1 is not complete, and the evidence
is unsigned. Release-facing Markdown updates made after the immutable gate are
enumerated separately in the evidence package; gated code, schemas, fixtures,
tests, scripts, and `dist/` artifacts remain byte-identical.

### Recorded alpha.2 result: `20260730T102841Z`

The final immutable gate exited `0` for source archive SHA-256
`893d07fc8711799b68dfe0aabede71cf7154b6c0b13560313d5f0fd96b9eeed9`.
All 18 recorded gate steps exited `0`.

| Field | Recorded value |
| --- | --- |
| Guest VM | Isolated Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic`, Linux `amd64` under QEMU |
| Controller/workload toolchain | Linux `amd64`; Go 1.26.5 |
| Docker client | 29.1.3, API 1.52, commit `29.1.3-0ubuntu3~24.04.2` |
| Docker Engine server | 29.1.3, API 1.52 (minimum 1.44), commit `29.1.3-0ubuntu3~24.04.2` |
| Node image inspect | Exact repository digest match for `sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`; `linux/amd64` |
| Python image inspect | Exact repository digest match for `sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de`; `linux/amd64` |
| Source gates | Validator self-test, `go vet ./...`, and `go test -count=1 ./...` exited `0` |
| Container cases | `healthy_node_cli`; `healthy_python_cli_with_persisted_setup_output`; `healthy_python_http`; `healthy_node_http`; `workload_forged_verification_is_ignored`; `term_resistant_http_child_is_removed`; `service_exits_before_readiness`; `service_never_becomes_ready`; `TestContainerDiskQuotaExpectedDenial`: `9/9 PASS` |
| Source integrity | Before/after source manifests were identical |
| Listener and container residue | Before/after host-listener manifests were identical; before/after all-container inventories were header-only; no host-publish residue remained |
| Artifact smoke in gate | Both `SHA256SUMS` entries verified; Linux text and JSON version reported `0.1.0-alpha.2` |

The final Linux and Windows `amd64` binaries were rebuilt from a different
source path and matched byte-for-byte. This pass is scoped only to the exact
Docker 29.1.3/Ubuntu 24.04.4 LTS QEMU/Linux `amd64`/approved-image tuple above.
It is not a Podman, other-Docker-version, or `arm64` compatibility result.
Built-in observation remains incomplete, so a healthy functional pass is
capability `incomplete` and overall `inconclusive`. M1 is not complete, and
the evidence is unsigned.

### Historical alpha.1 result: `20260730T074535Z`

The final immutable gate exited `0` for source archive SHA-256
`8a6abeac48f5c1200bea4d78763f030f1809532732510dcd30e8197e8a02fdb2`.
The archive contained the final binaries and checksum file; the documentation
updates that record this result do not broaden its tested scope.

| Field | Recorded value |
| --- | --- |
| Host and VM | Windows 11 Pro build 26200; QEMU 11.0.3 with WHPX; Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic` |
| Controller/workload platform | Linux `amd64`; Go 1.26.5 |
| Docker client | 29.1.3, API 1.52, commit `29.1.3-0ubuntu3~24.04.2` |
| Docker Engine server | 29.1.3, API 1.52 (minimum 1.44), commit `29.1.3-0ubuntu3~24.04.2` |
| Node image inspect | Exact repository digest match for `sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`; `linux/amd64` |
| Python image inspect | Exact repository digest match for `sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de`; `linux/amd64` |
| Source gates | Validator self-test, `go vet ./...`, and `go test -count=1 ./...` exited `0` |
| Container cases | Node CLI; Python CLI with persisted setup output; forged-result/background-mutator quiescence; expected `ENOSPC` disk enforcement: `4/4 PASS` |
| Artifact smoke in gate | Both `SHA256SUMS` entries verified; Linux text and JSON version reported `0.1.0-alpha.1` |
| Harness cleanup | `guest_cleanup_verified=yes` |

This pass is scoped to that exact Docker/VM/image tuple. It is not a Podman,
other-Docker-version, or `arm64` compatibility result. The live functional
passes still have capability `incomplete` and overall `inconclusive` because
the observer set remains incomplete.

## 4. Build reproducible snapshots

After the final executable source state and an initial live pass are fixed,
build stripped, path-independent Linux and Windows full/verifier executables,
the two canonical verifier kits, and `dist/SHA256SUMS`. `dist` must be absent
or empty; the builder never overwrites an earlier release:

```powershell
./scripts/build-release.ps1 -Version 0.1.0-alpha.33
```

The Alpha.33 script accepts only the exact Alpha.33 version, sets
`CGO_ENABLED=0`, uses `-trimpath`, restores the caller's Go environment
variables, validates the exact seven-file inventory in private staging, and
publishes the completed directory with a single no-overwrite directory move.
`SHA256SUMS` binds the other six files with lowercase SHA-256 in deterministic
filename order.

Building changes the release archive identity. Freeze the resulting `dist/`
files, rerun the complete live gate in section 3, and treat only that
post-build run as the final immutable release record.

At minimum, verify the exact inventory, all six checksum entries, both packaged
versions, and both kits with an independent strict parser. Repeat the build
from an independent source copy into a fresh empty output and compare every
byte:

```powershell
.\dist\repopass-windows-amd64.exe version
.\dist\repopass-verify-windows-amd64.exe version
Get-Content .\dist\SHA256SUMS
Get-ChildItem .\dist -File | Sort-Object Name | Select-Object Name,Length
Get-FileHash -Algorithm SHA256 .\dist\*
```

The source-bound Alpha.27 qualification harness applies a separately
implemented strict USTAR/manifest verifier to both kit archives; a successful
Go build alone is not that independent-parser result.

No Alpha.17 release hashes are claimed in this source document. The historical
Alpha.8 local/repro record `20260731T085753Z` reproduced its release files
byte-for-byte:

- `repopass-linux-amd64`:
  `1b11d68135dd13ab06ae2e7d00d871575e30e4bfb5257062309c3e891c54dbef`
- `repopass-windows-amd64.exe`:
  `371b73220d1fc6ade9e7604ecbfc52dc0e34f5b673ee988c9683e16503a7ccd6`
- `SHA256SUMS`:
  `4f97e297518e80fe77b51fb1c78301ac95c55f40450d7b430ef841997a604b76`

Historical live gate `20260731T085836Z` revalidated those exact Alpha.8
artifacts before tests. The table below remains the historical alpha.4 record
and does not replace the historical Alpha.8 hashes above.

The final historical `0.1.0-alpha.4` snapshots were rebuilt with Go 1.26.5
from a different source path and reproduced byte-for-byte. `SHA256SUMS`
self-verification, packaged Windows text/JSON version, Linux ELF64
little-endian `amd64` header, and Linux text/JSON version checks passed.

| Historical alpha.4 artifact | SHA-256 |
| --- | --- |
| `repopass-linux-amd64` | `7a40d9cad99f40615df1d011e61ac36ada8ca209b9e3f858bed72d1064dda81d` |
| `repopass-windows-amd64.exe` | `9675ea553a1d954958d8d463fb019bacf954e156587e7331e69b8a6ae5fc8420` |
| `SHA256SUMS` | `fe84a2942b0d3b3ff51413fe125f11885c33d34c47483275b603fd62be263678` |

For historical comparison, the retained `alpha.3` hashes were
`85d3460277d43db4847a55663a3e0cb0d199cd5f9f354f160430116976ddd62e`
for Linux `amd64` and
`89abca38fa79c7f3fdc352fe70601c4b9d97a9d65c0879efdfbc57e00cc51773`
for Windows `amd64`. The retained `alpha.2` hashes were
`d27691b4fb7397ee9bac8a18b4bf03a6cb691d5ef4e3e7c3989bc7e6e56bcc8e`
for Linux `amd64` and
`637fee295391bbc8e6065e5a24f29f8b9fd77a81c6a17dad4a73e3b7a1428716`
for Windows `amd64`. The retained `alpha.1` hashes were
`108c67b83eacd6395a0d401dd4385a01263fc522d69a1f66ee56e7ffb5ed65ab`
for Linux `amd64` and
`b7a115e0805cd542a356e0c185cb1c56c750b50118be22c5e54fa36c073f76c8`
for Windows `amd64`.

Future files under `dist/` that differ from these hashes or postdate this source
record are development snapshots until the build and live-gate sequence is
repeated.

## Deferred release artifacts

This alpha does not produce signed binaries, Sigstore/OIDC or hosted trusted
signer identities, transparency-log provenance, KMS/TPM/HSM signatures,
freshness validation, SBOM generation/completeness validation, remote
publication, or a formal release evidence package. Its in-toto output remains
the narrow local Ed25519 attestation, optionally carrying one plan-selected
strict caller-supplied SPDX derivative. Do not describe that slice as complete
M3 or as any of the deferred guarantees.
