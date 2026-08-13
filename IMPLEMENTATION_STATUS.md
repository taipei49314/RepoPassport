# Implementation status

Status date: 2026-08-13

RepoPassport `v0.1.0-alpha.33` is the current `v1alpha1` vertical slice. This
source document does not claim completed Alpha.33 race, local/repro, fixed-VM,
or release qualification; an exact source-bound evidence package must carry
those results. Alpha.32 and earlier evidence remain historical and do not
qualify or repackage this changed source. This is not a complete implementation
of every milestone in the project plan.

The public source branch additionally carries an unreleased Git-worktree
identity compatibility fix with a new frozen privacy ruleset. It is not
byte-identical to, or qualified by, the Alpha.33 canonical release evidence.

## Unreleased canonical module/source identity

RFC-0001 accepts `github.com/taipei49314/RepoPassport` as the exact canonical
repository, Go module, and repository-owned package prefix. This source
atomically migrates `go.mod`, imports, the public `schemas` package, release
linker target, active documentation, and release build-information checks.
Protocol URLs, JSON Schema identifiers, evidence predicates, binary names,
CLI output, historical Alpha artifacts, and M1-M7 scope are unchanged.

Source conformance and release qualification fail closed on legacy/case-variant
identity, workspace replacement, wrong main package, unreadable build
information, revision mismatch, dirty source, missing required artifacts, and
portable-kit substitution. PR checks establish only implementation status.
The scoped `RP-M0-MODULE` row is now `PASS`: exact merged main first-attempt
Linux and Windows checks cover the source, external consumer, release binaries,
portable kits, and a second clean-source byte-for-byte release rebuild with no
required skip. The acceptance registry re-derives this row for each current CI
subject from the required Go and Windows checks. This does not close M0 and is
not repository-owner or signer authentication, trusted time, provenance, or
overall verification.

## Unreleased current-source qualification controller

RFC-0002 defines and this source implements the private, fail-closed
current-source qualification data plane: exact Git subject inspection,
canonical USTAR source and manifest generation, strict Linux/Windows receipts,
bounded source gates, attempt tombstones, exact package/tool assembly, and
empty-directory offline subject verification. Filesystem traversal is bounded
and no-follow; output publication is identity-bound and rechecks the source
before retaining a lane artifact.

The production controller intentionally cannot authorize a PASS yet. It has no
authenticated complete GitHub attempt-history provider, and the OS gate
executor has no lane-lifetime authority that can hold the executable, loader,
runtime, and toolchain identities immutable. Linux has a rootless network
namespace enforcement path; Windows reports the network-denied gate BLOCKED
until an equally enforceable platform boundary exists. Missing authority is
never converted to a skip or PASS. A preconstruction non-PASS is retained as
one canonical attempt tombstone using only the successful workflow context's
explicit expected subject; it is not a lane receipt and does not close
`RP-M0-QUAL`.

The GitHub workflow is transport and replay automation only. Actions artifacts
are not external trust, signer identity, trusted time, provenance, or release
approval. `RP-M0-QUAL` remains BLOCKED until both required lanes run on the
exact merged default-branch SHA with authenticated first-attempt history,
immutable gate applications, complete PASS receipts, independent offline
replay, and no required skip. M1-M7, external trust, independent review, and
stable release qualification remain unchanged and incomplete.

## Unreleased required Docker and Podman healthy-journey check

The ordinary CI workflow includes a required Linux `amd64` matrix for the
existing Docker and Podman command backends. Each fresh job pulls the exact
approved digest-pinned Node and Python images, records the checkout, runner,
kernel, cgroup, engine, and selected image details, and runs only the named
healthy Node/Python CLI and single-service HTTP journeys. The named test
requires functional `PASS`, reproducibility `STABLE`, cleanup
`ALLOWED_RESIDUE`, exact configured repeat counts, and confirmed removal of
every container created by the controller.

This is a non-versioned current-source CI check, not a release receipt or a
fixed-VM qualification. Podman continues to report the Docker-only engine
diff, activity-notification, and peer-port observers as unavailable. Healthy
results therefore remain capability `INCOMPLETE` and overall `INCONCLUSIVE`.
The scoped `RP-M1-JOURNEY` functional/reproducibility/cleanup row is now
`PASS`: an exact merged-main first-attempt run completed all four named
Docker and Podman journeys with no required skip or labeled residue. The
acceptance registry re-derives this row for each current CI subject from the
exact backend matrix. It does not complete M1, any M2 observer row, external
trust, or stable release qualification.

## Unreleased machine-verifiable acceptance registry

RFC-0003 freezes the full roadmap as exactly 37 ordered, required `RP-*` rows
in canonical `acceptance-registry.json`. The strict parser and public schemas
reject missing, duplicate, unknown, reordered, weakened, or noncanonical
scope. Ordinary CI derives a separate canonical evaluation bound to its exact
commit, Git tree, workflow run, attempt, and required-check results, then
independently replays its digest and subject before retaining it outside the
checkout.

The tracked registry contains no self-referential commit or tree. The runtime
evaluation is producer-owned CI transport with `formalClaim=false`; it is not
external authority, trusted time, release approval, or append-only history.
Ordinary CI validates an honest incomplete state instead of requiring false
completion. `RP-M0-MODULE` and `RP-M1-JOURNEY` are current-check-derived,
`RP-M0-QUAL` remains `BLOCKED`, and unfinished rows remain `NOT_RUN`.
`RP-REGISTRY` itself remains `NOT_RUN` until every required row has current
evidence. The separate completion operation cannot pass or set
`stableEligible=true` unless all 37 exact rows, the four external
qualification rows, and the stable-schema row are `PASS`.

## Alpha.33 bounded offline policy-authority transition chain

Alpha.33 composes 2..8 existing Alpha.32 transition envelopes in one canonical
unsigned transport. Verification begins at an explicit caller root and
authenticates every ordered hop before reading the terminal policy. It binds
exact adjacency, unique authority identities, cycle rejection, strictly
increasing generations, an explicit terminal key, and an authority floor. The
root, every intermediate, and terminal authority must all remain separate from
trusted and revoked evidence-signer roles.

The full CLI adds a bounded chain assembler that publishes exactly the
terminal SPKI, chain JSON, and root SPKI companion into a new no-overwrite
directory. The portable verifier exposes verification only. Opt-in durable
state is one separate root-scoped chain+policy record; direct, one-hop, and
chain namespaces are not implicitly migrated or compared, so no cross-mode
rollback protection is claimed. A compromised accepted root can still
authorize a malicious chain. There is no root discovery, compromise recovery,
trusted identity/time, transparency, historical revocation, or remote key
lifecycle. Formal qualification remains evidence-bound; `formalClaim=false`,
capability `incomplete`, overall `inconclusive`.

## Alpha.32 one-hop offline policy-authority continuity

Alpha.32 adds a purpose-separated canonical one-hop DSSE transition from an
explicit previous offline trust-policy authority to one distinct terminal
authority. `verify-attestation` accepts the transition only with the complete
signed-policy triple, explicit old root, explicit terminal key, and canonical
policy and authority floors. It verifies the intrinsic bundle first, then the
transition and terminal policy, enforces authority/evidence-signer role
separation, and only then may atomically observe one combined root-scoped
state record before signer claims can be released.

The full CLI adds a bounded producer that publishes exactly the terminal SPKI,
transition DSSE envelope, and previous-root SPKI companion into a new
no-overwrite directory. Both SPKIs remain companions rather than trust roots.
The portable binary exposes verification only and its exact-four kit declares
that no transition sidecar is included. Direct signed-policy mode remains
compatible. There is no multi-hop chain, automatic bootstrap, KMS/HSM,
compromise recovery, remote publication, transparency, trusted identity/time,
or historical revocation. Formal qualification remains evidence-bound;
`formalClaim=false`, capability `incomplete`, overall `inconclusive`.

## Alpha.31 bounded offline trust-policy issuer

Alpha.31 adds `sign-offline-trust-policy` to the full CLI. It authors only the
existing strict `offline-trust-policy-v2` payload and its dedicated exact-one-
signature Ed25519 DSSE envelope. Callers supply one safe-integer generation,
1..32 canonical Ed25519 signer SPKIs classified as trusted or revoked, one
separate canonical PKCS#8 Ed25519 authority private key, and one new output
directory. The implementation derives `spki-sha256` key IDs, globally sorts
and de-duplicates them, rejects authority/signer role overlap, signs, parses
and authenticates its exact output, rechecks signer snapshots, and publishes
exactly the envelope and authority-SPKI companion through the existing
no-replace directory transaction.

The command neither creates nor stores private keys. The authority key remains
an explicit caller-managed local input and must be outside the repository,
authoritative data root, and output location. The companion remains transport
material rather than a trust anchor. Existing verification still requires an
independently accepted authority SPKI and explicit minimum generation; optional
local monotonic state has the same reset/fork limitations. The portable
verifier does not expose the producer command. There is no KMS/HSM, rotation,
remote publication, root discovery, transparency, identity assertion, or
trusted time. `formalClaim=false`, capability remains `incomplete`, and
overall remains `inconclusive`.

## Alpha.30 bounded release-policy-authority chain

Alpha.30 introduces release-authority-transition-chain-v1: an offline,
canonical transport of 2..8 individually authenticated authority hops. The
explicit caller root remains the sole initial trust anchor. A chain must be
fully authenticated before policy or authority-state I/O; its hops are exact
adjacent, globally unique, cycle-free, and strictly generation-increasing.
The terminal generation satisfies the caller floor and its key equals the
explicit policy authority. One-hop and direct authority modes remain supported.
Chain state is controller-local, root anchored, and binds the terminal
generation to a domain-separated digest of the complete canonical chain.

Alpha.30 retains the external signed inventory for one exact
release-artifact root and adds an opt-in bounded offline authority chain.
`release-authority-transition-v1` is a canonical bounded, exact-one-Ed25519-
signature DSSE envelope that is signed by an explicit old trust root and names
one distinct next policy authority plus a caller-enforced generation floor.
Direct mode remains byte/output compatible apart from the product version.
The previous-root companion is never implicitly trusted, and neither adjacent
nor bundled keys bootstrap trust.

The portable verifier accepts `verify-attestation` and
`verify-release-index`, but includes no root/private key, release-index,
policy, authority-transition sidecar, or evidence. An accepted index means
cryptographic binding and authorization relative to explicit invocation inputs
only; publisher identity and trusted time are both `none`. `formalClaim=false`,
capability is `incomplete`, and overall is `inconclusive`. This does not add
root discovery, remote publication, transparency, trusted time, or
tamper-resistant/distributed state.

The verifier authenticates the index signature before chain, policy, state,
artifact, or runner I/O. In chain mode it authenticates every bounded hop from the explicit old
root, next policy authority, and transition before policy I/O, optionally
observes transition state before policy state, then authorizes the signer,
checks every artifact, and observes release state last. Artifact files are
capped at 128 MiB each, the exact set at 512 MiB, and `SHA256SUMS` at 64 KiB.
Transition, policy, and release state detect rollback/equivocation only relative
to surviving controller-local records; deleting, restoring, copying, renaming,
or forking the selected data root resets or forks the corresponding history.
Generations are not trusted time, and an exact digest is a caller-supplied pin.

Exact artifact verification uses two complete stable scans. It rejects drift
observed across those scans, but assumes a quiescent operator-controlled root;
it is not an atomic snapshot or hostile concurrent-writer boundary.

## Alpha.27 portable offline verifier

Alpha.27 adds a verifier-only executable whose accepted command surface is
limited to help, version, and the existing `verify-attestation` use case. It
shares that implementation with the full CLI, including raw-bundle digest
ordering, canonical bundle validation, signature/privacy evaluation, explicit
SPKI and policy trust, output, exit codes, and optional currentness. Unsupported
commands are rejected before command-specific I/O.

Linux/amd64 and Windows/amd64 verifier executables are distributed in exact,
canonical four-member USTAR kits. A canonical manifest binds the executable
path, byte length, SHA-256, target, product version, supported trust modes, and
the fixed trust boundary. The kit itself includes no evidence signer key,
trust policy, evidence bundle, private key, timestamp, or identity assertion.
Historical replay needs no live worktree or network; opt-in current-source
comparison and persisted policy state still depend on caller-selected local
inputs and state.

This is portable verification tooling, not trust bootstrap. A signature-valid
bundle without independently supplied trust remains `unknown`; a bundled or
companion public key never authorizes itself. macOS, arm64, Sigstore/OIDC,
KMS/HSM, transparency, trusted time, historical revocation, complete M1/M2/M3,
capability conformance, and overall verification remain out of scope.

## Alpha.26 typed public qualification evidence

Alpha.26 changes the qualification/evidence publication boundary, not the
product's runtime observer semantics. Raw fixed-VM Docker info/version/inspect,
image pull/cleanup, Node/Python smoke, `go test -json`, `go test -race`, OS,
container/network/image/volume/listener snapshots, guest console, host listener
snapshots, and process identifiers remain private bounded runner inputs and are
not eligible for the public evidence package.

The public fixed-VM inventory is exact. Its dynamic execution facts are reduced
to canonical, duplicate-key-rejecting typed environment, race, guest-residue,
host-residue, verdict, and summary receipts, plus strict source/harness/matrix
records and fixed one-line terminals. Every allowlisted public path has an
explicit content parser or record grammar; a filename allowlist and marker scan
alone are insufficient. Raw content under its original name or renamed into an
allowlisted slot, unknown/duplicate keys, wrong types, BOM/CRLF, trailing bytes,
path collision, link/reparse alias, inventory drift, or a recomputed manifest/
receipt/external-index chain must fail closed.

This is evidence minimization, not proof that redaction detects every secret.
The historical Alpha.26 external integrity anchor remains unsigned and
supplies no identity or trusted time; Alpha.29 does not retroactively upgrade
it. Alpha.25's listener result and blind spots are unchanged; healthy
runs remain capability `incomplete`, overall `inconclusive`, and
`formalClaim=false`. Alpha.26 does not complete M1, M2, or M3.

## Alpha.25 aggregate peer TCP-listener comparison

For the existing exact Docker/Linux/amd64 approved Node-or-Python, foreground
single-service HTTP profile, Alpha.25 compares the sampled TCP listener union
against the single canonical declared listener after the existing initial and
final barriers. In addition to fixed non-sensitive observer metadata, a
complete public `port.listener-trace.summary` contains `comparisonResult`,
`evidenceBasis=aggregate-only`, and exactly four endpoint-related counts:
baseline, declared, sampled, and undeclared. A `not-tested` summary keeps the
fixed metadata plus the result and evidence basis; no comparison count is
public. An unmatched sample
adds at most one aggregate `UNDECLARED_PORT_LISTEN` finding per repeat.

No public detail may contain an endpoint, IP, port, URL, process/socket/
namespace identity, token, protocol frame, or stderr. `PortObserverVersion`
is now `0.3.0` and is plan-digest-bound; the retained Alpha.24 lock is
historical and does not bind this semantics. This is not a qualification claim:
the 100 ms Linux TCP polling window can miss short-lived listeners and does
not cover UDP, Unix sockets, attribution, outbound traffic, NAT, or any wider
baseline. Required `port-listen` remains capability `incomplete`, a healthy
run remains overall `inconclusive`, and `formalClaim=false` remains required.

## Alpha.24 bounded Python notification comparison

Alpha.24 adds a positive, aggregate-only nonconformance detector for transient
create/delete, write-then-restore, and mutations declared only in another
controller-dispatch phase. It is limited to the exact Docker/Linux/pinned-
Python/CLI synchronous foreground tuple. The helper acknowledges the active
phase and only its existing `filesystem.write` rules before dispatch; the
controller requires separated, identical process snapshots before and after
that window and one confirmed successful dispatch for every acknowledged
window.

Only complete unmatched mutation notifications can produce one aggregate
`UNDECLARED_FILESYSTEM_WRITE` per repeat. Paths, rule text, content, tokens,
cookies, and raw transcripts are discarded before public evidence. Node,
Podman, non-Linux/non-Python runtimes, HTTP/services, signals, and background
work remain `not-tested`/`unavailable`. Queue overflow, watch races, malformed
transport, identity drift, phase/quiescence failure, unconfirmed dispatch, or
any bound failure is `not-tested`, publishes no partial count, and produces no
finding. After readiness, the Python helper latches overflow/gap, stops trusting
filesystem events, completes only the exact phase/stop protocol, and emits a
minimal session-bound typed failure terminal. Only exact exit `1` plus clean
transport is accepted; no partial aggregate or digest is retained publicly.

The detector is not complete operation history, syscall tracing, actor/process
attribution, rename pairing, or observation outside `/outputs`. Composite
filesystem-write coverage stays `best-effort`; healthy runs remain capability
`incomplete`, overall `inconclusive`, and `formalClaim=false`. Observer version
`0.6.0` is plan-digest-bound. It does not complete M1, M2, or rootless
qualification.

## Alpha.23 bounded retained-state declaration comparison

The controller now compares the existing bounded `/outputs` retained-state
delta with the `filesystem.write` declaration union of phases that actually
execute. The comparison starts only after both snapshots, both immutable
identity checks, workload quiescence, and the 256-change public bound succeed.
It covers the normalized create, delete, modify, and type-change delta paths.
Exact paths, one-child `/*`, and recursive `/**` use the versioned Linux
sandbox-path semantics; other `*` characters are literal.

A complete summary adds only aggregate comparison status and counts. It never
publishes raw paths, path fragments, contents, symlink targets, helper output,
or host locations. If any retained delta is outside every executed-phase write
scope, the run records one high-severity `UNDECLARED_FILESYSTEM_WRITE` finding.
This is a capability mismatch rather than an operational execution failure:
functional assertions and cleanup continue independently. A synthetic live
fixture is expected to be functional `pass`, cleanup `allowed-residue`, and
capability/overall `nonconforming`.

This comparison remains a final-state necessary-condition check, not operation
history. Transient create/delete, write-then-restore, wrong-phase activity that
is declared by another executed phase, paths outside `/outputs`, syscall/actor
attribution, rename pairing, and metadata-only semantics remain blind spots.
Composite filesystem-write coverage stays `best-effort`; healthy runs remain
capability `incomplete` and overall `inconclusive`. Observer version `0.5.0` is
plan-digest-bound, and prior version-4 locks with `0.4.0` produce `PLAN_DRIFT`.

## Alpha.22 local monotonic signed-policy state (verifier-only)

`verify-attestation` accepts exactly one signed-policy triple:
`--trust-policy-envelope FILE`, `--trust-policy-authority-key FILE`, and
`--minimum-trust-policy-generation UINT`. Each occurs once with a non-empty
canonical value. The generation is decimal `1..9007199254740991`, with no
sign, whitespace, or leading zero. This mode is mutually exclusive with
`--trust-key` and Alpha.19's `--trust-policy`/`--expect-trust-policy-digest`
pair; shape errors occur before bundle I/O. Alpha.22 retains exactly
one valueless `--persist-trust-policy-state`, only with that complete triple;
duplicates, values, malformed spellings, partial modes, and mixed modes fail
before bundle I/O.

After canonical bundle, signature, SPDX, and privacy validation, the verifier
canonicalizes the caller-supplied Ed25519 authority SPKI, verifies the bounded
single-signature DSSE envelope and its dedicated payload type, then parses the
canonical `offline-trust-policy-v2` payload and applies the caller floor. Only
after that floor passes, opt-in stateful mode uses `--data-dir` (or the
controller default) to observe one canonical record and lock per authority
below `trust-policy-state/v1`. It detects lower-generation rollback and
same-generation different-payload equivocation relative to that surviving
local record. Observation precedes signer authorization, so authenticated
policies that reject a `revoked` or `not-listed` signer still initialize or
advance state. Reports add only `trustPolicyStateEvaluation` and, for valid
state, `trustPolicyStateGeneration`; rollback, equivocation, and unavailable
state use fixed `state-generation-rollback`, `state-generation-equivocation`,
and `state-unavailable` reasons. These fields are omitted in stateless/legacy
modes. State failures release no claims and do not start freshness probes.

On Windows, new state-directory components and lock files are born with their
protected private DACL through explicit creation security attributes and are
validated before use. Existing objects are validation-only and are never
retroactively repaired. This closes only the normal creation-time ACL window;
it does not broaden the trust-state or platform security claims.

The guard is not tamper-resistant or distributed state, trusted time/expiry,
authority rotation/revocation/lifecycle, historical revocation, KMS/HSM,
Sigstore/OIDC/transparency, hosted trust, arbitrary policy extensions,
private-key management, complete M3, capability conformance, or overall
verification.
Deleting, restoring, copying, or forking the selected data directory can reset
or fork local history. Capability remains `incomplete` and overall remains
`inconclusive`; `formal_claim=false` remains mandatory.

## Alpha.19 digest-pinned offline trust policy

`verify-attestation` now accepts exactly one paired
`--trust-policy FILE --expect-trust-policy-digest sha256:<64-lowercase-hex>`
mode, mutually exclusive with `--trust-key`. Flag shape and digest syntax fail
before bundle I/O. Any supplied bundle pin plus complete canonical
bundle/content/signature, strict SPDX, and privacy validation all precede
policy I/O; the policy's exact
raw-byte digest is checked before parsing or use.

`offline-trust-policy-v1` is a strict canonical JSON document no larger than
64 KiB. It fixes schema version `"1"`, `ed25519`, `spki-sha256`, and 1--32
strictly sorted unique lowercase SHA-256 key IDs, each `trusted` or `revoked`.
Only the verifier-computed SPKI DER key ID is evaluated. `trusted` accepts,
`revoked` rejects with reason `revoked`, and absence rejects as `not-listed`.
Optional report fields record `trustBasis`, `trustPolicyDigest`, and
`trustReason`. Current tests verify that legacy no-trust and `--trust-key`
JSON omit those optional fields and retain the pre-policy JSON shape. No
sealed Alpha.18 exact-byte output golden is exercised here, so byte-for-byte
compatibility with Alpha.18 is not claimed. An accepted policy may authorize
the existing bounded freshness re-observation.

The policy is unsigned operator-selected input. Its digest is an integrity
pin, not authenticity, authorization provenance, anti-rollback, signing-time
status, or trusted time. Alpha.19 adds no external signer backend, key
generation, KMS/HSM, Sigstore/OIDC, transparency log, hosted policy, complete
M3, capability conformance, or overall verification. Capability remains
`incomplete` and overall remains `inconclusive`.

## Alpha.18 repository-derived SPDX v2 (narrow profile)

`attest --derive-spdx --current-manifest FILE` is an occurrence-aware,
mutually-exclusive alternative to `--spdx FILE`. It statically derives one
repository-owned SPDX document only from the frozen local Node input profile:
root `package.json` and `package-lock.json` with lockfile version 3. It is
command-free and does not execute npm, Node, Git, network access, or any
repository command.

Two identical bounded source snapshots are required before derivation, and a
third identical snapshot before signing. Canonical SPDX and a derived
provenance payload are bound to the version-2 exact USTAR bundle. Replay may
attempt current SBOM derivation only after explicit SPKI trust and a complete
raw-bundle digest pin; its independent outcome is `fresh`, `stale`, or
`unknown`, never a replacement for signed historical results.

The accepted lockfile `integrity` is a checksum-shape gate only. RepoPassport
does not contact or authenticate a registry, support general npm resolution,
prove all packages were discovered, validate an SBOM's truth/completeness, or
perform license or vulnerability analysis. This does not complete M3 or alter
capability `incomplete` / overall `inconclusive` boundaries.

## Alpha.17 dependency remediation

The required indirect `golang.org/x/text` module is now pinned at `v0.39.0`,
the minimum reviewed fixed release for `GO-2026-5970` /
`CVE-2026-56852`. The old `v0.14.0` content and module sums are absent. No other
application dependency, module path, or Go directive changed.

The exact upstream selected-graph consequences are `golang.org/x/mod`
`v0.8.0 -> v0.37.0`, `golang.org/x/tools` `v0.6.0 -> v0.47.0`, and the addition
of `golang.org/x/sync@v0.21.0`. These graph-only tool modules are not
repository-declared application dependencies. Formal release qualification
must prove that none is embedded in the final Linux or Windows product binary.

The GitHub Actions Go job now runs `go mod download`, `go mod verify`, and
`go mod tidy -diff`, then the pinned official `govulncheck v1.6.0` scanner
against the `cmd/repopass` application module graph and against source plus
test symbols. The module gate is intentionally stricter than symbol
reachability and uses the scanner's ordinary non-zero finding exit;
structured-output modes are not pass gates.

Alpha.16 had zero reachable-symbol and zero imported-package findings for this
advisory, but its selected graph still required the affected module version.
Alpha.17 removes that graph defect without changing CLI, schema, manifest,
plan, execution, attestation, SPDX, privacy, freshness, cleanup, error-code, or
verdict behavior. A successful qualification is point-in-time evidence for the
exact source, binaries, selected module graph, and vulnerability database it
records. It is not an SBOM or a proof of future vulnerability absence,
dependency completeness, exploitability, license safety, all-build-tag
reachability, complete M1/M2/M3, capability conformance, or overall
verification. Capability remains `incomplete` and overall `inconclusive`.

## Alpha.16 bounded local freshness re-observation

`verify-attestation --current-manifest FILE` now provides an opt-in unsigned
replay-time currentness report after explicit SPKI trust and a complete raw
bundle digest pin. It performs two stable pre-plan source snapshots, resolves
the signed scenario and current policy/plan, requires a matching third source
snapshot, and probes only the exact signed Docker/Podman backend. Runner
comparison is limited to `runner-stable-v1`.

The deterministic four-check report is `current`, `stale`, or `unknown`.
Stable drift emits `EVIDENCE_STALE`; incomplete observations use fixed-safe
source, plan, runner, or cancellation errors and are not called stale. Legacy
replay remains `not-evaluated`; original verdicts and signed bundle/schema
bytes are unchanged.

This does not rerun historical work, prove elapsed-age validity, defeat a
hostile concurrent namespace swap, validate Git/registry provenance or full
runner identity, re-observe execution coverage/SBOM currentness, establish
revocation/transparency, upgrade capability/overall, or complete M3.

## Alpha.15 bounded caller-supplied SPDX attachment

Resolved-plan schema version `"4"` now binds a required exact evidence object.
`minimal-public` accepts either
`[normalized-observations, verification-summary]` or the exact sorted set with
`sbom` between them; the three raw exclusions remain mandatory. Version-1,
version-2, and version-3 locks are historical and are rejected by current
checking, execution, and verification.

An SBOM-selected authoritative run requires exactly one `attest --spdx FILE`.
The source is read through a bounded no-link, same-handle double-read contract,
then validated as RepoPassport's strict SPDX 2.3 JSON subset. The canonical
derivative—not the raw transport—is checked by `minimal-public-v1alpha3` and
bound into an exact six-member USTAR. Manifest order/digest/size, the in-toto
predicate's exact four-field `sbom` object, DSSE, and flattened public
`sbomPresent`/`sbomFormat`/`sbomDigest` metadata agree on that derivative.
Schema-4 runs without `sbom` retain the exact five-member model and report the
three flattened fields as `false`, empty, and empty.

Offline verification selects the model from the raw member-name set before
trusting protected content, checks canonical tar and authoritative verification
integrity, manifest, statement, DSSE, and Ed25519 signature, then validates the
strict SPDX profile and privacy before optional trust-key access. Direct
tampering is `ATTESTATION_INVALID`; correctly re-signed privacy-unsafe SPDX is
`EVIDENCE_PRIVACY_BLOCKED`.

This increment attaches but does not generate or independently validate an
SBOM's truth. Package discovery, completeness/currentness claims, license or
vulnerability evaluation, producer identity, remote publication, and complete
M3 remain deferred. Attaching an SPDX document does not alter any original
verdict; capability may remain `incomplete` and overall `inconclusive`.

## Alpha.14 M3-c bounded minimal-public gate

The canonical public verification payload is evaluated by frozen policy
`minimal-public-v1alpha3` before signing and publication. CLI evaluation
precedes working-directory/private-key access; `Build` repeats the pure check
before key normalization. Replay evaluates after canonical bundle, integrity,
statement, DSSE, and Ed25519 validity and before optional trust-key processing.

Rejection is `EVIDENCE_PRIVACY_BLOCKED`, severity high, exit 7. Serialized
details contain only fixed policy/rule/surface metadata, bounded count, and
truncation state. The scanner deterministically fails closed at depth 64,
65,536 nodes, 65,536 bytes per string, or 100 findings. It does not redact or
rewrite the payload and is not universal secret/PII detection. Producer fixes
publish `/outputs`, fixed cleanup scope, and logical `sandbox` instead of host
paths or container IDs. Schemas and bundle/predicate versions are unchanged;
capability remains `incomplete` and overall remains `inconclusive`.

## Alpha.13 M3-b retained portable-replay increment

Alpha.13 adds a separate canonical public-key companion and complete-bundle
transport pin to the existing local Ed25519 attestation. `attest` accepts
optional `--public-key-out`; the companion is the exact canonical Ed25519 SPKI
PEM for the signing key. Build and command results report
`bundleDigest` over the complete raw USTAR bytes and `publicKeyDigest` over the
canonical PEM bytes. `signerKeyId` remains SHA-256 over canonical SPKI DER.

Bundle and companion destinations are prevalidated as new, distinct, bounded
paths outside the authoritative store and detected repository. Both use
same-directory restrictive no-replace publication. No validation failure
publishes either artifact. Because the public companion is published first, a
later I/O or durability failure can leave only that complete companion; the
structured error records publication and durability state without exposing
the private-key path or material.

`verify-attestation` accepts optional `--expect-bundle-digest` in exact
lowercase `sha256:<64 hex>` form. Syntax failure is `MANIFEST_INVALID` and a
raw-byte mismatch is `EVIDENCE_DIGEST_MISMATCH` before optional trust-key file
access. A matching transport digest does not bypass canonical tar, protected
content, verification-integrity, DSSE, or Ed25519 validation. It also does not
confer trust; only `--trust-key` exact canonical SPKI equality can produce
`trustDecision: accepted`.

This increment does not evaluate current freshness or provide maintainer/CA
identity, transparency, timestamping, revocation, Sigstore/OIDC, KMS/HSM,
SBOM, remote publication, hosted trust policy, or complete M3. Original
results remain unchanged, capability remains `incomplete`, and overall remains
`inconclusive`.

## Alpha.12 attached-service cleanup lifecycle increment

Alpha.12 fixes one cleanup signal time-of-check/time-of-use race without
changing the public schema or error vocabulary. Only Runner-owned attached
service finalization passes a private authorization for an exact quiescent
no-op. Direct helper calls remain fail-closed.

The Node, Python, and controller predicates accept exactly two disjoint helper
states. Delivered success is `ok=true`, `remaining=0`,
`initialTargets>=1`, and `1<=sent<=initialTargets`; escalation is allowed only
there. Quiescent no-op success is `ok=true`, private authorization present,
`remaining=0`, `initialTargets>=0`, `sent=0`, and `escalated=false`. Negative
or impossible counts, remaining targets, escalated or unauthorized no-op,
false or missing `ok`, malformed/unknown/duplicate/trailing JSON, truncation,
dirty stderr, and nonzero helper exit fail closed.

The no-op state emits `service.signal` as succeeded with
`alreadyExited=true` and exact `sent=0`, without implying delivery.
`service.exit` intentionally records `failed` with
`exitedBeforeSignal=true`. This lifecycle observation does not make cleanup
fail: cleanup is clean only after the existing bounded wait observes the exact
attached service execution finish. A wait timeout or cancellation uncertainty
remains `CLEANUP_FAILED`; an attached execution error remains the primary run
error, and a primary readiness or journey failure is never erased.

This increment does not change immutable-container-ID quiescence, final
observers, residue classification, export safety, forced removal, or residue
checks. It does not expand runtime/backend compatibility, complete M1/M2/M3,
or upgrade capability `incomplete` or overall `inconclusive`.

## Alpha.11 M3-a local attestation increment

Alpha.11 implements only M3-a: a local, offline Ed25519 attestation around one
already stored authoritative verification result. It does not complete M3.
`repopass attest --run <id> --key <private-pkcs8.pem> --out <bundle.tar>` reads
the run through the authoritative external `RunStore`, recomputes its existing
integrity contract, and signs an in-toto Statement v1 with one DSSE Ed25519
signature. The signing key must be a canonical PKCS#8 PEM file; the emitted
public key is canonical SPKI PEM. The signer key ID is the SHA-256 digest of
the SPKI DER.

The output is one deterministic, uncompressed USTAR archive with exactly five
sorted regular-file entries: `attestation.json`, `bundle-manifest.json`,
`payload/verification.json`, `signature.dsse.json`, and
`signer-public-key.pem`. Headers and JSON are canonical and bounded. The
minimal-public manifest hashes only the verification payload and public key;
the in-toto predicate binds the run and verification IDs, source identity,
plan and policy digests, runner, original verdicts, and both verification
digests. Verification rejects noncanonical JSON or tar bytes, unknown,
duplicate, missing, reordered, linked, special, oversized, or otherwise
altered entries and any mismatch among the manifest, statement, DSSE payload,
key ID, signature, public key, and verification integrity contract.

`repopass verify-attestation <bundle.tar> [--trust-key <public-spki.pem>]`
performs that validation offline. A valid signature without a trust key is
reported with trust `unknown` and exit 7; a nonmatching or unreadable explicit
key is `rejected` and exit 7; only an exact canonical Ed25519 SPKI key is
`accepted`. The embedded public key and key ID are identification material,
not a trust anchor. Cryptographic invalidity is reported before trust-file
availability is considered.

The verification report deliberately separates `artifactIntegrity`,
`signatureValidity`, `signerKeyId`, `trustDecision`, and
`freshnessEvaluation`. Alpha.11 always emits
`freshnessEvaluation: "not-evaluated"`: it does not re-observe a repository,
plan, policy, or runner. `originalResults.freshness` is only the historical
value already stored in the signed verification, and no original verdict or
evidence state is upgraded. The historical verification contains portable
source identity but not the former local source path, so attestation cannot
recover or recheck that path.

Private keys and output locations are fail-closed within the detectable
boundary. Keys must be bounded, regular, canonical, outside the authoritative
data store and output location and, when a current repository is detectable
from the working directory through `.git` or `repo-passport.yml`, outside that
repository. They cannot be symlinks/reparse points or hard links. On
Windows, UNC, device, extended-namespace, alternate-data-stream, trailing-dot
or trailing-space, and reserved DOS paths are rejected; key ownership and DACL
must be provable as the current owner with access limited to that owner,
SYSTEM, and Builtin Administrators. If that proof is unavailable, signing
fails. Output publication uses a same-directory temporary file, flush/close,
identity checks, and no-replace publication, but this is not a claim of
resistance to a hostile concurrent rename/symlink/junction swap of the output
parent. Nor is it a universal claim of power-loss durability for every Windows
filesystem or storage provider.

The key and output safety statements apply to the bounded path and handle
state the command actually validates when those locations are not concurrently
mutated by a hostile local actor. Alpha.11 does not extend those statements to
an adversary racing key replacement or parent-directory topology changes. If
no current-repository marker is found, the command has no repository boundary
to exclude; the historical verification cannot supply its former local source
path as a fallback.

Sigstore, OIDC identities, transparency logs, KMS, TPM/HSM, key generation or
rotation, revocation, timestamping, freshness re-observation, SBOM attachment,
remote publication, and hosted trust policy remain deferred.
`EVIDENCE_STALE` was reserved by Alpha.11 and is not emitted by that historical
path. Alpha.16 emits it only for an opt-in trusted, pinned, stable local drift;
uncertain observation remains `unknown` under an operational error.

## Alpha.10 cleanup-residue classification increment

Resolved-plan schema version `"3"` requires cleanup classifier version
`"0.1.0"` and a non-null `allowedResidue` list. Only `[]` and
`["/outputs/**"]` are executable. This field is canonical digest and lock
material, is deeply cloned into the sealed execution plan, and negotiates the
runner feature `cleanup-residue-classification`. Version-1 and version-2 plans
are historical contracts and are rejected for current checking/execution
rather than reinterpreted.

After the declared cleanup action, service termination, immutable-ID workload
quiescence, and existing final observers, the runner removes its disposable
`.home`/`.tmp` trees, verifies the immutable 64-hex container identity and run
label, and inventories only the `/outputs` tmpfs. Node and Python helpers use
bounded streaming no-follow, directory-fd-rooted traversal. They never read
regular-file content or symlink targets. The strict envelope caps entries at
2,048, normalized UTF-8 paths at 1,024 bytes, depth at 64, stdout control at
512 KiB, and stderr at 4 KiB; ambiguity, truncation, dirty stderr, identity
change, or boundary failure is `not-tested`.

Public `cleanup.residue.summary` evidence carries safe counts, a fixed
post-quiescence/pre-repair/pre-export/pre-destroy boundary, exact completion
flags, the allowlist profile, and an opaque one-time token made with a fresh
ephemeral HMAC-SHA-256 key. It contains no raw entry path, symlink target,
regular content, helper transcript, secret key, or unsalted path hash. The key
and raw inventory are discarded, so the token cannot be opened or
independently recomputed and is neither an attestation nor proof. Failure to
obtain random key material cannot produce a successful classification.

Zero descendants is `clean`. With `/outputs/**`, only regular files and plain
directories are `allowed-residue`. Any descendant under an empty allowlist,
or any symlink/special/unmatched entry, is `undeclared-residue` and adds
`CLEANUP_RESIDUE`. That finding is conformance evidence rather than an
operational execution error, so fresh repeats continue; it also survives a
separate later `SANDBOX_DESTROY_FAILED`. Unsafe symlink/special trees are not
permission-repaired or exported. Other technical failures make cleanup
`not-tested`.

Repeat aggregation is order-independent with precedence
`undeclared-residue > not-tested > allowed-residue > clean`, and the exact
cleanup verdict participates in the semantic reproducibility fingerprint.
This does not raise filesystem-write coverage or complete a milestone.
Capability remains `incomplete`, healthy overall remains `inconclusive`, M1
and M2 remain incomplete, and evidence remains unsigned.

Manifest `repopass.dev/v1alpha1`, CLI journey driver `0.2.0`, HTTP journey
driver `0.1.0`, and observation/assertion/verification/error/CLI-envelope
schema version `"1"` remain unchanged.

## Historical Alpha.9 CLI stdout JSON Schema increment

The dependency-free CLI journey now accepts one `stdoutJsonSchema` assertion.
The schema is an immutable local repository file resolved without executing
repository code. Planning validates the supported offline Draft 2020-12 subset
and seals the portable path, SHA-256 digest, dialect, and validator version in
the resolved plan. Remote, dynamic, and cross-file references remain rejected.

The trusted controller evaluates the complete captured stdout as exactly one
bounded strict JSON document. Instance limits are 1 MiB, depth 128, 100,000
nodes, and explicit/effective decimal exponent `-1000..1000`; invalid UTF-8,
duplicate keys, trailing content, empty output, and bound violations cannot
pass. Complete malformed JSON and schema mismatch are assertion `failed`.
Because stdout and stderr share one bounded capture status, any shared log
truncation makes complete stdout unknowable and is `inconclusive`, never a
validation of a prefix. A missing sealed binding is `blocked`; other
controller schema-evaluation failures are `inconclusive`.

Public assertion evidence contains the plan-bound schema path, digest, dialect,
and validator version plus only safe booleans and a failure kind. It excludes
raw stdout, parsed values, property names, stdout hashes, and byte counts. The
verifier integrity-binds this controller result but does not independently
recapture stdout.

Adding this field to the resolved execution contract moves only the
resolved-plan schema to version `"2"`. CLI journey driver version is `0.2.0`;
HTTP remains `0.1.0`. The manifest remains
`repopass.dev/v1alpha1`, and observation, assertion, verification, error, and
CLI-envelope artifacts remain schema version `"1"`. Version-1 plan locks
produce `PLAN_DRIFT` and must be regenerated rather than reinterpreted. Old
version-1 evidence remains a historical, read-only integrity record.

This assertion does not add an observer or complete the capability model.
Capability remains `incomplete`, overall remains `inconclusive`, M1 and M2
remain incomplete, evidence remains unsigned, and broader runtime/engine
tuples remain unclaimed.

## Historical Alpha.8 Docker peer TCP-listener observation increment

Docker now has a controller-owned peer-container observer for the one declared
TCP listener in the supported single-service HTTP profile. The profile remains
limited to the exact built-in Node/Python Linux `amd64` runtime tuples and a
canonical `http://127.0.0.1:<explicit-port>/...` journey. The peer uses the
same exact pinned image as the target and joins the target network namespace
with `--network container:<immutable-target-id>`.

The peer shares no target PID, mount, IPC, or cgroup namespace and receives no
host mount, published port, device, privileged mode, or added capability. It
runs as UID/GID `65534` with a read-only root filesystem, all capabilities
dropped, `no-new-privileges`, 64 MiB memory and swap limits, a 16-task limit,
and a 0.25 CPU limit. The controller verifies the immutable 64-hex target and
peer identities, exact run and observer labels, exact image, running state,
network sharing, and namespace isolation. Only the network namespace is
shared.

The controller creates and attaches the peer immediately before service
dispatch, requires exactly one strict bounded `READY` frame before starting the
service, waits for workload quiescence, and then requests exactly one strict
bounded `FINAL` frame. A cryptographically random 256-bit session token is
sent only through stdin. It is not placed in argv, environment variables,
logs, or public evidence.

The fixed Node/Python helper samples only `/proc/net/tcp` and
`/proc/net/tcp6` entries in state `0A` (`LISTEN`). It takes an initial and
final barrier around a 100 ms polling cadence capped at 1,200 samples. A
successful result requires the one declared `127.0.0.1:<port>/tcp` endpoint to
be absent initially, observed during the window, and absent finally. Endpoint,
transition, frame, stdout, stderr, sample-gap, and canonical-transcript bounds
are enforced. Dirty stderr, nonzero exit, timeout, invalid UTF-8,
missing/duplicate/unknown/trailing/oversize frames, identity or namespace
mismatch, a sample gap, overflow, incomplete lifecycle evidence, or cleanup
failure prevents successful observer evidence.

Public `port.listener-trace.summary` evidence is aggregate-only. It exposes no
session token, raw `/proc` rows, socket inodes, or undeclared endpoints. Its
canonical digest is a helper commitment, not a controller-recomputed
attestation. Even a complete trace provides only `best-effort` coverage: the
bounded sampling window can miss short-lived listeners, observes TCP only,
and cannot attribute a socket to a process. Observer failure remains
supplemental and does not rewrite the functional verdict; peer removal failure
is independently reported as cleanup failure, and the peer is removed before
the target.

Required `port-listen` observation therefore remains capability `incomplete`,
overall remains `inconclusive`, and neither M1 nor M2 is complete. Podman port
observation is `unavailable`. The exact Alpha.8 Docker/Linux `amd64` live and
race qualification is recorded below; it does not broaden those boundaries.

## Historical Alpha.7 Docker `/outputs` activity-trace increment

Docker now has a bounded, controller-owned activity trace around workload
execution. Before repository workload commands start, the controller launches
a trusted helper as root with the exact shell-free
`docker exec --interactive --user 0:0 ...` transport. It stops the helper only after
workload quiescence. The stdin/stdout protocol is strict bounded JSONL and
requires exactly one `READY` and one `FINAL` frame. A cryptographically random
session token is written only to helper stdin and is never exposed through
argv, environment variables, logs, or public evidence.

Each JSONL frame is capped at 8 KiB, total stdout at 16 KiB, stderr at 8 KiB,
notifications at 4,096, and the canonical transcript at 1 MiB. No
workload-writable control file is created.

Raw workload paths remain only in bounded in-memory helper state. The public
`filesystem.activity-trace.summary` is aggregate-only: bounded notification
counts, controller-window phase hints, and a keyed canonical transcript
digest. It does not contain paths, contents, the session token, per-operation
records, or actor attribution. Node manually installs non-recursive
per-directory `fs.watch` watchers with a hard 2,048-watch limit; its kernel
queue-overflow detection is unavailable. Python uses inotify with the same
watch limit and fails closed on queue overflow.

Every trust and completeness gate applies to the whole trace. Dirty stderr,
nonzero helper exit, timeout, invalid/missing/extra/trailing/oversize frames,
container-identity mismatch, notification/transcript bounds, overflow, or a
detected gap yields activity-trace coverage `unavailable`, not partial
success. Dynamic watch installation, coalescing, reads, rename pairing,
watched-directory replacement, exact operation semantics, exact phase
attribution, and actor attribution remain blind spots.

This is a best-effort notification trace, never operation or syscall history.
It is Docker-only; Podman activity tracing is unavailable until separately
live-qualified. Its
`observerPlacement=in-sandbox-trusted-helper` and
`sharesSandboxResourceBudget=true` mean helper CPU, memory, tasks, and tmpfs
effects may perturb resource observation. Required filesystem-write remains
incomplete; capability remains `incomplete`, overall remains `inconclusive`,
M1 and M2 remain incomplete, no undeclared-write verdict is produced, and
evidence remains unsigned.

Existing retained-state and engine-diff path commitments use unsalted raw
SHA-256. Hiding the raw path does not make those commitments
dictionary-resistant: low-entropy candidate paths can be guessed and tested.
The activity trace's per-session keyed canonical digest does not retroactively
strengthen those historical commitments.

## Historical Alpha.6 Docker engine filesystem-diff increment

The Docker backend now collects a bounded, opaque commitment to the container
writable-layer diff. The controller invokes no shell and uses only the fixed
argument vector `docker container diff <immutable-64hex-id>`, after verifying
the full immutable container ID. Stdout and stderr are each capped at 4 MiB.
The control call is accepted only with exit `0`, no truncation, and empty
stderr; otherwise the engine-diff component is `unavailable` without stopping
the functional run or later repeats.

Docker CLI stdout is deliberately opaque because a filename may contain a
newline. RepoPassport does not parse or expose `A`/`C`/`D` records, paths, or
raw bytes. Public evidence contains only a SHA-256 commitment, byte count, and
nonempty flag. The pre-workload baseline is diagnostic only and neither grants
nor downgrades coverage. Only a final transcript collected after workload
quiescence and before permission repair, with the immutable container identity
reverified, may give the engine-diff component `best-effort` coverage.

Docker reports changes cumulatively from container creation, so the final
transcript can include trusted initialization, observer, and other
pre-workload activity. It cannot attribute an actor, operation time, or
workload phase and does not cover `/outputs`, which is a separate tmpfs, or
bind and other mounts such as source, workspace, and inputs. The supported
container root filesystem remains read-only.

The complete retained-state snapshot pair may still give
`filesystem.retained-state.summary` event coverage `high`. Combining that
evidence with the Docker transcript raises no claim beyond composite
filesystem-write `best-effort`. Required `filesystem-write` remains
incomplete; capability remains `incomplete`, overall remains `inconclusive`,
M1 and M2 remain incomplete, no undeclared-write verdict is produced, and
evidence remains unsigned.

## Historical Alpha.5 retained-state observer increment

The runner takes strict, controller-owned, bounded snapshots below
`/outputs`. The baseline is captured after controller output initialization
and before workload execution; the final snapshot is captured after confirmed
workload quiescence and before permission repair, disposable-directory
removal, or export. The same immutable container identity and run label must be
verified at both boundaries.

Each snapshot has at most 2,048 entries, 1,024 UTF-8 bytes per normalized path,
and a 4 MiB helper-control envelope; the retained diff is capped at 256
changes. Entry commitments cover path, type, mode, and size. Regular-file
contents and raw symlink targets contribute SHA-256 commitments. Public
evidence remains aggregate-only: the
`filesystem.retained-state.summary` event exposes snapshot digests, entry
counts, and a change count, not contents, symlink targets, or per-path records.
The event itself has `high` coverage only for a complete snapshot pair.

A complete pair gives the `filesystem.retained-state.summary` observation
event coverage `high`. Composite `FilesystemWriteObservation` remains
`best-effort`, so the required
`filesystem-write` observer remains incomplete. The snapshots include trusted
helpers and runner-managed, workload-writable disposable `/outputs/.home` and
`/outputs/.tmp`, which are excluded from export. They do
not cover state outside `/outputs`, transient create/delete, write-then-restore,
operation time, process/phase attribution, rename identity, ownership,
timestamps, xattrs, ACLs, inode identity, or device identity. Any snapshot,
identity, quiescence, bound, or decode failure reports retained-state
`unavailable` without stopping the functional run or later repeats.

This increment does not implement undeclared-write detection, a full
filesystem observer, or M1/M2 completion. Healthy runs remain capability
`incomplete` and overall `inconclusive`; evidence remains unsigned.

## Historical Alpha.4 resource-observer increment

The collector separates resource-limit enforcement from
`ResourceUsage` observation. On a complete sample it binds sandbox CPU time,
cgroup-wide peak memory, peak tasks, a final writable-allocation snapshot,
verified accepted output bytes, and captured controller log bytes into
verification evidence. Memory is a cgroup peak, not RSS; task peak is not a
process count; writable allocation is a final snapshot, not a historical peak.

The composite coverage ceiling is `high`. Live gate `20260730T173121Z`
validates that claim only for the exact Docker 29.1.3 /
Ubuntu 24.04.4 / kernel 6.8 / Linux `amd64` / cgroup-v2 / approved-image tuple
and complete samples for every repeat. A failed probe or missing snapshot
remains unavailable/incomplete and is never represented as zero. Podman,
rootless engines, other Docker versions, kernels, architectures, and images are
not claimed.

## Milestone coverage

| Milestone | Status | What is implemented | Deliberately deferred |
| --- | --- | --- | --- |
| M0 — Specification Skeleton | Public schema and partial alpha semantics implemented; conformance corpus incomplete | Strict manifest/schema, implemented semantic invariants, capability and scenario models, independent verdict dimensions, stable error subset, deterministic digest subset, RFC template, Node/Python CLI examples, and the constrained single-service HTTP profile | Remaining semantic/reference invariants, broader compatibility and conformance corpus |
| M1 — Local Verified Runnability | Functional CLI and single-service HTTP paths implemented; full milestone incomplete | `inspect`, `init`, `validate`, `plan`, `verify`, `report`; unit-tested Docker/Podman Linux `amd64` command backend; exact runtime-image policy bound into the policy digest; immutable source and read-only workspace/input copies; runtime and workload-identity probes; non-root CLI and attached HTTP service execution; same-container bounded HTTP driver; controller-owned CLI stdout, HTTP response, and ordered `/outputs` file validation against sealed offline Draft 2020-12 schemas; singular JSONPath; bounded aggregate retained-state evidence; Docker-only bounded opaque engine-diff commitments, Docker-only bounded aggregate activity-notification hints, and Docker-only bounded peer TCP-listener hints for the supported HTTP profile; read-only root; denied runtime network with no host publish; aggregate writable tmpfs cap; signaled and quiesced cleanup; safe tar-stream output export; bounded logs; forced cleanup; repeated CLI/HTTP journey assertions; integrity-checked JSON/text/HTML artifacts; historical exact-tuple Alpha.9 local/repro and Docker fixed-VM qualification | Capability-conforming observer set; redirects, TLS, authentication, multiple services, full RFC 9535 JSONPath, and remote/cross-file schema references; Podman activity/port observation and other Docker/version/platform combinations |
| M2 — Capability Conformance | Partial foundations only | Phase-scoped declarations, hard network-deny and writable-storage enforcement, explicit observer coverage, nonconforming/incomplete verdict separation, narrow controller-owned `/outputs` retained-state evidence and executed-phase-union comparison for surviving mutations, Docker-only aggregate engine-diff commitments and activity-notification hints, Docker-only aggregate peer TCP-listener hints for the supported HTTP profile, and exact-tuple live-validated cgroup-v2 resource observation separate from enforcement | Full operation-history process/filesystem/port/network-attempt observation, transient and exact-phase undeclared-write comparison, broader resource and port observers and compatibility tuples, and setup egress allowlists |
| M3 — Portable Evidence | Partial: local attestation, bounded replay/privacy/freshness, offline signer policy, and bounded SPDX models | Canonical component digests, authoritative external run store, strict read-time recomputation and tamper rejection, deterministic minimal-public USTAR models, caller-supplied or frozen derived SPDX binding, separate canonical SPKI companion, complete-bundle digest pin, in-toto Statement v1, one local Ed25519 DSSE signature, explicit SPKI trust, digest-pinned canonical offline policy trust, and bounded local freshness | External signer identity, Sigstore/OIDC, transparency log, KMS, TPM/HSM, managed key lifecycle/distribution, trusted-time or historical revocation, SBOM generation/completeness validation, license/vulnerability analysis, remote publication, authenticated hosted policy, and complete M3 |
| M4–M7 | Not implemented | Schema and architecture seams only | GitHub-native integration, trial UI, hosted hardened runner, plugin ecosystem |

## Supported alpha path

- Local directory acquisition only. Remote Git references are recognized and
  rejected until credential and SSRF isolation exists.
- Static Node.js and Python discovery. Inspection never runs repository code.
- Strict `repopass.dev/v1alpha1` manifests validated against the embedded public
  schema plus the implemented semantic subset. YAML aliases, duplicate keys,
  merge keys, multiple documents, unknown fields, and literal secrets fail
  closed.
- Dependency-free Node and Python CLI journeys through the Docker/Podman command
  backend. `baseline-v1` accepts only the exact Linux `amd64` runtime/image
  tuples listed in `docs/release.md`; the allowlist is included in the policy
  bundle digest. The exact runtime version is probed before workload commands
  run. It is a bounded consistency self-report from the selected image, not
  independent image attestation.
- CLI `stdoutJsonSchema` validates complete captured stdout as exactly one
  strict JSON document against one plan-bound offline Draft 2020-12 schema.
  Instance bounds are 1 MiB, depth 128, 100,000 nodes, and exponent
  `-1000..1000`. Shared log truncation is `inconclusive`; complete malformed
  JSON or a schema mismatch is `failed`. Evidence omits stdout content, parsed
  values, property names, stdout hashes, and byte counts.
- One dependency-free HTTP service may run under the same exact Node/Python
  tuples. It is attached as UID/GID `65532`; readiness and requests are made
  by a bounded controller-supplied helper running as UID/GID `65533` in the
  same `--network none` container. URLs are canonical, no longer than 2,048
  bytes, use literal `http://127.0.0.1:<explicit-port>`, match the scenario's
  one declared TCP listener, and stay on the same origin. No host port is
  published.
- For that exact Docker HTTP profile only, a controller-owned peer container
  from the same pinned runtime image may observe the declared TCP listener.
  The peer joins only the target network namespace, has separate PID, mount,
  IPC, and cgroup namespaces, runs as restricted UID/GID `65534`, and is
  independently resource-limited. Strict identity, isolation, bounded
  `READY`/`FINAL`, workload-quiescence, declared-listener lifecycle, and
  peer-removal gates are required before the aggregate
  `port.listener-trace.summary` can contribute `best-effort` coverage.
  Podman port observation remains `unavailable`.
- Controller-supplied Python helpers use `python -I -S` and working directory
  `/`; repository modules in `/workspace` are therefore outside their import
  search path.
- HTTP readiness/request timeouts are absolute wall-clock deadlines, not
  socket-inactivity timers. A small runner-owned margin exists only to cancel,
  quiesce, and confirm helper exit after the functional deadline. HTTP
  durations must resolve to whole milliseconds and be at least 1 ms: `1.5s`
  resolves to 1,500 ms and is valid, while `1.5ms` is invalid. Readiness is
  capped at 2 minutes, retries with exponential backoff, and stops after at
  most 128 attempts. Each explicit per-request timeout and the resolved
  exercise fallback used when omitted are capped at 30 minutes; the fallback
  is `phases.exercise.timeout`, or 1 minute when absent. Expected readiness and
  response statuses are 200–599.
- An HTTP journey has at most 128 ordered steps and 32 requests. Effective
  headers must simultaneously satisfy count ≤ 64 and aggregate bytes ≤ 65,536,
  and each header value has at most 8,192 bytes. Aggregate bytes are
  `sum(len(name bytes) + len(value bytes) + 4)` over all effective headers;
  accepted names and values are ASCII, so these are also their UTF-8 byte
  lengths. The automatic JSON `content-type` counts in both the count and
  aggregate. A text request body and the actual serialized JSON request bytes
  are each capped at 1 MiB.
- Before a readiness retry or service cleanup, UID/GID `65533` must have
  exited synchronously or been quiesced by a trusted root helper. An
  unconfirmed helper state fails closed.
- The HTTP assertion subset is response status, one header substring,
  `bodyContains`, `fileExists`, singular `jsonPath.equals`, offline Draft
  2020-12 response `jsonSchema`, and ordered `jsonFile`. JSONPath is limited to
  `$`, dot/bracket members, and non-negative array indexes (1,024 bytes and 64
  selectors). Strict JSON rejects duplicate keys, trailing values, and
  excessive depth/nodes while preserving large-number precision; explicit and
  effective decimal exponents are limited to `-1000..1000`. Schema files are
  regular portable source paths capped at 256 KiB; the plan binds path, SHA-256,
  dialect, and validator version. External/dynamic and cross-file references
  are rejected. `Prepare` keeps runtime decisions on a private
  deep-cloned plan and indexes compiled schemas by that complete binding, so
  later mutation of the exported plan copy cannot change execution. Redirects,
  TLS, authentication-bearing requests,
  multiple services, full RFC 9535 JSONPath, and remote/cross-file schemas are
  not claimed.
- HTTP `fileExists` is an ordered assertion, evaluated immediately at its
  journey position by a trusted in-container `lstat` walk. Only normalized
  UTF-8 `/outputs` paths of at most 4,096 bytes are accepted, and a symlink in
  any component fails the assertion.
- HTTP `jsonFile` is also ordered and point-in-time. A fixed trusted helper
  walks below `/outputs` with dirfd/`O_NOFOLLOW`, requires a regular file,
  reads at most 1 MiB, and returns bounded base64/size/SHA-256. The controller
  recomputes integrity and evaluates strict JSON plus the plan-bound schema.
  Missing, symlink, directory, special, malformed, duplicate-key, oversized,
  or schema-mismatching files cannot pass; helper/TOCTOU uncertainty is
  inconclusive. Raw JSON is not persisted in assertion evidence.
- The single HTTP service requires one cleanup signal. The runner honors its
  grace period, escalates remaining workload processes to `SIGKILL`, and
  quiesces UID/GID `65532` before export. Delivered success requires
  `initialTargets >= 1`, `1 <= sent <= initialTargets`, and no remaining
  workload process. Runner-owned finalization may instead privately authorize
  an exact non-escalated no-op with `sent=0`, `remaining=0`, and a nonnegative
  initial-target count; direct helper calls still reject it. The no-op records
  `service.signal` succeeded/`alreadyExited=true` and `service.exit`
  failed/`exitedBeforeSignal=true`, then still waits for the attached execution.
  Every signal, including `kill`, requires a whole-millisecond grace period
  from 1 ms through 10 seconds. The signal is the final resolved command, and
  the cleanup deadline retains separate helper slack. The UID/GID `65533`
  helper exits or is root-quiesced before cleanup; the runner forcibly removes
  the container.
- A `service.start` lifecycle observation is `succeeded` only after readiness
  succeeds. Starting the attached process without satisfying readiness is not
  reported as service-start success.
- Linux `amd64` plans bind an explicit platform. The public schema recognizes
  `arm64`, but this built-in runtime policy has no approved `arm64` tuple.
  Source, workspace, and required file/directory inputs are read-only. Writable
  output, workload home, and temporary data share the declared engine tmpfs
  cap, with a local hard ceiling of 2 GiB.
- Workload commands are actively probed as UID/GID `65532`, with zero
  inheritable, permitted, effective, and ambient capabilities and
  `no-new-privileges`. Before export, the controller quiesces that workload
  identity, removes disposable home/temp data, validates the output tree,
  streams a fixed USTAR archive from `/bin/tar`, and safely extracts and
  atomically commits accepted files.
- Declarative CLI exit-code, stdout/stderr substring, stdout regular-expression,
  stdout-schema, HTTP response status/header/body-substring, and output-file
  existence/JSONPath/response-schema/ordered-file-schema assertions evaluated
  by the trusted controller.
- Controller-owned run storage outside the source tree. Repository-local
  verification files are not authoritative.
- Deterministic offline M3-a attestations over an authoritative historical run,
  using one canonical local Ed25519 PKCS#8 private key and either explicit
  canonical SPKI public-key trust or an independently digest-pinned canonical
  `offline-trust-policy-v1`. Policy trust evaluates only the verifier-computed
  SPKI DER key ID. The attestation does not change stored verdicts or recover
  the historical local source path; freshness remains a separate bounded
  opt-in re-observation.
- Alpha.22 retains Alpha.21's authenticated, caller-floor-qualified signed
  policy observation in one local authority-scoped monotonic record before
  signer authorization, and hardens Windows creation-time DACL handling. It
  detects only rollback/equivocation relative to surviving local state and
  leaves formal claims false, capability incomplete, and overall inconclusive.

## Trust and interpretation limits

- A result verifies one source snapshot, manifest, resolved plan, scenario,
  policy bundle, runner feature set, and execution interval. It is not proof
  that a repository is universally safe.
- Missing observer coverage produces `incomplete` or `inconclusive`; it never
  becomes a capability pass.
- The built-in backend currently reports best-effort foreground-process and
  composite filesystem-write coverage, retained-state summary event coverage
  `high` only after a complete bounded snapshot pair, and Docker
  `best-effort` port-listen coverage only for the supported single-service
  HTTP profile after every peer-observer gate succeeds. Port observation is
  `unavailable` on Podman and for unsupported profiles. Because required
  port-listen observation is still not complete, the required filesystem-write
  category remains below `high`, and other required gaps remain, a functional
  pass still has
  capability `incomplete` and overall `inconclusive`; this slice does not yet
  produce an overall `verified` result.
- On Docker only, `filesystem.engine-diff.summary` may contribute
  `best-effort` to the composite filesystem-write view after an identity-bound,
  post-quiescence/pre-repair final collection. Its CLI transcript is opaque,
  cumulatively covers changes since container creation, includes trusted and
  pre-workload activity, and excludes `/outputs` tmpfs and mounted
  source/workspace/input filesystems. A baseline result is diagnostic only.
- On Docker only, `filesystem.activity-trace.summary` may contribute
  `best-effort` aggregate notification hints after a strict, identity-bound,
  clean `READY`/`FINAL` session spanning workload execution through
  quiescence. It is unavailable on Podman and never represents operation,
  syscall, actor, or exact phase history.
- On Docker only, `port.listener-trace.summary` may contribute
  `best-effort` aggregate TCP listener hints for the supported single-service
  HTTP profile. The peer shares only the target network namespace and must
  produce a clean, identity- and isolation-bound `READY`/`FINAL` session from
  immediately before service dispatch through workload quiescence. Sampling
  can miss short-lived listeners, UDP and process attribution are unavailable,
  and no complete port-listen history or conformance claim follows.
- The resource collector does not change that overall boundary.
  `ResourceUsage=high` is validated only for the exact `alpha.4` Docker/cgroup
  tuple and a complete sample for every repeat. Resource-limit enforcement is
  evaluated separately and cannot substitute for observation.
- The authoritative verification's original evidence state remains
  `unsigned`. Alpha.13 can wrap that immutable historical result in a local
  Ed25519 DSSE attestation and verify an explicitly trusted SPKI key offline;
  this does not rewrite the original evidence field or provide a CA, identity
  federation, transparency log, timestamp, revocation, or freshness decision.
- Full filesystem-write operation history, filesystem-read, complete
  port-listen history, denied-destination, and full process-exec observation
  are not claimed by the current built-in backend. Retained-state summary
  event coverage `high` is not an
  undeclared-filesystem-write detector, and neither is the aggregate Docker
  engine-diff commitment or the Docker activity-notification summary.
- The runner does not pull images during verification. A trusted preparation
  step must approve and pre-pull one exact tuple accepted by the built-in
  runtime policy. The selected image's runtime binary and `/bin/tar` helper are
  part of the local runner trusted computing base. Digest pinning provides
  immutability, not publisher trust, provenance, or signature verification.
- The long-lived sandbox's controller-supplied idle supervisor and fixed
  initialization/finalization helpers run as root with only `DAC_OVERRIDE`,
  `FOWNER`, and `KILL` added. Repository commands cannot supply those helper
  arguments. Repository CLI commands and services run under the probed
  UID/GID `65532`; the bounded trusted HTTP helper runs as UID/GID `65533`.
  The Alpha.8 peer TCP observer is a separate UID/GID `65534` container with
  all capabilities dropped and shares only the target network namespace.
- The current snapshot profile accepts portable ASCII repository paths and
  rejects symlinks/reparse points and special files.

## Verification performed in this workspace

- Alpha.13 formal local/repro and fixed-VM gate results are not embedded in this
  source document. Only a completed evidence package that binds the final
  source, release files, exact environment, and every required result may make
  that qualification claim.
- Local/repro gate `20260731T085753Z` reported zero formatting drift and passed
  `go vet ./...`, `go test ./... -count=1`, a five-repeat shuffled
  security-focused suite, integration-tag compilation, release smoke checks,
  and an exact byte-for-byte rebuild.
- Live gate `20260731T085836Z` passed the full Go suite, Linux
  `go test -race -count=1 -v ./internal/execution`, and all 12 required Docker
  integration cases. `TestContainerPeerPortObservation` emitted one complete
  aggregate record for Node and one for Python.
- Public-schema compilation, healthy-manifest contracts, and emitted
  plan/verification/observation/assertion/error schema checks.
- The historical Alpha.8 exact Docker live record is listed below. It does not
  qualify Alpha.13; Podman port observation remains unavailable.
- Healthy and invalid manifest behavior, including stable error codes.
- Deterministic plan generation and lock drift checks.
- Authoritative blocked artifact creation when no runner exists.
- Default verify exit behavior and strict `--fail-on` behavior.
- Verification artifact JSON round-trip, report rendering, and digest tamper
  rejection.
- Forged workload verification data cannot replace an authoritative artifact.
- Exact runtime-policy rejection, workload-identity invariants, quiesce/repair/
  export/remove ordering, exact tar argv, unsafe archive rejection, controller
  disk ceilings, archive and logical byte caps, Windows path/device hazards,
  case-fold collisions, link/special-file rejection, reserved exit-status
  failure, no-commit behavior, and forced cleanup are covered by unit tests.
- The `alpha.4` Windows/Linux `amd64` snapshots were rebuilt with Go 1.26.5,
  `CGO_ENABLED=0`, and `-trimpath`. A rebuild from a different source path
  matched byte-for-byte; checksum verification, embedded-version, Linux
  ELF-header, Linux text/JSON version, and packaged-Windows text/JSON version
  checks passed. Exact artifact hashes are recorded in `docs/release.md`.
- `govulncheck` reported zero reachable and zero imported-package
  vulnerabilities. It also reported required-module-only `GO-2026-5970`; the
  analyzed code does not call the vulnerable symbols.
- The Linux race run used Go 1.26.5, GCC 13.3.0, and passed. It does not claim a
  Windows race result.

## Live-container release gates

### Alpha.15 qualification status

Status: **not claimed by this source document**.

A final Alpha.15 record must bind the exact SPDX-attachment source, resolved
plan version 4 and evidence selection, CLI driver `0.2.0`, bounded attestation implementation, release
artifacts, exact runtime/engine/VM tuple, complete local and live results,
residue comparisons, and cleanup. A partial, missing, failed, skipped, or
source-mismatched package qualifies nothing.

### Historical qualification status

Earlier qualified source and evidence packages remain historical. Alpha.15
does not reinterpret, repackage, or broaden those results, and they do not
qualify this changed source.

### Historical Alpha.10 qualification status

Status: **not claimed by this source document**. No Alpha.10 record is promoted
or retroactively signed by Alpha.11.

### Historical Alpha.9 qualification status

Local/repro record `20260731T102030Z` and fixed-VM live record
`20260731T102115Z` bind only the exact Alpha.9 source and evidence package
`repopass-v0.1.0-alpha.9-evidence-20260731T102115Z`. They do not qualify
Alpha.10, Alpha.11, Alpha.12, or Alpha.13.

### Historical Alpha.8 qualification status

Live gate `20260731T085836Z` passed 19/19 ordered guest gates and 12/12 required
cases on Docker client/server 29.1.3 in an isolated Ubuntu 24.04.4 LTS, kernel
6.8.0-134-generic, Linux `amd64`, cgroup-v2 QEMU VM. Both exact approved images
matched. Node and Python peer listener sessions verified identity, namespace
isolation, listener open/close lifecycle, workload quiescence, peer security
identity, and peer removal. Before/after container, network, volume, source,
and host-listener records matched; guest cleanup and final QEMU/seed shutdown
passed without force. This exact-tuple record is unsigned, does not qualify
Podman/rootless/other tuples, and leaves capability `incomplete`, overall
`inconclusive`, M1 incomplete, and M2 incomplete.

### Historical Alpha.7 qualification status

This in-tree status document does not claim an `alpha.7` live pass. A separate
qualification package may do so only when it binds the exact source manifest,
gate ID, environment tuple, and every required result, including the
Docker-only activity-trace case. Historical Alpha.6 and earlier evidence
cannot qualify the changed `alpha.7` source and observer behavior.

### Historical Alpha.5 qualification target

Record `20260730T202049Z` is a qualification target, not an embedded pass
claim. Alpha.5 is qualified only when the external evidence package for that
record reports gate exit `0`, contains every required source, schema, unit,
integration, live-container, cleanup, residue, and reproducible-build result,
and binds the exact Docker/VM/kernel/Linux `amd64`/approved-image tuple. A
missing package, nonzero exit, skipped required case, or tuple mismatch
qualifies nothing.

Even when qualified, the record can establish only bounded `/outputs`
retained-state summary event coverage `high` and composite filesystem-write coverage
`best-effort`. Required filesystem-write remains incomplete; capability
remains `incomplete`, overall remains `inconclusive`, M1 and M2 remain
incomplete, and no Podman, rootless, other-version, other-kernel, other-image,
or `arm64` result follows.

### Alpha.4 record

Status: **passed for the exact recorded alpha.4 environment**.

- Record: `20260730T173121Z`; gate exit `0`; all 18 ordered gate steps and all
  ten required cases passed (`10/10`).
- The tenth case, `TestContainerResourceUsageObservation`, proved complete
  resource fields and `ResourceUsage=high` on Docker client/server 29.1.3,
  isolated Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic`, Linux `amd64`,
  cgroup v2, and both pinned approved images.
- Gated source snapshot SHA-256:
  `4492de55cf8c1c57ccdda8fb0f0be4bd2512a7a2dc393ef0e419e620d2d5b4d6`.
  Source-manifest file SHA-256:
  `0f1593e634a3295ed329dafc977ff1b84e0c1eb226b8e89b073e7fe2a74ead78`.
  Evidence-inventory file SHA-256:
  `ffd724e50414c841ebe6e7a7bdd39d8c40102522130039c9e62cf95c83e601c7`.
- Source and host-listener manifests were unchanged. Before/after all-container
  inventories were header-only, and no host-publish residue remained.
- Local gate `20260730T173051Z` passed. Its independent rebuild matched:
  `7a40d9cad99f40615df1d011e61ac36ada8ca209b9e3f858bed72d1064dda81d`
  (`repopass-linux-amd64`),
  `9675ea553a1d954958d8d463fb019bacf954e156587e7331e69b8a6ae5fc8420`
  (`repopass-windows-amd64.exe`), and
  `fe84a2942b0d3b3ff51413fe125f11885c33d34c47483275b603fd62be263678`
  (`SHA256SUMS`).
- This is not a Podman, other-Docker-version, other-kernel, rootless, or
  `arm64` result. Other observer gaps remain, so M1 is incomplete, healthy
  runs remain capability `incomplete` and overall `inconclusive`, and evidence
  remains unsigned. The inventory hash does not claim a packaged evidence
  bundle.

### Alpha.3 record

Status: **passed for the exact recorded alpha.3 environment**.

- Record: `20260730T150346Z`; gate exit `0`; source archive SHA-256
  `f5073b9378dbaa792938267ac10a24c4c3a26585402ad61993168003ace3731e`;
  154 source-manifest entries.
- Guest: isolated Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic`, Linux
  `amd64` under QEMU; Go 1.26.5.
- Backend: Docker client 29.1.3 API 1.52 and Docker Engine server 29.1.3
  API 1.52 (minimum 1.44), both commit `29.1.3-0ubuntu3~24.04.2`.
- Images: the exact Node and Python references in `docs/release.md`; both
  inspected with exact repository-digest matches on `linux/amd64`.
- Gate steps: all 18 recorded steps exited `0`, including validator self-test,
  `go vet ./...`, `go test -count=1 ./...`, binary/version smoke, image
  inspection, integration execution, residue checks, and source integrity.
- Container cases: `healthy_node_cli`,
  `healthy_python_cli_with_persisted_setup_output`, `healthy_python_http`,
  `healthy_node_http`, `workload_forged_verification_is_ignored`,
  `term_resistant_http_child_is_removed`, `service_exits_before_readiness`,
  `service_never_becomes_ready`, and
  `TestContainerDiskQuotaExpectedDenial` all passed (`9/9`).
- Source and host-listener manifests were unchanged. The before/after
  all-container inventories were header-only, and no host-publish residue
  remained.
- Final binaries were rebuilt from a different source path byte-for-byte
  identically. SHA-256:
  `85d3460277d43db4847a55663a3e0cb0d199cd5f9f354f160430116976ddd62e`
  (`repopass-linux-amd64`) and
  `89abca38fa79c7f3fdc352fe70601c4b9d97a9d65c0879efdfbc57e00cc51773`
  (`repopass-windows-amd64.exe`).

This is a compatibility record only for that exact Docker/VM/image tuple.
Podman, other Docker versions, and `arm64` remain unclaimed. M1 remains
incomplete; observer coverage remains capability `incomplete`, so successful
fixture journeys remain overall `inconclusive`, not overall `verified`.
Evidence remains `unsigned`.

### Alpha.2 record

Status: **passed for the exact recorded alpha.2 environment**.

- Record: `20260730T102841Z`; gate exit `0`; source archive SHA-256
  `893d07fc8711799b68dfe0aabede71cf7154b6c0b13560313d5f0fd96b9eeed9`.
- Guest: isolated Ubuntu 24.04.4 LTS, kernel `6.8.0-134-generic`, Linux
  `amd64` under QEMU; Go 1.26.5.
- Backend: Docker client 29.1.3 API 1.52 and Docker Engine server 29.1.3
  API 1.52 (minimum 1.44), both commit `29.1.3-0ubuntu3~24.04.2`.
- Images: the exact Node and Python references in `docs/release.md`; both
  inspected with exact repository-digest matches on `linux/amd64`.
- Gate steps: all 18 recorded steps exited `0`, including validator self-test,
  `go vet ./...`, `go test -count=1 ./...`, binary/version smoke, image
  inspection, integration execution, residue checks, and source integrity.
- Container cases: `healthy_node_cli`,
  `healthy_python_cli_with_persisted_setup_output`, `healthy_python_http`,
  `healthy_node_http`, `workload_forged_verification_is_ignored`,
  `term_resistant_http_child_is_removed`, `service_exits_before_readiness`,
  `service_never_becomes_ready`, and
  `TestContainerDiskQuotaExpectedDenial` all passed (`9/9`).
- Source and host-listener manifests were unchanged. The before/after
  all-container inventories were header-only, and no host-publish residue
  remained.
- Final binaries were rebuilt from a different source path byte-for-byte
  identically. SHA-256:
  `d27691b4fb7397ee9bac8a18b4bf03a6cb691d5ef4e3e7c3989bc7e6e56bcc8e`
  (`repopass-linux-amd64`) and
  `637fee295391bbc8e6065e5a24f29f8b9fd77a81c6a17dad4a73e3b7a1428716`
  (`repopass-windows-amd64.exe`).

This is a compatibility record only for that exact Docker/VM/image tuple.
Podman, other Docker versions, and `arm64` remain unclaimed. M1 remains
incomplete; observer coverage remains capability `incomplete`, so successful
fixture journeys remain overall `inconclusive`, not overall `verified`.
Evidence remains `unsigned`.

### Historical alpha.1 record

Status: **passed for the exact recorded alpha.1 environment**.

- Record: `20260730T074535Z`; gate exit `0`; source archive SHA-256
  `8a6abeac48f5c1200bea4d78763f030f1809532732510dcd30e8197e8a02fdb2`.
- Host/guest: Windows 11 Pro build 26200, QEMU 11.0.3 with WHPX, Ubuntu
  24.04.4 LTS kernel `6.8.0-134-generic`, Linux `amd64`, Go 1.26.5.
- Backend: Docker client 29.1.3 API 1.52 and Docker Engine server 29.1.3
  API 1.52 (minimum 1.44), both commit `29.1.3-0ubuntu3~24.04.2`.
- Images: the exact Node and Python references in `docs/release.md`; both
  inspected with exact repository-digest matches on `linux/amd64`.
- Source gates: validator self-test, `go vet ./...`, and
  `go test -count=1 ./...` exited `0`.
- Container cases: Node CLI, Python CLI with persisted setup output,
  forged-result/background-mutator quiescence, and expected `ENOSPC` disk
  enforcement all passed (`4/4`).
- Artifact smoke: both `dist/SHA256SUMS` entries verified, and the Linux binary
  returned `0.1.0-alpha.1` in text and JSON modes.
- Harness cleanup: `guest_cleanup_verified=yes`.

This is a compatibility record only for the exact environment above. Podman,
other Docker versions, and `arm64` remain unclaimed. Observer coverage remains
capability `incomplete`, so successful fixture journeys remain overall
`inconclusive`, not overall `verified`.
