# Changelog

## 0.1.0-alpha.33 - 2026-08-04

Alpha.33 adds a bounded canonical two-through-eight-hop transition chain for
the authority that signs the offline attestation trust policy. Every existing
Alpha.32 transition is authenticated in order from one explicit caller root;
adjacency, global key uniqueness, cycle rejection, strictly increasing
generations, the explicit terminal authority, and the caller floor are bound
before the terminal policy is read. Root, intermediate, and terminal
authorities cannot also act as evidence signers.

The full CLI adds an exact-three no-overwrite chain assembler; the portable
verifier shares chain verification but rejects the producer before
command-specific I/O. Optional chain+policy state uses a separate root-scoped
atomic namespace and makes no cross-mode rollback claim. Direct and one-hop
modes remain supported. Root discovery, compromise recovery, trusted time,
identity, transparency, historical revocation, and remote key lifecycle stay
out of scope; identity/time remain `none`, `formalClaim=false`, capability
`incomplete`, and overall `inconclusive`.

## 0.1.0-alpha.32 - 2026-08-04

Alpha.32 adds bounded one-hop continuity for the authority that signs the
offline attestation trust policy. It introduces a purpose-separated canonical
DSSE transition, explicit old-root and terminal-key verification, strict
generation floors, exact-three full-CLI production, and a single root-scoped
atomic transition+policy state record. Direct signed-policy verification stays
supported; the portable verifier shares rotation verification but rejects the
producer before command-specific I/O and packages no trust sidecars.

It also closes a consumer-side role-separation gap by rejecting a signed policy
that lists its own authority as an evidence signer. Multi-hop policy-authority
chains, root discovery, compromise recovery, identity, trusted time,
transparency, historical revocation, and remote key custody/publication remain
outside scope. Identity/time stay `none`; `formalClaim=false`, capability
`incomplete`, overall `inconclusive`.

## 0.1.0-alpha.31 - 2026-08-04

Alpha.31 adds a bounded full-CLI producer for the existing canonical
`offline-trust-policy-v2` contract. It derives globally sorted unique
`spki-sha256` identities from 1..32 canonical Ed25519 signer SPKIs, supports
only explicit trusted/revoked decisions, enforces authority/signer role
separation, emits one purpose-separated Ed25519 DSSE signature, self-verifies,
rechecks signer inputs, and atomically publishes exactly the envelope and
authority-SPKI companion into a new directory. The portable verifier remains
verification-only and rejects the producer before command-specific I/O.

This is bounded local authoring, not key generation/custody, authority
lifecycle, remote publication, trust bootstrap, identity, trusted time,
transparency, KMS/HSM, or a capability/overall upgrade. The authority companion
is never implicitly trusted; `identityAttestation=none`,
`timeAttestation=none`, `formalClaim=false`, capability remains `incomplete`,
and overall remains `inconclusive`.

## 0.1.0-alpha.30 - 2026-08-04

Alpha.30 adds an opt-in canonical offline authority-transition chain for
release-index verification. The bounded transport contains 2..8 ordered,
old-root-authorized transition hops; verification enforces canonical encoding,
exact key adjacency, global key uniqueness, cycle rejection, strictly
increasing generations, an explicit terminal authority binding, and optional
root-anchored controller-local chain state. It adds the chain assembler and
chain verification mode while retaining direct and Alpha.29 one-hop modes.
The release remains exact-seven payload files plus exact-seven public sidecars.
No publisher identity, trusted time, transparency, root discovery, remote
publication, or distributed/tamper-resistant state is claimed.

## 0.1.0-alpha.29 - 2026-08-03

Alpha.29 adds an opt-in, offline, one-hop `release-authority-transition-v1`
contract for rotating the authority that signs `release-key-policy-v1`. A
transition is authenticated only by an explicit caller-supplied old root and
binds one distinct next policy authority; direct Alpha.28 verification remains
compatible. Rotation does not make a companion, adjacent, or bundled key a
trust anchor.

The portable verifier kit remains deterministic and self-contained, but now
declares the explicit transition verification capability. It carries no trust
root, policy, release-index or transition sidecar, evidence, or private key.
The increment adds no publisher identity, trusted time, transparency, remote
publication, root discovery, or tamper-resistant/distributed state claim.
`formalClaim=false`, capability remains `incomplete`, and overall remains
`inconclusive`.

## 0.1.0-alpha.28 - 2026-08-03

Alpha.28 adds the purpose-separated external `release-index-v1` and
`release-key-policy-v1` contracts, each with a dedicated exact-one-signature
Ed25519 DSSE envelope. Release-index acceptance is relative to an explicit
caller-supplied authority SPKI, never an adjacent or bundled key. The signed
index inventories exactly one artifact root; its sidecars, signer key, policy,
authority root, and local state remain outside that root.

The portable verifier additionally declares `verify-release-index`, while
continuing to package no root/private key, index sidecar, policy, or evidence.
This authenticates cryptographic authorization only, not publisher identity or
trusted time. `formalClaim=false`, capability remains `incomplete`, and overall
remains `inconclusive`; authority-root lifecycle, automatic discovery,
historical revocation, remote publication, and complete M1/M2/M3 are deferred.
Artifact processing is bounded to 128 MiB per file, 512 MiB per exact set, and
64 KiB for `SHA256SUMS`. Optional policy/release state detects rollback or
same-generation equivocation only relative to surviving local records;
deletion, restore, copy, rename, or fork can reset or fork history.
Exact artifact verification performs two complete stable scans of a quiescent,
operator-controlled root; it does not claim an atomic snapshot or immunity to
a hostile concurrent writer.
Portable-kit input executables are now capped at 32 MiB, bounding the existing
multi-copy canonical build/validation memory path.

## 0.1.0-alpha.27 - 2026-08-03

Alpha.27 adds a verifier-only `repopass-verify` entry point and deterministic
Linux/amd64 and Windows/amd64 offline-verifier release kits. The reduced entry
point accepts only help, version, and the existing `verify-attestation`
contract; verification parsing, validation ordering, output, exit semantics,
cryptography, privacy evaluation, trust decisions, and optional currentness
remain shared with the full CLI.

Each canonical USTAR kit has an exact four-member inventory and a canonical
manifest that binds its target, executable bytes, product version,
capabilities, and trust boundary. Kits carry no evidence, private key, policy,
or trust root. An embedded or adjacent evidence key still identifies only a
signing key; acceptance requires independently supplied trust material under
the existing rules. This increment does not add Sigstore/OIDC, trusted time,
publisher identity, arm64/macOS support, or complete M3, and it never upgrades
`incomplete`, `inconclusive`, or `formalClaim=false` evidence.

## 0.1.0-alpha.26 - 2026-08-03

Historical Alpha.26 hardens fixed-VM qualification evidence publication without changing
the Alpha.25 runtime observer or verdict semantics. Raw Docker info/version/
inspect, image and runtime logs, test JSONL, race output, OS output, container/
network/image/volume/listener snapshots, guest console transcripts, host
listener snapshots, and process IDs are private bounded inputs and are not
public package members.

The public package uses an exact inventory of canonical typed environment,
race, guest/host residue, verdict, summary, source-binding, matrix, identity,
and one-line terminal receipts. Every public slot has an explicit parser or
strict record grammar. The builder/verifier reject raw or renamed unstructured
content, duplicate/unknown keys, wrong types, noncanonical encoding/numbers,
path and link aliases, inventory drift, and mutation even after recomputing the
manifest, receipt, and its then-unsigned external index.

This reduces evidence-substitution and accidental-publication risk; it is not
universal secret detection, trusted provenance, identity, trusted time, or M3
completion. That historical Alpha.26 external anchor remains unsigned and is
not retroactively upgraded by Alpha.29. Healthy capability remains
`incomplete`, overall remains `inconclusive`, and `formalClaim=false`.

## 0.1.0-alpha.25 - 2026-08-03

Alpha.25 makes the existing Docker peer TCP-listener slice a bounded declared-
versus-observed aggregate comparison for its exact Docker/Linux/amd64,
approved Node-or-Python, one-service HTTP profile. Public
`port.listener-trace.summary` details contain fixed non-sensitive observer
metadata plus `comparisonResult` and `evidenceBasis=aggregate-only`; complete
observations add exactly four endpoint-related counts for baseline, declared,
sampled, and undeclared. `not-tested` contains no comparison counts. A positive comparison emits at most one aggregate
`UNDECLARED_PORT_LISTEN` per repeat. `PortObserverVersion=0.3.0` is bound into
the plan digest, so prior `0.2.0` locks drift rather than inheriting it.

The same increment removes repository-controlled HTTP `bodyContains` strings
from public assertion results. Matching still uses the sealed resolved plan;
public evidence contains only fixed configured/value-not-published metadata
and typed match/truncation booleans. `minimal-public-v1alpha2` adds only exact-
path boolean and lower-case SHA-256 response-schema exemptions; raw or wrong-
typed body fields remain blocked. The changed policy and derived projection
have new frozen ruleset digests.

This is still sampling of Linux TCP listener tables, not an absence proof or
complete port history. Short-lived listeners, UDP/Unix sockets, outbound or
NAT traffic, raw endpoint identity, process attribution, and baseline history
outside the sealed window remain unavailable. Functional success remains
separate; healthy runs are capability `incomplete`, overall `inconclusive`,
and `formalClaim=false`. This source change is not a formal qualification or
compatibility claim.

## 0.1.0-alpha.24 - 2026-08-02

Alpha.24 adds a bounded, aggregate-only positive nonconformance detector for
the three retained-state blind spots: transient create/delete, write-then-
restore, and a mutation authorized only by another controller-dispatch phase.
It is available only for the exact Docker/Linux/pinned-Python/CLI foreground
tuple. The trusted helper receives only the active phase's existing
`filesystem.write` rules, acknowledges that phase before dispatch, and emits
no paths, rule text, content, tokens, cookies, or raw transcript.

This is not complete filesystem operation history. Node, Podman, non-Linux or
non-Python runtimes, HTTP/services, signal workflows, and background work are
`not-tested`/`unavailable`; queue overflow, watch races, identity, transport,
phase, separated-snapshot quiescence, unconfirmed dispatch, and bound failures
fail closed without partial public counts or a positive finding. Runtime
overflow and gap cases use an exact minimal typed failure terminal, bound to
the helper session/adapter and exit `1`, with no success-shaped aggregate.
A complete unmatched notification emits at most one
aggregate `UNDECLARED_FILESYSTEM_WRITE` per repeat; healthy runs remain
capability `incomplete`, overall `inconclusive`, and `formalClaim=false`.
Filesystem observer version `0.6.0` is plan-digest-bound. This increment does
not complete M1, M2, rootless qualification, or a complete operation observer.

## 0.1.0-alpha.23 - 2026-08-02

Alpha.23 adds a bounded declared-versus-observed comparison for the existing
`/outputs` retained-state delta. After the existing identity, quiescence,
snapshot, and change-count gates succeed, every create/delete/modify/type-change
delta path is compared with the `filesystem.write` union of phases whose
runtime dispatch actually starts. An unmatched retained mutation adds one
aggregate
`UNDECLARED_FILESYSTEM_WRITE`, making capability and overall nonconforming
without rewriting successful functional assertions or cleanup.

Public evidence remains aggregate-only and contains no raw path or content.
This final-state slice cannot detect transient or write-then-restore activity,
wrong-phase access covered by another executed phase, or activity outside
`/outputs`; it is not operation history and does not complete M1 or M2.
Healthy runs remain capability `incomplete`, overall `inconclusive`, and
`formal_claim=false`. Filesystem observer version `0.5.0` is plan-digest-bound;
locks carrying `0.4.0` drift rather than inheriting the new comparison.

## 0.1.0-alpha.22 - 2026-08-02

Alpha.22 hardens Windows creation of the opt-in local signed-policy state
introduced in Alpha.21. New state directories and per-authority lock files are
created with their final protected private DACL in the same kernel operation
that first makes each object visible, using explicit `SECURITY_ATTRIBUTES`,
`CreateDirectory`, and exclusive `CreateFile(..., CREATE_NEW, ...)`. Existing
objects remain validation-only and are never retroactively trusted or repaired.

This narrows the Windows creation-time ACL exposure window only. It does not
add a CLI, schema, report field, trust decision, tamper-resistant or distributed
state, trusted time, historical revocation, authority lifecycle, KMS/HSM, or an
overall verification claim. Capability remains `incomplete`, overall remains
`inconclusive`, and `formal_claim=false` remains mandatory. Alpha.21 and earlier
evidence remain historical and bind only their exact source.

## 0.1.0-alpha.21 - 2026-08-02

Alpha.21 adds one opt-in, controller-local monotonic guard to the Alpha.20
authenticated `offline-trust-policy-v2` verifier. It remains verifier-only and
does not add policy authoring, signing, authority private-key management, or
authority lifecycle.

### Available in this alpha

- The exact Alpha.20 signed-policy triple may additionally include exactly one
  valueless `--persist-trust-policy-state`. It is rejected before bundle I/O
  when duplicated, assigned a value, malformed, partial, or mixed with legacy
  trust modes. Stateless signed-policy and all legacy modes remain unchanged.
- Stateful mode uses the global `--data-dir`, or the controller default, and
  stores one canonical authority-scoped record and lock below
  `trust-policy-state/v1`. It observes the authenticated payload digest and
  generation after bundle/policy authentication and the caller floor, but
  before signer authorization. A rejected `revoked` or `not-listed` signer can
  therefore initialize or advance state.
- The state guard reports `initialized`, `matched`, `advanced`,
  `rollback-rejected`, `equivocation-rejected`, or `unavailable`, with its
  stored generation only when valid state was read or committed, as
  `trustPolicyStateEvaluation` and `trustPolicyStateGeneration`. Rollback,
  equivocation, and unavailable state use the fixed untrusted reasons
  `state-generation-rollback`, `state-generation-equivocation`, and
  `state-unavailable`, and expose no state path, lock, stored digest, or
  parser/OS detail. Alpha.21 fields are omitted in stateless and legacy reports.

This local record is not tamper-resistant or distributed trust, trusted time or
expiry, historical revocation, authority rotation/revocation/lifecycle,
KMS/HSM, Sigstore/OIDC/transparency, hosted trust, complete M3, capability
conformance, or overall verification. Deleting, restoring, copying, or
forking the selected data directory can reset or fork its history. Capability
remains `incomplete`, overall remains `inconclusive`, and Alpha.20 evidence is
historical; `formal_claim=false` remains mandatory.

## 0.1.0-alpha.20 - 2026-08-02

Alpha.20 adds one verifier-only authenticated offline trust-policy floor. It
does not add policy authoring, a policy-signing command, authority private-key
management, or authority-key lifecycle support.

### Available in this alpha

- `verify-attestation` accepts exactly one three-flag signed-policy mode:
  `--trust-policy-envelope FILE`, `--trust-policy-authority-key FILE`, and
  `--minimum-trust-policy-generation UINT`. It is mutually exclusive with
  `--trust-key` and the Alpha.19 policy/digest pair; malformed, duplicate,
  partial, near-prefix, and case-alias forms fail before bundle I/O.
- The verifier validates the complete bundle before it reads the authority key
  or signed policy, then verifies one canonical DSSE envelope with payload type
  `application/vnd.repopass.offline-trust-policy.v2+json`. The policy payload
  is canonical `offline-trust-policy-v2`, with a signed safe-integer generation
  in `1..9007199254740991`.
- Acceptance authenticates the policy only relative to the caller-supplied
  canonical Ed25519 authority SPKI and enforces that invocation's caller floor.
  Reports expose only fixed policy/envelope digests, authority key ID,
  generation, caller floor, signature validity, and a fixed decision reason.

This is not persistent anti-rollback, trusted time/expiry, same-generation
equivocation prevention, authority rotation/revocation/lifecycle, historical
revocation, KMS/HSM, Sigstore/OIDC/transparency, hosted trust, complete M3,
capability conformance, or overall verification. Capability remains
`incomplete` and overall remains `inconclusive`. Alpha.20 qualification needs
exact source-bound evidence; Alpha.19 evidence is historical.

## 0.1.0-alpha.19 - 2026-08-02

Alpha.19 adds one bounded, digest-pinned offline signer-authorization policy
without changing the signed bundle, signer, or historical verdict model.

### Available in this alpha

- `verify-attestation` accepts exactly one paired `--trust-policy FILE` and
  `--expect-trust-policy-digest sha256:<64-lowercase-hex>` mode, mutually
  exclusive with `--trust-key`. Strict flag errors precede bundle I/O.
- The verifier completes any supplied bundle pin plus canonical
  archive/content, Ed25519/DSSE, SPDX, and privacy checks before policy I/O,
  then checks the digest of the
  exact raw policy bytes before parsing or authorization.
- `offline-trust-policy-v1` is canonical JSON bounded to 64 KiB with 1--32
  strictly sorted unique `spki-sha256` Ed25519 key IDs. `trusted` accepts;
  `revoked` and `not-listed` reject. Only the key ID recomputed from canonical
  SPKI DER is evaluated.
- Policy reports add optional `trustBasis`, `trustPolicyDigest`, and
  `trustReason`. They are omitted from legacy no-trust and `--trust-key`
  output. Accepted policy trust may authorize the existing bounded freshness
  route.

The policy is unsigned operator-selected input. The digest pin provides byte
integrity, not policy authenticity, anti-rollback, trusted time, historical
revocation status, external signer identity, KMS/HSM, Sigstore/OIDC, or
transparency. Alpha.19 does not complete M3 or upgrade capability `incomplete`
or overall `inconclusive`. Formal Alpha.19 release qualification requires its
own source-bound evidence; sealed Alpha.18 evidence remains historical.

## 0.1.0-alpha.18 - 2026-08-01

Alpha.18 adds one deliberately narrow, repository-derived SPDX path for
portable evidence. It is selected only by exactly one
`attest --derive-spdx --current-manifest FILE`; it is mutually exclusive with
caller-supplied `--spdx FILE`.

### Available in this alpha

- Derivation is static and command-free. It accepts only the frozen local
  Node profile: the root `package.json` and a lockfile-version-3
  `package-lock.json`, exact supported dependency specifications, and the
  lockfile graph needed by that profile. It does not invoke npm, Node, Git, or
  repository commands.
- Two matching source snapshots are required before derivation and a third
  matching snapshot before signing. The resulting canonical SPDX and its
  provenance are bound into the distinct version-2 exact USTAR model.
- Replay may re-observe this derived profile only after explicit SPKI trust and
  a complete raw-bundle digest pin. Its separate SBOM-currentness result is
  `fresh`, `stale`, or `unknown`; it never changes the signed historical
  verification verdict.

The lockfile `integrity` value is checked only for the accepted checksum shape;
it is not verified against a registry or network source. This is not general
npm compatibility, package-manager execution, registry provenance, dependency
completeness, SBOM truth, license/vulnerability analysis, or a claim that all
packages are discovered. Capability remains `incomplete` and overall remains
`inconclusive`.

Sealed Alpha.18 qualification evidence applies only to its exact historical
source and does not qualify Alpha.19. Focused development checks do not
constitute a verified Alpha.19 release.

## 0.1.0-alpha.17 - 2026-08-01

Alpha.17 is a bounded dependency remediation with no product-semantic change.
It replaces the required indirect `golang.org/x/text@v0.14.0` module with
`v0.39.0`, the minimum reviewed fixed release for `GO-2026-5970` /
`CVE-2026-56852`. Alpha.16 had no reachable-symbol or imported-package finding
for this advisory; the affected version was present only as a required module
through `internal/structuredjson -> jsonschema/v6 -> x/text/language`.

### Available in this alpha

- Public module authentication remains enabled, and CI runs `go mod download`,
  `go mod verify`, and `go mod tidy -diff` before vulnerability analysis.
- The pinned official `govulncheck v1.6.0` scanner fails the Go job on either a
  finding in the `cmd/repopass` application module graph or a reachable source
  or test symbol finding.
- The module scan intentionally has no package pattern and is stricter than the
  source/test symbol scan. Human-readable exit status is the pass gate;
  structured JSON/SARIF output is not used as a verdict.
- Upstream graph-only consequences are exact: `x/mod` moves from `v0.8.0` to
  `v0.37.0`, `x/tools` moves from `v0.6.0` to `v0.47.0`, and
  `x/sync@v0.21.0` is added. Other repository-declared requirements remain at
  their Alpha.16 versions; qualification must prove those three tool modules
  are absent from both final product binaries.
- CLI flags and output, manifests, plans, execution, attestation, SPDX,
  privacy, freshness, cleanup, error codes, and verdict schemas are unchanged.

A successful gate proves only the selected `x/text@v0.39.0` graph and scanner
results against the database observed by that exact run. It is not future
vulnerability absence, dependency completeness, an SBOM, license safety,
exploitability analysis, all-build-tag reachability, complete M1/M2/M3,
capability conformance, or overall verification. Capability remains
`incomplete` and overall remains `inconclusive`.

## 0.1.0-alpha.16 - 2026-08-01

Alpha.16 adds one opt-in, bounded local freshness re-observation to trusted,
raw-digest-pinned attestation replay. It does not rerun the historical scenario
or upgrade any signed verdict.

### Available in this alpha

- `verify-attestation --current-manifest FILE` requires exactly one explicit
  trust key and one canonical complete-bundle digest pin before any current
  source or runner access.
- Two matching bounded source snapshots precede source comparison or plan
  resolution; a third matching snapshot is required before policy, plan, or
  runner results are accepted.
- The report adds deterministic `current`, `stale`, or `unknown` evaluation,
  four ordered source/policy/plan/runner checks, and fixed reason vocabulary.
  Stable drift emits `EVIDENCE_STALE`; observation uncertainty uses the
  existing source, plan, runner, or cancellation code and is never called
  stale.
- Runner comparison uses only the signed backend and the finite
  `runner-stable-v1` projection: backend, controller OS, workload OS, rootless
  mode, and engine version.
- Without the opt-in flag, Alpha.15 replay output and
  `freshnessEvaluation: "not-evaluated"` remain unchanged.

This is a point-in-time local identity comparison, not scenario re-execution,
elapsed-age validation, hostile namespace-race immunity, signer revocation or
transparency, Git/registry provenance, complete runner identity, observer
re-validation, SBOM currentness, capability conformance, overall verification,
or complete M3.

## 0.1.0-alpha.15 - 2026-08-01

Alpha.15 implements one bounded caller-supplied SPDX attachment increment for
offline portable evidence. It does not generate an SBOM, discover dependencies,
evaluate licenses or vulnerabilities, prove attachment correctness or
completeness, establish producer identity, evaluate freshness, or complete M3.

### Available in this alpha

- Resolved-plan schema version `"4"` requires and digest-binds the exact
  `minimal-public` evidence selection. It accepts the existing two-item include
  set or that exact set plus `sbom`; plan locks v1, v2, and v3 remain historical
  and fail current checking/execution.
- `attest --spdx FILE` is occurrence-aware and must match the sealed selection.
  The reader rejects final/parent links and Windows reparse/device/UNC/ADS
  paths, binds the opened regular-file handle to path identity, and requires
  two identical bounded reads with stable metadata.
- A strict 1 MiB SPDX 2.3 JSON subset is decoded without duplicate keys,
  trailing data, BOM, invalid UTF-8, excessive depth/nodes, unknown fields, or
  unbounded identifiers/strings. Canonical JSON is the signed derivative; no
  raw-input digest claim is made.
- The selected model is an exact deterministic six-member USTAR with
  `payload/sbom.spdx.json`. Manifest, in-toto predicate, DSSE signature, and
  public `sbomPresent`/`sbomFormat`/`sbomDigest` metadata bind that derivative.
  The same schema-4 no-SBOM result/key remains an exact five-member model.
- Offline verification selects the model from the raw member-name set, checks
  canonical structure and all protected bindings before signature, validates
  the strict SPDX profile, and applies `minimal-public-v1alpha1` before optional
  trust-key access. Direct tampering remains `ATTESTATION_INVALID`; a correctly
  re-signed privacy-unsafe attachment is `EVIDENCE_PRIVACY_BLOCKED`.
- A repository-owned executable Node fixture seals `sbom` selection and carries
  a synthetic public SPDX input for unit, integration, and fixed-VM paths.

The attachment never changes the authoritative functional, capability,
reproducibility, cleanup, evidence, freshness, or overall verdict. Capability
may remain `incomplete` and overall `inconclusive`; no broader SPDX 2.3,
backend, platform, trust, or milestone compatibility is claimed.

## 0.1.0-alpha.14 - 2026-08-01

Alpha.14 implements only the bounded M3-c `minimal-public` privacy gate. It
does not complete M3, redact authoritative evidence, establish anonymity, or
upgrade capability or overall verdicts.

### Available in this alpha

- A frozen `minimal-public-v1alpha1` descriptor and SHA-256 fingerprint bind
  deterministic limits, pattern revision, rule order, and entropy thresholds.
- CLI and `Build` block before private-key use/signing/publication. Rejection
  is non-echoing `EVIDENCE_PRIVACY_BLOCKED` (high, exit 7) and publishes no
  bundle or companion.
- Replay evaluates only after canonical protected-content and Ed25519 validity,
  but before optional trust-key I/O. Tampering remains `ATTESTATION_INVALID`.
- Success reports exact profile, policy, ruleset digest, and `passed`. Bundle,
  predicate, and schema versions remain unchanged.
- Output export, controller-copy cleanup, and resource-usage producers no
  longer publish controller paths or immutable container IDs.

The policy is not universal secret/PII discovery, redaction, unlinkability,
encoded/encrypted-secret detection, raw-log cleanup, or remote-publication
safety. Exact UTC timestamps and opaque IDs remain public. Freshness, external
identity, Sigstore/OIDC, SBOM, hosted trust, and full M3 remain incomplete;
capability stays `incomplete` and overall stays `inconclusive`.

## 0.1.0-alpha.13 - 2026-08-01

Alpha.13 implements only the bounded M3-b portable-replay increment. It does
not complete M3, establish an external signer identity, evaluate freshness, or
upgrade any original verdict.

### Available in this alpha

- `attest` accepts optional `--public-key-out <new-public-spki.pem>` and
  publishes the exact canonical Ed25519 SPKI PEM for the signing key. JSON and
  text report lowercase SHA-256 digests over the complete raw bundle and the
  canonical PEM companion. The existing signer key ID remains SHA-256 over
  canonical SPKI DER and is intentionally separate.
- Bundle and companion outputs are prevalidated as new, distinct, isolated
  paths and use bounded restrictive same-directory no-replace publication.
  Validation failure publishes neither. If companion publication succeeds and
  later bundle publication fails, only the complete companion may remain and
  structured error details record that state.
- `verify-attestation` accepts optional
  `--expect-bundle-digest sha256:<64 lowercase hex>`. Malformed syntax is
  `MANIFEST_INVALID`; mismatch is `EVIDENCE_DIGEST_MISMATCH` before optional
  trust-key access. A tampered bundle accompanied by its recomputed transport
  digest still reaches canonical/signature validation and is
  `ATTESTATION_INVALID`.
- Verification reports the computed complete-bundle and canonical-PEM
  digests. A digest match, embedded key, companion, or key ID does not confer
  trust; only explicit canonical `--trust-key` equality is accepted.

### Interpretation and qualification status

- This source document records no completed Alpha.13 local/repro or fixed-VM
  qualification. Earlier source-bound evidence does not qualify this changed
  source.
- Freshness re-observation, maintainer/CA identity, transparency, revocation,
  Sigstore/OIDC, KMS/HSM, SBOM, hosted trust, and full M3 remain unimplemented.
  Capability remains `incomplete` and overall remains `inconclusive`.

## 0.1.0-alpha.12 - 2026-08-01

Alpha.12 fixes one attached-service cleanup time-of-check/time-of-use race. It
does not change schemas or error codes, complete a milestone, expand observer
coverage or compatibility, or qualify this changed source.

### Available in this alpha

- Runner-owned attached-service finalization now privately authorizes exactly
  one idempotent quiescent no-op. Accepted delivered state is `ok=true`,
  `remaining=0`, `initialTargets>=1`, and
  `1<=sent<=initialTargets`; escalation is allowed only there. Accepted no-op
  state is `ok=true`, authorization present, `remaining=0`,
  `initialTargets>=0`, `sent=0`, and `escalated=false`.
- Direct signal-helper calls remain fail-closed. Negative or impossible counts,
  remaining targets, escalated or unauthorized no-op, false/missing `ok`,
  malformed/unknown/duplicate/trailing JSON, truncation, dirty stderr, and a
  nonzero helper exit are rejected. The Node, Python, and controller predicates
  are pinned to the same state contract.
- An accepted no-op emits `service.signal` as succeeded with
  `alreadyExited=true` and exact `sent=0`, without claiming signal delivery.
  `service.exit` records `failed` with `exitedBeforeSignal=true` because the
  attached process exited before delivery.
- Helper success never bypasses the existing bounded wait for the exact
  attached service. A wait timeout or cancellation uncertainty remains
  `CLEANUP_FAILED`; an attached execution error remains the primary run error,
  and primary readiness or journey failure is never erased by cleanup
  convergence.

### Interpretation and qualification status

- This source document records no completed Alpha.12 local/repro or fixed-VM
  qualification. The qualified Alpha.11 source and evidence package remain
  historical and do not qualify or repackage Alpha.12.
- Capability remains `incomplete`, overall remains `inconclusive`, and M1, M2,
  and full M3 remain incomplete.

## 0.1.0-alpha.11 - 2026-07-31

Alpha.11 implements only the M3-a local portable-attestation increment. It
does not complete M3, change observer coverage, upgrade an original verdict,
or claim a new runtime/engine compatibility tuple.

### Available in this alpha

- Added
  `repopass attest --run <id> --key <private-pkcs8.pem> --out <bundle.tar>`.
  It reads and integrity-checks the authoritative verification from the
  external run store, accepts only canonical Ed25519 PKCS#8 PEM, and produces
  a deterministic offline bundle without executing repository content.
- Added a canonical, uncompressed USTAR profile containing exactly five
  sorted regular-file entries: `attestation.json`, `bundle-manifest.json`,
  `payload/verification.json`, `signature.dsse.json`, and
  `signer-public-key.pem`. Fixed headers, strict canonical JSON, exact path and
  count rules, byte limits, and byte-for-byte tar reconstruction make alternate
  encodings fail closed.
- Added an in-toto Statement v1 predicate that binds the authoritative run and
  verification IDs, verification artifact and content digests, source
  identity, scenario/environment and plan/policy digests, runner, and original
  multidimensional verdicts. Added one Ed25519 DSSE signature using exact PAE;
  the signer key ID is SHA-256 over SPKI DER.
- Added strict public schemas for the bundle manifest, in-toto statement, and
  single-signature DSSE envelope, plus strict runtime validation of the
  embedded verification artifact.
- Added
  `repopass verify-attestation <bundle.tar> [--trust-key <public-spki.pem>]`.
  It validates the full canonical artifact graph and signature offline before
  applying explicit trust. No trust key is `unknown` and exit 7; a malformed,
  unavailable, or nonmatching trust key is `rejected` and exit 7; only the
  exact canonical Ed25519 SPKI public key is `accepted` and exit 0.
- Added separate verification fields for artifact integrity, signature
  validity, signer key ID, trust decision, freshness evaluation, run and
  verification IDs, and original results. Alpha.11 intentionally reports
  `freshnessEvaluation: "not-evaluated"`; the embedded
  `originalResults.freshness` is only the stored historical verdict.
- Added stable `ATTESTATION_INVALID`, `ATTESTATION_UNTRUSTED`,
  `EVIDENCE_STALE`, and `SIGNING_FAILED` error codes to the executable error
  model. `EVIDENCE_STALE` is reserved and is not emitted by the Alpha.11
  attestation path because that path performs no freshness re-observation.
- Private keys and outputs now use bounded regular-file checks, link/reparse
  rejection, path separation from the authoritative data store/output and,
  when a current repository is detectable through `.git` or
  `repo-passport.yml`, that repository, canonical key encoding, and fail-closed
  no-overwrite output publication through a flushed same-directory temporary
  file. Private key
  bytes and paths are excluded from command output and bundle content.
- Windows signing rejects UNC, device, extended-namespace,
  alternate-data-stream, trailing-dot/trailing-space, reserved DOS,
  hard-linked, and reparse-point key/output paths. Key ownership and DACL must
  be provably restricted to the current owner, SYSTEM, and Builtin
  Administrators; inability to prove that boundary is `SIGNING_FAILED`.

### Interpretation and qualification status

- Signing preserves the embedded verification exactly. It does not turn
  `capability: incomplete` or `overall: inconclusive` into verified, and it
  does not rewrite the original `evidence: unsigned` field.
- Trust is only explicit local SPKI equality. The embedded public key and key
  ID are not trust anchors. Sigstore, OIDC, transparency logs, KMS, TPM/HSM,
  key lifecycle, timestamping, revocation, SBOM, hosted identities, and remote
  publication remain unsupported.
- `freshnessEvaluation` is not evaluated. A historical verification does not
  contain the former local source path, so the attestation command cannot
  recover or re-observe that path.
- If no `.git` or `repo-passport.yml` marker makes the current repository
  detectable from the working directory, Alpha.11 cannot infer either that
  repository boundary or the historical source location for key/output path
  exclusion.
- The no-replace output path does not claim resistance to a hostile concurrent
  rename/symlink/junction swap of its parent directory. The Windows publication
  path also does not claim universal power-loss durability across every
  filesystem and storage provider.
- This source document records no completed Alpha.11 local/repro or fixed-VM
  qualification. Historical Alpha.9 and Alpha.8 records qualify only their
  exact sources and evidence packages.

## 0.1.0-alpha.10 - 2026-07-31

This increment adds a strict controller-owned cleanup-residue classification
boundary. It does not complete filesystem-write observation, M1, or M2, and it
does not turn a bounded final inventory into operation history or attestation.

### Available in this alpha

- Resolved plans now use schema version `"3"` and contain required cleanup
  contract `{classifierVersion:"0.1.0", allowedResidue:[...]}`. The only
  accepted profiles are `[]` and `["/outputs/**"]`; cleanup participates in
  canonical plan identity, lock checking, cloning, and sealed execution.
- Version-1 and version-2 locks remain historical. Current checking and
  execution reject them with `PLAN_DRIFT`/plan-contract failure rather than
  silently applying version-3 semantics. Manifest `v1alpha1`, CLI driver
  `0.2.0`, HTTP driver `0.1.0`, and the other artifact schema versions do not
  change.
- After service finalization, immutable-ID workload quiescence, and existing
  final observers, fixed Node/Python helpers remove `.home` and `.tmp`,
  reverify the immutable container identity and run label, and inventory only
  the `/outputs` tmpfs. Traversal is streaming, no-follow, directory-fd rooted,
  and bounded to 2,048 entries, 1,024 UTF-8 path bytes, depth 64, and a
  512-KiB control envelope.
- Strict control decoding rejects invalid UTF-8, unknown/duplicate/missing or
  null fields, trailing data, dirty stderr, unsorted or duplicate entries,
  count mismatch, overflow, identity change, disposable residue, and malformed
  types. Helpers never read regular-file content or symlink targets.
- Public `cleanup.residue.summary` evidence contains a fixed boundary, safe
  counts and completion flags, and an opaque one-time token made with a fresh
  ephemeral HMAC-SHA-256 key. The key and raw inventory are discarded, so the
  token cannot be opened or independently recomputed and is neither an
  attestation nor proof. Raw paths, symlink targets, contents, helper output,
  and unsalted path hashes are excluded.
- Zero descendants is `clean`; regular files/directories covered by
  `/outputs/**` are `allowed-residue`; an empty allowlist with any descendant,
  or any symlink/special/unmatched entry, is `undeclared-residue` with a
  `CLEANUP_RESIDUE` finding. Incomplete evidence is `not-tested`.
- Confirmed undeclared residue is a conformance finding, not an operational
  execution error, so all requested fresh repeats may finish. It outranks
  later cleanup/destroy uncertainty. Unsafe symlink/special trees are not
  permission-repaired or exported; an aggregate export-denial observation with
  `Result=denied` is emitted before forced removal.
- Repeated cleanup verdicts use the fixed precedence
  `undeclared-residue > not-tested > allowed-residue > clean`, and cleanup is
  part of the semantic reproducibility fingerprint. The new malicious fixture
  proves functional pass plus regular and symlink residue without publishing
  its path or target.

### Qualification status

- This source document does not claim a completed Alpha.10 local/repro or
  fixed-VM live qualification. Such a claim requires the separate final
  source-bound gate package and exact environment tuple.
- Capability remains `incomplete`, healthy overall remains `inconclusive`,
  M1/M2 remain incomplete, and evidence remains unsigned. Alpha.9
  qualification records `20260731T102030Z` and `20260731T102115Z` remain
  historical and do not qualify Alpha.10.

## 0.1.0-alpha.9 - 2026-07-31

This increment adds one narrow, controller-evaluated JSON Schema assertion for
complete CLI stdout. It does not expand the runtime tuple, observer coverage,
or release milestone claims.

### Available in this alpha

- A CLI assertion may declare `stdoutJsonSchema` as one portable repository
  path. Planning loads only that immutable local source file, validates the
  supported offline Draft 2020-12 subset, and seals its path, SHA-256 digest,
  dialect, and validator version.
- The trusted controller evaluates the complete captured stdout as exactly one
  strict JSON document. Instance limits are 1 MiB, depth 128, 100,000 nodes,
  and explicit/effective decimal exponent `-1000..1000`. Invalid UTF-8,
  duplicate keys, trailing data, empty output, and limit violations fail
  closed.
- Complete malformed JSON and schema mismatch produce a `failed` assertion.
  Shared stdout/stderr log truncation makes complete stdout unknowable and
  produces `inconclusive`. A missing sealed schema binding blocks evaluation;
  any other controller schema-evaluation failure is `inconclusive`.
- Assertion evidence includes the sealed schema binding and only safe
  completeness/match booleans plus a failure kind. It never includes raw
  stdout, a parsed value, property names, a stdout digest, or byte count. The
  verifier integrity-binds this controller result; it does not independently
  recapture stdout.
- Remote, dynamic, and cross-file schema references remain unsupported.
  Repository code is not executed while resolving or evaluating the schema.
- The resolved-plan schema is now version `"2"`. The CLI journey driver is
  `0.2.0`; the HTTP journey driver remains `0.1.0`. The manifest stays
  `repopass.dev/v1alpha1`, and observation, assertion, verification, error, and
  CLI-envelope artifacts remain schema version `"1"`.
- Version-1 resolved-plan locks produce `PLAN_DRIFT` and must be regenerated;
  they are never silently reinterpreted. Existing version-1 evidence remains
  historical and integrity-readable, but it is not a current Alpha.9 execution
  contract.
- Capability remains `incomplete`, overall remains `inconclusive`, M1 and M2
  remain incomplete, and evidence remains unsigned. Podman port observation,
  broader runtime/engine tuples, full RFC 9535 JSONPath, and remote schemas are
  not claimed.

### Qualification status

- No formal Alpha.9 local/repro or fixed-VM live qualification result is
  claimed in this source document. A publishable result requires a separate
  source-bound evidence package containing the exact gate records and
  environment tuple.
- Alpha.8 records below remain historical and do not qualify the changed
  Alpha.9 source or resolved-plan contract.

## 0.1.0-alpha.8 - 2026-07-31

This increment adds a deliberately narrow Docker peer-container observation of
the declared TCP listener for the supported single-service HTTP profile. It is
bounded `best-effort` evidence, not complete socket-lifecycle history, and it
does not make a required `port-listen` capability complete.

### Available in this alpha

- The observer is limited to Docker, Linux `amd64`, the exact built-in
  Node/Python runtime tuples, one HTTP service, and one declared
  `127.0.0.1:<port>/tcp` listener.
- The controller creates a peer from the same exact pinned image and joins
  only the target's network namespace with
  `--network container:<immutable-target-id>`. It verifies immutable 64-hex
  identities, exact image and labels, running state, network sharing, and
  separate PID, mount, IPC, and cgroup namespaces.
- The peer is UID/GID `65534`, read-only, capability-free, and
  `no-new-privileges`, with no host mount, port publish, device, privileged
  mode, or added capability. Independent limits are 64 MiB memory/swap,
  16 tasks, and 0.25 CPU.
- The peer attaches immediately before service dispatch. Exactly one strict
  bounded `READY` frame is required before the service starts, and exactly one
  strict bounded `FINAL` frame is requested only after workload quiescence. A
  cryptographically random 256-bit token is transported only through stdin and
  is excluded from argv, environment variables, logs, and public evidence.
- The fixed Node/Python helper samples only `/proc/net/tcp` and
  `/proc/net/tcp6` `LISTEN` entries. Initial and final barriers enclose a
  100 ms polling cadence capped at 1,200 samples. The declared listener must be
  absent initially, observed during the window, and absent finally.
- Strict bounds cover endpoints, samples, transitions, frames, stdout, stderr,
  sample gaps, and the canonical transcript. Dirty stderr, nonzero exit,
  timeout, invalid or extra protocol data, identity or namespace mismatch,
  gap, overflow, incomplete listener lifecycle, or cleanup failure cannot
  produce successful observer evidence.
- Public `port.listener-trace.summary` evidence is aggregate-only. It contains
  no session token, raw `/proc` rows, socket inodes, or undeclared endpoints.
  Its canonical digest is a helper commitment, not a controller-recomputed
  attestation.
- The peer is removed before the target. Observer failure is supplemental and
  does not rewrite functional success; peer-removal failure remains an
  independent cleanup error.
- A complete trace supplies only `PortObservation=best-effort`: short-lived
  listeners may fall between samples, UDP is not observed, and process
  attribution is unavailable. A required `port-listen` capability remains
  `incomplete`, overall remains `inconclusive`, and M1/M2 remain incomplete.
  Podman port observation is `unavailable`.

### Qualification status

- Local/repro gate `20260731T085753Z` passed formatting, vet, reachable
  vulnerability scanning, the complete and shuffled security-focused Go test
  suites, integration-tag compilation, release smoke checks, and byte-identical
  rebuilds.
- Live gate `20260731T085836Z` passed all 19 ordered guest gates and all 12
  required Docker cases, including sequential Node/Python
  `TestContainerPeerPortObservation` evidence and Linux
  `go test -race ./internal/execution`. Container, network, volume, and
  host-listener inventories matched before/after; guest cleanup and final
  QEMU/seed shutdown passed without force.
- The live claim is limited to Docker client/server 29.1.3, Ubuntu 24.04.4 LTS,
  kernel 6.8.0-134-generic, Linux `amd64`, cgroup v2, QEMU, and the two exact
  approved images. It is unsigned and does not qualify Podman, rootless,
  another version/kernel/image/architecture tuple, M1, or M2. Capability
  remains `incomplete` and overall remains `inconclusive`.

## 0.1.0-alpha.7 - 2026-07-31

This increment adds a Docker-only, bounded activity-notification trace for
`/outputs`. It is supplemental evidence, not filesystem operation or syscall
history, and it does not complete the required filesystem observer.

### Available in this alpha

- The controller starts a trusted root helper before workload execution with
  the exact shell-free `docker exec --interactive --user 0:0 ...` transport and stops it
  only after workload quiescence. The helper placement is
  `observerPlacement=in-sandbox-trusted-helper`, and
  `sharesSandboxResourceBudget=true`; helper CPU, memory, task, and tmpfs use
  can perturb resource measurements.
- Control and result messages are strict bounded stdin/stdout JSONL. Exactly
  one `READY` and one `FINAL` frame are required. Each frame is capped at
  8 KiB, total stdout at 16 KiB, stderr at 8 KiB, notifications at 4,096, and
  the canonical transcript at 1 MiB. No workload-writable control file is
  created. A cryptographically random
  session token is delivered only through stdin and is never placed in argv,
  environment variables, logs, or public evidence.
- Raw workload paths stay only in bounded helper memory. Public evidence is
  aggregate-only: notification counts, controller-window phase hints, and a
  keyed canonical transcript digest. It contains no raw path, file content,
  token, actor attribution, or per-operation record.
- The Node adapter manually installs non-recursive, per-directory `fs.watch`
  watchers and caps the topology at 2,048 watches. Its
  `kernelOverflowDetection` is `unavailable`. The Python adapter uses inotify,
  has the same 2,048-watch cap, and fails closed when the inotify queue reports
  overflow.
- Dirty stderr, nonzero exit, timeout, missing/extra/trailing/oversize frames,
  identity mismatch, count/bound failure, overflow, or a detected gap makes
  the whole activity trace `unavailable`. Partial counts or commitments are
  not published as successful evidence; the functional run and cleanup still
  continue.
- Blind spots include dynamic watch-installation races, event coalescing,
  reads, rename pairing, watched-directory replacement, exact operation
  semantics, exact phase attribution, and actor attribution.
- Complete Docker evidence gives only `best-effort` notification hints.
  Podman activity tracing remains `unavailable` until separately
  live-qualified. Required filesystem-write observation remains
  `incomplete`, capability remains `incomplete`, overall remains
  `inconclusive`, M1/M2 remain incomplete, no undeclared-write verdict is
  produced, and evidence remains unsigned.
- Existing retained-state and engine-diff path commitments use unsalted raw
  SHA-256. Suppressing raw paths does not provide dictionary-resistant path
  secrecy; low-entropy candidate paths can still be guessed and tested. The
  new activity transcript's keyed digest does not strengthen those historical
  commitments.

### Qualification status

- This changelog does not claim an `alpha.7` live-container qualification.
  Any such claim requires an external package bound to the exact source and
  environment tuple. Historical Alpha.6 and earlier results do not qualify
  this source state.

## 0.1.0-alpha.6 - 2026-07-31

This increment adds a Docker-only, bounded observation of the engine's
container writable-layer diff. It supplements the retained-state observer; it
does not turn Docker CLI output into filesystem operation history, implement
undeclared-write detection, or complete the required filesystem observer.

### Available in this alpha

- The controller invokes Docker without a shell and with the fixed argument
  vector `docker container diff <immutable-64hex-id>`. The full 64-hex
  container ID is identity-checked before collection.
- Stdout and stderr are bounded independently to 4 MiB. Collection succeeds
  only when the command exits `0`, neither stream is truncated, and stderr is
  empty. Any dirty or incomplete transcript makes this supplemental component
  `unavailable`; it does not stop the functional run or later repeats.
- Docker CLI stdout is treated as an opaque byte transcript because filenames
  may contain newlines. RepoPassport does not parse `A`/`C`/`D` records or
  publish raw output or paths. Public evidence contains only a SHA-256
  commitment, byte count, and nonempty flag.
- A pre-workload baseline is diagnostic only and never supplies or downgrades
  coverage. Only the final snapshot, taken after workload quiescence and before
  permission repair, may give the engine-diff component coverage
  `best-effort`, and only after the immutable container identity is rechecked.
- Docker defines the final transcript cumulatively from container creation.
  It can include trusted initialization, observer, and other pre-workload
  activity. It has no actor, operation-time, workload-phase, or complete
  transient-history attribution.
- The engine transcript covers neither the separate `/outputs` tmpfs nor bind
  and other mounts such as source, workspace, and inputs. The container root
  filesystem remains read-only in the supported profile.
- A complete retained-state snapshot pair may still give
  `filesystem.retained-state.summary` event coverage `high`. The combined
  filesystem-write view remains only `best-effort`; required
  `filesystem-write` remains capability `incomplete`, overall remains
  `inconclusive`, and M1/M2 remain incomplete. No undeclared-write verdict is
  produced, and evidence remains unsigned.

### Qualification status

- This changelog does not embed an `alpha.6` live-container qualification
  claim. Any external qualification package must bind the exact source
  manifest, gate ID, environment tuple, and complete live results. The
  historical `alpha.5` target and its evidence do not qualify `alpha.6`.

## 0.1.0-alpha.5 - 2026-07-31

This increment adds a deliberately narrow, controller-owned observation of
retained state below `/outputs`. It does not implement operation-history
tracing, undeclared-write detection, or a complete filesystem observer.

### Available in this alpha

- The runner captures strict, bounded baseline and final snapshots below
  `/outputs`: at most 2,048 entries, 1,024 UTF-8 bytes per normalized public
  path, 256 retained changes, and a 4 MiB helper-control envelope.
- The baseline boundary is after controller output initialization and before
  workload execution. The final boundary is after workload quiescence and
  before permission repair, disposable-directory removal, or output export.
  The same immutable container identity and run label are verified at both
  boundaries.
- Snapshot commitments include entry path, type, mode, and size. Regular-file
  contents and raw symlink targets are committed with SHA-256. Public evidence
  is aggregate-only: one `filesystem.retained-state.summary` event reports
  snapshot digests, entry counts, and the retained change count without
  publishing file contents, symlink targets, or per-path change records. Its
  event coverage is `high` only for a complete snapshot pair.
- A complete pair of snapshots gives the
  `filesystem.retained-state.summary` observation event coverage `high`.
  Because the observer does not capture filesystem operation history, composite
  `FilesystemWriteObservation` is only `best-effort`. The required
  `filesystem-write` observer remains incomplete.
- The snapshot scope includes trusted helpers and runner-managed,
  workload-writable disposable `/outputs/.home` and `/outputs/.tmp` state,
  which is excluded from export. It is scenario-wide and cannot
  attribute a retained change to a process, workload phase, or operation time.
- Snapshot, identity, quiescence, bound, or decode failure makes retained-state
  coverage `unavailable`. This supplemental observer failure is nonfatal and
  must not be represented as an empty successful diff or stop later repeats.
- Blind spots are explicit: state outside `/outputs`; transient
  create/delete; write-then-restore; operation time and process/phase
  attribution; rename versus delete/create; ownership, timestamps, xattrs,
  ACLs, inode identity, and device identity.
- A healthy run therefore remains capability `incomplete` and overall
  `inconclusive`. This increment completes neither M1 nor M2, does not produce
  `UNDECLARED_FILESYSTEM_WRITE`, and does not claim a full filesystem observer.
  Evidence remains unsigned.

### Qualification target

- `20260730T202049Z` is the alpha.5 exact-tuple qualification target. It is
  qualified only if the external evidence package for that record reports
  gate exit `0` and contains the complete required source, schema, unit,
  integration, live-container, cleanup, residue, and reproducible-build
  evidence.
- A missing package, nonzero gate exit, skipped required case, or tuple mismatch
  is not an alpha.5 compatibility result. Even a qualified record applies only
  to its exact Docker/VM/kernel/Linux `amd64`/approved-image tuple; it is not a
  Podman, rootless, other-version, other-kernel, other-image, or `arm64` claim.

## 0.1.0-alpha.4 — 2026-07-31

This increment adds a cgroup-v2 resource observer. The compatibility claim is
limited to the exact tuple recorded below; it does not broaden the historical
`alpha.3` record or close the other observer gaps.

### Available in this alpha

- Resource-limit enforcement is a separate runner feature. Successful CPU,
  memory, PID, or writable-storage enforcement cannot by itself satisfy a
  `ResourceUsage` observer requirement.
- A complete resource observation records sandbox CPU time from cgroup-v2
  `cpu.stat usage_usec` (with the public millisecond value rounded down), the
  cgroup-wide `memory.peak`, `pids.peak`, a final writable-allocation snapshot,
  verified accepted output bytes, and captured controller stdout/stderr bytes.
- Structured evidence uses `sandboxCPUTimeMillis`,
  `sandboxPeakMemoryBytes`, `maxTasks`, `writableBytes`, `outputBytes`, and
  `observedFields`. `observedFields` distinguishes an observed zero from a
  missing measurement. The legacy `cpuTimeMillis`, `peakMemoryBytes`, and
  `maxProcesses` keys remain only for alpha.3 wire compatibility and are not
  populated by the new observer.
- `memory.peak` is the sandbox cgroup's total peak, including cache, tmpfs,
  kernel memory, and trusted helpers; it is not RSS or repository-code-only
  memory. `pids.peak` counts tasks/threads, not processes. Writable bytes are a
  final allocation snapshot, not peak growth, so write-then-delete spikes may
  not be represented.
- The composite `ResourceUsage` coverage ceiling is `high`, not `full`, and is
  available only after every required sample succeeds for every repeat. Probe
  or snapshot failure produces unavailable/incomplete evidence; missing values
  are never filled with zero.
- The validated `high` claim is limited to the exact Docker client/server
  29.1.3, Ubuntu 24.04.4, kernel 6.8, Linux `amd64`, cgroup-v2, and approved
  image tuple in `docs/release.md`. Podman, rootless engines, other Docker
  versions, kernels, architectures, and images remain unclaimed.
- Filesystem-write and port-listen observation remain unavailable and complete
  child-process history remains best effort. Therefore M1 remains incomplete;
  a healthy run remains capability `incomplete` and overall `inconclusive`.
  Evidence remains unsigned.

### Exact release record

- Live gate `20260730T173121Z` passed all 18 ordered gate steps and all ten
  required cases, including `TestContainerResourceUsageObservation`, on Docker
  client/server 29.1.3, isolated Ubuntu 24.04.4, kernel
  `6.8.0-134-generic`, Linux `amd64`, cgroup v2, and both pinned approved
  images.
- Gated source snapshot SHA-256:
  `4492de55cf8c1c57ccdda8fb0f0be4bd2512a7a2dc393ef0e419e620d2d5b4d6`.
  Source-manifest file SHA-256:
  `0f1593e634a3295ed329dafc977ff1b84e0c1eb226b8e89b073e7fe2a74ead78`.
  Evidence-inventory file SHA-256:
  `ffd724e50414c841ebe6e7a7bdd39d8c40102522130039c9e62cf95c83e601c7`.
- Local gate `20260730T173051Z` passed formatting, vet, full non-container
  tests, security-sensitive shuffled repetitions, integration-tag compilation,
  release build, and an independent byte-for-byte rebuild.
- Go 1.26.5 release hashes are
  `7a40d9cad99f40615df1d011e61ac36ada8ca209b9e3f858bed72d1064dda81d`
  for Linux `amd64`,
  `9675ea553a1d954958d8d463fb019bacf954e156587e7331e69b8a6ae5fc8420`
  for Windows `amd64`, and
  `fe84a2942b0d3b3ff51413fe125f11885c33d34c47483275b603fd62be263678`
  for `SHA256SUMS`.
- `govulncheck` found zero reachable or imported-package vulnerabilities. It
  reported required-module-only `GO-2026-5970`; the analyzed code does not call
  the vulnerable symbols.
- The source-manifest and evidence-inventory hashes identify individual gate
  metadata files. No packaged evidence bundle is claimed here.

## 0.1.0-alpha.3 — 2026-07-30

This increment keeps the Alpha.2 single-service lifecycle and adds
controller-owned structured HTTP JSON assertions. It does not complete M1,
close observer gaps, or change the honest `incomplete`/`inconclusive` verdict
boundary.

### Available in this alpha

- Singular response `jsonPath.equals`: root `$`, dot members, quoted bracket
  members, and non-negative array indexes. Paths are capped at 1,024 UTF-8
  bytes and 64 selectors; wildcard, slice, filter, union, recursive descent,
  and function syntax are rejected.
- Strict JSON decoding preserves numbers without `float64`, distinguishes
  missing paths from JSON `null`, and rejects duplicate keys, trailing values,
  invalid UTF-8, excessive nesting, excessive node counts, and documents over
  1 MiB. Explicit and effective decimal exponents are limited to
  `-1000..1000` before values reach the schema validator.
- Offline Draft 2020-12 response `jsonSchema`. Schema files must be bounded
  regular files in the immutable source inventory. The resolved plan binds
  portable path, SHA-256, dialect, and
  `github.com/santhosh-tekuri/jsonschema/v6@v6.0.2`; execution re-reads and
  recompiles the copied snapshot before any workload container starts.
- Same-document fragment `$ref` is supported. Remote, relative cross-file,
  dynamic, recursive, and custom-vocabulary resolution is rejected; schema
  bytes, depth, nodes, branches, references, and regular-expression patterns
  have hard limits.
- Ordered `jsonFile` below `/outputs`. Fixed Node/Python helpers walk path
  components with dirfd/`O_NOFOLLOW`, require a regular file, read at most
  1 MiB plus an overflow sentinel, and return bounded base64/size/SHA-256.
  The controller recomputes integrity and validates the point-in-time snapshot
  against the plan-bound schema.
- `.repopass/schemas/**` is included in immutable source identity while the
  rest of `.repopass/**` controller state remains excluded.
- `Prepare` seals a private deep-cloned execution-plan snapshot. Runtime
  decisions no longer read the exported diagnostic copy, and compiled schemas
  are looked up by the complete path/digest/dialect/validator binding rather
  than digest alone.
- Planning applies the same strict JSON byte/depth/node/exponent profile to a
  canonicalized `jsonPath.equals` value that execution revalidates.
- Trusted HTTP helper control is an exact tagged envelope: duplicate, unknown,
  missing, wrong-union, or trailing fields fail closed before an assertion can
  consume the response.
- Structured assertion evidence contains only paths, schema/file digests,
  sizes, and evaluation booleans/categories. Raw response/file JSON and
  extracted values are not persisted.
- The `capabilities` command now reports the implemented HTTP service journey
  and structured JSON assertion slice instead of listing the service journey
  as unsupported.

### Interpretation and deferred surface

- CLI `stdoutJsonSchema`, full RFC 9535 JSONPath, remote/cross-file schema
  resolution, redirects, TLS, authentication-bearing requests, arbitrary
  sandbox file reads, and multiple services remain fail-closed.
- Filesystem-write and port-listen observation remain unavailable, foreground
  process coverage remains best effort, and resource usage remains
  enforcement-only. Healthy functional runs remain capability `incomplete`
  and overall `inconclusive`.
- Evidence remains unsigned. Live Podman, other Docker versions, and `arm64`
  are not claimed.
- Live-gate record `20260730T150346Z` passed all 18 ordered gate steps and all
  nine exact required cases on Docker client/server 29.1.3 in an isolated
  Ubuntu 24.04.4 LTS Linux `amd64` QEMU VM. The gated 154-file source snapshot
  SHA-256 is
  `f5073b9378dbaa792938267ac10a24c4c3a26585402ad61993168003ace3731e`.
- Go 1.26.5 reproducible release hashes are
  `85d3460277d43db4847a55663a3e0cb0d199cd5f9f354f160430116976ddd62e`
  for Linux `amd64` and
  `89abca38fa79c7f3fdc352fe70601c4b9d97a9d65c0879efdfbc57e00cc51773`
  for Windows `amd64`.

## 0.1.0-alpha.2 — 2026-07-30

This increment adds one deliberately constrained HTTP service journey to the
existing local vertical slice. It does not complete M1 or repair the built-in
observer gaps.

### Available in this alpha

- One attached Node or Python HTTP service for the exact built-in Linux
  `amd64` runtime/image tuples. Service execution remains non-root at UID/GID
  `65532`.
- Literal IPv4 loopback only: readiness and request URLs must use
  `http://127.0.0.1:<explicit-port>`, match the scenario's one declared TCP
  listener, stay on the same origin, be canonical, and be no longer than 2,048
  bytes.
- The service and controller-supplied HTTP driver share one
  `--network none` container. The runner does not publish a host port. The
  bounded trusted helper runs separately from repository code as UID/GID
  `65533`.
- Controller-supplied Python helpers run as `python -I -S` with working
  directory `/`; they do not import through the repository workspace.
- Bounded readiness and requests use an absolute wall-clock deadline rather
  than a socket-inactivity timeout. Runner-owned slack is reserved for helper
  cancellation and exit confirmation, not added to the functional budget.
  HTTP durations must resolve to whole milliseconds of at least 1 ms: `1.5s`
  is valid as 1,500 ms, while `1.5ms` is rejected. Readiness is capped at 2
  minutes, uses exponential retry backoff, and has a hard limit of 128
  attempts. Each explicit per-request timeout and the resolved exercise
  fallback used when omitted are capped at 30 minutes; the fallback is
  `phases.exercise.timeout`, or 1 minute when absent. Readiness and asserted
  response statuses are limited to 200–599.
- At most 128 ordered HTTP journey steps and 32 requests. Effective headers
  must simultaneously satisfy count ≤ 64 and aggregate bytes ≤ 65,536, with
  each value capped at 8,192 bytes. Aggregate bytes are
  `sum(len(name bytes) + len(value bytes) + 4)` over every effective header;
  accepted names and values are ASCII, so these are also their UTF-8 byte
  lengths. The trusted driver's automatic JSON `content-type` counts in both
  the count and aggregate. Text request bodies and actual serialized JSON
  request bytes are each capped at 1 MiB.
- Before a readiness retry or cleanup, the UID/GID `65533` driver helper must
  exit synchronously or be quiesced by a trusted root helper. Failure to
  confirm that state fails closed.
- Controller-evaluated response status, header-contains, `bodyContains`, and
  `fileExists` assertions. Header `contains` values are limited to 8,192 bytes;
  `bodyContains` must be non-empty and no larger than 1 MiB.
- Ordered HTTP `fileExists` uses trusted in-container `lstat` at that journey
  step, accepts only normalized UTF-8 `/outputs` paths no longer than 4,096
  bytes, and rejects a symlink in any traversed component.
- Exactly one cleanup signal for the declared service. The trusted helper
  applies the declared signal and grace period, escalates remaining workload
  processes to `SIGKILL`, and finalization quiesces UID/GID `65532` workload
  processes before export and forced container removal. It requires at least
  one workload target and at least one successful signal send; an
  enumeration/send race fails closed. Success does not require sending to
  every initially enumerated target: the required counters are
  `initialTargets >= 1` and `sent >= 1`, followed by zero remaining workload
  processes. Every signal type, including `kill`, requires a
  whole-millisecond grace period from 1 ms through 10 seconds. The synchronous
  UID/GID `65533` HTTP helper exits after each operation. The service signal
  must be the final resolved command, with separate runner-owned slack left for
  the signal helper to finish.
- `service.start` becomes a succeeded lifecycle observation only after the
  readiness status succeeds; process launch alone is not reported as a
  successful service start.
- Stable negative outcomes for a service that exits before readiness
  (`SERVICE_START_FAILED`) and one that remains alive but never becomes ready
  (`READINESS_FAILED`).

### Interpretation and deferred surface

- JSONPath (`jsonPath`), JSON Schema (`jsonSchema`), and `jsonFile` assertions
  remain recognized but planner-gated. Redirect following, TLS,
  authentication-bearing requests, and multiple services are not supported;
  these shapes fail closed rather than being silently approximated.
- Filesystem-write and port-listen observation remain unavailable, foreground
  process coverage remains best effort, and resource usage remains
  enforcement-only. A functional HTTP pass is therefore capability
  `incomplete` and overall `inconclusive`.
- Live-gate record `20260730T102841Z` passed all 18 gate steps and these exact
  nine cases on Docker client/server 29.1.3 in an isolated Ubuntu 24.04.4 LTS
  Linux `amd64` QEMU VM: `healthy_node_cli`,
  `healthy_python_cli_with_persisted_setup_output`, `healthy_python_http`,
  `healthy_node_http`, `workload_forged_verification_is_ignored`,
  `term_resistant_http_child_is_removed`, `service_exits_before_readiness`,
  `service_never_becomes_ready`, and
  `TestContainerDiskQuotaExpectedDenial`.
- The source and host-listener manifests were unchanged; before/after
  all-container inventories were header-only, and no host-publish residue
  remained. The approved Node and Python image digests were inspected exactly.
- The Linux and Windows `amd64` binaries were rebuilt from a different source
  path byte-for-byte identically. Their SHA-256 values are recorded in
  [the release guide](docs/release.md).
- That pass claims only the recorded Docker 29.1.3/Ubuntu 24.04.4 LTS
  QEMU/Linux `amd64`/approved-image tuple. Podman, other Docker versions, and
  `arm64` remain unclaimed. Evidence remains unsigned, M1 remains incomplete,
  and observer gaps still make a healthy functional pass capability
  `incomplete` and overall `inconclusive`.

## 0.1.0-alpha.1 — 2026-07-30

This is the first runnable RepoPassport vertical slice. It is an alpha delivery,
not completion of every milestone or definition-of-done item in the project
plan.

### Available in this alpha

- Strict `repopass.dev/v1alpha1` manifest loading, schema validation, and the
  implemented fail-closed semantic subset.
- `inspect`, `init`, `validate`, `plan`, `verify`, `report`, and `doctor` CLI
  paths for local source directories.
- Deterministic plans and lock drift checks, with the exact baseline runtime
  image policy included in the policy bundle digest.
- Dependency-free Node and Python CLI execution for the two exact
  `baseline-v1` Linux `amd64` runtime tuples documented in
  [the release guide](docs/release.md).
- A long-lived Docker/Podman sandbox with read-only source, workspace, inputs,
  and root filesystem; non-root workload commands; runtime network deny;
  bounded CPU, memory, PIDs, logs, time, and aggregate writable tmpfs storage.
- Fail-closed finalization that quiesces workload processes, removes disposable
  home/temp data, validates the output tree, streams it through the fixed
  allowlisted-image `/bin/tar`, safely extracts it in Go, atomically commits
  accepted outputs, and forcibly removes the sandbox.
- Controller-owned assertions, multidimensional verdicts, tamper-checked run
  storage, and JSON, text, and static HTML reports.

### Security and interpretation boundary

- Repository content and workload output remain untrusted. The selected exact
  runtime image, its Node/Python binary, and `/bin/tar` helper are an explicitly
  allowlisted part of the local runner trusted computing base. Digest pinning
  supplies immutability, not publisher identity or supply-chain attestation.
- The idle supervisor and fixed initialization/finalization helpers run as root
  with a restricted capability set. Repository commands run as UID/GID `65532`
  with zero inheritable, permitted, effective, and ambient capabilities and
  `no-new-privileges`.
- Built-in filesystem-write, port-listen, and complete process observation are
  not yet sufficient for capability conformance. A functional pass therefore
  remains capability `incomplete` and overall `inconclusive`.
- Live-gate record `20260730T074535Z` passed on Docker client/server 29.1.3 in
  an Ubuntu 24.04.4 Linux `amd64` QEMU VM. Exact Node, Python persisted-setup,
  forged-result/background-quiescence, and expected-`ENOSPC` cases all passed.
  This record does not extend to other engine/version/platform combinations,
  and it does not change the incomplete/inconclusive observer boundary.
- Final Linux and Windows `amd64` snapshots were rebuilt reproducibly from the
  gated source. Their exact checksums and smoke-test scope are recorded in
  [the release guide](docs/release.md).

### Deliberately deferred

- HTTP services, readiness and request journeys, signals, explicit shells,
  setup egress allowlists, synthetic-secret injection, and richer command/input
  forms.
- Full filesystem, process, port, network-attempt, and resource-usage
  observation.
- Signed attestations, signer trust, SBOM attachment, and the `local-full`
  evidence profile.
- Remote acquisition, hosted hardened workers, interactive trial, GitHub
  writeback, registries, and external plugins.
