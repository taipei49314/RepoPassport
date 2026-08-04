# Artifact model

This document records the public v1alpha1 JSON artifacts emitted by the reference CLI. The JSON Schemas in `schemas/` are authoritative.

## Resolved plan

`resolved-plan.schema.json` defines the immutable execution contract.

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Resolved-plan schema version, currently `"4"`. |
| `source` | Source identity, optional exact Git commit, and tree digest. |
| `manifestDigest` | Digest of the accepted manifest. |
| `scenario`, `environment` | Selected scenario and environment. |
| `runtimeAdapter`, `runtimeVersion` | Adapter and exact resolved runtime. |
| `baseImageReference`, `baseImageDigest` | Digest-pinned image and digest. |
| `resources`, `inputs` | Resolved limits and mounted inputs. |
| `adapterVersions`, `observerVersions` | Exact implementation versions. |
| `journeyDriver`, `journeyDriverVersion` | Resolved journey driver. |
| `commands`, `journeyAssertions` | Ordered execution and assertion contracts. |
| `cleanup` | Required cleanup classifier version and exact allowed-residue profile. |
| `evidence` | Exact plan-bound `minimal-public` include/exclude selection. |
| `capabilities` | Effective capability set for all six phases. |
| `requiredRunnerFeatures`, `observerSet` | Required runner features and observers. |
| `repeatCount`, `successThreshold` | Reproducibility contract. |
| `policyBundleDigest`, `planDigest` | Policy and complete plan identities. |

A command contains `phase`, `id`, `timeout`, and `role`, plus exactly one of an `argv` array or a `signal` object. `timeout` is a normalized Go duration string. `planDigest` is computed over the canonical resolved plan with `planDigest` omitted.

Resolved-plan schema version 4 adds the required `evidence` object. Its profile
is exactly `minimal-public`; its sorted `include` is exactly normalized
observations plus verification summary, with or without `sbom`; and its sorted
`exclude` is exactly raw stderr, raw stdout, and raw syscall trace. Version 3
historically added cleanup classifier `"0.1.0"` with `allowedResidue` exactly
`[]` or `["/outputs/**"]`; version 2 added the CLI `stdoutJsonSchema` binding
and driver `0.2.0`. The HTTP driver remains `0.1.0`. Version-1, version-2, and
version-3 plan locks are different execution contracts and produce
`PLAN_DRIFT`; none is reinterpreted or upgraded in place.

Alpha.23 binds filesystem observer `0.5.0` for bounded retained-state
declaration comparison. Earlier schema-4 locks that bind `0.4.0` also produce
`PLAN_DRIFT`; generated schema version and component implementation versions
are independent parts of the execution contract.

## Observation

`observation.schema.json` defines one ordered evidence event. Every event contains `schemaVersion`, `sequence`, `timestamp`, `phase`, `actor`, `operation`, `resource`, `result`, `observer`, `coverage`, and `confidence`. `details` is optional bounded metadata. `sequence` is authoritative stream order; wall-clock timestamps are descriptive.

## Assertion result

`assertion.schema.json` defines one assertion evaluation. It carries the assertion ID and type, required flag, expected and actual values, status, evidence references, and optional message, repeat, and duration.

Public artifacts emit `passed`, `failed`, `blocked`, or `inconclusive`.
The controller normalizes internal runner compatibility spellings
`pass`/`fail` before serialization.

For `type: "stdout-json-schema"`, `expected` contains only the sealed schema
path, digest, dialect, and validator version. `actual` contains only safe
completeness/strictness/match booleans and, when applicable, a failure kind.
It MUST NOT include raw stdout, parsed JSON, workload property names, a stdout
digest, or a stdout byte count. Shared log truncation is `inconclusive`;
complete malformed JSON or schema mismatch is `failed`; unavailable sealed
schema material is `blocked`.

## Verification result

`verification.schema.json` defines the authoritative verification artifact. It includes separate `verificationId` and `runId`; timestamps; source and plan identities; runner features and verdicts; observer coverage; embedded observations, assertions, policy decisions, and errors; repeat and resource measurements; and content digests.

A consumer MUST recompute digests before trusting the corresponding verdicts.

## Local attestation bundle

The current Alpha.19 profile retains the local
`repopass.attestation.bundle.v1` envelope. It is not complete M3. The bundle is
an uncompressed canonical USTAR with exactly five regular-file entries when the
schema-4 plan does not select `sbom`, or exactly six when it does:

| Path | Contract |
| --- | --- |
| `attestation.json` | Canonical in-toto Statement v1 described by `attestation.schema.json` |
| `bundle-manifest.json` | Canonical strict `minimal-public` manifest described by `bundle-manifest.schema.json` |
| `payload/verification.json` | Unchanged canonical authoritative verification satisfying `verification.schema.json` and its recomputed integrity contract |
| `payload/sbom.spdx.json` | Present only in the six-member model; canonical strict caller-supplied SPDX 2.3 derivative selected by the plan |
| `signature.dsse.json` | Canonical exact single-signature envelope described by `dsse-envelope.schema.json` |
| `signer-public-key.pem` | Canonical Ed25519 SubjectPublicKeyInfo PEM |

USTAR mode is `0600`, UID/GID are zero, modification time is Unix epoch zero,
and user/group/link names are empty. Alternate entry count, path, order, case,
type, link, mode, metadata, padding, trailing bytes, size, or archive encoding is
invalid. A verifier reconstructs the canonical tar and requires byte equality.

`bundle-manifest.schema.json` fixes `schemaVersion: "1"`, bundle format
`repopass.attestation.bundle.v1`, and privacy profile `minimal-public`. It
contains exactly two ordered hash/size records in the five-member model, for
`payload/verification.json` and `signer-public-key.pem`. The six-member model
inserts the `payload/sbom.spdx.json` record between them. Other entries are
protected by the canonical statement, DSSE, and full reconstruction contract;
they are not extra manifest file records.

`attestation.schema.json` fixes `_type` to
`https://in-toto.io/Statement/v1` and `predicateType` to
`https://repopass.dev/attestation/verification/v0.1`. Its single subject is the
canonical bundle manifest. The predicate binds the run and verification IDs,
verification artifact and content digests, source identity, scenario,
environment, plan and policy bundle digests, schema-4 evidence selection,
runner, and original results. In the six-member model it also binds exactly
`SPDX-2.3`, `application/spdx+json`, `payload/sbom.spdx.json`, and the canonical
derivative digest; that object is absent, not null, in the five-member model.
The source binding is portable identity only; the historical verification does
not retain its former local source path.

`dsse-envelope.schema.json` fixes payload type
`application/vnd.in-toto+json`, requires the payload to be the exact canonical
statement bytes, and permits exactly one Ed25519 signature. The signature uses
exact DSSE PAE. `keyid` is SHA-256 over the canonical SPKI DER and is
identification, not a trust decision.

The command may publish a separate byte-identical copy of
`signer-public-key.pem` as a canonical SPKI PEM companion. The companion is
never an archive member (and therefore adds no sixth or seventh member to
either exact model) and does not change the signed graph. Its
`publicKeyDigest` is SHA-256 over canonical PEM bytes. `bundleDigest` is
SHA-256 over the complete raw canonical USTAR bytes; neither digest is the
DER-based `signerKeyId` or a trust assertion.

## Attestation verification report

`verify-attestation` reports the following dimensions separately:

| Field | Meaning |
| --- | --- |
| `artifactIntegrity` | Whether the complete canonical artifact graph and embedded verification integrity are valid |
| `signatureValidity` | Whether the exact Ed25519 DSSE signature is valid |
| `bundleDigest` | SHA-256 over the complete raw bundle bytes |
| `publicKeyDigest` | SHA-256 over the embedded canonical SPKI PEM bytes |
| `signerKeyId` | SHA-256 identity of the embedded SPKI DER |
| `trustDecision` | `unknown`, `rejected`, or `accepted` under explicit SPKI equality or the selected offline policy |
| `trustBasis`, policy/envelope digests, authority key ID, policy/caller generation, policy signature validity, `trustReason` | Alpha.20 signed-policy-mode-only fixed metadata; basis is `signed-offline-policy-v2` and reason is `trusted`, `revoked`, `not-listed`, `generation-below-minimum`, or `invalid-or-unavailable`; omitted for legacy modes |
| `freshnessEvaluation` | `not-evaluated` without opt-in; otherwise bounded replay-time `current`, `stale`, or `unknown` |
| `freshness` | Opt-in-only local-reobserve-v1 profile, reason, runner profile, and four ordered digest checks |
| `runId`, `verificationId` | Historical authoritative result identities |
| `originalResults` | Original multidimensional verdicts, unchanged by signing |
| `sbomPresent`, `sbomFormat`, `sbomDigest` | Required flattened attachment metadata; false/empty/empty in the five-member model |
| `privacyProfile`, `privacyPolicy`, `privacyRulesetDigest`, `privacyEvaluation` | Frozen `minimal-public` gate identity and decision |

`originalResults.freshness` is stored historical data and MUST NOT be confused
with `freshnessEvaluation`. A valid signature without an independent trust key
is not accepted. The embedded public key or key ID alone cannot establish
trust.

Alpha.16 freshness is unsigned verification-time metadata. It requires an
explicit accepted SPKI key and complete raw-bundle pin before current source
access, and it never rewrites or re-aggregates `originalResults`. Stable drift
is `EVIDENCE_STALE`; an incomplete or unstable observation is `unknown`, not
stale. The finite runner projection is not complete runner or executable
identity, and the check is not historical scenario re-execution.

An optional expected bundle digest is checked before an explicit trust-key
file is accessed. Digest equality pins only the received raw bytes. A retained
companion, embedded key, PEM digest, DER key ID, or package-local equality does
not establish maintainer identity or external trust.

Alpha.19 may instead consume a separate canonical
`offline-trust-policy-v1` document after all bundle, signature, SPDX, and
privacy validation. The policy is not embedded, signed, or added to the exact
USTAR member set. Its required expected digest is checked over exact raw bytes
before parsing. Only the verifier-computed SHA-256 identity of canonical SPKI
DER is queried. A `trusted` entry accepts; `revoked` or absent rejects. This is
operator-selected authorization state, not policy provenance, trusted time, or
historical revocation evidence.

Alpha.20 may instead consume a separate signed canonical
`offline-trust-policy-v2` payload. It is never a bundle member and is accepted
only through the exact caller-supplied envelope, authority-key, and minimum-
generation triple after bundle validation. The envelope's dedicated DSSE type
and signature authenticate the policy only relative to that canonical authority
SPKI. Its signed generation is a safe integer in `1..9007199254740991` and is
checked only against the caller floor for that invocation. This adds neither
persistent anti-rollback nor trusted time/expiry, equivocation prevention,
authority lifecycle, historical revocation, or a
capability/overall-verification upgrade.

Alpha.31 may author that unchanged input with the full CLI and atomically
publish exactly its envelope plus authority-SPKI companion. These remain
external verifier inputs, never attestation bundle members or automatic trust
roots. The producer adds no private-key artifact, key lifecycle, identity,
trusted time, or capability/overall-verification upgrade.

Alpha.32's one-hop authority transition, explicit previous root, explicit
terminal authority, exact-three producer sidecars, and combined local state are
also external replay inputs. They are never attestation bundle members,
manifest/plan fields, automatic trust roots, or evidence claims. The portable
kit declares that no offline trust-policy authority-transition sidecar is
included.

Alpha.33's chain JSON, explicit root/terminal SPKIs, ordered hop inputs,
authority floor, exact-three assembler output, and separate local chain state
are likewise external replay inputs. They are never bundle members,
manifest/plan fields, automatic trust roots, or evidence claims. Portable kits
contain no chain sidecar or assembler input.

## Errors

`error.schema.json` defines structured errors. Every error includes `schemaVersion`, a stable Appendix-C error `code`, `severity`, `message`, `evidenceRefs`, and `retryable`. `phase`, bounded `details`, and `suggestion` are optional.

Human-readable text is explanatory only. Automation branches on stable codes and typed fields.

## Binding and integrity

All digest fields use lowercase `sha256:<64 lowercase hex>`. Git commits are full lowercase 40-hex object IDs. The plan binds source, manifest, runtime, image, adapters, observers, capabilities, runner requirements, driver, repetition policy, evidence selection, and policy bundle. The verification binds the plan digest, schema-4 evidence object, and its emitted evidence arrays.

Only the resolved-plan artifact is currently schema version 4. Observation,
assertion, verification, error, CLI structured-output, and attestation envelope
schemas remain version 1. Historical resolved-plan version-1/version-2/version-3
evidence remains read-only under the exact reader that originally supported its
schema; it is not a current Alpha.19 execution or attestation contract.
