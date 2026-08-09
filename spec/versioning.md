# Versioning and Compatibility

RepoPassport versions four public contracts independently:

| Contract | Version field |
|---|---|
| Manifest API | `apiVersion` |
| Generated JSON artifacts | `schemaVersion` |
| CLI | executable semantic version plus structured-output `schemaVersion` |
| Policy/runner/adapter/observer | exact semantic version and immutable digest where applicable |

## Go module and source identity

The canonical, case-sensitive repository and Go module identity is:

```text
github.com/taipei49314/RepoPassport
```

Repository-owned package paths are this exact value or this value followed by
`/`. The public Go schemas package is therefore
`github.com/taipei49314/RepoPassport/schemas`. Builds MUST NOT use a workspace
or module replacement to reinterpret this identity. Release executables bind
the exact module, main package, tested commit, and clean-tree state through Go
build information as specified by
[RFC-0001](../docs/rfcs/0001-canonical-go-module-identity.md).

Module identity is not a signer, repository-owner, freshness, or artifact-trust
proof. It does not change the independently versioned manifest, generated
artifact, CLI, policy, runner, adapter, observer, or evidence contracts.

## Manifest API

The initial manifest API is:

```text
repopass.dev/v1alpha1
```

An alpha version may make breaking changes only by changing `apiVersion`. A validator MUST select a schema from the exact version and MUST NOT reinterpret a document using the newest schema.

Adding a new enum value, changing a default, changing path/glob semantics, changing capability merge rules, or changing digest participation is semantic and requires an API-version decision.

## Generated schema version

Alpha.23 writers emit resolved plans with:

```json
{
  "schemaVersion": "4"
}
```

Observation, assertion, verification, error, and CLI structured-output
envelopes continue to use `schemaVersion: "1"`. The manifest API remains
`repopass.dev/v1alpha1`.

Generated schemas are strict. A producer cannot emit an unknown field to an older schemaVersion. A consumer cannot silently drop one.

Backward-compatible readers MAY support multiple exact schema versions. Writers emit one configured version and record it in every standalone artifact.

Resolved-plan version 4 adds the required exact `minimal-public` evidence
selection. Version 3 historically added cleanup classifier `"0.1.0"` and a
non-null allowlist restricted to `[]` or `["/outputs/**"]`; version 2 added the
sealed CLI `stdoutJsonSchema` binding and CLI driver `0.2.0`. HTTP plans
continue to bind driver version `0.1.0`. A runner accepts only the exact
schema/driver combination it implements; it MUST NOT infer current semantics
from an older plan.

Alpha.23 keeps resolved-plan schema version 4 but advances the plan-bound
filesystem observer from `0.4.0` to `0.5.0`. A schema-4 lock carrying the old
observer version is a different execution contract and returns `PLAN_DRIFT`;
schema equality alone never authorizes reinterpretation.

### Resolved-plan version-1/version-2/version-3 migration

A version-1, version-2, or version-3 lock is never rewritten or interpreted as
version 4.
Current `plan --check` returns `PLAN_DRIFT`; the operator regenerates the lock
with `--write-lock` and reviews the new schema version, driver version, cleanup
contract, evidence selection, schema binding, and plan digest.

Historical version-1/version-2/version-3 evidence remains readable only under
its original strict schema and digest rules. It is a read-only integrity record
and is not current Alpha.20 execution authority. Changing
freshness/currentness does not invalidate the historical artifact's original
integrity.

## Offline trust-policy input

## External release-index input

Alpha.28 added the separately versioned `release-index-v1` and
`release-key-policy-v1` inputs and their dedicated DSSE envelope schemas. They
are not manifest, plan, bundle, evidence, or artifact-root members. Their
semantics are purpose-separated: a release-index signer is authorized only by
a root-signed policy for `release-index-signing`, relative to an explicit
caller-supplied authority SPKI. Any alteration to the index inventory,
trust-boundary fields, policy purpose, algorithms, status values, generation
rules, or root relationship requires a new release-input contract; readers
MUST NOT reinterpret it permissively.

Alpha.29 adds the separately versioned `release-authority-transition-v1` input
and its dedicated DSSE envelope. It authorizes exactly one explicit old-root to
next-policy-authority hop for `release-key-policy-v1`; it does not make a
companion, adjacent, or bundled key a trust anchor. Direct Alpha.28 mode stays
accepted. The new transition generation is not time, and local transition state
is controller-local rather than tamper-resistant or distributed.

Alpha.30 adds the separately versioned `release-authority-transition-chain-v1`
transport. It is bounded to 2..8 ordered transition hops and is not a trust
anchor: the caller-supplied root remains explicit. Altering transport shape,
hop ordering, canonicality, key-ID adjacency, uniqueness, cycle handling,
generation rules, terminal-key binding, or chain-state digest domain requires a
new release-input contract. Direct and one-hop readers remain distinct exact
modes; no reader may permissively reinterpret a chain as either.

These versioned inputs do not establish identity or trusted time, and do not
complete capability/overall verification. Authority-root discovery, broader
lifecycle, transparency, and remote publication remain out of band.

Alpha.31 adds a producer for the unchanged exact `offline-trust-policy-v2`
contract; it does not create a v3 payload or permissive reader. The producer
derives signer identities from canonical Ed25519 SPKI DER, emits the existing
sorted unique trusted/revoked key set and safe-integer generation, and wraps it
in the existing dedicated exact-one-signature DSSE envelope. Any new decision,
algorithm, metadata, threshold, expiry, generation semantics, or trust-root
relationship requires a new policy contract rather than an Alpha.31 extension.
The authority companion remains transport material, not a trust anchor.

Alpha.32 adds the separate exact
`offline-trust-policy-authority-transition-v1` input and dedicated DSSE payload
type. It authorizes exactly one explicit previous-root-to-terminal-policy-
authority hop and binds the unchanged v2 policy payload type. Direct v2 policy
verification remains distinct. Adding chains, alternate algorithms, expiry,
thresholds, root discovery, resettable generation semantics, or a different
role model requires a new versioned contract; this reader must not reinterpret
release-authority transitions or future chain transports.

Alpha.33 adds the distinct exact
`offline-trust-policy-authority-transition-chain-v1` unsigned transport. It
contains only 2..8 canonical base64 encodings of existing Alpha.32 transition
envelopes and the canonical next-authority SPKIs those envelopes name. It does
not change or recursively extend the Alpha.32 signed payload. Direct, one-hop,
and chain modes remain explicitly selected; no reader may reinterpret one as
another. Alternate algorithms, unbounded paths, root discovery, compromise
recovery, expiry, thresholds, certificates, or a different role model require
a new versioned contract.

Alpha.20 adds the separate strict `offline-trust-policy-v2` signed-policy
input. It is not a manifest, plan, bundle member, or signed artifact schema.
It has its own canonical payload, dedicated DSSE payload type, and caller-
supplied canonical authority SPKI. Its generation is a signed safe integer in
`1..9007199254740991`; the caller floor applies only to that invocation. Any
semantic expansion requires a new policy contract. It does not imply policy
authoring/signing, authority lifecycle, persistent anti-rollback, trusted time,
or a capability/overall-verification upgrade.

Alpha.19 adds the separately versioned strict input contract
`offline-trust-policy-v1`. It is not a manifest, plan, bundle member, or signed
artifact schema. Policy-mode verification may add `trustBasis`,
`trustPolicyDigest`, and `trustReason` to the version-1 report; legacy no-trust
and `--trust-key` output omits them, preserving its serialized shape. Any
semantic expansion of accepted policy fields, algorithms, or status values
requires a new policy contract rather than permissive interpretation.

## Enum policy

- Verdicts, statuses, phases, methods, signals, coverage, and other ordinary wire enums are lowercase.
- Multiword ordinary enum values use hyphens.
- Stable error codes retain exact `UPPER_SNAKE_CASE` for compatibility with Appendix C and the domain error API.
- Enum comparison is case-sensitive.
- Producers MUST NOT normalize an unknown enum into a known value.

## Extensions

Manifest objects explicitly permitting `x-` fields use:

```text
x-<lowercase extension name>
```

An extension:

- is included in `manifestDigest`;
- has no core semantics unless a separately versioned adapter negotiates it;
- cannot weaken core validation, sandbox, capability, observation, policy, or verdict rules;
- must cause a blocked/unsupported outcome if a scenario requires its semantics and no implementation is present.

Generated artifacts do not accept arbitrary `x-` fields in any current strict
schema version.

## Stable errors

Error code meaning is backward-compatible public API. Text may improve, but a code is never repurposed.

Removing a code or changing when it is emitted requires a documented compatibility review. New codes require a generated-schema version that accepts them before producers emit them.

## Canonicalization compatibility

Canonicalization is part of the resolved-plan schema contract. A change that alters canonical bytes or a digest for the same semantic plan requires:

1. a new resolved-plan schema version;
2. a migration note;
3. old digest golden tests;
4. explicit freshness behavior for old evidence.

Implementations record exact adapter, observer, runner, and policy identities so behavioral changes cannot hide behind an unchanged plan.

## Deprecation

Before removing a public field or enum:

1. mark it deprecated in documentation;
2. retain validation and read support for the documented window;
3. provide a deterministic migration;
4. add compatibility fixtures;
5. change the version when removal occurs.

Alpha status shortens the support window but does not permit silent semantic change.
