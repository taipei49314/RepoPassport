# Status, Verdict, and Error Model

All status and verdict values are lowercase wire enums. Stable error codes are the sole exception and retain `UPPER_SNAKE_CASE`.

## Run lifecycle

Lifecycle records orchestration progress, not verification success:

```text
created
resolving
preflight
ready
preparing-sandbox
executing
observing
evaluating
finalizing
completed
cancelled
expired
```

A terminal `completed` lifecycle may contain any verdict. `cancelled` and `expired` are lifecycle states and do not substitute for functional or freshness values.

## Functional verdict

```text
pass
fail
blocked
inconclusive
```

- `pass`: every required assertion ran and passed, and evidence is sufficient to decide.
- `fail`: the scenario executed validly and at least one required functional assertion failed.
- `blocked`: a runtime, runner feature, dependency, policy prerequisite, or other required condition prevented valid execution from starting.
- `inconclusive`: execution started, but timeout, truncation, observer/driver failure, or incomplete evidence prevents a trustworthy functional decision.

`flaky` is not a functional value.

## Capability verdict

```text
conforming
warning
nonconforming
incomplete
```

- `conforming`: required enforcement and observation coverage are present and no capability mismatch was found.
- `warning`: only non-required coverage or declared-not-observed differences remain.
- `nonconforming`: a trusted observer found undeclared or forbidden behavior.
- `incomplete`: required coverage is unavailable or incomplete.

## Reproducibility verdict

```text
stable
flaky
not-reproducible
not-tested
```

- `stable`: the configured repeat and matching threshold was met with fresh sandboxes and identical plan inputs.
- `flaky`: repeated results disagree but no deterministic failure dominates.
- `not-reproducible`: the required repetition contract was attempted and did not meet its threshold.
- `not-tested`: only one run was requested/completed or repetition was not evaluated.

## Cleanup verdict

```text
clean
allowed-residue
undeclared-residue
not-tested
```

`clean` requires controller confirmation that the complete process tree and sandbox resources are gone. A missing cleanup observer is `not-tested`, never `clean`.

## Evidence state

```text
none
unsigned
self-signed
maintainer-ci-signed
public-runner-signed
enterprise-signed
tampered
untrusted-signer
```

Signature validity and signer trust are separate checks even though this alpha schema records their aggregate evidence state. `unsigned` may provide internal digest consistency but no external identity.

## Freshness

```text
current
source-changed
plan-changed
policy-changed
runner-changed
expired
```

Any source, manifest, plan, image, adapter, observer, policy, runner-profile, or configured-age change makes previous evidence non-current.

## Assertion status

```text
passed
failed
blocked
inconclusive
```

An assertion result records its ID, type, required flag, expected value, actual value, evidence references, optional repeat index, and duration. Assertion content from the workload is untrusted until the external journey driver constructs this record.

## Overall display status

Overall is a deterministic convenience projection. The individual dimensions remain authoritative. Apply the following first-match table:

| Priority | Condition | Overall |
|---:|---|---|
| 1 | Evidence is `tampered` or `untrusted-signer` | `nonconforming` |
| 2 | Freshness is not `current` | `stale` |
| 3 | Functional is `blocked` | `blocked` |
| 4 | Functional is `inconclusive` | `inconclusive` |
| 5 | Functional is `fail` | `failed` |
| 6 | Capability is `nonconforming` or cleanup is `undeclared-residue` | `nonconforming` |
| 7 | Capability is `incomplete`, reproducibility is `flaky`, reproducibility is `not-reproducible`, or cleanup is `not-tested` | `inconclusive` |
| 8 | Functional is `pass`, capability is `warning`, cleanup is `clean` or `allowed-residue` | `verified-with-warnings` |
| 9 | Functional is `pass`, capability is `conforming`, cleanup is `allowed-residue` | `verified-with-warnings` |
| 10 | Functional is `pass`, capability is `conforming`, cleanup is `clean`, but reproducibility is `not-tested` or evidence is `none`, `unsigned`, or `self-signed` | `verified-with-warnings` |
| 11 | Functional is `pass`, capability is `conforming`, cleanup is `clean`, freshness is `current`, and no earlier condition matches | `verified` |

The case `functional: pass` plus `capability: nonconforming` is therefore `overall: nonconforming`.

## Error object

A stable error contains:

```json
{
  "schemaVersion": "1",
  "code": "UNDECLARED_NETWORK_DESTINATION",
  "phase": "run",
  "severity": "high",
  "message": "An undeclared network destination was observed.",
  "evidenceRefs": ["network:3"],
  "suggestion": "Declare the destination or remove the runtime connection.",
  "retryable": false
}
```

`code` is public API. Messages and suggestions may improve without changing code semantics. CLI, JSON, HTML, CI, and integrations use the same code.

The complete code enum is normative in `schemas/error.schema.json` and is grouped semantically as:

- source acquisition and snapshot;
- manifest validation;
- plan resolution and drift;
- runner, sandbox, limit, and timeout;
- phase execution, readiness, journey, and cleanup;
- capability mismatches;
- observer and nondeterminism;
- evidence, attestation, freshness, and signing;
- policy;
- internal error and cancellation.

Unknown future codes require a schema/API version change or an explicitly negotiated extension. A consumer MUST NOT rewrite one stable error code into another merely to alter exit behavior.

For the Alpha.19 local attestation path, `ATTESTATION_INVALID` means canonical bundle,
protected-content, embedded verification-integrity, key binding, or signature
validation failed. `ATTESTATION_UNTRUSTED` means the signature is valid but an
explicit trusted SPKI key is absent, rejected, or unavailable, or the selected
offline policy is unavailable, invalid, `revoked`, or `not-listed`. A policy
raw-byte pin mismatch is `EVIDENCE_DIGEST_MISMATCH`. `SIGNING_FAILED`
covers local private-key syntax/type/permission/DACL/link/path safety or the
signing operation. Opt-in trusted and pinned local freshness replay emits
`EVIDENCE_STALE` only for a stable source, policy, plan, or bounded runner
profile mismatch. Source, plan, runner, or cancellation uncertainty is
`unknown` under the corresponding existing operational code and MUST NOT be
reported stale. Without opt-in, freshness remains `not-evaluated`.

Alpha.14 additionally defines `EVIDENCE_PRIVACY_BLOCKED` for the bounded
`minimal-public-v1alpha2` gate. It is severity `high`, exits 7, publishes no
artifact, and serializes only fixed-safe policy/rule/surface/count metadata.
Signature/protected-content failure retains precedence as
`ATTESTATION_INVALID`; privacy evaluation precedes either optional trust
mechanism.

Alpha.15 uses `MANIFEST_INVALID`/exit 2 for malformed `--spdx` flag shape and
`EVIDENCE_BUILD_FAILED`/exit 1 for sealed-selection mismatch or bounded
attachment read/profile/canonicalization failure. Attachment privacy rejection
remains `EVIDENCE_PRIVACY_BLOCKED`/exit 7. These errors use fixed-safe metadata
and MUST NOT echo a path, source bytes, rejected value, dynamic key, or key
material.
