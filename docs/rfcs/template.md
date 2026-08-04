# RFC-NNNN: Title

- Status: Draft
- Authors:
- Reviewers:
- Created: YYYY-MM-DD
- Updated: YYYY-MM-DD
- Target milestone:
- Tracking issue:
- Supersedes:

## Summary

State the proposed decision in a few sentences. Include the user-visible and machine-contract outcome.

## Motivation

Describe the concrete problem, affected users, current failure mode, and why existing behavior is insufficient. Separate evidence from assumptions.

## Goals

- Goal one.
- Goal two.

## Non-goals

- Explicitly excluded behavior.
- Work deferred to a later milestone.

## Normative proposal

Use RFC 2119/8174 terms for requirements.

### Data model

List added, changed, or removed domain types and invariants.

### Wire contract

Provide exact JSON/YAML examples and field tables:

- field name;
- type;
- required/default behavior;
- enum values;
- normalization;
- error behavior;
- digest participation.

### State and verdict semantics

Define lifecycle and each affected verdict dimension independently. Include a deterministic decision table for aggregation.

### CLI behavior

Define commands, flags, defaults, stdout/stderr, structured output, and exit codes.

### Failure behavior

For each failure, specify the stable error code, retryability, evidence retained, cleanup behavior, and whether the result is fail, blocked, or inconclusive.

## Trust boundaries and security

Answer:

1. Which inputs are untrusted?
2. Which component produces the authoritative fact?
3. Can the workload influence or forge it?
4. Does this add a host mount, credential, network path, device, process privilege, or parser?
5. What happens when enforcement or observation is unavailable?
6. What data may leak into logs, reports, cache, or evidence?
7. How are path traversal, symlink escape, injection, resource exhaustion, and malicious output handled?

List security invariants that remain non-configurable.

## Privacy

Describe collection, redaction, retention, public-bundle inclusion, deletion, and telemetry effects. Do not claim perfect secret detection.

## Canonicalization and integrity

State:

- which fields participate in each digest;
- fields excluded to avoid self-reference;
- set versus ordered arrays;
- normalization rules;
- backward compatibility with existing golden digests.

## Compatibility and versioning

Identify all affected contracts:

- manifest `apiVersion`;
- generated `schemaVersion`;
- CLI;
- stable error codes;
- policy bundle;
- runner profile;
- adapter/observer API;
- evidence predicate.

Explain migration, deprecation, freshness, and downgrade behavior. Silent downgrade is forbidden.

## Implementation plan

Break work into independently reviewable changes. Name owning packages and ports without coupling the domain to infrastructure objects.

## Test and conformance plan

Include:

- unit tests;
- schema examples;
- golden fixtures and digests;
- property or fuzz tests;
- integration matrix;
- malicious/adversarial case;
- failure and cleanup paths;
- backward compatibility.

Define measurable acceptance criteria.

## Rollout and rollback

Describe feature negotiation, default state, release channel, observability, rollback trigger, and how rollback preserves stored artifacts.

## Alternatives considered

For each serious alternative, state advantages, disadvantages, security effect, and why it was not selected.

## Open questions

- Question requiring a decision.

## Decision record

Complete when accepted:

- Decision:
- Date:
- Approvers:
- Required follow-up:
- Known limitations:
