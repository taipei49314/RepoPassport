# RFC-0004: Toolchain Identity Migration to Go 1.26.6

- Status: Accepted
- Authors: @taipei49314 (decision); drafted by the implementing agent
- Reviewers: None (owner approval only; no independent review claimed)
- Created: 2026-08-17
- Updated: 2026-08-17
- Target milestone: M0 / pre-v0.1.0
- Tracking issue: [#6](https://github.com/taipei49314/RepoPassport/issues/6)
- Supersedes: None (advances the frozen toolchain value fixed by RFC-0002)

## Summary

The repository's frozen Go toolchain identity advances from `go1.26.5` to
`go1.26.6` everywhere that identity is normative: ordinary CI, the
source-qualification workflow, the `RP-M0-QUAL-GO-VERSION` gate predicate,
and the receipt and tool-manifest contracts. The source-qualification receipt
and tool-manifest `schemaVersion` advance from `"1"` to `"2"` so readers can
distinguish the toolchain generations; schema and artifact file names keep
their existing `v1` lineage, because the `schemaVersion` field — not the file
name — is the version authority (`spec/versioning.md`: writers emit one
configured version and record it in every standalone artifact). Historical
evidence recorded under `go1.26.5` is history and is not rewritten.

## Motivation

govulncheck reports eight standard-library vulnerabilities present in
`stdlib@go1.26.5` and fixed in `stdlib@go1.26.6` (GO-2026-5026 among them).
Because RFC-0002 froze `Go 1.26.5` into gate 1's PASS predicate and the
receipt platform/controller contracts, and `TestCanonicalModuleIdentitySourceContract`
pins ordinary CI to the same version, every branch now fails the
vulnerability scan and no lane can reach `PASS` on a toolchain with known
fixed vulnerabilities. RFC-0002's own rule — changing a semantic predicate
requires a new schema version and an RFC — makes this migration an RFC-level
decision; this document is that decision.

## Goals

- Remove the known-fixed stdlib vulnerability exposure from every gate and CI
  surface.
- Keep the toolchain identity exact and machine-checked at `go1.26.6`.
- Let readers distinguish go1.26.6-generation receipts and tool manifests
  from the go1.26.5 generation by `schemaVersion` alone.

## Non-goals

- No change to gate IDs, ordering, timeouts, network modes, lanes,
  aggregation rules, or the attempt-tombstone contract (its `schemaVersion`
  stays `"1"`; it binds no toolchain identity).
- No repackaging or reinterpretation of historical Alpha evidence, container
  qualification records, or existing tombstones.
- No release authorization and no change to the scope of `RP-M0-QUAL`.
- No claim that `go1.26.6` is free of unknown vulnerabilities — only that the
  currently known stdlib findings are addressed.

## Normative proposal

- `RP-M0-QUAL-GO-VERSION` PASS predicate: exact single line for Go 1.26.6
  and the receipt OS/arch.
- Receipt contract: `platform.goVersion` and `controller.goVersion` are the
  constant `go1.26.6`; receipt `schemaVersion` is `"2"`.
- Tool-manifest contract: `goVersion` is `go1.26.6`; `schemaVersion` is
  `"2"`.
- Readers MUST reject `schemaVersion` `"1"` receipts and tool manifests as
  current inputs; those artifacts remain valid only as historical evidence
  through the commits that produced them.
- `.github/workflows/ci.yml` and
  `.github/workflows/source-qualification.yml` MUST pin
  `actions/setup-go` to `go-version` 1.26.6 exactly; the module-identity
  contract test enforces the ci.yml pin count.
- Schema files `source-qualification-receipt-v1.schema.json` and
  `source-qualification-tool-manifest-v1.schema.json` keep their names and
  encode the new constants; the RFC-0002 artifact file-name aggregate is
  unchanged.

## Failure behavior

Unchanged from RFC-0002: a toolchain that does not produce the exact
`go1.26.6` version line fails gate 1; a receipt or manifest carrying any
other `schemaVersion` or `goVersion` is `SOURCE_QUAL_RECEIPT_INVALID` /
manifest-invalid, never reinterpreted.

## Compatibility and history

The Alpha.33 release inventory, historical qualification records in
`docs/release.md` and `IMPLEMENTATION_STATUS.md`, and every existing attempt
tombstone remain untouched and continue to state `go1.26.5` truthfully as the
toolchain of their runs. Future toolchain advances repeat this RFC pattern:
new RFC, `schemaVersion` advance, exact new pin, no history rewrite.
