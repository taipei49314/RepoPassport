# RFC-0001: Canonical Go Module and Release Build Identity

- Status: Accepted
- Authors: @taipei49314
- Reviewers: None (author self-review only; no independent review claimed)
- Created: 2026-08-09
- Updated: 2026-08-09
- Target milestone: M0 / pre-v0.1.0
- Tracking issue: [#1](https://github.com/taipei49314/RepoPassport/issues/1)
- Supersedes: None

## Summary

RepoPassport will adopt the exact public repository origin,
`github.com/taipei49314/RepoPassport`, as its canonical Go module path.

The public Go schemas package will therefore be imported as
`github.com/taipei49314/RepoPassport/schemas`. Repository-owned source,
release linker symbols, Go build information, release qualification, and active
documentation MUST use the same exact, case-sensitive namespace.

This is an intentional pre-v0 breaking migration from
`github.com/repopass/repopass`. The implementation MUST NOT depend on a
redirect, compatibility module, forwarding package, or committed `replace`
directive for the legacy namespace.

JSON Schema identifiers under `https://schemas.repopass.dev/v1alpha1/` and
evidence predicate identifiers under `https://repopass.dev/` remain unchanged.
They are versioned protocol identities, not Go source import paths.

## Motivation

The only public repository controlled by the project is:

```text
https://github.com/taipei49314/RepoPassport
```

At the initial qualification baseline
`a297c034dcb6f13be48332c8ce752b184e105a55` and the RFC base
`f5a44d1d4b5229a1bf81398bac961b4aba81fcca`, `go.mod` declares:

```text
module github.com/repopass/repopass
```

The legacy prefix also appears in 141 Go source files and in the release
builder's `-X` linker target. README currently describes the public location as
a mirror and warns consumers not to treat it as a stable import path.

This creates four concrete failures:

1. the public repository and Go module identify different owners;
2. an external consumer cannot rely on one canonical import path for the
   public `schemas` package;
3. release binaries can embed a main module and main package that differ from
   their download origin;
4. a future module appearing under the uncontrolled legacy namespace could be
   mistaken for this project.

A clone-and-build success does not resolve these identity or supply-chain
ambiguities. The pre-v0 period is the appropriate time to perform an explicit,
breaking, atomic migration.

## Goals

- Make the public repository and Go module identity exact and consistent.
- Give external consumers one supported import path for the public `schemas`
  Go package.
- Make source, linker symbols, release binaries, portable verifier kits, and
  qualification checks agree on the same namespace.
- Reject legacy or ambiguous module identities before release publication.
- Preserve historical artifacts and all non-Go protocol identities exactly.
- Provide deterministic Linux and Windows conformance tests.

## Non-goals

- Acquiring, redirecting, or making claims about control of
  `github.com/repopass/repopass`.
- Publishing a compatibility module at the legacy path.
- Supporting both module paths simultaneously.
- Changing the manifest API, JSON Schema semantics, verdict aggregation,
  evidence predicates, trust policy, or stable runtime error codes.
- Rebranding or rebuilding historical Alpha artifacts.
- Closing the other M0 rows, M1-M7, or stable-release qualification.
- Treating a module-path string as proof of repository ownership, signer
  identity, or artifact trust.

## Normative proposal

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are interpreted as described by RFC 2119 and RFC 8174.

### Canonical identities

The following strings are normative and case-sensitive:

| Identity | Required value |
|---|---|
| Repository URL | `https://github.com/taipei49314/RepoPassport` |
| Go module path | `github.com/taipei49314/RepoPassport` |
| Public schemas import | `github.com/taipei49314/RepoPassport/schemas` |
| Full CLI main package | `github.com/taipei49314/RepoPassport/cmd/repopass` |
| Portable verifier main package | `github.com/taipei49314/RepoPassport/cmd/repopass-verify` |
| Release-kit helper main package | `github.com/taipei49314/RepoPassport/cmd/repopass-kit` |

A transport clone URL MAY end in `.git`; that suffix is not part of the Go
module identity.

The implementation MUST preserve the exact `RepoPassport` case. It MUST NOT
silently lowercase, case-fold, redirect, or normalize a different module path
into the canonical value.

The legacy prefix is:

```text
github.com/repopass/repopass
```

It MUST NOT occur in:

- the `go.mod` module directive;
- a committed `replace` or workspace directive;
- any Go import declaration;
- a release linker-symbol target;
- a workflow or script that builds project binaries;
- an active installation or import example;
- release executable build information.

It MAY occur in this RFC and in changelog/migration history solely to explain
the former identity.

### Data model

Implementation code SHOULD centralize the expected values in one small,
standard-library-only qualification package:

```go
type BuildIdentity struct {
    ModulePath  string
    MainPackage string
}
```

The validation invariant is exact equality. Prefix matches, case-insensitive
matches, suffix matches, redirects, inferred repository ownership, and empty
values are invalid.

The expected main package depends on the artifact:

| Artifact | Expected main package |
|---|---|
| `repopass` | `github.com/taipei49314/RepoPassport/cmd/repopass` |
| `repopass-verify` | `github.com/taipei49314/RepoPassport/cmd/repopass-verify` |
| host-only `repopass-kit` helper | `github.com/taipei49314/RepoPassport/cmd/repopass-kit` |
| verifier inside a portable kit | `github.com/taipei49314/RepoPassport/cmd/repopass-verify` |

All four use the same expected main module:

```text
github.com/taipei49314/RepoPassport
```

### Wire contract

This RFC adds no manifest, plan, verification, evidence, policy, CLI, JSON
Schema, or versioned public-receipt field. Module-identity results are CI/check
annotations, not a new wire artifact. Persisting them in a public receipt later
requires a separately reviewed, versioned schema and canonicalization contract.

Release identity is read from the standard Go build-information record using
`debug/buildinfo`. The normative mapping is:

| Go build-information field | Required value |
|---|---|
| `BuildInfo.Main.Path` | `github.com/taipei49314/RepoPassport` |
| `BuildInfo.Path` for full CLI | `github.com/taipei49314/RepoPassport/cmd/repopass` |
| `BuildInfo.Path` for verifier | `github.com/taipei49314/RepoPassport/cmd/repopass-verify` |
| `BuildInfo.Path` for host-only kit helper | `github.com/taipei49314/RepoPassport/cmd/repopass-kit` |

`BuildInfo.Main.Version` is not used to decide module identity because a local
exact-SHA qualification build may report `(devel)`. Product version remains
the separately injected and tested CLI version.

For a release-build check, every required full CLI, verifier, and host-only kit
helper executable MUST be built with `-buildvcs=true` and contain
`vcs.revision` exactly equal to the tested commit SHA and `vcs.modified`
exactly `false`. A missing,
duplicate, malformed, or different setting fails closed. The check log MUST
bind the tested commit SHA, tree SHA, and SHA-256 of every inspected executable.
These CI fields are not a versioned receipt. Satisfying the module-path check
alone does not establish exact-source eligibility.

Every source-list, test, and build command used by this check, including the
release builder and host-only helper build, MUST run with `GOWORK=off`.

The portable kit manifest already binds the verifier executable by size and
SHA-256. Consequently, validating the build information of the exact bound
executable transitively binds its module identity without adding a field to
the existing manifest schema.

### Source module conformance

From the exact checkout, with `GOWORK=off`, this command:

```text
go list -m -f '{{.Path}}'
```

MUST exit zero and write exactly one line containing:

```text
github.com/taipei49314/RepoPassport
```

Any additional line, alternate case, surrounding whitespace, legacy path,
workspace override, or non-zero exit is `MODULE_PATH_MISMATCH`.

Also with `GOWORK=off`, `go list -f '{{.ImportPath}}' ./...` MUST exit zero.
Every repository-owned package path MUST be either the exact module path or
begin with the exact module path followed by `/`.

An AST scan that includes build-tagged Go files MUST reject an import equal to
the exact legacy path or beginning with the legacy path followed by `/`. It
MUST also reject any ASCII-case-insensitive match of a canonical or legacy
segment-prefix unless the canonical prefix is byte-exact. Any committed
`go.mod` or `go.work` replacement involving either namespace is rejected.
Package-list failures emit `PACKAGE_PATH_MISMATCH`; an observed legacy prefix
also emits `LEGACY_MODULE_REFERENCE`.

### External `schemas` import

The supported public Go import becomes:

```go
import "github.com/taipei49314/RepoPassport/schemas"
```

Conformance MUST create a temporary consumer whose module path is outside the
RepoPassport namespace, for example:

```text
example.invalid/repopass-schema-consumer
```

The consumer MUST:

1. require the canonical RepoPassport module;
2. set `GOWORK=off` and use a local replacement to the exact checkout only to
   route the RepoPassport module under test;
3. import the canonical `/schemas` package;
4. call at least one exported validator;
5. pass `go test`;
6. require `go list -m -f '{{.Path}}'
   github.com/taipei49314/RepoPassport` to emit exactly the canonical path;
7. show exactly one RepoPassport module in `go list -m all`, using the canonical
   path.

The local replacement is test transport only. No `replace` directive may be
committed to RepoPassport or recommended to normal consumers.

JSON Schema `$id` values such as
`https://schemas.repopass.dev/v1alpha1/verification.schema.json`, their
relative `$ref` values, and attestation predicate identifiers MUST remain
unchanged. Changing a Go package path MUST NOT be used to reinterpret or
version these wire contracts.

### Release build metadata

The release builder MUST use the canonical linker target:

```text
github.com/taipei49314/RepoPassport/internal/cli.Version
```

Before publishing `dist` or executing the host-only kit helper, the builder or
its qualification harness MUST parse every full CLI, verifier, and helper
executable with `debug/buildinfo` and validate the exact module/main-package
pair and source settings.

The executable identity scan MUST reject the legacy prefix in
`BuildInfo.Path`, `BuildInfo.Main.Path`, `BuildInfo.Main.Replace.Path`, every
dependency `Path` or `Replace.Path`, and every build-setting key or value. It
MUST also require `BuildInfo.Main.Replace` to be nil. It MUST NOT trust filename
or version text as a substitute for these checks.

For each portable verifier kit, qualification MUST:

1. validate the kit's existing exact inventory and hashes;
2. extract the verifier as bounded untrusted input;
3. parse its Go build information;
4. require the canonical verifier identity;
5. delete the extraction directory on success and failure.

A binary with correct filename and CLI version text but wrong, missing, or
unreadable build identity MUST be rejected. Recomputing its checksum or
repacking a kit MUST NOT make the module-identity gate pass.

### State and verdict semantics

Module identity is a source/release qualification dimension. It does not alter
the six RepoPassport verification verdict dimensions.

| Observation | Module qualification |
|---|---|
| Every required source, consumer, binary, and kit check passes | `PASS` |
| Module mismatch | `FAIL` / `MODULE_PATH_MISMATCH` |
| Repository package/import path is outside the exact canonical prefix | `FAIL` / `PACKAGE_PATH_MISMATCH` |
| Main-package mismatch | `FAIL` / `MAIN_PACKAGE_PATH_MISMATCH` |
| Legacy reference in module/workspace data, Go imports, build scripts, workflows, active documentation, or executable identity | `FAIL` / `LEGACY_MODULE_REFERENCE` |
| Missing or unreadable Go build information | `FAIL` / `BUILD_INFO_UNREADABLE` |
| Embedded source revision is absent or differs from the tested SHA | `FAIL` / `SOURCE_REVISION_MISMATCH` |
| Embedded modified state is absent, malformed, duplicated, or not false | `FAIL` / `SOURCE_TREE_DIRTY` |
| Canonical external `schemas` consumer does not compile | `FAIL` / `EXTERNAL_IMPORT_FAILED` |
| Required artifact or test was not executed | `NOT_RUN` / `REQUIRED_CHECK_NOT_RUN` |

The implementation PR MUST freeze the required check set before producing a
result. Aggregation is deterministic and fail-first:

1. if any required check is `FAIL`, the aggregate is `FAIL`;
2. otherwise, if any required check is `NOT_RUN`, the aggregate is `NOT_RUN`;
3. otherwise, and only if every required check is `PASS`, the aggregate is
   `PASS`.

When multiple results apply, only identical tuples are deduplicated. Results
are ordered by `(result-rank, label, artifact-or-check-ID)`, where bytewise
result rank is fixed as `FAIL=0`, `NOT_RUN=1`, and `PASS=2`; label and ID are
then compared bytewise. The potentially public CI run log also retains the
first failing observation in execution order and applies the same redaction as
annotations. A later observation MUST NOT hide that first failure or convert
`FAIL` into `NOT_RUN`.

If an artifact's build information is unreadable, that artifact emits only
`BUILD_INFO_UNREADABLE`; the implementation MUST NOT derive source-revision,
dirty-state, module, main-package, or legacy labels from fields it could not
parse. Independently observed source-scan failures remain separate results.

A module-identity `PASS` MUST NOT upgrade functional, capability,
reproducibility, cleanup, evidence, freshness, or overall verification.

### CLI behavior

Existing CLI commands, flags, stdout, stderr, structured-output
`schemaVersion`, and exit codes are unchanged.

In particular, `version` and `version --json` continue to report the product
version according to their current contract. Release qualification reads Go
build information directly rather than adding unversioned fields to CLI
structured output.

No public module-identity inspection command is introduced by this RFC.

### Failure behavior

The following qualification check labels are exact implementation contracts
under this RFC. They are not domain/CLI error-schema members and are not fields
in a persisted or public evidence artifact:

| Code | Condition | Retryable | Result |
|---|---|---:|---|
| `MODULE_PATH_MISMATCH` | Declared or embedded module is not exact canonical value | No | Fail |
| `PACKAGE_PATH_MISMATCH` | Repository-owned package/import is outside the exact canonical prefix | No | Fail |
| `MAIN_PACKAGE_PATH_MISMATCH` | Embedded main package is not the artifact's exact expected package | No | Fail |
| `LEGACY_MODULE_REFERENCE` | Legacy prefix occurs on any active identity surface listed above | No | Fail |
| `BUILD_INFO_UNREADABLE` | Required binary has absent, malformed, or unreadable Go build information | No | Fail |
| `SOURCE_REVISION_MISMATCH` | `vcs.revision` is absent or differs from the tested commit SHA | No | Fail |
| `SOURCE_TREE_DIRTY` | `vcs.modified` is absent, malformed, duplicated, or not `false` | No | Fail |
| `EXTERNAL_IMPORT_FAILED` | External `schemas` consumer or its exact module-list check fails | No | Fail |
| `REQUIRED_CHECK_NOT_RUN` | Required check or artifact was not executed or produced | Yes | Not run |

Diagnostics MAY include the expected identity, inspected artifact name, and
actual non-secret identity string. They MUST NOT include environment secrets,
credentials, module-proxy credentials, or arbitrary binary bytes.

A failed or not-run check retains its bounded, potentially public CI log,
emits only its exact check label plus allowlisted non-secret identity fields in
the CI annotation, removes temporary consumer/extraction directories, and
makes the tested source or artifact release-ineligible. The annotation is not
a public evidence bundle. A mismatch never becomes `blocked` or `inconclusive`
merely because another identity was observed.

## Trust boundaries and security

Repository source, module declarations, dependency paths, build scripts,
binaries, kit members, and build-information records are untrusted until
validated.

The Go toolchain produces executable build information. The qualification
controller—not the workload and not CLI version text—decides whether it matches
the canonical identity.

A module string is not a trust anchor. This RFC does not prove control of a
GitHub account, authenticate a release signer, establish freshness, or replace
checksum, SBOM, provenance, Sigstore/OIDC, and policy verification.

The uncontrolled legacy namespace MUST be treated as a different and untrusted
module. No redirect or similarity of package contents may authorize it.

The external-consumer test may use only the exact local checkout through a
temporary `replace` for the RepoPassport module. CI MUST pre-download and verify
dependencies in its controlled setup phase, then run the consumer with
`GOPROXY=off` and `GOWORK=off`. A cache miss fails the consumer check rather
than opening a network path. Dependency authentication during setup continues
to use Go's configured public checksum behavior.

Build-information and kit parsing MUST be bounded. Kit extraction MUST retain
the existing regular-file, path, size, inventory, and cleanup protections.
Symlinks, traversal, duplicate members, malformed archives, and oversized
members remain rejected before build identity is trusted.

Security invariants that remain non-configurable:

- exact, case-sensitive identity equality;
- no legacy alias or silent fallback;
- no committed `replace` workaround;
- no inference of trust from module identity;
- no publication when required build identity is unreadable;
- no change to workload verdict authority.

## Privacy

Module path, main package, repository URL, artifact filename, digest, size, Go
version, and source revision are public build metadata.

CI annotations and logs MUST NOT collect or emit module-proxy credentials, Git
credentials, environment secrets, private filesystem paths, or raw executable
bytes. CI logs are treated as potentially public, receive the same redaction
as annotations, and use the CI platform's configured bounded retention.

This RFC defines no public evidence or receipt schema. Any later public bundle
MUST use a separately reviewed allowlist, schema version, canonicalization, and
privacy contract. Temporary consumer and extraction directories are deleted
after the check. This RFC adds no telemetry.

## Canonicalization and integrity

The canonical module and package strings are compared as exact UTF-8/ASCII
bytes. There is no case folding, URL decoding, path cleaning, redirect
following, or trailing-slash normalization.

These identity strings do not enter existing manifest, plan, verification,
policy, attestation, or evidence digests. Their protocol golden digests
therefore remain unchanged.

The module-path change necessarily changes Go source bytes, executable bytes,
source-tree digests, SBOM package identity, release checksums, and any artifact
digest that binds those bytes. New evidence MUST be produced for the new exact
source. Historical Alpha digests remain valid only for their original artifacts
and identity.

No arrays or set-ordering rules are introduced.

## Compatibility and versioning

This migration affects the Go module/import contract and release build
identity. It does not affect the other independently versioned contracts.

| Contract | Effect |
|---|---|
| Manifest `apiVersion` | No change |
| Generated artifact `schemaVersion` values | No change |
| CLI behavior and structured output | No change |
| Stable runtime error codes | No change |
| Policy bundle | No change |
| Runner profile | No change |
| Adapter/observer API | No change |
| Evidence predicate | No change |
| Go module/import path | Intentional pre-v0 breaking change |
| Release binary build information | Changes to canonical public namespace |

Consumers using the old Go import path must update imports and `require`
directives. No compatibility window is offered because the project does not
control the legacy namespace and cannot safely guarantee a forwarding module.

A reader MUST NOT reinterpret historical artifacts as having the new module
identity. Existing strict readers and historical artifacts remain available
under their original versions and digests.

The release carrying this change must describe it in `CHANGELOG.md` as a
pre-alpha breaking migration. The normal release process decides the next
pre-release number; the module decision does not authorize a stable release.

Silent downgrade to the old path is forbidden.

## Implementation plan

The work is deliberately split into an RFC-only PR followed by one atomic
implementation PR.

1. **RFC-only PR**
   - add this RFC;
   - link the tracking issue;
   - obtain an explicit maintainer decision;
   - do not change module or implementation files.

2. **Atomic module implementation PR**
   - change the `go.mod` module directive;
   - mechanically update every repository-owned Go import;
   - update the release builder's linker symbol;
   - add a standard-library-only identity validator and table/property tests;
   - add an early scan for legacy executable identity references;
   - add the external `schemas` consumer test;
   - add release binary and portable-kit build-information checks;
   - update README, versioning/release documentation, implementation status,
     and changelog;
   - preserve JSON Schema and evidence protocol identifiers;
   - run complete Linux and Windows gates.

The implementation PR MUST NOT be split such that `go.mod` and imports are
temporarily inconsistent on the default branch. It MUST NOT include unrelated
M1-M7 implementation.

## Test and conformance plan

### Unit tests

- Accept only the exact canonical module path.
- Accept only the artifact's exact expected main package.
- Reject empty, legacy, lowercase, case-varied, suffix-appended,
  trailing-slash, URL-form, and lookalike paths.
- Reject missing or malformed build information.
- Assert qualification check labels and their fail-first ordering
  deterministically.
- Property test that arbitrary path strings pass only on exact equality.

### Source conformance

- Parse `go.mod` and require the exact module directive.
- With `GOWORK=off`, require `go list -m -f '{{.Path}}'` to emit exactly one
  canonical module-path line.
- With `GOWORK=off`, require every `go list -f '{{.ImportPath}}' ./...` result
  to use the exact canonical prefix.
- Reject committed `go.mod` or `go.work` replacements involving either
  namespace.
- Parse all Go files, including build-tagged files; reject legacy
  segment-prefix imports and non-byte-exact case variants of canonical or
  legacy segment-prefixes.
- Inspect release scripts and workflows for the exact canonical linker target.
- Check active documentation examples separately from allowed historical prose.
- Run the identity gate before release publication.

### External package conformance

- Create a separate temporary module.
- Import the canonical `/schemas` package.
- Invoke an exported strict validator.
- Run `go test` and inspect `go list -m all`.
- Confirm no RepoPassport module appears under the legacy path.
- Remove the temporary module on all paths.

### Release conformance

- Build Linux/amd64 and Windows/amd64 full/verifier executables and the
  host-only kit helper used on each qualification host.
- Parse each artifact with `debug/buildinfo`.
- Validate exact main module, main package, tested commit SHA, clean
  source setting, and absence of legacy identity records.
- Validate each portable kit, then validate the embedded verifier identity.
- Substitute a binary built with a legacy or wrong module identity and require
  deterministic rejection even when its filename/version text is plausible.
- Rebuild from two clean source paths and compare bytes.
- Verify checksums after the identity check.

### Regression gates

Run at minimum:

```text
go mod download
go mod verify
go mod tidy -diff
gofmt check
go vet ./...
go test -count=1 ./...
go test -count=1 -tags=integration ./internal/cli -run ^$
pinned govulncheck module gate
pinned govulncheck source/test gate
release build and build-information validation
external schemas consumer test
```

Required identity and external-consumer tests run on both Linux and Windows.

Existing manifest/schema examples, golden protocol digests, verdict tests,
malicious workload fixtures, and strict unknown-field tests must remain green.
No protocol golden should be regenerated merely because the Go import path
changed.

### Measurable acceptance

`RP-M0-MODULE` is used here only as the release program's tracking label; this
RFC does not create or serialize an acceptance-registry entry. That row may
become `PASS` only when all source, external-consumer, release binary,
portable-kit, documentation, and exact merged default-branch SHA checks above
pass with no required skip.

## Rollout and rollback

### Rollout

1. Merge the accepted RFC.
2. Apply the module/import/linker migration atomically on a short-lived branch.
3. Run local source and external-consumer checks.
4. Build and inspect release artifacts without publishing them.
5. Open the focused implementation PR.
6. Require Linux and Windows identity checks to pass.
7. Merge only after the scoped checks are green.
8. Re-run the complete check set on the exact merged default-branch SHA; a PR
   run or pre-merge artifact cannot qualify that SHA.
9. Publish the migration only in the next authorized pre-alpha release.

There is no feature flag or dual-path negotiation. The migration is atomic.

CI should expose the exact check label and inspected artifact while redacting
environment details. This annotation is not a versioned public receipt. Any
legacy-reference or build-information failure blocks release publication.

### Rollback

Before any release publication, rollback is a full revert of the atomic
implementation PR. A partial rollback that restores only `go.mod`, imports,
linker symbols, or documentation is forbidden.

Rollback triggers include:

- canonical external `schemas` import failure;
- any repository-owned package retaining the legacy path;
- release build-information mismatch;
- release-kit identity validation failure;
- deterministic-build regression caused by the migration.

Rollback does not delete, overwrite, or rebrand stored source receipts,
binaries, kits, checksums, or historical Alpha evidence.

After rollback, `RP-M0-MODULE` MUST return to `FAIL` or `NOT_RUN`, and no release
may publish until a new accepted namespace decision and all required checks
pass on the new exact merged default-branch SHA.

After a pre-alpha artifact containing the migration has been published, its tag
and assets MUST NOT be overwritten. A defect is corrected in a new pre-alpha
version with explicit migration notes. The project MUST NOT restore the
uncontrolled legacy namespace as a compatibility shortcut.

## Alternatives considered

### Keep `github.com/repopass/repopass`

Advantage: no source import rewrite.

Disadvantages: the path does not match the controlled public origin; external
imports and release metadata remain ambiguous; future content at the legacy
namespace could be mistaken for this project.

Security effect: preserves an uncontrolled identity dependency.

Decision: rejected.

### Wait for an owner or repository transfer

Advantage: could preserve the old import path if the exact organization and
repository became controlled.

Disadvantages: no such control is current evidence; it leaves M0 blocked on an
external assumption and keeps published source internally inconsistent.

Security effect: encourages redirect/control assumptions without proof.

Decision: rejected.

### Support both paths with a compatibility module or forwarding packages

Advantage: old consumers might continue to compile.

Disadvantages: creates duplicate module/package identities, complicates
`internal` imports, SBOMs, build information, vulnerability scans, and release
qualification.

Security effect: makes substitution and provenance ambiguity harder to detect.

Decision: rejected.

### Commit a `replace` directive

Advantage: can make selected local builds appear to work.

Disadvantages: a `replace` is local build routing, not a canonical public
identity; consumers do not inherit it reliably.

Security effect: masks rather than fixes the namespace mismatch.

Decision: rejected.

### Lowercase the GitHub repository path

Advantage: visually resembles common Go module conventions.

Disadvantages: it does not exactly match the published repository spelling and
requires case normalization assumptions across GitHub, proxies, filesystems,
and evidence.

Security effect: weakens exact identity comparison.

Decision: rejected.

### Change JSON Schema `$id` values to GitHub URLs

Advantage: source and protocol URLs would look similar.

Disadvantages: JSON Schema identifiers and Go import paths are independent
versioned contracts. Changing them would cause unnecessary schema/digest
migration and conflate source hosting with protocol identity.

Security effect: risks silent schema reinterpretation.

Decision: rejected.

## Open questions

No open question blocks the namespace decision.

The normal release process will choose the first pre-alpha version carrying the
migration. That choice does not alter this RFC and does not authorize stable
promotion.

## Decision record

Complete when accepted:

- Decision: Accept `github.com/taipei49314/RepoPassport` as the canonical Go
  module and source namespace, with one atomic pre-v0 migration.
- Date: 2026-08-09
- Approvers: @taipei49314 (repository owner and RFC author; self-approval,
  no independent review claimed)
- Required follow-up:
  - atomic module implementation PR;
  - external `schemas` consumer conformance;
  - release build-information checks;
  - merged-SHA module-identity check and, if later specified, a separately
    versioned receipt.
- Known limitations:
  - module identity is not repository-owner or signer authentication;
  - historical artifacts retain their old module identity;
  - this decision does not close the other M0 rows, M1-M7, or stable release
    qualification.
