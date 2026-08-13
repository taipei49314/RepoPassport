# RFC-0003: Machine-Verifiable Acceptance Registry and Current-Source Evaluation

- Status: Accepted
- Authors: @taipei49314
- Reviewers: None (author self-review only; no independent review claimed)
- Created: 2026-08-13
- Updated: 2026-08-13
- Target milestone: M0 / pre-v0.1.0
- Tracking issue: [#15](https://github.com/taipei49314/RepoPassport/issues/15)
- Supersedes: None

## Summary

RepoPassport will publish one canonical, versioned acceptance registry that
freezes the complete roadmap scope as exactly 37 required `RP-*` rows. A
strict validator will reject a missing, duplicate, reordered, renamed, or
unknown row and will validate every row's milestone, applicable surface,
criterion, and evaluation policy.

The tracked registry is a normative catalogue. It deliberately contains no
claim about the Git commit or tree that contains it. A separate canonical
acceptance evaluation is derived at workflow runtime and binds the registry
digest, exact repository commit, Git tree, workflow run, required-check
results, per-row status, and deterministic roll-up. This separation avoids an
impossible self-reference in which a tracked file would need to contain the
hash of the Git tree that is changed by that file.

A structurally valid evaluation may honestly be incomplete. The ordinary CI
gate succeeds when the registry and evaluation are canonical, exact-set,
internally consistent, and do not overstate evidence. It does not require all
37 rows to pass. A distinct completion check fails unless every required row
is `PASS`. Neither check creates external authority, release approval, a tag,
or a GitHub Release.

## Motivation

RepoPassport has machine-readable contracts for manifests, verifications,
release indexes, trust policies, and current-source qualification. It does not
have a single machine-readable contract for the full M0--M7 acceptance scope.
The active roadmap names baseline, milestone, release-schema, and external
qualification rows, but a human-maintained Markdown checklist can omit or
rename a row without a parser noticing.

That creates five concrete risks:

1. progress can be overstated by silently shrinking the set of required rows;
2. a skipped or blocked row can be rendered as a successful overall check;
3. historical evidence can be presented as current-source evidence;
4. producer-owned CI or a GitHub artifact can be mistaken for independent
   external approval; and
5. a tracked status file that embeds its own commit or tree would require an
   unattainable hash fixed point.

The current source has scoped exact-main evidence for canonical module and
release identity and for Docker and Podman healthy journeys. It also has an
honest current-source qualification blocker. The registry must preserve those
facts without promoting incomplete M2--M7 or external qualification work.

## Goals

- Freeze the full roadmap as one exact ordered set of 37 required identifiers.
- Make every row's milestone, applicable surface, criterion, and evaluation
  policy machine-readable and digest-bound.
- Produce a canonical runtime evaluation bound to one exact commit, tree, and
  workflow attempt without embedding a self-referential source hash.
- Distinguish structural validity from roadmap completion.
- Reject missing, duplicate, unknown, reordered, skipped-as-pass, stale, or
  cross-subject evidence.
- Keep producer-owned CI, historical evidence, and external acceptance as
  distinct evidence classes.
- Preserve incomplete and blocked states without weakening product verdicts.

## Non-goals

- Closing M0 as a whole, M1 as a whole, or any M2--M7 milestone.
- Closing `RP-M0-QUAL` while its authenticated history, immutable application,
  and Windows network-isolation prerequisites remain unavailable.
- Creating an RC, stable tag, GitHub Release, or release promotion approval.
- Treating a workflow result, GitHub artifact, checksum, self-signature,
  same-workflow replay, or registry digest as external authority.
- Replacing RFC-0002 source qualification or any product verdict dimension.
- Authenticating GitHub, a runner, a publisher, time, or evidence retention.
- Embedding live API results, credentials, free-form logs, or host paths in the
  tracked registry.

## Normative proposal

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are interpreted as described by RFC 2119 and RFC 8174.

### Contract files

The implementation MUST add and maintain these public files:

| Path | Role |
|---|---|
| `acceptance-registry.json` | Canonical normative 37-row catalogue |
| `schemas/acceptance-registry-v1.schema.json` | Strict registry shape |
| `schemas/acceptance-evaluation-v1.schema.json` | Strict runtime evaluation shape |

`acceptance-registry.json` MUST be canonical UTF-8 JSON with no BOM or
trailing newline. It MUST NOT contain a source revision, tree, workflow run,
row status, evidence result, timestamp, URL, or digest of itself.

An `acceptance-evaluation-v1.json` file is a derived workflow artifact. It
MUST NOT be committed as a claim about the commit that contains it. GitHub
artifact transport is explicitly untrusted and does not increase its
authority.

### Registry wire contract

The registry top level contains exactly these members:

| Field | Type | Exact rule |
|---|---|---|
| `artifactType` | string | `repopass-acceptance-registry` |
| `product` | string | `repopass` |
| `rows` | array | Exactly the 37 rows below, in the listed order |
| `schemaVersion` | string | `1` |

Each row contains exactly:

| Field | Type | Rule |
|---|---|---|
| `appliesTo` | string array | Nonempty, unique, strict ordinal order, only the surface enum below |
| `criterion` | string | Printable ASCII, 1--512 bytes, byte-exact value frozen below |
| `evaluation` | object | Exact evaluation policy defined below |
| `id` | string | Exact stable identifier from the 37-row table |
| `milestone` | string | Exact value from the table |
| `required` | boolean | MUST be `true` |

The `appliesTo` enum is:

```text
docker-linux-amd64
external-review
github
hosted-runner
linux-amd64
plugin
podman-linux-amd64
release
repository
ui
windows-amd64
```

The milestone enum is `BASELINE`, `M0`, `M1`, `M2`, `M3`, `M4`, `M5`,
`M6`, `M7`, `RELEASE`, or `QUALIFICATION`.

### Exact required row set

The order in this table is normative. A semantic set comparison is not
sufficient because the canonical registry bytes and review order are also
frozen.

| Ordinal | ID | Milestone | Applies to | Criterion |
|---:|---|---|---|---|
| 1 | `RP-B00` | `BASELINE` | `github`, `repository` | The baseline revision equals the live default branch, or default-branch drift is recorded and the baseline is recomputed. |
| 2 | `RP-B01` | `BASELINE` | `linux-amd64`, `repository`, `windows-amd64` | Source gates pass on their first attempt; public output and receipts remain outside the repository and contain no secret. |
| 3 | `RP-B02` | `BASELINE` | `docker-linux-amd64`, `podman-linux-amd64` | Current-source container evidence and historical Alpha evidence are classified without presenting historical evidence as current. |
| 4 | `RP-B03` | `BASELINE` | `docker-linux-amd64`, `podman-linux-amd64`, `repository` | The source worktree is clean before and after the baseline, with no process, container, network, or volume residue. |
| 5 | `RP-B04` | `BASELINE` | `docker-linux-amd64`, `podman-linux-amd64` | Healthy results remain capability INCOMPLETE and overall INCONCLUSIVE until the required observations exist. |
| 6 | `RP-M0-CORPUS` | `M0` | `linux-amd64`, `repository`, `windows-amd64` | The complete fixture matrix and frozen fuzz or property seeds pass on Linux and Windows build paths, and malicious fixtures fail closed. |
| 7 | `RP-M0-MODULE` | `M0` | `linux-amd64`, `release`, `repository`, `windows-amd64` | Clone, build, import, module metadata, and release assets use one exact canonical repository namespace. |
| 8 | `RP-M0-QUAL` | `M0` | `linux-amd64`, `repository`, `windows-amd64` | The current source archive, required tests, and receipts bind one exact source revision and tree without repackaging historical Alpha evidence. |
| 9 | `RP-M0-SPEC` | `M0` | `linux-amd64`, `repository`, `windows-amd64` | Every public schema, specification, and reference behavior has machine-readable conformance coverage and unknown semantics fail closed. |
| 10 | `RP-M1-JOURNEY` | `M1` | `docker-linux-amd64`, `podman-linux-amd64` | CLI and HTTP healthy journeys pass functionally, remain reproducibly stable, and clean up on every supported Docker and Podman tuple. |
| 11 | `RP-M2-COVERAGE` | `M2` | `docker-linux-amd64`, `podman-linux-amd64` | Every required observer category reaches its normative high or complete coverage and gap or overflow fixtures remain incomplete. |
| 12 | `RP-M2-MATRIX` | `M2` | `docker-linux-amd64`, `podman-linux-amd64` | Docker and Podman each have current exact-source clean-VM evidence with no required skip or retry laundering. |
| 13 | `RP-M2-RESIDUE` | `M2` | `docker-linux-amd64`, `podman-linux-amd64` | Success, timeout, cancellation, crash, termination-resistant, and early-exit paths restore the after-inventory to the baseline. |
| 14 | `RP-M2-VERDICT` | `M2` | `docker-linux-amd64`, `podman-linux-amd64` | At least one healthy Node and Python profile honestly reaches capability CONFORMING and overall VERIFIED while adversarial gaps do not. |
| 15 | `RP-M3-IDENTITY` | `M3` | `external-review`, `release` | Accepted evidence is authorized by external identity and policy; self-signed, unknown, revoked, or stale signers are not accepted. |
| 16 | `RP-M3-INTEGRITY` | `M3` | `external-review`, `release` | Removal, rename, remint, signature, key, policy, source, and SBOM substitution all fail closed. |
| 17 | `RP-M3-PORTABLE` | `M3` | `linux-amd64`, `release`, `windows-amd64` | The release verifier kit validates the exact bundle on two clean operating systems without the producer worktree. |
| 18 | `RP-M3-PRIVACY` | `M3` | `release`, `repository` | Every public file is typed and privacy-checked, and raw data renamed into an allowlisted slot is still rejected. |
| 19 | `RP-M4-CHECK` | `M4` | `github` | A real pull-request check binds the exact pull-request revision and maps healthy, failed, and inconclusive results according to the specification. |
| 20 | `RP-M4-FORK` | `M4` | `github` | A fork pull request receives no secret or write authority and artifact substitution cannot deceive the privileged publisher. |
| 21 | `RP-M4-REPRO` | `M4` | `github`, `release` | A downloaded check artifact is independently verifiable and binds its workflow run and source revision. |
| 22 | `RP-M5-JOURNEY` | `M5` | `ui` | A new user can follow the README on a clean machine, complete the local trial, and verify the evidence. |
| 23 | `RP-M5-SECURITY` | `M5` | `ui` | Untrusted repository text or reports cannot execute script, inject HTML, open arbitrary network access, or disclose raw evidence. |
| 24 | `RP-M5-TRUTH` | `M5` | `ui` | Every UI status traces to the canonical model and visibly preserves INCOMPLETE or INCONCLUSIVE rather than presenting success. |
| 25 | `RP-M6-AUTHORITY` | `M6` | `hosted-runner` | A compromised worker or forged result cannot produce accepted evidence or a passing GitHub Check. |
| 26 | `RP-M6-CLEANUP` | `M6` | `hosted-runner` | Every termination path destroys the VM and credential, seals its store prefix, and restores the after-inventory to baseline. |
| 27 | `RP-M6-ISOLATION` | `M6` | `hosted-runner` | Two concurrent tenants have no filesystem, process, network, or artifact cross-contamination. |
| 28 | `RP-M6-LIVE` | `M6` | `hosted-runner` | An owner-controlled hosted environment has current-source evidence; without real infrastructure this row remains blocked. |
| 29 | `RP-M7-CAPABILITY` | `M7` | `plugin` | Unauthorized I/O is blocked before it occurs and a plugin cannot change policy, coverage, or the overall verdict. |
| 30 | `RP-M7-CONFORMANCE` | `M7` | `plugin` | Two reference plugins pass the same conformance kit and unsupported protocol versions return a stable error. |
| 31 | `RP-M7-SUPPLYCHAIN` | `M7` | `plugin`, `release` | Plugin signature, trust, SBOM, and currentness are verifiable and an unknown signer remains unknown or blocked. |
| 32 | `RP-Q-PROTOCOL` | `QUALIFICATION` | `external-review`, `release` | An independent reviewer approves and hash-freezes the acceptance policy before observing results. |
| 33 | `RP-Q-REPLAY` | `QUALIFICATION` | `external-review`, `release` | The reviewer reruns the required matrix in a clean room with no unexplained required skip, blocked result, or internal error. |
| 34 | `RP-Q-SUBJECT` | `QUALIFICATION` | `external-review`, `release` | The audited subject is the merged default-branch commit and tree plus final candidate artifact digests, and any later byte change invalidates the pass. |
| 35 | `RP-Q-VERDICT` | `QUALIFICATION` | `external-review`, `release` | The reviewer returns PASS for the exact candidate with no open P0 or P1, and implementer or self-CI evidence cannot substitute for that verdict. |
| 36 | `RP-REGISTRY` | `M0` | `repository` | The complete M0--M7 registry and public specification or RFC exact set are closed and every required row has current evidence. |
| 37 | `RP-R-STABLE-SCHEMA` | `RELEASE` | `linux-amd64`, `release`, `windows-amd64` | Historical v1 verification, v2 round-trip and negative tests, and builder, CLI, and kit version agreement all pass. |

The `appliesTo`, evaluation policy, and exact criterion strings for these rows
MUST be published in `acceptance-registry.json`. Changing an ID, criterion, or
required evidence policy is a normative scope change and requires an accepted
RFC. Adding a new required row requires a new registry schema version unless a
prior RFC explicitly reserves and defines that row.

### Evaluation policies

Each registry row has exactly one `evaluation` object with one of these
shapes:

```json
{"kind":"required-checks","requiredChecks":["ci/go","ci/windows-go"]}
```

```json
{"kind":"blocked","reasonCode":"SOURCE_QUALIFICATION_PREREQUISITES_UNAVAILABLE"}
```

```json
{"kind":"not-run","reasonCode":"ROADMAP_WORK_NOT_SCHEDULED"}
```

The only v1 required-check identifiers are:

```text
ci/container-matrix
ci/go
ci/schema-json
ci/windows-go
```

`requiredChecks` is a nonempty, unique, strict ordinal-sorted array. A row
using `required-checks` is `PASS` only when every listed current-subject check
is `success`. `failure` or `cancelled` produces `FAIL`. `skipped` or a missing
check produces `NOT_RUN`; it never produces `PASS`.

The initial v1 registry MUST derive these rows from current checks:

| Row | Required checks |
|---|---|
| `RP-B00` | all four v1 checks, and the runtime subject MUST be a `push` to `refs/heads/main` |
| `RP-B04` | `ci/container-matrix` |
| `RP-M0-MODULE` | `ci/go`, `ci/windows-go` |
| `RP-M1-JOURNEY` | `ci/container-matrix` |

`RP-M0-QUAL` MUST initially use `blocked` with reason code
`SOURCE_QUALIFICATION_PREREQUISITES_UNAVAILABLE`. Every other row, including
`RP-B01`, `RP-B02`, `RP-B03`, and `RP-REGISTRY`, MUST initially use `not-run` with reason code
`ROADMAP_WORK_NOT_SCHEDULED`. This deliberately avoids upgrading historical,
partial, or merely implemented behavior into current acceptance.

The initial mapping may be changed only by a focused implementation change
whose accepted RFC or unchanged criterion supplies the missing machine-check
predicate and current evidence source. A prose status edit alone is not
sufficient.

### Runtime evaluation wire contract

The evaluation top level contains exactly:

| Field | Type | Rule |
|---|---|---|
| `artifactType` | string | `repopass-acceptance-evaluation` |
| `evaluationDigest` | string | Domain-separated digest defined below |
| `formalClaim` | boolean | MUST be `false` |
| `overallStatus` | string | `PASS`, `FAIL`, or `INCOMPLETE` |
| `registryDigest` | string | SHA-256 of exact canonical registry bytes |
| `rows` | array | Exactly 37 evaluations in registry order |
| `run` | object | Exact producer workflow identity |
| `schemaVersion` | string | `1` |
| `stableEligible` | boolean | Computed, never caller-selected |
| `subject` | object | Exact source subject |
| `trustBoundary` | string | `producer-owned-ci` |

`subject` contains exactly `repository`, `revision`, and `treeSHA`.
`repository` is exactly `github.com/taipei49314/RepoPassport`; revision and
tree are lowercase 40-hex Git object IDs.

`run` contains exactly `attempt`, `event`, `id`, `ref`, and `workflowPath`.
`attempt` is an integer in `1..2147483647`; `id` is an integer in
`1..9007199254740991`; `event` is `push`, `pull_request`, or
`workflow_dispatch`; `ref` is a printable ASCII GitHub ref of at most 256
bytes; and `workflowPath` is exactly `.github/workflows/ci.yml`.

Each row evaluation contains exactly:

| Field | Type | Rule |
|---|---|---|
| `evidence` | array | Exact derived check records, in registry check order |
| `id` | string | Must equal the registry row at this ordinal |
| `reasonCode` | string | Exact reason enum below |
| `status` | string | `PASS`, `FAIL`, `NOT_RUN`, or `BLOCKED` |

Each evidence record contains exactly `checkId` and `result`. `checkId` is one
of the four v1 check identifiers; `result` is `success`, `failure`,
`cancelled`, or `skipped`. Blocked and not-run policies have an empty evidence
array.

The v1 reason-code enum is:

```text
CURRENT_REQUIRED_CHECKS_PASSED
NOT_DEFAULT_BRANCH
REQUIRED_CHECK_CANCELLED
REQUIRED_CHECK_FAILED
REQUIRED_CHECK_MISSING_OR_SKIPPED
ROADMAP_WORK_NOT_SCHEDULED
SOURCE_QUALIFICATION_PREREQUISITES_UNAVAILABLE
```

For a required-check row, `CURRENT_REQUIRED_CHECKS_PASSED` is legal only with
`PASS`; failure and cancellation use their matching reason and `FAIL`; a
missing or skipped check uses `NOT_RUN`. `RP-B00` evaluated outside a main
push uses `NOT_RUN` and `NOT_DEFAULT_BRANCH`, even when all checks succeed.
Fixed blocked and not-run policies MUST reproduce the registry reason exactly.
`ci/container-matrix=success` is accepted only because the workflow contract
independently freezes the exact required backend matrix to Docker and Podman,
disables fail-fast and skip semantics, and requires every matrix child to
succeed.

### State and roll-up semantics

Row statuses are independent of product functional, capability,
reproducibility, cleanup, evidence, and freshness verdict dimensions.

| Condition | Row status |
|---|---|
| All current required checks observed success | `PASS` |
| A required check observed failure or cancellation | `FAIL` |
| A required check is absent/skipped, the subject is not the required default-branch subject, or work is not scheduled | `NOT_RUN` |
| A named prerequisite prevents the predicate from running | `BLOCKED` |

The top-level roll-up is deterministic:

1. any `FAIL` row makes `overallStatus=FAIL`;
2. otherwise any `BLOCKED` or `NOT_RUN` row makes
   `overallStatus=INCOMPLETE`;
3. only 37 `PASS` rows make `overallStatus=PASS`.

`stableEligible` is `true` only when `overallStatus=PASS`, all 37 exact rows
are present and `PASS`, all four `RP-Q-*` rows are `PASS`, and
`RP-R-STABLE-SCHEMA` is `PASS`. It is `false` for every other state. The
ordinary registry CI gate MUST NOT fail merely because an honest evaluation
is incomplete. A separate `require-complete` operation MUST fail unless
`stableEligible=true`.

### CLI behavior

The implementation adds a repository-owned CI command at
`./cmd/repopass-acceptance-registry`. It is not added to the release artifact
inventory.

The exact commands are:

```text
repopass-acceptance-registry validate --registry <path>
```

```text
repopass-acceptance-registry evaluate --registry <path> --repository <value> --revision <40hex> --tree-sha <40hex> --event <value> --ref <value> --workflow-run-id <integer> --workflow-run-attempt <integer> --go-result <value> --schema-json-result <value> --windows-go-result <value> --container-result <value> --output <path>
```

```text
repopass-acceptance-registry require-complete --evaluation <path>
```

Flags are required exactly once. Unknown, duplicate, abbreviated, positional,
environment-derived, or alternate flags are invalid. Paths are local operator
inputs and MUST NOT be copied into public output or errors. The process MUST
not read credentials or invoke GitHub APIs.

On success, stdout is exactly one canonical JSON line containing only
`code`, `overallStatus`, `sha256`, and `status`; stderr is empty. `validate`
uses code `ACCEPTANCE_REGISTRY_VALID`; `evaluate` uses
`ACCEPTANCE_EVALUATION_WRITTEN`; `require-complete` uses
`ACCEPTANCE_COMPLETE`. `status` is the command execution status `PASS`, not a
replacement for `overallStatus`.

Exit code 0 means the requested operation succeeded. Exit code 1 means the
input or evaluation failed a stable contract. Exit code 2 means CLI syntax was
invalid. All failures emit one fixed, redacted canonical record and no raw
parser, filesystem, environment, JSON, or path text.

### Required CI gate

`.github/workflows/ci.yml` MUST add one required `acceptance-registry` job
that depends on `go`, `schema-json`, `windows-go`, and the exact Docker/Podman
matrix job `container-integration`. The job MUST run with `if: always()`, read-only
permissions, pinned actions, a clean exact checkout, the `go.mod` Go version,
and no credential persistence.

The job MUST:

1. validate all four dependency results against the exact result enum;
2. compute and validate the checkout revision and Git tree;
3. call `validate` and `evaluate` with explicit values;
4. parse the output with an independent strict JSON parser and require the
   exact subject, registry digest, row count, row order, computed roll-up,
   `formalClaim=false`, `trustBoundary=producer-owned-ci`, and
   `stableEligible=false` for the initial registry;
5. upload exactly one `acceptance-evaluation-v1.json` file from
   `runner.temp` under a run-ID-bound name with finite retention; and
6. fail the job if any dependency was not `success`, after retaining any
   safely produced evaluation.

The workflow MUST NOT run `require-complete` as ordinary CI while the roadmap
is incomplete. The artifact action is transport only. A workflow log or
artifact ID is not an external review, release claim, trusted timestamp, or
append-only history.

### Failure behavior

| Failure | Stable code | Result |
|---|---|---|
| Registry bytes are noncanonical, malformed, oversized, or structurally invalid | `ACCEPTANCE_REGISTRY_INVALID` | command failure |
| Exact row set/order, required flag, criterion, platform, or evaluation policy differs | `ACCEPTANCE_SCOPE_MISMATCH` | command failure |
| Runtime subject or workflow identity is invalid | `ACCEPTANCE_SUBJECT_INVALID` | command failure |
| Required-check input is missing or outside the enum | `ACCEPTANCE_CHECK_INPUT_INVALID` | command failure |
| Evaluation bytes or digest are invalid | `ACCEPTANCE_EVALUATION_INVALID` | command failure |
| Completion is requested while any row is not `PASS` | `ACCEPTANCE_INCOMPLETE` | command failure |
| Output cannot be published atomically without replacement | `ACCEPTANCE_OUTPUT_UNAVAILABLE` | command failure, no accepted output |

Failure output MUST NOT echo input bytes, paths, refs, JSON fragments, command
lines, environment values, or raw errors. Temporary output MUST be created
outside the checkout with owner-private permissions and published atomically
without replacing a pre-existing path. Cleanup failure is a command failure.

## Trust boundaries and security

The registry file, evaluation flags, workflow contexts, repository bytes,
JSON inputs, filesystem namespace, and downloaded artifacts are untrusted
until validated. The validator is authoritative only for structural and
semantic conformance to this RFC. The current CI workflow is authoritative
only for its own producer-owned required-check observations.

The workload cannot select row IDs, criteria, evaluation policies, status,
roll-up, `formalClaim`, `stableEligible`, registry digest, or evidence order.
Those values are derived by the validator. The workflow may supply only the
explicit source/run identity and four bounded check results.

This RFC adds no secret, OIDC token, write permission, host mount, device,
network path, process privilege, signing key, trusted time, or external
identity. Missing enforcement, a skipped check, an unknown result, or an
unavailable prerequisite fails closed as `FAIL`, `NOT_RUN`, or `BLOCKED`; it
never becomes `PASS`.

The parser MUST reject invalid UTF-8, BOM, duplicate or unknown object names,
trailing content, alternate whitespace, noncanonical numbers, excessive byte,
depth, node, row, evidence, or string bounds, and bytes that differ from
canonical re-encoding. Registry and evaluation limits are respectively 256
KiB and 1 MiB, depth 16, and 16,384 nodes. Each row has at most four evidence
records.

File access MUST reject path redirection, symlinks, Windows reparse points,
alternate data streams, external hard-link aliases, special files, identity
changes while reading, and case-ambiguous inventory. Output publication MUST
be no-replace. The implementation security model continues to exclude a
hostile same-principal or administrator concurrently rewriting an
operator-controlled runner filesystem; this limitation MUST remain explicit.

## Privacy

The registry contains only fixed public contract text. The evaluation contains
only public repository identity, Git object IDs, numeric workflow identity,
the fixed workflow path, a bounded GitHub event/ref, fixed check IDs/results,
fixed row statuses/reasons, and digests.

It MUST NOT contain timestamps, actor names, email addresses, hostnames,
runner names, image versions, host paths, environment values, stdout, stderr,
error messages, HTTP endpoints, credentials, tokens, free-form annotations,
or evidence payloads. The ref uses a narrow printable-ASCII Git-ref grammar
and is privacy-scanned before publication. Logs expose only the fixed command
record described above. Artifact retention is finite and deletion does not
change a release or external-trust claim because none is created.

## Canonicalization and integrity

Both documents use the deterministic JSON profile in
`spec/canonicalization.md`: UTF-8, ASCII object names, exact key order produced
by the pinned Go implementation, no indentation, no BOM, and no trailing
newline. Row and evidence arrays are ordered sequences. `appliesTo` and
`requiredChecks` are strict ordinal-sorted sets.

`registryDigest` is lowercase `sha256:<64 hex>` over the exact validated
canonical bytes of `acceptance-registry.json`.

`evaluationDigest` is computed as follows:

1. construct the complete evaluation object;
2. remove only top-level `evaluationDigest`;
3. prefix the canonical remaining bytes with
   `repopass.acceptance-evaluation.v1\x00`;
4. compute SHA-256; and
5. insert lowercase `sha256:<64 hex>`.

No other field is excluded. The registry has no embedded registry digest,
revision, tree, or evaluation, so no digest fixed point exists. An evaluation
digest proves byte integrity only; it does not authenticate the producer.

## Compatibility and versioning

This is a new contract. It does not change manifest `apiVersion`, product
verdicts, RFC-0001 module identity, RFC-0002 source qualification, existing
release artifacts, or existing evidence predicate identifiers.

Schema version `1` freezes the 37 rows and all wire enums. A row rename,
deletion, requirement downgrade, criterion change, alternate aggregation,
external-authority reinterpretation, or silent fallback requires an accepted
RFC and, where bytes cease to validate under v1, a new schema version.

Adding an evidence predicate for a previously not-run row may update that
row's evaluation policy under an accepted RFC without changing the row ID or
criterion. Historical v1 evaluations remain verifiable. Unknown versions fail
closed; there is no downgrade to Markdown or a smaller row set.

## Implementation plan

1. Land this RFC alone and record that it has author self-review only.
2. Add tests that fail for the missing exact registry, schemas, strict parser,
   semantic validator, CLI, and CI job.
3. Add `acceptance-registry.json` and the two public schemas.
4. Implement `internal/acceptanceregistry` using the existing strict JSON and
   canonical JSON primitives without sharing producer and test serializers.
5. Implement the repository-owned CI command and private no-replace output.
6. Add the required CI job and finite-retention transport artifact.
7. Update active implementation, release, and known-limitations documents to
   state the scoped current rows and the incomplete roll-up.
8. Merge only after first-attempt required CI passes; verify the exact merged
   main revision and record its evaluation artifact without calling it
   external qualification.

## Test and conformance plan

Required tests include:

- exact 37-row golden ID/order/criterion/milestone/platform/policy checks;
- missing, extra, duplicate, renamed, reordered, `required=false`, unknown
  enum, and altered-criterion rejection;
- registry and evaluation schema strictness and public schema embedding;
- duplicate JSON names, BOM, invalid UTF-8, alternate whitespace, CRLF,
  trailing newline/content, noncanonical number, byte/depth/node/string, and
  evidence-count bounds;
- canonical registry digest and domain-separated evaluation digest goldens;
- every required-check result combination and main-push versus pull-request
  subject behavior;
- deterministic `FAIL` over `INCOMPLETE` over `PASS` roll-up;
- `stableEligible` false unless all 37 rows, all `RP-Q-*`, and stable schema
  pass;
- forged caller-selected status, roll-up, evidence order, formal claim,
  stable eligibility, registry digest, and cross-subject substitution;
- path redirect, symlink/reparse, hard link, alternate stream, mutation,
  collision, no-replace, cleanup, and bounded-inventory tests on Linux and
  Windows;
- CLI exact flags, duplicates, equals form, unknown flags, fixed output,
  writer failure, and path/raw-input redaction;
- workflow structural parsing for exact needs, `if: always()`, pinned actions,
  read-only permissions, clean source binding, explicit result mapping,
  independent replay, finite retention, and no `require-complete` call; and
- full `go vet ./...`, `go test -count=1 ./...`, integration-tag compile,
  schema JSON parse, `actionlint`, and exact-main first-attempt CI.

The implementation PR is acceptable when the new gate passes structurally,
its exact-main evaluation is `INCOMPLETE`, scoped implemented rows are not
overstated, `RP-M0-QUAL` is `BLOCKED`, unfinished rows remain `NOT_RUN`, and no
required job is skipped.

## Rollout and rollback

The registry gate becomes required in ordinary CI. Because incomplete roadmap
state is a valid honest evaluation, the rollout does not make every progress
PR fail until M7 is complete. Structural or overstatement failures remain
hard failures.

Rollback may remove the required CI invocation only by reverting the complete
implementation while preserving this accepted RFC and already published
evaluations. Rollback MUST NOT reinterpret an older incomplete evaluation as
complete or delete historical evidence. A corrected evaluation uses a new
workflow run and does not overwrite an earlier artifact.

## Alternatives considered

### Track one status Markdown table

This is easy to edit but cannot reject missing, renamed, duplicate, or
unknown rows and cannot bind deterministic status semantics. Rejected.

### Commit a current-SHA evaluation

Changing the evaluation changes the tree whose hash it would contain, so an
exact self-binding tracked file requires an impractical fixed point. Rejected.

### Make ordinary CI fail until all 37 rows pass

This would keep the default branch permanently red during honest incremental
delivery and encourage scope weakening. Structural validation and completion
enforcement are therefore separate operations. Rejected.

### Accept GitHub artifact IDs or checksums as external evidence

They provide transport identity or integrity but not external authority,
append-only history, trusted time, or independent review. Rejected.

### Begin with only currently implemented rows

That would silently shrink M0--M7 and make later scope restoration optional.
The complete 37-row set is required from v1. Rejected.

## Open questions

None.

## Decision record

- Decision: Adopt the exact 37-row canonical acceptance registry, derived
  producer-owned current-source evaluation, and separate completion check in
  this RFC.
- Date: 2026-08-13
- Approvers: @taipei49314 (author self-review only; no independent review)
- Required follow-up: Tests-first schema, validator, CI command, required CI
  job, active status calibration, exact-main evaluation evidence.
- Known limitations: The registry and ordinary evaluation provide structural
  and producer-owned CI evidence only. They do not provide append-only attempt
  history, immutable runner applications, Windows non-bypassable network
  isolation, external identity, trusted time, transparency, release approval,
  or stable promotion authority.
