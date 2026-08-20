# RFC-0002: Exact Current-Source Qualification Archive and Receipt

- Status: Accepted
- Authors: @taipei49314
- Reviewers: None (author self-review only; no independent review claimed)
- Created: 2026-08-11
- Updated: 2026-08-11
- Target milestone: M0 / pre-v0.1.0
- Tracking issue: [#6](https://github.com/taipei49314/RepoPassport/issues/6)
- Supersedes: None

## Summary

RepoPassport will add a deterministic archive for one exact Git source tree,
a versioned manifest for that archive, and one public source-qualification
receipt for each required operating-system lane. A complete qualification
package contains the identical source archive and manifest observed by clean
Linux/amd64 and Windows/amd64 controllers, plus one receipt from each lane.

The package is current only relative to an explicit expected default-branch
commit and tree. It is not a signature, provenance statement, trusted clock,
GitHub identity assertion, or release approval. Closing `RP-M0-QUAL` does not
change a product verdict dimension and does not close M0 as a whole.

## Motivation

The current release builder requires an exact clean checkout and inspects the
build information in its binaries. CI also runs source tests on Linux and
Windows. Those controls are valuable, but their ordinary logs are not a
versioned source receipt and CI does not preserve a canonical source archive.

This leaves five concrete gaps:

1. a changed source tree can only be related to ephemeral job logs;
2. required gates do not have one exact, machine-checked identifier set;
3. missing, skipped, duplicate, or renamed checks have no portable aggregate;
4. historical Alpha evidence can be confused with current-source evidence;
5. a clean downloader cannot replay archive and receipt validation without a
   checkout.

GitHub's source zip, a repository checksum, or a successful workflow badge is
not sufficient. None binds the exact cross-platform required gate set under a
public, fail-closed contract.

## Goals

- Bind source qualification to one exact repository, base commit, tested
  commit, Git tree, module path, archive, and archive manifest.
- Produce the same source archive and manifest bytes from distinct clean paths
  on Linux and Windows.
- Freeze the Linux and Windows required gate identifiers and exact invocations.
- Preserve gate attempts without copying raw stdout, stderr, host paths, or
  environment values into the public package.
- Reject structural ambiguity, stale subjects, historical substitution, and
  any required gate that is not an observed pass.
- Permit a clean downloader, without a checkout, to run the producer-owned
  structural verifier against explicit independently supplied repository,
  workflow-run, base-commit, tested-commit, tree, controller-digest, and
  package-digest inputs. An authenticated downloader separately selects exact
  numeric artifact IDs. Currentness still requires a separate live lookup.

## Non-goals

- Establishing repository-owner, workflow, runner, or publisher identity.
- Providing trusted time, transparency, revocation, or an external signature.
- Replacing M3 trust policy, independent review, or release promotion.
- Changing runtime functional, capability, reproducibility, cleanup, evidence,
  or freshness verdict semantics.
- Qualifying Docker, Podman, observer completeness, hosted runners, UI, or
  plugins.
- Changing the seven-file Alpha.33 binary inventory or rebuilding historical
  Alpha evidence.
- Treating a GitHub Actions artifact as an immutable or trusted store.

## Normative proposal

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are interpreted as described by RFC 2119 and RFC 8174.

### Qualification package

A complete public package MUST be one directory containing exactly these four
case-sensitive regular files and no directories, links, reparse points, hard
link aliases, alternate streams, or special entries:

| File | Role |
|---|---|
| `repopass-source.tar` | Canonical source payload |
| `source-archive-manifest-v1.json` | Canonical source subject and file inventory |
| `source-qualification-linux-amd64-v1.json` | Linux required-gate receipt |
| `source-qualification-windows-amd64-v1.json` | Windows required-gate receipt |

Filenames are part of the version-1 contract. A missing, additional,
case-colliding, or non-regular entry MUST fail verification.

Intermediate platform artifacts MAY contain only the archive, manifest, and
that platform's receipt. Only the exact four-file aggregate above is eligible
to close `RP-M0-QUAL`.

This aggregate is M0 qualification transport, not an RC or stable payload. It
MUST NOT be promoted verbatim, attached to a release as one opaque package, or
listed in `PAYLOAD_MANIFEST`. A later stable-v2 contract MAY list byte-identical
source archive and manifest bytes as payload. Platform receipts remain detached
qualification evidence and may be referenced only by `QUALIFICATION_INDEX`.
Before any public upload, the controller MUST confirm through the canonical
GitHub repository API that `testedRevision` exists there with the exact
`treeSHA`; otherwise it MUST NOT publish tracked source bytes.

### Source subject

The manifest and both receipts MUST contain an identical `subject` object:

| Field | Type | Required value or rule |
|---|---|---|
| `repository` | string | `https://github.com/taipei49314/RepoPassport` |
| `modulePath` | string | `github.com/taipei49314/RepoPassport` |
| `moduleVersion` | string | exactly `0.1.0-alpha.33` in version 1 |
| `gitObjectFormat` | string | exactly `sha1` |
| `baseRevision` | string | 40 lowercase hexadecimal Git commit ID |
| `testedRevision` | string | 40 lowercase hexadecimal Git commit ID |
| `treeSHA` | string | 40 lowercase hexadecimal Git tree ID |
| `dirty` | boolean | exactly `false` |

The controller MUST resolve all three Git identities itself. `HEAD` MUST equal
`testedRevision`; `HEAD^{tree}` MUST equal `treeSHA`; and the repository MUST
report `sha1` as its Git object format. For a default-branch `push` run,
`baseRevision` MUST equal both the event's independently supplied `before` SHA
and `git rev-parse testedRevision^1`. For a pull-request prequalification run,
it is the first parent of the tested synthetic merge commit. For a manual
dispatch it is also the tested commit's first parent and cannot close the row.
A root commit,
missing parent, non-SHA-1 repository, or ambiguous parent fails closed.

Checkout MUST use complete history (`fetch-depth: 0`) and
`persist-credentials: false`. Before any gate and after all gates, the
controller MUST reject:

- a staged or unstaged change to a tracked path, or any untracked or ignored
  filesystem entry outside `.git`;
- any tracked path whose bytes or mode differ from `HEAD^{tree}`;
- `assume-unchanged`, `skip-worktree`, sparse-checkout, or sparse-index state;
- any symlink, reparse point, hard-link alias, alternate data stream, device,
  socket, FIFO, or other special entry in the checkout outside Git metadata;
- an injected worktree, index, object directory, alternate object database,
  replacement object, Git configuration, or repository alias.

The implementation MUST enumerate tracked objects with fixed Git plumbing:
`git ls-tree -r -z --full-tree --long <testedRevision>` and
`git cat-file --batch`.
It MUST set `GIT_NO_REPLACE_OBJECTS=1` and `GIT_OPTIONAL_LOCKS=0`, use the
canonical checkout as the fixed working directory, reject a bare or shallow
repository and external object alternates, and clear `GIT_DIR`, `GIT_WORK_TREE`,
`GIT_COMMON_DIR`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`,
`GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_REPLACE_REF_BASE`, `GIT_CONFIG`, and
every `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*` input. Each
batch response's object ID, type, and size MUST match the tree enumeration.
Archive bytes come from these verified blob objects, never from worktree bytes.

PR and synthetic-merge packages MAY be produced as prequalification evidence,
but only a package whose `testedRevision` and `treeSHA` equal the then-live
default branch can close `RP-M0-QUAL`.

### Canonical source archive

`repopass-source.tar` MUST represent every blob in the exact tested Git tree
and no other content. The controller MUST read Git objects; it MUST NOT trust
working-tree file bytes merely because `git status` is clean.

Version 1 supports only Git regular-file modes `100644` and `100755`.
Symlinks, submodules, sparse omissions, or other modes MUST fail closed. Git
LFS pointer-looking bytes are ordinary tracked blob bytes in this version; the
controller neither resolves nor downloads their target and records that fixed
limitation.

The archive profile is canonical USTAR. It deliberately reuses the repository
printable-ASCII portable-path subset; arbitrary Unicode is outside version 1.
Every path byte MUST be in `0x20..0x7e`, paths use `/`, and every component is
nonempty and is neither `.` nor `..`. A path containing backslash, colon,
`*?"<>|`, a control byte, an absolute/drive/UNC/device form, a component ending
in dot or space, or a Windows reserved device component (case-insensitive,
with or without an extension) is invalid. Paths MUST be unique by raw bytes
and by ASCII case-folding. A file path MUST NOT be a slash-boundary prefix of
another path. The complete path is at most 255 bytes.

For the reserved-device test, ASCII-uppercase the bytes before the first dot
and reject exactly `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `CLOCK$`,
`COM1` through `COM9`, and `LPT1` through `LPT9`. No locale or filesystem query
participates in this comparison.

Entries are regular files sorted by unsigned raw path bytes. For a path of at
most 100 bytes, the USTAR `name` field is the whole path and `prefix` is empty.
Otherwise the builder selects the rightmost slash for which the prefix is
1..155 bytes and the final name is 1..100 bytes; no valid split is an error.
The slash itself is stored in neither field. There is exactly one header per
entry and no directory header.

Every 512-byte header has this exact byte layout:

| Offset | Width | Value |
|---:|---:|---|
| 0 | 100 | name bytes, then NUL bytes |
| 100 | 8 | `0000644\0` or `0000755\0` |
| 108 | 8 | `0000000\0` |
| 116 | 8 | `0000000\0` |
| 124 | 12 | size as exactly eleven lowercase octal digits plus NUL |
| 136 | 12 | `00000000000\0` |
| 148 | 8 | checksum as six lowercase octal digits, NUL, space |
| 156 | 1 | ASCII `0` |
| 157 | 100 | all NUL bytes |
| 257 | 6 | `ustar\0` |
| 263 | 2 | `00` |
| 265 | 32 | all NUL bytes |
| 297 | 32 | all NUL bytes |
| 329 | 8 | `0000000\0` |
| 337 | 8 | `0000000\0` |
| 345 | 155 | prefix bytes, then NUL bytes |
| 500 | 12 | all NUL bytes |

The checksum is the unsigned sum of all header bytes while offsets 148..155
are eight ASCII spaces. File bytes are exact Git blob bytes, followed by the
minimum zero padding to a 512-byte boundary. Exactly two all-zero 512-byte
blocks terminate the archive and no byte follows. PAX, GNU, base-256 numbers,
sparse data, links, compression, alternate checksum forms, nonzero padding,
additional zero blocks, and semantically equivalent headers are invalid. The
verifier MUST independently reconstruct the entire USTAR byte stream from the
accepted manifest and blob bytes and require byte-for-byte equality.

The version-1 limits are 16,384 files, 128 MiB per file, and 512 MiB for the
complete raw archive including headers, padding, and terminators. All size and
offset arithmetic MUST be checked before allocation or publication.

Verification MUST parse and hash members in place and MUST NOT extract the tar.
For every file it MUST recompute the Git SHA-1 blob object from
`"blob " + decimal-size + NUL + exact-bytes`. It MUST reconstruct all Git tree
objects, including implicit directories with mode `40000`. Siblings use
unsigned-byte Git tree ordering with comparison keys `basename + NUL` for a
file and `basename + "/"` for a directory. Entries are encoded as
`<mode><space><basename><NUL><20 raw object-ID bytes>`. It MUST hash each tree
as `"tree " + decimal-size + NUL + exact-tree-bytes`, recompute the root SHA-1, and
require equality with `subject.treeSHA`. Rewriting the archive, manifest, and
receipts while retaining an unrelated tree string therefore cannot pass.

The archive member `go.mod` MUST exist, have Git mode `100644`, and its parsed
module directive MUST equal `github.com/taipei49314/RepoPassport`. A committed
`go.work`, or a `replace` involving the canonical or legacy module namespace,
is invalid.

### Source archive manifest

`source-archive-manifest-v1.json` MUST be canonical JSON with this shape:

The indented example is presentation-only; wire bytes use the repository
deterministic JSON profile and have no trailing newline.

```json
{
  "archive": {
    "format": "ustar-v1",
    "name": "repopass-source.tar",
    "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "size": 123
  },
  "artifactType": "repopass-source-archive-manifest",
  "files": [
    {
      "gitBlobSHA1": "0123456789abcdef0123456789abcdef01234567",
      "gitMode": "100644",
      "path": "README.md",
      "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "size": 123
    }
  ],
  "schemaVersion": "1",
  "subject": {
    "baseRevision": "0123456789abcdef0123456789abcdef01234567",
    "dirty": false,
    "gitObjectFormat": "sha1",
    "modulePath": "github.com/taipei49314/RepoPassport",
    "moduleVersion": "0.1.0-alpha.33",
    "repository": "https://github.com/taipei49314/RepoPassport",
    "testedRevision": "89abcdef0123456789abcdef0123456789abcdef",
    "treeSHA": "fedcba9876543210fedcba9876543210fedcba98"
  }
}
```

`files` MUST contain exactly one entry per archive member in the same order.
`gitBlobSHA1` MUST be the recomputed 40-lowercase-hex Git blob identity. All
other digests are lowercase SHA-256 prefixed by `sha256:`. Integers are exact
non-negative JSON integers within the version-1 limits. Unknown or duplicate
keys, duplicate paths, noncanonical ordering, BOM, CRLF, trailing whitespace
or newline, a Git object mismatch, or a manifest that does not reproduce the
archive MUST fail.

Canonical manifest bytes are at most 16 MiB, JSON nesting depth is at most 16,
and the file array is bounded by the archive's 16,384-file limit. The parser
MUST reject rather than truncate any bound overflow.

The manifest does not contain its own digest. Each platform receipt binds the
complete canonical manifest bytes, avoiding self-reference.

### Platform receipts

Each receipt MUST use the existing deterministic JSON profile with no BOM,
indentation, CRLF, trailing whitespace, or trailing LF. Unknown or duplicate
keys at any depth are invalid. The top-level key set is exactly:

```text
artifactType, attempt, controller, execution, gates, limitations,
notApplicable, platform, predicateType, productDimensions,
qualificationStatus, run, schemaVersion, source, subject
```

`artifactType` is `repopass-source-qualification-receipt`, `schemaVersion` is
`1`, and `predicateType` is
`https://repopass.dev/source-qualification/v1`. `subject` is the exact source
subject above. The remaining objects have the exact contracts below.
Canonical receipt bytes are at most 1 MiB, nesting depth at most 16, total JSON
nodes at most 32,768, and every string at most 4,096 bytes unless a narrower
field rule applies.

#### Run and attempt binding

`run` contains exactly:

| Field | Rule |
|---|---|
| `event` | `push`, `pull_request`, or `workflow_dispatch`; only `push` can close the row |
| `headSHA` | exact `subject.testedRevision` |
| `issuer` | exactly `NOT_ESTABLISHED` |
| `lane` | `linux-amd64` or `windows-amd64` |
| `qualificationRunId` | derived digest below |
| `ref` | exact GitHub full ref; closure requires `refs/heads/main` |
| `workflowPath` | `.github/workflows/source-qualification.yml` |
| `workflowRepository` | `taipei49314/RepoPassport` |
| `workflowRunAttempt` | integer `1..2147483647` |
| `workflowRunId` | decimal string matching `^[1-9][0-9]{0,19}$` |
| `workflowURL` | `https://github.com/taipei49314/RepoPassport/actions/runs/<workflowRunId>` |

`qualificationRunId` is `sha256:` plus lowercase SHA-256 over the UTF-8
sequence `github-actions`, exact `run.workflowRepository`, exact
`run.workflowPath`, event, ref, decimal run ID, decimal run attempt, and tested
revision, separated by one NUL byte. Both receipts MUST bind the same run except for
lane. Closing
`RP-M0-QUAL` requires run attempt 1. The downloader supplies repository,
workflow path, run ID, run attempt, both numeric artifact IDs, head SHA, base,
tree, and qualification-run ID independently; artifact content and names are
never sources for expected values.

For `push`, ref is `refs/heads/main`; for pull-request prequalification it is
`refs/pull/<positive-decimal>/merge`; for manual dispatch it is a printable
ASCII `refs/heads/<name>` of at most 255 bytes. No abbreviated ref is accepted.

`attempt` contains exactly `attemptId`, `finishedAt`, `ordinal`,
`priorAttempts`, `retryOf`, and `startedAt`. `attemptId` is
`<qualificationRunId>:<lane>:<ordinal>`. The ordinal is a positive signed
32-bit integer and equals `len(priorAttempts)+1`; only ordinal 1 can close the
row. `retryOf` is null for ordinal 1 and otherwise the immediately preceding
attempt ID. `startedAt` and `finishedAt` are whole-second UTC
`YYYY-MM-DDTHH:MM:SSZ`, with finish not earlier than start. They are untrusted
sequence metadata and MUST NOT establish trusted time, freshness, or
currentness.

Attempt scope is the exact canonical workflow path, tested revision, and lane.
Every workflow execution and GitHub rerun in that scope is one attempt, ordered
by numeric workflow run ID and then numeric workflow run attempt. `ordinal` is
its one-based position in that complete order. `run.workflowRunAttempt` is the
GitHub rerun counter for the current run and participates in
`qualificationRunId`; it is not interchangeable with ordinal. Closing the row
requires both values to equal 1.

Each `priorAttempts` entry contains exactly `attemptId`,
`qualificationStatus`, and `receiptSHA256`. Status is `FAIL`, `BLOCKED`, or
`NOT_RUN`; the digest is canonical receipt bytes or null only when
cancellation, infrastructure loss, or a preconstruction failure prevented a
schema-valid receipt. Entries are complete and chronological. The live acceptance controller MUST also query
the authenticated workflow history; a prior non-PASS attempt for the same
tested revision and lane makes that revision ineligible even if omitted from
an untrusted receipt.

`execution` contains exactly `manualActionCount`, `rawLogsPublished`,
`retryCount`, and `skippedGateCount`. All are non-negative signed 32-bit
integers except the boolean `rawLogsPublished`. Closing the row requires all
three counts to be zero and `rawLogsPublished=false`.

#### Platform, controller, source, and non-applicable facts

`platform` contains exactly `gitVersion`, `goVersion`, `goarch`, `goos`,
`kernelVersion`, `powerShellVersion`, `runnerArch`, `runnerImage`,
`runnerImageVersion`, and `runnerOS`. Go is exactly `go1.26.5`, architecture is
exactly `amd64`, and OS/lane pairs are `linux`/`Linux`/`X64` or
`windows`/`Windows`/`X64`. Other values are nonempty printable ASCII strings
of at most 128 bytes and MUST NOT contain a hostname, username, local path,
endpoint, or environment value.

`controller` contains exactly `goVersion`, `mainPackage`, `modulePath`,
`sha256`, `vcsModified`, and `vcsRevision`. The main package is
`github.com/taipei49314/RepoPassport/internal/sourcequalification/cmd/repopass-source-qualify`,
the module is canonical, Go is `go1.26.5`, revision equals the subject, and
`vcsModified` is false. The digest covers the exact controller executable.

`source` contains exactly `archive` and `manifest`; each contains exactly
`name`, `role`, `sha256`, and `size`. Names are the fixed package filenames;
roles are `source-payload` and `source-archive-manifest`. Both receipts MUST
bind byte-identical bytes. Receipt fields never include member paths.

`notApplicable` contains exactly these lexicographically ordered keys, all
with the exact string `NOT_APPLICABLE`:

```text
cgroupVersion, containerEngineVersion, engineProviderVersion, imageDigests,
observerSetDigest, planDigest, policyDigest, runtimeVersion, sbomDigest,
signatureDigest, trustPolicyDigest
```

This fixed object records out-of-scope facts; it cannot turn an unavailable
source gate into a pass.

`productDimensions` contains exactly `capability`, `cleanup`, `coverage`,
`evidence`, `freshness`, `functional`, `overall`, and `reproducibility`. Each
value is exactly:

```json
{"evaluationStatus":"NOT_RUN","reason":"not-evaluated-by-source-qualification","value":null}
```

The fixed ordered `limitations` array is:

```json
["currentness-requires-live-caller-input","gate-execution-is-self-ci","github-artifact-is-untrusted-transport","lfs-pointers-not-resolved","network-service-state-is-not-bound","no-external-review","no-publisher-or-workflow-identity","no-signature-transparency-trusted-time-or-revocation","product-verdicts-not-evaluated","rp-m0-qual-only","stable-release-not-authorized"]
```

#### Gate records

Every gate contains exactly `argv`, `attempt`, `exitCode`, `finishedAt`, `id`,
`network`, `startedAt`, `status`, and `timeoutSeconds`. `attempt` is exactly 1;
gate reruns are forbidden. Gate timestamps use the same untrusted whole-second
UTC grammar as the receipt attempt; NOT_RUN gates have both timestamps null.
Status is `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`; network is `none`,
`go-modules`, `vulnerability-database`, or
`go-modules-and-vulnerability-database`. `argv` is the exact public logical
vector from the registry, never a private executable path. PASS
requires exit 0 and its semantic predicate. FAIL normally has a signed 32-bit
exit code; it may have exit 0 for a semantic mismatch or null after timeout,
output overflow, cancellation, or process-tree cleanup failure. BLOCKED is
used only when a prerequisite prevents invocation and has null exit. NOT_RUN
has null exit. Raw stdout and stderr are private and are never receipt fields.

### Required gate registry

Registry order is normative. `{testedRevision}` is the only dynamic token and
is replaced by the receipt subject. Every command runs directly, without a
shell, from the exact repository root.

| Order | ID | Lanes | Exact public `argv` | Timeout | Network | Additional PASS predicate |
|---:|---|---|---|---:|---|---|
| 1 | `RP-M0-QUAL-GO-VERSION` | both | `["go","version"]` | 30 s | none | exact single line for Go 1.26.5 and receipt OS/arch |
| 2 | `RP-M0-QUAL-SCHEMA-JSON` | both | `["repopass-source-qualify","validate-schema-json","--root","."]` | 120 s | none | every `schemas/**/*.json` and `testdata/fixtures/**/*.json` is one strict JSON value and at least one schema exists |
| 3 | `RP-M0-QUAL-MODULE-DOWNLOAD` | both | `["go","mod","download","-modcacherw","all"]` | 600 s | go-modules | exit 0 |
| 4 | `RP-M0-QUAL-MODULE-VERIFY` | both | `["go","mod","verify"]` | 120 s | none | exit 0 |
| 5 | `RP-M0-QUAL-TIDY-DIFF` | both | `["go","mod","tidy","-diff"]` | 300 s | none | exit 0 and no output or source change |
| 6 | `RP-M0-QUAL-FORMAT` | both | `["gofmt","-l","."]` | 120 s | none | exit 0 and stdout empty |
| 7 | `RP-M0-QUAL-VET` | both | `["go","vet","./..."]` | 600 s | none | exit 0 |
| 8 | `RP-M0-QUAL-TEST` | both | `["go","test","-count=1","-timeout=30m","./..."]` | 2100 s | none | exit 0 |
| 9 | `RP-M0-QUAL-INTEGRATION-COMPILE` | both | `["go","test","-count=1","-tags=integration","./internal/cli","-run","^$"]` | 600 s | none | exit 0; no container workload executes |
| 10 | `RP-M0-QUAL-VULN-MODULE` | Linux | `["go","run","golang.org/x/vuln/cmd/govulncheck@v1.6.0","-C","cmd/repopass","-scan","module"]` | 900 s | go-modules-and-vulnerability-database | exit 0 |
| 11 | `RP-M0-QUAL-VULN-TEST` | Linux | `["go","run","golang.org/x/vuln/cmd/govulncheck@v1.6.0","-test","./..."]` | 1200 s | go-modules-and-vulnerability-database | exit 0 |
| 12 | `RP-M0-QUAL-RELEASE-BUILD` | both | `["pwsh","-NoLogo","-NoProfile","-NonInteractive","-File","scripts/build-release.ps1","-Version","0.1.0-alpha.33","-TestedRevision","{testedRevision}"]` | 1500 s | go-modules | exact seven-file builder qualification, safe `dist` removal, clean checkout |
| 13 | `RP-M0-QUAL-WINDOWS-LOCK-STRESS` | Windows | `["go","test","-count=20","-timeout=10m","./internal/releasestate","./internal/trustchainstate","./internal/trustrotationstate","./internal/truststate","-run","^(TestObserveContextAndTimeoutBoundLockContention|TestObserveChainStateConcurrencyCancellationAndProcessContention|TestObserveContentionAndCancellationLeaveStateUnchanged|TestObserveCrossProcessLockTimeoutAndExitRelease)$"]` | 720 s | none | exit 0 |

Linux contains rows 1 through 12. Windows contains rows 1 through 9, 12, and
13 in that relative order. Missing, extra, duplicate, unknown, reordered, or
platform-inapplicable rows are structural invalidity. A correctly positioned
skip is `NOT_RUN`, never PASS.

Every gate uses resolved application binaries and fixed environment:
`GOWORK=off`, `GOENV=off`, `GOTOOLCHAIN=local`, empty `GOFLAGS`, empty
`GOCACHEPROG`, `GOTELEMETRY=off`, task-local caches and temporary directories,
and cleared Go overlay/tool-exec, Git redirection/config/credential/SSH/prompt,
and proxy-auth injection. Network is enabled only for the registry rows that
declare it; after dependency acquisition all other Go commands use
`GOPROXY=off`, `GONOPROXY=none`, and no credentials. The runner carries no
repository secrets and its GitHub token is read-only.
`RP-M0-QUAL-RELEASE-BUILD` alone additionally receives the fixed
`REPOPASS_RELEASE_QUALIFICATION_CLEANUP=1` marker. The builder must validate,
atomically withdraw, and safely remove its exact `dist` publication before the
controller's unchanged clean-worktree guard can accept that gate.

Stdout and stderr are separately drained into private bounded logs, each at
most 4 MiB. Overflow fails the gate. Timeout or cancellation terminates the
complete Unix process group or Windows Job Object, waits at most 30 seconds
for cleanup, and fails if any child remains. After the first FAIL or BLOCKED,
later rows are retained in position as NOT_RUN. Retry count is always zero for
an accepted run.

Changing an ID, token, timeout, network mode, semantic predicate, required
platform, ordering, or aggregation rule requires a new schema version and RFC.

### State and verdict semantics

Source qualification is a release-program result, not a product verdict.
Aggregation is deterministic:

| Condition | `qualificationStatus` |
|---|---|
| Any structurally valid gate is `FAIL` | `FAIL` |
| Otherwise any gate is `BLOCKED` | `BLOCKED` |
| Otherwise any gate is `NOT_RUN` | `NOT_RUN` |
| Every exact gate is `PASS`, exit 0, and satisfies its predicate | `PASS` |

Precedence is `FAIL > BLOCKED > NOT_RUN > PASS`. Structural invalidity is
rejected rather than converted to a status. A complete package can close
`RP-M0-QUAL` only when both receipts are PASS; bind identical subject,
qualification-run ID, archive, and manifest; are a first-attempt canonical
main push with no retry, skip, or manual action; reproduce the expected Git
tree; and match independently supplied live repository/run/artifact/base/
revision/tree/controller/package inputs.

Any first merged-main FAIL, BLOCKED, NOT_RUN, cancellation, or missing receipt
makes that tested revision ineligible. A rerun remains historical evidence and
cannot replace it; closure then requires a new tracked commit. Attempts publish
under distinct no-overwrite IDs and earlier evidence is never deleted.

### Controller and CLI behavior

The implementation MUST provide a private, repository-owned controller below
`internal/sourcequalification`. It MUST NOT be added to the shipped full CLI
or verifier command surface in version 1.

The controller interface MUST support these operations:

- build and inspect a canonical source archive and manifest from one clean
  exact checkout;
- record a platform receipt from controller-executed fixed gates;
- assemble the exact Linux and Windows platform outputs without trusting one
  platform's labels;
- verify an aggregate package against explicit expected revision and tree.

The private executable is `repopass-source-qualify` and exposes only:

```text
repopass-source-qualify produce-lane --repo-root PATH \
  --lane linux-amd64|windows-amd64 \
  --event push|pull_request|workflow_dispatch --expected-ref REF \
  --expected-base-revision 40HEX \
  --expected-tested-revision 40HEX --expected-tree 40HEX \
  --workflow-run-id DECIMAL \
  --workflow-run-attempt UINT \
  --private-log-root NEW_PATH --out-dir NEW_PATH

repopass-source-qualify assemble --linux-dir PATH --windows-dir PATH \
  --expected-base-revision 40HEX --expected-tested-revision 40HEX \
  --expected-tree 40HEX --expected-qualification-run-id SHA256 \
  --expected-workflow-run-id DECIMAL --expected-workflow-run-attempt UINT \
  --out-dir NEW_PATH

repopass-source-qualify assemble-tools --package-dir PATH \
  --linux-controller PATH --windows-controller PATH --out-dir NEW_PATH

repopass-source-qualify verify-integrity --package-dir PATH

repopass-source-qualify verify-subject --package-dir PATH \
  --expected-repository https://github.com/taipei49314/RepoPassport \
  --expected-base-revision 40HEX --expected-tested-revision 40HEX \
  --expected-tree 40HEX --expected-qualification-run-id SHA256 \
  --expected-workflow-run-id DECIMAL --expected-workflow-run-attempt UINT \
  --expected-package-digest SHA256 --tool-manifest PATH \
  --expected-tool-manifest-digest SHA256 \
  --expected-executable-digest SHA256

repopass-source-qualify validate-schema-json --root PATH
repopass-source-qualify version
```

There are no default expected identities and no caller-selected command,
registry, status, platform, archive inventory, or receipt input. `produce-lane`
receives the expected base, tested revision, and tree only from the successful
`context` job. It MUST reject any safely inspected source whose actual tree
does not equal `--expected-tree`. Before safe source construction is complete,
that explicit context-bound tree is the only permitted source for the
preconstruction tombstone's `expectedTreeSHA`; the controller MUST NOT infer it
from an error, partial receipt, ambient environment value, or unverified
working-tree bytes. `produce-lane` otherwise resolves facts and executes
compiled-in gates. `assemble` strictly verifies
two exact three-file lane directories and requires byte-identical archive and
manifest bytes before publishing a new exact four-file directory.
`assemble-tools` first verifies that four-file directory, then verifies and
copies the exact two lane-controller bytes and creates their canonical tool
manifest; it publishes exactly the three-file tool directory.
`verify-integrity` reports only `HISTORICAL_INTEGRITY`; `verify-subject` also
compares every explicit CLI expected value and reports `SUBJECT_MATCH`.
Numeric artifact IDs are authenticated downloader inputs outside the package
and verifier; they select bytes but are not claims the downloaded files can
self-assert. Neither operation is currentness, identity, or release approval.

The package digest is not a package member. It is SHA-256 over the UTF-8 domain
`repopass.source-qualification.package.v1`, one NUL, then for each of the four
filenames in package-contract order: filename, NUL, canonical decimal size,
NUL, lowercase raw SHA-256 hex, and LF. The aggregate job exposes it outside
the artifact and the downloader supplies the expected value explicitly.

`scripts/qualify-source.ps1` MAY orchestrate the fixed commands on both
supported operating systems. It MUST resolve the exact Go and Git application
binaries, isolate ambient Go workspace/overlay/tool-exec settings, keep raw
logs in a private run directory, and expose only fixed code-based diagnostics.

The private executable MUST emit bounded canonical JSONL records containing
exactly `code`, `id`, `qualificationStatus`, `sha256`, `testedRevision`, and
`treeSHA`, in canonical key order. Values are stable allowlisted identifiers;
private paths and raw errors are forbidden. Exit `0` means the requested
operation completed and verified. Any invalid input, structural failure,
failed gate, cleanup failure, or output failure exits non-zero.

Every output directory MUST be absent, have a verified non-link parent, and be
created with controller-private permissions. Publication is a same-parent,
atomic, no-replace rename after a fixed-handle double snapshot. No operation
overwrites, merges, repairs, or leaves a partial accepted directory.

### Offline tool transport and replay

The no-checkout downloader receives a separate tool artifact containing
exactly `repopass-source-qualify-linux-amd64`,
`repopass-source-qualify-windows-amd64.exe`, and
`source-qualification-tool-manifest-v1.json`. It is not one of the four
qualification files and MUST NOT be a release payload or trust root.

The canonical tool manifest has exact top-level keys `artifactType`,
`schemaVersion`, `subject`, and `tools`. Type is
`repopass-source-qualification-toolset`, version is `1`, and `tools` is Linux
then Windows. Each entry has exactly `goarch`, `goos`, `goVersion`,
`mainPackage`, `modulePath`, `path`, `sha256`, `size`, `vcsModified`, and
`vcsRevision`; it binds the exact controller contract above, Go 1.26.5,
canonical module, tested revision, and `vcsModified=false`.
Canonical tool-manifest bytes are at most 64 KiB and nesting depth at most 8.

`verify-subject` MUST hash its own executable through one fixed handle before
parsing untrusted package claims. It strictly verifies the externally supplied
tool manifest and expected digest, requires both manifest tool entries to equal
the corresponding receipt `controller` values for their six shared identity
fields (`goVersion`, `mainPackage`, `modulePath`, `sha256`, `vcsModified`, and
`vcsRevision`), and independently validates the tool-only OS, architecture,
path, and size fields. It requires the current executable digest to equal its
lane entry, its lane receipt, and `--expected-executable-digest`. It hashes the
same executable handle again after verification and fails on mutation.

Both binaries are built outside the checkout with `CGO_ENABLED=0`, `-trimpath`,
`-buildvcs=true`, fixed clean environment, and no untracked source. The lane
inspects build information before upload. The tool-manifest digest is exposed
outside the tool artifact. The tool and its digest remain producer-owned and
self-consistent; replay independence is only from the producer workspace and
artifact directory, not implementation, identity, or acceptance authority.
The aggregate MUST copy the exact verified lane-controller bytes into the tool
artifact; it MUST NOT rebuild, rename from an unverified source, or substitute
a third controller binary.

Offline replay MUST create empty package/tool directories, download by
independently supplied numeric run and artifact IDs, verify the independently
supplied tool-manifest digest and selected binary digest before execution,
disable network, invoke `verify-subject` with every expected value, and re-hash
the tool and four package files afterward. The verifier reads USTAR in place;
it neither extracts source nor loads plugins. PASS cannot satisfy M3, RP-Q,
`PREQUALIFIED`, tag promotion, stable release, or a 100% claim.

### Failure behavior

The implementation MUST use these stable diagnostic codes internally and in
allowlisted controller output:

| Code | Meaning | Retry | Accepted evidence |
|---|---|---|---|
| `SOURCE_QUAL_INVALID_INPUT` | Flag or structural input invalid | no | none |
| `SOURCE_QUAL_SOURCE_DIRTY` | Checkout changed or is dirty | after source change | failed attempt only |
| `SOURCE_QUAL_SUBJECT_MISMATCH` | Commit/tree/base/currentness mismatch | no | failed attempt only |
| `SOURCE_QUAL_ARCHIVE_INVALID` | Archive shape/content/canonicalization failed | no | failed attempt only |
| `SOURCE_QUAL_MANIFEST_INVALID` | Manifest/schema/digest failed | no | failed attempt only |
| `SOURCE_QUAL_RECEIPT_INVALID` | Receipt/schema/platform binding failed | no | failed attempt only |
| `SOURCE_QUAL_GATE_SET_INVALID` | Gate missing/extra/duplicate/unknown/reordered/platform-inapplicable | no | failed attempt only |
| `SOURCE_QUAL_GATE_FAILED` | Gate failed, timed out, overflowed, or violated its semantic predicate | new tested revision for closure | failed attempt only |
| `SOURCE_QUAL_GATE_BLOCKED` | Required tool, network input, or infrastructure prerequisite unavailable | diagnostic retry only; new revision for closure | blocked attempt only |
| `SOURCE_QUAL_GATE_NOT_RUN` | Required gate skipped, cancelled, or not invoked | diagnostic retry only; new revision for closure | not-run attempt only |
| `SOURCE_QUAL_PRIVACY_INVALID` | Forbidden public content detected | no | no public package |
| `SOURCE_QUAL_CLEANUP_FAILED` | Private staging could not be removed | after operator action | failed attempt only |
| `SOURCE_QUAL_OUTPUT_LIMIT` | Public or private bounded output exceeded its limit | new tested revision for closure | failed attempt only |
| `SOURCE_QUAL_DESTINATION_EXISTS` | No-replace publication destination already exists | no | failed attempt only |

Diagnostics MUST NOT include a private path, raw command output, environment
value, source content, or secret candidate. A cleanup failure cannot be
downgraded after otherwise successful gates.

## Trust boundaries and security

Repository names and bytes, Git objects, worktree state, archives, manifests,
receipts, CI artifacts, workflow labels, filenames, and command outputs are
untrusted inputs. The producer-owned controller and offline structural
verifier produce authoritative structural and digest decisions only within
this limited self-CI predicate. They are not independent acceptance authorities.

Archive construction and offline verification never execute source bytes.
Gate execution does: `go test`, `go vet`, `go run`, and the release builder can
compile or execute code from the tested revision. Gates therefore run only in
a disposable, no-secret VM with read-only GitHub permissions, no host home,
engine socket, device, SSH agent, credential helper, or persisted checkout
credential. The controller owns the gate process group/Job Object and fails if
timeout, cancellation, cleanup, or residue enforcement is unavailable.

Version 1 does not claim isolation from an actor already executing as the same
OS principal or SYSTEM/root and racing controller-owned paths. Qualification
requires a quiescent, operator-controlled disposable runner. Such an actor is
in scope for M6, not hidden by an M0 receipt. Reparse, hardlink, alternate-data-
stream, no-replace, fixed-handle, and before/after checks remain mandatory.

This RFC adds parsers for Git paths, USTAR, and three strict JSON documents. All
are bounded and fail closed on traversal, symlink/reparse, hard-link, case
collision, duplicate key, noncanonical encoding, integer overflow, archive
extension, trailing data, inventory drift, mutation, or resource exhaustion.

No host credential, engine socket, device, home directory, or network service
is added to the product. Gate setup may use the existing Go module and
vulnerability database network paths; build and archive verification run with
their ambient injection surfaces disabled. The public package never contains
module proxy URLs or raw scanner output.

GitHub Actions uploads are transport only. Workflow identity, GitHub OIDC,
artifact retention, and checksums do not establish external trust under this
RFC.

## Privacy

Raw stdout, stderr, temporary paths, process identifiers, complete environment,
Git configuration, module-cache paths, and scanner responses are private run
inputs. They MUST be stored outside the checkout, bounded, and excluded from
the public four-file package.

The four-file transport has two privacy layers. `repopass-source.tar` and its
manifest are public source payload and payload metadata; they intentionally
contain already-public tracked bytes and portable tracked paths. The two
receipts are public evidence and MUST contain neither source member paths nor
source bytes. This does not authorize copying private, ignored, or untracked
worktree content. The canonical GitHub API public-tree confirmation is required
before either layer is uploaded.

Before publication, every receipt string MUST match its exact field grammar.
Manifest paths MUST pass the portable-path profile. A versioned allowlist-only
receipt scanner rejects token, cookie, authorization-header, email, endpoint,
local-path, private-key, and unrecognized high-entropy candidates; it never
scans raw source payload and then calls the result evidence-safe. Any receipt
scan match fails closed. This is minimization, not perfect secret detection.

Private run retention is a runner/operator policy. GitHub artifact retention
for the public package MUST be explicit and finite. There is no telemetry.

## Canonicalization and integrity

The archive digest covers every archive byte, including USTAR headers,
padding, and termination blocks. Each file digest covers exact Git blob bytes.
The manifest digest covers its complete canonical JSON bytes with no trailing
LF. Receipts bind archive and manifest digests. No file self-references or
claims to cover its own bytes; the separately reported package digest binds
all four canonical files without entering them.

Object keys follow the repository's canonical JSON ordering. `files` and
`gates` are ordered arrays; their order is semantically significant. No set is
silently sorted during verification. Time and platform facts appear only in
receipts, so they do not affect archive or manifest reproducibility.

Version-1 source artifacts are new. Existing Alpha archive, attestation,
release-index, policy, and golden digests remain byte-compatible and cannot be
read as version-1 source qualification.

## Compatibility and versioning

This RFC does not change manifest `apiVersion`, resolved-plan schema,
attestation bundle versions, product CLI, stable product error codes, policy
bundles, runner profile, adapter API, or observer API.

It introduces:

- `source-archive-manifest-v1.schema.json`;
- `source-qualification-receipt-v1.schema.json`;
- `source-qualification-tool-manifest-v1.schema.json`;
- predicate `https://repopass.dev/source-qualification/v1`;
- the exact version-1 four-file package and gate registry.

Readers MUST dispatch by exact schema and predicate version. A v0, Alpha
receipt, future version, or unknown field cannot be coerced into v1. Silent
downgrade is forbidden.

## Workflow acceptance

The version-1 workflow is
`.github/workflows/source-qualification.yml`. It MAY run for pull requests,
pushes to `main`, and manual dispatch, but only the first attempt of a canonical
`main` push can close `RP-M0-QUAL`. All actions use complete 40-hex commit pins;
checkout uses full history and no persisted credential. Workflow permissions
are exactly `contents: read` and `actions: read`; no secret, OIDC write,
environment, check write, content write, release authority, or cache is used.

Required jobs and dependencies are:

1. `context` resolves canonical repository, event, ref, tested revision, first
   parent, tree, run ID, run attempt, and qualification-run ID from trusted
   workflow context plus direct Git/GitHub reads.
2. `linux` and `windows` each check out that exact commit to distinct clean
   paths, build and inspect their host controller outside the checkout, and
   invoke `produce-lane`.
3. Each lane has an `if: always()` publication step. On PASS it uploads one
   exact three-file public lane artifact and a separate exact one-file
   controller artifact, named inside that artifact exactly
   `repopass-source-qualify-linux-amd64` or
   `repopass-source-qualify-windows-amd64.exe`. On a gate non-PASS after safe
   source construction it uploads the exact three-file lane output under a
   distinct attempt artifact. If safe source construction did not finish, it
   uploads only the fixed tombstone below. Neither variant is accepted as a
   lane input. Upload uses
   `if-no-files-found=error`,
   `overwrite=false`, hidden files disabled, compression level zero, and
   `retention-days: 90`. Private logs, caches, temp directories, and
   environment dumps are never uploaded.
4. `aggregate` uses `if: always()`, accepts only exact numeric artifact IDs from
   this run, independently validates both lane directories and both one-file
   controller artifacts, requires identical source/archive bytes and exact
   receipt/controller-digest agreement, creates the four-file aggregate and
   separate exact three-file tool artifact, and publishes their IDs/digests
   without overwrite.
5. `replay-linux` and `replay-windows` each start with empty directories,
   download aggregate and tool artifacts by numeric ID, disable network, and
   complete the no-checkout offline replay.
6. `accept` also uses `if: always()` and emits a deterministic non-PASS when
   any dependency failed, cancelled, timed out, or skipped.

Artifact names are exactly
`source-qualification-linux-amd64-<testedRevision>`,
`source-qualification-windows-amd64-<testedRevision>`,
`source-qualification-controller-linux-amd64-<testedRevision>`,
`source-qualification-controller-windows-amd64-<testedRevision>`,
`source-qualification-aggregate-<testedRevision>`, and
`source-qualification-tools-<testedRevision>`. A non-PASS attempt name is
`source-qualification-attempt-<lane>-<testedRevision>-<ordinal>`. Newest-artifact lookup,
name-only fallback, cross-run downloads, overwrite, and mixing attempts are
forbidden.

The preconstruction tombstone artifact contains exactly one regular file named
`source-qualification-attempt-v1.json`. Its canonical JSON has exactly
`artifactType`, `attemptId`, `code`, `expectedBaseRevision`,
`expectedTestedRevision`, `expectedTreeSHA`, `lane`, `ordinal`,
`qualificationRunId`, `qualificationStatus`, `schemaVersion`,
`workflowRunAttempt`, and `workflowRunId`. Type is
`repopass-source-qualification-attempt`, schema is `1`, expected identities
come only from the successful `context` job, status is `FAIL`, `BLOCKED`, or
`NOT_RUN`, and code is one failure-table identifier. It contains no error text,
path, output, or environment value. If even this safe file cannot be emitted,
authenticated GitHub run/job conclusion is the retained non-PASS attempt and
the revision is still ineligible; absence is never converted to PASS.
Canonical tombstone bytes are at most 16 KiB and nesting depth at most 4.

Immediately before PASS, `accept` MUST use the authenticated GitHub API and
out-of-package context to require: canonical repository; `push`; exact
`refs/heads/main`; attempt 1; live default branch still `main`; live main and
tree equal the tested subject; no earlier non-PASS source-qualification run for
that tested revision; exact first-parent base; both exact gate sets PASS with
no retry, skip, or manual action; aggregate/tool digests match; both replays
PASS on first execution; two source paths reproduce archive/manifest bytes;
and all cleanup checks return to baseline.

The accept record is one bounded canonical JSONL object with only `code`,
`packageArtifactId`, `packageDigest`, `qualificationRunId`,
`qualificationStatus`, `testedRevision`, `toolArtifactId`,
`toolManifestDigest`, `treeSHA`, and `workflowURL`. It is M0 release-program
evidence only, not a product verdict, external audit, signature, promotion, or
release authorization.

## Implementation plan

1. Add tests that freeze archive, manifest, receipt, registry, privacy, and
   repository source-contract behavior before production code.
2. Implement bounded Git-object acquisition and canonical USTAR construction
   in `internal/sourcequalification`.
3. Implement strict manifest/receipt parsers, schemas, canonical JSON, and
   aggregate verification.
4. Add the private `repopass-source-qualify` controller and PowerShell
   orchestrator.
5. Add Linux and Windows CI lanes that retain private logs only on the runner,
   upload platform public outputs, aggregate the two lanes, and verify the
   downloaded exact package.
6. Update release, status, limitation, and security documentation without
   claiming external trust or overall M0 completion.

Implementation MUST be a separate PR after this RFC is accepted.

## Test and conformance plan

Required tests include:

- canonical archive and manifest golden construction;
- two distinct absolute source paths producing identical archive and manifest;
- raw USTAR offset goldens for modes, empty/511/512/513-byte blobs, long-path
  prefix splitting, octal boundaries, checksum, padding, and exact terminator;
- Git blob/tree SHA-1 goldens and offline reconstruction rejection for changed
  content, path, mode, ordering, extra/missing entry, and copied tree string;
- path boundaries at 100/101/255/256 bytes, unsplittable paths, every forbidden
  byte, reserved device names, trailing dot/space, case collision, and
  file/directory prefix collision;
- exact Linux and Windows gate registries and aggregation precedence;
- wrong repository, module, base, tested revision, tree, dirty worktree, and
  changed-before/after source rejection;
- shallow/root/missing-parent repositories, replace objects, external
  alternates, sparse state, ignored/untracked entries, assume-unchanged,
  skip-worktree, staged mutation, wrong object type/size, and batch truncation;
- missing, extra, duplicate, unknown, reordered, failed, and not-run gates;
- archive traversal, absolute path, backslash, case collision, link, reparse,
  submodule, special entry, PAX/GNU extension, oversized entry/archive,
  truncation, mutation, and trailing-byte rejection;
- manifest/receipt duplicate keys, unknown fields, noncanonical JSON,
  digest/size drift, platform mismatch, and historical substitution;
- exact receipt key sets, field bounds, fixed limitations/non-applicable facts,
  attempt history, BLOCKED and output-semantic FAIL aggregation;
- cross-run, cross-attempt, name-only artifact lookup, rerun laundering,
  stale-main, wrong workflow/run/artifact ID, and tool substitution rejection;
- privacy rejection for path, endpoint, credential-like, and raw-output fields;
- timeout, output flood, cancellation, child-process residue, cleanup,
  preexisting destination, no-replace publication, hardlink/reparse/ADS, and
  before/after mutation paths;
- frozen fuzz seeds for archive and receipt parsers;
- PowerShell 5.1 parsing and Linux PowerShell execution;
- exact Go 1.26.5 Linux and Windows full source gates;
- clean merged-main artifact download into an empty directory followed by
  producer-owned offline structural verification with every expected identity;
- pinned-action workflow contract, full-history/no-credential checkout,
  explicit 90-day retention, `if: always()` aggregation/acceptance, first-run
  main-only closure, no required skip, and no secret/write permission.

The implementation PR MUST preserve this tests-first sequence: schema and
contract tests commit red before production code; archive/Git tests commit red
before builders; receipt/registry tests commit red before gate execution; and
workflow source-contract tests commit red before workflow changes.

The minimum source acceptance replay is:

```text
go mod download -modcacherw all
go mod verify
go mod tidy -diff
gofmt -l .
go vet ./...
go test -count=1 -timeout=30m ./...
go test -count=1 -tags=integration ./internal/cli -run ^$
```

It also includes both pinned govulncheck commands, PowerShell 5.1 parser
validation, Linux PowerShell execution, both exact lane registries, clean-path
byte comparison, Git-tree reconstruction, empty-directory download by numeric
artifact ID, offline replay on Linux and Windows, and an issue #6 evidence
comment containing the exact merged SHA, tree, run URL, artifact IDs, sizes,
digests, package digest, tool digest, and first-attempt status.

`RP-M0-QUAL` passes only after the implementation PR is merged, exact-main CI
passes on both platforms on attempt 1 without required skip, the aggregate is
downloaded by an independent operator/controller context and structurally
verified with explicit expected values, and archive/manifest bytes reproduce
from two clean paths. This closes only `RP-M0-QUAL`.

## Rollout and rollback

Version 1 is additive and pre-stable. CI first produces platform artifacts,
then an aggregate current-source package. It does not alter product runtime
behavior or existing Alpha assets.

Rollback removes the workflow and implementation but preserves previously
published source packages as historical material. After rollback,
`RP-M0-QUAL` returns to `NOT_RUN` or `FAIL`, and release promotion remains
blocked. A failed package or attempt is retained; it is not overwritten.

Any tracked byte change after qualification creates a new tested revision and
requires the complete qualification sequence again.

## Alternatives considered

### Use GitHub's automatic source archive

This is convenient but lacks this archive profile, exact gate receipts, and
cross-platform byte comparison. It was rejected as the qualification payload.

### Treat successful CI checks as the receipt

Checks are useful live metadata but do not freeze the public schema, exact gate
set, source archive, or portable offline replay. This was rejected.

### Sign with a locally generated key

That would let the producer authorize itself and would not establish external
identity or trusted time. It is expressly forbidden.

### Fold source artifacts into the Alpha.33 binary directory

That would change a frozen seven-file historical inventory and blur payload,
qualification, and promotion layering. Source qualification remains separate.

## Open questions

None. External signature, transparency, and release-promotion policy remain
M3 and stable-release decisions, not unresolved parts of this RFC.

## Decision record

- Decision: Accept, effective upon merge, the version-1 exact source archive,
  manifest, receipts, gate registry, offline structural replay, and workflow
  contract above.
- Date: 2026-08-11
- Approvers: @taipei49314 (repository owner and RFC author; self-approval only,
  no independent review claimed)
- Required follow-up: Implement and qualify through tracking issue #6 in a
  separate tests-first PR.
- Known limitations: No signer identity, trusted time, transparency,
  revocation, external review, container qualification, or release approval;
  currentness requires an explicit expected default-branch commit and tree.
- Amendment (2026-08-11): Add the required `produce-lane --expected-tree`
  input so a preconstruction non-PASS can preserve a context-bound tombstone
  without guessing a tree from unverified source or diagnostics. The same
  value is required to equal the safely inspected tree on constructed lane
  outputs. This amendment does not authorize a PASS, alter receipt or
  tombstone schema version 1, or relax any acceptance condition.
