# Five-minute quick start

This quick start uses dependency-free fixtures. It does not download npm or pip
packages and does not require repository-provided setup scripts.

## 1. Run local checks

Use the Go version declared by `go.mod`:

```bash
gofmt -w .
go vet ./...
go test ./...
```

Docker is not needed for schema and unit tests. Live verification and the
opt-in integration test suite require a supported Linux container backend.

## 2. Inspect without execution

```bash
go run ./cmd/repopass inspect \
  ./testdata/fixtures/healthy/healthy-node-cli \
  --output json
```

Inspection may report a signal similar to:

```json
{
  "field": "runtime",
  "value": "node",
  "source": "package.json",
  "method": "node-package-adapter",
  "confidence": 1,
  "status": "inferred"
}
```

The signal is a proposal with provenance. `inspect` must not run a package
script, import a repository module, install dependencies, execute `setup.py`,
or execute a shell block copied from a README.

## 3. Validate a manifest

```bash
go run ./cmd/repopass validate \
  ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml
```

Try the two intentionally invalid examples:

```bash
go run ./cmd/repopass validate \
  ./testdata/fixtures/invalid/unknown-field/repo-passport.yml

go run ./cmd/repopass validate \
  ./testdata/fixtures/invalid/literal-secret/repo-passport.yml
```

They must fail with `MANIFEST_UNKNOWN_FIELD` and
`MANIFEST_LITERAL_SECRET`, respectively. Invalid fixtures should not proceed to
planning or execution.

## 4. Resolve a plan

From the healthy Node fixture:

```bash
go run ./cmd/repopass plan \
  --manifest ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml \
  --scenario quickstart \
  --write-lock
```

A resolved plan removes floating values and binds:

- immutable source identity;
- exact base image digest;
- exact declared runtime and adapter versions;
- plan-bound JSON Schema path, digest, dialect, and validator version when a
  structured assertion is declared;
- Linux workload platform;
- commands and sandbox paths;
- cleanup classifier version and the exact allowed-residue profile;
- phase-scoped capabilities;
- required runner and observer features;
- policy bundle digest;
- canonical plan digest.

Running resolution twice with the same semantic input must produce the same
plan digest. `plan --check` must return `PLAN_DRIFT` if the committed lockfile
does not match.

Alpha.15 uses resolved-plan `schemaVersion: "4"` and seals the exact
`minimal-public` evidence selection. The CLI journey driver is
`0.2.0`; the HTTP journey driver remains `0.1.0`, and the manifest API remains
`repopass.dev/v1alpha1`. Version-1, version-2, and version-3 plan locks are never
reinterpreted: expect
`PLAN_DRIFT`, regenerate it with `--write-lock`, and review the changed plan.
Historical evidence remains a read-only integrity record.

## 5. Check backend features

```bash
go run ./cmd/repopass doctor
```

Read the feature list literally. For example, network deny enforcement can be
available while denied destination observation is unavailable. A missing hard
runner feature blocks before workload execution. Missing observer coverage
remains explicit and prevents a complete capability/overall verdict; it does
not silently lower the standard.

## 6. Verify a scenario

The execution path never pulls an image. The built-in `baseline-v1` profile
accepts only the exact Node/Python Linux `amd64` tuples in
[the release guide](release.md), and binds that allowlist into the policy
digest. First use a trusted preparation step to approve and pull the exact
reference printed by `plan`; never substitute a mutable tag or a different
pinned image. A digest makes the selected image immutable, but does not
establish publisher trust.

```bash
go run ./cmd/repopass verify \
  --manifest ./testdata/fixtures/healthy/healthy-node-cli/repo-passport.yml \
  --scenario quickstart \
  --repeats 3 \
  --output json
```

The healthy Node CLI fixture exercises `stdoutJsonSchema`. The controller
validates the complete captured stdout as exactly one strict JSON document
against the local, plan-bound, offline Draft 2020-12 schema. The instance is
bounded to 1 MiB, depth 128, 100,000 nodes, and decimal exponent
`-1000..1000`. Shared stdout/stderr log truncation produces an
`inconclusive` assertion; complete malformed JSON or a schema mismatch is
`failed`. Assertion evidence omits stdout content, parsed values, property
names, stdout hashes, and byte counts.

`v0.1.0-alpha.19` also plans and verifies the constrained Python and Node HTTP
fixtures. Pre-pull the exact reference emitted by the plan, then run:

```bash
go run ./cmd/repopass plan \
  --manifest ./testdata/fixtures/healthy/healthy-python-http/repo-passport.yml \
  --scenario quickstart \
  --output json

go run ./cmd/repopass verify \
  --manifest ./testdata/fixtures/healthy/healthy-python-http/repo-passport.yml \
  --scenario quickstart \
  --output json
```

Alpha.10 classifies cleanup independently from the functional journey. The
healthy fixture declares `allowedResidue: [/outputs/**]`, so its deterministic
regular output is `allowed-residue`, not `clean`. An empty allowlist with any
descendant, or any symlink/special entry, is `undeclared-residue` and produces
`CLEANUP_RESIDUE` without becoming an operational execution error. A missing
or incomplete bounded inventory is `not-tested`; it is never promoted to
clean. Public cleanup evidence contains aggregate counts and an opaque
one-time token, not raw output paths, targets, or contents. The fresh HMAC key
and raw inventory are discarded; the token cannot be opened or independently
recomputed and is neither an attestation nor proof.

The HTTP profile runs exactly one attached repository service as UID/GID
`65532`. A bounded controller-supplied readiness/request helper runs
synchronously as UID/GID `65533` and exits after each operation. Both execute
inside the same `--network none` container, using only its loopback interface;
the runner publishes no host port. Readiness and request URLs must use literal
`http://127.0.0.1:<explicit-port>`, be canonical and no longer than 2,048 UTF-8
bytes, match the one declared TCP listener, and stay on the same origin.

When `port-listen` is required on this exact Docker profile, alpha.8 also
launches a controller-owned peer observer from the same pinned image. It shares
only the target network namespace and samples Linux TCP listener tables. A
clean report is still only `best-effort`; it does not satisfy the required
observer or turn the overall verdict into verified success. Podman does not
provide this observer.

For the Python tuple, controller-supplied helpers use `python -I -S` with
working directory `/`. They do not start from `/workspace`, so repository
modules cannot shadow helper imports.

Readiness and request timeout values are absolute wall-clock deadlines, not
socket-inactivity timers. A small runner-owned margin is reserved only to
cancel and account for the helper after the functional deadline. Before a
readiness retry or cleanup, UID/GID `65533` must have exited synchronously or
been quiesced by a trusted root helper; an unconfirmed state fails closed.
HTTP timeouts must resolve to whole milliseconds and be at least 1 ms.
Fractional seconds are accepted at exact millisecond precision: `1.5s` is
1,500 ms and valid, but `1.5ms` is rejected. Readiness is capped at 2 minutes,
uses exponential retry backoff, and stops after 128 attempts at the latest.
Readiness and asserted response statuses are 200–599. The controller reports
`service.start` as succeeded only after readiness succeeds. Each explicit
request timeout and the resolved exercise fallback used when omitted are
capped at 30 minutes; the fallback is `phases.exercise.timeout`, or 1 minute
when the phase timeout is absent.

The HTTP driver accepts at most 128 ordered steps and 32 requests. Effective
headers must simultaneously satisfy count ≤ 64 and aggregate bytes ≤ 65,536,
with each header value capped at 8,192 bytes. Aggregate bytes are
`sum(len(name bytes) + len(value bytes) + 4)` over every effective header;
accepted names and values are ASCII, so these are also their UTF-8 byte
lengths. The trusted driver's automatic JSON `content-type` counts in both the
effective count and aggregate. A text request body and the actual serialized
bytes of a JSON request are each capped at 1 MiB.

The implemented HTTP assertion subset is response status, header substring,
`bodyContains`, `fileExists`, singular `jsonPath.equals`, offline Draft
2020-12 response `jsonSchema`, and ordered `jsonFile`. The bundled healthy
HTTP fixtures exercise all three structured JSON operations. Redirect
following, TLS, request authentication, multiple services, full RFC 9535
JSONPath, and remote/cross-file schema resolution are not supported. A header
`contains` value is capped at 8,192 bytes, and `bodyContains` must be non-empty
and no larger than 1 MiB.

`fileExists` is checked when its ordered journey step executes. The trusted
in-container check accepts only a normalized UTF-8 `/outputs` path of at most
4,096 bytes, uses `lstat` through every component, and rejects symlinks rather
than following them.

Structured JSON response/file bodies are limited to 1 MiB and decoded
strictly: duplicate keys, trailing JSON, excessive nesting/node counts,
decimal exponents outside `-1000..1000`, and invalid UTF-8 fail closed while
accepted numbers retain exact precision. Schema files are portable regular
source files capped at 256 KiB; their path,
SHA-256, Draft 2020-12 dialect, and validator version are bound into the
resolved plan. `jsonFile` uses a dirfd/`O_NOFOLLOW` walk under `/outputs` and
validates the point-in-time snapshot. Raw JSON and extracted values are not
written to assertion evidence.

Exactly one cleanup signal targets the service. The trusted signal helper
honors its grace period and escalates surviving UID/GID `65532` workload
processes to `SIGKILL`; finalization quiesces that workload identity before
export. Cleanup is successful only if the signal helper found at least one
workload target and successfully sent at least one signal; an
enumeration/delivery race fails closed. This means `initialTargets >= 1` and
`sent >= 1`, not that every initial target must receive the signal. Every
signal type, including `kill`, requires a whole-millisecond grace period from
1 ms through 10 seconds. The service signal is the final cleanup step and final
resolved command, leaving runner-owned helper slack. UID/GID `65533` has
already exited or been root-quiesced.

Verification creates a fresh sandbox for every repeat. The declared CLI command
or attached service is untrusted workload code; the controller evaluates CLI
exit status or bounded HTTP responses and declared assertions outside the
workload's decision boundary.
Source, workspace, and inputs are read-only. Writable output, workload home,
and temporary data share the declared engine tmpfs cap, up to the local 2 GiB
ceiling. After initialization and before workload execution, the runner
verifies the immutable container identity and captures a bounded `/outputs`
retained-state baseline. On Docker it also invokes exactly
`docker container diff <immutable-64hex-id>` and records an opaque diagnostic
baseline commitment. Finalization quiesces the non-root workload identity,
re-verifies that identity, and captures the final retained-state and Docker
engine-diff commitments before deleting disposable home/temp state or
repairing the tree. It then checks and streams
the output tree through the allowlisted image's fixed `/bin/tar`. Go code
rejects unsafe archive entries and atomically commits only a bounded,
twice-inventoried staging tree. The selected runtime and tar helper are
therefore explicit local trusted-computing-base components; this flow does not
use engine `cp`.
The verifier combines those assertions, available observations, runner
features, policy, and run metadata.

## 7. Interpret results

Always read all dimensions:

```text
Functional       PASS | FAIL | BLOCKED | INCONCLUSIVE
Capability       CONFORMING | WARNING | NONCONFORMING | INCOMPLETE
Reproducibility  STABLE | FLAKY | NOT_REPRODUCIBLE | NOT_TESTED
Cleanup          CLEAN | ALLOWED_RESIDUE | UNDECLARED_RESIDUE | NOT_TESTED
Evidence         NONE | UNSIGNED | SELF_SIGNED | ...
Freshness        CURRENT | SOURCE_CHANGED | PLAN_CHANGED | ...
```

These are rendered labels. Versioned JSON uses the lowercase enum values defined
by its schema.

`Functional PASS` plus `Capability NONCONFORMING` is not verified success. A
single run cannot produce `STABLE`; it remains `NOT_TESTED`. Missing required
observation coverage must produce `INCOMPLETE`, `BLOCKED`, or `INCONCLUSIVE`
according to where the gap was discovered.

With the built-in observation report, a complete alpha.5 snapshot pair gives
the `filesystem.retained-state.summary` event coverage `high`, while composite
`FilesystemWriteObservation` and foreground process coverage are best effort.
On the exact alpha.8 Docker HTTP profile, the peer listener summary can make
`PortObservation` `best-effort`; it remains `unavailable` on Podman and
unsupported shapes. The retained-state event is an
aggregate `filesystem.retained-state.summary`: its snapshot commitments
incorporate regular-file content and raw symlink-target SHA-256, but it exposes
only snapshot digests, entry counts, and a change count. It includes trusted
helpers and runner-managed, workload-writable disposable `.home`/`.tmp` state,
which is excluded from export.

The retained-state snapshot pair itself is not operation history. It cannot
observe outside `/outputs`, operation time, process/actor attribution, rename
identity, ownership, timestamps, xattrs, ACLs, inodes, or device identity;
its failure is nonfatal and reports retained-state `unavailable`.

Alpha.24 adds a separate aggregate-only positive detector for transient
create/delete, write-then-restore, and a mutation declared only in another
controller-dispatch phase. It is available only for Docker/Linux/pinned-Python
CLI synchronous foreground commands without service, HTTP, signal, or
background work. The helper acknowledges only the active phase's existing
`filesystem.write` rules before dispatch, and the controller checks immutable
identity plus separated, identical process snapshots on both sides and records
one confirmed successful dispatch per acknowledged window. Its public summary never
contains a path, rule, content, token, inotify cookie, or raw transcript.

It remains `best-effort`, not complete operation history: Node, Podman,
non-Linux/non-Python runtimes, HTTP/services, signals, and background work are
`not-tested`/`unavailable`; queue overflow, watch races, unsafe paths, identity
or transport failure, malformed frames, phase/quiescence failure, unconfirmed
dispatch, and every bound failure fail closed without partial counts or a
finding. Runtime Python overflow/gap uses a minimal exact session-bound failure
terminal and exit `1`, never a success-shaped partial aggregate. Healthy runs
remain capability `INCOMPLETE`, overall `INCONCLUSIVE`, and
`formalClaim=false`; Alpha.24 does not complete M1, M2, or rootless
qualification.

Alpha.8 adds the Docker-only `port.listener-trace.summary`. Immediately before
service dispatch, the controller creates a peer container from the exact
pinned Node or Python image. It verifies the same network namespace and
separate PID, mount, IPC, and cgroup namespaces, then requires strict `READY`
and `FINAL` boundaries around service execution and quiescence. The peer runs
as UID/GID `65534` with a read-only root, no capabilities, no new privileges,
no mounts, ports, devices, or privilege, and fixed 64 MiB memory/swap, 16-PID,
and 0.25-CPU limits. It is removed before the target container.

The peer samples `/proc/net/tcp` and `/proc/net/tcp6` every 100 ms. It accepts
at most 16 endpoints, 1,200 samples, 4,096 transitions, a 1-second maximum
sample gap, 8 KiB frames, 16 KiB total stdout, 8 KiB stderr, and a 1 MiB
canonical sample stream. The declared loopback TCP endpoint must be absent
initially, observed while the service runs, and absent again after quiescence.
Any identity, namespace, boundary, protocol, timeout, overflow, gap, stderr,
exit, or removal failure makes the event unavailable.

Public evidence contains only declared-endpoint aggregates and a keyed helper
commitment, not the session token, raw `/proc` data, socket inodes, undeclared
endpoint identities, or process attribution. Polling can miss a short-lived
listener and supplies no kernel-event, UDP, or process-attribution coverage;
the controller does not independently recompute the helper commitment.
Therefore even a complete trace is `best-effort`, required `port-listen`
remains incomplete, and the overall result remains `INCONCLUSIVE`.

Historical Alpha.6 additionally reports a Docker-only
`filesystem.engine-diff.summary`. The fixed shell-free
`docker container diff <immutable-64hex-id>` call bounds stdout and stderr
independently to 4 MiB and accepts only exit `0`, no truncation, and empty
stderr. Because filenames may contain newlines, stdout remains opaque. The
report exposes only its SHA-256, byte count, and nonempty flag—never raw bytes,
paths, or parsed `A`/`C`/`D` records.

The baseline engine transcript is diagnostic only. Only the identity-reverified
final call after quiescence and before repair can give this component
`best-effort`. Docker's output is cumulative from container creation, may
include trusted and pre-workload work, and cannot attribute actor, time, or
phase. It excludes `/outputs` tmpfs and mounted source/workspace/input
filesystems. It does not change retained-state event coverage `high` into full
filesystem coverage, detect undeclared writes, or satisfy the required
filesystem-write observer.

Historical Alpha.7 adds a separate Docker-only
`filesystem.activity-trace.summary`. The controller starts a trusted root
helper before workload execution with the shell-free
`docker exec --interactive --user 0:0 ...` transport and stops it after quiescence. Its
strict bounded stdin/stdout JSONL protocol must contain exactly one `READY`
and one `FINAL`. The random session token crosses only stdin and is never
published in argv, environment variables, logs, or evidence. No
workload-writable control file is created.

The report contains aggregate notification counts, controller-window phase
hints, and a per-session keyed canonical transcript digest, not paths,
contents, actors, operations, or syscalls. Node uses non-recursive
per-directory `fs.watch` watchers capped at 2,048 and cannot detect kernel
queue overflow. Python uses inotify with the same cap and fails closed on
queue overflow. Dirty stderr, nonzero exit, timeout, malformed/extra/trailing/
oversize frames, identity mismatch, overflow, a detected gap, or bound failure
makes the whole trace unavailable.

Dynamic watch installation, coalescing, reads, rename pairing, exact operation
and phase semantics, and actor attribution remain blind spots. The helper
reports `observerPlacement=in-sandbox-trusted-helper` and
`sharesSandboxResourceBudget=true`, so it can perturb resource measurements.
Podman activity tracing remains unavailable. Even a complete
trace supplies only `best-effort` notification hints and does not complete the
required filesystem observer.

Existing retained-state and engine-diff path commitments use unsalted raw
SHA-256. Not publishing raw paths does not make them dictionary-resistant:
low-entropy candidate paths can be guessed and tested. The activity trace's
keyed digest does not change that historical boundary.

Historical live record `20260730T173121Z` validates `ResourceUsage` coverage
`high` only for a complete
cgroup-v2 sample on the exact Docker 29.1.3 / Ubuntu 24.04.4 / kernel 6.8 /
Linux `amd64` / approved-image tuple. Memory is a cgroup peak, not RSS; PID
peak counts tasks, not processes; writable bytes are a final allocation
snapshot, not a peak. Enforcement alone cannot satisfy the observer, and
missing fields remain unavailable rather than zero. Required filesystem-write
coverage remains incomplete. A live CLI or HTTP functional pass therefore
still has capability `INCOMPLETE` and overall `INCONCLUSIVE`; neither M1 nor M2
is complete, and the result must not be described as overall verified.

By default, exit code `0` means the command completed; read the verdict from
structured output. CI can opt into verdict-to-exit mapping:

```bash
--fail-on functional-fail,blocked,nonconforming,inconclusive
```

This option changes process exit behavior, not the recorded verdict.

## 8. Test the trust boundary

The malicious fixture writes a forged `/outputs/verification.json`:

```bash
go run ./cmd/repopass verify \
  --manifest ./testdata/fixtures/malicious/fake-verification-json/repo-passport.yml \
  --scenario quickstart \
  --output json
```

The file is a workload output. It must never replace trusted assertions,
observations, policy decisions, or the verification result.

## 9. Render an offline report

```bash
go run ./cmd/repopass report \
  --run <run-id> \
  --format html
```

By default, authoritative runs live in the controller's user configuration
area. A report store inside the current repository is rejected when that
repository is detectable from the working directory; no historical source
path is available to infer an otherwise unknown boundary.

The static report works without an official API. Repository-controlled fields
rendered in HTML are escaped, raw workload streams are not included, and a
restrictive Content Security Policy prevents repository-provided scripts from
running.

## 10. Create and verify a local attestation

Alpha.19 retains the local attestation/replay, optional schema-4-plan-selected
SPDX attachment, and bounded freshness profiles, and adds a digest-pinned
offline trust-policy alternative.
Prepare an Ed25519 private key
as canonical PKCS#8 PEM and its public key as canonical SPKI PEM using a trusted
key-management procedure. Keep the private key outside the authoritative data
directory and output location and, when detectable, the current repository.
The bundle destination must also be new, outside the authoritative data
directory, and outside the current repository when detectable.

```bash
go run ./cmd/repopass --data-dir <authoritative-data-dir> attest \
  --run <run-id> \
  --key <private-pkcs8.pem> \
  --out <new-bundle.tar> \
  --public-key-out <new-public-spki.pem>

go run ./cmd/repopass verify-attestation <new-bundle.tar> \
  --expect-bundle-digest sha256:<64-lowercase-hex> \
  --trust-key <new-public-spki.pem> \
  --output json

# Optional point-in-time local freshness re-observation. All three trust/pin
# inputs are mandatory together.
go run ./cmd/repopass verify-attestation <new-bundle.tar> \
  --expect-bundle-digest sha256:<64-lowercase-hex> \
  --trust-key <independently-accepted-public-spki.pem> \
  --current-manifest <current-source-root>/repo-passport.yml \
  --output json
```

Alpha.31 can produce that existing signed-policy input with the full CLI.
Signer public keys and the authority private key must come from an independently
controlled key-management procedure; the command does not generate or retain
them. Keep the authority private key outside the repository, authoritative data
directory, and output location. The output directory must not already exist:

```bash
go run ./cmd/repopass sign-offline-trust-policy \
  --generation 7 \
  --trusted-signer-key <accepted-evidence-signer-public-spki.pem> \
  --revoked-signer-key <retired-evidence-signer-public-spki.pem> \
  --key <policy-authority-private-pkcs8.pem> \
  --out-dir <new-policy-directory> \
  --output json
```

At least one and at most 32 signer-key flags may be repeated in any order. The
producer derives and sorts their identities, rejects duplicates and authority
role overlap, rechecks the signer files before publication, and writes exactly
`offline-trust-policy.dsse.json` and
`offline-trust-policy-authority-public-key.pem`. The latter is a companion, not
a trust anchor; verify it through an independent trusted channel before use.

Alpha.22 retains Alpha.21's local-state option. Append the opt-in flag when the
controller should remember accepted policy generations for that authority:

```bash
go run ./cmd/repopass --data-dir <controller-data-dir> verify-attestation <new-bundle.tar> \
  --trust-policy-envelope <new-policy-directory>/offline-trust-policy.dsse.json \
  --trust-policy-authority-key <independently-accepted-authority-public-spki.pem> \
  --minimum-trust-policy-generation 1 \
  --persist-trust-policy-state \
  --output json
```

The triple occurs exactly once and is mutually exclusive with `--trust-key` and
the Alpha.19 pair below. `--persist-trust-policy-state` occurs exactly once,
has no value, and is legal only with that complete triple; omit it for the
unchanged stateless mode. The payload is canonical `offline-trust-policy-v2` in
a dedicated single-signature DSSE envelope. After bundle/policy authentication
and the caller floor, stateful mode records one canonical authority-scoped
generation/payload state below `<data-dir>/trust-policy-state/v1/`, before
signer authorization or freshness. It rejects local rollback and
same-generation payload equivocation; a `revoked` or `not-listed` signer still
records the authenticated floor-qualified policy. Reports expose only the
state evaluation and valid stored generation, and omit both fields in
stateless/legacy modes. This is not tamper-resistant or distributed state,
trusted time/expiry, authority lifecycle, or historical revocation: deleting,
restoring, copying, or forking the data directory can reset/fork local state.

Alpha.32 can rotate that policy authority by exactly one explicitly trusted
hop. Produce transition companions with the full CLI:

```bash
go run ./cmd/repopass sign-offline-trust-policy-authority-transition \
  --next-authority-key <terminal-policy-authority-public-spki.pem> \
  --generation 8 \
  --key <previous-policy-authority-private-pkcs8.pem> \
  --out-dir <new-transition-directory> \
  --output json
```

Then verify using an independently accepted previous root and the terminal
authority that signed the policy:

```bash
go run ./cmd/repopass --data-dir <controller-data-dir> verify-attestation <bundle.tar> \
  --trust-policy-envelope <terminal-policy-directory>/offline-trust-policy.dsse.json \
  --trust-policy-authority-key <terminal-policy-authority-public-spki.pem> \
  --minimum-trust-policy-generation 8 \
  --trust-policy-authority-transition <new-transition-directory>/offline-trust-policy-authority-transition.dsse.json \
  --trust-policy-authority-trust-root <independently-accepted-previous-authority-public-spki.pem> \
  --minimum-trust-policy-authority-generation 8 \
  --persist-trust-policy-state \
  --output json
```

The three rotation flags are all-or-none. Persistence writes one combined
root-scoped transition+policy state record; it does not update the direct
Alpha.31 state file. The exact-three output public keys remain companions and
must not be used as automatic trust bootstrap.

Alpha.33 can instead verify an explicit chain of 2..8 ordered Alpha.32
transitions. Assemble already-signed hop envelopes with the full CLI:

```bash
go run ./cmd/repopass assemble-offline-trust-policy-authority-transition-chain \
  --hop-envelope <root-to-intermediate.dsse.json> \
  --hop-next-authority-key <intermediate-public-spki.pem> \
  --hop-envelope <intermediate-to-terminal.dsse.json> \
  --hop-next-authority-key <terminal-policy-authority-public-spki.pem> \
  --trust-policy-authority-trust-root <independently-accepted-root-public-spki.pem> \
  --minimum-trust-policy-authority-generation 8 \
  --out-dir <new-chain-directory> \
  --output json
```

Then replace the one-hop transition flag with the chain transport:

```bash
go run ./cmd/repopass --data-dir <controller-data-dir> verify-attestation <bundle.tar> \
  --trust-policy-envelope <terminal-policy-directory>/offline-trust-policy.dsse.json \
  --trust-policy-authority-key <terminal-policy-authority-public-spki.pem> \
  --minimum-trust-policy-generation 8 \
  --trust-policy-authority-transition-chain <new-chain-directory>/offline-trust-policy-authority-transition-chain.json \
  --trust-policy-authority-trust-root <independently-accepted-root-public-spki.pem> \
  --minimum-trust-policy-authority-generation 8 \
  --persist-trust-policy-state \
  --output json
```

One-hop and chain flags are mutually exclusive. Chain persistence uses a
separate root-scoped combined record and does not claim rollback protection
when changing between direct, one-hop, and chain modes. Every authority in the
chain must remain absent from trusted and revoked evidence-signer entries.

Alpha.19 alternatively uses an exact canonical policy containing the
verifier-computed signer key ID. The file must contain only these one-line JSON
bytes, with keys sorted by `keyId` and no BOM, CR, alternate whitespace, or
final newline:

```json
{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[{"keyId":"sha256:<64-lowercase-hex>","status":"trusted"}],"schemaVersion":"1"}
```

Then pin that exact file independently:

```bash
go run ./cmd/repopass verify-attestation <new-bundle.tar> \
  --trust-policy <offline-policy.json> \
  --expect-trust-policy-digest sha256:<64-lowercase-hex> \
  --output json

# Policy-authorized freshness still requires the complete raw-bundle pin.
go run ./cmd/repopass verify-attestation <new-bundle.tar> \
  --expect-bundle-digest sha256:<64-lowercase-hex> \
  --trust-policy <offline-policy.json> \
  --expect-trust-policy-digest sha256:<64-lowercase-hex> \
  --current-manifest <current-source-root>/repo-passport.yml \
  --output json
```

The policy pair is mandatory together and mutually exclusive with
`--trust-key`. `trusted` accepts, `revoked` rejects, and an absent signer is
`not-listed`. The digest pins bytes; it does not authenticate the policy or
provide anti-rollback, trusted time, or signing-time revocation history.

The verifier checks the plan-selected deterministic five- or six-entry USTAR,
strict canonical JSON,
authoritative verification integrity, manifest and in-toto bindings, exact
single-signature DSSE envelope, Ed25519 signature, key ID, and selected trust
mechanism entirely offline. Without either an explicit key or complete policy
pair, a valid signature is reported with trust `unknown` and exit code 7. A
different or unreadable key is rejected; policy status `trusted` accepts,
while `revoked` or `not-listed` rejects.

When the verified manifest's exact evidence include set contains `sbom`, the
attest command instead requires one strict caller-supplied SPDX 2.3 JSON file:

```bash
go run ./cmd/repopass --data-dir <authoritative-data-dir> attest \
  --run <sbom-selected-run-id> \
  --spdx ./testdata/fixtures/healthy/minimal-public-spdx/sbom.spdx.json \
  --key <private-pkcs8.pem> \
  --out <new-six-member-bundle.tar>
```

The six-member model binds the canonical derivative as
`payload/sbom.spdx.json`; JSON and text report presence, `SPDX-2.3`, and its
canonical SHA-256 digest. RepoPassport does not generate the input, discover
packages, assess licenses/vulnerabilities, or prove completeness, correctness,
currentness, or producer identity.

Alpha.18 additionally offers the mutually-exclusive repository-derived form:

```bash
go run ./cmd/repopass --data-dir <authoritative-data-dir> attest \
  --run <sbom-selected-run-id> \
  --derive-spdx \
  --current-manifest <current-source-root>/repo-passport.yml \
  --key <private-pkcs8.pem> \
  --out <new-v2-seven-member-bundle.tar>
```

This is a static, command-free narrow profile for only root `package.json` and
lockfile-version-3 `package-lock.json`: it does not run npm, Node, Git,
network access, or a repository command. Two matching snapshots bind
derivation and a third binds signing. Lockfile integrity is accepted by
checksum shape only; it is not verified with a registry. The derived v2 bundle
binds canonical SPDX and provenance. It is not general npm compatibility,
package discovery/completeness, SBOM truth, supplier provenance, or
license/vulnerability analysis. The current snapshot must exactly equal the
authoritative verification subject. Since this command-free profile uses an
empty Commit, it supports only the same local/exported non-Git identity; a
Git-commit subject fails closed.

The expected digest pins the complete received bundle bytes before the
trust file is accessed. It does not confer trust. The separately published
companion is byte-identical to the embedded canonical SPKI PEM, but package-
local equality is not maintainer identity, CA validation, or transparency.

Read the JSON dimensions independently. Without `--current-manifest`, replay
reports `freshnessEvaluation: "not-evaluated"`. With the opt-in flag, exact
trust and the raw-bundle pin must succeed before current source access. The
report then contains ordered source, policy, plan, and runner checks and is
`current`, `stale`, or `unknown`. Stable mismatch emits `EVIDENCE_STALE`;
unavailable or unstable observation remains `unknown` under an operational
source, plan, runner, or cancellation error. The nested
`originalResults.freshness` is the stored historical verdict and does not mean
the source, plan, policy, or runner was re-observed. The original result,
including `capability: incomplete`, `overall: inconclusive`, or
`evidence: unsigned`, is never upgraded by signing. The historical verification
does not retain the former local source path, so this command cannot recover or
recheck it. Repository exclusion is based only on a `.git` or
`repo-passport.yml` marker discoverable from the current working directory. If
neither exists, the current boundary is unknown and the historical path cannot
fill that gap.

On Windows, signing additionally requires a provably restricted key DACL: the
current owner, SYSTEM, and Builtin Administrators are the only permitted
identities. UNC, device, extended-namespace, alternate-data-stream,
trailing-dot/trailing-space, reserved DOS, reparse-point, and hard-linked key
paths fail closed. Output publication does not claim protection against a
hostile concurrent rename/symlink/junction swap of its parent, or universal
power-loss durability for every Windows filesystem/provider.

The bounded check does not rerun the scenario, evaluate elapsed age, defeat a
hostile concurrent namespace swap, validate Git/registry provenance, recover
complete runner identity, re-observe execution coverage, or establish SBOM
currentness. Sigstore, OIDC, KMS, TPM/HSM, transparency logs, timestamping,
revocation, SBOM generation/independent validation, remote publication, and
complete M3 remain unsupported.

For a trusted, raw-digest-pinned derived-v2 bundle, the same opt-in current
manifest route performs its derived-SBOM comparison only after trust and pin
acceptance. It separately reports `fresh`, `stale`, or `unknown`; that value
never upgrades stored `capability: incomplete` or `overall: inconclusive`.
Alpha.22 qualification requires exact source-bound evidence. Alpha.21 and
earlier qualification evidence is historical, applies only to its exact source,
and does not qualify Alpha.22.

## Current scope

Alpha.25's `port.listener-trace.summary` is present only for the narrow
supported Docker peer-observer HTTP profile. Its public comparison is
aggregate-only: fixed non-sensitive observer metadata and result/evidence
basis always, exactly four endpoint-related counts only when complete, no
comparison counts for `not-tested`, and no raw endpoint information. It is
not a listener-absence proof or UDP/process-attribution observer; healthy runs
remain capability `incomplete`, overall `inconclusive`, and `formalClaim=false`.

Read [known limitations](known-limitations.md) before interpreting a live run
and [error reference](error-reference.md) when automating the CLI. Alpha.8
local/repro record `20260731T085753Z` passed and reproduced the release files,
but remains historical and does not qualify the changed Alpha.22 source.
Historical live record `20260731T085836Z` passed 19/19 ordered guest gates, 12/12 required
Docker cases, sequential Node/Python peer-listener evidence, and the Linux race
gate on Docker 29.1.3, Ubuntu 24.04.4 LTS, kernel 6.8.0-134-generic, Linux
`amd64`, cgroup v2, QEMU, and the exact approved images. Residue comparisons and
final teardown also passed. This record is unsigned and exact-tuple only: it
does not qualify Podman, rootless operation, another version/kernel/image/
architecture tuple, M1, or M2, and healthy results remain capability
`INCOMPLETE` and overall `INCONCLUSIVE`.

This source document does not claim an Alpha.22 local/repro or fixed-VM live
qualification. Use only a final source-bound evidence package that records the
exact gate results and environment tuple.

Historical live record `20260730T173121Z` passed all 18 gate steps and all ten
required CLI/HTTP,
adversarial, lifecycle, cleanup, disk-enforcement, and resource-observation
cases on Docker
client/server 29.1.3 in an isolated Ubuntu 24.04.4 LTS Linux `amd64` QEMU VM.
The resource case used kernel 6.8 and cgroup v2. It claims only that exact
Docker/VM/cgroup/approved-image tuple; Podman, rootless engines, other Docker
versions or kernels, and `arm64` remain unclaimed. The nine-case
`20260730T150346Z` `alpha.3`, `20260730T102841Z` `alpha.2`, and four-case
`20260730T074535Z` `alpha.1` records remain historical. Healthy functional
passes remain capability `INCOMPLETE` and overall `INCONCLUSIVE`, M1 and M2
are incomplete. Their original evidence remains unsigned; Alpha.11 can sign an
immutable historical verification without rewriting that state.
