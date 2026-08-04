# Security policy

RepoPassport executes untrusted repository workloads. Security reports are
therefore treated as first-class project work.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use the repository's private **Security → Report a vulnerability** flow. Include:

- the affected commit or release;
- the runner profile and container engine;
- a minimal reproducer or malicious fixture;
- expected and observed trust-boundary behavior;
- whether host credentials, paths, sockets, devices, network access, evidence,
  or report rendering may be affected;
- logs after removing secrets and personal data.

If private security advisories are unavailable, contact a maintainer privately
through the repository owner's published security contact. Do not send secrets,
live credentials, or harmful payloads by ordinary issue comments.

Maintainers will acknowledge receipt, reproduce the issue in an isolated
environment, assess supported versions, and coordinate remediation and
disclosure. Response times are targets rather than guarantees for this
early-stage project.

## Supported versions

| Version | Security fixes |
|---|---|
| Latest tagged alpha | Best effort |
| `main` | Development only |
| Older alpha releases | Not supported |

This table will become a formal supported-version policy before a stable
release.

## Dependency vulnerability qualification

Alpha.17 replaces the required indirect `golang.org/x/text@v0.14.0` module with
the minimum reviewed fixed release `v0.39.0` for `GO-2026-5970` /
`CVE-2026-56852`. Public checksum-database authentication remains enabled. The
GitHub Actions Go job runs `go mod download`, `go mod verify`, and
`go mod tidy -diff` before these pinned official scanner gates:

Selecting `x/text@v0.39.0` also advances upstream graph-only `x/mod` from
`v0.8.0` to `v0.37.0` and `x/tools` from `v0.6.0` to `v0.47.0`, and adds
`x/sync@v0.21.0`. No other repository-declared requirement changes. Release
qualification must prove that those three tool modules are absent from both
final product binaries.

```text
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 -C cmd/repopass -scan module
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 -test ./...
```

The first command fails on an advisory in the selected application module
graph even if static analysis finds no reachable vulnerable symbol. The second
checks reachable source and test symbols. Ordinary human-readable scanner mode
is intentional because structured JSON/SARIF output does not provide the same
finding exit-status gate.

A passing qualification is point-in-time evidence about the exact source,
release binaries, selected module graph, scanner version, and vulnerability
database recorded by that run. It is not an SBOM, dependency-completeness or
exploitability analysis, all-build-tag coverage, license review, or a guarantee
against future advisories. It does not upgrade the product's capability
`incomplete` or overall `inconclusive` verdict boundary.

## Alpha.33 offline trust-policy authority-chain boundary

Alpha.33 authenticates a canonical 2..8-hop sequence of existing Alpha.32
transitions from one explicit caller-supplied Ed25519 root. Every next key is
used only after the preceding authority authenticates its exact SPKI identity.
Global uniqueness, cycle rejection, strict generation increase, explicit
terminal-key equality, and the caller's terminal generation floor are required.
The root, every intermediate, and terminal authority must not also be a
trusted or revoked evidence signer in the terminal policy.

Flag shape and mode exclusivity are resolved before I/O. Intrinsic bundle
verification precedes root, terminal, chain, and policy access. State remains
untouched until the complete chain, terminal policy, floors, and role
separation pass; one private root-scoped chain-state transaction then commits
both chain and policy dimensions. This namespace is separate from direct and
one-hop state and supplies no cross-mode rollback protection.

The exact-three public companions cannot bootstrap trust. A compromised
accepted root can still authorize an attacker-controlled valid chain, so this
boundary is not compromise recovery. Root discovery, trusted identity/time,
historical revocation, transparency, tamper-resistant/distributed state, and
remote key custody/publication remain outside scope. The fixed claim boundary
is `identityAttestation=none`, `timeAttestation=none`, `formalClaim=false`,
capability `incomplete`, overall `inconclusive`.

## Alpha.32 offline trust-policy authority-transition boundary

Alpha.32 authenticates exactly one purpose-separated transition from an
independently accepted previous Ed25519 authority to one explicit distinct
terminal policy authority. Release-index transition payloads cannot replay in
this domain. Root, terminal, signature key ID, policy payload type, purpose,
and generation floor are cryptographically bound; the terminal and previous
authority cannot also be evidence signers in the terminal policy.

All mode/flag shape is rejected before I/O. Intrinsic bundle verification
precedes trust-input access. State is untouched until transition and terminal
policy signatures, roles, and floors are valid, then a single private
root-scoped lock and atomic record commit both dimensions. Invalid state is
rejected, never repaired. Direct policy state remains separate and is not
automatically promoted or migrated.

The producer's exact-three public companions cannot bootstrap trust. This
boundary does not provide compromise recovery: possession of an accepted old
root remains sufficient to authorize a malicious next authority. Multi-hop
chains, trusted identity/time, historical revocation, transparency,
tamper-resistant/distributed state, and remote key custody/publication remain
outside scope. The fixed claim boundary is
`identityAttestation=none`, `timeAttestation=none`, `formalClaim=false`,
capability `incomplete`, overall `inconclusive`.

## Alpha.31 offline trust-policy issuer boundary

`sign-offline-trust-policy` is a bounded local producer, not a trust service.
It accepts only a canonical PKCS#8 Ed25519 authority private key and 1..32
canonical Ed25519 signer SPKIs with explicit trusted/revoked decisions. Key IDs
are derived from canonical SPKI DER, globally sorted, and unique. The authority
must not also appear as a policy signer. Invalid argument shape is rejected
before command-specific I/O; signer inputs are read through bounded stable
snapshots and rechecked before exact-two publication.

The authority private key is never generated or published and must remain
outside the repository, authoritative data root, and output location. Existing
private-key ACL/mode, link/reparse, alternate-stream, hard-link, identity, and
stable-read checks apply. Publication uses a protected staging directory and a
no-replace same-parent directory rename; existing output is never overwritten.
The output authority SPKI is a companion only. It cannot bootstrap trust, and
verification still requires an independently trusted authority input and an
explicit generation floor.

This boundary does not cover a hostile writer replacing the already trusted
parent namespace, secure erasure, KMS/HSM, threshold signing, key generation,
custody, rotation, revocation history, remote publication, root discovery,
transparency, identity, or trusted time. It changes neither capability coverage
nor verdict semantics: `identityAttestation=none`, `timeAttestation=none`,
`formalClaim=false`, capability `incomplete`, and overall `inconclusive`.

## Alpha.30 signed external release-index and authority-transition-chain boundary

The new chain transport is not a trust anchor and performs no discovery or
fetching. It contains 2..8 canonical old-root-authorized transition envelopes
and exact next-key SPKIs. Verification authenticates each hop in order from the
explicit root, rejects key reuse, cycles, broken adjacency, non-increasing
generations, and a terminal key that differs from the supplied policy authority.
Only after a complete valid chain may optional controller-local chain state be
observed. A failed or incomplete later hop cannot initialize or advance state.

Alpha.30 retains the canonical exact artifact inventory with one dedicated
Ed25519 DSSE release signature, then authorizes that signer only through a
separately supplied, authority-root-signed `release-key-policy-v1`. The
authority SPKI is an explicit caller input; adjacent or bundled keys never
bootstrap trust, and authority/release roles must be different keys. Legacy
one-hop rotation requires explicit old-root and next-authority SPKIs plus one
old-root-signed canonical `release-authority-transition-v1`. Chain mode requires
the explicit initial root and authenticates 2..8 such transitions in order.
Every root companion is input material, not an implicit trust anchor.

The verifier authenticates the canonical index, scope, and DSSE signature
before chain, policy, state, artifact, or runner I/O. In chain mode it
then authenticates the explicit roots and transition before policy I/O, observes
an authenticated transition before policy state when persistence is selected,
authorizes the signer, enforces the caller's release-generation floor, verifies
every artifact, and only then observes release state. Files are bounded to 128 MiB each and 512 MiB per set;
`SHA256SUMS` is capped at 64 KiB. Unsafe names, links/reparse points,
hard-link aliases, alternate data streams, inventory drift, and mutations
observed by the two complete stable scans fail closed within the implemented
platform checks. The artifact root must be quiescent and operator controlled;
there is no atomic filesystem snapshot or immunity to a hostile concurrent
namespace/content writer.

Local authority-transition, policy, and release records detect rollback or same-generation equivocation
only relative to surviving records. Deletion, restore, copy, rename, or fork of
the selected data root can reset or fork history; generation is not trusted
time. Exact-digest mode is a caller pin. The result asserts neither publisher
legal identity nor trusted time: both attestations remain `none`,
`formalClaim=false`, capability `incomplete`, and overall `inconclusive`.
Rotation adds neither publisher identity, trusted time, transparency, remote
publication, root discovery, nor a tamper-resistant/distributed state service.

## Alpha.26 typed public qualification-evidence boundary

Alpha.26 treats raw fixed-VM Docker info/version/inspect, runtime/image logs,
test JSONL, race output, OS identity output, resource/listener snapshots, guest
console, host listener snapshots, and process IDs as private runner inputs.
They must not enter the public package. Guest temporary raw artifacts are
cleanup-attempted on all exits; host-private tool/operator/known-host records
are commitment inputs only.

Public fixed-VM execution facts are canonical typed receipts with bounded sizes, exact
keys and types, duplicate-key rejection, deterministic LF-only encoding, and
fixed semantic values. Every allowed public fixed-VM path has a parser or strict
record grammar. The builder and verifier reject renamed raw fixed-VM content, unknown or
duplicate fields, wrong types, noncanonical numbers, BOM/CRLF/trailing bytes,
path/case collision, link/reparse alias, public/private inventory drift, and
tampering even when the manifest, receipt, and its then-unsigned external index are
recomputed.

Local qualification Go logs remain bounded execution transcripts with
gate-specific validation and confidentiality scanning; this increment does not
claim that every local tool transcript is a typed receipt.

This minimizes an evidence-exfiltration surface; it does not guarantee secret
detection, trusted provenance, signer identity, trusted time, or full M3. That
historical Alpha.26 unsigned index proves only post-creation byte consistency
and is not retroactively upgraded by Alpha.29. Runtime
observer coverage and Alpha.25 verdict semantics are unchanged: healthy
capability remains `incomplete`, overall remains `inconclusive`, and
`formalClaim=false`.

## Alpha.25 peer TCP-listener comparison boundary

Alpha.25's peer listener comparison is limited to the sealed Docker/Linux/
amd64 approved Node-or-Python single-service HTTP profile. It reads only
Linux TCP listener tables within the existing trusted peer's bounded sample
window. The public event has an exact aggregate-only contract: fixed
non-sensitive observer metadata plus `comparisonResult` and
`evidenceBasis=aggregate-only`, and, only when complete, exactly four
endpoint-related counts for baseline, declared, sampled, and undeclared.
`not-tested` has no comparison-count fields. A positive comparison has at most one aggregate
`UNDECLARED_PORT_LISTEN` finding per repeat.

Raw endpoint/IP/port/URL data, `/proc` rows, socket inodes, namespace or PID
identity, tokens, frames, and stderr must not cross into public observations,
findings, reports, receipts, or formal evidence. Unexpected keys, malformed
counts, unsupported shapes, or incomplete barriers must fail closed without a
rendered count or finding. Sampling is not absence proof and does not cover
UDP, Unix sockets, short-lived listeners, outbound/NAT traffic, or process
attribution. Capability remains `incomplete`, overall remains `inconclusive`,
and `formalClaim=false`; this boundary is not a formal qualification claim.

## Alpha.24 Python notification-comparison boundary

Alpha.24 has a narrowly scoped positive detector, not complete filesystem
operation history. It is available only for Docker/Linux/pinned-Python CLI
synchronous foreground dispatches with no service, HTTP, signal, or background
work in the comparison window. The controller verifies immutable container
identity and separated, identical process snapshots on both sides; the trusted helper must
acknowledge the active phase and its bounded `filesystem.write` rules before
the workload command starts.

The helper performs matching in-container and exports only aggregate status and
counts. Raw paths, rules, contents, tokens, inotify cookies, and transcripts
never enter observations, findings, rendered reports, receipts, or formal
evidence. Queue overflow, unknown events, watch errors or races, unsafe names,
identity or transport failures, malformed/out-of-order frames, phase failure,
non-quiescence, unconfirmed dispatch, and all size/count limits fail closed: the comparison is
`not-tested`, with no partial public data or positive finding.

Node, Podman, non-Linux/non-Python runtimes, HTTP/services, signals, and
background execution remain unavailable. Inotify coalescing, rename pairing,
reads, syscalls, actor/process attribution, xattrs, ACLs, ownership, and paths
outside `/outputs` remain out of scope. Healthy runs remain capability
`incomplete` and overall `inconclusive`; `formalClaim=false`. This does not
complete M1, M2, or rootless qualification.

## Alpha.23 retained-state comparison boundary

Alpha.23 compares only the bounded post-init/pre-workload and
post-quiescence/pre-repair snapshots of `/outputs`. Observed paths must first
pass the existing normalized UTF-8, containment, length, entry-count, immutable
container identity, and quiescence gates. Matching accepts only exact paths,
the versioned one-child `/*` suffix, and the recursive `/**` suffix; other
characters are literal. Declarations from phases with no executable work do
not widen the comparison.

Public observations and errors expose aggregate counts and fixed semantics,
not raw paths, fragments, contents, symlink targets, helper output, or host
locations. A known unmatched retained delta fails capability conformance even
though complete operation coverage is unavailable. An unavailable snapshot or
boundary never becomes a successful comparison.

This boundary does not observe transient create/delete, write-then-restore,
the exact phase, actor, process, syscall, rename pairing, metadata-only action,
or any path outside `/outputs`. The comparison is therefore best-effort and
must not be treated as complete filesystem-write observation, sandbox proof,
or M2 completion.

## Alpha.22 local signed offline trust-policy state boundary

Alpha.22 retains Alpha.21's verifier-only state contract. Its exact
`verify-attestation` signed-policy triple is
`--trust-policy-envelope FILE`, `--trust-policy-authority-key FILE`, and
`--minimum-trust-policy-generation UINT`; it is mutually exclusive with both
legacy trust modes. The verifier completes bundle, signature, SPDX, and privacy
validation before reading the canonical authority SPKI or policy envelope. It
accepts only a bounded canonical `offline-trust-policy-v2` payload in a
single-signature DSSE envelope of type
`application/vnd.repopass.offline-trust-policy.v2+json`, and only when its
signed generation is within `1..9007199254740991` and meets the caller floor.

Acceptance authenticates policy solely relative to the caller-supplied
canonical authority SPKI and enforces that invocation's floor. The optional,
exactly-once valueless `--persist-trust-policy-state` is valid only with this
triple. After floor acceptance, it uses global `--data-dir` (or the controller
default) to serialize one canonical generation/payload record and lock per
authority. It rejects local rollback and same-generation payload equivocation
before signer authorization or freshness claims; a `revoked` or `not-listed`
signer still records an authenticated floor-qualified policy. Reports expose
only the state evaluation and valid stored generation, never a state path,
lock, stored digest, or filesystem detail; state fields are omitted outside
this opt-in mode.

On Windows, every newly created state-directory component and per-authority
lock file receives its protected private DACL in the atomic create operation,
through explicit `SECURITY_ATTRIBUTES`, `CreateDirectory`, and exclusive
`CreateFile(..., CREATE_NEW, ...)`, and is validated before use. Existing
objects are validation-only and are not re-ACL'd or repaired. This reduces a
creation-time ACL window; it does not make the selected data directory a native
sandbox or a boundary against an already-compromised administrator.

This is not tamper-resistant or distributed state, trusted time/expiry,
authority rotation/revocation/lifecycle, historical revocation, KMS/HSM,
Sigstore/OIDC/transparency, hosted trust, arbitrary policy extensions or
private-key management, complete M3, capability conformance, or overall
verification. Deleting, restoring, copying, or forking the selected data
directory can reset or fork local history. Alpha.21 and earlier evidence are
historical, bind only their exact source, and do not qualify Alpha.22.

## Alpha.19 offline trust-policy boundary

`verify-attestation --trust-policy FILE` requires an independently supplied
digest for the exact canonical policy bytes. The verifier completes any
supplied bundle digest check and all canonical bundle, signature, SPDX, and
privacy checks before policy access, then verifies the raw policy digest before
parsing. Authorization uses only the signer key ID recomputed from canonical
Ed25519 SPKI DER.

The policy is unsigned operator-selected input. `revoked` means rejected by
that supplied current policy only; it is not historical revocation evidence.
The digest is not policy authenticity, authorization provenance,
anti-rollback, trusted time, transparency, or external signer identity. Store
and distribute policy plus its independent digest through a trusted operator
process; Alpha.19 does not provide that process.

## Alpha.18 repository-derived SPDX boundary

The opt-in `attest --derive-spdx --current-manifest FILE` path is not a package
manager. It is a command-free static reader for only root `package.json` and
lockfile-version-3 `package-lock.json`; it does not invoke npm, Node, Git,
network services, or repository commands. It requires two matching source
snapshots before derivation and one more before signing, then binds canonical
SPDX plus provenance into the version-2 bundle model.

The lockfile `integrity` field has only an accepted checksum shape here; it is
not a registry download, registry authentication, or checksum verification.
The narrow profile is not general npm compatibility, package discovery or
completeness, SBOM truth, license/vulnerability analysis, or supplier identity.
Replay can touch a current source only after explicit SPKI trust and a raw
complete-bundle digest pin; currentness is separately `fresh`, `stale`, or
`unknown` and cannot upgrade capability `incomplete` or overall
`inconclusive`. Sealed Alpha.18 qualification evidence applies only to its
exact historical source and does not qualify Alpha.19.

## Security boundary

The trusted computing base includes the RepoPassport CLI, source acquisition,
resolver, policy evaluator, verifier, evidence builder, selected runner backend,
and external observers. Repository code and all workload-produced files are
untrusted.

A valid report does not mean a repository is safe, malware-free, or free of
vulnerabilities. It only describes a specific source, plan, policy, runner,
observer set, and scenario. Unobserved code paths remain unverified.

Important invariants:

- inspection does not execute repository commands;
- workload output cannot replace observations, assertions, policy decisions,
  verification results, or evidence;
- host roots, home directories, credentials, engine sockets, devices,
  privileged mode, host PID, and host networking are forbidden;
- source and selected inputs are read-only to the workload;
- unsupported enforcement or observation features produce `BLOCKED`,
  `INCOMPLETE`, or `INCONCLUSIVE`, never a fabricated pass;
- HTML reports escape repository-controlled content and use a restrictive
  Content Security Policy.

See [docs/security-model.md](docs/security-model.md) for the threat model and
[docs/known-limitations.md](docs/known-limitations.md) for current gaps.

## Security-sensitive changes

Changes to acquisition, archive/path handling, sandbox mounts, network
enforcement, process cleanup, observers, policy, verdict aggregation,
redaction, report rendering, evidence, signing, or CI release permissions
require security review. Add or update a malicious fixture with the fix.

Do not weaken a hard safety invariant through manifest configuration.
