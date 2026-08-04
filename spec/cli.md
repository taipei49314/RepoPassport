# CLI Contract

The full executable name is `repopass`. The portable verifier executable is
`repopass-verify`; it accepts only help, version, global options,
`verify-attestation`, and `verify-release-index`. Every other command is
rejected before command-specific I/O.

## Commands

```text
repopass inspect [path-or-url]
repopass init [path]
repopass validate [manifest]
repopass plan --scenario <name>
repopass verify --scenario <name>
repopass trial --scenario <name>
repopass report --run <id> --format text|json|html
repopass diff <old> <new>
repopass attest --run <id> --key <private-pkcs8.pem> --out <bundle.tar> [--public-key-out <public-spki.pem>] [--spdx <sbom.spdx.json>]
repopass verify-attestation <bundle.tar> [--expect-bundle-digest sha256:<hex>] [--trust-key <public-spki.pem> | --trust-policy <offline-policy.json> --expect-trust-policy-digest sha256:<hex> | --trust-policy-envelope <offline-policy.dsse.json> --trust-policy-authority-key <authority-public-spki.pem> --minimum-trust-policy-generation <uint> [(--trust-policy-authority-transition <transition.dsse.json> | --trust-policy-authority-transition-chain <chain.json>) --trust-policy-authority-trust-root <previous-public-spki.pem> --minimum-trust-policy-authority-generation <uint>]] [--persist-trust-policy-state] [--current-manifest <repo-passport.yml>]
repopass sign-offline-trust-policy --generation <uint> (--trusted-signer-key <public-spki.pem> | --revoked-signer-key <public-spki.pem>) [repeat, 1..32 total] --key <authority-private-pkcs8.pem> --out-dir <new-dir>
repopass sign-offline-trust-policy-authority-transition --next-authority-key <terminal-public-spki.pem> --generation <uint> --key <previous-authority-private-pkcs8.pem> --out-dir <new-dir>
repopass assemble-offline-trust-policy-authority-transition-chain --hop-envelope <file> --hop-next-authority-key <file> [repeat each ordered pair 2..8 times] --trust-policy-authority-trust-root <root-public-spki.pem> --minimum-trust-policy-authority-generation <uint> --out-dir <new-dir>
repopass sign-release-index --artifact-root <dir> --product-version 0.1.0-alpha.33 --release-generation <uint> --key <private-pkcs8.pem> --out-dir <new-dir>
repopass sign-release-policy --policy <canonical-policy.json> --key <authority-private-pkcs8.pem> --out-dir <new-dir>
repopass sign-release-authority-transition --next-authority-key <file> --generation <uint> --product repopass --channel alpha --key <previous-authority-private-pkcs8.pem> --out-dir <new-dir>
repopass assemble-release-authority-transition-chain --hop-envelope <file> --hop-envelope <file> [2..8 ordered values] --hop-next-authority-key <file> --hop-next-authority-key <file> [same count] --authority-trust-root <root-public-spki.pem> --out-dir <new-dir>
repopass verify-release-index --index <file> --signature <file> --signer-key <file> --artifact-root <dir> --policy-envelope <file> --policy-authority-key <authority-public-spki.pem> --product repopass --channel alpha --minimum-policy-generation <uint> --minimum-release-generation <uint> [--authority-transition <file> --authority-trust-root <file> --minimum-authority-generation <uint> | --authority-transition-chain <file> --authority-trust-root <file> --minimum-authority-generation <uint>] [--expect-release-index-digest sha256:<hex> | --persist-release-state]
repopass policy test
repopass doctor
repopass capabilities
repopass publish
```

`sign-offline-trust-policy` is available only in the full executable. It
requires exactly one generation, authority key, and new output directory plus
1..32 total trusted/revoked signer-key flags. It rejects malformed shape before
command-specific I/O. Every signer input must be canonical Ed25519 SPKI; IDs
are derived, globally sorted, and unique, so duplicate or cross-status identity
is invalid. The canonical PKCS#8 Ed25519 authority key cannot be a policy
signer. After signing, the producer authenticates its own exact envelope,
rechecks the signer snapshots, and publishes exactly
`offline-trust-policy.dsse.json` and
`offline-trust-policy-authority-public-key.pem` through a no-overwrite atomic
directory transaction. The companion never establishes trust. Structured
output retains `identityAttestation=none`, `timeAttestation=none`,
`formalClaim=false`, `capability=incomplete`, and `overall=inconclusive`.

`sign-offline-trust-policy-authority-transition` is full-CLI only. It signs one
canonical purpose-separated old-root-to-terminal transition, self-verifies,
rechecks the terminal key snapshot, and atomically publishes exactly terminal
SPKI, transition DSSE envelope, and previous-root SPKI companion. Companions
never establish trust. Rotation verification requires its three added flags as
an exact all-or-none extension of the complete signed-policy triple. The
existing persistence flag then commits one root-scoped combined transition+
policy record, not two partial records. Direct signed-policy mode remains
unchanged.

`assemble-offline-trust-policy-authority-transition-chain` is full-CLI only.
It accepts 2..8 occurrence-ordered transition-envelope/next-key pairs, one
explicit root, one canonical authority floor, and one new output directory.
It authenticates the complete chain, rejects input drift, and atomically
publishes exactly chain JSON plus terminal/root SPKI companions. Portable mode
rejects the producer before command-specific I/O. Verification selects either
one-hop or chain mode, never both; chain/root/floor flags are all-or-none.
Every authority must remain absent from terminal-policy evidence-signer roles.
Optional persistence writes one separate root-scoped chain+policy record and
makes no direct/one-hop/chain cross-mode rollback claim.

`verify-release-index` authenticates the index signature before it reads a
transition, policy, local state, artifact, or runner input. Direct mode omits
all rotation inputs. Rotation mode requires the exact complete transition/root/
generation group, authenticates the old root, next policy authority, and
old-root-signed transition before policy I/O, and observes authenticated
transition state before policy state when persistence is selected. It then
authenticates the purpose-separated policy, authorizes the authenticated release
signer, verifies the exact artifact set, and finally observes the release
generation. Artifact files are bounded to 128 MiB each and 512 MiB in total;
`SHA256SUMS` is additionally bounded to 64 KiB.

The artifact root MUST be quiescent and controlled by the trusted operator.
The verifier compares two complete stable scans and rejects observed drift; it
does not provide an atomic filesystem snapshot or a hostile concurrent-writer
security boundary.

`--persist-release-state` detects rollback or same-generation equivocation only
relative to the surviving local records under `--data-dir`. Deleting,
restoring, copying, renaming, or forking that state can reset or fork history.
`--expect-release-index-digest` is an exact caller pin, not trusted time.

Rotation success retains the existing release fields and reports
`trustBasis=release-key-policy-v1+authority-transition-v1`, the explicit
`trustRootKeyId`, `policyAuthorityKeyId`, transition payload/envelope digests,
transition generation, and the caller minimum authority-transition generation.
Persisted rotation additionally reports its transition-state evaluation and
generation. Direct mode keeps `trustBasis=release-key-policy-v1`, uses the
direct authority as `trustRootKeyId`, and omits all transition-only fields.
Both modes retain `publisherIdentityAttestation=none`, `timeAttestation=none`,
`formalClaim=false`, `capability=incomplete`, and `overall=inconclusive`.

Chain mode is mutually exclusive with one-hop mode. It accepts only 2..8
canonical ordered hops, authenticates the complete chain from the explicit root
before policy or state input, and reports the chain digest, hop count, terminal
generation, initial-root key ID, terminal authority key ID, caller floor, and
optional chain-state evaluation. The assembler rejects malformed argument shape
before input I/O and atomically publishes exactly chain JSON, root companion,
and terminal-authority companion; companions never bootstrap trust.

M1 requires `inspect`, `init`, `validate`, `plan`, `verify`, and `report`. Other commands may return a stable recognized-but-unsupported error until their milestone.

## Global flags

```text
--config <path>
--data-dir <path>
--cache-dir <path>
--log-level <level>
--log-format text|json
--no-color
--offline
--non-interactive
--output json|text
```

`--offline` forbids network acquisition and remote resolution. It does not permit stale or unresolved material to be presented as current.

`--non-interactive` fails rather than prompting for consent, ambiguity, or overwrite.

`--output json` emits exactly one versioned JSON document to stdout. Logs, progress, and diagnostics go to stderr. ANSI control sequences are never emitted in JSON mode.

## Inspect

```text
repopass inspect [path-or-url] --output json
```

Inspect performs inventory and static detection only. It MUST NOT execute, import, build, install, or source repository content. Every candidate field carries `declared` or `inferred` status, confidence, and provenance.

## Init

```text
repopass init [path]
```

Init writes `repo-passport.yml` and optional `.repopass/` authoring assets. It MUST NOT overwrite an existing manifest without explicit interactive confirmation. In non-interactive mode an existing target is an error.

Inferred fields retain provenance and are not represented as maintainer-confirmed.

## Validate

```text
repopass validate [manifest]
```

The default manifest path is `repo-passport.yml` in the selected repository. Validate performs JSON Schema and semantic validation and never executes repository code.

## Plan

```text
repopass plan --scenario quickstart
repopass plan --scenario quickstart --write-lock
repopass plan --scenario quickstart --check
```

Plan is preview-only by default. It resolves and prints:

- source identity;
- exact runtime and image digest;
- commands and defaults;
- phase capabilities;
- required runner features and observers;
- policy bundle;
- risk warnings;
- `planDigest`.

It does not modify `passport.lock.json` unless `--write-lock` is present.

`--write-lock` and `--check` are mutually exclusive. `--check` compares against an existing lockfile and reports `PLAN_DRIFT`; it never writes.

## Verify

```text
repopass verify --scenario quickstart --repeats 3
```

`--repeats` overrides the requested repeat count for this invocation but MUST NOT reduce it below the manifest's policy minimum. The effective value is included in the resolved plan, so changing it changes `planDigest`.

Safe defaults are:

- no host secret;
- runtime external network deny;
- no interactive workload shell;
- no host path mount;
- bounded logs and resources;
- complete sandbox cleanup attempt even after failure.

Verify produces controller-owned observations, assertion results, policy decisions, verification result, and report artifacts.

## Report

```text
repopass report --run <id> --format text
repopass report --run <id> --format json
repopass report --run <id> --format html
```

JSON and HTML are rendered from the same immutable verification view model. The JSON form validates against `verification.schema.json`. HTML is a static, escaped presentation and cannot contain active repository-provided HTML or script.

Without `--out`, the selected representation is written to stdout. With
`--out <path>`, the command writes that file and reports the path. `verify`
also stores a deterministic `report.html` beside the authoritative
`verification.json`.

## Attest

```text
repopass attest --run <id> --key <private-pkcs8.pem> --out <bundle.tar> [--public-key-out <public-spki.pem>] [--spdx <sbom.spdx.json>]
```

This is the narrow Alpha.15 local profile, not complete M3. The command
MUST load `<id>` from the authoritative external run store selected by
`--data-dir` and MUST recompute the verification artifact's existing integrity
contract before signing. It MUST NOT accept a repository-local verification as
authority or execute repository content.

The authoritative schema-4 plan seals whether `sbom` is selected. A selected
run requires exactly one occurrence-aware `--spdx` value; a no-SBOM run rejects
the flag without reading its path. Missing, duplicate, empty, positional,
single-dash, or otherwise malformed flag shapes are fixed, non-echoing
`MANIFEST_INVALID`/exit 2 failures before working-directory, key, or output
access. A well-formed flag whose presence disagrees with the sealed selection is
`EVIDENCE_BUILD_FAILED`/exit 1.

For the selected model, the attachment MUST be read through the bounded no-link
identity-preserving reader, validated as the strict RepoPassport SPDX 2.3 JSON
subset, canonically encoded, and passed through the frozen `minimal-public`
privacy gate before private-key or output access. Read/profile/canonicalization
failures are fixed, non-echoing `EVIDENCE_BUILD_FAILED`/exit 1; privacy rejection
is `EVIDENCE_PRIVACY_BLOCKED`/exit 7. No error or output may disclose its path,
raw bytes, rejected value, or dynamic JSON key.

The private key MUST be exactly one canonical PEM `PRIVATE KEY` block
containing Ed25519 PKCS#8 DER. It MUST be a bounded regular file outside the
authoritative data store and output location. When a current repository can be
detected by walking upward from the working directory to a `.git` or
`repo-passport.yml` marker, it MUST also be outside that repository. Symlink,
reparse, hard-link, device, alternate-data-stream, and unsafe platform path
forms MUST
fail closed. Unix group/other access MUST be rejected. On Windows, ownership
and DACL MUST be provable: the current owner, SYSTEM, and Builtin
Administrators are the only accepted identities. UNC, device,
extended-namespace, alternate-data-stream, trailing-dot/trailing-space, and
reserved DOS path forms MUST be rejected.

`--out` MUST name a new file outside the authoritative data store and, when
the current repository is detectable as described above, outside that
repository. The implementation MUST NOT overwrite an existing path. The
current
local implementation stages in the same directory, flushes and closes the
complete regular file, rechecks identity and size, and publishes with
no-replace semantics. This does not specify resistance to a hostile concurrent
rename/symlink/junction swap of the output parent and does not claim universal
power-loss durability for every Windows filesystem or storage provider.

The command optionally publishes `--public-key-out` as a separate canonical
Ed25519 SubjectPublicKeyInfo PEM companion for the exact signing key. Bundle
and companion destinations MUST be new, distinct, outside the authoritative
store and detectable repository, and validated before publication. Both use
bounded restrictive same-directory no-replace publication. Validation failure
MUST publish neither. If the companion is confirmed complete and durable but a
later bundle I/O/publication step fails, only that public artifact may remain
and structured error details MUST record the state.

The result MUST be one deterministic uncompressed USTAR. A no-SBOM schema-4 run
has exactly the following five regular-file entries; an SBOM-selected run has
exactly six by inserting the bracketed entry in the shown position:

```text
attestation.json
bundle-manifest.json
payload/verification.json
[payload/sbom.spdx.json]
signature.dsse.json
signer-public-key.pem
```

JSON and USTAR metadata MUST use the canonical Alpha.11 profile. The embedded
verification is unchanged. The in-toto Statement v1 predicate MUST bind its
run and verification IDs, artifact/content digests, source identity,
scenario/environment, plan/policy digests, schema-4 evidence selection, runner,
and original results. In the six-member model, the manifest and predicate also
bind the canonical SPDX path, byte size, digest, `SPDX-2.3` format, and
`application/spdx+json` media type. The
DSSE envelope MUST contain exactly one Ed25519 signature using exact PAE. The
key ID MUST be lowercase `sha256:<hex>` over the canonical SPKI DER.

Success reports `runId`, `verificationId`, `signerKeyId`, `manifestDigest`,
`bundleDigest`, `publicKeyDigest`, `bundlePath`, optional `publicKeyPath`,
`originalResults`, `privacyProfile`, `privacyPolicy`, `privacyRulesetDigest`,
`privacyEvaluation`, `sbomPresent`, `sbomFormat`, and `sbomDigest`.
The no-SBOM model reports false/empty/empty for those three attachment fields.
`bundleDigest` hashes the complete raw bundle bytes;
`publicKeyDigest` hashes canonical PEM bytes; `signerKeyId` continues to hash
canonical SPKI DER. It MUST NOT report the
private key path or bytes, and signing MUST NOT rewrite an original verdict or
evidence state.

## Verify attestation

```text
repopass verify-attestation <bundle.tar>
repopass verify-attestation <bundle.tar> --trust-key <public-spki.pem>
repopass verify-attestation <bundle.tar> --expect-bundle-digest sha256:<64-lowercase-hex>
repopass verify-attestation <bundle.tar> --expect-bundle-digest sha256:<64-lowercase-hex> --trust-key <public-spki.pem> --current-manifest <repo-passport.yml>
repopass verify-attestation <bundle.tar> --trust-policy <offline-policy.json> --expect-trust-policy-digest sha256:<64-lowercase-hex>
repopass verify-attestation <bundle.tar> --expect-bundle-digest sha256:<64-lowercase-hex> --trust-policy <offline-policy.json> --expect-trust-policy-digest sha256:<64-lowercase-hex> --current-manifest <repo-passport.yml>
repopass verify-attestation <bundle.tar> --trust-policy-envelope <offline-policy.dsse.json> --trust-policy-authority-key <authority-public-spki.pem> --minimum-trust-policy-generation <1..9007199254740991>
```

Verification is offline. Before considering the trust file, it MUST enforce
the complete bounded canonical USTAR/JSON profile, recompute the embedded
verification integrity, reconstruct the expected manifest and in-toto
statement, require the exact single-signature DSSE payload and PAE, derive the
key ID from the embedded canonical Ed25519 SPKI DER, and validate the
signature. When present, it MUST then require the plan-selected canonical SPDX
derivative, digest, strict profile, and privacy decision before optional trust
key access. Cryptographic or protected-content failure is
`ATTESTATION_INVALID`, even when a requested trust file is missing, unreadable,
or nonregular.

When `--expect-bundle-digest` is present, only exact lowercase
`sha256:<64 lowercase hex>` syntax is accepted. Malformed syntax is
`MANIFEST_INVALID`/exit 2. The verifier hashes the complete raw bundle before
trust-key file access; a mismatch is `EVIDENCE_DIGEST_MISMATCH`/exit 7. A
matching digest only pins transport bytes. Tampered bytes accompanied by their
recomputed digest continue to canonical and signature verification and are
`ATTESTATION_INVALID`.

The embedded public key and key ID MUST NOT confer trust. With no
`--trust-key`, a cryptographically valid bundle has `trustDecision: "unknown"`
and exits 7 with `ATTESTATION_UNTRUSTED`. An unavailable, malformed, or
different explicit key has `trustDecision: "rejected"` and exits 7. Only exact
canonical Ed25519 SPKI equality has `trustDecision: "accepted"` and exits 0.

Alpha.19 alternatively accepts the exact pair `--trust-policy FILE` and
`--expect-trust-policy-digest sha256:<64-lowercase-hex>`. Each MUST occur once
with a non-empty value; the pair is mandatory together and MUST NOT be combined
with `--trust-key`. Shape and digest-syntax errors are fixed, non-echoing
`MANIFEST_INVALID`/exit 2 before bundle I/O. The verifier MUST finish any raw
bundle digest pin, canonical archive/content, embedded verification, DSSE,
Ed25519, SPDX, and privacy checks before policy file access. It then reads one
bounded unlinked regular file, verifies the digest over its exact raw bytes,
and only then parses and evaluates it. Policy digest mismatch is
`EVIDENCE_DIGEST_MISMATCH`; unavailable or invalid policy and non-accepting
decisions are `ATTESTATION_UNTRUSTED`/exit 7.

The policy evaluates only the key ID recomputed from canonical embedded SPKI
DER. Status `trusted` produces `accepted` and reason `trusted`; `revoked`
produces `rejected`/`revoked`; an absent key produces
`rejected`/`not-listed`. Policy-mode reports add `trustBasis:
"offline-policy-v1"`, `trustPolicyDigest`, and `trustReason`. These optional
fields MUST be omitted in legacy no-trust and `--trust-key` output.

Alpha.20 alternatively accepts exactly one each of
`--trust-policy-envelope FILE`, `--trust-policy-authority-key FILE`, and
`--minimum-trust-policy-generation UINT`. The non-empty canonical generation
is decimal `1..9007199254740991`, with no sign, whitespace, or leading zero.
The triple MUST NOT be combined with `--trust-key` or Alpha.19's policy/digest
pair. Duplicate, partial, malformed, near-prefix, and case-alias shapes are
`MANIFEST_INVALID`/exit 2 before bundle I/O; separated and equals forms are
equivalent.

After all bundle integrity, signature, SPDX, and privacy checks, the verifier
reads the canonical authority SPKI and bounded signed-policy envelope. It
recomputes the authority key ID, requires it in the single DSSE signature,
checks PAE Ed25519 over payload type
`application/vnd.repopass.offline-trust-policy.v2+json`, then strictly parses
canonical `offline-trust-policy-v2` and enforces its signed generation against
the caller floor. It evaluates only the embedded signer SPKI DER key ID.
Policy-mode reports use `trustBasis: "signed-offline-policy-v2"` and may expose
only canonical policy/envelope digests, authority key ID, policy generation,
caller minimum generation, policy signature validity, and fixed reason
`trusted`, `revoked`, `not-listed`, `generation-below-minimum`, or
`invalid-or-unavailable`; paths, key bytes, policy contents, parser details,
and signature bytes are not reported. New fields are omitted from legacy modes.

This authenticates policy only relative to the caller-supplied authority and
enforces only that invocation's floor. It is not persistent anti-rollback,
trusted time/expiry, same-generation equivocation prevention, authority
rotation/revocation/lifecycle, historical revocation, KMS/HSM,
Sigstore/OIDC/transparency, hosted trust, policy signing/private-key management,
complete M3, capability conformance, or overall verification.

Structured output reports `artifactIntegrity`, `signatureValidity`,
`bundleDigest`, `publicKeyDigest`, `signerKeyId`, `trustDecision`,
`freshnessEvaluation`, `runId`, `verificationId`, `originalResults`,
`privacyProfile`, `privacyPolicy`, `privacyRulesetDigest`, `privacyEvaluation`,
`sbomPresent`, `sbomFormat`, and `sbomDigest`. Without `--current-manifest`,
Alpha.16 MUST report `freshnessEvaluation: "not-evaluated"` and omit the
`freshness` object. The opt-in flag requires exactly one accepted trust
mechanism (one `--trust-key`, the complete digest-pinned policy pair, or the
complete signed-policy triple) and one canonical
expected bundle digest; malformed, empty, missing, duplicate, or mixed trust
inputs fail before I/O. Accepted trust authorizes bounded source/policy/plan
re-observation and an exact signed-backend probe. The resulting unsigned report
is `current`, `stale`, or `unknown` with four ordered checks. Stable mismatch
uses `EVIDENCE_STALE`; incomplete observation MUST remain `unknown` under an
operational error. `originalResults.freshness` is only the signed historical
value and MUST NOT be rewritten or presented as replay currentness. The
historical verification does not contain the former local source path, so the
caller-supplied root is not inferred historical provenance. If the current working
directory exposes neither repository marker, the historical result cannot be
used to infer a repository boundary for private-key or output exclusion.

The bounded freshness report is not scenario re-execution, elapsed-age or
expiry validation, hostile namespace-swap immunity, Git/registry provenance,
complete runner identity, observer/SBOM re-validation, or a capability/overall
upgrade. Sigstore, OIDC, transparency logs, KMS, TPM/HSM, timestamping,
historical revocation, key lifecycle, SBOM generation/completeness validation,
hosted policy authenticity, anti-rollback, and remote publication are outside
this bounded contract.

Separated `--name value` and `--name=value` forms are equivalent for the
Alpha.16/Alpha.19/Alpha.20 flags. Argument normalization MUST preserve each flag value and MUST
NOT reinterpret or reorder it as the single bundle positional argument.
A separated path value may begin with `-`; it remains the value unless that
token is a recognized freshness flag (including a malformed freshness-flag
variant), in which case the preceding flag is missing its value. Automation
SHOULD prefer the `--name=value` spelling for dash-leading paths.

## Failure policy

CI may request verdict-sensitive exits:

```text
--fail-on blocked,functional-fail,nonconforming,inconclusive
```

The default set is empty. A completed verification therefore exits zero even when its JSON contains `fail`, `nonconforming`, `blocked`, or `inconclusive`. A selected `--fail-on` condition changes that exit status.

`--fail-on` changes only process exit behavior. It MUST NOT rewrite any verdict.

When multiple selected outcomes occur, use this precedence:

```text
nonconforming -> functional-fail -> blocked -> inconclusive
```

## Exit codes

| Code | Contract |
|---:|---|
| 0 | Operation completed successfully; verification verdict remains in JSON. |
| 1 | Command usage, IO, or internal error. |
| 2 | Manifest/schema/semantic validation failure or plan drift in check mode. |
| 3 | Verification blocked. |
| 4 | Selected functional failure. |
| 5 | Selected capability nonconformance. |
| 6 | Selected inconclusive outcome. |
| 7 | Evidence or attestation verification failed. |

Stable errors remain present in JSON regardless of the exit mapping.

## Structured output envelope

Non-report commands use:

```json
{
  "schemaVersion": "1",
  "command": "validate",
  "status": "ok",
  "data": {
    "valid": true,
    "manifestDigest": "sha256:..."
  }
}
```

`status` is `ok`, `invalid`, or `error`. A command-level failure uses the
singular `error` field and validates against `error.schema.json`; validation
findings appear in `data.errors`. `data` is command-specific and the envelope
is versioned with `schemaVersion`.

Report JSON is the verification document itself, not this envelope, so automation does not need to unwrap the authoritative result.
