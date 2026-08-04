# Canonicalization, Digests, and Lockfile

This document defines the v1alpha1 canonical byte representation. Implementations that produce different bytes for the same semantic value are nonconforming.

## Digest format

Every digest is:

```text
sha256:<64 lowercase hexadecimal characters>
```

The prefix identifies the algorithm and is part of the wire value. SHA-256 input is the exact canonical UTF-8 byte sequence described below.

## Deterministic JSON profile

v1alpha1 uses the reference Go implementation's deterministic JSON profile. It is deliberately narrower than, and MUST NOT be advertised as, full RFC 8785/JCS interoperability:

1. Values are first encoded and decoded through Go `encoding/json`; the decoder uses `UseNumber`.
2. Non-ASCII object keys are rejected. This keeps the supported key-ordering domain portable and testable.
3. Map keys use the deterministic ordering produced by the pinned Go runtime. Structs are converted through JSON before the final encoding.
4. The final encoder uses `SetEscapeHTML(false)`, emits no indentation, and the trailing newline is removed.
5. Arrays retain order unless a field is explicitly defined as a set below.
6. NaN, infinity, non-JSON data, and duplicate decoded object names are outside the supported model.
7. Resolved CPU, memory, disk, and PID limits are integers. Command timeouts remain normalized Go duration strings in schema version 1.
8. The exact output bytes are UTF-8 without BOM.

The profile is deterministic for the v1alpha1 portable subset and pinned reference implementation. Cross-language equivalence for non-ASCII keys, unusual Unicode escaping, or RFC 8785 number formatting is not claimed. A future cross-language canonicalization standard requires a new generated schema/canonicalization version and golden migration tests.

## Set-valued arrays

The resolver removes duplicates and sorts these fields by the canonical bytes of each item:

- filesystem path sets;
- network allow endpoint sets;
- port-listen endpoint sets;
- process executable sets;
- environment variable sets;
- secret ID sets;
- `allowedExitCodes`;
- `requiredRunnerFeatures`;
- `observerSet`;
- evidence include/exclude sets;
- evidence and error reference sets.

Command arrays, phase steps, HTTP driver steps, assertions, observations, and repeats are ordered sequences and MUST NOT be reordered.

## Normalization before plan construction

The resolver MUST:

- replace a Git ref with a complete lowercase 40-hex commit;
- compute the normalized SHA-256 tree digest;
- resolve a runtime range to one exact semantic version;
- resolve a base-image reference to one SHA-256 image digest;
- bind every adapter and observer to an exact semantic version;
- expand command working directory, timeout, allowed exit codes, output mode, and environment references;
- expand all phase capability defaults;
- convert CPU to integer millicores;
- convert sizes to integer bytes;
- normalize durations to Go duration strings;
- make every sandbox path absolute and canonical;
- add explicit protocol defaults;
- bind the runner profile and policy bundle to digests.

The lockfile MUST contain no mutable tag, version range, inherited capability, relative sandbox path, floating policy reference, default timeout, or ambiguous source ref.

## Source and tree identity

For Git sources:

- `source.commit` is the complete 40-hex Git commit object ID.
- `source.identity` is `git:` plus that complete commit.
- `source.treeDigest` is not the Git object ID. It is SHA-256 over the normalized file inventory.

For directory sources, `commit` is absent and `source.identity` equals the normalized SHA-256 tree digest.

Each normalized inventory entry contains path, size, normalized mode, and content digest. Entries are sorted by path. v1alpha1 source paths are restricted to a printable-ASCII portable subset; backslashes, control characters, Windows reserved device names, trailing dot/space segments, traversal, and portable case-fold collisions are rejected. Arbitrary Unicode NFC/case-fold behavior is not claimed.

## Manifest digest

`manifestDigest` is SHA-256 over the canonical JSON form of the validated manifest after:

- YAML decoding;
- identifier, host, and path normalization;
- removal of YAML presentation details such as comments, anchors, and key order.

Author-provided `x-` extensions remain included. Resolver-added defaults are not inserted into the manifest digest; they appear in and are bound by the resolved plan.

## Plan digest

`planDigest` is computed as follows:

1. Build the complete object that validates against `resolved-plan.schema.json`.
2. Remove the top-level `planDigest` member only.
3. Canonicalize the remaining object with this profile.
4. Compute SHA-256 over those bytes.
5. Prefix the lowercase hex result with `sha256:`.
6. Insert that value as `planDigest`.

The digest therefore excludes itself and includes source identity, manifest digest, scenario, environment, exact runtime and full image reference, resource limits, resolved inputs, adapter/observer/driver versions, commands, journey assertions, cleanup, exact evidence selection, capabilities, runner features, observer set, repeat policy, and policy bundle digest. Non-semantic timestamps are forbidden in a resolved plan.

## Verification digest

The `digests.verification` field is computed analogously:

1. Construct the complete verification object.
2. Remove only `digests.verification`.
3. Canonicalize and SHA-256 hash the remainder.
4. Insert the resulting digest.

Observation, assertion, and policy-decision digests are computed over their canonical ordered collections and are included in the verification object.

## Alpha.11 M3-a attestation canonicalization

The local Alpha.11 attestation profile adds a byte-exact canonical contract; it
does not claim complete M3 or general in-toto/DSSE archive interoperability.

### Attestation JSON

`attestation.json`, `bundle-manifest.json`, `payload/verification.json`, the
optional `payload/sbom.spdx.json`, and `signature.dsse.json` use the deterministic
JSON profile above. In addition, an attestation verifier MUST reject invalid
UTF-8, a BOM, duplicate object names, unknown fields, trailing content,
noncanonical base64, excessive depth/node/byte bounds, or bytes that differ
from re-encoding the accepted value canonically. The embedded verification
MUST also satisfy `verification.schema.json` and its recomputed integrity
contract. Semantically equivalent alternate JSON bytes are invalid in this
bundle profile.

### Ed25519 key and key ID

The signing key input is exactly one header-free PEM block of type
`PRIVATE KEY` whose bytes are canonical Ed25519 PKCS#8 DER; any remainder or
alternate encoding is invalid. The bundle public key is exactly one
header-free PEM block of type `PUBLIC KEY` whose bytes are canonical Ed25519
SubjectPublicKeyInfo DER. Parsing and re-marshalling MUST reproduce the exact
PEM and DER bytes.

The DSSE `keyid` is:

```text
sha256:<lowercase SHA-256 hex of the canonical SPKI DER bytes>
```

PEM text is not the key-ID hash input. The key ID and embedded key identify a
signer but are not a trust anchor; trust requires exact comparison with an
independently supplied canonical SPKI key.

### Public-key companion and complete-bundle digest

When requested, the separate public companion MUST be byte-identical to the
canonical embedded SPKI PEM. Its digest is:

```text
sha256:<lowercase SHA-256 hex of the canonical SPKI PEM bytes>
```

The complete bundle digest uses the same textual form but hashes every raw
byte of the canonical USTAR. Expected-digest input accepts exactly that form.
It is checked before optional trust-key access and does not replace canonical
archive reconstruction, DSSE/Ed25519 verification, or explicit SPKI trust.

### Alpha.19 offline trust policy

`offline-trust-policy-v1` is a separate authorization input, never a bundle
member. Its accepted bytes are exactly the deterministic JSON encoding of:

```json
{"keyAlgorithm":"ed25519","keyIdAlgorithm":"spki-sha256","keys":[{"keyId":"sha256:<64-lowercase-hex>","status":"trusted"}],"schemaVersion":"1"}
```

There is no BOM, CR, leading/trailing byte, alternate whitespace, alternate
object-key order, escaped/duplicate/unknown name, or trailing newline. The
document is at most 65,536 bytes and contains 1--32 keys in strict increasing
ordinal `keyId` order with no duplicates. Each status is exactly `trusted` or
`revoked`. The expected policy digest is lowercase `sha256:<64 hex>` over
these exact raw canonical bytes and MUST match before parsing or use.

The policy does not alter bundle canonicalization or signature bytes. Its
digest pins bytes but does not authenticate the operator-selected policy or
provide anti-rollback, historical revocation time, or trusted time.

### Alpha.20 signed offline trust policy

`offline-trust-policy-v2` is a separate authorization input,
never a bundle member. Its canonical JSON payload is at most 65,536 bytes and
has schema version `"2"`, `ed25519`, `spki-sha256`, a positive safe-integer
`generation` in `1..9007199254740991`, and 1--32 strict ordinal-sorted unique
signer entries with only `trusted` or `revoked` status. It uses the deterministic
JSON profile: no BOM, duplicate or unknown names, alternate whitespace,
noncanonical number form, or trailing byte.

It is carried only in a canonical single-signature DSSE envelope no larger than
98,304 bytes, with payload type exactly
`application/vnd.repopass.offline-trust-policy.v2+json`. The signature is
Ed25519 over the DSSE PAE and its `keyid` is SHA-256 over canonical supplied
authority SPKI DER. The verifier recomputes that identity rather than trusting
the envelope field. This canonical transport authenticates policy only relative
to the caller-supplied authority; it does not persist generations or provide
anti-rollback, trusted time, expiry, equivocation prevention, or authority
lifecycle.

Alpha.31's full-CLI producer emits exactly this unchanged canonical payload and
envelope. It derives every key ID from canonical Ed25519 SPKI DER, sorts the
complete trusted/revoked set ordinally, rejects duplicate or authority-role
identities, and self-verifies the exact envelope before exact-two publication.
The authority SPKI companion does not change canonicalization or establish
trust; a verifier still receives an independently trusted authority input.

### Alpha.32 signed offline policy-authority transition

The one-hop transition payload is canonical JSON no larger than 16 KiB with
exact schema version, purpose, v2 policy payload type, safe-integer generation,
Ed25519/SPKI-SHA256 algorithms, and distinct previous/next authority key IDs.
Its canonical exact-one-signature DSSE envelope is no larger than 32 KiB and
uses only
`application/vnd.repopass.offline-trust-policy-authority-transition.v1+json`.
The previous root signs; both explicit canonical SPKIs must match the payload.
Release transition types, alternate JSON/base64/PEM encodings, multiple
signatures, and role overlap fail closed.

### Alpha.33 signed offline policy-authority transition chain

The chain is an unsigned canonical JSON transport no larger than 256 KiB with
exact `schemaVersion`, `purpose`, `policyPayloadType`, and `hops` fields. It has
2..8 ordered hops, each containing only canonical padded RFC 4648 base64 of one
canonical Alpha.32 transition DSSE envelope and one canonical next-authority
SPKI PEM. The decoded per-member limits remain those of Alpha.32.

Canonical bytes, adjacency, globally unique authority IDs, cycle rejection,
strictly increasing generations, explicit root and terminal equality, and the
terminal generation floor all bind. The domain-separated chain digest prefixes
the exact canonical transport with
`repopass.offline-trust-policy-authority-transition-chain.v1\x00`. An embedded
key, companion, reordered hop, release-protocol envelope, or permissively
decoded representation cannot establish trust.

### Alpha.28 external release index and key policy

`release-index-v1` is an external canonical JSON payload, at most 1 MiB, for
exactly one artifact root. It has exactly `artifactType`, `channel`, `files`,
`product`, `productVersion`, `releaseGeneration`, `schemaVersion`, and
`trustBoundary` in the deterministic JSON profile. `files` has 1--128 strict
ordinal-sorted, unique and case-fold-unique top-level portable basenames. Each
entry has only `path`, `sha256`, and a JSON-safe non-negative `size`; digests
are lowercase `sha256:<64 hex>`. Its trust boundary is exactly
`formalClaim=false`, capability `incomplete`, overall `inconclusive`, and
identity/time attestation `none`.

The index is transported only in a canonical exact-one-Ed25519-signature DSSE
envelope with payload type
`application/vnd.repopass.release-index.v1+json`. The envelope payload must be
the exact canonical index bytes; `keyid` is SHA-256 over canonical signer SPKI
DER. The index, envelope, signer SPKI, key policy, authority root, state, and
evidence are sidecars outside the artifact root and cannot inventory
themselves.

`release-key-policy-v1` is a separately canonical, at-most-64-KiB payload with
exactly `schemaVersion=1`, `product=repopass`, `channel=alpha`,
`purpose=release-index-signing`, a positive safe-integer `generation`,
`keyAlgorithm=ed25519`, `keyIdAlgorithm=spki-sha256`, and 1--32 strict
ordinal-sorted unique `{keyId,status}` entries. Status is only `trusted` or
`revoked`. Its sole transport is an exact-one-Ed25519-signature DSSE envelope
with payload type `application/vnd.repopass.release-key-policy.v1+json`,
authenticated relative to the caller-supplied canonical authority SPKI.

### Alpha.29 release-policy authority transition

`release-authority-transition-v1` is a separate canonical JSON payload, at
most 16 KiB, with exactly `schemaVersion="1"`, `product="repopass"`,
`channel="alpha"`, `purpose="release-policy-authority-rotation"`, canonical
safe-integer `generation` in `1..9007199254740991`, `keyAlgorithm="ed25519"`,
`keyIdAlgorithm="spki-sha256"`, `previousAuthorityKeyId`, and
`nextAuthorityKeyId`. The two key IDs are distinct SHA-256 identities of
canonical Ed25519 PKIX SPKI DER. It is transported only in a canonical exact-
one-Ed25519-signature DSSE envelope at most 32 KiB, payload type exactly
`application/vnd.repopass.release-authority-transition.v1+json`, whose signer
is the previous authority. The next key is not a trust anchor until that
transition verifies under the caller-supplied previous root.

### DSSE payload and PAE

`signature.dsse.json` has payload type exactly
`application/vnd.in-toto+json`, canonical standard padded base64 of the exact
`attestation.json` bytes, and exactly one Ed25519 signature. The signed message
is the exact DSSE pre-authentication encoding:

```text
"DSSEv1" SP decimal-byte-length(payloadType) SP payloadType SP
decimal-byte-length(payload) SP payload
```

`SP` is one ASCII space, decimal lengths have no sign or leading decoration,
and there is no quoting, BOM, terminator, or newline in PAE. The signature is
canonical standard padded base64 of exactly 64 Ed25519 signature bytes. Zero,
multiple, reordered, alternate-algorithm, noncanonical-base64, or key-ID-
mismatching signatures are invalid.

### Deterministic USTAR

The bundle is uncompressed USTAR with exactly the five regular entries below
when the schema-4 plan does not select `sbom`. When it does, the canonical SPDX
derivative is inserted after `payload/verification.json`, producing exactly six
entries:

```text
attestation.json
bundle-manifest.json
payload/verification.json
[payload/sbom.spdx.json]
signature.dsse.json
signer-public-key.pem
```

Each header uses the exact path above, mode `0600`, UID/GID `0`, size equal to
the following content bytes, modification time Unix epoch `0`, regular-file
type, USTAR format, and empty link/user/group names. Device major/minor are
zero; access/change times carry no USTAR value. Content padding and the two
end-of-archive zero blocks use the standard USTAR representation. Compression,
PAX/GNU extensions, sparse data, links, devices, directories, extra, missing,
duplicate, case-fold-colliding, reordered, or trailing entries/bytes are
invalid.

The raw name set selects the five- or six-member model before protected content
is trusted. The verifier MUST rebuild the complete archive from exactly those
accepted payloads using this profile and require byte-for-byte equality.
File-level semantic equivalence does not make a different tar representation
valid. The optional SPDX payload is the exact canonical derivative of the
bounded caller input; no raw-input digest or semantic array normalization is
claimed.

## Lockfile behavior

The persistent resolved plan is named `passport.lock.json`.

- Maintainer-managed repositories SHOULD commit it.
- Ad-hoc inspection MAY retain it only in cache.
- Release evidence MUST include it.
- Users MUST NOT hand-edit it.

`repopass plan` is preview-only by default. It prints the resolved plan and risk warnings but does not modify `passport.lock.json`.

`repopass plan --write-lock` writes the canonical lockfile atomically.

`repopass plan --check` resolves without writing, compares the computed `planDigest` with the committed lockfile, and returns `PLAN_DRIFT` when different. Formatting-only differences that canonicalize identically are not drift.

The reference implementation writes a same-directory temporary file, flushes and closes it, and uses the platform replacement primitive. Readers reject partial or invalid lockfiles. Crash-atomic behavior across every Windows filesystem/provider combination is not claimed; that remains a conformance and hardening target.
