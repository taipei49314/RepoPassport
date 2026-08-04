# Error and exit-code reference

Error codes are a public API. Messages and remediation text may improve, but an
existing code does not change meaning without a versioned compatibility plan.
CLI JSON, reports, HTTP errors, and future GitHub Checks use the same codes.

## Error shape

```json
{
  "code": "UNDECLARED_NETWORK_DESTINATION",
  "phase": "run",
  "severity": "high",
  "message": "An undeclared network destination was observed.",
  "evidenceRefs": ["network:3"],
  "suggestion": "Declare the destination or remove the runtime connection."
}
```

An HTTP response wraps the same detail and adds a request identifier:

```json
{
  "error": {
    "code": "RUNNER_FEATURE_UNAVAILABLE",
    "message": "Required port observer is unavailable.",
    "details": {},
    "requestId": "req_..."
  }
}
```

## CLI exit codes

| Exit | Meaning |
|---:|---|
| `0` | Operation succeeded; read verification outcome from structured output |
| `1` | Command or internal error |
| `2` | Validation error |
| `3` | Verification blocked |
| `4` | Functional failure |
| `5` | Capability nonconformance |
| `6` | Inconclusive result |
| `7` | Evidence verification failed |

By default, a successfully completed `verify` command may exit `0` even when its
recorded verdict is not a pass. CI selects outcome-to-exit behavior with
`--fail-on`. That flag never rewrites the result.

## Source

| Code | Meaning |
|---|---|
| `SOURCE_NOT_FOUND` | Source does not exist or cannot be addressed |
| `SOURCE_TOO_LARGE` | Source byte limit was exceeded |
| `SOURCE_TOO_MANY_FILES` | Source file-count limit was exceeded |
| `SOURCE_PATH_TRAVERSAL` | A path escaped its permitted root |
| `SOURCE_SYMLINK_ESCAPE` | A symbolic link escaped its permitted root |
| `SOURCE_REF_UNRESOLVED` | A mutable or ambiguous source reference could not be resolved |
| `SOURCE_DIGEST_MISMATCH` | Resolved source content did not match its expected digest |

## Manifest

| Code | Meaning |
|---|---|
| `MANIFEST_NOT_FOUND` | No manifest was found at the requested location |
| `MANIFEST_INVALID` | Manifest syntax or a typed field is invalid |
| `MANIFEST_UNKNOWN_FIELD` | A non-extension field is unknown |
| `MANIFEST_LITERAL_SECRET` | Secret material was embedded directly in a manifest |
| `MANIFEST_UNSAFE_SHELL` | Shell execution violated supported safety policy |

## Plan

| Code | Meaning |
|---|---|
| `PLAN_UNRESOLVED` | Required plan inputs could not be made immutable |
| `PLAN_DRIFT` | Resolved plan differs from the committed lockfile |
| `MUTABLE_BASE_IMAGE` | Formal verification still references a mutable image |
| `RUNTIME_VERSION_UNRESOLVED` | Runtime constraint could not be resolved |
| `POLICY_BUNDLE_UNRESOLVED` | Policy reference could not be resolved and digested |

## Runner and sandbox

| Code | Meaning |
|---|---|
| `RUNNER_UNAVAILABLE` | Requested runner backend is unavailable |
| `RUNNER_FEATURE_UNAVAILABLE` | A required runner or observer feature is missing |
| `SANDBOX_PREPARE_FAILED` | Sandbox preparation failed |
| `SANDBOX_START_FAILED` | Prepared sandbox could not start |
| `SANDBOX_DESTROY_FAILED` | Sandbox destruction could not be confirmed |
| `RESOURCE_LIMIT_EXCEEDED` | A declared resource limit was exceeded |
| `TIMEOUT` | A phase or run exceeded its wall-time limit |

## Execution and journey

| Code | Meaning |
|---|---|
| `SETUP_FAILED` | Setup phase command failed |
| `BUILD_FAILED` | Build phase command failed |
| `SERVICE_START_FAILED` | Declared service failed to start |
| `READINESS_FAILED` | Service did not satisfy readiness criteria |
| `JOURNEY_ASSERTION_FAILED` | A required external journey assertion failed |
| `CLEANUP_FAILED` | Cleanup action failed |
| `PROCESS_LEAK` | A process survived the allowed cleanup boundary |

## Capability and cleanup

| Code | Meaning |
|---|---|
| `UNDECLARED_FILESYSTEM_WRITE` | Workload wrote outside declared write patterns |
| `FORBIDDEN_FILESYSTEM_ACCESS` | Workload attempted explicitly forbidden filesystem access |
| `UNDECLARED_NETWORK_DESTINATION` | Observed destination was not declared |
| `FORBIDDEN_NETWORK_ATTEMPT` | Workload attempted explicitly forbidden network access |
| `UNDECLARED_PORT_LISTEN` | Workload listened on an undeclared address or port |
| `UNDECLARED_PROCESS_EXEC` | Workload executed an undeclared process |
| `CLEANUP_RESIDUE` | Unallowed state remained after cleanup |

`UNDECLARED_RESIDUE` is a cleanup verdict value. `CLEANUP_RESIDUE` is the stable
error code that explains it.

## Observation and reproducibility

| Code | Meaning |
|---|---|
| `OBSERVER_START_FAILED` | Required observer could not start |
| `OBSERVER_INCOMPLETE` | Observation ended with insufficient coverage or missing events |
| `OBSERVATION_SCHEMA_INVALID` | An observation event failed its wire schema |
| `NONDETERMINISTIC_RESULT` | Repeated equivalent runs produced incompatible results |

## Evidence and attestation

| Code | Meaning |
|---|---|
| `EVIDENCE_BUILD_FAILED` | Evidence bundle construction failed, including a sealed SPDX selection mismatch or bounded attachment read/profile failure |
| `EVIDENCE_DIGEST_MISMATCH` | Protected evidence content or an explicitly pinned complete bundle does not match its digest |
| `EVIDENCE_PRIVACY_BLOCKED` | The bounded minimal-public policy rejected publication; serialized details contain no matched content or location |
| `ATTESTATION_INVALID` | Canonical bundle, protected content, embedded verification integrity, key binding, or signature is invalid |
| `ATTESTATION_UNTRUSTED` | Signature is valid but explicit signer trust is absent, rejected, or cannot be read safely |
| `EVIDENCE_STALE` | A trusted, pinned Alpha.16 local re-observation found stable source, policy, plan, or bounded runner-profile drift; incomplete observation is `unknown` under an operational code, never stale |
| `SIGNING_FAILED` | Local signing key syntax, type, permission/DACL, link/path safety, or signing operation failed |

For `attest --spdx`, missing/empty/duplicate/single-dash/malformed occurrences
or a positional argument are pre-access `MANIFEST_INVALID` (exit 2). A valid
flag whose presence disagrees with the stored schema-4 selection, or whose file
cannot pass the bounded reader/profile, is `EVIDENCE_BUILD_FAILED` (exit 1).
Errors never echo the source path, rejected value, or attachment bytes.

For Alpha.19 offline policy mode, a missing, empty, duplicate, malformed, or
mixed `--trust-policy` / `--expect-trust-policy-digest` / `--trust-key` shape
is pre-I/O `MANIFEST_INVALID` (exit 2). A policy raw-byte digest mismatch is
`EVIDENCE_DIGEST_MISMATCH` (exit 7). An unreadable, unsafe, oversized,
noncanonical, or schema-invalid policy, and `revoked` or `not-listed` signer,
are `ATTESTATION_UNTRUSTED` (exit 7). Fixed errors do not echo policy paths,
bytes, key IDs, or rejected values.

## Policy

| Code | Meaning |
|---|---|
| `POLICY_DENIED` | A policy rule explicitly denied the result or plan |
| `POLICY_EVALUATION_FAILED` | Policy could not be evaluated reliably |

## Generic

| Code | Meaning |
|---|---|
| `INTERNAL_ERROR` | Unexpected trusted-component failure |
| `CANCELLED` | Operation was cancelled |

Every code should have a deterministic exit mapping, documentation, and a
fixture or unit test covering its public serialization.
