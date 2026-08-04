# RepoPassport Core Contract v1alpha1

Status: normative alpha specification.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described by RFC 2119 and RFC 8174.

## Contract artifacts

The v1alpha1 artifact chain is:

```text
repo-passport.yml
  -> passport.lock.json
  -> observations.ndjson
  -> assertions.json
  -> policy-decisions.json
  -> verification.json
  -> report.json / report.html
```

`repo-passport.yml` is an author-controlled declaration. Every later artifact is generated. A verifier MUST NOT treat a generated artifact written by the workload as authoritative.

The normative schemas are:

| Artifact | Schema |
|---|---|
| Manifest | `schemas/repo-passport.schema.json` |
| Resolved plan / lockfile | `schemas/resolved-plan.schema.json` |
| One normalized observation | `schemas/observation.schema.json` |
| One assertion result | `schemas/assertion.schema.json` |
| Verification result | `schemas/verification.schema.json` |
| Stable error | `schemas/error.schema.json` |

All schemas use JSON Schema Draft 2020-12. YAML manifests MUST first be decoded to the JSON data model without applying YAML-specific implicit typing beyond JSON scalars.

## Wire conventions

- JSON object member names use lower camel case.
- Enum values are lowercase ASCII and multiword values use hyphens, except stable error codes. Stable error codes are public API and retain the Appendix C `UPPER_SNAKE_CASE` spelling.
- `apiVersion`, `kind`, and schema version constants retain the exact case defined by their schemas.
- Identifiers are lowercase DNS-label-like strings matching `^[a-z][a-z0-9-]{0,62}$`.
- A Git commit is the complete lowercase 40-hex object ID. Abbreviated commits are invalid.
- A digest is `sha256:` followed by exactly 64 lowercase hexadecimal characters.
- Sandbox paths are absolute POSIX paths. Repository fixture paths are relative POSIX paths. Neither form may contain a `..` segment or a backslash.
- General durations in an authoring manifest use an integer followed by `ms`,
  `s`, `m`, or `h`. The `alpha.3` HTTP timeout and signal-grace fields are the
  narrow exception: a fractional unit is accepted only when the parsed value
  is a whole number of milliseconds, so `1.5s` is valid as 1,500 ms while
  `1.5ms` is invalid. The v1alpha1 lockfile stores the normalized Go-duration
  string used by the runner.
- Manifest sizes use an integer followed by `KiB`, `MiB`, `GiB`, or `TiB`. Resolved values use integer bytes.
- Timestamps use RFC 3339 UTC form. Timestamps never participate in `planDigest`.

## Core domain model

| Type | Required semantic content |
|---|---|
| `SourceRef` | Local path, Git URL, provider repository reference, archive reference, or OCI reference. The current v1alpha1 implementation executes local directories only; other kinds are recognized for later profiles. |
| `ResolvedSource` | Source kind, canonical URL when applicable, full commit for Git, retrieval metadata, expected digest. |
| `SourceSnapshot` | Immutable source identity, full commit when Git, normalized tree digest, file inventory, immutable materialized path, byte and file counts. |
| `ProjectDescriptor` | Project kind, language/runtime candidates, package manager, entrypoint candidates, audiences, confidence, and provenance. |
| `EnvironmentSpec` | Platform, architecture, resolved runtime, base-image digest, resource limits, required services, and required runner features. |
| `ScenarioSpec` | Name, purpose, audience, environment, inputs, phases, capabilities, assertions, repeat settings, timeouts, and cleanup rules. |
| `CapabilitySet` | Filesystem, network, port, process, environment, secret, resource, device, and host-integration permissions for one phase. |
| `ResolvedPlan` | Immutable source, manifest digest, scenario, environment, runtime and image, resources, inputs, commands, journey assertions, phase capabilities, required runner features, observers, repetition policy, policy digest, and plan digest. |
| `Run` | Run ID, plan digest, runner identity, start/end timestamps, lifecycle state, and exit reason. |
| `ObservationEvent` | Sequence, wall timestamp, phase, actor label, operation, resource label, result, observer label, coverage, confidence, and optional structured details. |
| `AssertionResult` | Assertion ID and type, required flag, expected value, actual value, status, and evidence references. |
| `PolicyDecision` | Policy ID and bundle digest, decision, severity, message, and evidence references. |
| `VerificationCell` | One source × scenario × environment × runner × policy tuple. |
| `EvidenceBundle` | Subjects, plan, observation summary, assertions, policy decisions, verdicts, signer metadata, and bundle digest. |
| `TrialSession` | Session ID, plan reference, consent, interactive inputs, isolation profile, exported output, and expiration. |

Lifecycle, functional verdict, capability verdict, reproducibility, cleanup, evidence state, and freshness are distinct fields. They MUST NOT be collapsed into one enum in storage.

## Trust and producer boundaries

- The repository, its manifest, filenames, logs, outputs, and network responses are untrusted input.
- Acquisition and static discovery MUST NOT execute repository code.
- The resolver, sandbox controller, observer, journey driver, verifier, policy evaluator, and report renderer run outside the workload trust boundary.
- `/source` is immutable and read-only. `/workspace` is a fresh per-run tree whose writability is profile-defined. `/inputs` is read-only by default. `/outputs` is the only declared workload export area. The current executable profile mounts `/workspace` read-only and planner-gates workspace writes.
- Authoritative observations, assertion results, policy decisions, `verification.json`, and evidence artifacts MUST be written to a controller-owned path that is never mounted writable into the workload.
- A file named `verification.json` or an equivalent verdict claim created inside `/workspace` or `/outputs` is ordinary untrusted workload output and MUST be ignored as a verdict.
- Missing observer coverage MUST produce an incomplete or inconclusive dimension; absence of an event is not proof that no behavior exists.
- Functional success never overrides a nonconforming capability verdict.

## v1alpha1 implementation profile

The executable part of the first implementation profile supports:

- Linux workloads in Docker or Podman;
- local directory sources, including local Git worktrees without remote fetch;
- Node and Python using only the exact `baseline-v1` runtime/image tuples bound into the policy bundle, with the planned runtime version probed as a bounded self-report in the operator-approved selected image;
- explicit Linux `amd64` workload platform binding; the public schema recognizes `arm64`, but the current built-in runtime policy has no approved `arm64` tuple;
- foreground argv commands and CLI journeys;
- one attached Node or Python HTTP service, canonical bounded
  `http://127.0.0.1:<explicit-port>` readiness and requests, ordered bounded
  HTTP assertions, and one final cleanup signal under the `alpha.3` profile;
- declared exit-code, stdout/stderr substring, stdout regular-expression,
  file-existence, singular JSONPath, offline response-schema, and ordered
  output-file-schema assertions;
- read-only source, workspace, and fixture mounts plus an aggregate engine-tmpfs disk cap, no greater than 2 GiB locally, for writable output, home, and temporary data;
- quiesced output export through a fixed allowlisted-image USTAR helper and a controller-side Go extractor that rejects links, special/extended entries, non-portable paths, collisions, and data beyond the entry, logical-byte, and archive-byte caps before atomic commit;
- network-deny enforcement, foreground-process exit evidence, and forced container cleanup, with all unavailable observer coverage reported explicitly;
- JSON, text, and static HTML reports.

The executable HTTP subset is the single-service contract in
[`scenario-model.md`](scenario-model.md): URLs are canonical and at most 2,048
UTF-8 bytes; a journey has at most 128 ordered steps and 32 requests; effective
request headers MUST simultaneously satisfy count ≤ 64 and aggregate bytes
≤ 65,536, with each value ≤ 8,192 bytes. The aggregate is the sum of
`len(name bytes) + len(value bytes) + 4` for every effective header; accepted
names and values are ASCII, so these are also their UTF-8 byte lengths. An
automatic JSON `content-type` is included in the count and sum.
Text request bodies and actual serialized JSON request bytes are each limited
to 1 MiB; response header `contains` is limited to 8,192 bytes and non-empty
`bodyContains` to 1 MiB;
`fileExists` uses a normalized UTF-8 `/outputs` path of at most 4,096 bytes;
HTTP timeouts and every signal grace period are whole milliseconds of at least
1 ms. Fractional seconds such as `1.5s` are valid when they resolve exactly to
whole milliseconds; `1.5ms` is invalid. An explicit per-request timeout and
the resolved exercise fallback used when it is omitted are each at most 30
minutes; the fallback is `phases.exercise.timeout`, or 1 minute when that field
is absent. Readiness is at most 2 minutes and status expectations are 200–599.
The readiness loop uses bounded exponential backoff with a hard 128-attempt
limit, and `service.start` succeeds only after readiness.

The public schema also describes broader HTTP and signal shapes, network
allowlists, synthetic secrets, and non-file inputs. The reference resolver or
runner rejects unsupported paths before workload execution. Filesystem
write/read, port-listen, denied-destination, and full child-process observation
are not claimed by the built-in backend. A runner that does not implement a
recognized feature MUST return `RUNNER_FEATURE_UNAVAILABLE` and a blocked or
inconclusive result. It MUST NOT silently skip the phase. The implemented HTTP
lifecycle therefore remains capability `incomplete` and overall
`inconclusive`, and M1 remains incomplete.

## Validation layers

Schema validation is necessary but not sufficient. A conforming semantic validator MUST additionally check:

1. Every `project.entrypoints[]` value names a scenario.
2. Every scenario `environment` names an environment.
3. Step IDs, request IDs, service IDs, and assertion IDs are unique in their scope.
4. Every HTTP assertion `requestId` names an earlier request in the same driver.
5. Every signal target names a service started by the scenario.
6. Every environment input/secret reference resolves in the same scenario.
7. `successThreshold <= repeats`.
8. Every phase capability key corresponds to a declared phase or to a documented resolver default.
9. A pinned image reference and exact runtime are present before a verified plan is emitted.
10. Literal secret fields and unsupported secret sources fail with `MANIFEST_LITERAL_SECRET` or `MANIFEST_INVALID`.
11. A shell command is explicit, its executable is absolute, and policy either approves it or fails with `MANIFEST_UNSAFE_SHELL`.
12. All normalized paths remain within their declared sandbox roots after symlink resolution.
13. The `alpha.3` HTTP limits, loopback origin, ordered references, one-service
    lifecycle, readiness semantics, and final signal shape satisfy
    [`scenario-model.md`](scenario-model.md).

## Source provenance

An `init` implementation MAY emit authoring provenance alongside the manifest. Each inferred field record contains:

```json
{
  "field": "spec.scenarios.quickstart.phases.run.service.command",
  "value": ["pnpm", "start"],
  "source": "package.json#/scripts/start",
  "method": "node-package-adapter",
  "confidence": 0.99,
  "status": "inferred"
}
```

Provenance status is `declared` or `inferred`. Inferred content MUST NOT be presented as maintainer-confirmed.
