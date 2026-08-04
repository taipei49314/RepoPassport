# Fixture catalog

Fixtures are small repositories used by schema, discovery, planner, verifier,
report, and conformance tests. They contain only synthetic data and have no
third-party runtime dependencies.

## Classes

| Class | Purpose |
|---|---|
| `healthy` | A schema-valid, internally consistent fixture; only fixtures inside the executable alpha subset are expected to run |
| `invalid` | Manifest validation must fail before planning or execution |
| `nonconforming` | Function may work while observed behavior violates declared capabilities |
| `blocked` | A prerequisite prevents an effective run |
| `flaky` | Equivalent fresh runs intentionally disagree |
| `malicious` | Exercises a trust boundary without harming the host |

Current fixtures:

| Fixture | Expected behavior |
|---|---|
| `healthy/healthy-node-cli` | Dependency-free Node CLI; declared output and no external network |
| `healthy/healthy-node-http` | Dependency-free Node loopback HTTP service; three fresh repeats produce twenty-one trusted journey assertions, including controller-owned JSONPath, response-schema, and ordered output-schema checks, while observer coverage remains incomplete |
| `healthy/healthy-python-cli` | Dependency-free Python CLI; setup output persists into the exercise phase in one sandbox, with two fresh repeats |
| `healthy/healthy-python-http` | Dependency-free Python loopback HTTP service; three fresh repeats produce fifteen trusted journey assertions, including controller-owned JSONPath, response-schema, and ordered output-schema checks, while observer coverage remains incomplete |
| `healthy/minimal-public-spdx` | Self-contained Node CLI repository whose manifest seals the Alpha.15 SBOM evidence selection; `sbom.spdx.json` is its synthetic bounded attachment for the six-member attestation path |
| `invalid/unknown-field` | `MANIFEST_UNKNOWN_FIELD`, CLI validation exit `2` |
| `invalid/literal-secret` | `MANIFEST_LITERAL_SECRET`, CLI validation exit `2` |
| `malicious/fake-verification-json` | Workload forges a result file; trusted verifier ignores it |
| `malicious/http-service-early-exit` | HTTP service exits non-zero before readiness; verification records `SERVICE_START_FAILED` and removes the sandbox |
| `malicious/http-never-ready` | Live process never opens its declared port; bounded readiness ends with `READINESS_FAILED` and removes the sandbox |
| `malicious/http-term-resistant-child` | Functional HTTP service leaves a detached child that ignores TERM; trusted final quiescence removes it before output export |
| `malicious/cleanup-undeclared-residue` | Functional assertions pass, but cleanup finds residue outside its resolved allowlist and reports nonconformance |
| `malicious/undeclared-retained-write` | Functional assertions and allowed-residue cleanup pass while one surviving output falls outside the executed-phase `filesystem.write` union, producing one aggregate `UNDECLARED_FILESYSTEM_WRITE` |
| `malicious/alpha24-transient-create-delete` | Python CLI transiently creates then deletes an undeclared output; Alpha.24's supported notification comparison is expected to produce capability nonconformance without publishing the private marker |
| `malicious/alpha24-write-restore` | Setup writes an authorized baseline, then exercise mutates and restores it without an exercise-phase declaration; Alpha.24 is expected to report nonconformance even though retained bytes match |
| `malicious/alpha24-wrong-phase` | Build first declares and writes one output; exercise mutates that build-only path, so phase-local Alpha.24 comparison is expected to report nonconformance |
| `malicious/alpha24-notification-overflow` | Declared high-volume Python output churn is a fail-closed control: functional assertions pass, but an exhausted notification bound must be `not-tested`/capability `incomplete`, never a finding |
| `malicious/alpha24-new-directory-gap` | Declared Python output directory creation is a fail-closed control: the recursive-watch installation race makes notification comparison `not-tested` without publishing partial counts or a finding |
| `malicious/alpha25-undeclared-port-node` | Node single-HTTP service keeps one extra synthetic loopback TCP listener open while declaring only the HTTP listener; Alpha.25 is expected to produce aggregate `UNDECLARED_PORT_LISTEN` nonconformance without publishing the extra endpoint |
| `malicious/alpha25-undeclared-port-python` | Python single-HTTP service keeps one extra synthetic loopback TCP listener open while declaring only the HTTP listener; Alpha.25 is expected to produce aggregate `UNDECLARED_PORT_LISTEN` nonconformance without publishing the extra endpoint |

`fixture.json` is test metadata, not part of the repository manifest contract.
Tests should normalize run IDs, timestamps, temporary paths, and platform noise
before comparing golden output.

Never execute a program under `malicious/` directly on a development host.
Malicious fixtures are intentionally harmless, but their contract is to run
only through the same sandbox path used by integration tests.

The five Alpha.24 fixtures are Python CLI inputs for the narrow Docker/Linux
operation-notification comparison tuple. The healthy declared-notification
control remains `healthy/healthy-python-cli`; it is intentionally not copied.
Their `RAW-ALPHA24-*` filenames and
contents are privacy test markers only: public observations, findings,
reports, receipts, and formal evidence must not contain them. They use only
phase-local `filesystem.write`; they do not enable create, delete, rename, or
other gated manifest fields.

The two Alpha.25 fixtures are Docker/Linux single-service HTTP inputs for the
peer TCP listener comparison. Each keeps one synthetic extra listener open for
the full service lifecycle while declaring only the `8080` HTTP listener. The
extra endpoint is fixture-private: public observations, findings, reports,
receipts, and formal evidence must publish only the aggregate comparison and
must not contain the endpoint string or its port.

Healthy and malicious plan-ready fixtures use pullable official images pinned by
full `sha256:` digest. A live integration environment must never silently
replace an unavailable digest with a mutable tag. Validation-only invalid
fixtures may use syntactically valid placeholder digests because they must never
reach planning or execution.
