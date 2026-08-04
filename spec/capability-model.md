# Capability Model

Capabilities are declared per scenario phase. A declaration states intended access; it does not prove enforcement or observation.

## Current reference profile

The local alpha enforces one of the exact `baseline-v1` Node/Python Linux
`amd64` runtime/image tuples, a read-only root filesystem, read-only source,
workspace, and fixture mounts, non-root workload commands, bounded CPU, memory,
PID, time, logs, and aggregate writable storage, plus external network deny.
The public schema recognizes `arm64`, but this built-in policy has no approved
`arm64` tuple.
Writable `/outputs`, workload home, and temporary storage share one
engine-managed tmpfs capped by the declared disk limit and a local 2 GiB
ceiling. Setup allowlists and synthetic-secret injection are recognized but
unavailable. Filesystem and port observation remain best effort on the exact
qualified Docker profile (with narrower components unavailable on Podman),
process observation is best effort, and network coverage is enforcement-only.
Alpha.23 compares only surviving `/outputs` retained deltas with the write
declaration union recorded for phases actually dispatched in that run. The
richer declarations below define the versioned model and must not be read as
claims that this runner observes or enforces every category.

## Three independent facts

Every report keeps these facts separate:

```text
declared
enforced
observed
```

For example:

```text
declared: runtime network denied
enforced: true
observed denied attempts: 2
capability verdict: nonconforming
```

Enforcement of deny does not make denied attempts conforming. No observed attempt means only that the exercised path produced no observed attempt.

## Default and merge rules

- Capabilities are phase-local. There is no implicit inheritance between phases.
- An omitted capability category is an empty declaration.
- An omitted network declaration resolves to `deny: true`.
- `run`, `exercise`, and `cleanup` always resolve to external-egress deny unless a later API version explicitly changes that rule.
- `setup` also defaults to deny. It may opt into an explicit destination allowlist.
- `deny: true` and `allow` are mutually exclusive.
- A resolver MUST fully materialize every default in `passport.lock.json`.
- When a versioned policy makes a declaration narrower, the narrower result wins. A manifest cannot widen a core deny.
- Any extension that would weaken a core deny, observer requirement, or sandbox invariant is ignored and produces a validation or policy error.

The lockfile therefore contains no inherited, omitted, or ambiguous capability.

## Filesystem

Filesystem operations are:

```text
read
write
create
delete
rename
chmod
symlink
```

Each value is a set of canonical sandbox-path patterns. The runner baseline exposes:

```text
/source       immutable, read-only
/workspace    fresh read-only workspace in the executable alpha
/inputs       read-only by default
/outputs      writable engine tmpfs and declared export
/outputs/.home disposable home in the same tmpfs cap
/outputs/.tmp  temporary storage in the same tmpfs cap
```

A structural mount being present does not implicitly declare every operation on it. For example, a command can read `/workspace` while a write outside declared patterns remains nonconforming.

The following mounts are forbidden regardless of a manifest:

- host root or host home;
- SSH, cloud, GitHub, Kubernetes, or package-manager host credentials;
- SSH agent;
- Docker or Podman socket;
- host PID or host network namespace;
- arbitrary device.

### Path matching

1. Paths are normalized POSIX sandbox paths before matching.
2. `.` segments are removed and `..` segments are rejected.
3. Symlinks are resolved within the sandbox before policy comparison. Escape is always forbidden.
4. Matching is case-sensitive for the v1alpha1 Linux environment.
5. `/x/*` matches one nonempty path segment below `/x`.
6. `/x/**` matches `/x` and every descendant.
7. All other characters are literal in v1alpha1; brace expansion and platform globs are not supported.
8. A more specific rule does not override a core forbidden mount.

The glob semantics are versioned with the manifest API and require golden conformance tests.

## Network

A deny declaration is:

```yaml
network:
  deny: true
```

An allowlist declaration is:

```yaml
network:
  allow:
    - host: registry.npmjs.org
      port: 443
      protocol: tcp
```

`protocol` defaults to `tcp` and is materialized in the resolved plan. Host matching occurs after IDNA and lowercase normalization. A DNS name permission does not implicitly permit arbitrary rebinding, private address space, metadata endpoints, or a direct IP. Runner enforcement details and limitations are part of the runner profile.

Runtime external egress deny is a required v1alpha1 safety feature. If the runner cannot enforce it, verification is blocked or capability is incomplete; it never silently becomes observe-only.

Loopback service traffic is declared under `ports.listen`, not network egress:

```yaml
ports:
  listen:
    - host: 127.0.0.1
      port: 3000
      protocol: tcp
```

Only `127.0.0.1` and `::1` listen declarations are supported in v1alpha1.

## Process

Process capability fields are:

| Field | Meaning |
|---|---|
| `exec[]` | Declared executable names or canonical paths. |
| `childProcesses` | Whether child creation is declared. |
| `shell` | Whether explicit shell execution is declared. |
| `backgroundProcesses` | Whether a process may outlive its initiating step until cleanup. |

Untrusted workload commands run as the fixed non-root workload user with
`no-new-privileges`; privileged mode is forbidden, resource limits apply to the
container, and the controller owns its process tree. The current long-lived
sandbox uses a fixed controller-selected runtime process as root with only
`DAC_OVERRIDE`, `FOWNER`, and `KILL` added so it can quiesce workload processes
and initialize or repair the bounded output filesystem. Fixed finalization also
invokes that image's `/bin/tar` as root to stream a quiescent USTAR archive into
the controller-side safe extractor. The runtime binary and tar helper come from
an exact tuple bound into the policy digest; repository commands and arguments
never control the helper operation. Digest pinning provides immutability, not
publisher trust or supply-chain attestation. These are profile invariants, not
author-grantable capabilities.

Any live process after cleanup is `PROCESS_LEAK` and makes cleanup non-clean.

## Environment and secrets

Environment capability declares variable names that may be read or written plus controlled locale/timezone. A command receives only explicitly resolved input and secret references; it does not inherit the host environment.

Secret capability lists scenario-scoped synthetic secret IDs. A profile that
implements secrets injects each only during its declared scope, and secret
values never appear in observations, commands, lockfiles, reports, cache keys,
or error details. The current local profile rejects any scenario requesting
secret injection before a plan can execute.

## Resources

Resource capability includes CPU, memory, disk, PIDs, time, and log bytes.
Implemented limits are required enforcement inputs. The current local profile
enforces CPU, memory, PID, time, bounded logs, and one aggregate engine-tmpfs
disk cap shared by `/outputs`, workload home, and temporary storage. The
controller rejects a local disk request above 2 GiB and revalidates archive
bytes, logical bytes, entries, types, and paths before atomically committing the
staged export.

A runner reports each limit as enforced or unavailable. Exceeding a limit produces `RESOURCE_LIMIT_EXCEEDED` or `TIMEOUT`; unavailable required enforcement produces `RUNNER_FEATURE_UNAVAILABLE`.

## Devices and host integration

`devices` and `hostIntegration` are fixed to `false` in v1alpha1. They cannot be enabled by an extension.

## Observer coverage

Coverage values are:

```text
full
high
best-effort
enforcement-only
unavailable
```

Coverage is category-specific:

- `full` satisfies every minimum.
- `high` satisfies `high` and `best-effort`.
- `best-effort` satisfies only `best-effort`.
- `enforcement-only` satisfies only a network-enforcement requirement and only when the minimum is `enforcement-only`.
- `unavailable` satisfies no required observation.

An implementation MUST NOT compare coverage values as a single numeric score across observer categories.

## Mismatch classification

| Mismatch | Meaning |
|---|---|
| `undeclared-observed` | Trusted observation found behavior absent from the declaration. |
| `forbidden-observed` | Trusted observation found an attempted or completed forbidden behavior. |
| `out-of-scope` | The event is valid but outside this scenario's conformance scope. |
| `declared-not-observed` | Declared access did not occur on the exercised path. |
| `observer-unavailable` | Required observer not present. |
| `observation-incomplete` | Observer started but did not provide required coverage. |

The verification JSON expresses concrete mismatches through stable error codes such as `UNDECLARED_FILESYSTEM_WRITE`, `FORBIDDEN_NETWORK_ATTEMPT`, and `UNDECLARED_PORT_LISTEN`.
