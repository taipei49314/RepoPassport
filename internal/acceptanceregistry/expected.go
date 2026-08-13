package acceptanceregistry

func expectedRegistry() Registry {
	return Registry{
		ArtifactType:  "repopass-acceptance-registry",
		Product:       "repopass",
		Rows:          expectedRegistryRows(),
		SchemaVersion: "1",
	}
}

func expectedRegistryRows() []RegistryRow {
	rows := []RegistryRow{
		expectedRow("RP-B00", "BASELINE", []string{"github", "repository"}, "The baseline revision equals the live default branch, or default-branch drift is recorded and the baseline is recomputed."),
		expectedRow("RP-B01", "BASELINE", []string{"linux-amd64", "repository", "windows-amd64"}, "Source gates pass on their first attempt; public output and receipts remain outside the repository and contain no secret."),
		expectedRow("RP-B02", "BASELINE", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Current-source container evidence and historical Alpha evidence are classified without presenting historical evidence as current."),
		expectedRow("RP-B03", "BASELINE", []string{"docker-linux-amd64", "podman-linux-amd64", "repository"}, "The source worktree is clean before and after the baseline, with no process, container, network, or volume residue."),
		expectedRow("RP-B04", "BASELINE", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Healthy results remain capability INCOMPLETE and overall INCONCLUSIVE until the required observations exist."),
		expectedRow("RP-M0-CORPUS", "M0", []string{"linux-amd64", "repository", "windows-amd64"}, "The complete fixture matrix and frozen fuzz or property seeds pass on Linux and Windows build paths, and malicious fixtures fail closed."),
		expectedRow("RP-M0-MODULE", "M0", []string{"linux-amd64", "release", "repository", "windows-amd64"}, "Clone, build, import, module metadata, and release assets use one exact canonical repository namespace."),
		expectedRow("RP-M0-QUAL", "M0", []string{"linux-amd64", "repository", "windows-amd64"}, "The current source archive, required tests, and receipts bind one exact source revision and tree without repackaging historical Alpha evidence."),
		expectedRow("RP-M0-SPEC", "M0", []string{"linux-amd64", "repository", "windows-amd64"}, "Every public schema, specification, and reference behavior has machine-readable conformance coverage and unknown semantics fail closed."),
		expectedRow("RP-M1-JOURNEY", "M1", []string{"docker-linux-amd64", "podman-linux-amd64"}, "CLI and HTTP healthy journeys pass functionally, remain reproducibly stable, and clean up on every supported Docker and Podman tuple."),
		expectedRow("RP-M2-COVERAGE", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Every required observer category reaches its normative high or complete coverage and gap or overflow fixtures remain incomplete."),
		expectedRow("RP-M2-MATRIX", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Docker and Podman each have current exact-source clean-VM evidence with no required skip or retry laundering."),
		expectedRow("RP-M2-RESIDUE", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "Success, timeout, cancellation, crash, termination-resistant, and early-exit paths restore the after-inventory to the baseline."),
		expectedRow("RP-M2-VERDICT", "M2", []string{"docker-linux-amd64", "podman-linux-amd64"}, "At least one healthy Node and Python profile honestly reaches capability CONFORMING and overall VERIFIED while adversarial gaps do not."),
		expectedRow("RP-M3-IDENTITY", "M3", []string{"external-review", "release"}, "Accepted evidence is authorized by external identity and policy; self-signed, unknown, revoked, or stale signers are not accepted."),
		expectedRow("RP-M3-INTEGRITY", "M3", []string{"external-review", "release"}, "Removal, rename, remint, signature, key, policy, source, and SBOM substitution all fail closed."),
		expectedRow("RP-M3-PORTABLE", "M3", []string{"linux-amd64", "release", "windows-amd64"}, "The release verifier kit validates the exact bundle on two clean operating systems without the producer worktree."),
		expectedRow("RP-M3-PRIVACY", "M3", []string{"release", "repository"}, "Every public file is typed and privacy-checked, and raw data renamed into an allowlisted slot is still rejected."),
		expectedRow("RP-M4-CHECK", "M4", []string{"github"}, "A real pull-request check binds the exact pull-request revision and maps healthy, failed, and inconclusive results according to the specification."),
		expectedRow("RP-M4-FORK", "M4", []string{"github"}, "A fork pull request receives no secret or write authority and artifact substitution cannot deceive the privileged publisher."),
		expectedRow("RP-M4-REPRO", "M4", []string{"github", "release"}, "A downloaded check artifact is independently verifiable and binds its workflow run and source revision."),
		expectedRow("RP-M5-JOURNEY", "M5", []string{"ui"}, "A new user can follow the README on a clean machine, complete the local trial, and verify the evidence."),
		expectedRow("RP-M5-SECURITY", "M5", []string{"ui"}, "Untrusted repository text or reports cannot execute script, inject HTML, open arbitrary network access, or disclose raw evidence."),
		expectedRow("RP-M5-TRUTH", "M5", []string{"ui"}, "Every UI status traces to the canonical model and visibly preserves INCOMPLETE or INCONCLUSIVE rather than presenting success."),
		expectedRow("RP-M6-AUTHORITY", "M6", []string{"hosted-runner"}, "A compromised worker or forged result cannot produce accepted evidence or a passing GitHub Check."),
		expectedRow("RP-M6-CLEANUP", "M6", []string{"hosted-runner"}, "Every termination path destroys the VM and credential, seals its store prefix, and restores the after-inventory to baseline."),
		expectedRow("RP-M6-ISOLATION", "M6", []string{"hosted-runner"}, "Two concurrent tenants have no filesystem, process, network, or artifact cross-contamination."),
		expectedRow("RP-M6-LIVE", "M6", []string{"hosted-runner"}, "An owner-controlled hosted environment has current-source evidence; without real infrastructure this row remains blocked."),
		expectedRow("RP-M7-CAPABILITY", "M7", []string{"plugin"}, "Unauthorized I/O is blocked before it occurs and a plugin cannot change policy, coverage, or the overall verdict."),
		expectedRow("RP-M7-CONFORMANCE", "M7", []string{"plugin"}, "Two reference plugins pass the same conformance kit and unsupported protocol versions return a stable error."),
		expectedRow("RP-M7-SUPPLYCHAIN", "M7", []string{"plugin", "release"}, "Plugin signature, trust, SBOM, and currentness are verifiable and an unknown signer remains unknown or blocked."),
		expectedRow("RP-Q-PROTOCOL", "QUALIFICATION", []string{"external-review", "release"}, "An independent reviewer approves and hash-freezes the acceptance policy before observing results."),
		expectedRow("RP-Q-REPLAY", "QUALIFICATION", []string{"external-review", "release"}, "The reviewer reruns the required matrix in a clean room with no unexplained required skip, blocked result, or internal error."),
		expectedRow("RP-Q-SUBJECT", "QUALIFICATION", []string{"external-review", "release"}, "The audited subject is the merged default-branch commit and tree plus final candidate artifact digests, and any later byte change invalidates the pass."),
		expectedRow("RP-Q-VERDICT", "QUALIFICATION", []string{"external-review", "release"}, "The reviewer returns PASS for the exact candidate with no open P0 or P1, and implementer or self-CI evidence cannot substitute for that verdict."),
		expectedRow("RP-REGISTRY", "M0", []string{"repository"}, "The complete M0--M7 registry and public specification or RFC exact set are closed and every required row has current evidence."),
		expectedRow("RP-R-STABLE-SCHEMA", "RELEASE", []string{"linux-amd64", "release", "windows-amd64"}, "Historical v1 verification, v2 round-trip and negative tests, and builder, CLI, and kit version agreement all pass."),
	}
	for index := range rows {
		switch rows[index].ID {
		case "RP-B00":
			rows[index].Evaluation = EvaluationPolicy{Kind: "required-checks", RequiredChecks: []string{"ci/container-matrix", "ci/go", "ci/schema-json", "ci/windows-go"}}
		case "RP-B04", "RP-M1-JOURNEY":
			rows[index].Evaluation = EvaluationPolicy{Kind: "required-checks", RequiredChecks: []string{"ci/container-matrix"}}
		case "RP-M0-MODULE":
			rows[index].Evaluation = EvaluationPolicy{Kind: "required-checks", RequiredChecks: []string{"ci/go", "ci/windows-go"}}
		case "RP-M0-QUAL":
			rows[index].Evaluation = EvaluationPolicy{Kind: "blocked", ReasonCode: "SOURCE_QUALIFICATION_PREREQUISITES_UNAVAILABLE"}
		default:
			rows[index].Evaluation = EvaluationPolicy{Kind: "not-run", ReasonCode: "ROADMAP_WORK_NOT_SCHEDULED"}
		}
	}
	return rows
}

func expectedRow(id, milestone string, appliesTo []string, criterion string) RegistryRow {
	return RegistryRow{
		AppliesTo: appliesTo,
		Criterion: criterion,
		ID:        id,
		Milestone: milestone,
		Required:  true,
	}
}
