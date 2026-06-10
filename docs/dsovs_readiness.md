# DSOVS Readiness Mapping

VMGA uses the OWASP DevSecOps Verification Standard (DSOVS) as a
self-assessment lens for release and deployment readiness. DSOVS is useful for
gap analysis, maturity-roadmap planning, and evidence collection; this file is
not OWASP certification, endorsement, formal compliance evidence, or a complete
DSOVS assessment.

The control identifiers below follow the current DSOVS phase naming used by the
OWASP project, for example `DES-002` and `CODE-004`. Re-check the upstream
standard before using this mapping in an audit packet because DSOVS evolves as
processes and technologies change.

## Selected Control Areas

- `DES-002` Threat Modelling: VMGA documents trust domains, deployment
  preconditions, and bypass paths in the README, deployment runbook, and
  Hermes/OpenClaw integration notes.
- `CODE-002` Hardcoded Secrets Detection: Release review checks committed docs,
  examples, and integration files for obvious OAuth credentials, tokens,
  approval secrets, private keys, and public Gmail account leakage.
- `CODE-004` Static Application Security Testing: CodeQL is expected to run
  through GitHub default setup for the canonical repository; releases should
  record the relevant run status rather than relying on local assumptions.
- `CODE-005` Software Composition Analysis: Dependabot alerts and dependency
  update PRs are part of release review. Optional OpenClaw runtime findings are
  tracked as upstream integration advisories when VMGA cannot patch them safely.
- `CODE-006` Software License Compliance: Dependencies and borrowed prior art
  should have compatible licenses and attribution before a tagged release.
- `CODE-009` Secure Dependency Management: Dependency updates should be tracked
  through reviewable PRs and CI, not applied through unreviewed local lockfile
  churn.
- `REL-003` Secret Management: Gmail tokens, Google OAuth client material,
  approval verifier secrets, and broker bearer tokens must live outside the
  agent authority domain for hard-enforcement claims.
- `REL-004` Secure Configuration: Example policies should use strict defaults,
  placeholder values, explicit denial for unknown or ambiguous behavior, and
  runtime posture output that fails toward advisory or cannot-determine when
  required roots, anchors, or bypass evidence are missing.
- `REL-005` Security Policy Enforcement: VMGA should fail closed when policy,
  approval, state, backend, evidence, or posture-readiness requirements are
  missing. Posture results are deployment evidence, not a replacement for
  concrete bypass, credential-isolation, approval, and ledger checks.
- `REL-008` Secure Release Management: Tagged releases should have a release
  checklist, changelog, tests, security-scan status, and explicit claim
  boundaries.
- `OPR-004` Application Security Logging: VMGA evidence must be structured,
  traceable by correlation ID, and free of raw approval tokens, OAuth material,
  and mailbox payloads.
- `OPR-005` Vulnerability Disclosure: The public repository should keep a
  monitored reporting path and private vulnerability reporting enabled.
- `TEST-005` Security Test Coverage: Tests should cover proposal validation,
  approval binding, execution gating, policy decisions, evidence events,
  lockdown behavior, and CI-safe integration contracts.

## Evidence To Collect

For each tagged release or deployment that claims hard VMGA enforcement, collect
or link:

- VMGA unit, contract, and integration test output.
- Release-check output from `scripts/vmga_release_check.py`.
- CodeQL, secret-scanning, Dependabot, dependency-review, and license-review
  status where configured.
- Documentation review showing security claims are bounded by deployment
  preconditions.
- Sample redacted VMGA evidence ledger entries for allow, review-required, deny,
  approval, execution, lockdown, and reset paths.
- Runtime posture output for the deployment under review, with explicit
  agent-readable roots and any direct-bypass attestation evidence reference.
- Deployment-specific bypass evidence for Hermes, OpenClaw, gogcli, and any
  other mailbox-capable runtime surface being claimed.
