# Changelog

All notable changes to VMGA will be documented here.

## Unreleased

- Added the runtime enforcement posture self-check (`/v1/posture`,
  `vmga-operator posture`, and broker startup summaries) so operators can see
  when a deployment is advisory, cannot be determined, or hard-ready under
  explicit evidence.
- Tightened posture checks to avoid optimistic path-isolation results: agent
  roots must be supplied explicitly, and direct Gmail/Workspace bypass closure
  requires an evidence-referenced operator attestation.
- Added v0.3.0 design records for tamper-evident evidence and asymmetric
  out-of-domain approval signatures.
<<<<<<< HEAD
- Added opt-in Ed25519 approval-signature mode with broker-held public keys,
  detached signature evidence, single-use approval nonces, and an external
  `vmga-approval-sign` helper. HMAC approval remains available for advisory and
  development use and is broker-forgeable because the broker holds the secret.
=======
- Implemented opt-in Tier-1 evidence HMAC chaining with expected-head
  checkpoints, cross-file rotated-ledger verification, key rotation support,
  crash-after-append recovery, and separate CLI reporting for advisory event
  checks versus integrity state.
>>>>>>> b5dcda4 (Add Tier-1 tamper-evident evidence ledger with HMAC chain (#2))

## v0.2.1 - 2026-06-10

### Security

- Serialized proposal, approval, execution, and lockdown-reset mutations behind
  an adapter state lock to prevent concurrent approval-token replay in the
  single-process broker.
- Made the fake Gmail backend honor the broker search contract (`max_results`)
  and added a regression test that exercises the broker against the shipped
  backend.
- Refused unauthenticated broker startup unless `--allow-unauthenticated` is
  set on a loopback host; non-loopback binds now require `VMGA_BROKER_TOKEN`.
- Switched broker bearer-token comparison to a constant-time check.
- Redacted and length-capped agent-supplied justification and reason text before
  it is written to evidence.
- Persisted lockdown reset so a cleared lockdown survives broker restart.
- Expired stale SQLite rate-limit state on load.
- Linked GitHub private vulnerability reporting in `SECURITY.md`.

### Documentation

- Reframed the v0.2 spec as a historical reference; clarified the standalone
  ledger is append-only JSONL, not hash-chained, and that credential isolation
  is a deployment precondition.
- Documented the built-in broker as a single-process control plane and noted
  multi-process hard enforcement needs transactional cross-process approval
  consumption.
- Documented `reset_lockdown` as an in-process operator maintenance API, not a
  public broker route.

### Maintenance

- Added npm Dependabot coverage for the OpenClaw integration and documented the
  upstream `hono` advisory handling.
- Switched the repository to GitHub default CodeQL setup.

## v0.2.0 - 2026-06-10

- Added the production-alpha VMGA broker scaffold for governed Gmail and
  Workspace actions.
- Added proposal, approval, policy, state, evidence, ledger, executor, and
  broker modules with compatibility exports for the original adapter.
- Added JSON schemas for VMGA proposals, approvals, and evidence records.
- Added broker endpoints for proposals, approvals, and executions, including
  legacy compatibility routes.
- Added fake Gmail and gogcli-backed backend paths with shell-free subprocess
  execution.
- Added VMGA CLI entry points for broker operation, evidence verification,
  release checks, and approval-token workflows.
- Added dry-run and release evidence generation with verifier support.
- Added Hermes integration manifests, schemas, tool handlers, and skill docs.
- Added OpenClaw plugin packaging, profile adapter, examples, and validation
  scripts.
- Hardened broker operations with SQLite WAL mode, correlation IDs, in-memory
  redaction, bounded approval tokens, evidence lifecycle guidance, strict mock
  schemas, live-smoke cleanup tagging, and Gmail rate-limit backoff.
- Added open-source readiness scaffolding for packaging, CI, security reporting,
  contribution guidance, release checklists, evidence docs, and DSOVS
  self-assessment.
- Added the MIT License.

## Earlier

- Started standalone VMGA repository extraction.
- Imported the v0.2 reference adapter, policies, specification, and tests.
- Hardened VMGA policy validation, denial error codes, and approval binding
  checks for production-alpha work.
