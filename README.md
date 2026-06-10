# VMGA

Vesta Mail Governance Adapter (VMGA) is a control-plane governance boundary for
AI agents with Gmail access.

VMGA is not an agent, model wrapper, prompt filter, or UI product. It mediates
mailbox actions by requiring agents to submit structured Gmail proposals, then
enforcing policy, approval, execution binding, and evidence logging before any
mailbox side effect occurs.

## Current Status

This repository is being extracted from the Vesta Agent Runtime Governance
reference implementation. The current code is a reference implementation, not a
complete production service.

Production enforcement requires deployment controls outside this package:

- Gmail credentials are not readable by the agent runtime.
- VMGA policy and approval verifier secrets are not writable by the agent.
- Gmail write-capable APIs are reachable only through the VMGA execution gate.
- Approval occurs out-of-band from the agent session.
- Evidence logs are retained somewhere the agent cannot rewrite.

Without those controls, VMGA should be described as advisory governance or a
reference control pattern, not hard isolation.

## What VMGA Governs

- Read, summarize, classify, and extract actions.
- Draft creation, sending, forwarding, archive/delete/label operations.
- Attachment download and release.
- Proposal hashing, approval binding, execution integrity, and lockdown.

## Repository Layout

```text
src/vmga/          Python package
policies/          Example VMGA policy profiles
docs/              Specification, deployment, and readiness notes
tests/             Unit tests
```

## Quickstart

```bash
python3 -m pip install -e ".[dev]"
pytest -q
```

## Broker Mode

Run the local broker with the fake backend for offline development:

```bash
export VMGA_APPROVAL_SECRET="replace-with-a-local-dev-secret"
vmga-broker --backend fake --policy policies/draft_assist.yaml
```

For a gogcli-backed broker, point VMGA at the agent-safe wrapper and keep gog
OAuth config outside the agent-readable workspace:

```bash
export VMGA_APPROVAL_SECRET="replace-with-a-broker-secret"
vmga-broker \
  --backend gogcli \
  --gog-binary /opt/homebrew/bin/gog-agent-safe \
  --gog-home /path/outside/agent/workspace
```

The gogcli backend starts with a narrow Gmail surface: search, read, and create
draft. It always enables `--gmail-no-send`, `--no-input`, and an exact command
allowlist. Gmail send remains denied by VMGA policy and by the backend.

## Design Influences

- The original VMGA reference implementation in Vesta Agent Runtime Governance.
- The VMGA v0.2 specification carried into `docs/vmga_spec_v0.2.md`.
- `orlyjamie/hardmail`, as prior art for a shell-free Hermes mail surface. VMGA
  borrows that ergonomics direction, not hardmail's self-gated approval model.
- OWASP DSOVS, as a release-readiness and evidence self-assessment lens. This
  does not imply OWASP certification or endorsement.
- OpenClaw's public gateway security, exposure, formal-model, and MITRE ATLAS
  threat-model docs, as deployment-boundary references for OpenClaw integrations.
- OpenClaw SecretRef, secrets audit, and trusted-proxy auth docs, as credential
  migration and gateway-auth references. SecretRefs are treated as plaintext
  residue reduction, not process isolation.
- OpenClaw approvals, sandbox, gateway protocol, `/tools/invoke`, and pairing
  docs, as runtime-boundary references. These controls complement VMGA but do
  not replace VMGA proposal-bound approval.
- OpenClaw sandboxing, OpenShell, tool policy/elevated, operator-scope, and
  secure-file-operation docs, as isolation and file-safety references. These are
  deployment controls, not proof that VMGA is enforced by themselves.
- Hermes security, Docker, Tool Gateway, credential-pool, gateway-internals,
  session-storage, CLI-extension, and tools-runtime docs, as Hermes deployment
  boundary references.
- Hermes plugin-build docs, as the reference shape for VMGA's future Hermes
  plugin package and tool handler contract.

## Non-Goals

VMGA does not claim prompt-injection prevention, DLP, host compromise
protection, browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals.

## License

VMGA is released under the MIT License. See `LICENSE`.
