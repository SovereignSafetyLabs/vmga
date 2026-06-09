# VMGA Deployment Runbook

This runbook describes the minimum deployment posture needed before VMGA can be
described as a hard Gmail governance boundary.

## Required Preconditions

1. The agent process cannot read Gmail OAuth tokens, approval verifier secrets,
   VMGA policy files, or executor credentials.
2. The agent cannot call Gmail write-capable APIs outside VMGA.
3. Approval happens through a channel the agent cannot spoof or operate.
4. VMGA state and evidence paths are not writable by the agent.
5. Kinetic actions fail closed when policy, state, approval, or evidence writes
   are unavailable.

## OpenClaw Deployments

For OpenClaw, VMGA assumes one trusted operator boundary per gateway. Use
separate gateways, OS users, hosts, VMs, or containers for materially different
trust boundaries. Shared routing labels and `sessionKey` values are context
selectors, not VMGA authorization boundaries.

Before exposing an OpenClaw-backed VMGA deployment, run:

```bash
openclaw doctor
openclaw security audit --deep
openclaw secrets audit --check
openclaw health
```

Record the audit output, accepted residual warnings, gateway config hash, VMGA
policy hash, plugin manifest hash, secrets audit output, and proof that non-VMGA
Gmail write paths are denied. If `openclaw secrets apply` or
`openclaw secrets reload` is part of the deployment, keep the plan and reload
result in release evidence. See `docs/openclaw_integration.md` for the detailed
OpenClaw checklist.

SecretRefs are useful but do not isolate secrets from an agent that can read
files or execute commands in the same authority context. If plaintext
credentials, OAuth refresh material, copied configs, backups, generated model
catalogs, or unsupported credential classes remain readable by the agent,
describe the deployment as advisory.

## Advisory Mode

If VMGA runs in the same authority context as the agent, or if the agent can read
tokens and policy files, describe the deployment as advisory governance only.

## Evidence To Collect

- Service identity and filesystem permission output.
- Network egress rules showing direct Gmail write paths are unavailable to the
  agent.
- Policy file hash and deployment config hash.
- Sample ledger entries for allow, deny, review-required, approval, execution,
  lockdown, and reset.
