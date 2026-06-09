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
openclaw sandbox explain --json
openclaw approvals get --gateway --json
openclaw health
```

Record the audit output, accepted residual warnings, gateway config hash, VMGA
policy hash, plugin manifest hash, secrets audit output, and proof that non-VMGA
Gmail write paths are denied. If `openclaw secrets apply` or
`openclaw secrets reload` is part of the deployment, keep the plan and reload
result in release evidence. See `docs/openclaw_integration.md` for the detailed
OpenClaw checklist.

If sandbox configuration, OpenShell policy, SSH sandbox auth, Docker image,
backend, mode, or setup commands change, recreate the affected sandbox runtimes
with `openclaw sandbox recreate` before treating the new policy as active.

Treat OpenClaw `/tools/invoke` as a gateway operator surface. A deployment must
prove that direct mailbox write tools cannot be invoked through it unless they
emit VMGA proposals and pass through VMGA execution.

OpenClaw exec approvals and node pairing are not substitutes for VMGA approval.
VMGA approval remains proposal-bound, non-replayable, and verified by VMGA before
any Gmail side effect.

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
