# OpenClaw Integration Notes

VMGA should integrate with OpenClaw through an explicit plugin/gateway boundary.

OpenClaw's public security model is a personal-assistant trust model: one
trusted operator boundary per gateway, with separate gateways, OS users, or
hosts for materially different trust boundaries. VMGA must preserve that
assumption. If multiple untrusted users can trigger the same tool-enabled agent,
they share that agent's delegated mailbox authority unless the deployment splits
the runtime boundary.

The OpenClaw path must:

- Register VMGA as a plugin with explicit enablement.
- Map Gmail actions into structured VMGA proposals.
- Preserve `plugin_id`, `tool_id`, `actor_id`, and proposal metadata in evidence.
- Keep Gmail credentials and approval verifier secrets outside the agent process.
- Document that OpenClaw core internals are outside VMGA's enforcement claim.
- Treat OpenClaw `sessionKey` values and routing labels as context selectors, not
  as VMGA authorization boundaries.
- Require deployment evidence that direct Gmail and Google Workspace write paths
  are unavailable to the agent outside VMGA.
- Run `openclaw security audit --deep` before and after changing gateway bind,
  channel exposure, tool profiles, plugin enablement, or sandbox policy.
- Run `openclaw secrets audit --check` after credential migration and before
  claiming a hard VMGA enforcement boundary.

See `docs/deployment_runbook.md` for bypass-closure requirements.

## Recommended OpenClaw Posture

Start with the narrowest exposure pattern that supports the workflow:

- Keep the gateway loopback-only unless remote access is required.
- Use token/password or trusted-proxy authentication when the gateway is
  reachable off-host.
- Prefer pairing or strict sender allowlists for messaging channels.
- Use `session.dmScope: "per-channel-peer"` when more than one person can DM the
  bot.
- Disable host exec and elevated tools for any agent reachable from non-local
  senders.
- Keep browser, canvas, node, cron, gateway, and session-spawn tools away from
  open or semi-open mailbox workflows.
- Keep bind mounts narrow and exclude home directories, credential directories,
  Docker sockets, and system paths.

For company-shared workflows, use a dedicated runtime identity: a dedicated
machine, VM, container, or OS user; dedicated browser/profile/accounts; and no
personal Google account or password-manager state in that runtime.

## Secrets And Credential Surfaces

OpenClaw SecretRefs are useful for VMGA deployments, but they are not a
process-isolation boundary. Treat them as a plaintext-residue reduction control:
they help keep supported credentials out of `openclaw.json`,
`auth-profiles.json`, `.env`, and generated `agents/*/agent/models.json` files
after migration.

For VMGA hard-enforcement claims, credential migration is complete only when:

- Supported OpenClaw credentials use SecretRefs instead of plaintext values.
- Legacy plaintext residue has been scrubbed from `openclaw.json`,
  `auth-profiles.json`, `.env`, generated `models.json` files, and any backups
  or copied configs reachable by the agent.
- `openclaw secrets audit --check` reports clean.
- Unsupported, OAuth-durable, rotating, or session-bearing credentials are
  protected by OS isolation, container isolation, or an external credential
  proxy.
- Gmail and Workspace credentials used by VMGA are held by the VMGA broker or an
  external credential service, not by an OpenClaw agent process.

SecretRefs are resolved eagerly into an in-memory runtime snapshot. Startup and
reload fail fast when active refs cannot resolve, and reload keeps the
last-known-good snapshot on failure. VMGA release evidence should capture
`openclaw secrets audit --check` output and any `secrets.reload` status used
during deployment.

If using `openclaw secrets apply`, treat the plan as a controlled migration
artifact:

- Dry-run the plan before write mode.
- Keep the generated plan in release evidence, redacted if needed.
- Confirm all targets are in OpenClaw's supported SecretRef credential surface.
- Pass `--allow-exec` only when the plan intentionally uses exec SecretRefs or
  providers, and record why that provider path is trusted.
- Remember that invalid plan targets fail before configuration mutation, while
  scrubbed plaintext values are intentionally not backed up as rollback secrets.

For exec SecretRef providers, prefer absolute regular-file resolver paths, no
shell, minimal environment allowlists, output limits, timeouts, and trusted
directories only when needed for known package-manager symlinks. A compromised
resolver path is equivalent to a compromised secret source.

## VMGA Bypass Controls For OpenClaw

The deployment is hard-enforced only if OpenClaw cannot reach Gmail side effects
without VMGA. Deny or remove these from the agent runtime:

- Direct `gws`, `gog`, `gmail`, or custom Workspace CLI execution unless the
  binary is a VMGA-owned broker path with isolated credentials.
- Environment credentials such as `GOOGLE_WORKSPACE_CLI_TOKEN`,
  `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE`, and `GOOGLE_APPLICATION_CREDENTIALS`.
- Credential directories such as `~/.config/gws`, `~/.config/gog`,
  `~/.hermes/google_token.json`, browser profile OAuth state, and OpenClaw
  agent auth profiles unless explicitly scoped for VMGA.
- Plaintext OpenClaw credentials in `openclaw.json`, `auth-profiles.json`,
  `.env`, generated `models.json` files, legacy auth stores, copied configs, and
  backups readable by the agent.
- Network egress from the agent sandbox directly to Gmail/Workspace APIs when
  write-capable credentials are present.
- Plugin-owned tools that expose Gmail writes without emitting VMGA proposals.

If any of those paths remain reachable, document the deployment as advisory
governance only.

## Trusted Proxy Auth

Trusted-proxy auth can be appropriate for VMGA deployments behind an
identity-aware proxy, but the proxy becomes the authentication boundary. Use it
only when:

- The proxy authenticates users before forwarding traffic.
- The proxy is the only network path to the Gateway.
- `gateway.trustedProxies` contains only proxy source IPs.
- The proxy strips or overwrites client-supplied identity and forwarding
  headers.
- `gateway.auth.trustedProxy.allowUsers` lists the expected operators when the
  proxy serves more than one audience.

Do not use trusted-proxy auth for a plain TLS terminator, a load balancer that
does not authenticate users, or any setup where direct gateway access bypasses
the proxy. Avoid `gateway.auth.trustedProxy.allowLoopback` unless the same-host
proxy is the intended trust boundary and local processes are trusted.

Do not combine trusted-proxy mode with token auth. OpenClaw rejects ambiguous
mixed-token configurations because loopback requests can authenticate on the
wrong path.

## Exposure Validation

Before exposing an OpenClaw VMGA deployment:

1. Run `openclaw doctor`.
2. Run `openclaw security audit --deep`.
3. Run `openclaw secrets audit --check`.
4. If secrets changed, run `openclaw secrets reload` and record the result.
5. Prove an authorized sender can trigger a VMGA proposal.
6. Prove an unauthorized sender or browser session is denied.
7. Prove direct Gmail writes through non-VMGA tools fail.
8. Confirm approval-gated actions still require VMGA approval.
9. Confirm logs redact tokens and message secrets.
10. Record all accepted residual warnings.

VMGA release evidence should include the audit output, gateway configuration
hash, plugin manifest hash, policy hash, and representative VMGA evidence
entries for allow, review-required, deny, approval, execution, and lockdown.

## Formal-Model Alignment

OpenClaw's formal-verification documentation describes bounded TLA+/TLC models
for gateway exposure, node exec approvals, pairing caps, ingress gating, routing
isolation, and trace idempotency. VMGA should align with those modeled claims by
keeping approval tokens non-replayable, treating routing/session identifiers as
non-authoritative context, and recording stable trace identifiers across
proposal, approval, execution, and denial evidence.

Those models are useful regression references, but they are not proof that a
specific OpenClaw plus VMGA deployment is secure. VMGA's claim still depends on
the concrete deployment evidence above.

## Threat-Model Alignment

OpenClaw's MITRE ATLAS threat model frames the relevant boundaries as channel
access, session isolation, tool execution, external content, and supply chain.
For VMGA, map those boundaries this way:

- Channel access: who can trigger mailbox proposals.
- Session isolation: which actor/thread/message context is bound into the
  proposal and approval record.
- Tool execution: whether Gmail side effects can occur only through VMGA.
- External content: whether untrusted email content can influence action
  proposals without becoming authority.
- Supply chain: whether OpenClaw plugins, Hermes plugins, Workspace CLIs, and
  VMGA packages are pinned, reviewed, and explicitly enabled.

This keeps VMGA's claims bounded: VMGA governs Gmail actions at the mailbox
execution boundary; it does not make OpenClaw a hostile multi-tenant isolation
layer.

## References

- OpenClaw Gateway Security: https://docs.openclaw.ai/gateway/security
- OpenClaw Gateway Exposure Runbook:
  https://docs.openclaw.ai/gateway/security/exposure-runbook
- OpenClaw Secrets CLI: https://docs.openclaw.ai/cli/secrets
- OpenClaw Secrets Management: https://docs.openclaw.ai/gateway/secrets
- OpenClaw Secrets Apply Plan Contract:
  https://docs.openclaw.ai/gateway/secrets-plan-contract
- OpenClaw Trusted Proxy Auth:
  https://docs.openclaw.ai/gateway/trusted-proxy-auth
- OpenClaw SecretRef Credential Surface:
  https://docs.openclaw.ai/reference/secretref-credential-surface
- OpenClaw Formal Verification:
  https://docs.openclaw.ai/security/formal-verification
- OpenClaw MITRE ATLAS Threat Model:
  https://docs.openclaw.ai/security/THREAT-MODEL-ATLAS
