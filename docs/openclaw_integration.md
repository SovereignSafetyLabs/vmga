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
- Treat OpenClaw exec approvals, node pairing, Gateway auth, and `/tools/invoke`
  as separate OpenClaw controls. None of them replaces VMGA's proposal hash,
  approval binding, Gmail executor isolation, or evidence requirements.

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

## Upstream Dependency Advisory

VMGA treats OpenClaw as an optional external runtime, not as part of the VMGA
broker. The npm package for OpenClaw `2026.6.5` currently ships a shrinkwrapped
dependency tree that pins `hono@4.12.18`, while GitHub Dependabot recommends
`hono >= 4.12.21` for multiple medium-severity advisories. Because the vulnerable
copy is pinned inside OpenClaw's published shrinkwrap, VMGA's package-level
`overrides` cannot reliably replace it.

Until OpenClaw publishes a patched runtime, keep OpenClaw VMGA deployments local
or private-network only and treat any remote exposure as blocked unless the
operator can prove an equivalent patched OpenClaw runtime, authenticated ingress,
operator allowlists, sandboxing, and denied direct-bypass paths.

## Local Gateway Readiness

`plugin.vmga` being loaded proves only that OpenClaw can see the plugin. It does
not prove the Gateway is ready for a mailbox-capable workflow.

Minimum local readiness checks:

```bash
openclaw config set gateway.mode local
openclaw doctor
openclaw plugins inspect plugin.vmga
openclaw security audit --deep
openclaw secrets audit --check
openclaw sandbox explain --json
openclaw approvals get --gateway --json
```

The evidence should show:

- Gateway mode is configured and the gateway can start.
- Token auth or an equivalent local operator control is active.
- A command owner is configured for privileged commands and approvals.
- Session storage exists and is writable by the OpenClaw runtime only.
- `plugin.vmga` is loaded from the intended source and points at the VMGA broker.
- Sandbox and elevated exec posture cannot reach Gmail side effects outside
  VMGA.
- Direct Gmail, gog, gws, Workspace, shell, browser, MCP, or native mail write
  paths are denied or unavailable to the mailbox-capable agent.

Keep public or remote gateway exposure deferred until the same evidence is clean
behind authenticated ingress or a private network boundary.

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

## Gateway Protocol And Tool Invocation

OpenClaw's Gateway WebSocket protocol is the control plane and node transport.
Clients connect with a role and scopes during the first `connect` frame, and the
Gateway reports negotiated role/scopes in the `hello-ok` response. VMGA should
record the relevant OpenClaw actor, role, session key, tool name, and request
correlation identifiers in VMGA evidence, but it must not treat those fields as
approval authority by themselves.

The HTTP `POST /tools/invoke` endpoint is always enabled and uses Gateway auth
plus tool policy. For VMGA deployments, treat this endpoint as a full
operator-access surface for the gateway:

- Shared gateway token/password bearer auth is an owner/operator credential, not
  a narrow per-user Gmail permission.
- Shared-secret auth can restore broad default operator scopes even if a caller
  supplies a narrower scope header.
- Direct tool invokes should remain on loopback, tailnet, or private ingress.
- Public internet exposure requires an identity-aware proxy and the trusted-proxy
  checks described above.
- If Gmail, Workspace, shell, filesystem, browser, or plugin-owned write tools
  are reachable through `/tools/invoke`, they are VMGA bypass candidates unless
  they emit VMGA proposals and pass through VMGA execution.

OpenClaw returns 404 when policy denies a tool through this endpoint. VMGA
deployment evidence should include at least one denied direct invocation for a
non-VMGA Gmail write path.

## Exec Approvals, Sandbox, And Pairing

OpenClaw exec approvals are operator guardrails for shell execution; they are
not VMGA approval. A VMGA approval must still be out-of-band, proposal-bound,
non-replayable, and verified by VMGA before a Gmail side effect occurs.

For OpenClaw exec policy:

- Keep host exec denied for exposed VMGA agents.
- Do not use YOLO-style `security: "full"` plus `ask: "off"` for mailbox-capable
  agents.
- Treat the host approvals file as the enforceable source of truth for exec
  approvals, and keep requested `tools.exec.*` policy aligned with it.
- If any exec surface is reachable through `/tools/invoke`, assume shell-level
  mutation is possible even if file-write tools are denied.

For sandbox policy:

- Prefer sandbox mode for non-main or all mailbox-capable agents.
- Use `openclaw sandbox explain --json` to capture effective sandbox mode,
  backend, scope, workspace access, sandbox tool policy, and elevated gates.
- Treat sandbox mode, tool policy, and elevated mode as separate controls:
  sandboxing decides where tools run; tool policy decides which tools are
  callable; elevated is an exec-only path that runs outside the sandbox.
- Deny elevated exec for mailbox-capable agents unless the deployment has a
  documented break-glass reason and proves the elevated path cannot reach Gmail
  side effects outside VMGA.
- Deny `group:runtime` as well as mutating filesystem tools for read-only
  mailbox agents. If `exec` is allowed, denying `write`, `edit`, and
  `apply_patch` does not make shell execution read-only.
- After changing Docker, SSH, OpenShell source, OpenShell policy, sandbox mode,
  or setup commands, run `openclaw sandbox recreate` for the affected scope
  before claiming the new policy is active.
- Record `openclaw sandbox list --json` or equivalent runtime evidence after
  recreation.
- Review Docker bind mounts and workspace access independently. Bind mounts
  pierce the sandbox filesystem, default to read-write when mode is omitted, and
  must not expose credential roots, Docker sockets, home config directories, or
  VMGA state/evidence paths to the agent.

For OpenShell:

- Choose `mirror` when the local workspace should remain canonical and sync
  before/after exec is acceptable.
- Choose `remote` when the remote OpenShell workspace should become canonical
  after initial seed.
- Record the selected `plugins.entries.openshell.config.mode`, `policy`,
  `providers`, `gpu`, and gateway settings in deployment evidence.
- In `remote` mode, host edits after the initial seed are not visible until
  `openclaw sandbox recreate` re-seeds the workspace.
- Recreate after changing OpenShell backend, source, mode, or policy settings.

For node pairing:

- Pairing establishes node trust and issues/rotates node tokens; it does not pin
  the live command surface for a node.
- Live node commands come from what the node declares on connect after global
  node command policy is applied.
- Node `system.run` and related exec commands require stronger operator scopes
  during pairing approval, but VMGA must still deny Gmail side effects unless
  they pass through VMGA.
- Paired nodes that can reach Gmail/Workspace credentials, local browser
  profiles, or direct Workspace CLIs are part of the VMGA bypass surface.

## Operator Scopes And File Safety

Operator scopes are OpenClaw control-plane guardrails inside one trusted Gateway
operator domain. They do not create hostile multi-tenant separation. For VMGA:

- `operator.write` can invoke tools and relay node commands, so treat it as
  mailbox-relevant when any Gmail-capable tool is reachable.
- `operator.admin` can mutate configuration, approve high-risk access, and
  satisfy every operator scope. Keep admin-scoped sessions away from
  mailbox-capable shared workflows.
- `operator.approvals` covers OpenClaw exec/plugin approval APIs, not VMGA Gmail
  approval.
- `operator.talk.secrets` can read Talk configuration with secrets included; do
  not expose it to agents that should not see secrets.
- Shared gateway token/password auth is trusted operator access for the whole
  Gateway. Use separate Gateways for real trust-boundary separation.

OpenClaw fs-safe protects trusted OpenClaw code handling untrusted paths with
root-bounded access, atomic writes, symlink/hardlink defenses on selected APIs,
byte limits, and private modes for supported secret/state files. It is not a
sandbox and does not replace OS users, containers, tool policy, or VMGA executor
isolation.

For VMGA deployments:

- Do not rely on fs-safe alone when the threat includes hostile local users or an
  agent with filesystem/shell access in the same authority context.
- Prefer OpenClaw plugin SDK file helpers for plugin-facing paths rather than
  raw filesystem calls.
- If POSIX same-UID path-race hardening is part of the security posture, use
  `OPENCLAW_FS_SAFE_PYTHON_MODE=require`; `auto` can fall back to Node-only
  behavior.
- VMGA state, approval verifier secrets, Gmail credentials, and evidence logs
  should remain outside agent-readable roots regardless of fs-safe settings.

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
- `/tools/invoke` access to Gmail, Workspace, shell, filesystem, browser, node,
  or plugin-owned write tools that can mutate mailbox state outside VMGA.
- Paired node commands or host exec allowlists that can invoke direct mailbox
  write paths.
- Elevated exec paths for mailbox-capable agents.
- Docker, browser, SSH, or OpenShell mounts that expose VMGA state, Gmail
  credentials, home credential roots, browser profiles, Docker sockets, or
  OpenClaw config/auth material.

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
5. Run `openclaw sandbox explain --json` for mailbox-capable agents.
6. If sandbox config changed, run `openclaw sandbox recreate` for the affected
   scope and record `openclaw sandbox list --json`.
7. Inspect sandbox tool policy, elevated gates, bind mounts, workspace access,
   and OpenShell mode/policy in the captured sandbox evidence.
8. Run `openclaw approvals get --gateway --json` or the relevant node/local
   approvals command and record the effective exec posture.
9. Prove an authorized sender can trigger a VMGA proposal.
10. Prove an unauthorized sender or browser session is denied.
11. Prove direct Gmail writes through non-VMGA tools fail, including through
    `/tools/invoke` when that endpoint is reachable in the deployment.
12. Confirm approval-gated actions still require VMGA approval, not merely
    OpenClaw exec approval.
13. Confirm paired nodes cannot expose Gmail side effects outside VMGA.
14. Confirm logs redact tokens and message secrets.
15. Record all accepted residual warnings.

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

## Release Watchpoints

OpenClaw `v2026.6.5` includes several security-relevant fixes that VMGA
deployments should preserve in release evidence:

- Auth profile state moved toward SQLite-backed durability, while session
  metadata SQLite migration was deferred in that release train. VMGA deployments
  should record which OpenClaw state stores remain JSON-backed and which are
  SQLite-backed.
- Owner-only HTTP tools are gated more tightly. VMGA should still prove
  `/tools/invoke` cannot reach non-VMGA Gmail or Workspace write tools.
- MCP HTTP redirects are guarded and richer MCP tool-result blocks are coerced
  at the materialize boundary. VMGA should still treat MCP servers with
  Workspace credentials as bypass surfaces unless they route through VMGA.
- Official plugin install records keep trusted pins, and prerelease fallback
  integrity checks avoid carrying stale integrity forward. VMGA OpenClaw
  examples should record plugin manifest hashes and pinned package/commit
  identities.
- Service environment planning skips unresolved placeholders that could mask
  state-dir secrets. VMGA deployments should record effective service env and
  prove VMGA/Gmail secrets are not agent-readable.
- Release and QA proof paths now fail closed on missing runtime tool evidence,
  loose release limits, and unbounded diagnostics. VMGA should keep its release
  evidence similarly bounded and reproducible.

## References

- OpenClaw 2026.6.5 Release:
  https://github.com/openclaw/openclaw/releases/tag/v2026.6.5
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
- OpenClaw Approvals CLI: https://docs.openclaw.ai/cli/approvals
- OpenClaw Sandbox CLI: https://docs.openclaw.ai/cli/sandbox
- OpenClaw Sandboxing: https://docs.openclaw.ai/gateway/sandboxing
- OpenClaw OpenShell: https://docs.openclaw.ai/gateway/openshell
- OpenClaw Sandbox vs Tool Policy vs Elevated:
  https://docs.openclaw.ai/gateway/sandbox-vs-tool-policy-vs-elevated
- OpenClaw Operator Scopes:
  https://docs.openclaw.ai/gateway/operator-scopes
- OpenClaw Secure File Operations:
  https://docs.openclaw.ai/gateway/security/secure-file-operations
- OpenClaw Gateway Protocol: https://docs.openclaw.ai/gateway/protocol
- OpenClaw Tools Invoke API:
  https://docs.openclaw.ai/gateway/tools-invoke-http-api
- OpenClaw Gateway-Owned Pairing:
  https://docs.openclaw.ai/gateway/pairing
- OpenClaw Formal Verification:
  https://docs.openclaw.ai/security/formal-verification
- OpenClaw MITRE ATLAS Threat Model:
  https://docs.openclaw.ai/security/THREAT-MODEL-ATLAS
