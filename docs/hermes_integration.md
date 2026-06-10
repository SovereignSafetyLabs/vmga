# Hermes Integration Notes

VMGA's Hermes integration should provide shell-free email tools inspired by
`hardmail`, while routing kinetic actions through VMGA's proposal and approval
contract.

## Target Tool Surface

- `mail_search`: read-only search.
- `mail_get`: read-only message retrieval.
- `mail_get_attachment`: governed attachment retrieval.
- `mail_create_draft`: proposal-backed draft creation.
- `mail_send`: proposal-backed send request, denied or held unless policy and
  approval permit execution.

## Important Difference From hardmail

`hardmail` self-gates `mail_send` inside the plugin. VMGA should not use
self-gating for production claims. VMGA approval must be out-of-band and bound to
the exact proposal hash.

## Toolset Scoping

Hermes deployments should scope VMGA mail tools only to platforms that need
email access and should avoid granting `terminal`, generic browser, or generic
web tools to the same untrusted mail-reading surface.

## Hermes Security Controls And VMGA Boundaries

Hermes dangerous-command approval is not VMGA approval. Hermes approvals govern
terminal commands that match dangerous patterns; VMGA approval governs exact
Gmail proposals and must remain out-of-band, proposal-hash-bound,
non-replayable, and verified by VMGA before a mailbox side effect occurs.

For VMGA deployments:

- Do not run mailbox-capable Hermes sessions with `--yolo`, `/yolo`,
  `HERMES_YOLO_MODE=1`, or `approvals.mode: off`.
- Keep `approvals.cron_mode: deny` for mailbox-capable cron or background
  workflows.
- Treat permanent Hermes `command_allowlist` entries as bypass-relevant release
  evidence.
- Do not rely on Hermes dangerous-command patterns, hardline blocks, Tirith, or
  command approval prompts to govern Gmail actions. Gmail actions must be VMGA
  proposals.
- If Tirith is part of the deployment security posture, set
  `security.tirith_fail_open: false`; the default fail-open behavior is not a
  hard enforcement control.

Hermes user authorization helps decide who can trigger a gateway agent, but it
does not create separate mailbox authority inside one mailbox-capable agent.
Use strict platform allowlists or DM pairing, and avoid allow-all settings such
as `GATEWAY_ALLOW_ALL_USERS=true` or platform `*_ALLOW_ALL_USERS=true` for any
agent with VMGA tools.

## Credential And Environment Boundaries

Hermes filters many environment variables and MCP subprocess environments, but
explicit passthrough and skill-declared credentials can deliberately reintroduce
secrets. For VMGA hard-enforcement claims:

- Gmail OAuth tokens, Google client secrets, VMGA executor credentials, VMGA
  approval verifier secrets, and VMGA policy/evidence paths must not be readable
  by the Hermes agent process.
- Do not mount Hermes Google Workspace credential files such as
  `google_token.json` or `google_client_secret.json` into the same runtime that
  can call non-VMGA Gmail tools.
- Do not add Gmail, Google Workspace, VMGA, gateway, or provider secrets to
  `env_passthrough`, `terminal.docker_forward_env`, skill
  `required_environment_variables`, MCP `env`, or credential-file passthrough
  unless the receiving process is the VMGA broker.
- Treat `terminal.credential_files` as a sensitive bypass surface. Docker mounts
  credential files read-only, but read-only credentials can still be used or
  exfiltrated by code running in the container.
- Keep MCP servers that expose Gmail/Workspace writes disabled or behind VMGA.
  Hermes MCP env filtering does not make an intentionally configured MCP
  credential safe for an untrusted mailbox agent.

Credential pools are useful for provider rate-limit resiliency, but they are not
a VMGA credential boundary. Do not pool Gmail or Workspace write credentials in
Hermes for mailbox-capable agents. VMGA-owned credentials should live in the
VMGA broker or a separate credential service.

## Docker And Runtime Isolation

Hermes Docker, Modal, Daytona, Singularity, and SSH backends can reduce host
blast radius for terminal commands. They do not prove VMGA enforcement unless
Gmail credentials and direct Gmail write paths are also isolated from the agent.

For Docker-backed Hermes deployments:

- Prefer Docker or another isolated backend for production gateway deployments.
- Do not bind-mount `/var/run/docker.sock` into a mailbox-capable Hermes
  container.
- Do not mount host browser profiles, `~/.hermes` credential files, Google CLI
  credential directories, VMGA state/evidence, SSH keys, cloud credentials, or
  password-manager state into the agent container.
- Keep `terminal.docker_forward_env` empty unless every forwarded variable is
  intentionally available to model-generated code.
- Use explicit CPU, memory, and disk limits.
- Treat persistent container filesystems as durable agent state that may contain
  transcripts, downloaded attachments, generated code, or copied credentials.
- Do not set `HERMES_ALLOW_ROOT_GATEWAY=1` unless the deployment explicitly
  accepts root-owned file and gateway-state risk.

Hermes skips dangerous-command checks inside several container backends because
the container is treated as the boundary. VMGA cannot rely on those prompts in
container mode; it must rely on credential isolation, tool scoping, and VMGA's
own proposal/approval/execution gate.

## Tool Gateway, Tool Runtime, And Plugin Discovery

The Nous Tool Gateway routes web search, image generation, TTS, and cloud
browser automation through Nous-managed infrastructure. It is not a Gmail
governance boundary. For VMGA deployments:

- Keep generic browser and URL-capable tools away from untrusted mail-reading
  contexts unless they are required and separately risk-reviewed.
- Keep `security.allow_private_urls: false` for public-facing or
  prompt-injection-exposed gateways.
- Use Hermes website blocklists to reduce SSRF/internal-service exposure, but do
  not treat them as Gmail action governance.

Hermes tools are registered through a central registry, discovered from built-in
tools, MCP servers, and plugins. Plugin `pre_tool_call` and `post_tool_call`
hooks can observe or wrap tool calls, but VMGA should not rely on an in-process
hook alone for hard enforcement when the agent can still reach Gmail credentials
or direct Gmail tools elsewhere.

For a VMGA Hermes plugin:

- Ship the standard Hermes plugin layout:
  `plugin.yaml`, `__init__.py`, `schemas.py`, and `tools.py`.
- Declare only VMGA-provided tools in `plugin.yaml` `provides_tools`, and keep
  the manifest as release evidence.
- Use `requires_env` only for non-secret broker endpoints or intentionally
  injected VMGA broker credentials; do not use it to pass Gmail OAuth material
  into the agent plugin.
- Implement handlers as `def handler(args: dict, **kwargs) -> str`, returning
  JSON strings for success and error paths without raising.
- Register only the VMGA mail tool names needed for the deployment.
- Keep tool names unique; Hermes later registration can win on name collision.
- Make every kinetic tool return a VMGA proposal or VMGA denial unless an
  already-approved execution token is supplied to the VMGA broker.
- Ensure plugin `check_fn` availability checks fail closed when VMGA policy,
  broker health, credentials, or evidence storage are unavailable.
- Avoid plugin slash commands or hooks that call `ctx.dispatch_tool()` for
  terminal, browser, MCP, or native Gmail tools unless the dispatched call emits
  VMGA proposals and passes through VMGA execution.
- Treat `pre_tool_call` and `post_tool_call` hooks as observability or defense in
  depth. They run in-process and are not the hard VMGA enforcement boundary.
- Prefer `ctx.register_skill()` for bundled VMGA skills; do not copy skills into
  global `~/.hermes/skills/`, which can create name-collision and drift risk.
- Treat agent-loop tools such as memory, session search, and delegation as
  separate context surfaces. They must not carry VMGA secrets or approval tokens.

## Runtime Verification

Before treating a Hermes session as VMGA-wired, verify the enabled plugin and
broker path from the operator shell:

```bash
hermes plugins list
curl -fsS http://127.0.0.1:8765/health
```

Expected state:

- `vmga-mail` is enabled.
- `VMGA_BROKER_URL` points at the VMGA broker.
- If the broker uses bearer auth, `VMGA_BROKER_TOKEN` is available only to the
  VMGA plugin process or operator-controlled wrapper.
- `mail_search` returns a VMGA broker response for a safe read/search query.
- `mail_create_draft` returns `REVIEW_REQUIRED`, `DENY`, or an approved VMGA
  execution response; it does not call Gmail directly.
- Missing or unreachable broker returns fail-closed JSON with a VMGA error code.

Do not mark Hermes runtime wiring complete until the mailbox-capable Hermes
profile has no native Gmail/Workspace write tools, direct `gog`/`gws` command
surface, browser session capable of Gmail writes, or MCP/plugin path that can
mutate Gmail outside VMGA.

## Gateway And Session Storage

Hermes gateway session keys route messages using platform and chat context. They
are not VMGA authorization tokens. VMGA evidence should record Hermes source,
session key, platform, chat/thread identifier, actor, tool name, and VMGA
proposal hash, but approval must bind to VMGA proposal fields rather than to
Hermes routing metadata alone.

Hermes persists session metadata, message history, tool calls, and searchable
FTS content in `~/.hermes/state.db` by default. For VMGA:

- Treat `~/.hermes/state.db`, WAL/SHM files, gateway logs, and profile data as
  sensitive operational records.
- Do not store VMGA approval verifier secrets, Gmail refresh tokens, execution
  tokens, or long-lived VMGA broker credentials in Hermes session messages,
  memory, tool results, or reasoning fields.
- If mailbox content appears in Hermes transcripts, handle the session database
  as mailbox-derived data in retention and release evidence.
- Do not rely on Hermes session lineage or session titles as security
  boundaries.

## Hermes Bypass Checklist

A Hermes deployment is hard-enforced only if these non-VMGA paths are denied or
unavailable:

- Native Hermes Google Workspace/Gmail tools that can send, draft, forward,
  label, archive, delete, or download attachments outside VMGA.
- Direct Google Workspace CLIs such as `gws`, `gog`, `gmail`, or custom scripts
  reachable through terminal, MCP, plugins, browser automation, cron, or hooks.
- `google_token.json`, `google_client_secret.json`, browser OAuth profiles,
  Google CLI credentials, service-account files, or raw access tokens readable
  by the agent.
- Tool Gateway/browser flows that can operate logged-in Google sessions outside
  VMGA.
- MCP servers, hooks, plugins, wrapper CLI commands, or skill requirements that
  expose Workspace credentials or Gmail write methods without VMGA proposals.
- Cron/background jobs that can send email without VMGA approval.

If any of these remain reachable, describe the deployment as advisory governance
only.

## References

- Hermes Security:
  https://hermes-agent.nousresearch.com/docs/user-guide/security
- Hermes Docker:
  https://hermes-agent.nousresearch.com/docs/user-guide/docker
- Hermes Tool Gateway:
  https://hermes-agent.nousresearch.com/docs/user-guide/features/tool-gateway
- Hermes Credential Pools:
  https://hermes-agent.nousresearch.com/docs/user-guide/features/credential-pools
- Hermes Gateway Internals:
  https://hermes-agent.nousresearch.com/docs/developer-guide/gateway-internals
- Hermes Session Storage:
  https://hermes-agent.nousresearch.com/docs/developer-guide/session-storage
- Hermes Extending The CLI:
  https://hermes-agent.nousresearch.com/docs/developer-guide/extending-the-cli
- Hermes Tools Runtime:
  https://hermes-agent.nousresearch.com/docs/developer-guide/tools-runtime
- Hermes Build A Plugin:
  https://hermes-agent.nousresearch.com/docs/guides/build-a-hermes-plugin
