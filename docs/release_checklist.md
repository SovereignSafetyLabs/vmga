# VMGA Release Checklist

Use this checklist before tagging or publishing a VMGA release, and before
deploying VMGA with live mailbox credentials.

- Verify the MIT License is present and reflected in package metadata.
- Run the VMGA test suite.
- Run secrets scanning.
- Run SAST or document the static-analysis substitute.
- Review dependency and license posture.
- Verify docs do not claim prompt-injection prevention, DLP, host security,
  compliance certification, or hard isolation without deployment preconditions.
- For OpenClaw examples, capture `openclaw security audit --deep` and
  `openclaw secrets audit --check` output.
- Record the OpenClaw version under test and check current release notes for
  security-relevant changes to HTTP tool gating, MCP redirect handling, plugin
  install pinning, state-store migrations, service env planning, and release
  proof behavior.
- Capture `openclaw sandbox explain --json` and effective exec approvals for
  mailbox-capable agents.
- If sandbox or OpenShell policy changes, recreate affected runtimes and capture
  the post-recreate sandbox list.
- Review sandbox mode, backend, scope, workspace access, sandbox tool policy,
  elevated gates, bind mounts, and OpenShell mode/policy for mailbox-capable
  agents.
- Verify elevated exec is disabled for mailbox-capable agents or documented as a
  break-glass exception with bypass evidence.
- Verify `/tools/invoke` cannot call non-VMGA Gmail/Workspace write paths.
- Verify node pairing and node command policy do not expose mailbox side effects
  outside VMGA.
- Verify VMGA state, evidence, Gmail credentials, browser profiles, Docker
  sockets, and OpenClaw config/auth material are not exposed through sandbox bind
  mounts or agent-readable paths.
- If OpenClaw SecretRefs are migrated, retain the redacted `openclaw secrets
  apply` plan and `openclaw secrets reload` result.
- If trusted-proxy auth is documented or enabled, verify the proxy authenticates
  users, is the only gateway path, strips or overwrites identity headers, and
  has an explicit `allowUsers` operator list for shared audiences.
- For Hermes examples, verify `--yolo`, `/yolo`, `HERMES_YOLO_MODE=1`, and
  `approvals.mode: off` are not part of mailbox-capable deployments.
- Verify Hermes gateway allowlists or DM pairing restrict who can trigger VMGA
  mail tools.
- Verify Hermes env passthrough, Docker forwarded env vars, credential-file
  mounts, MCP env config, hooks, plugins, cron jobs, and native
  Google Workspace tools do not expose Gmail writes outside VMGA.
- Verify Hermes plugin examples use the standard plugin layout, declare only
  VMGA tools in `provides_tools`, return JSON strings from handlers, and avoid
  slash-command/hook dispatch to non-VMGA Gmail or terminal tools.
- Verify Hermes `~/.hermes/state.db`, gateway logs, credential files, browser
  profiles, VMGA state, and VMGA evidence are treated as sensitive deployment
  artifacts.
- Verify example policies use placeholder domains and strict defaults.
- Verify SQLite state is using WAL mode and a busy timeout in broker deployments.
- Verify evidence rotation is configured through VMGA or the host log-rotation
  system before live use.
- Verify broker correlation IDs appear on proposal, state, approval, and
  execution evidence for at least one request lifecycle.
- Verify redaction happens in memory before writing shareable smoke-test or
  release evidence.
- Verify live smoke drafts are tagged with `[VMGA-SMOKE]` or cleaned up before
  sharing evidence.
- Verify CI-safe mocks use the same broker request contract as the real broker.
- Verify gogcli rate-limit handling returns structured VMGA errors after
  bounded exponential backoff.
- Run the runtime posture self-check for any live deployment claim. Supply
  explicit `--agent-root` values and retain any `--direct-bypass-evidence`
  reference used with `--attest-no-direct-bypass`.
- Verify posture output does not claim hard-ready from configuration strings
  alone. Until the v0.3.0 implementations land, `hmac_chain` evidence and
  `signature` approvals are design-stage requirements, not active proof.
- For v0.3.0 or later tags, verify evidence-integrity and approval-signature
  acceptance gates in `docs/evidence_integrity_design.md` and
  `docs/approval_signing_design.md` before making hard-boundary claims.
- Verify `SECURITY.md` has a monitored reporting path.
- Record DSOVS self-assessment evidence in `docs/dsovs_readiness.md`.
