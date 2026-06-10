---
name: vmga-mail
description: VMGA governance mail skill for mailbox operators
---

Load this skill when you need governance-gated Gmail workflows:

- `mail_search`
- `mail_get`
- `mail_get_attachment`
- `mail_create_draft`
- `mail_send`

Notes:

- These tools call the VMGA broker and return JSON strings.
- Kinetic mail actions (`mail_create_draft`, `mail_send`) are proposal-shaped and governed by VMGA policy.
- No native terminal or Workspace tooling is executed by this plugin.
- Confirm `VMGA_BROKER_URL` before using the tools. If broker bearer auth is
  enabled, provide `VMGA_BROKER_TOKEN` to the plugin environment.
- Do not substitute Gmail, gog, gws, browser, terminal, MCP, or native Workspace
  write tools for VMGA-governed mail actions.
