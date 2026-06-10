# VMGA OpenClaw Plugin

This OpenClaw tool plugin routes mailbox tool calls to the local VMGA broker.
It does not call Gmail, gog, Google Workspace, shell, browser, or terminal
tools directly.

Default broker URL: `http://127.0.0.1:8765`

Install locally during development:

```bash
cd integrations/openclaw
npm install
npm run plugin:validate
openclaw plugins install "$PWD" --link
```

After installing, inspect the loaded plugin:

```bash
openclaw plugins inspect plugin.vmga
```

This only proves plugin loading. Gateway readiness still requires `openclaw
doctor`, token/auth setup, command-owner setup, sandbox and secrets checks, and
direct-bypass denial evidence as described in `docs/openclaw_integration.md`.

The linked plugin uses `dist/index.js`, so a fresh clone must run `npm install`
and `npm run plugin:validate` before link-installing it.
