# VMGA Gmail Backend Options

This note explains the intended backends without stretching the claims around
them.

## Advisory Local Mode

Use this when VMGA runs in the same authority context as the agent and the goal
is to exercise policy logic, proposal hashing, and evidence paths locally.

- Example file: `examples/advisory_local.yaml`
- Suitable for unit tests, docs, and offline review
- Not a hard enforcement boundary

## Brokered Mode

Use this when the Gmail credential path and approval material are handled by a
separate broker service.

- Example file: `examples/broker_local.yaml`
- Broker credentials should live outside the agent-readable workspace
- The broker should keep approval and token material out of the example file

### gogcli Backend

`vmga-broker --backend gogcli` runs Gmail operations through a broker-owned
`gog-agent-safe`/`gog` binary with list-style subprocess calls. The backend is
narrow by default:

- `gmail search` for governed search.
- `gmail get --sanitize-content` for governed message reads.
- `gmail drafts create --body-file -` for approved draft creation.

The backend always adds `--gmail-no-send`, `--no-input`, and an exact command
allowlist for `gmail.search,gmail.get,gmail.drafts.create`. Draft bodies are
passed over stdin instead of command-line arguments. Do not expose direct
`gog`, `gws`, or Google Workspace tools to Hermes/OpenClaw; route those requests
through the VMGA broker.

The backend treats `429`, quota, and rate-limit failures as retryable and uses a
bounded exponential backoff before returning a structured VMGA error. Batch
callers should still avoid high fan-out Gmail operations; VMGA is a governance
gate, not a bulk-mail queue.

Real-account setup checklist:

1. Store the Google OAuth client JSON outside the agent-readable repository.
2. Configure gog's keyring in an operator-owned location.
3. Authorize the Gmail account with the minimum scopes required by the backend.
4. Run `gog-agent-safe` health checks from the operator shell, not from Hermes or
   OpenClaw.
5. Start `vmga-broker --backend gogcli` with `--gog-binary` pointing at
   `gog-agent-safe` and `VMGA_BROKER_TOKEN` set in the operator environment.
6. Verify through `scripts/vmga_live_smoke.py --live`; do not validate by giving
   agents direct gog access.

The live smoke script deliberately probes read/search and send denial before any
optional draft creation. Add `--create-draft` only when creating a real draft in
the configured mailbox is acceptable. Smoke-created drafts include a
`[VMGA-SMOKE]` marker in the subject and body so they can be found and deleted.

## Release Hygiene

All backend examples must stay on placeholder values and must not contain live
tokens, private keys, or copied credential payloads.

VMGA does not claim prompt-injection prevention, DLP, host compromise
protection, browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals.

That sentence is part of the release hygiene bar, not a runtime guarantee.

## Practical Guidance

- Keep `example.com` and `example.invalid` in sample data.
- Use external credential sources for Gmail OAuth tokens and approval secrets.
- Treat any in-process backend as advisory unless the deployment proves a
  separate broker boundary and bypass closure.
