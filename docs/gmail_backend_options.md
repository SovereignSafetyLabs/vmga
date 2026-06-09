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
