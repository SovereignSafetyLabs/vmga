# VMGA Evidence Notes

VMGA release evidence should show what was tested, reviewed, and bounded for a
tagged release or live deployment without overstating VMGA's security boundary.

## What To Capture

- `python scripts/vmga_release_check.py`
- `pytest tests/test_release_checks.py -q`
- `python scripts/build_vmga_evidence.py --mode dry-run --force`
- `python scripts/build_vmga_evidence.py --mode release --include-local-tools`
- Policy load results for every shipped file in `policies/`
- A record of whether `schemas/` exists in the release bundle
- Secret-scan output for docs, examples, and integration example files when
  present
- Broker health output, VMGA operator proposal listing, gog auth health, Hermes
  plugin status, OpenClaw plugin status, and OpenClaw doctor/security outputs
  when a local deployment is being claimed
- Any deployment-specific evidence required by `docs/deployment_runbook.md`
- Correlation IDs for proposal, state, approval, and execution events when a
  request lifecycle is being traced.

## Claim Hygiene

The public docs must stay explicit about what VMGA is and is not. VMGA does not
claim prompt-injection prevention, DLP, host compromise protection,
browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals.

That language belongs in the README and supporting docs so reviewers can see the
boundary without cross-referencing hidden notes or oral context.

## Safe Publishing Rules

- Example configs should use `example.com`, `example.invalid`, or other clearly
  fake placeholders.
- Approval secrets and Gmail tokens should be referenced as external sources,
  never embedded in examples.
- Evidence bundles should be reproducible offline from the repository state and
  should not depend on live secrets.
- Live evidence should be redacted before sharing. Keep raw local transcripts in
  ignored artifact directories and commit only generic examples.
- Redact in memory before writing shareable evidence. Do not write raw OAuth
  tokens, mailbox content, or message payloads to temporary files as an
  intermediate step.

## Release Review

Use `scripts/vmga_release_check.py` as a preflight gate before tagging a
release. The script is intentionally conservative: missing required files or
obvious secret patterns are treated as errors, while a missing `schemas/`
directory is reported so the release reviewer can decide whether that is
expected for the current snapshot.

Use `scripts/build_vmga_evidence.py --mode release` to collect a redacted local
evidence skeleton. The command records hashes and broker health by default. Add
`--include-local-tools` only when the local Hermes/OpenClaw/gog command output is
intended to become part of the operator evidence bundle.
