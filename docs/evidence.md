# VMGA Evidence Notes

VMGA release evidence should prove the repository is safe to publish without
overstating its security boundary.

## What To Capture

- `python scripts/vmga_release_check.py`
- `pytest tests/test_release_checks.py -q`
- Policy load results for every shipped file in `policies/`
- A record of whether `schemas/` exists in the release bundle
- Secret-scan output for docs, examples, and integration example files when
  present
- Any deployment-specific evidence required by `docs/deployment_runbook.md`

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

## Release Review

Use `scripts/vmga_release_check.py` as a preflight gate before tagging a public
release. The script is intentionally conservative: missing required files or
obvious secret patterns are treated as errors, while a missing `schemas/`
directory is reported so the release reviewer can decide whether that is
expected for the current snapshot.
