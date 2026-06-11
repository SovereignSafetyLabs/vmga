# VMGA Action Catalog

This catalog is the reviewer-readable tier model for the Gmail actions VMGA
understands. It is intentionally tied to the shipped `GmailAction` enum,
`VMGAPolicy.classify_action`, and default `baseline_denies` behavior. The
release check parses the machine-readable block below so this document cannot
quietly drift from the adapter.

## Tier Model

VMGA has two action classes today:

- `non_kinetic`: reads or transforms mailbox data without changing Gmail state.
- `kinetic`: creates, mutates, moves, deletes, sends, labels, marks, downloads,
  or otherwise changes mailbox state or exports mailbox material.

No other tier is documented here. Adding a tier requires adapter support,
policy validation support, documentation, and release-check alignment in the
same change.

## Machine-Checked Catalog

<!-- BEGIN VMGA_ACTION_CATALOG -->
```json
{
  "schema_version": "vmga-action-catalog-v1",
  "actions": [
    {
      "action": "read",
      "class": "non_kinetic",
      "default_approval": "not_required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_read_access"]
    },
    {
      "action": "summarize",
      "class": "non_kinetic",
      "default_approval": "not_required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_read_access"]
    },
    {
      "action": "classify",
      "class": "non_kinetic",
      "default_approval": "not_required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_read_access"]
    },
    {
      "action": "extract_entities",
      "class": "non_kinetic",
      "default_approval": "not_required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_read_access", "metadata_extraction"]
    },
    {
      "action": "recommend_draft",
      "class": "non_kinetic",
      "default_approval": "not_required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_read_access", "suggested_response"]
    },
    {
      "action": "create_draft",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": ["credential_transmission"],
      "risk_vectors": ["draft_creation", "external_recipient_preparation"]
    },
    {
      "action": "send",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": ["bulk_forwarding", "credential_transmission", "financial_instructions", "mfa_recovery_handling"],
      "risk_vectors": ["mailbox_send", "external_exfiltration"]
    },
    {
      "action": "forward",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": ["bulk_forwarding", "credential_transmission", "financial_instructions", "mfa_recovery_handling"],
      "risk_vectors": ["mailbox_forward", "forwarding_abuse", "external_exfiltration"]
    },
    {
      "action": "archive",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_availability_change"]
    },
    {
      "action": "delete",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_destruction"]
    },
    {
      "action": "apply_label",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": [],
      "risk_vectors": ["label_abuse", "mailbox_visibility_change"]
    },
    {
      "action": "download_attachment",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": [],
      "risk_vectors": ["attachment_download", "attachment_exfiltration"]
    },
    {
      "action": "mark_read",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_visibility_change"]
    },
    {
      "action": "move",
      "class": "kinetic",
      "default_approval": "required",
      "baseline_denies": [],
      "risk_vectors": ["mailbox_availability_change"]
    }
  ]
}
```
<!-- END VMGA_ACTION_CATALOG -->

## Enforced Controls

VMGA enforces the following in code:

- Unknown action strings are rejected by `GmailAction.from_string` and
  `VMGAPolicy.validate_rules`.
- `allowed_actions` and `denied_actions` are validated against the enum.
- `non_kinetic` actions can be allowed when the policy permits them.
- `kinetic` actions default to approval-required unless policy explicitly
  configures otherwise.
- Baseline denies block credential transmission, MFA/recovery handling, bulk
  forwarding, and financial instruction patterns for the actions listed in the
  catalog.
- Draft creation has additional code-enforced guards for maximum length,
  required justification, and external-recipient denial unless explicitly
  allowed.
- External recipients are denied for `send` and `forward` when
  `external_domain_deny` is enabled.
- `apply_label` is constrained by `label_allowlist` at proposal time when a
  requested label is supplied.

## Deployment And Operator Controls

These controls are not created by the catalog itself:

- Gmail credentials must remain outside the agent authority domain.
- Direct `gog`, Google Workspace, or Gmail API access must not be exposed to
  Hermes/OpenClaw; route through the VMGA broker.
- `gog-agent-safe` no-send mode and its command allowlist cover direct send
  suppression and narrow command exposure for the shipped gogcli backend. They
  do not replace VMGA policy, approvals, evidence, or direct-bypass closure.
- Attachment downloads are kinetic because they export mailbox material.
- Label abuse is kinetic because label changes can hide, route, or stage
  mailbox content.
- Filter and forwarding-rule creation is not a shipped VMGA action. A backend
  that exposes Gmail filter or forwarding-rule mutation directly would bypass
  this catalog and must be treated as out of scope until VMGA adds a validated
  `GmailAction`, policy handling, tests, and release-check coverage.

See `docs/gmail_backend_options.md` for backend-specific controls and #1 for
the real-account gogcli backend boundary.
