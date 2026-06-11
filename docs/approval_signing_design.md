# Approval Signing Architecture Record

Status: canonical implemented architecture record for the `v0.3.0` approval
signature milestone. This document defines the approval-signature boundary
implemented by VMGA. Signature mode changes VMGA approval behavior only when
configured with approver public keys and when approver private keys are held
outside the broker and agent authority domains. HMAC approval remains available
and broker-forgeable on the approval axis.

## Goal

VMGA supports asymmetric, out-of-domain approval signatures for hard
approval-enforcement claims. The broker verifies an approver's detached
signature over the approval binding message, but never holds the approver's
private key.

Ed25519 is the implemented signature scheme because it is deterministic and has
a small, well-understood API surface. Any future signature scheme must preserve
the same deterministic VMGA signing payload, algorithm/keyring matching, and
fail-closed verification semantics before it can be counted as equivalent.

This detects:

- a compromised broker attempting to forge an operator approval without the
  approver private key;
- an agent attempting to grant itself mailbox authority;
- any caller that cannot produce a valid signature from the configured
  approver private key.

This does not detect or prevent:

- an attacker who controls the approver private key;
- compromise of the operator signing device;
- an operator intentionally signing a malicious approval.
- false `actor_id` provenance supplied by an upstream runtime unless the
  deployment binds broker authentication, channel identity, or routing evidence
  to the claimed actor.

Those residuals are out of scope for this design and must be named in any
hard-enforcement deployment claim.

## Boundary

Asymmetric signing is a security improvement only when the approver private key
lives outside both the broker and agent authority domains. A hardware-backed
operator key, hardware token, OS keychain item inaccessible to the broker
process, or operator-held signing host can satisfy that boundary. If the broker
holds the signing key, the design is no better than HMAC for approval
forgeability: the broker can still mint approvals.

The broker is configured with approver public keys only. The broker verifies
signatures and records approved proposals; it does not sign. Signing happens in
an external operator-side signer.

## Second-Order Residuals

Approval signatures bind exactly the proposal VMGA has recorded; they do not
prove that an upstream agent runtime honestly named the originating actor unless
the deployment separately binds broker credentials, channel identity, or routing
evidence to `actor_id`. Operators should treat `actor_id` as governed metadata
unless that upstream provenance chain is part of the deployment evidence.

VMGA pressure and risk signals are evidence aids, not semantic completeness
claims. Keyword and pattern detectors can miss homoglyphs, paraphrases,
non-English pressure, encoded text, or rendered-content tricks. The approval
signature still binds the canonical proposal bytes that VMGA recorded, but the
human reviewer remains responsible for inspecting the proposed content and
recipient context.

## Signed Message

The operator signs offline, before the broker computes approval expiry, so the
signed payload must contain only fields known at signing time. `proposal_hash`
already commits to the proposal's action, recipients, content, parameters,
thread, and message/attachment ids, so the signature transitively covers those
without re-listing them.

The operator-signed payload is exactly:

- `proposal_id`
- `proposal_hash` (commits to all proposal fields)
- `approver_id`
- `time_window`: the existing short UTC approval window
- `approval_nonce`: a single-use, high-entropy, unpredictable nonce for this
  approval attempt
- `key_id`: the approver public-key identifier used for verification
- `signature_version`: for example `vmga-approval-ed25519-v1`

`expires_at` is not part of the operator-signed payload. The broker computes
`expires_at = approved_at + approval_expiry_seconds` per policy after verifying
the signature, exactly as the current approve path does. The broker-internal
`ApprovalRecord.binding_hash` continues to bind `expires_at` and the full
proposal fields for at-rest record integrity; that binding hash is a separate,
broker-side artifact and is not what the operator signs. Do not conflate the
operator-signed payload with the binding hash.

The signed payload must be canonicalized as UTF-8 JSON with sorted keys and
compact separators `,` and `:`, using the same canonical encoding pattern as
`ApprovalRecord.compute_binding_hash`. Writer and verifier share one
canonicalization function.

The broker recomputes the signed payload from stored VMGA state and the approval
request: it derives `proposal_hash` from the stored proposal and must not trust
any caller-supplied action, recipient, content, expiry, or binding field that
can be recomputed from VMGA state. The only caller-supplied inputs the broker
accepts at face value are `approval_nonce`, `key_id`, and `signature_version`,
each of which is itself covered by the signature.

The broker must verify that the signature algorithm matches the algorithm
declared for that `key_id` in the keyring, so an attacker cannot present a
signature under one scheme against a key registered under another
(algorithm-confusion).

Signatures are not replayable across proposals, approvers, keys, time windows,
or nonces. The broker persists nonce use and denies any replay. Nonce
records are retained only for the maximum approval validity horizon (the policy
approval TTL plus the time-window grace) and pruned past it, so nonce state
cannot grow unbounded or be used to bloat broker state into the fail-closed
size limit.

## Key Handling And Rotation

The broker keyring maps `approver_id` to one or more public keys:

```json
{
  "operator_1": [
    {
      "key_id": "operator-2026-06",
      "algorithm": "ed25519",
      "public_key": "base64-or-ssh-public-key",
      "status": "active"
    }
  ]
}
```

The keyring must come from an operator-owned source equivalent to the
`VMGA_APPROVAL_SECRET` isolation story, but it contains public keys only.
Private keys must never be stored in the broker environment, state database,
policy file, evidence file, repository, or any agent-readable path.

Multiple approvers are supported by `approver_id`. Key rotation is supported by
`key_id`. New approvals must use an active key. Historical records may verify
under retained historical public keys. Unknown `key_id`, removed key material,
or an approver/key mismatch denies verification.

Hardware-backed signing, such as YubiKey/PIV or SSH security-key signing, is
compatible with the boundary but not required by VMGA's current implementation.
The shipped operator-side CLI signer satisfies the architecture only when the
private key remains outside the broker and agent authority domains.

## Verification States And Fail-Closed Behavior

Approval verification is binary at the broker decision point: anything other
than a valid approval signature for the current proposal is `DENY`.

The following cases fail closed:

- bad signature;
- unknown `approver_id`;
- approver not in `approver_allowlist`;
- unknown, removed, inactive, or mismatched `key_id`;
- missing public key when signature mode is configured;
- expired approval or expired time window;
- replayed `approval_nonce`;
- proposal hash mismatch;
- mutated proposal or approval fields;
- malformed signed payload;
- unsupported signature algorithm.

A deployment configured for asymmetric approval verification but missing a
required public key is `cannot_verify` at configuration/readiness time and
`DENY` at approval time. It must never pass open or silently fall back to HMAC
unless the operator explicitly configures HMAC mode.

## Compatibility And Modes

HMAC approval remains available for advisory, local development, and backward
compatibility. It continues to work with existing CLI flows and tests.

VMGA records the approval mode explicitly, for example:

```yaml
approval_auth: hmac        # advisory/dev compatibility
approval_auth: signature   # hard-enforcement requirement
```

`hmac` mode is broker-forgeable because the broker holds the same secret used to
mint tokens. It can still bind approvals to proposals, expiry windows, and
single-use records, but it cannot prove that approval authority lived outside
the broker.

`signature` mode is the hard-enforcement requirement when its key-isolation
precondition holds. README, runbook, and spec language must remain advisory for
deployments where the approver private key is broker-held, agent-readable, or
otherwise not isolated.

## Relationship To Evidence Integrity

This architecture is cross-linked with
`docs/evidence_integrity_design.md`. Approval signing and evidence-chain
checkpoint signing are the same boundary problem: VMGA needs an anchor the
broker cannot forge.

The operator approver key is a possible future Tier 2/3 evidence checkpoint
signer. The approval-signature implementation does not preclude reusing the
same operator-held key, or another key under the same operator boundary, to sign
evidence-chain checkpoints. If the same key is used for both approvals and
evidence checkpoints, signed payloads are domain-separated by
`signature_version` and payload type so an approval signature cannot verify as
an evidence checkpoint signature, or vice versa.

## CLI Sketch

The existing `vmga-approval-token` HMAC helper remains for HMAC mode. Signature
mode adds an operator-side signer, for example:

```bash
vmga-approval-sign \
  --proposal-id <proposal_id> \
  --proposal-hash <proposal_hash> \
  --approver-id operator_1 \
  --key-id operator-2026-06 \
  --time-window <YYYY-MM-DD-HH-MM> \
  --nonce <high-entropy-nonce> \
  --private-key /operator-owned/path/key
```

The signer uses the private key and emits a detached signature plus the exact
canonical payload metadata needed by the broker. The private key file,
hardware-token session, or signing environment must be operator-owned and never
agent-readable.

The broker-side approval API verifies the signature against the configured
public key for `(approver_id, key_id)`, recomputes the operator-signed payload
from stored VMGA state, checks expiry, time window, and nonce replay, then sets
`expires_at` per policy and stores durable approval metadata plus the full
detached signature. The detached signature is public, not secret: persisting it
(not merely a hash of it) makes operator approval non-repudiable and
independently re-verifiable later against the approver public key, which feeds
the evidence-integrity story in #2. Raw private-key material is never logged or
persisted.

## Related Implemented Records

- #2: tamper-evident evidence ledger and verification command.
- #24: asymmetric out-of-domain approval signatures.
- #25: action-tier catalog derived from real code classification.
- #26: multi-turn pressure evidence.

## Implementation Coverage

The v0.3.0 implementation covers the approval-signature boundary as follows:

- docs state the key-isolation boundary and private-key compromise residual
  plainly;
- the broker holds only public keys, and private keys never enter broker or
  agent-readable paths;
- the operator-signed payload contains only sign-time-known fields:
  `proposal_id`, `proposal_hash`, `approver_id`, `time_window`,
  `approval_nonce`, `key_id`, and `signature_version`, and excludes
  broker-computed `expires_at`; the broker sets `expires_at` per policy after
  verification;
- the broker recomputes the signed payload from stored state and trusts no
  caller-supplied field recoverable from VMGA state;
- the signature algorithm is verified against the keyring's declared algorithm
  for the `key_id`, with no algorithm-confusion;
- `approval_nonce` is single-use and high-entropy, and nonce records are pruned
  past the approval validity horizon so nonce state cannot grow unbounded;
- the full detached signature is persisted as evidence, not only a hash, for
  non-repudiation and later re-verification;
- bad signature, unknown approver, approver not allowlisted, unknown or removed
  `key_id`, expired approval, replayed nonce, mutated proposal, and missing
  public key all fail closed;
- missing public key in signature mode is `cannot_verify` for readiness and
  `DENY` for approval, never pass;
- HMAC mode remains available and is documented as broker-forgeable;
- signature mode is documented as the hard-enforcement requirement only when
  approver private-key isolation holds;
- tests cover valid signature, wrong key, tampered message, expired signature,
  replayed nonce, unknown approver, key rotation, old key verifying historical
  records, removed key denial, and signature-payload mutation;
- README/spec/runbook wording remains advisory for deployments where the
  approver private key is not isolated.
