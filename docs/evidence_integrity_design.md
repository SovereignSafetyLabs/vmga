# Evidence Integrity Design

Status: draft for `v0.3.0` issue #2. This document defines the intended
tamper-evidence boundary before implementation. It does not upgrade the current
VMGA evidence claim: until this design ships and anchor material is configured
outside the agent authority domain, VMGA evidence remains append-only JSONL
with advisory verification.

## Goal

VMGA should make post-hoc evidence modification detectable under an explicit
trust boundary. The target is tamper-evident evidence, not tamper-proof storage.
VMGA cannot prevent a writer with filesystem access from deleting or rewriting
bytes; it can make mutation detectable when the actor cannot forge the integrity
anchor used by the verifier.

## Tier 1 Boundary

Tier 1 uses a keyed HMAC chain. It detects tampering by:

- the agent process, when the agent cannot read the HMAC key or write VMGA
  evidence outside the broker;
- operators, tools, or local processes that can edit evidence files but cannot
  read the broker-held HMAC key;
- accidental corruption, partial writes, insertion, deletion from the middle,
  and record reordering.

Tier 1 does not detect tampering by a compromised broker host or operator
context that can both rewrite evidence and read the HMAC key. That residual is
out of scope for Tier 1. Tiers 2 and 3 should close it by moving the anchor
outside the broker authority domain, for example with an external checkpoint
signer, append-only/WORM sink, or timestamping service.

## Record Commitment

Each integrity-protected record should carry integrity metadata in addition to
the existing evidence payload:

```json
{
  "integrity": {
    "version": "vmga-hmac-chain-v1",
    "sequence": 42,
    "key_id": "operator-2026-06",
    "prev_mac": "hex-or-null-for-genesis",
    "mac": "hex"
  }
}
```

The MAC input must be deterministic:

```text
MAC(key[key_id], key_id || "\n" || sequence || "\n" || prev_mac || "\n" || canonical(record_with_integrity_metadata_except_mac))
```

Canonicalization must match the JSONL writer:

- UTF-8 JSON;
- object keys sorted lexicographically;
- compact separators `,` and `:`;
- no insignificant whitespace;
- no alternate number, timestamp, or binary encodings introduced by the
  integrity layer.
- `key_id` must not contain a newline or the MAC field delimiter, since the MAC
  input is delimiter-framed rather than length-prefixed.

The verifier and writer must share one canonicalization function. The verifier
must recompute the canonical form from parsed JSON rather than trusting the
line's original whitespace.

Any evidence redaction, for example justification and reason fields, must be
applied before canonicalization and MAC computation, and the MAC must commit to
the exact bytes persisted to the ledger. The integrity layer never sees an
unredacted record, and the verifier recomputes the MAC over the redacted,
as-written record.

## Tail Truncation

A pure hash or HMAC chain detects mutation, insertion, middle deletion, and
reordering, but not deletion of the last N records when the truncated ledger is
otherwise internally consistent. Tier 1 therefore requires an expected head.

For Tier 1, the broker should persist an expected-head checkpoint outside the
JSONL file but inside the operator-owned broker state:

```json
{
  "ledger_path": "/path/outside/agent/evidence.jsonl",
  "last_sequence": 42,
  "last_mac": "hex",
  "key_id": "operator-2026-06"
}
```

The verifier must compare the ledger's final sequence and MAC to the expected
head supplied by the operator. A ledger with an internally valid chain but no
expected head is unanchored, not verified intact. A ledger whose final head does
not match the supplied expected head is verified tampered.

This Tier 1 expected head still lives in the broker/operator authority domain.
It detects tail truncation by actors who can edit the JSONL file but cannot edit
or forge the expected-head checkpoint. It does not detect a compromised broker
host that rewrites both the ledger and the checkpoint. That residual belongs to
Tier 2/3.

## Genesis Anchoring (Prefix Truncation)

Tail truncation is the mirror of prefix truncation, and the expected head only
anchors the newest record. Without a start anchor, deleting the oldest N records
is undetectable: the new first record's stored MAC was computed over its real
`prev_mac`, so it still verifies, the surviving records remain contiguous, and
the tail still matches the expected head. The verifier would report
`verified_intact` for a ledger that lost its beginning.

Tier 1 therefore anchors both ends of the retained chain:

- The first record of the oldest retained segment must be genesis:
  `sequence == <genesis_sequence>` (the chain's fixed start, for example `1`)
  and `prev_mac == null`.
- A ledger or retained segment set whose earliest record is not genesis, and is
  not continuous with an older retained segment, is not a complete chain.

The verifier must reject a chain that begins with a non-null `prev_mac` and has
no preceding retained record. Such a ledger is `verified_tampered` if an
expected head is present and the start cannot be reconciled, or `cannot_verify`
if no start anchor is available. It must never be `verified_intact`.

The expected-head checkpoint is extended to record the genesis the verifier
should expect, so prefix truncation that also forges a new genesis line is
caught:

```json
{
  "ledger_path": "/path/outside/agent/evidence.jsonl",
  "genesis_sequence": 1,
  "genesis_mac": "hex",
  "last_sequence": 42,
  "last_mac": "hex",
  "key_id": "operator-2026-06"
}
```

This start anchor lives in the same broker/operator authority domain as the
expected head and carries the same Tier 1 residual: it detects prefix deletion
by actors who cannot forge the checkpoint, not by a compromised broker that
rewrites both.

## Verification States

The integrity verifier must expose three states:

- `verified_intact`: the chain is valid, every record MAC verifies, sequence
  numbers are contiguous, all referenced `key_id` values are known, and the
  final head matches the supplied expected head.
- `verified_tampered`: the verifier has enough anchor material to check the
  ledger and detects mutation, insertion, deletion, reordering, sequence gaps,
  unknown or wrong MACs, or a head mismatch.
- `cannot_verify`: the verifier lacks the material required to establish the
  claim, such as a missing key, missing expected head, unknown `key_id`, absent
  integrity metadata, or a legacy unanchored ledger.

`cannot_verify` must fail closed for release and operator readiness checks. It
may be reported separately from `verified_tampered` so an operator can
distinguish "missing anchor material" from "anchor material proves tampering,"
but it must not render as success.

Examples that must be invalid for integrity verification:

- missing key or missing key file;
- unknown `key_id`;
- blank, absent, or malformed `mac`;
- missing or non-contiguous `sequence`;
- `prev_mac` that does not match the prior record's `mac`;
- final ledger head absent from the expected-head checkpoint;
- final ledger head different from the expected-head checkpoint;
- earliest retained record is not genesis (`prev_mac != null` or
  `sequence != genesis_sequence`) and is not continuous with an older retained
  segment;
- a missing segment between retained rotated files (seam discontinuity).

## Legacy Evidence Compatibility

Pre-`v0.3.0` evidence has no integrity metadata. The existing `verify_events`
sequence and leak checks remain valid as advisory evidence checks, but they are
a separate dimension from integrity verification.

Legacy or unanchored ledgers should report:

```json
{
  "event_sequence": {"valid": true},
  "integrity": {
    "state": "cannot_verify",
    "reason": "missing_integrity_metadata"
  }
}
```

They must not be silently upgraded to `verified_intact`. CLI and JSON output
should make the distinction obvious.

## Key Handling And Rotation

The HMAC key should be supplied from an operator-owned secret source, equivalent
to the `VMGA_APPROVAL_SECRET` isolation story and outside the agent-readable
workspace. A likely default is:

```text
VMGA_EVIDENCE_HMAC_KEY=<operator-owned random secret>
VMGA_EVIDENCE_HMAC_KEY_ID=<stable key id>
```

The agent must not be able to read the key, edit the key file, edit the
expected-head checkpoint, or bypass the broker to write evidence. If those
preconditions are false, the deployment is advisory/unanchored.

Each record carries `key_id`. During rotation, the writer starts a new segment
with the new `key_id` while preserving the previous record's MAC as `prev_mac`.
The verifier must verify each record under the key named by that record's
`key_id`. Unknown `key_id` is invalid. A keyring may contain historical verify
keys; removing an old key makes old segments `cannot_verify`, not intact.

## Write Path And Concurrency

The chain head is shared mutable state. In the built-in single-process broker,
record canonicalization, MAC computation, JSONL append, fsync, expected-head
update, and expected-head fsync must occur under the same adapter `_state_lock`
that currently guards proposal, approval, execution, and reset mutations.

The intended write order for Tier 1 is:

1. Read current expected head.
2. Assign `sequence = last_sequence + 1` and `prev_mac = last_mac`.
3. Canonicalize the record without `integrity.mac`.
4. Compute `mac`.
5. Append the JSONL line and fsync the ledger.
6. Persist the expected-head checkpoint atomically and fsync it.

Crash behavior must be defined:

- Crash before append: no new record exists; expected head still points to the
  prior record; verification remains intact.
- Crash after append but before expected-head persist: the ledger has an extra
  validly chained tail record, but the checkpoint points to the prior head. The
  verifier must report this as `cannot_verify` or `verified_tampered`, not
  success, because the expected head and ledger tail disagree.
- Crash after checkpoint persist: ledger and expected head match; verification
  remains intact.

Startup recovery: if the ledger tail is exactly one validly chained record
ahead of the expected head (the crash-after-append case), the broker advances
the expected head to that record after verifying its MAC and chain link. Any
larger or non-chaining divergence is left as `verified_tampered` or
`cannot_verify` for operator inspection. Recovery is a broker-domain operation
and does not change the Tier 1 boundary. A handled non-crash error while
persisting the expected-head checkpoint for a kinetic action fails closed in the
same way as a ledger write failure.

The built-in broker remains a single-process control plane. Multi-process hard
claims require a cross-process ledger/head transaction or external append-only
sink; `_state_lock` alone is not enough.

## Ledger Rotation

The built-in JSONL ledger rotates by size (`--ledger-rotate-bytes`,
`--ledger-backups`), so an integrity-protected chain will normally span an
active file plus rotated backups (`evidence.jsonl`, `evidence.jsonl.1`, ...).
Rotation interacts with anchoring in three ways that Tier 1 must handle
explicitly:

- The active file legitimately starts mid-chain after the first rotation, so the
  genesis rule applies to the oldest retained segment, not to every file.
- The expected head anchors only the newest record. Deleting an entire rotated
  backup removes a middle segment without touching the active file or its head,
  so a head-only check would miss it.
- Verification is defined over the ordered retained segment set, not a single
  file.

Tier 1 requires one of the following; the implementation must pick and document
which:

1. Cross-file verification (default). The verifier takes the ordered retained
   set from oldest backup through active file, checks MAC validity within each
   segment, checks `prev_mac` and `sequence` continuity across segment seams,
   anchors the newest record to the expected head and the oldest retained
   record to the genesis anchor, and verifies the retained range is contiguous
   with no missing segment. A gap between segments, such as a deleted backup, is
   `verified_tampered`. A retained set whose oldest record is neither genesis
   nor continuous with an absent-but-expected older segment is
   `verified_tampered`, not `verified_intact`.
2. External sink. Internal rotation is disabled when integrity is enabled and
   the ledger is shipped to an external append-only/WORM sink, moving the anchor
   out of the broker domain (Tier 2/3).

Documented residual: history rotated out of the retained set, meaning records
older than the oldest retained backup, is outside Tier 1's detection scope. The
expected head and genesis anchor cover the retained range only; pruned history
requires an external sink to remain verifiable.

## Acceptance Gates

Implementation for issue #2 should not be considered complete until:

- docs state the Tier 1 compromised-broker residual plainly;
- writer and verifier use the same deterministic canonicalization;
- every MAC commits to `key_id`, `sequence`, `prev_mac`, and canonical record
  content;
- verification distinguishes `verified_intact`, `verified_tampered`, and
  `cannot_verify`;
- the chain is anchored at both ends: genesis (oldest retained record) and
  expected head (newest record);
- missing key, missing expected head, unknown `key_id`, absent MAC, sequence
  gaps, broken links, and head mismatch fail closed;
- prefix truncation, a forged genesis, and a deleted rotated segment all fail
  closed;
- verification is defined over the ordered retained segment set, and the
  rotation strategy, cross-file verification or external sink, is documented;
- startup recovery for the crash-after-append case is defined and tested;
- tests cover mutation, insertion, middle deletion, reordering, tail
  truncation, prefix truncation, segment-gap deletion, cross-seam continuity,
  unknown key, missing key, missing expected head, and forged genesis cases;
- legacy JSONL remains advisory/unanchored rather than verified intact;
- README/spec wording keeps advisory language for deployments without an
  out-of-domain anchor.
