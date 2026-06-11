"""Tamper-evident HMAC chain helpers for VMGA evidence."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

INTEGRITY_VERSION = "vmga-hmac-chain-v1"


def canonical_json_bytes(record: Dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_json_line(record: Dict[str, Any]) -> str:
    return canonical_json_bytes(record).decode("utf-8") + "\n"


@dataclass(frozen=True)
class EvidenceHMACConfig:
    key_id: str
    key: bytes

    @classmethod
    def from_env(cls) -> Optional["EvidenceHMACConfig"]:
        key = os.getenv("VMGA_EVIDENCE_HMAC_KEY")
        key_id = os.getenv("VMGA_EVIDENCE_HMAC_KEY_ID")
        if not key and not key_id:
            return None
        if not key or not key_id:
            raise ValueError("VMGA_EVIDENCE_HMAC_KEY and VMGA_EVIDENCE_HMAC_KEY_ID must both be set")
        if "\n" in key_id:
            raise ValueError("VMGA_EVIDENCE_HMAC_KEY_ID must not contain a newline")
        return cls(key_id=key_id, key=key.encode("utf-8"))


@dataclass(frozen=True)
class EvidenceCheckpoint:
    ledger_path: str
    genesis_sequence: int
    genesis_mac: str
    last_sequence: int
    last_mac: str
    key_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ledger_path": self.ledger_path,
            "genesis_sequence": self.genesis_sequence,
            "genesis_mac": self.genesis_mac,
            "last_sequence": self.last_sequence,
            "last_mac": self.last_mac,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceCheckpoint":
        return cls(
            ledger_path=str(data["ledger_path"]),
            genesis_sequence=int(data["genesis_sequence"]),
            genesis_mac=str(data["genesis_mac"]),
            last_sequence=int(data["last_sequence"]),
            last_mac=str(data["last_mac"]),
            key_id=str(data["key_id"]),
        )


@dataclass
class IntegrityVerificationResult:
    state: str
    reason: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    last_sequence: Optional[int] = None
    last_mac: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "state": self.state,
            "reason": self.reason,
            "errors": self.errors,
            "warnings": self.warnings,
        }
        if self.last_sequence is not None:
            payload["last_sequence"] = self.last_sequence
        if self.last_mac is not None:
            payload["last_mac"] = self.last_mac
        return payload


def compute_record_mac(record_without_mac: Dict[str, Any], key: bytes) -> str:
    integrity = record_without_mac.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("record missing integrity metadata")
    key_id = str(integrity["key_id"])
    if "\n" in key_id:
        raise ValueError("key_id must not contain a newline")
    sequence = int(integrity["sequence"])
    prev_mac = integrity.get("prev_mac")
    prev_mac_text = "null" if prev_mac is None else str(prev_mac)
    mac_input = (
        key_id.encode("utf-8")
        + b"\n"
        + str(sequence).encode("utf-8")
        + b"\n"
        + prev_mac_text.encode("utf-8")
        + b"\n"
        + canonical_json_bytes(record_without_mac)
    )
    return hmac.new(key, mac_input, hashlib.sha256).hexdigest()


def add_integrity_metadata(
    record: Dict[str, Any],
    *,
    key_id: str,
    key: bytes,
    sequence: int,
    prev_mac: Optional[str],
) -> Dict[str, Any]:
    if "\n" in key_id:
        raise ValueError("key_id must not contain a newline")
    signed = copy.deepcopy(record)
    signed["integrity"] = {
        "version": INTEGRITY_VERSION,
        "sequence": sequence,
        "key_id": key_id,
        "prev_mac": prev_mac,
    }
    signed["integrity"]["mac"] = compute_record_mac(signed, key)
    return signed


def retained_segment_paths(path: str | Path) -> List[Path]:
    base = Path(path)
    paths: List[Path] = []
    index = 1
    while True:
        candidate = base.with_name(f"{base.name}.{index}")
        if not candidate.exists():
            break
        paths.append(candidate)
        index += 1
    paths.reverse()
    if base.exists():
        paths.append(base)
    return paths


def load_segmented_events(path: str | Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for segment in retained_segment_paths(path):
        with open(segment, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Invalid JSON in {segment} line {line_no}: {exc}") from exc
    return events


def verify_integrity(
    events: Iterable[Dict[str, Any]],
    *,
    checkpoint: Optional[EvidenceCheckpoint],
    keyring: Dict[str, bytes],
) -> IntegrityVerificationResult:
    records = list(events)
    if not records:
        if checkpoint is not None:
            # The anchor says records should exist; an empty retained set is
            # provable truncation, not missing anchor material.
            return IntegrityVerificationResult("verified_tampered", "empty_ledger_with_expected_head")
        return IntegrityVerificationResult("cannot_verify", "empty_ledger")
    if not checkpoint:
        if any("integrity" not in record for record in records):
            return IntegrityVerificationResult("cannot_verify", "missing_integrity_metadata")
        return IntegrityVerificationResult("cannot_verify", "missing_expected_head")

    prior_sequence: Optional[int] = None
    prior_mac: Optional[str] = None
    first_sequence: Optional[int] = None
    first_mac: Optional[str] = None

    for index, record in enumerate(records):
        integrity = record.get("integrity")
        if not isinstance(integrity, dict):
            return IntegrityVerificationResult("cannot_verify", "missing_integrity_metadata")
        if integrity.get("version") != INTEGRITY_VERSION:
            return IntegrityVerificationResult("cannot_verify", "missing_integrity_metadata")
        key_id = integrity.get("key_id")
        if not isinstance(key_id, str) or not key_id or "\n" in key_id:
            return IntegrityVerificationResult("cannot_verify", "malformed_integrity_metadata")
        key = keyring.get(key_id)
        if key is None:
            return IntegrityVerificationResult("cannot_verify", "unknown_key_id")
        try:
            sequence = int(integrity["sequence"])
            mac = integrity["mac"]
            prev_mac = integrity.get("prev_mac")
        except (KeyError, TypeError, ValueError):
            return IntegrityVerificationResult("cannot_verify", "malformed_integrity_metadata")
        if not isinstance(mac, str) or not mac:
            return IntegrityVerificationResult("cannot_verify", "malformed_integrity_metadata")
        record_without_mac = copy.deepcopy(record)
        record_without_mac["integrity"].pop("mac", None)
        expected_mac = compute_record_mac(record_without_mac, key)
        if not hmac.compare_digest(mac, expected_mac):
            return IntegrityVerificationResult("verified_tampered", "mac_mismatch")
        if index == 0:
            first_sequence = sequence
            first_mac = mac
        else:
            if sequence != (prior_sequence or 0) + 1:
                return IntegrityVerificationResult("verified_tampered", "sequence_gap")
            if prev_mac != prior_mac:
                return IntegrityVerificationResult("verified_tampered", "prev_mac_mismatch")
        prior_sequence = sequence
        prior_mac = mac

    assert prior_sequence is not None and prior_mac is not None
    if first_sequence != checkpoint.genesis_sequence or first_mac != checkpoint.genesis_mac:
        return IntegrityVerificationResult("verified_tampered", "genesis_mismatch", last_sequence=prior_sequence, last_mac=prior_mac)
    first_prev = records[0]["integrity"].get("prev_mac")
    if first_prev is not None:
        return IntegrityVerificationResult("verified_tampered", "prefix_truncation", last_sequence=prior_sequence, last_mac=prior_mac)
    if prior_sequence != checkpoint.last_sequence or prior_mac != checkpoint.last_mac:
        return IntegrityVerificationResult("verified_tampered", "head_mismatch", last_sequence=prior_sequence, last_mac=prior_mac)
    return IntegrityVerificationResult("verified_intact", "ok", last_sequence=prior_sequence, last_mac=prior_mac)


def recover_one_ahead(
    events: Iterable[Dict[str, Any]],
    *,
    checkpoint: Optional[EvidenceCheckpoint],
    keyring: Dict[str, bytes],
    ledger_path: str,
) -> Optional[EvidenceCheckpoint]:
    if checkpoint is None:
        return None
    records = list(events)
    if not records:
        return None
    if len(records) < checkpoint.last_sequence + 1:
        return None
    last = records[-1]
    integrity = last.get("integrity")
    if not isinstance(integrity, dict):
        return None
    try:
        sequence = int(integrity["sequence"])
        prev_mac = integrity.get("prev_mac")
        mac = str(integrity["mac"])
        key_id = str(integrity["key_id"])
    except (KeyError, TypeError, ValueError):
        return None
    if sequence != checkpoint.last_sequence + 1 or prev_mac != checkpoint.last_mac:
        return None
    if key_id not in keyring:
        return None
    prior_result = verify_integrity(records[:-1], checkpoint=checkpoint, keyring=keyring)
    if prior_result.state != "verified_intact":
        return None
    record_without_mac = copy.deepcopy(last)
    record_without_mac["integrity"].pop("mac", None)
    expected_mac = compute_record_mac(record_without_mac, keyring[key_id])
    if not hmac.compare_digest(mac, expected_mac):
        return None
    return EvidenceCheckpoint(
        ledger_path=ledger_path,
        genesis_sequence=checkpoint.genesis_sequence,
        genesis_mac=checkpoint.genesis_mac,
        last_sequence=sequence,
        last_mac=mac,
        key_id=key_id,
    )
