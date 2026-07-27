"""Tamper-evident proof receipts for Angerona remediation actions.

An action returning successfully is not proof that a finding is closed. The
remediation engine already performs a postcondition check and rolls back failed
changes. This module turns that result into a canonical, HMAC-attested receipt
whose hash is chained to the previous remediation receipt.

Receipts intentionally contain a digest of the action record rather than raw
paths or other endpoint evidence. The detailed record remains in the existing
local remediation ledger; exported proof can demonstrate integrity without
disclosing that evidence.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from angerona.core import report_attest


RECEIPT_VERSION = 1
GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    reason: str
    receipt_hash: str


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def record_digest(record: dict | None) -> str:
    return hashlib.sha256(_canonical(record or {})).hexdigest()


def receipt_hash(receipt: dict) -> str:
    return hashlib.sha256(_canonical(receipt)).hexdigest()


def create_receipt(
    *,
    ts: float,
    trigger: str,
    mitre: str,
    action_key: str,
    outcome: str,
    verified: int,
    host_level: bool,
    record: dict | None,
    previous_hash: str,
) -> tuple[dict, str]:
    """Create an attested receipt and return it with its chain hash."""
    if len(previous_hash) != 64:
        previous_hash = GENESIS_HASH
    body = {
        "receipt_version": RECEIPT_VERSION,
        "receipt_id": f"RCP-{uuid.uuid4().hex}",
        "ts": float(ts),
        "trigger": str(trigger)[:256],
        "mitre": str(mitre or "-")[:32],
        "action_key": str(action_key or "none")[:128],
        "outcome": str(outcome or "unknown")[:64],
        # -1 means no independent postcondition ran; it must never be presented
        # as a successful closure.
        "verification": (
            "passed" if int(verified) == 1
            else "failed" if int(verified) == 0
            else "not-run"
        ),
        "host_level": bool(host_level),
        "action_record_sha256": record_digest(record),
        "previous_receipt_hash": previous_hash,
    }
    receipt = report_attest.attest(body)
    return receipt, receipt_hash(receipt)


def verify_receipt(
    receipt: dict,
    *,
    record: dict | None,
    expected_previous_hash: str,
    stored_hash: str = "",
) -> ReceiptVerification:
    """Verify signature, record binding, chain pointer, and stored hash."""
    if not isinstance(receipt, dict):
        return ReceiptVerification(False, "receipt is not an object", "")
    actual_hash = receipt_hash(receipt)
    if stored_hash and stored_hash != actual_hash:
        return ReceiptVerification(False, "stored receipt hash does not match", actual_hash)
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        return ReceiptVerification(False, "unsupported receipt version", actual_hash)
    if receipt.get("previous_receipt_hash") != expected_previous_hash:
        return ReceiptVerification(False, "receipt chain link is broken", actual_hash)
    if receipt.get("action_record_sha256") != record_digest(record):
        return ReceiptVerification(False, "action record digest does not match", actual_hash)
    authenticity = report_attest.verify(receipt)
    if authenticity != "ok":
        return ReceiptVerification(
            False,
            f"receipt authenticity is {authenticity}",
            actual_hash,
        )
    verification = str(receipt.get("verification", ""))
    outcome = str(receipt.get("outcome", ""))
    if outcome == "applied" and verification != "passed":
        return ReceiptVerification(
            False,
            "an applied action lacks a passed postcondition",
            actual_hash,
        )
    return ReceiptVerification(True, "verified", actual_hash)
