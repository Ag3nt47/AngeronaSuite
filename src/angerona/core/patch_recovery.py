"""Exact-owner recovery handoff, separate from applied/closure proof."""
from __future__ import annotations

import json
import math


def verify_recovery_handoff(store, transaction_id, proof, *, expected_mitre, expected_action):
    """Authenticate one committed RECOVERY_REQUIRED receipt and relational row.

    This is local custody evidence only. It grants no native action, establishes
    no successful postcondition and cannot satisfy an application/closure gate.
    """
    from angerona.core.remediation_log import (MAX_APPLICATION_RECEIPT_BYTES,
        MAX_TRANSACTION_RECORD_BYTES, RemediationLog, _row_to_dict)
    try:
        if (type(store) is not RemediationLog or type(transaction_id) is not int
                or not 0 < transaction_id < 2**63 or type(proof) is not dict
                or any(type(value) is not str or not 1 <= len(value) <= 256
                       for value in (expected_mitre, expected_action))):
            return False
        digest, receipt_id = proof.get("receipt_hash"), proof.get("receipt_id")
        if (type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                or type(receipt_id) is not str or len(receipt_id) != 36 or not receipt_id.startswith("RCP-")
                or any(c not in "0123456789abcdef" for c in receipt_id[4:])):
            return False
        with store._lock:
            if store._db.in_transaction:
                return False
            store._assert_db_custody_locked()
            row = store._db.execute("""
              SELECT r.ts,r.trigger,r.mitre,r.action_key,r.action_title,r.outcome,
                     r.verified,r.host_level,r.record_json,r.receipt_json,r.receipt_hash,
                     t.id,t.trigger,t.mitre,t.action_key,t.action_title,t.host_level,t.updated_ts,t.record_json
              FROM remediation_log AS r JOIN remediation_transactions AS t ON t.id=:identifier
              WHERE r.receipt_hash=:digest AND r.outcome='recovery_required'
                AND t.state='RECOVERY_REQUIRED' AND t.owner_capability_sha256 IS NULL
                AND NOT EXISTS(SELECT 1 FROM remediation_reconciliation_claims AS c WHERE c.transaction_id=t.id)
                AND r.record_json=t.record_json
                AND typeof(r.record_json)='text' AND length(r.record_json)<=:record_limit
                AND length(CAST(r.record_json AS BLOB))<=:record_storage_limit
                AND typeof(r.receipt_json)='text' AND length(r.receipt_json)<=:receipt_limit
                AND length(CAST(r.receipt_json AS BLOB))<=:receipt_storage_limit
                AND length(r.trigger)<=256 AND length(r.mitre)<=256 AND length(r.action_key)<=256
                AND length(r.action_title)<=256 AND length(t.trigger)<=256 AND length(t.mitre)<=256
                AND length(t.action_key)<=256 AND length(t.action_title)<=256
              LIMIT 1
            """, {"identifier": transaction_id, "digest": digest,
                "record_limit": MAX_TRANSACTION_RECORD_BYTES, "record_storage_limit": 2 * MAX_TRANSACTION_RECORD_BYTES,
                "receipt_limit": MAX_APPLICATION_RECEIPT_BYTES, "receipt_storage_limit": 2 * MAX_APPLICATION_RECEIPT_BYTES}).fetchone()
            if row is None or len(row[8].encode("utf-8")) > MAX_TRANSACTION_RECORD_BYTES or len(row[9].encode("utf-8")) > MAX_APPLICATION_RECEIPT_BYTES:
                return False
            retained = _row_to_dict(row[:11])
            receipt, record = json.loads(row[9]), json.loads(row[8])
            valid = (retained["receipt_authenticity"] is True and retained["receipt_id"] == receipt_id
                and type(receipt.get("receipt_version")) is int and receipt["receipt_version"] == 1
                and receipt.get("outcome") == "recovery_required" and receipt.get("verification") == "failed"
                and receipt.get("trigger") == row[1] == row[12]
                and receipt.get("mitre") == row[2] == row[13] == expected_mitre
                and receipt.get("action_key") == row[3] == row[14] == expected_action
                and row[4] == row[15] and type(row[6]) is int and row[6] == 0
                and type(row[7]) is int and row[7] in (0, 1) and type(row[16]) is int and row[7] == row[16]
                and type(receipt.get("host_level")) is bool and receipt["host_level"] is bool(row[7])
                and type(receipt.get("ts")) in (int, float) and math.isfinite(receipt["ts"])
                and receipt["ts"] == row[0] == row[17]
                and type(record.get("transaction_id")) is int and record["transaction_id"] == transaction_id
                and record.get("action") == expected_action and record.get("mitre") == expected_mitre
                and record.get("transaction_state") == "recovery_required"
                and record.get("recovery_required") is True and record.get("verified") is False)
            store._assert_db_custody_locked()
            return valid
    except Exception:
        return False


def handoff_owned_failure(store, owner, record, *, failed_result, error):
    """Use the still-owned capability to commit an honest recovery handoff.

    A failed APPLIED commit does not release a MUTATING owner. Only this new
    distinct commit can release that exact owner for reviewed reconciliation.
    A second persistence failure leaves its existing durable state untouched.
    """
    from angerona.core.remediation_log import TransactionOwnerCapability
    if type(owner) is not TransactionOwnerCapability or type(record) is not dict:
        return {"committed": False, "reason": "Exact ordinary owner/record unavailable"}
    record["native_postcondition_before_commit"] = (record.get("native_postcondition_before_commit") is True
        or record.get("verified") is True)
    record["failed_terminal_commit"] = {"result": str(failed_result)[:64],
        "error_type": type(error).__name__, "error": str(error)[:512]}
    record["journal_error"] = str(error)[:512]
    record["recovery_handoff_intent"] = "release-exact-owner-for-reviewed-recovery"
    record.update(transaction_state="recovery_required", recovery_required=True)
    try:
        completion = store.finish_transaction(owner, result="recovery_required", record=record)
        normalized = completion.pop("record")
        record.clear()
        record.update(normalized)
        valid = verify_recovery_handoff(store, owner.transaction_id, completion,
            expected_mitre=record.get("mitre"), expected_action=record.get("action"))
        record["recovery_handoff_receipt"] = completion
        record["recovery_handoff_verified"] = valid
        return {"committed": valid, "receipt": completion,
            "reason": "" if valid else "Committed recovery state lacks independently accepted authenticated custody"}
    except Exception as exc:
        record["recovery_handoff_verified"] = False
        record["recovery_handoff_error"] = str(exc)[:512]
        return {"committed": False, "reason": str(exc)[:512]}
