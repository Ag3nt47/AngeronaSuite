"""One signed, durable rollback for an owned applied registry control.

No free-form target, command or ordinary weakness selects this action. Native
compare-before-write checks do not provide isolation against a kernel/admin
adversary racing the Windows registry.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from angerona.core.breach_state import protect_authority
from angerona.modules.remediation_actions import RemediationAction, RegistryHardeningAction


def _require_authority():
    allowed, reason = protect_authority()
    if os.name != "nt" or allowed is not True:
        raise PermissionError(reason or "Current installed host response authority is unavailable")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _store():
    from angerona.core.remediation_log import RemediationLog, get_log
    store = get_log()
    if type(store) is not RemediationLog:
        raise RuntimeError("Exact durable remediation store is unavailable")
    return store


def applied_registry_record(store, transaction_id, receipt_id, receipt_hash, *, mitre, control_id):
    if not store.verify_committed_application(transaction_id, receipt_hash, receipt_id,
                                               expected_mitre=mitre, expected_action="registry_hardening"):
        raise ValueError("Original applied registry transaction lacks committed authenticated custody")
    transaction = store.transaction(transaction_id)
    if (not transaction or transaction.get("state") != "APPLIED"
            or transaction.get("trigger") != "AngeronaPatch"):
        raise ValueError("Original registry transaction is no longer applied")
    record = transaction["record"]
    candidates = RegistryHardeningAction()._candidates({"mitre_id": mitre, "control_id": control_id})
    if len(candidates) != 1:
        raise ValueError("Original transaction has no exact reviewed registry control")
    control = candidates[0]
    if (record.get("action") != "registry_hardening" or record.get("mitre") != mitre
            or record.get("control_id") != control.control_id
            or record.get("subkey") != control.subkey or record.get("name") != control.value_name
            or type(record.get("new")) is not int or record["new"] != control.dword
            or type(record.get("prior_present")) is not bool
            or (record["prior_present"] and (type(record.get("prior")) is not int
                or not 0 <= record["prior"] <= 0xffffffff or record.get("prior_type") != 4))
            or (not record["prior_present"] and (record.get("prior") is not None or record.get("prior_type") is not None))):
        raise ValueError("Original registry record does not match the fixed control catalog")
    return record


class RegistryControlRollbackAction(RemediationAction):
    """Fixed recovery action, deliberately absent from ordinary matching."""

    key = "registry_control_rollback"
    title = "Restore one authenticated registry control's retained prior state"
    host_level = True
    reversible = True
    durable_transaction = True

    def matches(self, weakness):
        del weakness
        return False

    @staticmethod
    def _source(record):
        original = applied_registry_record(_store(), record.get("original_transaction_id"),
            record.get("original_receipt_id"), record.get("original_receipt_hash"),
            mitre=record.get("mitre"), control_id=record.get("control_id"))
        if (record.get("original_record_sha256") != hashlib.sha256(_canonical(original)).hexdigest()
                or record.get("subkey") != original["subkey"] or record.get("name") != original["name"]
                or record.get("before_present") is not True or type(record.get("before")) is not int
                or record.get("before") != original["new"] or type(record.get("before_type")) is not int
                or record.get("before_type") != 4
                or record.get("desired_present") is not original["prior_present"]
                or record.get("desired") != original["prior"]
                or (original["prior_present"] and type(record.get("desired")) is not int)
                or (not original["prior_present"] and record.get("desired") is not None)
                or record.get("desired_type") != original["prior_type"]):
            raise ValueError("Rollback transaction changed its exact signed source or inverse state")
        return original

    @staticmethod
    def _matches_state(record, prefix):
        return RegistryHardeningAction._state_matches(
            RegistryHardeningAction._read_state(record["subkey"], record["name"]),
            present=record[prefix + "_present"], value=record[prefix],
            value_type=record[prefix + "_type"])

    def begin_transaction(self, weakness, quarantine_dir):
        del quarantine_dir
        _require_authority()
        original = applied_registry_record(_store(), weakness.get("original_transaction_id"),
            weakness.get("original_receipt_id"), weakness.get("original_receipt_hash"),
            mitre=weakness.get("mitre_id"), control_id=weakness.get("control_id"))
        record = {"action": self.key, "mitre": weakness["mitre_id"],
            "control_id": original["control_id"], "subkey": original["subkey"], "name": original["name"],
            "original_transaction_id": weakness["original_transaction_id"],
            "original_receipt_id": weakness["original_receipt_id"],
            "original_receipt_hash": weakness["original_receipt_hash"],
            "original_record_sha256": hashlib.sha256(_canonical(original)).hexdigest(),
            "before_present": True, "before": original["new"], "before_type": 4,
            "desired_present": original["prior_present"], "desired": original["prior"],
            "desired_type": original["prior_type"], "transaction_state": "prepared",
            "compensation_ready": True, "mutation_started": False, "ok": False}
        if not self._matches_state(record, "before"):
            raise ValueError("Current registry state no longer matches the committed patch; rollback held")
        return record

    def apply_transactional(self, weakness, quarantine_dir, transaction):
        del weakness, quarantine_dir
        _require_authority()
        original = self._source(transaction)
        if not self._matches_state(transaction, "before"):
            transaction.update(ok=False, external_conflict=True, changed=False)
            return transaction
        transaction["mutation_started"] = True
        outcome = RegistryHardeningAction().rollback(original)
        transaction.update(ok=outcome.get("ok") is True, rollback_result=outcome)
        if outcome.get("external_conflict") is True:
            transaction.update(changed=False, mutation_started=False)
        return transaction

    def verify(self, weakness, record):
        del weakness
        try:
            self._source(record)
            return self._matches_state(record, "desired")
        except Exception:
            return False

    def rollback(self, record):
        """Compensate a failed undo back to its exact pre-undo patched state."""
        try:
            _require_authority()
            self._source(record)
            if self._matches_state(record, "before"):
                return {"ok": True, "changed": False}
            if not self._matches_state(record, "desired"):
                return {"ok": False, "external_conflict": True,
                        "error": "Undo state differs from both retained states; compensation held"}
            compensation = {"subkey": record["subkey"], "name": record["name"],
                            "prior_present": record["desired_present"], "prior": record["desired"],
                            "prior_type": record["desired_type"], "new": record["before"]}
            restored = RegistryHardeningAction().apply_transactional({}, Path(), compensation)
            return {"ok": restored.get("ok") is True and self.verify_rollback(record)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:300]}

    def verify_rollback(self, record):
        try:
            self._source(record)
            return self._matches_state(record, "before")
        except Exception:
            return False


def rollback_registry_transaction(weakness, *, approved=False, db_path=None):
    """One exact owned inverse, with durable intent, compensation and receipt."""
    if approved is not True:
        return {"ok": False, "state": "held", "reason": "Explicit reviewed rollback approval is required"}
    record = owner = None
    try:
        _require_authority()
        from angerona.core.remediation_log import init_log
        store = init_log(db_path)
        if store is not _store():
            raise ValueError("Rollback store binding differs")
        action = RegistryControlRollbackAction()
        record = action.begin_transaction(weakness, Path())
        owner = store.prepare_transaction(trigger="AngeronaPatchRollback", mitre=record["mitre"],
            action_key=action.key, action_title=action.title, host_level=True, record=record)
        record["transaction_id"] = owner.transaction_id
        store.transition_transaction(owner, state="MUTATING", record=record)
        try:
            action.apply_transactional(weakness, Path(), record)
            record["verified"] = record.get("ok") is True and action.verify(weakness, record)
        except Exception as exc:
            record.update(ok=False, verified=False, error=str(exc)[:300])
        if record["verified"]:
            completion = store.finish_transaction(owner, result="applied", record=record)
            retained = completion.pop("record")
            retained["proof_receipt"] = completion
            committed = store.verify_committed_application(owner.transaction_id,
                completion.get("receipt_hash"), completion.get("receipt_id"),
                expected_mitre=record["mitre"], expected_action=action.key) is True
            return {"ok": committed, "state": "rollback-applied" if committed else "receipt-unverified",
                    "record": retained, "gap_closed": False}
        compensated = action.rollback(record)
        record["rollback"] = compensated
        record["rollback_verified"] = compensated.get("ok") is True and action.verify_rollback(record)
        completion = store.finish_transaction(owner,
            result="rolled_back" if record["rollback_verified"] else "rollback_failed", record=record)
        retained = completion.pop("record")
        retained["proof_receipt"] = completion
        return {"ok": False,
                "state": "undo-failed-compensated" if record["rollback_verified"] else "recovery-required",
                "record": retained, "gap_closed": False}
    except Exception as exc:
        handoff = {"committed": False, "reason": "No owned transaction was admitted"}
        if owner is not None and type(record) is dict:
            from angerona.core.patch_recovery import handoff_owned_failure
            handoff = handoff_owned_failure(store, owner, record, failed_result="inverse-terminal", error=exc)
        # Only an actual exact-owner RECOVERY_REQUIRED commit releases the
        # mutation for reviewed reconciliation. A failed handoff remains held.
        return {"ok": False, "state": "recovery-required" if owner is not None else "held",
                "reason": str(exc)[:300], "record": record,
                "recovery_handoff": handoff,
                "transaction_id": owner.transaction_id if owner is not None else None,
                "gap_closed": False}
