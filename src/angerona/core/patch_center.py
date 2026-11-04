"""Exact-report, exact-control patch review using existing typed host actions."""
from __future__ import annotations

from collections import OrderedDict
import copy
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time

from angerona.core.breach_state import protect_authority
from angerona.core.patch_memory import report_classification, reported_gaps

# The legacy IFEO-root MitigationOptions entry has no bound image or runtime
# effectiveness proof. Do not offer it as an executable patch in this review.
_REVIEWABLE_CONTROLS = frozenset({
    "windows.lsass.run_as_ppl", "windows.wdigest.disable_cleartext",
    "windows.powershell.script_block_logging", "windows.uac.secure_desktop_consent",
    "windows.autorun.disable_all_drives", "windows.registry.base_object_auditing",
})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _authority():
    allowed, reason = protect_authority()
    return {"allowed": allowed is True, "reason": str(reason)[:512]}


def _registry_action(mitre, control_id):
    if control_id not in _REVIEWABLE_CONTROLS:
        raise ValueError("This catalog control has no supported executable patch in this workspace")
    from angerona.modules import remediation_actions as actions
    weakness = {"mitre_id": mitre, "control_id": control_id}
    decision = actions.classify_remediation(weakness)
    if type(decision.action) is not actions.RegistryHardeningAction:
        raise ValueError(decision.reason or "No supported executable registry control for this exact selection")
    return decision.action, weakness


class _PatchDispatchGuard:
    """A restrictive in-memory callback; never a replacement for host authority."""
    def __init__(self, service, plan_id):
        self._service, self._plan_id = service, plan_id

    def require(self, record):
        self._service._require_native_dispatch(self._plan_id, record, require_binding=True)

    def bind(self, record):
        self._service._require_native_dispatch(self._plan_id, record)
        record["patch_binding"] = self._service._binding(self._plan_id)


def require_reviewed_patch_dispatch(weakness, record):
    guard = weakness.get("_angerona_patch_dispatch")
    if guard is not None:
        if type(guard) is not _PatchDispatchGuard:
            raise PermissionError("Reviewed patch dispatch binding is invalid")
        guard.require(record)


def bind_reviewed_patch_transaction(weakness, record):
    guard = weakness.get("_angerona_patch_dispatch")
    if guard is not None:
        if type(guard) is not _PatchDispatchGuard:
            raise PermissionError("Reviewed patch intent binding is invalid")
        guard.bind(record)


class PatchReviewService:
    """No imported instructions, arbitrary target, batch apply or AI executor."""

    def __init__(self, posture, handoff):
        self.posture, self.handoff = posture, handoff
        self._lock = threading.RLock()
        self._plans = OrderedDict()
        self._undo_plans = OrderedDict()
        self._root = Path(posture.data_dir).resolve() if posture is not None else None

    def _report(self):
        if self.posture is None or self.handoff is None:
            raise ValueError("An authenticated immutable after-action report is required")
        from angerona.shark.aar_report import verified_aar_handoff_text
        verified_aar_handoff_text(self.handoff)
        if Path(self.handoff.report_directory).resolve() != self._root:
            raise ValueError("Report and Posture data profiles differ")
        report = json.loads(self.handoff.report_bytes.decode("utf-8"))
        classification, reason = report_classification(report)
        return report, classification, reason

    def _remember_attempt(self, attempt):
        memory = getattr(self.posture, "_patch_memory", None)
        if memory is None:
            return {"stored": False, "reason": "Patch memory is unavailable"}
        try:
            return memory.record_attempt(attempt)
        except Exception as exc:
            return {"stored": False, "reason": type(exc).__name__}

    def snapshot(self):
        state = {"report_state": "unverified", "reason": "", "gaps": [],
                 "authority": _authority(), "response_authorized": False,
                 "scope": "Reported practice gaps and separately reviewed OS configuration controls; no exploit patch claim"}
        try:
            report, classification, reason = self._report()
            self.posture._remember_patch_report(report)
            state.update(report_state=classification, reason=reason, run_id=report["run_id"],
                         report_sha256=self.handoff.report_sha256,
                         gaps=reported_gaps(report) if classification == "verified-practice" else [])
            from angerona.modules.remediation_actions import RegistryHardeningAction
            for gap in state["gaps"]:
                gap["controls"] = [{"control_id": control.control_id, "title": control.why}
                    for control in RegistryHardeningAction._CONTROLS
                    if gap["technique"] in control.techniques and control.control_id in _REVIEWABLE_CONTROLS]
                if not gap["controls"]:
                    gap["unsupported_reason"] = "No fixed executable OS control maps to this gap; source/backend repair and fresh validation remain required"
        except Exception as exc:
            state["reason"] = str(exc)[:512]
        state["memory"] = self.posture.patch_memory_snapshot() if self.posture is not None else {
            "available": False, "reason": "Posture Hardening module unavailable", "gaps": [], "attempts": [], "incidents": []}
        return state

    def build_plan(self, gap_id, control_id):
        with self._lock:
            report, classification, _reason = self._report()
            if classification != "verified-practice":
                raise ValueError("Diagnostic or unverified reports cannot authorize a patch plan")
            gap = next((row for row in reported_gaps(report) if row["gap_id"] == gap_id), None)
            if gap is None:
                raise ValueError("Selected gap is not part of this exact reviewed report")
            action, weakness = _registry_action(gap["technique"], control_id)
            from angerona.modules.remediation_actions import plan_remediation
            proposal = plan_remediation([weakness])
            if len(proposal) != 1 or proposal[0].get("action") != action.key or proposal[0].get("executable") is not True:
                raise ValueError("Typed action plan is unavailable or ambiguous")
            baseline = action.begin_transaction(weakness, self._root / "quarantine")
            reviewed = {"run_id": report["run_id"], "report_sha256": self.handoff.report_sha256,
                        "gap_id": gap_id, "control_id": control_id, "mitre": gap["technique"],
                        "action": action.key, "title": proposal[0]["title"],
                        "subkey": baseline["subkey"], "value_name": baseline["name"],
                        "prior_present": baseline["prior_present"], "prior": baseline["prior"],
                        "prior_type": baseline["prior_type"], "new": baseline["new"],
                        "reason": baseline["why"], "gap_remains_open": True,
                        "effective_runtime_protection_verified": False}
            plan_id = secrets.token_hex(32)
            reviewed["plan_id"] = plan_id
            reviewed["plan_sha256"] = hashlib.sha256(_canonical(reviewed)).hexdigest()
            reviewed["authority"] = _authority()
            reviewed["change_needed"] = not (baseline["prior_present"] and baseline["prior_type"] == 4
                                              and baseline["prior"] == baseline["new"])
            self._plans[plan_id] = {"review": copy.deepcopy(reviewed), "weakness": weakness,
                                    "baseline": baseline, "action": action, "created": time.monotonic(),
                                    "state": "reviewed"}
            while len(self._plans) > 32:
                self._plans.popitem(last=False)
            return copy.deepcopy(reviewed)

    def _binding(self, plan_id):
        review = self._plans[plan_id]["review"]
        return {key: review[key] for key in ("run_id", "report_sha256", "gap_id", "plan_sha256", "control_id")}

    def _require_native_dispatch(self, plan_id, record, *, require_binding=False):
        plan = self._plans.get(plan_id)
        if not plan or plan["state"] != "dispatching" or not 0 <= time.monotonic() - plan["created"] < 300:
            raise PermissionError("Exact reviewed patch plan expired or changed")
        _report, classification, _reason = self._report()
        if classification != "verified-practice" or not _authority()["allowed"]:
            raise PermissionError("Current source report or installed host authority is unavailable")
        action, _weakness = _registry_action(plan["review"]["mitre"], plan["review"]["control_id"])
        if action is not plan["action"]:
            raise PermissionError("Reviewed typed action registry changed")
        baseline = plan["baseline"]
        if any(record.get(field) != baseline.get(field) for field in (
            "action", "control_id", "subkey", "name", "prior_present", "prior", "prior_type", "new")):
            raise PermissionError("Native transaction no longer matches the reviewed exact control/baseline")
        if require_binding and record.get("patch_binding") != self._binding(plan_id):
            raise PermissionError("Native transaction lost its exact source-report/gap/plan binding")

    def apply(self, plan_id, *, approved=False):
        with self._lock:
            plan = self._plans.get(plan_id)
            if approved is not True or plan is None or plan["state"] != "reviewed":
                return {"ok": False, "state": "held", "reason": "One unconsumed reviewed plan and explicit approval are required"}
            authority = _authority()
            if not authority["allowed"]:
                return {"ok": False, "state": "held", "reason": authority["reason"]}
            if not plan["review"]["change_needed"]:
                return {"ok": False, "state": "already-configured", "reason": "The selected value already matches; no new patch or receipt was created", "gap_closed": False}
            attempt = {"attempt_id": secrets.token_hex(32), "gap_id": plan["review"]["gap_id"],
                       "run_id": plan["review"]["run_id"], "report_sha256": self.handoff.report_sha256,
                       "plan_sha256": plan["review"]["plan_sha256"], "mitre": plan["review"]["mitre"],
                       "control_id": plan["review"]["control_id"], "state": "prepared",
                       "action": "registry_hardening", "gap_closed": False}
            memory = getattr(self.posture, "_patch_memory", None)
            if memory is None or self._remember_attempt(attempt).get("stored") is not True:
                return {"ok": False, "state": "held", "reason": "Durable patch-attempt index is unavailable; no action was dispatched"}
            plan["state"] = "dispatching"
            try:
                self._require_native_dispatch(plan_id, plan["baseline"])
                from angerona.modules import remediation_actions as actions
                from angerona.core.remediation_log import get_log
                weakness = {**plan["weakness"], "_angerona_patch_dispatch": _PatchDispatchGuard(self, plan_id)}
                result = actions.apply_remediation([weakness], self._root / "quarantine", apply=True,
                    allow_host=True, trigger="AngeronaPatch", db_path=self._root / "flight-recorder.db")
                records = result.get("records", [])
                record = records[0] if len(records) == 1 and type(records[0]) is dict else None
                verified = (self.posture.committed_patch_record(get_log(), record,
                    expected_mitre=attempt["mitre"], expected_action="registry_hardening")
                    and record.get("patch_binding") == self._binding(plan_id))
                attempt["state"] = "applied-verified" if verified else "held-or-failed"
                if record:
                    proof = record.get("proof_receipt") if type(record.get("proof_receipt")) is dict else {}
                    attempt.update(transaction_id=record.get("transaction_id"), receipt_id=proof.get("receipt_id"),
                                   receipt_hash=proof.get("receipt_hash"), native_postcondition=(record.get("verified") is True
                                       or record.get("native_postcondition_before_commit") is True),
                                   recovery_required=record.get("recovery_required") is True,
                                   transaction_state=record.get("transaction_state"))
                    attempt["recovery_handoff_receipt"] = record.get("recovery_handoff_receipt")
                    attempt["recovery_handoff_verified"] = record.get("recovery_handoff_verified") is True
                    attempt["recovery_handoff_error"] = record.get("recovery_handoff_error")
                memory_status = self._remember_attempt(attempt)
                return {"ok": verified, "state": attempt["state"], "attempt": attempt,
                        "record": record, "gap_closed": False, "memory": memory_status,
                        "scope": "Exact registry configuration postcondition and committed local receipt only; effective runtime protection unverified"}
            except Exception as exc:
                attempt.update(state="held-or-failed", reason=str(exc)[:512])
                memory_status = self._remember_attempt(attempt)
                return {"ok": False, "state": attempt["state"], "reason": attempt["reason"], "attempt": attempt,
                        "memory": memory_status}
            finally:
                plan["state"] = "consumed"

    def _attempt(self, attempt_id):
        memory = self.posture.patch_memory_snapshot()
        attempt = next((row for row in memory.get("attempts", []) if row.get("attempt_id") == attempt_id), None)
        if not attempt:
            raise ValueError("Selected signed patch attempt is unavailable")
        return attempt

    def retest(self, attempt_id):
        attempt = self._attempt(attempt_id)
        result = check_patch_attempt(self.posture, attempt)
        attempt.update(watch_state=result["state"], last_checked=int(time.time()))
        memory_status = self._remember_attempt(attempt)
        return {**result, "attempt": attempt, "gap_closed": False, "memory": memory_status}

    def review_rollback(self, attempt_id):
        attempt = self._attempt(attempt_id)
        if attempt.get("state") != "applied-verified" or attempt.get("action") != "registry_hardening":
            return {"ok": False, "state": "held", "reason": "Only this tool's one committed applied registry control can be rolled back"}
        current = check_patch_attempt(self.posture, attempt)
        if current.get("retained_commit_verified") is not True or current.get("native_postcondition_current") is not True:
            return {"ok": False, "state": "held", "reason": "Exact owned receipt binding and unchanged current native state are required", "verification": current}
        from angerona.core.patch_controls import RegistryControlRollbackAction
        weakness = {"mitre_id": attempt["mitre"], "control_id": attempt["control_id"],
            "original_transaction_id": attempt.get("transaction_id"),
            "original_receipt_id": attempt.get("receipt_id"), "original_receipt_hash": attempt.get("receipt_hash")}
        inverse = RegistryControlRollbackAction().begin_transaction(weakness, self._root / "quarantine")
        identity = secrets.token_hex(32)
        public = {"ok": True, "state": "rollback-review-ready", "rollback_plan_id": identity,
            "attempt_id": attempt_id, "source_transaction_id": attempt["transaction_id"],
            "source_receipt_hash": attempt["receipt_hash"], "control_id": attempt["control_id"],
            "subkey": inverse["subkey"], "value_name": inverse["name"],
            "before": inverse["before"], "before_type": inverse["before_type"],
            "restore_present": inverse["desired_present"], "restore_value": inverse["desired"],
            "restore_type": inverse["desired_type"], "gap_closed": False,
            "scope": "Review this exact retained prior value or absence; no change has been made"}
        with self._lock:
            self._undo_plans[identity] = {"attempt_id": attempt_id, "created": time.monotonic(),
                "weakness": weakness, "source_record_sha256": inverse["original_record_sha256"]}
            while len(self._undo_plans) > 16:
                self._undo_plans.popitem(last=False)
        return public

    def rollback(self, attempt_id, *, approved=False, rollback_plan_id=None):
        with self._lock:
            review = self._undo_plans.pop(rollback_plan_id, None)
        if (approved is not True or not review or review["attempt_id"] != attempt_id
                or not 0 <= time.monotonic() - review["created"] < 300):
            return {"ok": False, "state": "held", "reason": "One exact unexpired reviewed rollback plan and explicit approval are required"}
        attempt = self._attempt(attempt_id)
        if (attempt.get("state") != "applied-verified" or attempt.get("transaction_id") != review["weakness"]["original_transaction_id"]
                or check_patch_attempt(self.posture, attempt).get("native_postcondition_current") is not True):
            return {"ok": False, "state": "held", "reason": "Reviewed rollback source or current native state changed"}
        from angerona.core.patch_controls import rollback_registry_transaction
        result = rollback_registry_transaction(review["weakness"],
            approved=approved, db_path=self._root / "flight-recorder.db")
        attempt["last_rollback_state"] = result.get("state")
        attempt["last_rollback_error"] = str(result.get("reason") or "")[:512]
        if type(result.get("record")) is dict:
            attempt["last_rollback_receipt"] = result["record"].get("proof_receipt")
        if result.get("ok") is True:
            attempt.update(state="rolled-back", rollback_transaction_id=result["record"]["transaction_id"],
                           rollback_receipt=result["record"]["proof_receipt"], watch_state="rolled-back")
        elif result.get("state") == "recovery-required":
            attempt.update(rollback_recovery_required=True, watch_state="undo-recovery-required", rollback_transaction_id=(result.get("transaction_id")
                or (result.get("record") or {}).get("transaction_id")))
            attempt["rollback_recovery_handoff_receipt"] = (result.get("record") or {}).get("recovery_handoff_receipt")
        memory_status = self._remember_attempt(attempt)
        return {**result, "gap_closed": False, "memory": memory_status}

    def recover(self, attempt_id, *, approved=False):
        attempt = self._attempt(attempt_id)
        authority = _authority()
        if approved is not True or not authority["allowed"]:
            return {"ok": False, "state": "held", "reason": authority["reason"] or "Explicit recovery approval is required"}
        transaction_id = attempt.get("rollback_transaction_id") if attempt.get("rollback_recovery_required") else attempt.get("transaction_id")
        if type(transaction_id) is not int:
            return {"ok": False, "state": "held", "reason": "No exact owned unresolved transaction is bound to this attempt"}
        from angerona.core.remediation_log import init_log
        store = init_log(self._root / "flight-recorder.db")
        transaction = store.transaction(transaction_id)
        if (not transaction or transaction.get("trigger") not in {"AngeronaPatch", "AngeronaPatchRollback"}
                or transaction.get("mitre") != attempt.get("mitre")
                or transaction.get("action_key") not in {"registry_hardening", "registry_control_rollback"}
                or transaction.get("record", {}).get("control_id") != attempt.get("control_id")):
            return {"ok": False, "state": "held", "reason": "Exact owned unresolved transaction is unavailable; applied actions need their separate reviewed rollback"}
        if transaction.get("state") != "RECOVERY_REQUIRED":
            return {"ok": False, "state": "held", "stored_state": transaction.get("state"),
                "transaction_id": transaction_id,
                "reason": "The exact owner has no committed recovery handoff; PREPARED/MUTATING custody cannot be stolen or labelled reconciled"}
        from angerona.core.patch_recovery import verify_recovery_handoff
        handoff_proof = (attempt.get("rollback_recovery_handoff_receipt") if attempt.get("rollback_recovery_required")
                         else attempt.get("recovery_handoff_receipt"))
        if not verify_recovery_handoff(store, transaction_id, handoff_proof,
                expected_mitre=attempt["mitre"], expected_action=transaction["action_key"]):
            return {"ok": False, "state": "held", "reason": "The exact owner has not released an authenticated committed recovery handoff; native recovery remains held"}
        original_id = transaction.get("record", {}).get("original_transaction_id") if attempt.get("rollback_recovery_required") else transaction_id
        original = store.transaction(original_id) if type(original_id) is int else None
        if (not original or original.get("trigger") != "AngeronaPatch"
                or original.get("record", {}).get("patch_binding") != {
                    key: attempt.get(key) for key in ("run_id", "report_sha256", "gap_id", "plan_sha256", "control_id")}):
            return {"ok": False, "state": "held", "reason": "Retained transaction is not bound to this exact report/gap/plan attempt"}
        from angerona.modules.remediation_actions import reconcile_remediation_transaction
        result = reconcile_remediation_transaction(transaction_id, authorized=True,
                                                   db_path=self._root / "flight-recorder.db")
        attempt["last_recovery"] = {key: result.get(key) for key in ("ok", "state", "transaction_id", "error")}
        if result.get("ok") is True:
            if attempt.get("rollback_recovery_required"):
                attempt.update(rollback_recovery_required=False, watch_state="failed-undo-compensated")
            else:
                attempt.update(recovery_required=False, state="reconciled-rolled-back", watch_state="rolled-back")
            attempt["recovery_receipt"] = result.get("proof_receipt")
        return {**result, "memory": self._remember_attempt(attempt)}


def check_patch_attempt(posture, attempt):
    """Fresh read-only native fact plus independently checked retained receipt."""
    try:
        from angerona.core.remediation_log import RemediationLog, get_log
        from angerona.core.patch_controls import applied_registry_record
        from angerona.modules.remediation_actions import RegistryHardeningAction
        store = get_log()
        if type(store) is not RemediationLog or Path(store._path).resolve() != (Path(posture.data_dir) / "flight-recorder.db").resolve():
            raise ValueError("Exact remediation journal is unavailable")
        record = applied_registry_record(store, attempt.get("transaction_id"), attempt.get("receipt_id"),
            attempt.get("receipt_hash"), mitre=attempt.get("mitre"), control_id=attempt.get("control_id"))
        if record.get("patch_binding") != {key: attempt.get(key)
                for key in ("run_id", "report_sha256", "gap_id", "plan_sha256", "control_id")}:
            raise ValueError("Retained control receipt differs from this report/gap/plan attempt")
        actual = RegistryHardeningAction._read_state(record["subkey"], record["name"])
        matches = RegistryHardeningAction._state_matches(actual, present=True, value=record["new"], value_type=4)
        return {"ok": matches, "state": "postcondition-current" if matches else "postcondition-regressed",
                "retained_commit_verified": True, "native_postcondition_current": matches,
                "effective_runtime_protection_verified": False}
    except Exception as exc:
        return {"ok": False, "state": "verification-unavailable", "reason": str(exc)[:512],
                "native_postcondition_current": None, "retained_commit_verified": False}


def refresh_patch_controls(posture):
    """Called only from Posture's existing worker cadence, never EventBus intake."""
    memory = posture.patch_memory_snapshot()
    checked = 0
    for attempt in memory.get("attempts", []):
        if attempt.get("state") != "applied-verified" or attempt.get("action") != "registry_hardening":
            continue
        result = check_patch_attempt(posture, attempt)
        old = attempt.get("watch_state")
        attempt.update(watch_state=result["state"], last_checked=int(time.time()))
        posture._patch_memory.record_attempt(attempt)
        if result["state"] == "postcondition-regressed" and old != result["state"]:
            from angerona.core.eventbus import Severity
            posture.emit("A retained typed registry control no longer has its committed native postcondition; review AngeronaPatch.",
                         Severity.HIGH, disposition="exposure", response_authorized=False,
                         control_id=attempt.get("control_id"), transaction_id=attempt.get("transaction_id"))
        checked += 1
        if checked >= 16:
            break
    return checked
